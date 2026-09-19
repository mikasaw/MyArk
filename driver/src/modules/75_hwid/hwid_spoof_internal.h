// MyArk hwid module: R3-1 (T-B) spoof subdivision engine.
//
// Per-class state machine over a fixed table (no dynamic allocation):
//   DRY_RUN  - probe the current value from below any attachment, no state
//              change, return a Real->Spoof preview.
//   APPLY    - attach (disk classes) / register (GPU), probe the original
//              value into the per-class cache, then enable rewriting.
//   RESTORE  - disable rewriting, detach, re-probe to prove the original
//              value is back, clear spoof + cache.
//
// Concurrency: one global EX_SPIN_LOCK guards all mutable class state.
// The completion-routine path copies the spoof bytes to a stack buffer
// under the shared lock and does all rewriting outside the lock (no pool
// allocation while held). Rewrite/query counters are interlocked.

#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "myark_config.h"
#include "hwid_descriptor.h"
#include "../../../shared/driver/MyArkHwidIoctl.h"

#if MYARK_MODULE_HWID

#include "MyArkSafetyToken.h"

// Device stacks filtered per class (disk: 1; partition: P0..P31).
#define MYARK_HWID_SPOOF_MAX_ATTACH     32
#define MYARK_HWID_SPOOF_MAX_PARTITIONS 32

// Attachment targets.
#define MYARK_HWID_TARGET_DISK          0   // \Device\HarddiskN\Partition0
#define MYARK_HWID_TARGET_PARTITION     1   // \Device\HarddiskN\PartitionM
#define MYARK_HWID_TARGET_NSIPROXY      2   // \Device\Nsi (class ARP)

// Filter device-object extension signature.
#define MYARK_HWID_FILTER_EXT_MAGIC     0x48574645UL  // 'HWFE'

// Per-IRP NSI request context magic (hwid_spoof_arp.c allocation).
#define MYARK_HWID_ARP_CTX_MAGIC        0x48574E43UL  // 'HWNC'
#define MYARK_HWID_ARP_POOL_TAG         0x6D485241UL  // 'ARHm'

typedef struct _MYARK_HWID_FILTER_EXT {
    ULONG          Magic;                    // MYARK_HWID_FILTER_EXT_MAGIC
    ULONG          Class;                    // owning MYARK_HWID_SPOOF_CLASS_*
    ULONG          TargetKind;               // MYARK_HWID_TARGET_*
    ULONG          TargetIndex;              // partition index (disk: 0)
    PDEVICE_OBJECT TargetDevice;             // IoAttachDeviceToDeviceStack result
    PFILE_OBJECT   TargetFileObject;         // from IoGetDeviceObjectPointer
    PDEVICE_OBJECT FilterDo;                 // our filter DO (self)
    IO_REMOVE_LOCK RemoveLock;
} MYARK_HWID_FILTER_EXT, *PMYARK_HWID_FILTER_EXT;

//
// Per-IRP capture context for \Device\Nsi: METHOD_BUFFERED overwrites
// the request with the response, so code + input head are captured at
// dispatch and consumed at completion (capture ring + rewrite match).
//
typedef struct _MYARK_HWID_ARP_CTX {
    ULONG                    Magic;         // MYARK_HWID_ARP_CTX_MAGIC
    PMYARK_HWID_FILTER_EXT   Ext;
    ULONG                    Code;
    ULONG                    InLen;
    UCHAR                    In[MYARK_HWID_CAPTURE_IN_BYTES];
} MYARK_HWID_ARP_CTX, *PMYARK_HWID_ARP_CTX;

typedef struct _MYARK_HWID_SPOOF_CLASS_STATE {
    ULONG   Class;                           // MYARK_HWID_SPOOF_CLASS_* (1-based)
    ULONG   DiskIndex;                       // target disk captured at APPLY

    // -- written under the exclusive lock only --
    BOOLEAN Active;                          // rewriting enabled
    BOOLEAN CacheValid;
    ULONG   SpoofLen;
    ULONG   CacheLen;
    UCHAR   Spoof[MYARK_HWID_SPOOF_VALUE_MAX_BYTES];
    UCHAR   Cache[MYARK_HWID_SPOOF_VALUE_MAX_BYTES];
    ULONG   AttachedCount;

    // -- written under the exclusive lock only (attachment arrays) --
    PMYARK_HWID_FILTER_EXT Attachments[MYARK_HWID_SPOOF_MAX_ATTACH];

    // -- interlocked / diagnostic --
    volatile LONG RewrittenCount;
    volatile LONG QueryCount;
    NTSTATUS      LastStatus;
} MYARK_HWID_SPOOF_CLASS_STATE, *PMYARK_HWID_SPOOF_CLASS_STATE;

//
// Class-id -> state-table index helper (class ids are 1-based).
//
PMYARK_HWID_SPOOF_CLASS_STATE
MyArkHwidSpoofClassState(_In_ UINT32 Class);

//
// Global engine lifecycle: zero the table / detach everything still
// attached. Called from the module Init/Cleanup paths.
//
NTSTATUS MyArkHwidSpoofEngineInit(VOID);
VOID     MyArkHwidSpoofEngineTeardown(VOID);

//
// Attachment plumbing (hwid_spoof_state.c). DetachClassLocked releases
// one router reference per detached attachment, so callers never touch
// the router refcount directly. Serialization contract: 0x753 handlers
// are mutually exclusive (WDF sequential default queue) and engine
// teardown runs after the queues drain, so DetachClassLocked is called
// from a single thread and takes NO spin lock -- it performs
// PASSIVE-only work (IoDetachDevice/IoDeleteDevice) and must stay
// lock-free.
//
NTSTATUS
MyArkHwidSpoofAttachTarget(
    _In_    ULONG                            Class,
    _In_    PUNICODE_STRING                  TargetName,
    _In_    ULONG                            TargetKind,
    _In_    ULONG                            TargetIndex,
    _Inout_ PMYARK_HWID_SPOOF_CLASS_STATE    State);

VOID
MyArkHwidSpoofDetachClassLocked(
    _Inout_ PMYARK_HWID_SPOOF_CLASS_STATE State);

//
// Global engine lock accessors (the EX_SPIN_LOCK itself stays private to
// hwid_spoof_state.c). Shared: completion-path spoof snapshots.
// Exclusive: state publication.
//
ULONG MyArkHwidSpoofLockShared(VOID);
VOID  MyArkHwidSpoofUnlockShared(_In_ ULONG OldIrql);
ULONG MyArkHwidSpoofLockExclusive(VOID);
VOID  MyArkHwidSpoofUnlockExclusive(_In_ ULONG OldIrql);

//
// Per-IRP capture context for IOCTL_STORAGE_QUERY_PROPERTY: the
// METHOD_BUFFERED input (PropertyId) is gone by completion, so it is
// captured at dispatch and freed after the completion rewrite.
// Capture returns the ctx, or Ext itself when nothing needs capturing
// (allocation failure fails open: pass-through, no rewrite).
//
PVOID
MyArkHwidCaptureQueryContext(
    _In_ PMYARK_HWID_FILTER_EXT Ext,
    _Inout_ PIRP                Irp,
    _In_ PIO_STACK_LOCATION     Slot);

PMYARK_HWID_FILTER_EXT
MyArkHwidExtFromContext(_In_ PVOID Context);

VOID
MyArkHwidFreeQueryContext(_In_ PVOID Context);

//
// Completion-path rewrite dispatcher (hwid_spoof_disk.c): inspects the
// completed DEVICE_CONTROL IRP and rewrites the response buffer for the
// owning class when the class is active. Context is the captured ctx or
// the filter extension.
//
VOID
MyArkHwidRewriteControlBuffer(
    _In_ PVOID   Context,
    _Inout_ PIRP Irp);

//
// 0x753 worker shared by the IOCTL handler (token already validated).
// Runs the DRY_RUN/APPLY/RESTORE state machine for one class.
//
NTSTATUS
MyArkHwidSpoofSetConfig(
    _In_  PMYARK_HWID_SPOOF_SET_INPUT  Input,
    _Out_ PMYARK_HWID_SPOOF_SET_OUTPUT Output);

//
// GPU class (registry rewrite under the display class key).
// Apply/restore mirror the disk-class contract but the attachment is a
// CmCallback instead of a device stack.
//
NTSTATUS
MyArkHwidSpoofGpuDryRun(
    _In_ PMYARK_HWID_SPOOF_CLASS_STATE State,
    _In_ PUCHAR                        Spoof,
    _In_ ULONG                         SpoofLen,
    _Out_ PUCHAR                       Real,
    _Inout_ PULONG                     RealLen);

NTSTATUS
MyArkHwidSpoofGpuApply(
    _In_     PMYARK_HWID_SPOOF_CLASS_STATE State,
    _In_     PUCHAR                        Spoof,
    _In_     ULONG                         SpoofLen,
    _Out_    PUCHAR                        Real,
    _Inout_  PULONG                        RealLen);

NTSTATUS
MyArkHwidSpoofGpuRestore(
    _In_ PMYARK_HWID_SPOOF_CLASS_STATE State,
    _Out_ PUCHAR                       Real,
    _Inout_ PULONG                     RealLen);

VOID MyArkHwidSpoofGpuTeardown(VOID);

//
// Disk-backed classes (DISK_SERIAL / MOUNTMGR_UID / PARTITION_GUID).
//
NTSTATUS
MyArkHwidSpoofDiskDryRun(
    _In_ PMYARK_HWID_SPOOF_CLASS_STATE State,
    _In_ UINT32                        DiskIndex,
    _In_ PUCHAR                        Spoof,
    _In_ ULONG                         SpoofLen,
    _Out_ PUCHAR                       Real,
    _Inout_ PULONG                     RealLen);

NTSTATUS
MyArkHwidSpoofDiskApply(
    _In_  PMYARK_HWID_SPOOF_CLASS_STATE State,
    _In_  UINT32                        DiskIndex,
    _In_  PUCHAR                        Spoof,
    _In_  ULONG                         SpoofLen,
    _Out_ PUCHAR                        Real,
    _Inout_ PULONG                      RealLen);

NTSTATUS
MyArkHwidSpoofDiskRestore(
    _In_  PMYARK_HWID_SPOOF_CLASS_STATE State,
    _Out_ PUCHAR                       Real,
    _Inout_ PULONG                     RealLen);

//
// Probe a value from below the attachment point (always the hardware
// truth): sends a synchronous device control IRP to the saved target
// device. PASSIVE_LEVEL only.
//
NTSTATUS
MyArkHwidSpoofProbeControl(
    _In_  PDEVICE_OBJECT TargetDevice,
    _In_  ULONG          Ioctl,
    _In_opt_ PVOID       InputBuf,
    _In_  ULONG          InputLen,
    _Out_ PVOID          OutputBuf,
    _In_  ULONG          OutputLen,
    _Out_ PULONG_PTR     Returned);

//
// Class-specific probes: fill Real/RealLen with the current value.
//
NTSTATUS
MyArkHwidSpoofProbeDiskSerial(
    _In_  PDEVICE_OBJECT TargetDevice,
    _Out_ PUCHAR         Real,
    _Inout_ PULONG       RealLen);

//
// Partition identifier probe: GPT -> 16-byte PartitionId of the partition
// device; MBR -> 4-byte disk Signature from the layout on the whole-disk
// device. The spoof value length must match the probed flavor.
//
NTSTATUS
MyArkHwidSpoofProbePartitionId(
    _In_  PDEVICE_OBJECT DiskDevice,
    _In_  PDEVICE_OBJECT PartDevice,
    _Out_ PUCHAR         Real,
    _Inout_ PULONG       RealLen);

NTSTATUS
MyArkHwidSpoofProbeUniqueId(
    _In_  PDEVICE_OBJECT TargetDevice,
    _Out_ PUCHAR         Real,
    _Inout_ PULONG       RealLen);

//
// VPD 0x83 identifier probe (class DEVICE_ID): StorageDeviceIdProperty
// response, first identifier's data bytes.
//
NTSTATUS
MyArkHwidSpoofProbeDeviceId(
    _In_  PDEVICE_OBJECT TargetDevice,
    _Out_ PUCHAR         Real,
    _Inout_ PULONG       RealLen);

//
// ARP class (R3-1b, hwid_spoof_arp.c).
//
// Capture plumbing (bring-up tool): arm/stop the passive NSI request
// ring and read it back through 0x754. The capture attachment doubles
// as the rewrite attachment once a build profile is pinned.
//
NTSTATUS
MyArkHwidSpoofArpCaptureStart(
    _Inout_ PMYARK_HWID_SPOOF_CLASS_STATE State);

VOID
MyArkHwidSpoofArpCaptureStop(
    _Inout_ PMYARK_HWID_SPOOF_CLASS_STATE State);

VOID
MyArkHwidSpoofArpFillCaptureOutput(
    _Out_ PMYARK_HWID_CAPTURE_OUTPUT Output);

//
// Completion path for \Device\Nsi filters (called from the router's
// control completion). CAPTURE mode records the request tuple / dumps
// enumerate-shaped responses; REWRITE mode (class active, build profile
// pinned) rewrites the configured neighbor's MAC bytes in flight.
//
VOID
MyArkHwidArpControlComplete(
    _In_ PMYARK_HWID_FILTER_EXT       Ext,
    _In_opt_ PVOID                    Context,
    _Inout_ PIRP                      Irp);

//
// Per-IRP capture context for the NSI path: METHOD_BUFFERED overwrites
// the input with the response, so the request code + first input bytes
// must be captured at dispatch. Returns a ctx (magic-tagged) or Ext
// itself when allocation fails (fail open, no capture/rewrite).
//
PVOID
MyArkHwidArpCaptureRequestContext(
    _In_ PMYARK_HWID_FILTER_EXT Ext,
    _Inout_ PIRP                Irp,
    _In_ PIO_STACK_LOCATION     Slot);

//
// ARP DRY_RUN/APPLY/RESTORE entry points (profile-gated). Value layout:
// 10 bytes = neighbor IPv4 [0..3] + replacement MAC [4..9]; Real preview
// carries the same 10-byte shape with the current MAC.
//
NTSTATUS
MyArkHwidSpoofArpDryRun(
    _In_ PMYARK_HWID_SPOOF_CLASS_STATE State,
    _In_ PUCHAR                        Spoof,
    _In_ ULONG                         SpoofLen,
    _Out_ PUCHAR                       Real,
    _Inout_ PULONG                     RealLen);

NTSTATUS
MyArkHwidSpoofArpApply(
    _Inout_ PMYARK_HWID_SPOOF_CLASS_STATE State,
    _In_ PUCHAR                           Spoof,
    _In_ ULONG                            SpoofLen,
    _Out_ PUCHAR                          Real,
    _Inout_ PULONG                        RealLen);

NTSTATUS
MyArkHwidSpoofArpRestore(
    _Inout_ PMYARK_HWID_SPOOF_CLASS_STATE State,
    _Out_ PUCHAR                          Real,
    _Inout_ PULONG                        RealLen);

BOOLEAN
MyArkHwidArpProfileAvailable(VOID);

#endif // MYARK_MODULE_HWID
