// MyArk thread module: within-module offsets + helpers.
//
// ETHREAD / KTHREAD field offsets are hardcoded for Windows 11 24H2 / build
// 26100.x. S7.1 (DynData) replaces them with a runtime-loaded profile.
//
// ETHREAD (Win11 24H2) field layout used by this module:
//
//   0x044  State             -- KTHREAD_STATE byte
//   0x05C  Priority          -- KPRIORITY byte
//   0x098  WaitReason        -- KWAIT_REASON byte
//   0x178  ApcState.Process  -- PETHREAD / PEPROCESS pointer
//   0x3B8  CreateTime        -- LARGE_INTEGER (8 bytes)
//   0x4E8  UniqueThreadId    -- HANDLE / NT_TID
//   0x4F8  ThreadListEntry   -- LIST_ENTRY (8 bytes; Flink/Blink)
//   0x4F0  StartAddress      -- PVOID (kernel-mode start)
//   0x508  Win32StartAddress -- PVOID (user-mode start, may be NULL)
//
// All reads go through MmIsAddressValid so a stale ETHREAD (e.g. a thread
// that exited between the lookup and the field read) does not blue-screen
// the VM. The caller has already done a PsLookupThreadByThreadId so the
// structure itself is alive when the helpers read it.

#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "module_descriptor.h"
#include "myark_config.h"
#include "../../../shared/driver/MyArkThreadIoctl.h"

#if MYARK_MODULE_THREAD

#include "../10_process/process_offsets.h"

//
// Tier A accessors (build-independent) for the thread fields the kernel
// exports. ETHREAD.ThreadListEntry comes from MyArkArkOffsetsGet(); the
// remaining MYARK_OFF_ETHREAD_* constants are the 24H2 informational profile
// and must only be read when ProfileMatched is set.
//
//
// ETHREAD Tier C offsets (Win11 24H2 / build 26100.x profile).
//
#define MYARK_OFF_ETHREAD_UNIQUE_THREAD_ID                0x4E8UL
#define MYARK_OFF_ETHREAD_THREAD_LIST_ENTRY               0x4F8UL
#define MYARK_OFF_ETHREAD_STATE                           0x044UL
#define MYARK_OFF_ETHREAD_PRIORITY                        0x05CUL
#define MYARK_OFF_ETHREAD_BASE_PRIORITY                   0x03AUL
#define MYARK_OFF_ETHREAD_WAIT_REASON                     0x098UL
#define MYARK_OFF_ETHREAD_CREATE_TIME                     0x3B8UL
#define MYARK_OFF_ETHREAD_APC_STATE_PROCESS               0x178UL
#define MYARK_OFF_ETHREAD_START_ADDRESS                   0x4F0UL
#define MYARK_OFF_ETHREAD_WIN32_START_ADDRESS             0x508UL

//
// EPROCESS offsets we re-use from process_internal.h conceptually; re-declare
// just what the thread helpers need so this header stays self-contained.
//
#define MYARK_EP_OFF_THREAD_LIST_HEAD                     0x5E0UL
#define MYARK_EP_OFF_UNIQUE_PROCESS_ID                    0x1D0UL
#define MYARK_EP_OFF_IMAGE_FILE_NAME                      0x5A8UL

//
// Driver-side caps.
//
#define MYARK_THREAD_ENUM_MAX_ENTRIES        256
#define MYARK_THREAD_CROSSVIEW_VIEW_COUNT    3
#define MYARK_THREAD_PUBLIC_TID_CAP          16384

//
// Maximum number of modules we cache for the StartAddress ownership check.
// The PsLoadedModuleList on a typical VM is a few hundred; cap at 1024 so
// the cached array fits in a single paged allocation.
//
#define MYARK_THREAD_MODULE_CACHE_MAX        1024

//
// Tracing helper: assign a stable prefix for thread-module lines.
//
#define MYARK_TRACE_THREAD                   MYARK_TRACE_MODULE

//
// Public / kernel-view record types used by the three-view walk.
//
//
// Snapshot of one thread. The scheduler-visible fields are captured HERE
// (not read later through a stored pointer) so the collector can release the
// ETHREAD reference immediately: the TID-scan enumerator holds a reference
// per thread and must not keep it beyond the row it produced.
//
typedef struct _MYARK_PICKED_THREAD {
    ULONG       Tid;
    ULONG       OwnerPid;
    PVOID       EThread;            // address only, for reporting
    UINT64      StartAddress;       // Tier C (profile only)
    UINT64      CreateTime;         // Tier A accessor
    UINT8       State;              // Tier C (profile only)
    UINT8       Priority;           // Tier C (profile only)
    UINT8       WaitReason;         // Tier C (profile only)
} MYARK_PICKED_THREAD, *PMYARK_PICKED_THREAD;

typedef struct _MYARK_PICKED_THREAD_LIST {
    ULONG                   Count;
    MYARK_PICKED_THREAD     Items[MYARK_THREAD_ENUM_MAX_ENTRIES];
} MYARK_PICKED_THREAD_LIST, *PMYARK_PICKED_THREAD_LIST;

typedef struct _MYARK_PUBLIC_THREAD_RECORD {
    ULONG   Tid;
    ULONG   Pid;
} MYARK_PUBLIC_THREAD_RECORD, *PMYARK_PUBLIC_THREAD_RECORD;

typedef struct _MYARK_PUBLIC_THREAD_SET {
    ULONG                       Count;
    MYARK_PUBLIC_THREAD_RECORD  Items[MYARK_THREAD_PUBLIC_TID_CAP];
} MYARK_PUBLIC_THREAD_SET, *PMYARK_PUBLIC_THREAD_SET;

//
// Module-global working buffers for the view collectors (defined in
// thread_ioctl.c). Sequential device queue => single-threaded use.
//
extern MYARK_PICKED_THREAD_LIST g_ThreadPickedList;
extern MYARK_PUBLIC_THREAD_SET  g_ThreadPublicSet;


//
// Module range cache populated at driver_entry (via the module Init). The
// cross-view + enum helpers look the StartAddress up against this cache.
//
typedef struct _MYARK_MODULE_RANGE {
    UINT64      Base;
    UINT64      End;
    WCHAR       Name[MYARK_THREAD_MODULE_NAME_MAX];
} MYARK_MODULE_RANGE, *PMYARK_MODULE_RANGE;

typedef struct _MYARK_MODULE_RANGE_CACHE {
    ULONG                   Count;
    MYARK_MODULE_RANGE      Ranges[MYARK_THREAD_MODULE_CACHE_MAX];
} MYARK_MODULE_RANGE_CACHE, *PMYARK_MODULE_RANGE_CACHE;

extern MYARK_MODULE_RANGE_CACHE g_MyArkThreadModuleRanges;

//
// NTSTATUS helper.
//
NTSTATUS MyArkThreadInit(VOID);
VOID     MyArkThreadCleanup(VOID);

//
// IOCTL handler prototypes. All conform to MYARK_IOCTL_HANDLER.
//
NTSTATUS MyArkThreadIoctlEnum(
    _In_ WDFDEVICE Device, _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned);

NTSTATUS MyArkThreadIoctlDetail(
    _In_ WDFDEVICE Device, _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned);

NTSTATUS MyArkThreadIoctlDetailRuntime(
    _In_ WDFDEVICE Device, _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned);

NTSTATUS MyArkThreadIoctlCrossview(
    _In_ WDFDEVICE Device, _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned);

NTSTATUS MyArkThreadIoctlTerminate(
    _In_ WDFDEVICE Device, _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned);

//
// Cross-file helpers.
//
VOID
MyArkThreadCopyModuleName(
    _Out_writes_(DestChars) PWCHAR Dest,
    _In_ size_t DestChars,
    _In_opt_ PCWSTR Source);

UINT8
MyArkThreadClassifyStartAddress(
    _In_ UINT64 StartAddress,
    _Out_writes_(DestChars) PWCHAR ModuleName,
    _In_ size_t DestChars);

NTSTATUS
MyArkThreadCollectViews(
    _In_  ULONG  Pid,
    _Out_ PMYARK_PICKED_THREAD_LIST KernelView,
    _Out_ PMYARK_PUBLIC_THREAD_SET  PublicSet);

NTSTATUS
MyArkThreadFillEntry(
    _Out_ PMYARK_THREAD_ENTRY Entry,
    _In_  PETHREAD EThread);

NTSTATUS
MyArkThreadFillDetail(
    _Out_ PMYARK_THREAD_DETAIL Detail,
    _In_  ULONG Tid);

NTSTATUS
MyArkThreadFillDetailRuntime(
    _Out_ PMYARK_THREAD_DETAIL_RUNTIME Runtime,
    _In_  ULONG Tid);

NTSTATUS
MyArkThreadBuildCrossview(
    _In_  ULONG  Pid,
    _In_  ULONG  TidFilter,
    _Out_writes_bytes_to_(BufferSize, *BytesUsed) PUCHAR Buffer,
    _In_  ULONG  BufferSize,
    _Out_ PULONG BytesUsed,
    _Out_ PULONG HiddenCountOut);

NTSTATUS
MyArkThreadPerformTerminate(
    _In_  ULONG  Tid,
    _In_  ULONG  ExitCode,
    _Out_ PULONG StatusOut);

//
// Module descriptor exported via g_AllModules[].
//
extern MYARK_MODULE_DESCRIPTOR g_MyArkModule_Thread;

#endif // MYARK_MODULE_THREAD
