// MyArk file-monitor module: within-module state + monitor API.

#pragma once

// fltKernel.h MUST come first in every filemon translation unit: it defines
// _NTIFS_INCLUDED_ before pulling ntddk/wdm, which selects the ntifs-flavor
// PEPROCESS/PETHREAD typedefs (ntddk-first ordering is a C2371 conflict).
#include <fltKernel.h>
#include <wdf.h>
#include "../../../shared/driver/MyArkFileMonitorIoctl.h"
#include "../../../shared/driver/MyArkSafetyToken.h"

#if MYARK_MODULE_FILE_MONITOR

#define MYARK_TRACE_FILEMON                  MYARK_TRACE_MODULE

#define MYARK_FILEMON_RING_EVENTS            256   // event slots (power of two)
#define MYARK_FILEMON_POOL_TAG               0x6D4F466D  // 'mF Om' -> "mFOm"

// Monitor state. Everything mutable lives behind StateLock; the only
// lock-free fields are Skipped (interlocked) and VolumesAttached
// (interlocked), which are diagnostics, not protocol state.
typedef struct _MYARK_FILEMON_STATE {
    KSPIN_LOCK        StateLock;
    PFLT_FILTER       Filter;                    // set once registration succeeds
    BOOLEAN           Registered;
    BOOLEAN           Enabled;
    //
    // Armed prefix, uppercase NT sub-path form ("C:\dir" -> "\DIR"), without
    // a trailing separator. Compared against the normalized name after its
    // volume part; component-boundary checked so "\DIR" never matches
    // "\DIRX".
    //
    WCHAR             PrefixSubUc[MYARK_FILEMON_PATH_CHARS];
    UINT16            PrefixSubChars;
    //
    // Event ring. Producers append while holding StateLock; a full ring
    // drops the NEW event and bumps TotalDropped. DRAIN consumes under the
    // same lock.
    //
    PMYARK_FILEMON_EVENT Ring;
    UINT32            WriteIdx;
    UINT32            ReadIdx;
    UINT32            Buffered;
    UINT64            TotalRecorded;
    UINT64            TotalDropped;
    LONG              Skipped;                   // interlocked, no lock
    LONG              VolumesAttached;           // interlocked, no lock
    UINT64            NextSequence;              // under StateLock
    UINT32            StartStage;                // 0 ok; see STATUS protocol
    UINT32            StartStatus;               // NTSTATUS of failed stage
    //
    // R3-7 sampler bypass list (under StateLock): events whose requester
    // PID is listed are dropped before the name query.
    //
    UINT32            BypassPids[MYARK_FILEMON_BYPASS_MAX];
    UINT32            BypassCount;               // 0..MYARK_FILEMON_BYPASS_MAX
    UINT64            BypassDrops;               // lifetime bypassed events
} MYARK_FILEMON_STATE, *PMYARK_FILEMON_STATE;

extern MYARK_FILEMON_STATE g_MyArkFileMon;

// -- monitor core (filemon_monitor.c) --------------------------------------

// Creates Services\MyArkCore\Instances (idempotent) so FltRegisterFilter
// finds instance configuration even though the driver is loaded as a plain
// kernel service instead of by FLTMGR.
NTSTATUS
MyArkFileMonEnsureInstancesKey(
    VOID);

// Registers the filter, starts filtering, zeroes the ring. Never fails the
// module: any stage failure is parked in StartStage/StartStatus (surfaced
// via STATUS) and the module stays alive with Registered=0 so the IOCTL
// surface can still report what went wrong.
VOID
MyArkFileMonStart(
    VOID);

// Disarms, unregisters the filter, frees the ring. Called from module
// Cleanup (PASSIVE_LEVEL, unload context).
VOID
MyArkFileMonStop(
    VOID);

// Applies a CONTROL arm/disarm request (inputs already snapshotted and
// token-checked). Fills the in-band output fields.
NTSTATUS
MyArkFileMonControl(
    _In_ UINT32 Enable,
    _In_ PCWSTR PathPrefix,
    _Out_ PMYARK_FILEMON_CONTROL_OUTPUT Output);

// Copies out up to MaxEvents (0 = buffer-fit) oldest events, consuming
// them. Returns the batch in Output (header + events already written).
NTSTATUS
MyArkFileMonDrain(
    _In_ UINT32 MaxEvents,
    _Out_ PMYARK_FILEMON_DRAIN_OUTPUT Output,
    _In_ SIZE_T OutputBytes,
    _Out_ SIZE_T* BytesReturned);

// Fills a STATUS snapshot.
NTSTATUS
MyArkFileMonQueryStatus(
    _Out_ PMYARK_FILEMON_STATUS_OUTPUT Output);

// R3-7: walks every registered minifilter into the fixed-cap output
// (PASSIVE_LEVEL, IOCTL context). Returns STATUS_SUCCESS even when the
// system has more filters than the cap (Truncated=1).
NTSTATUS
MyArkFileMonEnumFilters(
    _Out_ PMYARK_FILEMON_ENUM_OUTPUT Output);

// R3-7: applies a bypass-list request (Action/Pid already snapshotted;
// token checked by the handler). Fills the in-band output.
NTSTATUS
MyArkFileMonBypass(
    _In_ UINT32 Action,
    _In_ UINT32 Pid,
    _Out_ PMYARK_FILEMON_BYPASS_OUTPUT Output);

// -- IOCTL handlers (filemon_ioctl.c, wired in filemon_descriptor.c) ------

NTSTATUS
MyArkFileMonIoctlControl(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned);

NTSTATUS
MyArkFileMonIoctlDrain(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned);

NTSTATUS
MyArkFileMonIoctlStatus(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned);

NTSTATUS
MyArkFileMonIoctlEnumFilters(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned);

NTSTATUS
MyArkFileMonIoctlBypassPid(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned);

// -- module init/cleanup (filemon_descriptor.c) ----------------------------

NTSTATUS
MyArkFileMonModuleInit(
    VOID);

VOID
MyArkFileMonModuleCleanup(
    VOID);

#endif // MYARK_MODULE_FILE_MONITOR
