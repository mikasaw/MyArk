// MyArk thread module: shared IOCTL protocol between R0 and R3.
//
// Function range 0xA10..0xA1F reserved for the thread module. Process
// uses 0xA00..0xA0C, so thread sits in the next free sub-block. All 5
// IOCTLs follow the MyArk METHOD_BUFFERED convention (matching the rest
// of the driver).
//
// Cross-view semantics (S6.2 acceptance criteria):
//   public       = ZwQuerySystemInformation(SystemProcessInformation) +
//                 toolhelp-style ThreadList per process
//   thread_list  = EPROCESS.ThreadListHead traversal
//   pspcidtable  = kernel handle table (PsLookupThreadByThreadId)
//
// A thread that is in ThreadListHead + PspCidTable but NOT in the public
// view is flagged HIDDEN_VIA_DKOM. DKOM hide preserves the PspCidTable
// record so the thread remains auditable.
//
// ETHREAD field offsets are hardcoded for Windows 11 24H2 / build
// 26100.x; S7.1 (DynData) will replace them with a runtime-loaded
// profile. Offsets are documented in thread_internal.h.

#pragma once

#include <ntddk.h>
#include <wdf.h>

// ---------------------------------------------------------------------------
// Module identity + IOCTL function codes.
// ---------------------------------------------------------------------------

#define MYARK_THREAD_MODULE_ID              0x44524854UL  // 'THRD' ASCII (LE)
#define MYARK_THREAD_MODULE_NAME_MAX        64
#define MYARK_THREAD_DEFAULT_MAX            256
#define MYARK_THREAD_HARD_CAP               4096

//
// 5 IOCTLs (function range 0xA10..0xA14). Method/Access match the rest of
// the driver: METHOD_BUFFERED + FILE_ANY_ACCESS.
//
#define IOCTL_MYARK_THREAD_ENUM \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA10, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_THREAD_DETAIL \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA11, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_THREAD_DETAIL_RUNTIME \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA12, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_THREAD_CROSSVIEW \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA13, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_THREAD_TERMINATE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA14, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ---------------------------------------------------------------------------
// Source mask used by crossview / enum / detail to mark which views saw the
// row. Bits align with the three-view model.
// ---------------------------------------------------------------------------

#define MYARK_THREAD_SRC_NONE               0x00
#define MYARK_THREAD_SRC_PUBLIC             0x01   // ZwQuerySystemInformation
#define MYARK_THREAD_SRC_THREADLIST         0x02   // EPROCESS.ThreadListHead
#define MYARK_THREAD_SRC_PSPCIDTABLE        0x04   // kernel handle table

#define MYARK_THREAD_HIDDEN_NONE            0x00
#define MYARK_THREAD_HIDDEN_VIA_DKOM        0x01   // in kernel + thread_list, not public

//
// Anomaly flags. Set in MYARK_THREAD_ENTRY.Anomaly when the driver-side
// checks (currently: StartAddress ownership) find something off.
//
#define MYARK_THREAD_ANOMALY_NONE                       0x00
#define MYARK_THREAD_ANOMALY_START_OUTSIDE_MODULE       0x01

// ---------------------------------------------------------------------------
// ENUM: list threads of a single process.
//
// Caller passes a Pid; the driver walks EPROCESS.ThreadListHead and returns
// every ETHREAD with its minimal snapshot (Tid / OwnerPid / StartAddress /
// owning module / State).
// ---------------------------------------------------------------------------

typedef struct _MYARK_THREAD_ENTRY {
    UINT32  Tid;
    UINT32  Pid;
    UINT64  StartAddress;
    WCHAR   Module[MYARK_THREAD_MODULE_NAME_MAX];   // base name of the module owning StartAddress
    UINT8   State;                                  // KTHREAD_STATE (Running/Ready/Waiting/...)
    UINT8   Anomaly;                                // MYARK_THREAD_ANOMALY_*
    UINT8   Reserved0;
    UINT8   Reserved1;
    UINT32  Priority;
    UINT32  WaitReason;                             // KWAIT_REASON (only meaningful when Waiting)
    UINT64  CreateTime;                             // KeQuerySystemTime tick at thread create
    UINT64  EThreadKernelAddress;                   // kernel virtual address of the ETHREAD (debug aid)
} MYARK_THREAD_ENTRY, *PMYARK_THREAD_ENTRY;

typedef struct _MYARK_THREAD_ENUM_INPUT {
    UINT32  Pid;                                    // target process; 0 = current process (PsGetCurrentProcess)
    UINT32  MaxEntries;                             // 0 = use driver-side cap (default 256)
    UINT32  Reserved0;
    UINT32  Reserved1;
} MYARK_THREAD_ENUM_INPUT, *PMYARK_THREAD_ENUM_INPUT;

typedef struct _MYARK_THREAD_ENUM_OUTPUT {
    UINT32  Size;
    UINT32  Count;
    UINT32  OwnerPid;                               // echoes the input Pid
    UINT32  AnomalyCount;                           // entries flagged MYARK_THREAD_ANOMALY_*
    MYARK_THREAD_ENTRY Entries[1];                  // variable length
} MYARK_THREAD_ENUM_OUTPUT, *PMYARK_THREAD_ENUM_OUTPUT;

// ---------------------------------------------------------------------------
// DETAIL: one thread, deep field dump.
//
// Output struct layout mirrors MYARK_PROCESS_DETAIL: every fixed field is
// an ETHREAD snapshot; the wide string slots describe the StartAddress /
// owning module path.
// ---------------------------------------------------------------------------

typedef struct _MYARK_THREAD_DETAIL {
    UINT32  Tid;
    UINT32  OwnerPid;
    UINT32  State;
    UINT32  Priority;
    UINT32  BasePriority;
    UINT32  WaitReason;
    UINT32  Anomaly;
    UINT32  Reserved0;
    UINT64  CreateTime;
    UINT64  StartAddress;
    UINT64  Win32StartAddress;                      // user-mode start (if it has one)
    UINT64  EThreadKernelAddress;
    UINT64  EProcessKernelAddress;
    UINT32  UniqueThreadIdOffset;                   // offset that produced Tid (debug aid)
    UINT32  ThreadListEntryOffset;
    UINT32  StateOffset;
    UINT32  PriorityOffset;
    UINT32  WaitReasonOffset;
    UINT32  CreateTimeOffset;
    UINT32  StartAddressOffset;
    UINT32  ApcStateProcessOffset;
    WCHAR   Module[MYARK_THREAD_MODULE_NAME_MAX];
    WCHAR   StartAddressModulePath[260];            // device path of the module owning StartAddress
} MYARK_THREAD_DETAIL, *PMYARK_THREAD_DETAIL;

// ---------------------------------------------------------------------------
// DETAIL_RUNTIME: extra runtime stats that cost more to compute.
//
// Returned as a single struct. Drivers fill what they can; the rest stays 0.
// ---------------------------------------------------------------------------

typedef struct _MYARK_THREAD_DETAIL_RUNTIME {
    UINT32  Tid;
    UINT32  Reserved0;
    UINT64  KernelTime;                             // ticks consumed in kernel mode
    UINT64  UserTime;                               // ticks consumed in user mode
    UINT64  CycleTime;                              // CPU cycles consumed
    UINT32  ContextSwitches;                        // voluntary + involuntary (best-effort)
    UINT32  Reserved1;
    UINT32  StateFlags;                             // KTHREAD flags (best-effort)
    UINT32  Reserved2;
} MYARK_THREAD_DETAIL_RUNTIME, *PMYARK_THREAD_DETAIL_RUNTIME;

// ---------------------------------------------------------------------------
// CROSSVIEW: same row as enum but SourceMask tells which of the 3 views saw
// the TID. Output format identical to ENUM so the R3 parser can reuse code.
// ---------------------------------------------------------------------------

typedef struct _MYARK_THREAD_CROSSVIEW_INPUT {
    UINT32  Tid;                                    // 0 = every thread of every PID the driver saw; non-zero = filter
    UINT32  Reserved0;
    UINT32  Reserved1;
    UINT32  Reserved2;
} MYARK_THREAD_CROSSVIEW_INPUT, *PMYARK_THREAD_CROSSVIEW_INPUT;

typedef struct _MYARK_THREAD_CROSSVIEW_OUTPUT {
    UINT32  Size;
    UINT32  Count;
    UINT32  HiddenCount;                           // rows flagged HIDDEN_VIA_DKOM
    UINT32  PublicOnly;                            // TIDs in public view but not in kernel
    MYARK_THREAD_ENTRY Entries[1];
} MYARK_THREAD_CROSSVIEW_OUTPUT, *PMYARK_THREAD_CROSSVIEW_OUTPUT;

// ---------------------------------------------------------------------------
// TERMINATE_THREAD: best-effort kill of one thread.
//
// R3 fallback (OpenThread + TerminateThread) runs first; the driver-side
// helper here is invoked only when the R3 attempt is blocked (e.g. PPL
// protected process). Both paths are acknowledged via UsedR0Fallback.
// ---------------------------------------------------------------------------

typedef struct _MYARK_THREAD_TERMINATE_INPUT {
    UINT32  Tid;                                    // target thread
    UINT32  ExitCode;                               // user-defined exit code (only meaningful for R3 fallback)
    UINT32  Force;                                  // non-zero = skip graceful path
    UINT32  Reserved;
} MYARK_THREAD_TERMINATE_INPUT, *PMYARK_THREAD_TERMINATE_INPUT;

typedef struct _MYARK_THREAD_TERMINATE_OUTPUT {
    UINT32  Tid;
    UINT32  Status;                                 // NTSTATUS
    UINT32  UsedR0Fallback;                         // 1 = driver did the kill, 0 = R3 fallback path
    UINT32  Reserved;
} MYARK_THREAD_TERMINATE_OUTPUT, *PMYARK_THREAD_TERMINATE_OUTPUT;
