// MyArk process module: internal-only definitions shared by the R0 source
// files. Anything the R3 client sees lives in
// ``shared/driver/MyArkProcessIoctl.h``; this header is the within-module
// private vocabulary.

#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "module_descriptor.h"
#include "myark_config.h"
#include "../../../shared/driver/MyArkProcessIoctl.h"

#if MYARK_MODULE_PROCESS

#include "process_offsets.h"

//
// EPROCESS/ETHREAD access strategy (see process_offsets.h):
//   Tier A - the exported accessors below. Build-independent, preferred for
//            every field they cover.
//   Tier B - ActiveProcessLinks / ThreadListHead / ThreadListEntry are
//            DISCOVERED at init (MyArkArkOffsetsGet()), never hardcoded.
//   Tier C - the MYARK_OFF_* constants below are the informational-field
//            profile for Windows 11 24H2 / 25H2 (26100..26299). Outside that
//            window they must not be read: guard with
//            MyArkArkOffsetsGet()->ProfileMatched and report 0/unknown.
//
#define MYARK_OFF_EPROCESS_UNIQUE_PROCESS_ID             0x1D0UL
#define MYARK_OFF_EPROCESS_ACTIVE_PROCESS_LINKS           0x1D8UL
#define MYARK_OFF_EPROCESS_INHERITED_FROM_UNIQUE_PID      0x540UL
#define MYARK_OFF_EPROCESS_IMAGE_FILE_NAME                0x5A8UL
#define MYARK_OFF_EPROCESS_PEB                            0x7C0UL
#define MYARK_OFF_EPROCESS_THREAD_LIST_HEAD               0x5E0UL
#define MYARK_OFF_EPROCESS_FLAGS2                         0x183UL
#define MYARK_OFF_EPROCESS_PROTECTION                     0x6B0UL
#define MYARK_OFF_EPROCESS_CREATE_TIME                    0x580UL
#define MYARK_OFF_EPROCESS_EXIT_STATUS                    0x548UL
#define MYARK_OFF_EPROCESS_ACTIVE_THREADS                 0x5F0UL
#define MYARK_OFF_EPROCESS_BASE_PRIORITY                  0x55CUL
#define MYARK_OFF_EPROCESS_AFFINITY                       0x578UL

//
// ETHREAD Tier C (informational) offsets -- Win11 24H2 / build 26100.x
// profile. Thread id / owner process / create time come from the Tier A
// accessors; only the scheduler-visible detail fields below need offsets.
//
#define MYARK_OFF_ETHREAD_UNIQUE_THREAD_ID                0x4E8UL
#define MYARK_OFF_ETHREAD_THREAD_LIST_ENTRY               0x4F8UL
#define MYARK_OFF_ETHREAD_STATE                           0x044UL
#define MYARK_OFF_ETHREAD_PRIORITY                        0x05CUL
#define MYARK_OFF_ETHREAD_WAIT_REASON                     0x098UL
#define MYARK_OFF_ETHREAD_CREATE_TIME                     0x3B8UL

//
// ETHREAD::Tcb.ApcState.Process -- superseded by MYARK_THREAD_PROCESS()
// (PsGetThreadProcess). Kept only for the 24H2 profile build.
//
#define MYARK_OFF_ETHREAD_APC_STATE_PROCESS               0x178UL

//
// Driver-side caps (defensive: callers can override via Input but never ask
// for an unbounded buffer).
//
#define MYARK_PROCESS_ENUM_MAX_ENTRIES        256
#define MYARK_PROCESS_THREAD_ENUM_MAX_ENTRIES 256

//
// Offsets the cross-view diff uses when comparing the public and kernel
// lists. The 4-byte Pid is enough -- callers do not need the full path
// when diffing.
//
#define MYARK_PROCESS_CROSSVIEW_VIEW_COUNT    3

//
// Tracing helper: assign a stable prefix for process-module lines.
//
#define MYARK_TRACE_PROCESS                   MYARK_TRACE_MODULE

NTSTATUS MyArkProcessInit(VOID);
VOID     MyArkProcessCleanup(VOID);

//
// IOCTL handler prototypes. All conform to MYARK_IOCTL_HANDLER.
//
NTSTATUS MyArkProcessIoctlEnum(
    _In_ WDFDEVICE Device, _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned);

NTSTATUS MyArkProcessIoctlEnumThread(
    _In_ WDFDEVICE Device, _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned);

NTSTATUS MyArkProcessIoctlDetail(
    _In_ WDFDEVICE Device, _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned);

NTSTATUS MyArkProcessIoctlDetailRuntime(
    _In_ WDFDEVICE Device, _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned);

NTSTATUS MyArkProcessIoctlCrossview(
    _In_ WDFDEVICE Device, _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned);

NTSTATUS MyArkProcessIoctlTerminate(
    _In_ WDFDEVICE Device, _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned);

NTSTATUS MyArkProcessIoctlSuspend(
    _In_ WDFDEVICE Device, _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned);

NTSTATUS MyArkProcessIoctlSetPplLevel(
    _In_ WDFDEVICE Device, _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned);

NTSTATUS MyArkProcessIoctlSetIntegrity(
    _In_ WDFDEVICE Device, _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned);

NTSTATUS MyArkProcessIoctlSetVisibility(
    _In_ WDFDEVICE Device, _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned);

NTSTATUS MyArkProcessIoctlSetSpecialFlags(
    _In_ WDFDEVICE Device, _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned);

NTSTATUS MyArkProcessIoctlDkom(
    _In_ WDFDEVICE Device, _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned);

NTSTATUS MyArkProcessIoctlInject(
    _In_ WDFDEVICE Device, _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned);

//
// R3-4: PspCidTable full-table walk + hidden-process join (read-only).
// Implementation in process_cidtable.c.
//
NTSTATUS MyArkProcessIoctlQueryCidTable(
    _In_ WDFDEVICE Device, _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned);

//
// Module descriptor exported via g_AllModules[].
//
extern MYARK_MODULE_DESCRIPTOR g_MyArkModule_Process;


//
// -------------------------------------------------------------------- public
// Cross-file helpers used by the IOCTL handlers / crossview / DKOM. Defined
// in process_query.c and process_detail.c.
//

#define MYARK_PROCESS_PUBLIC_PID_CAP    2048

typedef struct _MYARK_PICKED_PROC {
    ULONG       Pid;
    ULONG       Ppid;
    PVOID       EProcess;
    UCHAR       ImageFileName[MYARK_PROCESS_IMAGE_FILE_NAME_MAX];
    WCHAR       Name[MYARK_PROCESS_NAME_MAX];
} MYARK_PICKED_PROC, *PMYARK_PICKED_PROC;

typedef struct _MYARK_PICKED_LIST {
    ULONG                   Count;
    MYARK_PICKED_PROC       Items[1024];
} MYARK_PICKED_LIST, *PMYARK_PICKED_LIST;

VOID
MyArkProcessFillEntryFromPicked(
    _Out_ PMYARK_PROCESS_ENTRY Entry,
    _In_  PMYARK_PICKED_PROC Picked,
    _In_  UINT8 SourceMask,
    _In_  UINT8 Hidden);

NTSTATUS
MyArkProcessCollectViews(
    _Out_ PMYARK_PICKED_LIST KernelView,
    _Out_writes_(MaxPublic) PULONG PublicPids,
    _In_  ULONG MaxPublic,
    _Out_ PULONG PublicCountOut);

BOOLEAN
MyArkProcessPidIsInActiveLinks(
    _In_ PMYARK_PICKED_LIST KernelView,
    _In_ ULONG Pid);

BOOLEAN
MyArkProcessPidIsInPublicView(
    _In_reads_(PublicCount) const ULONG* PublicPids,
    _In_ ULONG PublicCount,
    _In_ ULONG Pid);

BOOLEAN
MyArkProcessPidIsInPspCidTable(
    _In_ ULONG Pid);

NTSTATUS
MyArkProcessFillDetail(
    _Out_ PMYARK_PROCESS_DETAIL Detail,
    _In_  ULONG Pid);

NTSTATUS
MyArkProcessFillDetailRuntime(
    _Out_ PMYARK_PROCESS_DETAIL_RUNTIME Runtime,
    _In_  ULONG Pid);

//
// Action helpers defined in process_actions.c. The IOCTL handlers in
// process_ioctl.c call these directly so the IOCTL bodies stay thin.
//
NTSTATUS
MyArkProcessPerformTerminate(
    _In_  ULONG  Pid,
    _In_  ULONG  ExitCode,
    _Out_ PULONG StatusOut);

NTSTATUS
MyArkProcessSuspendOrResume(
    _In_ ULONG   Pid,
    _In_ BOOLEAN Resume);

NTSTATUS
MyArkProcessPerformSetPpl(
    _In_  ULONG  Pid,
    _In_  UCHAR  Level,
    _In_  UCHAR  Audit,
    _In_  UCHAR  Type,
    _Out_ PUCHAR PreviousLevelOut);

NTSTATUS
MyArkProcessPerformSetIntegrity(
    _In_  ULONG  Pid,
    _In_  ULONG  IntegrityLevel,
    _Out_ PULONG PreviousIntegrityOut);

NTSTATUS
MyArkProcessPerformDkom(
    _In_  ULONG   Pid,
    _In_  BOOLEAN Hide,
    _Out_ PUCHAR  VisibilityStateOut);

NTSTATUS
MyArkProcessPerformSetSpecialFlags(
    _In_  ULONG  Pid,
    _In_  ULONG  Mask,
    _In_  ULONG  Value,
    _Out_ PULONG PreviousFlagsOut);

NTSTATUS
MyArkProcessPerformInject(
    _In_            ULONG  Pid,
    _In_            ULONG  Method,
    _In_reads_(PathChars) PCWSTR DllPath,
    _In_            ULONG  PathChars,
    _Out_           PULONG StatusOut);

#endif // MYARK_MODULE_PROCESS