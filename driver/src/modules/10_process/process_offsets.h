// MyArk: runtime resolution of EPROCESS / ETHREAD offsets.
//
// The 10_process and 11_thread modules walk kernel structures whose field
// offsets move between Windows builds. A single hardcoded table therefore
// only ever works on one build, which is why those modules used to refuse to
// load everywhere else. This resolver makes them build-independent:
//
//   Tier A - exported accessors (PsGetProcessId, PsGetProcessImageFileName,
//            PsGetProcessProtection, PsGetThreadProcess, ...). These exist on
//            every supported Win10/Win11 build, so every field they cover
//            needs no offset at all. Use MYARK_* accessor macros.
//
//   Tier B - the two linked-list offsets that have no accessor
//            (EPROCESS.ActiveProcessLinks, EPROCESS.ThreadListHead and
//            ETHREAD.ThreadListEntry) are DISCOVERED at init time by a
//            self-validating search: a candidate must satisfy the LIST_ENTRY
//            invariant AND its neighbours must be recognised as processes /
//            threads by the exported accessors. A wrong candidate cannot pass
//            both checks, so no per-build table is needed.
//
//   Tier C - purely informational fields (KTHREAD.State/Priority/WaitReason,
//            EPROCESS.Peb/ActiveThreads/Flags2/BasePriority/Affinity, ETHREAD
//            start addresses) have neither an accessor nor a structural role.
//            They come from a per-build profile table when one matches, and
//            read as zero otherwise. Callers must report them as "unknown"
//            rather than failing.

#pragma once

#include <ntddk.h>

//
// ---------------------------------------------------------------------------
// Tier A: exported accessors. Declared here because this WDK's ntddk.h does
// not expose all of them (project policy: ntifs.h is not included). Every one
// is a long-standing ntoskrnl export -- verified against the export tables of
// Windows 10 1903 through Windows 11 24H2.
// ---------------------------------------------------------------------------
//
NTKERNELAPI
HANDLE
PsGetProcessInheritedFromUniqueProcessId(
    _In_ PEPROCESS Process);

NTKERNELAPI
PCHAR
PsGetProcessImageFileName(
    _In_ PEPROCESS Process);

NTKERNELAPI
UCHAR
PsGetProcessSignatureLevel(
    _In_ PEPROCESS Process);

NTKERNELAPI
PVOID
PsGetProcessSectionBaseAddress(
    _In_ PEPROCESS Process);

NTKERNELAPI
HANDLE
PsGetProcessSessionId(
    _In_ PEPROCESS Process);

NTKERNELAPI
PACCESS_TOKEN
PsReferencePrimaryToken(
    _Inout_ PEPROCESS Process);

NTKERNELAPI
VOID
PsDereferencePrimaryToken(
    _Inout_ PACCESS_TOKEN Token);

NTKERNELAPI
PEPROCESS
PsGetThreadProcess(
    _In_ PETHREAD Thread);

//
// Field accessors: use these instead of offsets wherever they exist. They are
// the reason the process/thread views work on any build.
//
#define MYARK_PROC_PID(p)          (HandleToULong(PsGetProcessId(p)))
#define MYARK_PROC_PPID(p)         (HandleToULong(PsGetProcessInheritedFromUniqueProcessId(p)))
#define MYARK_PROC_IMAGE(p)        (PsGetProcessImageFileName(p))
#define MYARK_PROC_SIGLEVEL(p)     (PsGetProcessSignatureLevel(p))
#define MYARK_PROC_SECTION(p)      (PsGetProcessSectionBaseAddress(p))
#define MYARK_PROC_EXITSTATUS(p)   (PsGetProcessExitStatus(p))
#define MYARK_PROC_CREATETIME(p)   (PsGetProcessCreateTimeQuadPart(p))
#define MYARK_THREAD_TID(t)        (HandleToULong(PsGetThreadId(t)))
#define MYARK_THREAD_PROCESS(t)    (PsGetThreadProcess(t))
#define MYARK_THREAD_CREATETIME(t) (PsGetThreadCreateTime(t))

typedef struct _MYARK_ARK_OFFSETS {
    BOOLEAN Valid;                // Tier B discovery succeeded
    ULONG   ActiveProcessLinks;   // EPROCESS.ActiveProcessLinks
    ULONG   ThreadListHead;       // EPROCESS.ThreadListHead
    ULONG   ThreadListEntry;      // ETHREAD.ThreadListEntry
    BOOLEAN ProfileMatched;       // Tier C profile applies to this build
} MYARK_ARK_OFFSETS;

//
// Resolve the offsets for the running build. Idempotent; safe to call from
// every module Init. Uses the calling thread's own process/thread as the
// discovery anchor, so it needs no special context.
//
NTSTATUS
MyArkArkOffsetsInit(
    VOID);

//
// Resolved offsets, or NULL when Init has not run / failed. Callers that
// only need Tier A accessors can ignore this entirely.
//
const MYARK_ARK_OFFSETS*
MyArkArkOffsetsGet(
    VOID);