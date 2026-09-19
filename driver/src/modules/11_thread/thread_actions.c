// MyArk thread module: thread-mutating operations (TERMINATE).
//
// S6.2 ships the R0 side of the terminate primitive; S8.1 (actions) wires
// the R3-first / R0-fallback chain and adds the audit trail.
//
// The kernel-mode primitive to terminate a thread you don't own is
// PspTerminateThreadByPointer, which is exported by ntoskrnl.exe but not
// declared in the public WDK headers (it's a Psp* internal). We resolve it
// at module init time via MmGetSystemRoutineAddress and call it from the
// IOCTL handler. If the resolution fails (older Windows, or the symbol is
// retired), the handler returns STATUS_NOT_IMPLEMENTED so the R3 fallback
// (OpenThread + TerminateThread) is used.

#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>
#include "Trace.h"
#include "thread_internal.h"

#if MYARK_MODULE_THREAD

NTSTATUS PsLookupThreadByThreadId(_In_ HANDLE ThreadId, _Outptr_ PETHREAD* Thread);

NTSTATUS ObOpenObjectByPointer(
    _In_ PVOID Object,
    _In_ ULONG HandleAttributes,
    _In_opt_ PVOID PassedAccessState,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_TYPE ObjectType,
    _In_ KPROCESSOR_MODE AccessMode,
    _Out_ PHANDLE Handle);

extern POBJECT_TYPE *PsThreadType;

//
// Undocumented kernel export: PspTerminateThreadByPointer(ETHREAD, NTSTATUS, BOOLEAN).
// The third argument is TRUE for an immediate / forceful termination; FALSE
// is the graceful path that lets the thread unwind its APC state first.
// Resolved once at module init via MmGetSystemRoutineAddress.
//
typedef NTSTATUS (*PFN_PSP_TERMINATE_THREAD_BY_POINTER)(
    _In_ PETHREAD Thread,
    _In_ NTSTATUS ExitStatus,
    _In_ BOOLEAN  DirectTerminate);

static PFN_PSP_TERMINATE_THREAD_BY_POINTER g_MyArkThreadPspTerminateByPointer = NULL;


//
// ----------------------------------------------------------------- helpers

NTSTATUS
MyArkThreadResolveTerminator(
    VOID)
//
// One-shot resolver for PspTerminateThreadByPointer. Called lazily from
// the terminate IOCTL handler so a missing symbol doesn't prevent the rest
// of the module from linking.
//
{
    if (g_MyArkThreadPspTerminateByPointer != NULL) {
        return STATUS_SUCCESS;
    }

    UNICODE_STRING name;
    RtlInitUnicodeString(&name, L"PspTerminateThreadByPointer");
    g_MyArkThreadPspTerminateByPointer =
        (PFN_PSP_TERMINATE_THREAD_BY_POINTER)MmGetSystemRoutineAddress(&name);

    if (g_MyArkThreadPspTerminateByPointer == NULL) {
        return STATUS_NOT_IMPLEMENTED;
    }
    return STATUS_SUCCESS;
}


//
// ----------------------------------------------------------------- TERMINATE

NTSTATUS
MyArkThreadPerformTerminate(
    _In_  ULONG  Tid,
    _In_  ULONG  ExitCode,
    _Out_ PULONG StatusOut)
//
// Best-effort terminate: resolve the TID to an ETHREAD and dispatch to
// PspTerminateThreadByPointer. When the routine isn't resolvable the
// handler returns STATUS_NOT_IMPLEMENTED -- the R3 client falls back to
// OpenThread + TerminateThread on a STATUS_NOT_IMPLEMENTED result.
//
// Note: terminating a system thread (PID 4 / "System") will BSOD the box.
// Callers must restrict to user-mode threads (e.g. by checking the owning
// PID is not 4 / "System" via the crossview detail) before issuing this
// IOCTL.
//
{
    NTSTATUS status;
    PETHREAD thread = NULL;

    *StatusOut = (ULONG)STATUS_NOT_FOUND;

    if (Tid == 0) {
        *StatusOut = (ULONG)STATUS_INVALID_PARAMETER;
        return STATUS_INVALID_PARAMETER;
    }

    status = MyArkThreadResolveTerminator();
    if (!NT_SUCCESS(status)) {
        *StatusOut = (ULONG)STATUS_NOT_IMPLEMENTED;
        return STATUS_NOT_IMPLEMENTED;
    }

    status = PsLookupThreadByThreadId(UlongToHandle(Tid), &thread);
    if (!NT_SUCCESS(status) || thread == NULL) {
        *StatusOut = (ULONG)STATUS_NOT_FOUND;
        return STATUS_NOT_FOUND;
    }

    status = g_MyArkThreadPspTerminateByPointer(thread,
                                                (NTSTATUS)ExitCode,
                                                /* DirectTerminate */ TRUE);
    ObDereferenceObject(thread);

    *StatusOut = (ULONG)status;
    return status;
}

#endif // MYARK_MODULE_THREAD
