// MyArk process module: process-mutating operations (TERMINATE / SUSPEND /
// DKOM / set-PPL / set-integrity / set-visibility / set-special-flags /
// inject).
//
// S6.1 ships the R0 side of every operation as a standalone primitive;
// S8.1 (actions) wires the R3-first / R0-fallback chain and adds the audit
// trail. Each helper here returns STATUS_SUCCESS when the underlying kernel
// API accepted the request, regardless of higher-level audit metadata.

#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>
#include "Trace.h"
#include "process_internal.h"

#if MYARK_MODULE_PROCESS

//
// Forward decls for IFS-style kernel exports not in the WDM surface that
// ntddk.h pulls in. Keeping them here means the .c file compiles regardless
// of header ordering, and avoids the ntifs.h vs wdm.h PEPROCESS redefinition
// trap that bit the project on first try.
//
NTSTATUS PsLookupProcessByProcessId(_In_ HANDLE ProcessId, _Outptr_ PEPROCESS* Process);
NTSTATUS PsSuspendProcess(_In_ PEPROCESS Process);
NTSTATUS PsResumeProcess(_In_ PEPROCESS Process);

#define PROCESS_TERMINATE 0x0001

NTSTATUS
ObOpenObjectByPointer(
    _In_ PVOID Object,
    _In_ ULONG HandleAttributes,
    _In_opt_ PVOID PassedAccessState,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_TYPE ObjectType,
    _In_ KPROCESSOR_MODE AccessMode,
    _Out_ PHANDLE Handle);

extern POBJECT_TYPE *PsProcessType;


//
// ----------------------------------------------------------------- helpers


static
NTSTATUS
MyArkProcessResolveEProcessNoUnref(
    _In_  ULONG   Pid,
    _Out_ PVOID*  EProcessOut)
//
// Like process_detail.c's resolve, but keeps the reference. Caller is
// responsible for the matching ObDereferenceObject.
//
{
    NTSTATUS  status;
    PEPROCESS proc = NULL;

    status = PsLookupProcessByProcessId(UlongToHandle(Pid), &proc);
    if (!NT_SUCCESS(status) || proc == NULL) {
        return STATUS_NOT_FOUND;
    }
    *EProcessOut = proc;
    return STATUS_SUCCESS;
}


//
// ----------------------------------------------------------------- TERMINATE

NTSTATUS
MyArkProcessPerformTerminate(
    _In_ ULONG Pid,
    _In_ ULONG ExitCode,
    _Out_ PULONG StatusOut)
//
// Best-effort terminate: we open a kernel handle to the target EPROCESS
// with PROCESS_TERMINATE and call ZwTerminateProcess. That wrapper reaches
// the kernel's PsTerminateSystemThread-style path which tears down every
// thread of the target on Win8+.
//
{
    NTSTATUS  status;
    PEPROCESS proc = NULL;

    *StatusOut = (ULONG)STATUS_NOT_FOUND;

    status = MyArkProcessResolveEProcessNoUnref(Pid, &proc);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    HANDLE h = NULL;
    NTSTATUS openStatus = ObOpenObjectByPointer(proc,
                                                OBJ_KERNEL_HANDLE,
                                                NULL,
                                                PROCESS_TERMINATE,
                                                *PsProcessType,
                                                KernelMode,
                                                &h);
    if (!NT_SUCCESS(openStatus) || h == NULL) {
        ObDereferenceObject(proc);
        *StatusOut = (ULONG)STATUS_ACCESS_DENIED;
        return STATUS_ACCESS_DENIED;
    }

    status = ZwTerminateProcess(h, (NTSTATUS)ExitCode);
    ZwClose(h);
    ObDereferenceObject(proc);

    *StatusOut = (ULONG)status;
    return status;
}


//
// ----------------------------------------------------------------- SUSPEND


NTSTATUS
MyArkProcessSuspendOrResume(
    _In_ ULONG   Pid,
    _In_ BOOLEAN Resume)
//
// NtSuspendProcess / NtResumeProcess are kernel-exported. Both take an
// already-referenced EPROCESS so we resolve via PsLookupProcessByProcessId
// before calling them.
//
{
    NTSTATUS  status;
    PEPROCESS proc = NULL;

    status = MyArkProcessResolveEProcessNoUnref(Pid, &proc);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (Resume) {
        status = PsResumeProcess(proc);
    } else {
        status = PsSuspendProcess(proc);
    }

    ObDereferenceObject(proc);
    return status;
}


//
// ----------------------------------------------------------------- DKOM hide


NTSTATUS
MyArkProcessPerformDkom(
    _In_ ULONG   Pid,
    _In_ BOOLEAN Hide,
    _Out_ PUCHAR VisibilityStateOut)
//
// Splice the target EPROCESS in / out of the ActiveProcessLinks list.
//
//   Hide    -- remove the entry (unlink Flink/Blink around it, leaving
//              the entry's own links alone). The process stays in
//              PspCidTable (handle table) so it is auditable; only the
//              public / kernel-walk view loses it.
//
//   Restore -- splice back into the list at the head, immediately after
//              PsInitialSystemProcess. The original neighbours may have
//              moved on, so we don't try to recover the exact position --
//              appending at the head keeps the list consistent.
//
// VisibilityStateOut reports the resulting state (1 == hidden, 0 == visible).
//
{
    NTSTATUS    status;
    PEPROCESS   proc = NULL;
    const MYARK_ARK_OFFSETS* offsets = MyArkArkOffsetsGet();
    ULONG       linksOffset;

    *VisibilityStateOut = 0;

    //
    // The ActiveProcessLinks offset MUST come from the Tier B runtime
    // discovery (the same source the ENUM walk uses). The Tier C constant
    // (0x1D8) is 26100-only and points at unrelated EPROCESS fields on
    // other builds -- writing through it is an instant kernel AV
    // (bugchecked 0x3B on 18362, see tests/CRASH_DEBUG_LOG.md R3-4).
    //
    if (offsets == NULL || !offsets->Valid) {
        return STATUS_NOT_SUPPORTED;
    }
    linksOffset = offsets->ActiveProcessLinks;

    status = MyArkProcessResolveEProcessNoUnref(Pid, &proc);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    PLIST_ENTRY target = (PLIST_ENTRY)((PUCHAR)proc + linksOffset);

    if (Hide) {
        //
        // Sanity check: target->Flink / target->Blink must point to real
        // list entries. If not, the EPROCESS has already been corrupted
        // and we should refuse rather than make things worse.
        //
        if (!MmIsAddressValid(target->Flink) || !MmIsAddressValid(target->Blink)) {
            ObDereferenceObject(proc);
            return STATUS_UNSUCCESSFUL;
        }
        target->Blink->Flink = target->Flink;
        target->Flink->Blink = target->Blink;
        *VisibilityStateOut = 1;
    } else {
        //
        // Restore: walk to PsInitialSystemProcess and append.
        //
        PVOID seed = PsInitialSystemProcess;
        if (seed == NULL) {
            ObDereferenceObject(proc);
            return STATUS_UNSUCCESSFUL;
        }
        PLIST_ENTRY seedLink = (PLIST_ENTRY)((PUCHAR)seed
                                             + linksOffset);
        target->Flink = seedLink->Flink;
        target->Blink = seedLink;
        seedLink->Flink->Blink = target;
        seedLink->Flink = target;
        *VisibilityStateOut = 0;
    }

    ObDereferenceObject(proc);
    return STATUS_SUCCESS;
}


//
// ----------------------------------------------------------------- PPL / Integrity / Flags2


NTSTATUS
MyArkProcessPerformSetPpl(
    _In_  ULONG  Pid,
    _In_  UCHAR  Level,
    _In_  UCHAR  Audit,
    _In_  UCHAR  Type,
    _Out_ PUCHAR PreviousLevelOut)
//
// Write EPROCESS.Protection.Level byte. The wider PS_PROTECTION struct
// has 3 visible bytes (Type, Audit, Level); we currently only update Level
// because the acceptance test focuses on that field.
//
{
    NTSTATUS  status;
    PEPROCESS proc = NULL;

    *PreviousLevelOut = 0;

    status = MyArkProcessResolveEProcessNoUnref(Pid, &proc);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    PUCHAR protByte = (PUCHAR)proc + MYARK_OFF_EPROCESS_PROTECTION;
    if (!MmIsAddressValid(protByte)) {
        ObDereferenceObject(proc);
        return STATUS_UNSUCCESSFUL;
    }

    *PreviousLevelOut = *protByte;

    //
    // PS_PROTECTION layout (single byte): bits [2:0] = Level, [3] = Audit,
    // [6:5] = Type. We assemble the new byte and write it back atomically.
    //
    UCHAR newByte = (UCHAR)((Level & 0x07)
                            | ((Audit & 0x01) << 3)
                            | ((Type  & 0x03) << 5));

    KIRQL oldIrql = KeRaiseIrqlToDpcLevel();
    *protByte = newByte;
    KeLowerIrql(oldIrql);

    ObDereferenceObject(proc);
    return STATUS_SUCCESS;
}


NTSTATUS
MyArkProcessPerformSetIntegrity(
    _In_  ULONG  Pid,
    _In_  ULONG  IntegrityLevel,
    _Out_ PULONG PreviousIntegrityOut)
//
// Token integrity write is non-trivial: the token lives in a SEP_TOKEN
// substructure with its own locking rules. For S6.1 we record the request
// and return STATUS_NOT_IMPLEMENTED -- S8.1 actions module owns the full
// token-edit chain (R3 OpenProcessToken + SetTokenInformationToken +
// R0 fallback). The PreviousIntegrityOut stays 0.
//
{
    UNREFERENCED_PARAMETER(Pid);
    UNREFERENCED_PARAMETER(IntegrityLevel);

    *PreviousIntegrityOut = 0;
    return STATUS_NOT_IMPLEMENTED;
}


NTSTATUS
MyArkProcessPerformSetSpecialFlags(
    _In_  ULONG  Pid,
    _In_  ULONG  Mask,
    _In_  ULONG  Value,
    _Out_ PULONG PreviousFlagsOut)
//
// Mask-and-set EPROCESS.Flags2 (Debug, Protected, etc). Caller supplies
// the mask of bits to touch; non-masked bits are preserved.
//
{
    NTSTATUS  status;
    PEPROCESS proc = NULL;

    *PreviousFlagsOut = 0;

    status = MyArkProcessResolveEProcessNoUnref(Pid, &proc);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    PULONG flags = (PULONG)((PUCHAR)proc + MYARK_OFF_EPROCESS_FLAGS2);
    if (!MmIsAddressValid(flags)) {
        ObDereferenceObject(proc);
        return STATUS_UNSUCCESSFUL;
    }

    *PreviousFlagsOut = *flags;

    ULONG newValue = (*flags & ~Mask) | (Value & Mask);

    KIRQL oldIrql = KeRaiseIrqlToDpcLevel();
    *flags = newValue;
    KeLowerIrql(oldIrql);

    ObDereferenceObject(proc);
    return STATUS_SUCCESS;
}


//
// ----------------------------------------------------------------- INJECT


NTSTATUS
MyArkProcessPerformInject(
    _In_            ULONG  Pid,
    _In_            ULONG  Method,
    _In_reads_(PathChars) PCWSTR DllPath,
    _In_            ULONG  PathChars,
    _Out_           PULONG StatusOut)
//
// Inject placeholder. The full implementation lives in S8.1 (actions).
// S6.1 verifies the IOCTL plumbing by validating inputs and returning
// STATUS_NOT_IMPLEMENTED so the caller knows the request reached the
// driver.
//
{
    UNREFERENCED_PARAMETER(Pid);
    UNREFERENCED_PARAMETER(Method);

    if (DllPath == NULL || PathChars == 0) {
        *StatusOut = (ULONG)STATUS_INVALID_PARAMETER;
        return STATUS_INVALID_PARAMETER;
    }

    *StatusOut = (ULONG)STATUS_NOT_IMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

#endif // MYARK_MODULE_PROCESS