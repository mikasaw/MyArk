// MyArk actions module: INJECT_SHELLCODE (R3-2, T-C).
//
// Authorized-test-environment surface. The payload comes entirely from the
// caller; this driver is only the mechanism (no payload generation, no
// staging, no weaponized content in the repository). Pipeline:
//
//   PsLookupProcessByProcessId + PsGetProcessProtection
//     -> PPL targets are rejected EXPLICITLY (kernel-mode Zw* calls do not
//        trip the user-mode protected-process checks)
//   ZwOpenProcess (PROCESS_VM_* on the target)
//   payload snapshot into a kernel pool buffer FIRST -- the input and the
//        output of a METHOD_BUFFERED request alias one SystemBuffer, and
//        the output zeroing would otherwise clobber the payload head
//   ZwAllocateVirtualMemory  MEM_COMMIT|RESERVE, PAGE_READWRITE
//   MmCopyVirtualMemory      payload copy (ZwWriteVirtualMemory is not an
//                            ntoskrnl export) + read-back integrity check
//   ZwProtectVirtualMemory   PAGE_EXECUTE_READ
//   KeInitializeApc + KeInsertQueueApc
//                            queue a USER APC to the caller-chosen thread
//                            (TargetTid) whose normal routine IS the
//                            payload; the target thread runs it at its
//                            next alertable point. The payload must follow
//                            the 3-argument user-APC convention and
//                            terminate via a syscall/library call -- a
//                            bare RET is not APC-return-convention safe.
//
// Caps: PayloadSize in [1, 256 KB]. The benign regression stub is a bare
// x64 RET -- see verify_core.py. The pool-backed KAPC is freed by the APC
// kernel routine at delivery time; the target thread must belong to the
// target process (ownership checked).

#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>
#include "Trace.h"
#include "myark_config.h"
#include "ioctl_validation.h"
#include "../../../shared/driver/MyArkActionsIoctl.h"
#include "actions_descriptor.h"
#include "../../../shared/driver/MyArkPoolAlloc.h"
#include "actions_internal.h"

#if MYARK_MODULE_ACTIONS

// ntddk-flavor access masks (ntifs conveniences).
#ifndef PROCESS_CREATE_THREAD
#define PROCESS_CREATE_THREAD 0x0002
#endif
#ifndef PROCESS_VM_OPERATION
#define PROCESS_VM_OPERATION 0x0008
#endif
#ifndef PROCESS_VM_READ
#define PROCESS_VM_READ 0x0010
#endif
#ifndef PROCESS_VM_WRITE
#define PROCESS_VM_WRITE 0x0020
#endif
#ifndef THREAD_SET_CONTEXT
#define THREAD_SET_CONTEXT 0x0010
#endif

// wdm.h (ntddk flavor) does not declare the APC routine types.
typedef VOID (*PKNORMAL_ROUTINE)(PVOID NormalContext, PVOID SystemArgument1, PVOID SystemArgument2);
typedef VOID (*PKKERNEL_ROUTINE)(PRKAPC Apc, PKNORMAL_ROUTINE* NormalRoutine,
    PVOID* NormalContext, PVOID* SystemArgument1, PVOID* SystemArgument2);
typedef VOID (*PKRUNDOWN_ROUTINE)(PRKAPC Apc);
typedef enum _KAPC_ENVIRONMENT {
    OriginalApcEnvironment,
    AttachedApcEnvironment,
    CurrentApcEnvironment,
    InsertApcEnvironment
} KAPC_ENVIRONMENT;

NTKERNELAPI
NTSTATUS
ZwAllocateVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG PageProtection);

NTKERNELAPI
NTSTATUS
ZwProtectVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG NewProtection,
    _Out_ PULONG OldProtection);

NTKERNELAPI
NTSTATUS
ZwFreeVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG FreeType);

// Payload copy: ZwWriteVirtualMemory is not an ntoskrnl export;
// MmCopyVirtualMemory (exported) does the cross-process copy.
NTKERNELAPI
NTSTATUS
MmCopyVirtualMemory(
    _In_ PEPROCESS SourceProcess,
    _In_ PVOID SourceAddress,
    _In_ PEPROCESS TargetProcess,
    _Out_ PVOID TargetAddress,
    _In_ SIZE_T BufferSize,
    _In_ KPROCESSOR_MODE PreviousMode,
    _Out_ PSIZE_T ReturnSize);

NTKERNELAPI
NTSTATUS
PsLookupProcessByProcessId(
    _In_ HANDLE ProcessId,
    _Outptr_ PEPROCESS* Process);

NTSTATUS
PsLookupThreadByThreadId(
    _In_ HANDLE ThreadId,
    _Outptr_ PETHREAD* Thread);

// Raw owning-process pointer of the thread; valid while the caller holds a
// reference on the thread (we do).
NTKERNELAPI
PEPROCESS
PsGetThreadProcess(
    _In_ PETHREAD Thread);

// wdm.h (ntddk flavor) does not declare PS_PROTECTION / the getter.
#pragma warning(push)
#pragma warning(disable: 4201)  // unnamed struct/union (PS_PROTECTION layout)
typedef struct _MYARK_PS_PROTECTION {
    union {
        UCHAR Level;
        struct {
            UCHAR Type : 3;
            UCHAR Audit : 1;
            UCHAR Signer : 4;
        };
    };
} MYARK_PS_PROTECTION, *PMYARK_PS_PROTECTION;
#pragma warning(pop)

#define PsProtectedTypeNone 0
#define PsProtectedTypeProtectedLight 1
#define PsProtectedTypeProtected 2

NTKERNELAPI
MYARK_PS_PROTECTION
PsGetProcessProtection(
    _In_ PEPROCESS Process);

NTKERNELAPI
VOID
KeInitializeApc(
    _Out_ PRKAPC Apc,
    _In_ PRKTHREAD Thread,
    _In_ KAPC_ENVIRONMENT Environment,
    _In_ PKKERNEL_ROUTINE KernelRoutine,
    _In_opt_ PKRUNDOWN_ROUTINE RundownRoutine,
    _In_opt_ PKNORMAL_ROUTINE NormalRoutine,
    _In_ KPROCESSOR_MODE ProcessorMode,
    _In_opt_ PVOID NormalContext);

NTKERNELAPI
BOOLEAN
KeInsertQueueApc(
    _Inout_ PRKAPC Apc,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2,
    _In_ KPRIORITY Increment);

//
// Runs in the target thread at APC_LEVEL right before the user payload;
// frees the pool-backed KAPC (standard pattern).
//
static
VOID
MyArkInjectKernelRoutine(
    _In_ PRKAPC Apc,
    _Inout_ PKNORMAL_ROUTINE* NormalRoutine,
    _Inout_ PVOID* NormalContext,
    _Inout_ PVOID* SystemArgument1,
    _Inout_ PVOID* SystemArgument2)
{
    UNREFERENCED_PARAMETER(NormalRoutine);
    UNREFERENCED_PARAMETER(NormalContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);
    ExFreePoolWithTag(Apc, 'JINA');
}

NTSTATUS
MyArkActionsIoctlInjectShellcode(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    PMYARK_ACTION_INJECT_SHELLCODE_INPUT inBuf = NULL;
    PMYARK_ACTION_INJECT_SHELLCODE_OUTPUT outBuf = NULL;
    size_t inSize = 0;
    size_t outSize = 0;
    NTSTATUS status;
    NTSTATUS stepStatus;
    HANDLE processHandle = NULL;
    PVOID remoteBase = NULL;
    SIZE_T remoteSize = 0;
    ULONG targetPid;
    ULONG targetTid;
    ULONG payloadSize;
    PUCHAR payloadCopy = NULL;
    UCHAR verifyBuf[16];
    PEPROCESS targetProcess = NULL;
    PETHREAD targetThread = NULL;
    PVOID apc = NULL;
    CLIENT_ID clientId;
    OBJECT_ATTRIBUTES oa;
    SIZE_T protectSize = 0;
    SIZE_T copied = 0;

    UNREFERENCED_PARAMETER(Device);

    if (InputBufferLength < sizeof(MYARK_ACTION_INJECT_SHELLCODE_INPUT)
        || OutputBufferLength < sizeof(MYARK_ACTION_INJECT_SHELLCODE_OUTPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_ACTION_INJECT_SHELLCODE_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Token binds the TARGET pid (same discipline as the other actions):
    // a stolen token must not authorize injecting into an arbitrary
    // process.
    //
    status = MyArkActionsValidateToken(&inBuf->Token,
                                       MYARK_ACTION_OP_INJECT_SHELLCODE,
                                       inBuf->Pid);
    if (!NT_SUCCESS(status)) {
        return STATUS_ACCESS_DENIED;
    }

    //
    // Snapshot EVERYTHING (including the payload) before touching the
    // shared output buffer: METHOD_BUFFERED input and output alias one
    // SystemBuffer and the output zeroing would clobber the payload head.
    //
    targetPid = inBuf->Pid;
    targetTid = inBuf->TargetTid;
    payloadSize = inBuf->PayloadSize;
    if (payloadSize == 0 || payloadSize > MYARK_ACTION_SHELLCODE_MAX_BYTES) {
        return STATUS_INVALID_PARAMETER;
    }
    if (inBuf->Flags != 0) {
        return STATUS_INVALID_PARAMETER;
    }
    if (targetTid == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    if (inSize - sizeof(MYARK_ACTION_INJECT_SHELLCODE_INPUT) + 1 < payloadSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    payloadCopy = (PUCHAR)MyArkAllocatePool(NonPagedPoolNx, payloadSize, 'JINA');
    if (payloadCopy == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyMemory(payloadCopy, inBuf->Payload, payloadSize);

    status = MyArkIoctlFetchOutputBuffer(Request,
                                         sizeof(MYARK_ACTION_INJECT_SHELLCODE_OUTPUT),
                                         (PVOID*)&outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(payloadCopy, 'JINA');
        return status;
    }
    RtlZeroMemory(outBuf, sizeof(*outBuf));

    //
    // Explicit PPL rejection: kernel-mode Zw*/Mm* calls bypass the
    // user-mode protected-process checks, so query the protection level.
    //
    status = PsLookupProcessByProcessId(ULongToHandle(targetPid),
                                        &targetProcess);
    if (!NT_SUCCESS(status)) {
        goto Fail;
    }
    if (PsGetProcessProtection(targetProcess).Type != PsProtectedTypeNone) {
        ObDereferenceObject(targetProcess);
        targetProcess = NULL;
        ExFreePoolWithTag(payloadCopy, 'JINA');
        outBuf->Header.ResultCode = MYARK_ACTION_RESULT_FAILED;
        outBuf->Header.ExecutedTier = MYARK_ACTION_TIER_R0;
        outBuf->Pid = targetPid;
        RtlStringCbPrintfA((PSTR)outBuf->Header.AuditMessage,
                           sizeof(outBuf->Header.AuditMessage),
                           "inject: ppl target pid=%lu",
                           targetPid);
        *BytesReturned = sizeof(*outBuf);
        return STATUS_ACCESS_DENIED;
    }

    clientId.UniqueProcess = ULongToHandle(targetPid);
    clientId.UniqueThread = NULL;
    InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    status = ZwOpenProcess(&processHandle,
                           PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION
                               | PROCESS_VM_WRITE | PROCESS_VM_READ,
                           &oa,
                           &clientId);
    if (!NT_SUCCESS(status)) {
        goto Fail;
    }

    remoteSize = payloadSize;
    status = ZwAllocateVirtualMemory(processHandle,
                                     &remoteBase,
                                     0,
                                     &remoteSize,
                                     MEM_COMMIT | MEM_RESERVE,
                                     PAGE_READWRITE);
    if (!NT_SUCCESS(status)) {
        goto Fail;
    }

    status = MmCopyVirtualMemory(PsGetCurrentProcess(),
                                 payloadCopy,
                                 targetProcess,
                                 remoteBase,
                                 payloadSize,
                                 KernelMode,
                                 &copied);
    if (!NT_SUCCESS(status)) {
        goto Fail;
    }

    //
    // Read-back integrity (source = the TARGET address space we just
    // wrote, destination = a kernel-side buffer).
    //
    RtlZeroMemory(verifyBuf, sizeof(verifyBuf));
    {
        ULONG readbackSize = payloadSize < sizeof(verifyBuf)
                                 ? payloadSize
                                 : sizeof(verifyBuf);
        status = MmCopyVirtualMemory(targetProcess,
                                     remoteBase,
                                     PsGetCurrentProcess(),
                                     verifyBuf,
                                     readbackSize,
                                     KernelMode,
                                     &copied);
        if (!NT_SUCCESS(status)) {
            goto Fail;
        }
        if (RtlCompareMemory(verifyBuf, payloadCopy, readbackSize)
            != readbackSize) {
            status = STATUS_INVALID_USER_BUFFER;
            goto Fail;
        }
    }

    protectSize = payloadSize;
    {
        ULONG oldProtect = 0;
        status = ZwProtectVirtualMemory(processHandle,
                                        &remoteBase,
                                        &protectSize,
                                        PAGE_EXECUTE_READ,
                                        &oldProtect);
    }
    if (!NT_SUCCESS(status)) {
        goto Fail;
    }

    status = PsLookupThreadByThreadId(ULongToHandle(targetTid), &targetThread);
    if (!NT_SUCCESS(status)) {
        goto Fail;
    }

    //
    // The APC must land on a thread OF the target process; a cross-process
    // Tid would execute the payload in someone else's address space.
    //
    if (PsGetThreadProcess(targetThread) != targetProcess) {
        status = STATUS_INVALID_PARAMETER;
        goto Fail;
    }

    apc = MyArkAllocatePool(NonPagedPoolNx, sizeof(KAPC), 'JINA');
    if (apc == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Fail;
    }

    //
    // User APC: the target thread runs the payload as
    // NormalRoutine(NormalContext, Arg1, Arg2) at its next alertable point.
    // The KAPC frees itself in the kernel routine at delivery -- ownership
    // moves to async delivery on successful insert (Fail-path frees only
    // run when apc is still non-NULL, i.e. insert failed or never ran).
    //
    KeInitializeApc((PRKAPC)apc,
                    (PKTHREAD)targetThread,
                    OriginalApcEnvironment,
                    MyArkInjectKernelRoutine,
                    NULL,
                    (PKNORMAL_ROUTINE)remoteBase,
                    UserMode,
                    NULL);
    if (!KeInsertQueueApc((PRKAPC)apc, NULL, NULL, IO_NO_INCREMENT)) {
        status = STATUS_THREAD_NOT_IN_PROCESS;
        goto Fail;
    }

    ObDereferenceObject(targetThread);
    targetThread = NULL;
    ZwClose(processHandle);
    processHandle = NULL;

    outBuf->Header.Size = (UINT32)sizeof(*outBuf);
    outBuf->Header.ResultCode = MYARK_ACTION_RESULT_APPROVED;
    outBuf->Header.ExecutedTier = MYARK_ACTION_TIER_R0;
    KeQuerySystemTime(&outBuf->Header.Timestamp);
    RtlStringCbPrintfA((PSTR)outBuf->Header.AuditMessage,
                       sizeof(outBuf->Header.AuditMessage),
                       "inject: pid=%lu tid=%lu %lu bytes",
                       targetPid, targetTid, payloadSize);
    outBuf->Pid = targetPid;
    outBuf->ThreadId = targetTid;
    outBuf->RemoteBase = (UINT64)(UINT_PTR)remoteBase;
    outBuf->RemoteSize = (UINT64)payloadSize;
    *BytesReturned = sizeof(*outBuf);

    ExFreePoolWithTag(payloadCopy, 'JINA');
    return STATUS_SUCCESS;

Fail:
    stepStatus = status;
    if (targetThread != NULL) {
        ObDereferenceObject(targetThread);
    }
    if (apc != NULL) {
        ExFreePoolWithTag(apc, 'JINA');
    }
    if (payloadCopy != NULL) {
        ExFreePoolWithTag(payloadCopy, 'JINA');
    }
    if (remoteBase != NULL) {
        SIZE_T freeSize = 0;
        ZwFreeVirtualMemory(processHandle, &remoteBase, &freeSize, MEM_RELEASE);
    }
    if (targetProcess != NULL) {
        ObDereferenceObject(targetProcess);
    }
    if (processHandle != NULL) {
        ZwClose(processHandle);
    }
    outBuf->Header.ResultCode = MYARK_ACTION_RESULT_FAILED;
    outBuf->Header.ExecutedTier = MYARK_ACTION_TIER_R0;
    outBuf->Pid = targetPid;
    RtlStringCbPrintfA((PSTR)outBuf->Header.AuditMessage,
                       sizeof(outBuf->Header.AuditMessage),
                       "inject: fail 0x%08X",
                       status);
    *BytesReturned = sizeof(*outBuf);
    return stepStatus;
}

#endif // MYARK_MODULE_ACTIONS
