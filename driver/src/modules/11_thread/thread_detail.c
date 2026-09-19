// MyArk thread module: ETHREAD field extraction for DETAIL / DETAIL_RUNTIME.
//
// All offsets are hardcoded for Windows 11 24H2 / build 26100.x -- see
// thread_internal.h. S7.1 (DynData) loads a profile that overrides them.
//
// Every read goes through MmIsAddressValid so a stale ETHREAD (e.g. a
// thread that exited between the lookup and the field read) does not
// blue-screen the VM. The caller has already done a PsLookupThreadByThreadId
// to dereference the ETHREAD, so the structure itself is alive when we
// get here.

#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>
#include "Trace.h"
#include "thread_internal.h"

#if MYARK_MODULE_THREAD

NTKERNELAPI
ULONG
KeQueryRuntimeThread(
    _In_ PKTHREAD Thread,
    _Out_ PULONG UserTime);

NTSTATUS PsLookupThreadByThreadId(_In_ HANDLE ThreadId, _Outptr_ PETHREAD* Thread);
NTSTATUS PsLookupProcessByProcessId(_In_ HANDLE ProcessId, _Outptr_ PEPROCESS* Process);


//
// Generic ULONG / ULONGLONG / UCHAR readers that bail to zero on a bad
// address. Mirrors process_detail.c's helpers.
//

static
ULONG
MyArkThreadReadUlongSafe(
    _In_ PVOID Base,
    _In_ ULONG Offset)
{
    if (!MmIsAddressValid((PUCHAR)Base + Offset)) {
        return 0;
    }
    return *((PULONG)((PUCHAR)Base + Offset));
}


static
ULONGLONG
MyArkThreadReadUlonglongSafe(
    _In_ PVOID Base,
    _In_ ULONG Offset)
{
    if (!MmIsAddressValid((PUCHAR)Base + Offset)) {
        return 0;
    }
    return *((PULONGLONG)((PUCHAR)Base + Offset));
}


//
// Resolve a TID to a referenced ETHREAD; caller is responsible for the
// matching ObDereferenceObject.
//

static
NTSTATUS
MyArkThreadResolveEThread(
    _In_  ULONG    Tid,
    _Out_ PETHREAD* EThreadOut)
{
    NTSTATUS status;
    PETHREAD thread = NULL;

    if (Tid == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    status = PsLookupThreadByThreadId(UlongToHandle(Tid), &thread);
    if (!NT_SUCCESS(status) || thread == NULL) {
        return STATUS_NOT_FOUND;
    }

    *EThreadOut = thread;
    return STATUS_SUCCESS;
}


NTSTATUS
MyArkThreadFillDetail(
    _Out_ PMYARK_THREAD_DETAIL Detail,
    _In_  ULONG Tid)
//
// Fill MYARK_THREAD_DETAIL with the ETHREAD snapshot for Tid.
//
{
    NTSTATUS status;
    PETHREAD ethread = NULL;

    if (Detail == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Detail, sizeof(*Detail));

    status = MyArkThreadResolveEThread(Tid, &ethread);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    Detail->Tid    = Tid;
    Detail->OwnerPid = (UINT32)MyArkThreadReadUlongSafe(
        *((PVOID*)((PUCHAR)ethread + MYARK_OFF_ETHREAD_APC_STATE_PROCESS)),
        MYARK_EP_OFF_UNIQUE_PROCESS_ID);

    Detail->State        = MyArkThreadReadUlongSafe(ethread, MYARK_OFF_ETHREAD_STATE);
    Detail->Priority     = MyArkThreadReadUlongSafe(ethread, MYARK_OFF_ETHREAD_PRIORITY);
    Detail->BasePriority = MyArkThreadReadUlongSafe(ethread, MYARK_OFF_ETHREAD_BASE_PRIORITY);
    Detail->WaitReason   = MyArkThreadReadUlongSafe(ethread, MYARK_OFF_ETHREAD_WAIT_REASON);
    Detail->CreateTime   = MyArkThreadReadUlonglongSafe(ethread, MYARK_OFF_ETHREAD_CREATE_TIME);
    Detail->StartAddress = MyArkThreadReadUlonglongSafe(ethread, MYARK_OFF_ETHREAD_START_ADDRESS);
    Detail->Win32StartAddress = MyArkThreadReadUlonglongSafe(ethread, MYARK_OFF_ETHREAD_WIN32_START_ADDRESS);

    Detail->EThreadKernelAddress = (UINT64)(ULONG_PTR)ethread;
    PVOID owningEp = *((PVOID*)((PUCHAR)ethread + MYARK_OFF_ETHREAD_APC_STATE_PROCESS));
    if (owningEp != NULL && MmIsAddressValid(owningEp)) {
        Detail->EProcessKernelAddress = (UINT64)(ULONG_PTR)owningEp;
    }

    //
    // Module name + anomaly classification for the StartAddress. The cache
    // is one-shot; this call may be the first reference and triggers the
    // PsLoadedModuleList walk.
    //
    Detail->Anomaly = MyArkThreadClassifyStartAddress(Detail->StartAddress,
                                                     Detail->Module,
                                                     MYARK_THREAD_MODULE_NAME_MAX);
    //
    // StartAddressModulePath is a best-effort "device path" field. We don't
    // reach into the KLDR entry's FullDllName here (that would require
    // another cache indexed by base); the enum / cross-view consumers get
    // the same Module[] + StartAddress and resolve the rest in R3.
    //
    MyArkThreadCopyModuleName(Detail->StartAddressModulePath,
                              260,
                              Detail->Module);

    //
    // Debug aids: stash every offset that contributed a field so a
    // researcher can sanity-check against the WinDbg 'dt' output.
    //
    Detail->UniqueThreadIdOffset   = MYARK_OFF_ETHREAD_UNIQUE_THREAD_ID;
    Detail->ThreadListEntryOffset  = MYARK_OFF_ETHREAD_THREAD_LIST_ENTRY;
    Detail->StateOffset            = MYARK_OFF_ETHREAD_STATE;
    Detail->PriorityOffset         = MYARK_OFF_ETHREAD_PRIORITY;
    Detail->WaitReasonOffset       = MYARK_OFF_ETHREAD_WAIT_REASON;
    Detail->CreateTimeOffset       = MYARK_OFF_ETHREAD_CREATE_TIME;
    Detail->StartAddressOffset     = MYARK_OFF_ETHREAD_START_ADDRESS;
    Detail->ApcStateProcessOffset  = MYARK_OFF_ETHREAD_APC_STATE_PROCESS;

    ObDereferenceObject(ethread);
    return STATUS_SUCCESS;
}


NTSTATUS
MyArkThreadFillDetailRuntime(
    _Out_ PMYARK_THREAD_DETAIL_RUNTIME Runtime,
    _In_  ULONG Tid)
//
// Runtime snapshot: ETHREAD embeds the KTHREAD as its first member, so the
// ETHREAD pointer doubles as the PKTHREAD for KeQueryRuntimeThread (kernel
// + user tick counts). KTHREAD State rides the already-used Tier C offset.
// CycleTime / ContextSwitches have no clean cross-build source and stay 0
// (documented).
//
{
    NTSTATUS status;
    PETHREAD ethread = NULL;
    ULONG userTicks = 0;

    if (Runtime == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Runtime, sizeof(*Runtime));
    Runtime->Tid = Tid;

    status = MyArkThreadResolveEThread(Tid, &ethread);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // KeQueryRuntimeThread: 100 ns units, accumulated at clock-interval
    // granularity (~15.6 ms) -- a brand-new thread can legitimately read 0.
    //
    Runtime->KernelTime = KeQueryRuntimeThread((PKTHREAD)ethread, &userTicks);
    Runtime->UserTime = userTicks;
    Runtime->StateFlags = MyArkThreadReadUlongSafe(ethread, MYARK_OFF_ETHREAD_STATE);

    ObDereferenceObject(ethread);
    return STATUS_SUCCESS;
}

#endif // MYARK_MODULE_THREAD
