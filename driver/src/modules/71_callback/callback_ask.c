// MyArk callback module: ASK_USER interactive process-creation decisions
// (R2-11).
//
// A rule with action ASK parks the CREATING thread inside the
// PsSetCreateProcessNotifyRoutineEx callback on a per-slot KEVENT with a
// hard 5 s timeout (fail open) while R3 inspects and resolves it:
//   ASK_WAIT    -- non-blocking snapshot of pending slots + counters.
//                  Never parks a WDF request: the original R2-11 design
//                  parked the poll in the driver's sequential queue and
//                  starved every other IOCTL (driver-wide freeze).
//   ASK_ANSWER  -- token-gated resolve by sequence (ALLOW / DENY).
//   ASK_CANCEL  -- token-gated flush of every pending slot (fail open).
//
// The creating thread waits OUTSIDE every spin lock; a timeout answers
// ALLOW so a dead or slow manager can never wedge process creation
// system-wide. Slot state transitions: 0 (free) -> 1 (pending, reserved
// via InterlockedCompareExchange) -> 0 (freed by the woken creator).

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "myark_config.h"
#include "ioctl_validation.h"
#include "../../../shared/driver/MyArkCallbackIoctl.h"
#include "../../../shared/driver/MyArkSafetyToken.h"
#include "../../dispatch/safety_token.h"
#include "callback_internal.h"

#if MYARK_MODULE_CALLBACK

typedef struct _MYARK_ASK_SLOT {
    volatile LONG State;                        // 0 free, 1 pending
    UINT64 Sequence;                            // set while pending
    UINT64 ParentId;
    UINT64 ProcessId;
    USHORT NameChars;                           // incl. NUL
    WCHAR  Name[MYARK_CALLBACK_ASK_NAME_CHARS];
    LONG   Decision;                            // MYARK_CALLBACK_ASK_DECISION_*
    KEVENT Signal;
} MYARK_ASK_SLOT, *PMYARK_ASK_SLOT;

// The rules table lock (callback_rules.c) guards slot state too: the notify
// path holds it shared while matching, and the answer/cancel paths take it
// shared to resolve slots.
extern EX_SPIN_LOCK g_RulesLock;

static MYARK_ASK_SLOT g_AskSlots[MYARK_CALLBACK_ASK_MAX_PENDING];
static LONG64 volatile g_AskSequence;
static LONG g_AskAsked;
static LONG g_AskDenied;
static LONG g_AskTimedOut;
static LONG g_AskDropped;

VOID
MyArkAskInit(
    VOID)
{
    for (ULONG i = 0; i < MYARK_CALLBACK_ASK_MAX_PENDING; i++) {
        g_AskSlots[i].State = 0;
        KeInitializeEvent(&g_AskSlots[i].Signal, SynchronizationEvent, FALSE);
    }
}

//
// Fail-open every parked creation. Called from module cleanup (before the
// notify removal -- it fails while a callback is still parked) and from
// the ASK_CANCEL IOCTL.
//
VOID
MyArkAskFailOpenAll(
    VOID)
{
    KIRQL irql = ExAcquireSpinLockShared(&g_RulesLock);

    for (ULONG i = 0; i < MYARK_CALLBACK_ASK_MAX_PENDING; i++) {
        if (g_AskSlots[i].State == 1) {
            g_AskSlots[i].Decision = MYARK_CALLBACK_ASK_DECISION_ALLOW;
            KeSetEvent(&g_AskSlots[i].Signal, IO_NO_INCREMENT, FALSE);
        }
    }
    ExReleaseSpinLockShared(&g_RulesLock, irql);
}

//
// Parks the creating thread until R3 resolves the slot or the 5 s timeout
// hits (fail open). Returns TRUE when the creation must be denied. Runs in
// the Ps notify callback at PASSIVE_LEVEL with no spin lock held.
//
BOOLEAN
MyArkAskPark(
    _In_ HANDLE ParentId,
    _In_ HANDLE ProcessId,
    _In_reads_(NameChars) PCWSTR Name,
    _In_ USHORT NameChars)
{
    PMYARK_ASK_SLOT slot = NULL;
    LARGE_INTEGER timeout;
    NTSTATUS waitStatus;
    KIRQL oldIrql;

    for (ULONG i = 0; i < MYARK_CALLBACK_ASK_MAX_PENDING; i++) {
        LONG prevState =
            InterlockedCompareExchange(&g_AskSlots[i].State, 1, 0);
        if (prevState == 0) {
            slot = &g_AskSlots[i];
            break;
        }
    }
    if (slot == NULL) {
        InterlockedIncrement(&g_AskDropped);   // table full: fail open
        return FALSE;
    }

    //
    // Publish the fields under the EXCLUSIVE lock: the answer/cancel
    // scanners hold it SHARED while reading State==1 slots, so without
    // this a scanner could pair a stale Sequence from the slot's previous
    // life with the fresh reservation (misdirected verdict).
    //
    oldIrql = ExAcquireSpinLockExclusive(&g_RulesLock);
    slot->Sequence = (UINT64)InterlockedIncrement64(&g_AskSequence);
    slot->ParentId = (UINT64)(UINT_PTR)ParentId;
    slot->ProcessId = (UINT64)(UINT_PTR)ProcessId;
    slot->Decision = MYARK_CALLBACK_ASK_DECISION_ALLOW;
    slot->NameChars = NameChars;
    RtlCopyMemory(slot->Name, Name, (SIZE_T)NameChars * sizeof(WCHAR));
    InterlockedIncrement(&g_AskAsked);
    ExReleaseSpinLockExclusive(&g_RulesLock, oldIrql);

    //
    // Belt and braces: a raced timeout/free above could leave the event
    // signaled; the wait must always observe the full 5 s window.
    //
    KeResetEvent(&slot->Signal);

    timeout.QuadPart = -1 * MYARK_CALLBACK_ASK_TIMEOUT_MS * 10 * 1000;
    waitStatus = KeWaitForSingleObject(&slot->Signal,
                                       Executive,
                                       KernelMode,
                                       FALSE,
                                       &timeout);

    //
    // Release under the EXCLUSIVE lock: answer/cancel scan SHARED, so a
    // KeSetEvent can never land on a slot whose waiter is already gone
    // (a stranded signal would make the next park return immediately and
    // silently skip the 5 s prompt window).
    //
    oldIrql = ExAcquireSpinLockExclusive(&g_RulesLock);
    if (waitStatus == STATUS_TIMEOUT) {
        slot->Decision = MYARK_CALLBACK_ASK_DECISION_ALLOW;
        InterlockedIncrement(&g_AskTimedOut);
    }
    slot->State = 0;
    ExReleaseSpinLockExclusive(&g_RulesLock, oldIrql);

    if (slot->Decision == MYARK_CALLBACK_ASK_DECISION_DENY) {
        InterlockedIncrement(&g_AskDenied);
        return TRUE;
    }
    return FALSE;
}

//
// ASK_WAIT: non-blocking snapshot of the pending table. The R2-11
// postmortem design parked this poll request in the sequential queue,
// starving every other IOCTL -- never wait for a verdict here.
//
NTSTATUS
MyArkCallbackIoctlAskWait(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    PMYARK_CALLBACK_ASK_WAIT_OUTPUT outBuf = NULL;
    size_t outSize = 0;
    NTSTATUS status;
    KIRQL irql;

    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(InputBufferLength);

    if (OutputBufferLength < sizeof(MYARK_CALLBACK_ASK_WAIT_OUTPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         sizeof(MYARK_CALLBACK_ASK_WAIT_OUTPUT),
                                         (PVOID*)&outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlZeroMemory(outBuf, sizeof(MYARK_CALLBACK_ASK_WAIT_OUTPUT));
    irql = ExAcquireSpinLockShared(&g_RulesLock);
    for (ULONG i = 0; i < MYARK_CALLBACK_ASK_MAX_PENDING; i++) {
        if (g_AskSlots[i].State != 1) {
            continue;
        }
        if (outBuf->PendingCount >= MYARK_CALLBACK_ASK_MAX_PENDING) {
            break;
        }
        PMYARK_CALLBACK_ASK_ENTRY entry =
            &outBuf->Entries[outBuf->PendingCount];
        entry->Sequence = g_AskSlots[i].Sequence;
        entry->ParentId = g_AskSlots[i].ParentId;
        entry->ProcessId = g_AskSlots[i].ProcessId;
        entry->NameChars = g_AskSlots[i].NameChars;
        RtlCopyMemory(entry->Name, g_AskSlots[i].Name,
                      sizeof(entry->Name));
        outBuf->PendingCount++;
    }
    outBuf->Status = (UINT32)STATUS_SUCCESS;
    outBuf->TotalAsked = (UINT32)g_AskAsked;
    outBuf->TotalDenied = (UINT32)g_AskDenied;
    outBuf->TotalTimedOut = (UINT32)g_AskTimedOut;
    outBuf->TotalDropped = (UINT32)g_AskDropped;
    outBuf->EntryStructSize = (UINT32)sizeof(MYARK_CALLBACK_ASK_ENTRY);
    ExReleaseSpinLockShared(&g_RulesLock, irql);

    *BytesReturned = sizeof(MYARK_CALLBACK_ASK_WAIT_OUTPUT);
    return STATUS_SUCCESS;
}

//
// ASK_ANSWER: resolve one pending slot by sequence (token-gated).
//
NTSTATUS
MyArkCallbackIoctlAskAnswer(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    PMYARK_CALLBACK_ASK_ANSWER_INPUT inBuf = NULL;
    PMYARK_CALLBACK_ASK_ANSWER_OUTPUT outBuf = NULL;
    size_t inSize = 0;
    size_t outSize = 0;
    NTSTATUS status;
    UINT64 sequence;
    UINT32 decision;
    ULONG pending = 0;
    KIRQL irql;

    UNREFERENCED_PARAMETER(Device);

    if (InputBufferLength < sizeof(MYARK_CALLBACK_ASK_ANSWER_INPUT)
        || OutputBufferLength < sizeof(MYARK_CALLBACK_ASK_ANSWER_OUTPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_CALLBACK_ASK_ANSWER_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = MyArkSafetyTokenValidate(&inBuf->Token,
                                      MYARK_CALLBACK_OP_ASK_ANSWER,
                                      (UINT32)(UINT_PTR)PsGetCurrentProcessId());
    if (!NT_SUCCESS(status)) {
        return STATUS_ACCESS_DENIED;
    }

    sequence = inBuf->Sequence;
    decision = inBuf->Decision;
    if (decision != MYARK_CALLBACK_ASK_DECISION_ALLOW
        && decision != MYARK_CALLBACK_ASK_DECISION_DENY) {
        return STATUS_INVALID_PARAMETER;
    }

    status = MyArkIoctlFetchOutputBuffer(Request,
                                         sizeof(MYARK_CALLBACK_ASK_ANSWER_OUTPUT),
                                         (PVOID*)&outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    outBuf->Status = (UINT32)STATUS_NOT_FOUND;
    irql = ExAcquireSpinLockShared(&g_RulesLock);
    for (ULONG i = 0; i < MYARK_CALLBACK_ASK_MAX_PENDING; i++) {
        if (g_AskSlots[i].State != 1) {
            continue;
        }
        if (g_AskSlots[i].Sequence == sequence) {
            g_AskSlots[i].Decision = (LONG)decision;
            KeSetEvent(&g_AskSlots[i].Signal, IO_NO_INCREMENT, FALSE);
            outBuf->Status = (UINT32)STATUS_SUCCESS;
        } else {
            pending++;
        }
    }
    ExReleaseSpinLockShared(&g_RulesLock, irql);
    outBuf->PendingCount = pending;

    *BytesReturned = sizeof(MYARK_CALLBACK_ASK_ANSWER_OUTPUT);
    return STATUS_SUCCESS;
}

//
// ASK_CANCEL: resolve EVERY pending slot fail-open (token-gated).
//
NTSTATUS
MyArkCallbackIoctlAskCancel(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    PMYARK_CALLBACK_ASK_CANCEL_INPUT inBuf = NULL;
    PMYARK_CALLBACK_ASK_CANCEL_OUTPUT outBuf = NULL;
    size_t inSize = 0;
    size_t outSize = 0;
    NTSTATUS status;
    ULONG flushed = 0;
    KIRQL irql;

    UNREFERENCED_PARAMETER(Device);

    if (InputBufferLength < sizeof(MYARK_CALLBACK_ASK_CANCEL_INPUT)
        || OutputBufferLength < sizeof(MYARK_CALLBACK_ASK_CANCEL_OUTPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_CALLBACK_ASK_CANCEL_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = MyArkSafetyTokenValidate(&inBuf->Token,
                                      MYARK_CALLBACK_OP_ASK_CANCEL,
                                      (UINT32)(UINT_PTR)PsGetCurrentProcessId());
    if (!NT_SUCCESS(status)) {
        return STATUS_ACCESS_DENIED;
    }

    status = MyArkIoctlFetchOutputBuffer(Request,
                                         sizeof(MYARK_CALLBACK_ASK_CANCEL_OUTPUT),
                                         (PVOID*)&outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    irql = ExAcquireSpinLockShared(&g_RulesLock);
    for (ULONG i = 0; i < MYARK_CALLBACK_ASK_MAX_PENDING; i++) {
        if (g_AskSlots[i].State != 1) {
            continue;
        }
        g_AskSlots[i].Decision = MYARK_CALLBACK_ASK_DECISION_ALLOW;
        KeSetEvent(&g_AskSlots[i].Signal, IO_NO_INCREMENT, FALSE);
        flushed++;
    }
    ExReleaseSpinLockShared(&g_RulesLock, irql);

    outBuf->Status = (UINT32)STATUS_SUCCESS;
    outBuf->Flushed = flushed;
    *BytesReturned = sizeof(MYARK_CALLBACK_ASK_CANCEL_OUTPUT);
    return STATUS_SUCCESS;
}

#endif // MYARK_MODULE_CALLBACK
