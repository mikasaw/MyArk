// MyArk mutation module: transaction engine (R3-8).
//
// PREPARE stages mutation ops and snapshots originals; COMMIT atomically
// writes the staged values; ROLLBACK restores originals (useful after
// COMMIT as undo, and a no-op on an un-COMMITted slot). An audit ring
// (32 entries) records every PREPARE/COMMIT/ROLLBACK event.
//
// Locking: one EX_SPIN_LOCK exclusive for slot + ring mutation, shared
// for TX_LIST reads. The EPROCESS write itself runs at DPC_LEVEL inside
// the lock (same pattern as 10_process/process_actions.c).
//
// EPROCESS offsets are Tier C (Win11 24H2 profile, same constants the
// 10_process module uses; both test VMs verified).

#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>
#include "Trace.h"
#include "myark_config.h"
#include "../../../shared/driver/MyArkMutationIoctl.h"
#include "mutation_internal.h"

// wdm.h ntddk flavor lacks the prototype; exported by ntoskrnl.exe.
NTKERNELAPI
NTSTATUS
PsLookupProcessByProcessId(
    _In_ HANDLE ProcessId,
    _Outptr_ PEPROCESS *Process);

#if MYARK_MODULE_MUTATION

#define MYARK_TX_EPROCESS_PROTECTION  0x6B0UL
#define MYARK_TX_EPROCESS_FLAGS2      0x183UL

typedef struct _MYARK_TX_OP {
    UINT32 OpType;                               // MYARK_MUTATION_TX_OP_*
    UINT32 Pid;
    UINT32 PplLevel;
    UINT32 FlagsMask;
    UINT32 FlagsValue;
    UCHAR  PrevProtection;                       // original byte
    ULONG  PrevFlags;                            // original ULONG
    BOOLEAN Applied;                             // COMMIT wrote this op
} MYARK_TX_OP, *PMYARK_TX_OP;

typedef struct _MYARK_TX_SLOT {
    UINT32 State;                                // TX_STATE_*
    UINT32 OpCount;
    UINT64 CreatedAt;
    MYARK_TX_OP Ops[MYARK_MUTATION_TX_MAX_OPS];
} MYARK_TX_SLOT, *PMYARK_TX_SLOT;

static EX_SPIN_LOCK g_TxLock;
static MYARK_TX_SLOT g_TxSlots[MYARK_MUTATION_TX_MAX_SLOTS];
static UINT64 g_TxAuditTs[MYARK_MUTATION_TX_AUDIT_RING];
static UINT32 g_TxAuditToken[MYARK_MUTATION_TX_AUDIT_RING];
static UINT32 g_TxAuditAction[MYARK_MUTATION_TX_AUDIT_RING];
static UINT32 g_TxAuditOps[MYARK_MUTATION_TX_AUDIT_RING];
static UINT32 g_TxAuditStatus[MYARK_MUTATION_TX_AUDIT_RING];
static UINT32 g_TxAuditWriteIdx;
static UINT32 g_TxAuditTotal;

static
VOID
MyArkTxAuditAppend(
    _In_ UINT32 TxToken,
    _In_ UINT32 Action,
    _In_ UINT32 OpsCount,
    _In_ UINT32 Status)
{
    UINT32 idx = g_TxAuditWriteIdx % MYARK_MUTATION_TX_AUDIT_RING;
    g_TxAuditTs[idx] = KeQueryInterruptTime();
    g_TxAuditToken[idx] = TxToken;
    g_TxAuditAction[idx] = Action;
    g_TxAuditOps[idx] = OpsCount;
    g_TxAuditStatus[idx] = Status;
    g_TxAuditWriteIdx++;
    g_TxAuditTotal++;
}

//
// Resolve a PID to an EPROCESS pointer (caller must ObDereferenceObject).
//
static
NTSTATUS
MyArkTxResolveEProcess(
    _In_ UINT32 Pid,
    _Out_ PEPROCESS* ProcOut)
{
    HANDLE hpid = (HANDLE)(UINT_PTR)Pid;
    return PsLookupProcessByProcessId(hpid, ProcOut);
}

//
// Read the current value for one op type (PREPARE's snapshot phase).
//
static
NTSTATUS
MyArkTxReadCurrent(
    _In_ UINT32 OpType,
    _In_ UINT32 Pid,
    _Out_ UCHAR* PrevProtection,
    _Out_ PULONG PrevFlags)
{
    NTSTATUS status;
    PEPROCESS proc = NULL;

    *PrevProtection = 0;
    *PrevFlags = 0;

    status = MyArkTxResolveEProcess(Pid, &proc);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    switch (OpType) {
    case MYARK_MUTATION_TX_OP_PPL: {
        PUCHAR prot = (PUCHAR)proc + MYARK_TX_EPROCESS_PROTECTION;
        if (!MmIsAddressValid(prot)) {
            ObDereferenceObject(proc);
            return STATUS_UNSUCCESSFUL;
        }
        *PrevProtection = *prot;
        break;
    }
    case MYARK_MUTATION_TX_OP_FLAGS2: {
        PULONG flags = (PULONG)((PUCHAR)proc + MYARK_TX_EPROCESS_FLAGS2);
        if (!MmIsAddressValid(flags)) {
            ObDereferenceObject(proc);
            return STATUS_UNSUCCESSFUL;
        }
        *PrevFlags = *flags;
        break;
    }
    default:
        ObDereferenceObject(proc);
        return STATUS_INVALID_PARAMETER;
    }

    ObDereferenceObject(proc);
    return STATUS_SUCCESS;
}

//
// Write one op's new value (COMMIT's apply phase / ROLLBACK's undo phase).
//
static
NTSTATUS
MyArkTxApplyWrite(
    _In_ UINT32 OpType,
    _In_ UINT32 Pid,
    _In_ UCHAR NewProtection,
    _In_ ULONG NewFlags)
{
    NTSTATUS status;
    PEPROCESS proc = NULL;

    status = MyArkTxResolveEProcess(Pid, &proc);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    switch (OpType) {
    case MYARK_MUTATION_TX_OP_PPL: {
        PUCHAR prot = (PUCHAR)proc + MYARK_TX_EPROCESS_PROTECTION;
        if (!MmIsAddressValid(prot)) {
            ObDereferenceObject(proc);
            return STATUS_UNSUCCESSFUL;
        }
        KIRQL oldIrql = KeRaiseIrqlToDpcLevel();
        *prot = NewProtection;
        KeLowerIrql(oldIrql);
        break;
    }
    case MYARK_MUTATION_TX_OP_FLAGS2: {
        PULONG flags = (PULONG)((PUCHAR)proc + MYARK_TX_EPROCESS_FLAGS2);
        if (!MmIsAddressValid(flags)) {
            ObDereferenceObject(proc);
            return STATUS_UNSUCCESSFUL;
        }
        KIRQL oldIrql = KeRaiseIrqlToDpcLevel();
        *flags = NewFlags;
        KeLowerIrql(oldIrql);
        break;
    }
    default:
        ObDereferenceObject(proc);
        return STATUS_INVALID_PARAMETER;
    }

    ObDereferenceObject(proc);
    return STATUS_SUCCESS;
}

//
// Build the computed new value for one op from its spec + snapshot.
//
static
VOID
MyArkTxComputeNew(
    _In_ const MYARK_TX_OP* Op,
    _Out_ UCHAR* NewProtection,
    _Out_ PULONG NewFlags)
{
    *NewProtection = 0;
    *NewFlags = 0;

    switch (Op->OpType) {
    case MYARK_MUTATION_TX_OP_PPL:
        *NewProtection = (UCHAR)(Op->PplLevel & 0x07);
        break;
    case MYARK_MUTATION_TX_OP_FLAGS2:
        *NewFlags = (Op->PrevFlags & ~Op->FlagsMask) | (Op->FlagsValue & Op->FlagsMask);
        break;
    }
}

NTSTATUS
MyArkTxInit(
    VOID)
{
    RtlZeroMemory(g_TxSlots, sizeof(g_TxSlots));
    g_TxAuditWriteIdx = 0;
    g_TxAuditTotal = 0;
    return STATUS_SUCCESS;
}

NTSTATUS
MyArkTxPrepare(
    _In_ UINT32 OpCount,
    _In_ PMYARK_MUTATION_TX_OP_SPEC Specs,
    _Out_ PUINT32 TxTokenOut,
    _Out_ PUINT32 OpsAcceptedOut)
{
    KIRQL irql = ExAcquireSpinLockExclusive(&g_TxLock);
    LONG slot = -1;

    // Find a free slot.
    for (UINT32 i = 0; i < MYARK_MUTATION_TX_MAX_SLOTS; i++) {
        if (g_TxSlots[i].State == MYARK_MUTATION_TX_STATE_FREE) {
            slot = (LONG)i;
            break;
        }
    }
    if (slot < 0) {
        ExReleaseSpinLockExclusive(&g_TxLock, irql);
        *TxTokenOut = (UINT32)-1;
        *OpsAcceptedOut = 0;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    PMYARK_TX_SLOT tx = &g_TxSlots[slot];
    RtlZeroMemory(tx, sizeof(*tx));
    tx->State = MYARK_MUTATION_TX_STATE_PREPARED;
    tx->CreatedAt = KeQueryInterruptTime();

    UINT32 accepted = 0;
    for (UINT32 i = 0; i < OpCount && i < MYARK_MUTATION_TX_MAX_OPS; i++) {
        PMYARK_TX_OP op = &tx->Ops[accepted];
        op->OpType = Specs[i].OpType;
        op->Pid = Specs[i].Pid;
        op->PplLevel = Specs[i].PplLevel;
        op->FlagsMask = Specs[i].FlagsMask;
        op->FlagsValue = Specs[i].FlagsValue;
        op->Applied = FALSE;

        NTSTATUS st = MyArkTxReadCurrent(op->OpType, op->Pid,
                                          &op->PrevProtection, &op->PrevFlags);
        if (NT_SUCCESS(st)) {
            accepted++;
        }
        // Failed ops are not staged (the slot records only what succeeded).
    }

    if (accepted == 0) {
        tx->State = MYARK_MUTATION_TX_STATE_FREE;
        ExReleaseSpinLockExclusive(&g_TxLock, irql);
        *TxTokenOut = (UINT32)-1;
        *OpsAcceptedOut = 0;
        return STATUS_INVALID_PARAMETER;
    }

    tx->OpCount = accepted;
    *TxTokenOut = (UINT32)slot;
    *OpsAcceptedOut = accepted;

    MyArkTxAuditAppend((UINT32)slot, MYARK_MUTATION_TX_AUDIT_PREPARE,
                       accepted, STATUS_SUCCESS);
    ExReleaseSpinLockExclusive(&g_TxLock, irql);
    return STATUS_SUCCESS;
}

NTSTATUS
MyArkTxCommit(
    _In_ UINT32 TxToken,
    _Out_ PUINT32 OpsAppliedOut,
    _Out_ PUINT32 OpsFailedOut,
    _Out_ PUINT32 TxStateOut)
{
    KIRQL irql = ExAcquireSpinLockExclusive(&g_TxLock);

    if (TxToken >= MYARK_MUTATION_TX_MAX_SLOTS) {
        ExReleaseSpinLockExclusive(&g_TxLock, irql);
        *OpsAppliedOut = 0;
        *OpsFailedOut = 0;
        *TxStateOut = MYARK_MUTATION_TX_STATE_FREE;
        return STATUS_INVALID_PARAMETER;
    }

    PMYARK_TX_SLOT tx = &g_TxSlots[TxToken];
    if (tx->State != MYARK_MUTATION_TX_STATE_PREPARED) {
        ExReleaseSpinLockExclusive(&g_TxLock, irql);
        *OpsAppliedOut = 0;
        *OpsFailedOut = 0;
        *TxStateOut = tx->State;
        return STATUS_INVALID_DEVICE_STATE;
    }

    UINT32 applied = 0;
    UINT32 failed = 0;

    for (UINT32 i = 0; i < tx->OpCount; i++) {
        PMYARK_TX_OP op = &tx->Ops[i];
        UCHAR newProt;
        ULONG newFlags;
        MyArkTxComputeNew(op, &newProt, &newFlags);

        NTSTATUS st = MyArkTxApplyWrite(op->OpType, op->Pid,
                                         newProt, newFlags);
        if (NT_SUCCESS(st)) {
            op->Applied = TRUE;
            applied++;
        } else {
            failed++;
        }
    }

    tx->State = MYARK_MUTATION_TX_STATE_COMMITTED;
    *OpsAppliedOut = applied;
    *OpsFailedOut = failed;
    *TxStateOut = tx->State;

    MyArkTxAuditAppend(TxToken, MYARK_MUTATION_TX_AUDIT_COMMIT,
                       applied, STATUS_SUCCESS);
    ExReleaseSpinLockExclusive(&g_TxLock, irql);
    return STATUS_SUCCESS;
}

NTSTATUS
MyArkTxRollback(
    _In_ UINT32 TxToken,
    _Out_ PUINT32 OpsRolledBackOut,
    _Out_ PUINT32 TxStateOut)
{
    KIRQL irql = ExAcquireSpinLockExclusive(&g_TxLock);

    if (TxToken >= MYARK_MUTATION_TX_MAX_SLOTS) {
        ExReleaseSpinLockExclusive(&g_TxLock, irql);
        *OpsRolledBackOut = 0;
        *TxStateOut = MYARK_MUTATION_TX_STATE_FREE;
        return STATUS_INVALID_PARAMETER;
    }

    PMYARK_TX_SLOT tx = &g_TxSlots[TxToken];
    if (tx->State != MYARK_MUTATION_TX_STATE_PREPARED
        && tx->State != MYARK_MUTATION_TX_STATE_COMMITTED) {
        ExReleaseSpinLockExclusive(&g_TxLock, irql);
        *OpsRolledBackOut = 0;
        *TxStateOut = tx->State;
        return STATUS_INVALID_DEVICE_STATE;
    }

    UINT32 rolled = 0;

    for (UINT32 i = 0; i < tx->OpCount; i++) {
        PMYARK_TX_OP op = &tx->Ops[i];
        if (!op->Applied) {
            continue;                // was never written, nothing to undo
        }
        // Restore original values (op type determines which field matters).
        NTSTATUS st = MyArkTxApplyWrite(op->OpType, op->Pid,
                                         op->PrevProtection, op->PrevFlags);
        if (NT_SUCCESS(st)) {
            rolled++;
            op->Applied = FALSE;
        }
    }

    tx->State = MYARK_MUTATION_TX_STATE_ROLLED;
    *OpsRolledBackOut = rolled;
    *TxStateOut = tx->State;

    MyArkTxAuditAppend(TxToken, MYARK_MUTATION_TX_AUDIT_ROLLBACK,
                       rolled, STATUS_SUCCESS);
    ExReleaseSpinLockExclusive(&g_TxLock, irql);
    return STATUS_SUCCESS;
}

NTSTATUS
MyArkTxList(
    _Out_ PMYARK_MUTATION_TX_LIST_OUTPUT Output)
{
    KIRQL irql = ExAcquireSpinLockShared(&g_TxLock);

    RtlZeroMemory(Output, sizeof(*Output));
    Output->Status = (UINT32)STATUS_SUCCESS;
    Output->AuditWriteIdx = g_TxAuditWriteIdx;

    for (UINT32 i = 0; i < MYARK_MUTATION_TX_MAX_SLOTS; i++) {
        Output->Slots[i].State = g_TxSlots[i].State;
        Output->Slots[i].OpCount = g_TxSlots[i].OpCount;
        Output->Slots[i].Token = i;
        if (g_TxSlots[i].State != MYARK_MUTATION_TX_STATE_FREE) {
            Output->ActiveSlots++;
        }
    }

    // Copy the audit ring in write order (oldest first).
    UINT32 total = (g_TxAuditTotal < MYARK_MUTATION_TX_AUDIT_RING)
                       ? g_TxAuditTotal : MYARK_MUTATION_TX_AUDIT_RING;
    Output->AuditCount = total;
    UINT32 start = (g_TxAuditTotal > MYARK_MUTATION_TX_AUDIT_RING)
                       ? g_TxAuditWriteIdx - MYARK_MUTATION_TX_AUDIT_RING
                       : 0;
    for (UINT32 i = 0; i < total; i++) {
        UINT32 src = (start + i) % MYARK_MUTATION_TX_AUDIT_RING;
        Output->Audit[i].Timestamp = g_TxAuditTs[src];
        Output->Audit[i].TxToken = g_TxAuditToken[src];
        Output->Audit[i].Action = g_TxAuditAction[src];
        Output->Audit[i].OpsCount = g_TxAuditOps[src];
        Output->Audit[i].Status = g_TxAuditStatus[src];
    }

    ExReleaseSpinLockShared(&g_TxLock, irql);
    return STATUS_SUCCESS;
}

#endif // MYARK_MODULE_MUTATION
