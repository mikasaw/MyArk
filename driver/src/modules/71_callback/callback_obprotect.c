// MyArk callback module: ObCallbacks STRIP_ACCESS (R3-9).
//
// ObRegisterCallbacks on PsProcessType: when the target of a handle
// create/duplicate is a listed PID, dangerous rights (TERMINATE /
// CREATE_THREAD / VM_OPERATION / VM_READ / VM_WRITE / DUP_HANDLE /
// SUSPEND_RESUME) are stripped from the desired access mask. QUERY and
// SYNCHRONIZE survive, so the opener still gets a valid handle but cannot
// kill, write or inject. This is the standard "handle stripping" defence
// for hidden processes (R2-5 DKOM makes the process invisible to the
// public list; R3-9 makes it resilient to direct OpenProcess).
//
// The PID list lives in nonpaged .data guarded by the same EX_SPIN_LOCK
// pattern as the R2-6 rules engine (shared on the pre-op path, exclusive
// on list mutation). ObUnRegisterCallbacks must run before the module
// unload path; it is called from MyArkObProtCleanup.

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "myark_config.h"
#include "../../../shared/driver/MyArkCallbackIoctl.h"
#include "callback_internal.h"

#if MYARK_MODULE_CALLBACK

// PROCESS_* access rights (ABI-stable values, not in the ntddk wdm.h flavor).
#define MYARK_PROC_TERMINATE        0x0001
#define MYARK_PROC_CREATE_THREAD    0x0002
#define MYARK_PROC_VM_OPERATION     0x0008
#define MYARK_PROC_VM_READ          0x0010
#define MYARK_PROC_VM_WRITE         0x0020
#define MYARK_PROC_DUP_HANDLE       0x0040
#define MYARK_PROC_SUSPEND_RESUME   0x0800

#define MYARK_OB_PROT_ALTITUDE L"389998"

// Dangerous rights stripped from protected-process handle opens.
#define MYARK_OB_PROT_STRIP_MASK (\
    MYARK_PROC_TERMINATE        | \
    MYARK_PROC_CREATE_THREAD    | \
    MYARK_PROC_VM_OPERATION     | \
    MYARK_PROC_VM_READ          | \
    MYARK_PROC_VM_WRITE         | \
    MYARK_PROC_DUP_HANDLE       | \
    MYARK_PROC_SUSPEND_RESUME)

static EX_SPIN_LOCK g_ObProtLock;
static UINT32       g_ObProtPids[MYARK_CALLBACK_OB_PROTECT_MAX];
static UINT32       g_ObProtCount;
static UINT64       g_ObProtStrips[MYARK_CALLBACK_OB_PROTECT_MAX];
static UINT64       g_ObProtTotalStrips;
static BOOLEAN      g_ObProtRegistered;
static PVOID        g_ObProtHandle;

static
OB_PREOP_CALLBACK_STATUS
MyArkObProtPreOp(
    _In_ PVOID RegistrationContext,
    _In_ POB_PRE_OPERATION_INFORMATION OperationInformation)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    if (!g_ObProtRegistered || g_ObProtCount == 0) {
        return OB_PREOP_SUCCESS;
    }

    // Only process objects: thread-type stripping is a follow-up (R3-9b).
    if (OperationInformation->ObjectType != *PsProcessType) {
        return OB_PREOP_SUCCESS;
    }
    // Kernel handles (system worker threads opening processes for internal
    // bookkeeping) are exempt: stripping them could break the system.
    if (OperationInformation->KernelHandle) {
        return OB_PREOP_SUCCESS;
    }

    HANDLE hpid = PsGetProcessId(OperationInformation->Object);
    UINT32 target = (UINT32)(UINT_PTR)hpid;

    PACCESS_MASK mask;
    if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
        mask = &OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
    } else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        mask = &OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;
    } else {
        return OB_PREOP_SUCCESS;
    }

    KIRQL irql = ExAcquireSpinLockShared(&g_ObProtLock);
    for (UINT32 i = 0; i < g_ObProtCount; i++) {
        if (g_ObProtPids[i] == target) {
            UINT64 dangerous = *mask & MYARK_OB_PROT_STRIP_MASK;
            if (dangerous != 0) {
                *mask &= ~((ACCESS_MASK)MYARK_OB_PROT_STRIP_MASK);
                // Shared lock allows concurrent strip CPUs: use interlocked
                // to keep per-slot and total counters loss-free.
                InterlockedIncrement64((volatile LONG64 *)&g_ObProtStrips[i]);
                InterlockedIncrement64((volatile LONG64 *)&g_ObProtTotalStrips);
            }
            break;
        }
    }
    ExReleaseSpinLockShared(&g_ObProtLock, irql);
    return OB_PREOP_SUCCESS;
}

//
// PID list management (under exclusive lock). Returns STATUS_SUCCESS with
// *AppliedOut = 0 for idempotent no-ops.
//
static
NTSTATUS
MyArkObProtApply(
    _In_ UINT32 Action,
    _In_ UINT32 Pid,
    _Out_ PUINT32 AppliedOut,
    _Out_ PUINT32 CountOut)
{
    KIRQL  irql = ExAcquireSpinLockExclusive(&g_ObProtLock);
    UINT32 i;
    UINT32 j;

    *AppliedOut = 0;
    *CountOut = g_ObProtCount;

    switch (Action) {
    case MYARK_CALLBACK_OB_PROTECT_ACTION_ADD:
        if (Pid == 0) {
            // 0 = "no requester" (system threads): listing it would strip
            // every kernel-side handle open. System (4) stays allowed.
            ExReleaseSpinLockExclusive(&g_ObProtLock, irql);
            return STATUS_INVALID_PARAMETER;
        }
        for (i = 0; i < g_ObProtCount; i++) {
            if (g_ObProtPids[i] == Pid) {
                break;
            }
        }
        if (i < g_ObProtCount) {
            break;                              // already listed
        }
        if (g_ObProtCount >= MYARK_CALLBACK_OB_PROTECT_MAX) {
            ExReleaseSpinLockExclusive(&g_ObProtLock, irql);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        g_ObProtPids[g_ObProtCount++] = Pid;
        *AppliedOut = 1;
        *CountOut = g_ObProtCount;
        break;

    case MYARK_CALLBACK_OB_PROTECT_ACTION_REMOVE:
        for (i = 0; i < g_ObProtCount; i++) {
            if (g_ObProtPids[i] == Pid) {
                break;
            }
        }
        if (i >= g_ObProtCount) {
            break;                              // not listed, no-op
        }
        for (j = i; j + 1 < g_ObProtCount; j++) {
            g_ObProtPids[j] = g_ObProtPids[j + 1];
            g_ObProtStrips[j] = g_ObProtStrips[j + 1];
        }
        g_ObProtCount--;
        g_ObProtPids[g_ObProtCount] = 0;
        g_ObProtStrips[g_ObProtCount] = 0;
        *AppliedOut = 1;
        *CountOut = g_ObProtCount;
        break;

    case MYARK_CALLBACK_OB_PROTECT_ACTION_CLEAR:
        *AppliedOut = (g_ObProtCount != 0) ? 1 : 0;
        g_ObProtCount = 0;
        RtlZeroMemory(g_ObProtPids, sizeof(g_ObProtPids));
        RtlZeroMemory(g_ObProtStrips, sizeof(g_ObProtStrips));
        *CountOut = 0;
        break;

    default:
        ExReleaseSpinLockExclusive(&g_ObProtLock, irql);
        return STATUS_INVALID_PARAMETER;
    }

    ExReleaseSpinLockExclusive(&g_ObProtLock, irql);
    return STATUS_SUCCESS;
}

NTSTATUS
MyArkObProtInit(
    VOID)
{
    RtlZeroMemory(g_ObProtPids, sizeof(g_ObProtPids));
    RtlZeroMemory(g_ObProtStrips, sizeof(g_ObProtStrips));
    g_ObProtCount = 0;
    g_ObProtTotalStrips = 0;
    g_ObProtRegistered = FALSE;
    g_ObProtHandle = NULL;
    return STATUS_SUCCESS;
}

NTSTATUS
MyArkObProtArm(
    VOID)
{
    OB_CALLBACK_REGISTRATION cbReg = { 0 };
    OB_OPERATION_REGISTRATION opReg[1] = { { 0 } };
    UNICODE_STRING altitude = RTL_CONSTANT_STRING(MYARK_OB_PROT_ALTITUDE);
    NTSTATUS status;

    if (g_ObProtRegistered) {
        return STATUS_DEVICE_ALREADY_ATTACHED;
    }

    opReg[0].ObjectType = PsProcessType;
    opReg[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    opReg[0].PreOperation = MyArkObProtPreOp;
    opReg[0].PostOperation = NULL;

    cbReg.Version = OB_FLT_REGISTRATION_VERSION;
    cbReg.OperationRegistrationCount = 1;
    cbReg.Altitude = altitude;
    cbReg.RegistrationContext = NULL;
    cbReg.OperationRegistration = opReg;

    status = ObRegisterCallbacks(&cbReg, &g_ObProtHandle);
    if (NT_SUCCESS(status)) {
        g_ObProtRegistered = TRUE;
    }
    return status;
}

VOID
MyArkObProtDisarm(
    VOID)
{
    if (g_ObProtRegistered && g_ObProtHandle != NULL) {
        ObUnRegisterCallbacks(g_ObProtHandle);
        g_ObProtHandle = NULL;
        g_ObProtRegistered = FALSE;
    }
}

NTSTATUS
MyArkObProtFillStatus(
    _Out_ PMYARK_CALLBACK_OB_PROTECT_STATUS_OUTPUT Output)
{
    KIRQL irql = ExAcquireSpinLockShared(&g_ObProtLock);

    Output->Status = (UINT32)STATUS_SUCCESS;
    Output->Registered = g_ObProtRegistered ? 1 : 0;
    Output->Count = g_ObProtCount;
    Output->Reserved1 = 0;
    Output->TotalStrips = g_ObProtTotalStrips;
    RtlCopyMemory(Output->StripCount, g_ObProtStrips, sizeof(g_ObProtStrips));
    RtlCopyMemory(Output->Pids, g_ObProtPids, sizeof(g_ObProtPids));
    Output->Reserved2 = 0;

    ExReleaseSpinLockShared(&g_ObProtLock, irql);
    return STATUS_SUCCESS;
}

// Convenience export for the IOCTL handler.
NTSTATUS
MyArkObProtSet(
    _In_ UINT32 Action,
    _In_ UINT32 Pid,
    _Out_ PMYARK_CALLBACK_OB_PROTECT_SET_OUTPUT Output)
{
    NTSTATUS status = MyArkObProtApply(Action, Pid,
                                       &Output->Applied, &Output->Count);
    Output->Status = (UINT32)status;
    return status;
}

#endif // MYARK_MODULE_CALLBACK
