// MyArk callback module: process-creation rule engine (R2-6).
//
// A PsSetCreateProcessNotifyRoutineEx callback registered at module init
// matches every process-creation image name against an in-memory rule
// table. Actions: DENY (Info->CreationStatus = STATUS_ACCESS_DENIED, the
// user-space create fails with ERROR_ACCESS_DENIED) and LOG_ONLY (count
// only). The engine must be enabled via RUNTIME_STATE before any rule
// fires; with zero rules or a disabled engine the notify callback is a
// single shared-lock check.
//
// Locking: an EX_SPIN_LOCK -- shared on the notify path ( DISPATCH_LEVEL
// safe, rules live in nonpaged .data), exclusive on rule mutation and on
// the RUNTIME_STATE enable/disable. Unload requires the notify callback
// to be removed first; PsSetCreateProcessNotifyRoutineEx(Remove=TRUE) is
// retried in Cleanup because it fails while other creations are in
// flight.

#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>
#include "Trace.h"
#include "myark_config.h"
#include "ioctl_validation.h"
#include "../../../shared/driver/MyArkCallbackIoctl.h"
#include "../../../shared/driver/MyArkSafetyToken.h"
#include "../../dispatch/safety_token.h"
#include "callback_descriptor.h"
#include "callback_internal.h"

#if MYARK_MODULE_CALLBACK

typedef struct _MYARK_PROC_RULE {
    WCHAR   ImageName[MYARK_CALLBACK_RULE_NAME_CHARS]; // file name only
    USHORT  NameLength;                               // chars, without NUL
    USHORT  Action;                                   // MYARK_CALLBACK_RULE_ACTION_*
    ULONG   Hits;                                     // matches for this rule
    BOOLEAN Used;
} MYARK_PROC_RULE, *PMYARK_PROC_RULE;

// Non-static: the ASK parking machinery (callback_ask.c) resolves slots
// under this same lock.
EX_SPIN_LOCK g_RulesLock;
static MYARK_PROC_RULE g_Rules[MYARK_CALLBACK_RULE_MAX];
static ULONG g_ActiveRules;
static ULONG g_TotalMatched;
static ULONG g_TotalDenied;
static BOOLEAN g_Enabled;
static BOOLEAN g_NotifyRegistered;

//
// Case-insensitive tail-name compare: the notify info carries a full
// path, rules carry a bare file name.
//
static
BOOLEAN
MyArkRulesImageMatches(
    _In_ PCWSTR Path,
    _In_ SIZE_T PathChars,
    _In_ const MYARK_PROC_RULE* Rule)
{
    SIZE_T lastSlash = 0;
    BOOLEAN sawSlash = FALSE;
    for (SIZE_T i = 0; i < PathChars; i++) {
        if (Path[i] == L'\\') {
            lastSlash = i;
            sawSlash = TRUE;
        }
    }
    SIZE_T start = sawSlash ? lastSlash + 1 : 0;
    SIZE_T len = PathChars - start;
    if (len != (SIZE_T)Rule->NameLength) {
        return FALSE;
    }
    for (SIZE_T i = 0; i < len; i++) {
        WCHAR a = Path[start + i];
        WCHAR b = Rule->ImageName[i];
        if (a >= L'A' && a <= L'Z') {
            a = (WCHAR)(a - L'A' + L'a');
        }
        if (b >= L'A' && b <= L'Z') {
            b = (WCHAR)(b - L'A' + L'a');
        }
        if (a != b) {
            return FALSE;
        }
    }
    return TRUE;
}

VOID
MyArkRulesProcessNotify(
    _In_ HANDLE ParentId,
    _In_ HANDLE ProcessId,
    _In_opt_ PPS_CREATE_NOTIFY_INFO Info)
{
    UNREFERENCED_PARAMETER(ParentId);
    UNREFERENCED_PARAMETER(ProcessId);

    if (Info == NULL || !NT_SUCCESS(Info->CreationStatus)) {
        return;                     // teardown or already-failing create
    }
    if (Info->ImageFileName == NULL || Info->ImageFileName->Buffer == NULL) {
        return;
    }

    ULONG askMatch = FALSE;
    WCHAR askName[MYARK_CALLBACK_ASK_NAME_CHARS];
    USHORT askNameChars = 0;

    KIRQL irql = ExAcquireSpinLockShared(&g_RulesLock);
    do {
        if (!g_Enabled || g_ActiveRules == 0) {
            break;
        }
        PCWSTR path = Info->ImageFileName->Buffer;
        SIZE_T chars = Info->ImageFileName->Length / sizeof(WCHAR);
        PMYARK_PROC_RULE hit = NULL;
        for (ULONG i = 0; i < MYARK_CALLBACK_RULE_MAX; i++) {
            PMYARK_PROC_RULE rule = &g_Rules[i];
            if (rule->Used
                && MyArkRulesImageMatches(path, chars, rule)) {
                hit = rule;
                break;
            }
        }
        if (hit == NULL) {
            break;
        }
        // Shared lock allows concurrent notify CPUs: keep the counters
        // atomic (ULONG++ would drop updates).
        InterlockedIncrement((volatile LONG *)&hit->Hits);
        InterlockedIncrement((volatile LONG *)&g_TotalMatched);
        if (hit->Action == MYARK_CALLBACK_RULE_ACTION_DENY) {
            InterlockedIncrement((volatile LONG *)&g_TotalDenied);
            Info->CreationStatus = STATUS_ACCESS_DENIED;
        } else if (hit->Action == MYARK_CALLBACK_RULE_ACTION_ASK) {
            //
            // The park itself must run with NO spin lock held (it waits up
            // to 5 s); capture what the wait needs and act after release.
            //
            askMatch = TRUE;
            PCWSTR path2 = Info->ImageFileName->Buffer;
            SIZE_T chars2 = Info->ImageFileName->Length / sizeof(WCHAR);
            SIZE_T lastSlash = 0;
            for (SIZE_T i2 = 0; i2 < chars2; i2++) {
                if (path2[i2] == L'\\') {
                    lastSlash = i2;
                }
            }
            SIZE_T start = (path2[lastSlash] == L'\\') ? lastSlash + 1 : 0;
            SIZE_T nameLen = chars2 - start;
            if (nameLen >= MYARK_CALLBACK_ASK_NAME_CHARS) {
                nameLen = MYARK_CALLBACK_ASK_NAME_CHARS - 1;
            }
            RtlCopyMemory(askName, path2 + start, nameLen * sizeof(WCHAR));
            askName[nameLen] = L'\0';
            askNameChars = (USHORT)(nameLen + 1);
        }
    } while (FALSE);
    ExReleaseSpinLockShared(&g_RulesLock, irql);

    if (askMatch) {
        if (MyArkAskPark(Info->ParentProcessId, ProcessId, askName, askNameChars)) {
            Info->CreationStatus = STATUS_ACCESS_DENIED;
        }
    }
}

//
// Bare image-name check (same identifier discipline as the R2-5 service
// name): no separators, no path shapes.
//
static
NTSTATUS
MyArkRulesValidateImageName(
    _In_ PCWSTR Name,
    _Out_ PULONG LengthOut)
{
    SIZE_T len = wcsnlen(Name, MYARK_CALLBACK_RULE_NAME_CHARS);
    if (len == 0 || len >= MYARK_CALLBACK_RULE_NAME_CHARS) {
        return STATUS_INVALID_PARAMETER;
    }
    for (SIZE_T i = 0; i < len; i++) {
        WCHAR c = Name[i];
        BOOLEAN ok = (c >= L'0' && c <= L'9')
                     || (c >= L'a' && c <= L'z')
                     || (c >= L'A' && c <= L'Z')
                     || c == L'_' || c == L'-' || c == L'.';
        if (!ok) {
            return STATUS_INVALID_PARAMETER;
        }
    }
    *LengthOut = (ULONG)len;
    return STATUS_SUCCESS;
}

NTSTATUS
MyArkCallbackIoctlSetRules(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    PMYARK_CALLBACK_SET_RULES_INPUT inBuf = NULL;
    size_t inSize = 0;
    NTSTATUS status;

    if (InputBufferLength < sizeof(MYARK_CALLBACK_SET_RULES_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_CALLBACK_SET_RULES_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    WCHAR name[MYARK_CALLBACK_RULE_NAME_CHARS];
    ULONG operation = inBuf->Operation;
    ULONG action = inBuf->RuleAction;
    RtlCopyMemory(name, inBuf->ImageName, sizeof(name));

    status = MyArkSafetyTokenValidate(&inBuf->Token,
                                      MYARK_CALLBACK_OP_SET_RULES,
                                      (UINT32)(UINT_PTR)PsGetCurrentProcessId());
    if (!NT_SUCCESS(status)) {
        return STATUS_ACCESS_DENIED;
    }
    if (operation < MYARK_CALLBACK_RULES_OP_SET
        || operation > MYARK_CALLBACK_RULES_OP_CLEAR) {
        return STATUS_INVALID_PARAMETER;
    }
    //
    // Action matters only for SET (REMOVE/CLEAR ignore it); garbage on SET
    // is rejected rather than silently coerced to the strictest action.
    //
    if (operation == MYARK_CALLBACK_RULES_OP_SET
        && action != MYARK_CALLBACK_RULE_ACTION_DENY
        && action != MYARK_CALLBACK_RULE_ACTION_LOG_ONLY
        && action != MYARK_CALLBACK_RULE_ACTION_ASK) {
        return STATUS_INVALID_PARAMETER;
    }

    ULONG nameLen = 0;
    if (operation != MYARK_CALLBACK_RULES_OP_CLEAR) {
        status = MyArkRulesValidateImageName(name, &nameLen);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }

    KIRQL irql = ExAcquireSpinLockExclusive(&g_RulesLock);
    if (operation == MYARK_CALLBACK_RULES_OP_CLEAR) {
        RtlZeroMemory(g_Rules, sizeof(g_Rules));
        g_ActiveRules = 0;
    } else if (operation == MYARK_CALLBACK_RULES_OP_REMOVE) {
        for (ULONG i = 0; i < MYARK_CALLBACK_RULE_MAX; i++) {
            PMYARK_PROC_RULE rule = &g_Rules[i];
            if (rule->Used
                && _wcsnicmp(rule->ImageName, name,
                             MYARK_CALLBACK_RULE_NAME_CHARS) == 0) {
                RtlZeroMemory(rule, sizeof(*rule));
                g_ActiveRules--;
                break;
            }
        }
    } else {  // SET: replace the action of an existing rule, else add
        PMYARK_PROC_RULE slot = NULL;
        for (ULONG i = 0; i < MYARK_CALLBACK_RULE_MAX; i++) {
            PMYARK_PROC_RULE rule = &g_Rules[i];
            if (rule->Used
                && _wcsnicmp(rule->ImageName, name,
                             MYARK_CALLBACK_RULE_NAME_CHARS) == 0) {
                slot = rule;
                break;
            }
            if (slot == NULL && !rule->Used) {
                slot = rule;
            }
        }
        if (slot != NULL) {
            if (!slot->Used) {
                RtlCopyMemory(slot->ImageName, name,
                              nameLen * sizeof(WCHAR));
                slot->NameLength = (USHORT)nameLen;
                slot->Used = TRUE;
                g_ActiveRules++;
            }
            slot->Action = (USHORT)action;
        } else {
            ExReleaseSpinLockExclusive(&g_RulesLock, irql);
            return STATUS_INSUFFICIENT_RESOURCES;   // rule table full
        }
    }
    ULONG active = g_ActiveRules;
    ExReleaseSpinLockExclusive(&g_RulesLock, irql);

    PMYARK_CALLBACK_SET_RULES_OUTPUT outBuf = NULL;
    size_t outSize = 0;
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         sizeof(MYARK_CALLBACK_SET_RULES_OUTPUT),
                                         (PVOID*)&outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    outBuf->Status = 0;
    outBuf->ActiveRules = active;
    *BytesReturned = sizeof(MYARK_CALLBACK_SET_RULES_OUTPUT);
    return STATUS_SUCCESS;
}

NTSTATUS
MyArkCallbackIoctlRuntimeState(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    PMYARK_CALLBACK_RUNTIME_STATE_INPUT inBuf = NULL;
    size_t inSize = 0;
    NTSTATUS status;

    if (InputBufferLength < sizeof(MYARK_CALLBACK_RUNTIME_STATE_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_CALLBACK_RUNTIME_STATE_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    ULONG mode = inBuf->Mode;
    if (mode > MYARK_CALLBACK_STATE_DISABLE) {
        return STATUS_INVALID_PARAMETER;
    }
    if (mode != MYARK_CALLBACK_STATE_QUERY) {
        status = MyArkSafetyTokenValidate(&inBuf->Token,
                                          MYARK_CALLBACK_OP_RUNTIME_STATE,
                                          (UINT32)(UINT_PTR)PsGetCurrentProcessId());
        if (!NT_SUCCESS(status)) {
            return STATUS_ACCESS_DENIED;
        }
        KIRQL irql = ExAcquireSpinLockExclusive(&g_RulesLock);
        g_Enabled = (mode == MYARK_CALLBACK_STATE_ENABLE);
        ExReleaseSpinLockExclusive(&g_RulesLock, irql);
    }

    PMYARK_CALLBACK_RUNTIME_STATE_OUTPUT outBuf = NULL;
    size_t outSize = 0;
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         sizeof(MYARK_CALLBACK_RUNTIME_STATE_OUTPUT),
                                         (PVOID*)&outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    KIRQL irql = ExAcquireSpinLockShared(&g_RulesLock);
    outBuf->Enabled = g_Enabled ? 1 : 0;
    outBuf->ActiveRules = g_ActiveRules;
    outBuf->TotalMatched = g_TotalMatched;
    outBuf->TotalDenied = g_TotalDenied;
    ExReleaseSpinLockShared(&g_RulesLock, irql);
    *BytesReturned = sizeof(MYARK_CALLBACK_RUNTIME_STATE_OUTPUT);
    return STATUS_SUCCESS;
}

NTSTATUS
MyArkRulesInit(
    VOID)
{
    g_RulesLock = 0;   // EX_SPIN_LOCK is a plain ULONG: 0 = unlocked
    MyArkAskInit();
    NTSTATUS status = PsSetCreateProcessNotifyRoutineEx(MyArkRulesProcessNotify,
                                                        FALSE);
    if (NT_SUCCESS(status)) {
        g_NotifyRegistered = TRUE;
    }
    return status;
}

VOID
MyArkRulesCleanup(
    VOID)
{
    if (g_NotifyRegistered) {
        //
        // Fail-open every parked creation first: the notify removal below
        // fails while a callback is still in flight (parked = up to 5 s).
        //
        MyArkAskFailOpenAll();
        //
        // The removal fails while other creations are in flight; retry
        // rather than leaving the callback pointing at unloading code.
        //
        for (ULONG i = 0; i < 100; i++) {
            if (NT_SUCCESS(PsSetCreateProcessNotifyRoutineEx(
                               MyArkRulesProcessNotify, TRUE))) {
                g_NotifyRegistered = FALSE;
                break;
            }
            LARGE_INTEGER stall;
            stall.QuadPart = -10 * 1000 * 100;   // 100 ms
            KeDelayExecutionThread(KernelMode, FALSE, &stall);
        }
        if (g_NotifyRegistered) {
            //
            // Giving up is catastrophic: unloading with a live Ps notify
            // callback leaves the registration array pointing at freed
            // image memory -- the next process creation bugchecks.
            // Persist the error so the failure is at least attributable.
            //
            TraceEvents(TRACE_LEVEL_ERROR,
                        MYARK_TRACE_CALLBACK,
                        "MyArkRulesCleanup: notify removal FAILED after "
                        "retries -- unload will leave a live callback "
                        "(next process create will bugcheck)");
        }
    }
}

#endif // MYARK_MODULE_CALLBACK
