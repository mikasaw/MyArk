// MyArk hwid module: R3-1 GPU serial class (registry rewrite).
//
// The GPU serial string lives under the display device class key
//   HKLM\SYSTEM\CurrentControlSet\Control\Class\
//       {4d36e968-e325-11ce-bfc1-08002be10318}\00NN
// as REG_BINARY values:
//   HardwareInformation.SerialNumber    - adapter serial bytes
//   HardwareInformation.RegistryString  - ASCII serial used by some
//                                         vendor stacks
// APPLY caches the first subkey holding either value, then registers a
// CmCallback that rewrites KeyValuePartialInformation responses for that
// key path (same-length policy, REG_BINARY only). RESTORE unregisters
// and re-reads the value to prove the original bytes came back.

#include <ntddk.h>
#include <ntstrsafe.h>
#include "hwid_spoof_internal.h"
#include "../../framework/core_globals.h"

#if MYARK_MODULE_HWID

#define MYARK_TRACE_SPOOF "[hwid-spoof] "

#define MYARK_HWID_GPU_ALTITUDE   L"389998"

#define MYARK_HWID_GPU_KEY_MAX    320
#define MYARK_HWID_GPU_SCAN_MAX   64

static CONST WCHAR MyArkHwidGpuClassFmt[] =
    L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Class\\"
    L"{4d36e968-e325-11ce-bfc1-08002be10318}\\%02u";

static CONST UNICODE_STRING MyArkHwidGpuValueNames[2] = {
    RTL_CONSTANT_STRING(L"HardwareInformation.SerialNumber"),
    RTL_CONSTANT_STRING(L"HardwareInformation.RegistryString"),
};

static LARGE_INTEGER g_MyArkHwidGpuCookie = { 0 };
static BOOLEAN       g_MyArkHwidGpuRegistered = FALSE;
static WCHAR         g_MyArkHwidGpuKeyPath[MYARK_HWID_GPU_KEY_MAX];
static UNICODE_STRING g_MyArkHwidGpuKeyName = { 0, 0, g_MyArkHwidGpuKeyPath };
static ULONG         g_MyArkHwidGpuValueIndex = 0;

//
// Read one REG_BINARY value. The stack buffer covers the largest value
// the engine accepts (Value cap + KEY_VALUE_PARTIAL_INFORMATION header);
// anything longer is rejected, so a single query suffices.
//
static
NTSTATUS
MyArkHwidGpuReadValue(
    _In_ HANDLE            KeyHandle,
    _In_ PUNICODE_STRING   ValueName,
    _Out_ PUCHAR           Data,
    _Inout_ PULONG         DataLen)
{
    UCHAR                  small[MYARK_HWID_SPOOF_VALUE_MAX_BYTES
                                 + FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data)];
    PKEY_VALUE_PARTIAL_INFORMATION info = (PKEY_VALUE_PARTIAL_INFORMATION)small;
    ULONG                  needed = 0;
    NTSTATUS               status;

    status = ZwQueryValueKey(KeyHandle,
                             ValueName,
                             KeyValuePartialInformation,
                             small,
                             sizeof(small),
                             &needed);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (info->Type != REG_BINARY || info->DataLength == 0) {
        return STATUS_NOT_FOUND;
    }
    if (info->DataLength > *DataLen) {
        info->DataLength = *DataLen;
    }
    RtlCopyMemory(Data, info->Data, info->DataLength);
    *DataLen = info->DataLength;
    return STATUS_SUCCESS;
}

//
// Find the first display-class subkey carrying a GPU serial value and
// cache its full path + original bytes.
//
static
NTSTATUS
MyArkHwidGpuLocateKey(
    _Out_ PUCHAR Real,
    _Inout_ PULONG RealLen)
{
    WCHAR          path[MYARK_HWID_GPU_KEY_MAX];
    UNICODE_STRING uni;
    HANDLE         key = NULL;
    OBJECT_ATTRIBUTES attrs;
    NTSTATUS       status;
    ULONG          idx;
    ULONG          valueIdx;

    for (idx = 0; idx < MYARK_HWID_GPU_SCAN_MAX; idx++) {
        RtlStringCbPrintfW(path, sizeof(path) / sizeof(WCHAR),
                           MyArkHwidGpuClassFmt, idx);
        RtlInitUnicodeString(&uni, path);
        InitializeObjectAttributes(&attrs,
                                   &uni,
                                   OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                                   NULL,
                                   NULL);
        status = ZwOpenKey(&key, KEY_READ, &attrs);
        if (!NT_SUCCESS(status)) {
            continue;
        }
        for (valueIdx = 0; valueIdx < 2; valueIdx++) {
            ULONG len = *RealLen;
            status = MyArkHwidGpuReadValue(key,
                                           (PUNICODE_STRING)&MyArkHwidGpuValueNames[valueIdx],
                                           Real,
                                           &len);
            if (NT_SUCCESS(status)) {
                RtlStringCbCopyW(g_MyArkHwidGpuKeyPath,
                                 sizeof(g_MyArkHwidGpuKeyPath),
                                 path);
                RtlInitUnicodeString(&g_MyArkHwidGpuKeyName, g_MyArkHwidGpuKeyPath);
                g_MyArkHwidGpuValueIndex = valueIdx;
                *RealLen = len;
                ZwClose(key);
                return STATUS_SUCCESS;
            }
        }
        ZwClose(key);
    }
    return STATUS_NOT_FOUND;
}

//
// Post-query callback: rewrite KeyValuePartialInformation data for the
// cached key path + value name. Everything else passes untouched.
//
static
NTSTATUS
MyArkHwidGpuPostQuery(
    _In_opt_ PVOID Context,
    _In_opt_ PVOID Arg1,
    _In_opt_ PVOID Arg2)
{
    PREG_QUERY_VALUE_KEY_INFORMATION info = (PREG_QUERY_VALUE_KEY_INFORMATION)Arg1;
    PKEY_VALUE_PARTIAL_INFORMATION   partial;
    PUNICODE_STRING                  keyName = NULL;
    UCHAR                            spoofBuf[MYARK_HWID_SPOOF_VALUE_MAX_BYTES];
    ULONG                            spoofLen = 0;
    ULONG                            copy;
    ULONG                            oldIrql;
    PMYARK_HWID_SPOOF_CLASS_STATE    state;

    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(Arg2);

    if (info == NULL
        || info->KeyValueInformationClass != KeyValuePartialInformation
        || info->KeyValueInformation == NULL) {
        return STATUS_SUCCESS;
    }

    state = MyArkHwidSpoofClassState(MYARK_HWID_SPOOF_CLASS_GPU_SERIAL);
    if (state == NULL || !state->Active || !state->CacheValid) {
        return STATUS_SUCCESS;
    }
    if (g_MyArkHwidGpuKeyName.Length == 0) {
        // Unpublished window (registered but not published yet): a
        // zero-length prefix would match every key path.
        return STATUS_SUCCESS;
    }

    if (CmCallbackGetKeyObjectIDEx(&g_MyArkHwidGpuCookie,
                                   info->Object,
                                   NULL,
                                   &keyName,
                                   0) != STATUS_SUCCESS
        || keyName == NULL) {
        return STATUS_SUCCESS;
    }

    if (RtlPrefixUnicodeString(&g_MyArkHwidGpuKeyName, keyName, TRUE)) {
        BOOLEAN nameMatch =
            RtlEqualUnicodeString(info->ValueName,
                                  (PUNICODE_STRING)&MyArkHwidGpuValueNames[g_MyArkHwidGpuValueIndex],
                                  TRUE);
        if (nameMatch) {
            partial = (PKEY_VALUE_PARTIAL_INFORMATION)info->KeyValueInformation;
            if (partial->Type == REG_BINARY && partial->DataLength != 0) {
                oldIrql = MyArkHwidSpoofLockShared();
                if (state->Active && state->CacheValid) {
                    spoofLen = state->SpoofLen;
                    RtlCopyMemory(spoofBuf, state->Spoof, spoofLen);
                }
                MyArkHwidSpoofUnlockShared(oldIrql);

                if (spoofLen != 0) {
                    copy = (spoofLen < partial->DataLength)
                               ? spoofLen : partial->DataLength;
                    RtlCopyMemory(partial->Data, spoofBuf, copy);
                    if (copy < partial->DataLength) {
                        RtlZeroMemory(partial->Data + copy,
                                      partial->DataLength - copy);
                    }
                    InterlockedIncrement(&state->RewrittenCount);
                }
            }
        }
    }

    CmCallbackReleaseKeyObjectIDEx(keyName);
    return STATUS_SUCCESS;
}

NTSTATUS
MyArkHwidSpoofGpuDryRun(
    _In_ PMYARK_HWID_SPOOF_CLASS_STATE State,
    _In_ PUCHAR                        Spoof,
    _In_ ULONG                         SpoofLen,
    _Out_ PUCHAR                       Real,
    _Inout_ PULONG                     RealLen)
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(Spoof);

    // A DRY_RUN while the class is applied would (a) read the spoofed
    // bytes back through our own CmCallback and (b) churn the key-path
    // globals the callback matches on -- reject instead.
    if (State->Active) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (SpoofLen == 0 || SpoofLen > MYARK_HWID_SPOOF_VALUE_MAX_BYTES) {
        return STATUS_INVALID_PARAMETER;
    }

    // LocateKey caches the path globals on success; DRY_RUN must leave
    // no state behind, so undo that immediately.
    status = MyArkHwidGpuLocateKey(Real, RealLen);
    if (NT_SUCCESS(status)) {
        g_MyArkHwidGpuKeyPath[0] = 0;
        g_MyArkHwidGpuKeyName.Length = 0;
        g_MyArkHwidGpuKeyName.MaximumLength = 0;
        g_MyArkHwidGpuValueIndex = 0;
    }
    return status;
}

NTSTATUS
MyArkHwidSpoofGpuApply(
    _Inout_ PMYARK_HWID_SPOOF_CLASS_STATE State,
    _In_ PUCHAR                           Spoof,
    _In_ ULONG                            SpoofLen,
    _Out_ PUCHAR                          Real,
    _Inout_ PULONG                        RealLen)
{
    NTSTATUS       status;
    ULONG          oldIrql;

    if (State->Active) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (SpoofLen == 0 || SpoofLen > MYARK_HWID_SPOOF_VALUE_MAX_BYTES) {
        return STATUS_INVALID_PARAMETER;
    }
    if (g_MyArkCoreDriverObject == NULL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (g_MyArkHwidGpuRegistered) {
        // A live registration means a prior APPLY never restored; a second
        // APPLY would overwrite the cookie and leak the first callback.
        return STATUS_INVALID_DEVICE_STATE;
    }

    // 1. Locate + cache the original value bytes.
    status = MyArkHwidGpuLocateKey(Real, RealLen);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // 2. Register the rewrite callback. RTL_CONSTANT_STRING is an
    // initializer, not an assignable expression.
    UNICODE_STRING altitude = RTL_CONSTANT_STRING(MYARK_HWID_GPU_ALTITUDE);
    status = CmRegisterCallbackEx(MyArkHwidGpuPostQuery,
                                  &altitude,
                                  g_MyArkCoreDriverObject,
                                  NULL,
                                  &g_MyArkHwidGpuCookie,
                                  NULL);
    if (!NT_SUCCESS(status)) {
        g_MyArkHwidGpuKeyPath[0] = 0;
        g_MyArkHwidGpuKeyName.Length = 0;
        g_MyArkHwidGpuKeyName.MaximumLength = 0;
        return status;
    }
    g_MyArkHwidGpuRegistered = TRUE;

    // 3. Publish.
    oldIrql = MyArkHwidSpoofLockExclusive();
    State->SpoofLen = SpoofLen;
    RtlCopyMemory(State->Spoof, Spoof, SpoofLen);
    State->CacheLen = *RealLen;
    RtlCopyMemory(State->Cache, Real, *RealLen);
    State->CacheValid = TRUE;
    State->Active = TRUE;
    State->LastStatus = STATUS_SUCCESS;
    MyArkHwidSpoofUnlockExclusive(oldIrql);

    return STATUS_SUCCESS;
}

//
// Module-cleanup path: drop the callback registration if a RESTORE never
// ran (unload while applied).
//
VOID
MyArkHwidSpoofGpuTeardown(VOID)
{
    if (g_MyArkHwidGpuRegistered) {
        CmUnRegisterCallback(g_MyArkHwidGpuCookie);
        g_MyArkHwidGpuRegistered = FALSE;
        g_MyArkHwidGpuCookie.QuadPart = 0;
    }
    g_MyArkHwidGpuKeyPath[0] = 0;
    g_MyArkHwidGpuKeyName.Length = 0;
    g_MyArkHwidGpuKeyName.MaximumLength = 0;
    g_MyArkHwidGpuValueIndex = 0;
}

NTSTATUS
MyArkHwidSpoofGpuRestore(
    _Inout_ PMYARK_HWID_SPOOF_CLASS_STATE State,
    _Out_ PUCHAR                          Real,
    _Inout_ PULONG                        RealLen)
{
    UCHAR    cache[MYARK_HWID_SPOOF_VALUE_MAX_BYTES];
    ULONG    cacheLen = 0;
    BOOLEAN  hadCache;
    HANDLE   key = NULL;
    NTSTATUS status;
    ULONG    oldIrql;
    BOOLEAN  match;

    oldIrql = MyArkHwidSpoofLockExclusive();
    hadCache = State->CacheValid;
    cacheLen = State->CacheLen;
    RtlCopyMemory(cache, State->Cache, State->CacheLen);
    State->Active = FALSE;
    State->CacheValid = FALSE;
    State->SpoofLen = 0;
    MyArkHwidSpoofUnlockExclusive(oldIrql);

    if (g_MyArkHwidGpuRegistered) {
        CmUnRegisterCallback(g_MyArkHwidGpuCookie);
        g_MyArkHwidGpuRegistered = FALSE;
        g_MyArkHwidGpuCookie.QuadPart = 0;
    }

    if (!hadCache) {
        *RealLen = 0;
        State->LastStatus = STATUS_INVALID_DEVICE_STATE;
        return STATUS_INVALID_DEVICE_STATE;
    }

    // Re-read the value (callback gone) and compare with the cache.
    {
        OBJECT_ATTRIBUTES attrs;

        InitializeObjectAttributes(&attrs,
                                   &g_MyArkHwidGpuKeyName,
                                   OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                                   NULL,
                                   NULL);
        status = ZwOpenKey(&key, KEY_READ, &attrs);
    }
    if (NT_SUCCESS(status)) {
        ULONG len = *RealLen;
        status = MyArkHwidGpuReadValue(
            key,
            (PUNICODE_STRING)&MyArkHwidGpuValueNames[g_MyArkHwidGpuValueIndex],
            Real,
            &len);
        *RealLen = len;
        ZwClose(key);
    }

    match = NT_SUCCESS(status)
            && (*RealLen == cacheLen)
            && (cacheLen != 0)
            && (RtlCompareMemory(Real, cache, cacheLen) == cacheLen);

    oldIrql = MyArkHwidSpoofLockExclusive();
    State->LastStatus = match ? STATUS_SUCCESS : STATUS_VERIFY_REQUIRED;
    MyArkHwidSpoofUnlockExclusive(oldIrql);

    g_MyArkHwidGpuKeyPath[0] = 0;
    g_MyArkHwidGpuKeyName.Length = 0;
    g_MyArkHwidGpuKeyName.MaximumLength = 0;
    g_MyArkHwidGpuValueIndex = 0;

    return match ? STATUS_SUCCESS : (NT_SUCCESS(status) ? STATUS_VERIFY_REQUIRED
                                                        : status);
}

#endif // MYARK_MODULE_HWID
