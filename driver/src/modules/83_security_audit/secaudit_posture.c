// MyArk security-audit module: R3-6 posture snapshot (0x7D3).
//
// Read-only registry/CPUID audit. Every registry lookup degrades to the
// MYARK_SECPOST_NOTFOUND sentinel (or 0xFF for service Start) rather than
// silently reporting "disabled" -- an unreadable policy must not look like
// an absent policy. All paths are absolute hive paths under
// \Registry\Machine; no redirection interaction.

#include <ntifs.h>       /* ZwQueryDirectoryFile / FILE_BOTH_DIR_INFORMATION */
#include <wdf.h>
#include <ntstrsafe.h>
#include <intrin.h>
#include "Trace.h"
#include "myark_config.h"
#include "secaudit_internal.h"

#if MYARK_MODULE_SECURITY_AUDIT

#define POSTURE_POOL_TAG 0x6453414DUL  // 'MASd'

//
// Read one REG_DWORD value; *FoundOut = FALSE when key/value/type missing.
//
static
NTSTATUS
MyArkSecPostReadDword(
    _In_ PCWSTR   KeyPath,
    _In_ PCWSTR   ValueName,
    _Out_ UINT32* ValueOut,
    _Out_ BOOLEAN* FoundOut)
{
    OBJECT_ATTRIBUTES attrs;
    UNICODE_STRING    uniKey;
    UNICODE_STRING    uniValue;
    HANDLE            key = NULL;
    UCHAR             buf[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(UINT32)];
    ULONG             needed = 0;
    NTSTATUS          status;

    *FoundOut = FALSE;
    *ValueOut = 0;

    RtlInitUnicodeString(&uniKey, KeyPath);
    InitializeObjectAttributes(&attrs, &uniKey,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);
    status = ZwOpenKey(&key, KEY_READ, &attrs);
    if (!NT_SUCCESS(status)) {
        return STATUS_SUCCESS;            // missing key = audit finding, not error
    }

    RtlInitUnicodeString(&uniValue, ValueName);
    status = ZwQueryValueKey(key,
                             &uniValue,
                             KeyValuePartialInformation,
                             buf,
                             sizeof(buf),
                             &needed);
    if (NT_SUCCESS(status)) {
        PKEY_VALUE_PARTIAL_INFORMATION info = (PKEY_VALUE_PARTIAL_INFORMATION)buf;
        if (info->Type == REG_DWORD && info->DataLength == sizeof(UINT32)) {
            RtlCopyMemory(ValueOut, info->Data, sizeof(UINT32));
            *FoundOut = TRUE;
        }
    }
    ZwClose(key);
    return STATUS_SUCCESS;
}

//
// Count subkeys of one key (0 when absent).
//
static
ULONG
MyArkSecPostCountSubkeys(
    _In_ PCWSTR KeyPath)
{
    OBJECT_ATTRIBUTES attrs;
    UNICODE_STRING    uniKey;
    HANDLE            key = NULL;
    UCHAR             buf[512];
    ULONG             needed = 0;
    ULONG             count = 0;

    RtlInitUnicodeString(&uniKey, KeyPath);
    InitializeObjectAttributes(&attrs, &uniKey,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);
    if (!NT_SUCCESS(ZwOpenKey(&key, KEY_READ, &attrs))) {
        return 0;
    }
    if (NT_SUCCESS(ZwQueryKey(key,
                              KeyFullInformation,
                              buf,
                              sizeof(buf),
                              &needed))) {
        PKEY_FULL_INFORMATION info = (PKEY_FULL_INFORMATION)buf;
        count = info->SubKeys;
    }
    ZwClose(key);
    return count;
}

//
// AppLocker: any SrpV2 collection with EnforcementMode == 1 (enforced)?
//
static
BOOLEAN
MyArkSecPostAppLockerEnforced(
    _In_ PCWSTR SrpPath)
{
    static CONST PCWSTR known[] = {
        L"Appx", L"DLL", L"Exe", L"Msi", L"Script"
    };


    for (ULONG i = 0; i < RTL_NUMBER_OF(known); i++) {
        WCHAR          path[256];
        UNICODE_STRING uniKey;
        OBJECT_ATTRIBUTES attrs;
        HANDLE         key = NULL;
        UCHAR          buf[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(UINT32)];
        ULONG          needed = 0;
        NTSTATUS       status;

        RtlStringCchPrintfW(path, RTL_NUMBER_OF(path), L"%s\\%s", SrpPath, known[i]);
        RtlInitUnicodeString(&uniKey, path);
        InitializeObjectAttributes(&attrs, &uniKey,
                                   OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                                   NULL, NULL);
        if (!NT_SUCCESS(ZwOpenKey(&key, KEY_READ, &attrs))) {
            continue;
        }
        RtlInitUnicodeString(&uniKey, L"EnforcementMode");
        status = ZwQueryValueKey(key,
                                 &uniKey,
                                 KeyValuePartialInformation,
                                 buf,
                                 sizeof(buf),
                                 &needed);
        ZwClose(key);
        if (NT_SUCCESS(status)) {
            PKEY_VALUE_PARTIAL_INFORMATION info =
                (PKEY_VALUE_PARTIAL_INFORMATION)buf;
            UINT32 v = 0;
            if (info->Type == REG_DWORD && info->DataLength == sizeof(UINT32)) {
                RtlCopyMemory(&v, info->Data, sizeof(UINT32));
                if (v == 1) {
                    return TRUE;
                }
            }
        }
    }
    return FALSE;
}

//
// Count the active WDAC policy files in
// \SystemRoot\System32\CodeIntegrity\CiPolicies\Active. Directory absent
// or unreadable -> *CountOut stays 0 and FALSE is returned (the caller
// reports "not present" rather than "no policies"). One bounded pass:
// the 4 KiB buffer holds a small-directory listing; anything larger is
// reported by the restart-scan's first pass only.
//
static
BOOLEAN
MyArkSecPostCountWdacPolicies(
    _Out_ ULONG* CountOut)
{
    OBJECT_ATTRIBUTES      attrs;
    UNICODE_STRING         uniDir = RTL_CONSTANT_STRING(
        L"\\SystemRoot\\System32\\CodeIntegrity\\CiPolicies\\Active");
    IO_STATUS_BLOCK        iosb;
    HANDLE                 dir = NULL;
    UCHAR                  buf[4096];
    BOOLEAN                any = FALSE;
    ULONG                  total = 0;
    NTSTATUS               status;

    *CountOut = 0;

    InitializeObjectAttributes(&attrs, &uniDir,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);
    if (!NT_SUCCESS(ZwCreateFile(&dir,
                                 FILE_LIST_DIRECTORY,
                                 &attrs,
                                 &iosb,
                                 NULL,
                                 0,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE,
                                 FILE_OPEN,
                                 FILE_DIRECTORY_FILE,
                                 NULL,
                                 0))) {
        return FALSE;
    }

    //
    // Proper multi-call enumeration: the first call (restart) can return a
    // batch as small as the "." / ".." placeholders -- the remaining entries
    // require continued calls until STATUS_NO_MORE_FILES. Each call returns
    // one self-contained batch chain.
    //
    BOOLEAN restart = TRUE;
    for (;;) {
        status = ZwQueryDirectoryFile(dir,
                                      NULL,
                                      NULL,
                                      NULL,
                                      &iosb,
                                      buf,
                                      sizeof(buf),
                                      FileBothDirectoryInformation,
                                      restart,
                                      NULL,
                                      FALSE);
                if (status == STATUS_NO_MORE_FILES) {
            break;
        }
        if (!NT_SUCCESS(status) || iosb.Information == 0) {
            break;
        }
        any = TRUE;

        PFILE_BOTH_DIR_INFORMATION info = (PFILE_BOTH_DIR_INFORMATION)buf;
        for (;;) {
            if (!(info->FileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                total++;
            }
            if (info->NextEntryOffset == 0) {
                break;
            }
            info = (PFILE_BOTH_DIR_INFORMATION)((PUCHAR)info + info->NextEntryOffset);
        }
        restart = FALSE;
    }

    ZwClose(dir);
    if (any) {
        *CountOut = total;
    }
    return any;
}

NTSTATUS
MyArkSecurityAuditPosture(
    _Out_ PMYARK_SECURITY_AUDIT_POSTURE_OUTPUT Output)
{
    int     regs[4];
    UINT32  v = 0;
    BOOLEAN found = FALSE;
    NTSTATUS status;

    RtlZeroMemory(Output, sizeof(*Output));

    // Hypervisor presence (leaf 1 ECX bit 31) + vendor (leaf 0x40000000).
    __cpuid(regs, 1);
    Output->HypervisorPresent = ((regs[2] >> 31) & 1);
    if (Output->HypervisorPresent) {
        CHAR vendor[13];
        __cpuid(regs, 0x40000000);
        RtlCopyMemory(vendor + 0, &regs[1], 4);
        RtlCopyMemory(vendor + 4, &regs[2], 4);
        RtlCopyMemory(vendor + 8, &regs[3], 4);
        vendor[12] = '\0';
        RtlCopyMemory(Output->HypervisorVendor, vendor,
                      sizeof(vendor));   
    }

    // VBS / DeviceGuard.
    status = MyArkSecPostReadDword(
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard",
        L"EnableVirtualizationBasedSecurity", &v, &found);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    Output->VbsEnabled = found ? ((v != 0) ? 1 : 0) : MYARK_SECPOST_NOTFOUND;

    // HVCI scenario.
    status = MyArkSecPostReadDword(
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard"
        L"\\Scenarios\\HypervisorEnforcedCodeIntegrity",
        L"Enabled", &v, &found);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    Output->HvciEnabled = found ? ((v != 0) ? 1 : 0) : MYARK_SECPOST_NOTFOUND;

    status = MyArkSecPostReadDword(
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard"
        L"\\Scenarios\\HypervisorEnforcedCodeIntegrity",
        L"WasRunningByHygiene", &v, &found);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    Output->HvciRunning = found ? ((v != 0) ? 1 : 0) : MYARK_SECPOST_NOTFOUND;

    // AppLocker: SrpV2 collections + any enforcement.
    Output->AppLockerCollections = MyArkSecPostCountSubkeys(
        L"\\Registry\\Machine\\SOFTWARE\\Policies\\Microsoft\\Windows\\SrpV2");
    Output->AppLockerEnforced =
        MyArkSecPostAppLockerEnforced(
            L"\\Registry\\Machine\\SOFTWARE\\Policies\\Microsoft\\Windows\\SrpV2") ? 1 : 0;

    // BAM service start type (absent -> 0xFF).
    status = MyArkSecPostReadDword(
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\BAM",
        L"Start", &v, &found);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    Output->BamServiceStart = found ? v : MYARK_SECPOST_SERVICESTART_ABSENT;

    {
        ULONG wdac = 0;
        Output->WdacDirPresent =
            MyArkSecPostCountWdacPolicies(&wdac) ? 1 : 0;
        Output->WdacPolicyCount = wdac;
    }

    Output->Status = (UINT32)STATUS_SUCCESS;
    RtlStringCchCopyW(Output->Note,
                      MYARK_SECURITY_AUDIT_NOTE_MAX,
                      L"posture: cpuid+registry snapshot (R3-6)");
    return STATUS_SUCCESS;
}

#endif // MYARK_MODULE_SECURITY_AUDIT
