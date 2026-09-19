// MyArk Core Driver: registry-driven module enable mask.
//
// The mask is a 64-bit bitmap indexed by the module's position in
// g_AllModules[] (defined in module_registry.c). Bit i set = module i is
// enabled; otherwise it is disabled. Storage layout under the driver service
// key:
//
//     HKLM\SYSTEM\CurrentControlSet\Services\MyArkCore\Modules\<Name>
//         REG_DWORD = 0  (disabled) | non-zero (enabled)
//
// Modules that the registry does not mention default to enabled so a fresh
// `sc start MyArkCore` is useful without admin curation. DriverEntry calls
// MyArkModuleMaskLoadFromRegistry() before walking g_AllModules[] (S2.3).

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "module_registry.h"
#include "module_mask.h"

#define MYARK_REG_MODULES_PATH \
    L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\MyArkCore\\Modules"

#define MYARK_REG_VALUE_ENUM_BUFFER_SIZE  256

UINT64 g_ModuleEnableMask = 0;

//
// Walk g_AllModules[] (statically populated at link time) and set the bit
// for every module that the registry did not explicitly disable. Modules
// not represented in the registry therefore come up enabled.
//
static
VOID
MyArkModuleMaskEnableUnmentioned(
    VOID)
{
    for (UINT32 i = 0; i < MYARK_MAX_MODULES && g_AllModules[i] != NULL; i++) {
        g_ModuleEnableMask |= (1ULL << i);
    }
}

//
// Find the position of a module descriptor inside g_AllModules[]. Used both
// by the registry walker (to set the bit at the matching slot) and by
// MyArkModuleIsEnabled (to look up the bit for a given descriptor).
//
static
UINT32
MyArkModuleIndexInRegistry(
    _In_ PMYARK_MODULE_DESCRIPTOR Module)
{
    for (UINT32 i = 0; i < MYARK_MAX_MODULES && g_AllModules[i] != NULL; i++) {
        if (g_AllModules[i] == Module) {
            return i;
        }
    }
    return MYARK_MAX_MODULES;
}

//
// Convert a descriptor's ANSI ModuleName into Unicode and compare against a
// Unicode registry value name. Comparison is case-insensitive to match the
// registry's default behaviour for value names.
//
static
BOOLEAN
MyArkModuleNameMatchesValue(
    _In_ PCSTR ModuleName,
    _In_ PUNICODE_STRING ValueName)
{
    NTSTATUS        status;
    ANSI_STRING     ansi;
    UNICODE_STRING  unicode;
    BOOLEAN         match = FALSE;

    if (ModuleName == NULL || ValueName == NULL) {
        return FALSE;
    }

    RtlInitAnsiString(&ansi, ModuleName);
    status = RtlAnsiStringToUnicodeString(&unicode, &ansi, TRUE);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_WARNING,
                    MYARK_TRACE_MODULE,
                    "RtlAnsiStringToUnicodeString failed for %s: 0x%08X",
                    ModuleName,
                    status);
        return FALSE;
    }

    match = RtlCompareUnicodeString(ValueName, &unicode, TRUE) == 0;

    RtlFreeUnicodeString(&unicode);
    return match;
}

NTSTATUS
MyArkModuleMaskLoadFromRegistry(
    VOID)
{
    UNICODE_STRING      modulesPath;
    OBJECT_ATTRIBUTES   oa;
    HANDLE              keyHandle = NULL;
    NTSTATUS            status;
    ULONG               index = 0;

    g_ModuleEnableMask = 0;

    RtlInitUnicodeString(&modulesPath, MYARK_REG_MODULES_PATH);
    InitializeObjectAttributes(&oa,
                               &modulesPath,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);

    status = ZwOpenKey(&keyHandle, KEY_READ, &oa);
    if (!NT_SUCCESS(status)) {
        //
        // Missing Modules subkey is the common first-install case: leave the
        // mask empty and let MyArkModuleMaskEnableUnmentioned() default
        // every linked module to enabled.
        //
        TraceEvents(TRACE_LEVEL_INFORMATION,
                    MYARK_TRACE_MODULE,
                    "Modules subkey unavailable (0x%08X); defaulting all to enabled",
                    status);
        MyArkModuleMaskEnableUnmentioned();
        return status;
    }

    for (;;) {
        BYTE                        buffer[MYARK_REG_VALUE_ENUM_BUFFER_SIZE];
        PKEY_VALUE_FULL_INFORMATION info;
        UNICODE_STRING              valueName;
        ULONG                       resultLength = 0;
        BOOLEAN                     valueEnabled;
        ULONG                       dataOffset;

        status = ZwEnumerateValueKey(keyHandle,
                                     index,
                                     KeyValueFullInformation,
                                     buffer,
                                     sizeof(buffer),
                                     &resultLength);
        if (status == STATUS_NO_MORE_ENTRIES) {
            status = STATUS_SUCCESS;
            break;
        }
        if (status == STATUS_BUFFER_OVERFLOW || status == STATUS_BUFFER_TOO_SMALL) {
            //
            // Our fixed buffer covers any reasonable module-name length; if a
            // value exceeds it we surface the error rather than silently
            // dropping the entry.
            //
            TraceEvents(TRACE_LEVEL_ERROR,
                        MYARK_TRACE_MODULE,
                        "Modules value too large for %u-byte buffer (need %lu)",
                        MYARK_REG_VALUE_ENUM_BUFFER_SIZE,
                        resultLength);
            break;
        }
        if (!NT_SUCCESS(status)) {
            TraceEvents(TRACE_LEVEL_ERROR,
                        MYARK_TRACE_MODULE,
                        "ZwEnumerateValueKey[%u] failed: 0x%08X",
                        index,
                        status);
            break;
        }

        info = (PKEY_VALUE_FULL_INFORMATION)buffer;

        valueName.Buffer = info->Name;
        valueName.Length = (USHORT)info->NameLength;
        valueName.MaximumLength = (USHORT)info->NameLength;

        if (info->Type != REG_DWORD || info->DataLength < sizeof(ULONG)) {
            TraceEvents(TRACE_LEVEL_WARNING,
                        MYARK_TRACE_MODULE,
                        "Skipping Modules value %wZ (type=%lu, len=%lu)",
                        &valueName,
                        (ULONG)info->Type,
                        (ULONG)info->DataLength);
            index++;
            continue;
        }

        dataOffset = info->DataOffset;
        valueEnabled = (*(PULONG)((PUCHAR)info + dataOffset)) != 0;

        for (UINT32 i = 0; i < MYARK_MAX_MODULES && g_AllModules[i] != NULL; i++) {
            PMYARK_MODULE_DESCRIPTOR module = g_AllModules[i];
            if (module == NULL || module->ModuleName == NULL) {
                continue;
            }
            if (MyArkModuleNameMatchesValue(module->ModuleName, &valueName)) {
                if (valueEnabled) {
                    g_ModuleEnableMask |= (1ULL << i);
                } else {
                    g_ModuleEnableMask &= ~(1ULL << i);
                }
                TraceEvents(TRACE_LEVEL_INFORMATION,
                            MYARK_TRACE_MODULE,
                            "Modules\\%wZ = %u (slot %u)",
                            &valueName,
                            valueEnabled ? 1U : 0U,
                            i);
                break;
            }
        }

        index++;
    }

    ZwClose(keyHandle);

    //
    // Anything not mentioned in the registry defaults to enabled.
    //
    MyArkModuleMaskEnableUnmentioned();

    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_MODULE,
                "MyArkModuleMaskLoadFromRegistry: mask=0x%016llx",
                (unsigned long long)g_ModuleEnableMask);

    return status;
}

BOOLEAN
MyArkModuleIsEnabled(
    _In_ PMYARK_MODULE_DESCRIPTOR Module)
{
    UINT32 index;

    if (Module == NULL) {
        return FALSE;
    }

    index = MyArkModuleIndexInRegistry(Module);
    if (index >= MYARK_MAX_MODULES) {
        return FALSE;
    }

    return (g_ModuleEnableMask & (1ULL << index)) != 0;
}