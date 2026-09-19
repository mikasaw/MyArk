// MyArk Core Driver: DriverEntry + WDF driver object lifecycle.

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "myark_config.h"
#include "core_globals.h"
#include "module_registry.h"
#include "module_mask.h"
#include "ioctl_registry.h"
#include "core_ioctl_handlers.h"
#include "safety_token.h"

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD MyArkCoreDriverUnload;

// Captured for module Init() functions (see core_globals.h). Must be set
// before MyArkModuleLoaderLoadAll().
PDRIVER_OBJECT g_MyArkCoreDriverObject = NULL;
WCHAR g_MyArkCoreServiceKeyBuffer[MYARK_CORE_SERVICE_KEY_CHARS] = { 0 };
UNICODE_STRING g_MyArkCoreServiceKey = { 0, 0, NULL };

NTSTATUS
MyArkCoreCreateControlDevice(
    _In_ WDFDRIVER Driver);

//
// Walk every registered module descriptor, init the enabled ones, and push
// their IOCTL entries into the global dispatch table. Mirrors the v3 plan's
// ModuleLoaderLoadAll step. Failures are surfaced via tracing and isolated
// so that one bad module cannot stop the core from coming up.
//
static
NTSTATUS
MyArkModuleLoaderLoadAll(
    VOID)
{
    NTSTATUS status;

    status = MyArkIoctlRegistryInit();
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR,
                    MYARK_TRACE_DRIVER,
                    "MyArkIoctlRegistryInit failed: 0x%08X",
                    status);
        return status;
    }

    //
    // Core IOCTLs must come up before any module IOCTLs so the user-mode
    // client can query version / capability as soon as the device appears.
    //
    status = MyArkIoctlRegistryInitCore();
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR,
                    MYARK_TRACE_DRIVER,
                    "MyArkIoctlRegistryInitCore failed: 0x%08X",
                    status);
        return status;
    }

    status = MyArkModuleMaskLoadFromRegistry();
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_WARNING,
                    MYARK_TRACE_DRIVER,
                    "MyArkModuleMaskLoadFromRegistry: 0x%08X (using defaults)",
                    status);
    }

    status = MyArkModuleRegistryInit();
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR,
                    MYARK_TRACE_DRIVER,
                    "MyArkModuleRegistryInit failed: 0x%08X",
                    status);
        return status;
    }

    for (UINT32 i = 0; i < g_ModuleCount; i++) {
        PMYARK_MODULE_DESCRIPTOR module = g_AllModules[i];

        if (module == NULL) {
            continue;
        }

        if (!MyArkModuleIsEnabled(module)) {
            TraceEvents(TRACE_LEVEL_INFORMATION,
                        MYARK_TRACE_DRIVER,
                        "Module %s disabled by registry mask",
                        module->ModuleName ? module->ModuleName : "?");
            continue;
        }

        if (module->Init == NULL) {
            TraceEvents(TRACE_LEVEL_WARNING,
                        MYARK_TRACE_DRIVER,
                        "Module %s has NULL Init; skipping",
                        module->ModuleName ? module->ModuleName : "?");
            continue;
        }

        status = module->Init();
        if (!NT_SUCCESS(status)) {
            TraceEvents(TRACE_LEVEL_ERROR,
                        MYARK_TRACE_DRIVER,
                        "Module %s Init failed: 0x%08X (skipping)",
                        module->ModuleName ? module->ModuleName : "?",
                        status);
            continue;
        }
        module->Initialized = TRUE;

        if (module->Ioctls != NULL && module->IoctlCount > 0) {
            status = MyArkIoctlRegistryAdd(module->Ioctls, module->IoctlCount);
            if (!NT_SUCCESS(status)) {
                TraceEvents(TRACE_LEVEL_ERROR,
                            MYARK_TRACE_DRIVER,
                            "Module %s IOCTL registration failed: 0x%08X",
                            module->ModuleName ? module->ModuleName : "?",
                            status);
            }
        }

        TraceEvents(TRACE_LEVEL_INFORMATION,
                    MYARK_TRACE_DRIVER,
                    "Module %s initialised, ioctls=%lu",
                    module->ModuleName ? module->ModuleName : "?",
                    (unsigned long)module->IoctlCount);
    }

    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_DRIVER,
                "MyArkModuleLoaderLoadAll: total ioctls=%lu",
                (unsigned long)g_IoctlCount);

    return STATUS_SUCCESS;
}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT     DriverObject,
    _In_ PUNICODE_STRING    RegistryPath)
{
    NTSTATUS            status;
    WDF_DRIVER_CONFIG   config;
    WDFDRIVER           driver;

    WPP_INIT_TRACING(DriverObject, RegistryPath);

    g_MyArkCoreDriverObject = DriverObject;
    if (RegistryPath != NULL && RegistryPath->Buffer != NULL &&
        (SIZE_T)RegistryPath->Length < sizeof(g_MyArkCoreServiceKeyBuffer) - sizeof(WCHAR)) {
        RtlCopyMemory(g_MyArkCoreServiceKeyBuffer,
                      RegistryPath->Buffer,
                      RegistryPath->Length);
        g_MyArkCoreServiceKeyBuffer[RegistryPath->Length / sizeof(WCHAR)] = L'\0';
        RtlInitUnicodeString(&g_MyArkCoreServiceKey, g_MyArkCoreServiceKeyBuffer);
    }

    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_DRIVER,
                "MyArkCore DriverEntry: profile=%s",
                MYARK_HEADER_STR(MYARK_CONFIG_HEADER));

    //
    // Non-PnP control-only driver: no per-PDO EvtDeviceAdd. The single
    // control device is created explicitly below once WDF is up.
    //
    WDF_DRIVER_CONFIG_INIT(&config, NULL);
    config.DriverInitFlags |= WdfDriverInitNonPnpDriver;
    config.EvtDriverUnload  = MyArkCoreDriverUnload;

    status = WdfDriverCreate(DriverObject,
                             RegistryPath,
                             WDF_NO_OBJECT_ATTRIBUTES,
                             &config,
                             &driver);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR,
                    MYARK_TRACE_DRIVER,
                    "WdfDriverCreate failed: 0x%08X",
                    status);
        return status;
    }

    //
    // Provision the safety-token session key before any module comes up:
    // mutating IOCTLs fail closed while the key is absent, so a CNG
    // failure here must fail the load rather than boot with a dead
    // validator.
    //
    status = MyArkSafetyTokenInit();
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR,
                    MYARK_TRACE_DRIVER,
                    "MyArkSafetyTokenInit failed: 0x%08X",
                    status);
        return status;
    }

    //
    // Module loader runs after WdfDriverCreate so WDF is ready, but before
    // any device / queue is created -- that way the IOCTL table is populated
    // by the time the first request lands.
    //
    status = MyArkModuleLoaderLoadAll();
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR,
                    MYARK_TRACE_DRIVER,
                    "MyArkModuleLoaderLoadAll failed: 0x%08X",
                    status);
        return status;
    }

    status = MyArkCoreCreateControlDevice(driver);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR,
                    MYARK_TRACE_DRIVER,
                    "MyArkCoreCreateControlDevice failed: 0x%08X",
                    status);
        return status;
    }

    return STATUS_SUCCESS;
}

VOID
MyArkCoreDriverUnload(
    _In_ WDFDRIVER Driver)
{
    UNREFERENCED_PARAMETER(Driver);
    MyArkCoreRunModuleTeardown();
    WPP_CLEANUP_TRACING(NULL);
}

//
// Module/IOCTL/token teardown, shared by the WDF unload path and the
// filemon FilterUnloadCallback. Once FltRegisterFilter runs, FLTMGR owns
// DriverObject->DriverUnload and the WDF EvtDriverUnload above is never
// invoked -- the filter's unload callback becomes the real driver unload
// and must call this (see 90_filemon/filemon_monitor.c). Not re-entrant:
// every teardown step tolerates a second call.
//
VOID
MyArkCoreRunModuleTeardown(
    VOID)
{
    MyArkModuleRegistryCleanup();
    MyArkIoctlRegistryReset();
    MyArkSafetyTokenUnload();
}