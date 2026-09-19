// MyArk registry module: descriptor + IOCTL table.

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "myark_config.h"
#include "module_descriptor.h"
#include "ioctl_registry.h"
#include "../../../shared/driver/MyArkRegistryIoctl.h"
#include "registry_descriptor.h"
#include "registry_internal.h"

#if MYARK_MODULE_REGISTRY

static MYARK_IOCTL_ENTRY g_RegistryIoctls[] = {
    {
        IOCTL_MYARK_REGISTRY_READ_VALUE,
        MyArkRegistryIoctlReadValue,
        "IOCTL_MYARK_REGISTRY_READ_VALUE",
        0,
        0
    },
    {
        IOCTL_MYARK_REGISTRY_ENUM_KEY,
        MyArkRegistryIoctlEnumKey,
        "IOCTL_MYARK_REGISTRY_ENUM_KEY",
        0,
        0
    },
    {
        IOCTL_MYARK_REGISTRY_SET_VALUE,
        MyArkRegistryIoctlSetValue,
        "IOCTL_MYARK_REGISTRY_SET_VALUE",
        0,
        0
    },
    {
        IOCTL_MYARK_REGISTRY_DELETE_VALUE,
        MyArkRegistryIoctlDeleteValue,
        "IOCTL_MYARK_REGISTRY_DELETE_VALUE",
        0,
        0
    },
    {
        IOCTL_MYARK_REGISTRY_CREATE_KEY,
        MyArkRegistryIoctlCreateKey,
        "IOCTL_MYARK_REGISTRY_CREATE_KEY",
        0,
        0
    },
    {
        IOCTL_MYARK_REGISTRY_DELETE_KEY,
        MyArkRegistryIoctlDeleteKey,
        "IOCTL_MYARK_REGISTRY_DELETE_KEY",
        0,
        0
    },
    {
        IOCTL_MYARK_REGISTRY_RENAME_VALUE,
        MyArkRegistryIoctlRenameValue,
        "IOCTL_MYARK_REGISTRY_RENAME_VALUE",
        0,
        0
    },
    {
        IOCTL_MYARK_REGISTRY_RENAME_KEY,
        MyArkRegistryIoctlRenameKey,
        "IOCTL_MYARK_REGISTRY_RENAME_KEY",
        0,
        0
    },
};

MYARK_MODULE_DESCRIPTOR g_MyArkModule_Registry = {
    "registry",                                     // ModuleName
    "Registry module - R0 read/enum/write/delete/create/rename (8 IOCTL)",
    MYARK_REGISTRY_MODULE_ID,                       // ModuleId ('REGS')
    RTL_NUMBER_OF(g_RegistryIoctls),                // IoctlCount
    g_RegistryIoctls,                               // Ioctls
    MyArkRegistryModuleInit,                        // Init
    MyArkRegistryModuleCleanup,                     // Cleanup
    FALSE                                           // Initialized (set by loader)
};

NTSTATUS
MyArkRegistryModuleInit(
    VOID)
{
    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_REGISTRY,
                "MyArkRegistryModuleInit: registry module linked (%lu IOCTL)",
                (unsigned long)g_MyArkModule_Registry.IoctlCount);

    return STATUS_SUCCESS;
}

VOID
MyArkRegistryModuleCleanup(
    VOID)
{
    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_REGISTRY,
                "MyArkRegistryModuleCleanup: registry module torn down");
}

#endif // MYARK_MODULE_REGISTRY
