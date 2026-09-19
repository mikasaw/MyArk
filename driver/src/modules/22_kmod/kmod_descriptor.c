// MyArk kmod module: descriptor + IOCTL table.

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "myark_config.h"
#include "module_descriptor.h"
#include "ioctl_registry.h"
#include "../../../shared/driver/MyArkKmodIoctl.h"
#include "kmod_descriptor.h"

#if MYARK_MODULE_KMODULE

static MYARK_IOCTL_ENTRY g_KmodIoctls[] = {
    {
        IOCTL_MYARK_MODULE_QUERY_DRIVER_OBJECT,
        MyArkKmodIoctlQueryDriverObject,
        "IOCTL_MYARK_MODULE_QUERY_DRIVER_OBJECT",
        0,
        0
    },
    {
        IOCTL_MYARK_MODULE_QUERY_IOCTL_REGISTRY,
        MyArkKmodIoctlQueryIoctlRegistry,
        "IOCTL_MYARK_MODULE_QUERY_IOCTL_REGISTRY",
        0,
        0
    },
};

MYARK_MODULE_DESCRIPTOR g_MyArkModule_Kmod = {
    "module",                                       // ModuleName (friendly: "module" on the wire)
    "Kernel-driver module - IoDriverListHead walker (2 IOCTL)",
    MYARK_KMODULE_MODULE_ID,                        // ModuleId ('KMOD')
    RTL_NUMBER_OF(g_KmodIoctls),                    // IoctlCount
    g_KmodIoctls,                                   // Ioctls
    MyArkKmodInit,                                  // Init
    MyArkKmodCleanup,                               // Cleanup
    FALSE                                           // Initialized (set by loader)
};

NTSTATUS
MyArkKmodInit(
    VOID)
{
    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_KMOD,
                "MyArkKmodInit: kmod module linked (%lu IOCTL)",
                (unsigned long)g_MyArkModule_Kmod.IoctlCount);

    return STATUS_SUCCESS;
}

VOID
MyArkKmodCleanup(
    VOID)
{
    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_KMOD,
                "MyArkKmodCleanup: kmod module torn down");
}

#endif // MYARK_MODULE_KMODULE
