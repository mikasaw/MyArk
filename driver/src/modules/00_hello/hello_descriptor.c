// MyArk hello module: descriptor + Init / Cleanup entry points.
//
// Every byte in this file is gated on MYARK_MODULE_HELLO so a profile
// that omits the macro links nothing into the .sys. DriverEntry walks
// g_AllModules[] (defined in module_registry.c) which conditionally
// references g_MyArkModule_Hello.

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "myark_config.h"
#include "module_descriptor.h"
#include "ioctl_registry.h"
#include "../../../shared/driver/MyArkHelloIoctl.h"
#include "hello_descriptor.h"

#if MYARK_MODULE_HELLO

//
// The hello IOCTL table. Array lives in this translation unit so the
// address range is contiguous; QueryCapabilities reverse-looks up the
// owning module by walking g_AllModules[].Ioctls (see core_ioctl_handlers.c).
//
static MYARK_IOCTL_ENTRY g_HelloIoctls[] = {
    {
        IOCTL_MYARK_HELLO_PING,
        MyArkHelloIoctlPing,
        "IOCTL_MYARK_HELLO_PING",
        0,
        0
    },
    {
        IOCTL_MYARK_HELLO_GREET,
        MyArkHelloIoctlGreet,
        "IOCTL_MYARK_HELLO_GREET",
        0,
        0
    },
};

//
// The descriptor that g_AllModules[] points at when MYARK_MODULE_HELLO is on.
//
MYARK_MODULE_DESCRIPTOR g_MyArkModule_Hello = {
    "hello",                                         // ModuleName
    "Hello module - mechanism verification probe",   // ModuleDescription
    MYARK_HELLO_MODULE_ID,                           // ModuleId ('HELL')
    RTL_NUMBER_OF(g_HelloIoctls),                    // IoctlCount
    g_HelloIoctls,                                   // Ioctls
    MyArkHelloInit,                                  // Init
    MyArkHelloCleanup,                               // Cleanup
    FALSE                                            // Initialized (set by loader)
};

NTSTATUS
MyArkHelloInit(
    VOID)
{
    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_MODULE,
                "MyArkHelloInit: hello module linked (%lu IOCTL)",
                (unsigned long)g_MyArkModule_Hello.IoctlCount);

    return STATUS_SUCCESS;
}

VOID
MyArkHelloCleanup(
    VOID)
{
    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_MODULE,
                "MyArkHelloCleanup: hello module torn down");
}

#endif // MYARK_MODULE_HELLO