// MyArk capability module: descriptor + IOCTL table.
//
// S7.3 -- single-IOCTL read-only surface that walks g_AllModules[] and
// emits the capability table to the caller. The driver self-reports its
// own feature set so the R3 client can render a "what does this build
// support" view without probing each IOCTL code one at a time.
//
// All entries use the MyArk METHOD_BUFFERED convention.

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "myark_config.h"
#include "module_descriptor.h"
#include "ioctl_registry.h"
#include "../../../shared/driver/MyArkCapabilityIoctl.h"
#include "capability_descriptor.h"
#include "capability_internal.h"

#if MYARK_MODULE_CAPABILITY

static MYARK_IOCTL_ENTRY g_CapabilityIoctls[] = {
    {
        IOCTL_MYARK_CAPABILITY_REPORT,
        MyArkCapabilityIoctlReport,
        "IOCTL_MYARK_CAPABILITY_REPORT",
        0,
        0
    },
};

MYARK_MODULE_DESCRIPTOR g_MyArkModule_Capability = {
    "capability",                                   // ModuleName
    "Capability - driver self-reported capability table (1 IOCTL)",
    MYARK_CAPABILITY_MODULE_ID,                     // ModuleId ('CAP\0')
    RTL_NUMBER_OF(g_CapabilityIoctls),              // IoctlCount
    g_CapabilityIoctls,                             // Ioctls
    MyArkCapabilityInit,                            // Init
    MyArkCapabilityCleanup,                         // Cleanup
    FALSE                                           // Initialized (set by loader)
};

NTSTATUS
MyArkCapabilityInit(
    VOID)
{
    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_CAPABILITY,
                "MyArkCapabilityInit: capability module linked (%lu IOCTLs)",
                (unsigned long)g_MyArkModule_Capability.IoctlCount);
    return STATUS_SUCCESS;
}

VOID
MyArkCapabilityCleanup(
    VOID)
{
    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_CAPABILITY,
                "MyArkCapabilityCleanup: capability module torn down");
}

#endif // MYARK_MODULE_CAPABILITY