// MyArk preflight module: descriptor + IOCTL table.
//
// S7.3 -- single-IOCTL environment health snapshot. The driver fills the
// OS build / kernel base fields; the R3 client merges in the bcdedit
// (testsigning) + Secure Boot + Defender checks via its own fallback
// path.

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "myark_config.h"
#include "module_descriptor.h"
#include "ioctl_registry.h"
#include "../../../shared/driver/MyArkPreflightIoctl.h"
#include "preflight_descriptor.h"
#include "preflight_internal.h"

#if MYARK_MODULE_PREFLIGHT

static MYARK_IOCTL_ENTRY g_PreflightIoctls[] = {
    {
        IOCTL_MYARK_PREFLIGHT_HEALTH,
        MyArkPreflightIoctlHealth,
        "IOCTL_MYARK_PREFLIGHT_HEALTH",
        0,
        0
    },
};

MYARK_MODULE_DESCRIPTOR g_MyArkModule_Preflight = {
    "preflight",                                    // ModuleName
    "Preflight - environment health snapshot (1 IOCTL)",
    MYARK_PREFLIGHT_MODULE_ID,                     // ModuleId ('PFLT')
    RTL_NUMBER_OF(g_PreflightIoctls),              // IoctlCount
    g_PreflightIoctls,                             // Ioctls
    MyArkPreflightInit,                            // Init
    MyArkPreflightCleanup,                         // Cleanup
    FALSE                                           // Initialized (set by loader)
};

NTSTATUS
MyArkPreflightInit(
    void)
{
    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_PREFLIGHT,
                "MyArkPreflightInit: preflight module linked (%lu IOCTLs)",
                (unsigned long)g_MyArkModule_Preflight.IoctlCount);
    return STATUS_SUCCESS;
}

VOID
MyArkPreflightCleanup(
    void)
{
    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_PREFLIGHT,
                "MyArkPreflightCleanup: preflight module torn down");
}

#endif // MYARK_MODULE_PREFLIGHT