// MyArk file-monitor module: descriptor + IOCTL table (R2-7).

#include <fltKernel.h>
#include <wdf.h>
#include "Trace.h"
#include "myark_config.h"
#include "module_descriptor.h"
#include "ioctl_registry.h"
#include "../../../shared/driver/MyArkFileMonitorIoctl.h"
#include "filemon_descriptor.h"
#include "filemon_internal.h"

#if MYARK_MODULE_FILE_MONITOR

static MYARK_IOCTL_ENTRY g_FileMonIoctls[] = {
    {
        IOCTL_MYARK_FILEMON_CONTROL,
        MyArkFileMonIoctlControl,
        "IOCTL_MYARK_FILEMON_CONTROL",
        0,
        0
    },
    {
        IOCTL_MYARK_FILEMON_DRAIN,
        MyArkFileMonIoctlDrain,
        "IOCTL_MYARK_FILEMON_DRAIN",
        0,
        0
    },
    {
        IOCTL_MYARK_FILEMON_STATUS,
        MyArkFileMonIoctlStatus,
        "IOCTL_MYARK_FILEMON_STATUS",
        0,
        0
    },
    {
        IOCTL_MYARK_FILEMON_ENUM_FILTERS,
        MyArkFileMonIoctlEnumFilters,
        "IOCTL_MYARK_FILEMON_ENUM_FILTERS",
        0,
        0
    },
    {
        IOCTL_MYARK_FILEMON_BYPASS_PID,
        MyArkFileMonIoctlBypassPid,
        "IOCTL_MYARK_FILEMON_BYPASS_PID",
        0,
        0
    },
};

MYARK_MODULE_DESCRIPTOR g_MyArkModule_FileMonitor = {
    "filemon",                                      // ModuleName
    "File monitor - minifilter CREATE/disposition sampling + inventory + bypass PIDs (5 IOCTL, R2-7/R3-7)",
    MYARK_FILEMON_MODULE_ID,                        // ModuleId ('FMON')
    RTL_NUMBER_OF(g_FileMonIoctls),                 // IoctlCount
    g_FileMonIoctls,                                // Ioctls
    MyArkFileMonModuleInit,                         // Init
    MyArkFileMonModuleCleanup,                      // Cleanup
    FALSE                                           // Initialized (set by loader)
};

NTSTATUS
MyArkFileMonModuleInit(
    VOID)
{
    //
    // Start failures deliberately do not fail the module: the IOCTL surface
    // stays up and STATUS reports StartStage/StartStatus, so a broken
    // minifilter registration is diagnosable from user mode instead of
    // leaving only a registry lasterr.
    //
    MyArkFileMonStart();

    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_FILEMON,
                "MyArkFileMonModuleInit: stage=%lu status=0x%08X registered=%lu (%lu IOCTL)",
                (unsigned long)g_MyArkFileMon.StartStage,
                (unsigned long)g_MyArkFileMon.StartStatus,
                (unsigned long)g_MyArkFileMon.Registered,
                (unsigned long)g_MyArkModule_FileMonitor.IoctlCount);

    return STATUS_SUCCESS;
}

VOID
MyArkFileMonModuleCleanup(
    VOID)
{
    MyArkFileMonStop();

    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_FILEMON,
                "MyArkFileMonModuleCleanup: minifilter torn down");
}

#endif // MYARK_MODULE_FILE_MONITOR
