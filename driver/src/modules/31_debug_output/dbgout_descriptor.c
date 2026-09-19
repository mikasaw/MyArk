// MyArk debug-output module: descriptor + IOCTL table.

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "myark_config.h"
#include "module_descriptor.h"
#include "ioctl_registry.h"
#include "../../../shared/driver/MyArkDebugOutputIoctl.h"
#include "dbgout_descriptor.h"
#include "dbgout_internal.h"

#if MYARK_MODULE_DEBUG_OUTPUT

static MYARK_IOCTL_ENTRY g_DebugOutputIoctls[] = {
    {
        IOCTL_MYARK_DEBUG_OUTPUT_CONTROL,
        MyArkDebugOutputIoctlControl,
        "IOCTL_MYARK_DEBUG_OUTPUT_CONTROL",
        0,
        0
    },
    {
        IOCTL_MYARK_DEBUG_OUTPUT_DRAIN,
        MyArkDebugOutputIoctlDrain,
        "IOCTL_MYARK_DEBUG_OUTPUT_DRAIN",
        0,
        0
    },
};

MYARK_MODULE_DESCRIPTOR g_MyArkModule_DebugOutput = {
    "debug-output",                                  // ModuleName
    "Debug output module - DbgPrint ring buffer (2 IOCTL)",
    MYARK_DBG_OUTPUT_MODULE_ID,                      // ModuleId ('DBGO')
    RTL_NUMBER_OF(g_DebugOutputIoctls),               // IoctlCount
    g_DebugOutputIoctls,                             // Ioctls
    MyArkDebugOutputInit,                            // Init
    MyArkDebugOutputCleanup,                         // Cleanup
    FALSE                                            // Initialized (set by loader)
};

NTSTATUS
MyArkDebugOutputInit(
    VOID)
{
    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_DBGOUT,
                "MyArkDebugOutputInit: debug-output module linked (%lu IOCTL)",
                (unsigned long)g_MyArkModule_DebugOutput.IoctlCount);

    return STATUS_SUCCESS;
}

VOID
MyArkDebugOutputCleanup(
    VOID)
{
    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_DBGOUT,
                "MyArkDebugOutputCleanup: debug-output module torn down");
}

#endif // MYARK_MODULE_DEBUG_OUTPUT
