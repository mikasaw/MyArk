// MyArk safety module: descriptor + IOCTL table.

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "myark_config.h"
#include "module_descriptor.h"
#include "ioctl_registry.h"
#include "../../../shared/driver/MyArkSafetyIoctl.h"
#include "safety_descriptor.h"
#include "safety_internal.h"

#if MYARK_MODULE_SAFETY

static MYARK_IOCTL_ENTRY g_SafetyIoctls[] = {
    {
        IOCTL_MYARK_SAFETY_EVAL_GATE,
        MyArkSafetyIoctlEvalGate,
        "IOCTL_MYARK_SAFETY_EVAL_GATE",
        0,
        0
    },
};

MYARK_MODULE_DESCRIPTOR g_MyArkModule_Safety = {
    "safety",                                       // ModuleName
    "Safety - 6-step gate evaluator (1 IOCTL)",
    MYARK_SAFETY_MODULE_ID,                        // ModuleId ('SAFE')
    RTL_NUMBER_OF(g_SafetyIoctls),                 // IoctlCount
    g_SafetyIoctls,                                // Ioctls
    MyArkSafetyInit,                               // Init
    MyArkSafetyCleanup,                            // Cleanup
    FALSE                                          // Initialized (set by loader)
};

NTSTATUS
MyArkSafetyInit(
    void)
{
    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_SAFETY,
                "MyArkSafetyInit: safety module linked (%lu IOCTLs)",
                (unsigned long)g_MyArkModule_Safety.IoctlCount);
    return STATUS_SUCCESS;
}

VOID
MyArkSafetyCleanup(
    void)
{
    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_SAFETY,
                "MyArkSafetyCleanup: safety module torn down");
}

#endif // MYARK_MODULE_SAFETY