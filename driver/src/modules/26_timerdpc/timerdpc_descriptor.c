// timerdpc R0 IOCTL table + descriptor.

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "myark_config.h"
#include "module_descriptor.h"
#include "ioctl_registry.h"
#include "timerdpc_descriptor.h"
#include "../../../shared/driver/MyArkTimerIoctl.h"

#if MYARK_MODULE_TIMERDPC

#define MYARK_TRACE_TIMERDPC "[timerdpc] "

static NTSTATUS MyArkTimerDpcOnInit(VOID)
{
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
               MYARK_TRACE_TIMERDPC "init ok\n");
    return STATUS_SUCCESS;
}

static VOID MyArkTimerDpcOnCleanup(VOID)
{
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
               MYARK_TRACE_TIMERDPC "cleanup ok\n");
}

MYARK_IOCTL_ENTRY g_MyArkTimerDpcIoctlTable[] = {
    {
        IOCTL_MYARK_TIMER_QUERY,
        MyArkTimerDpcIoctlQueryTimer,
    },
    {
        IOCTL_MYARK_DPC_QUERY,
        MyArkTimerDpcIoctlQueryDpc,
    },
};

MYARK_MODULE_DESCRIPTOR g_MyArkModule_TimerDpc = {
    .ModuleName      = "timerdpc",
    .ModuleId        = MYARK_TIMERDPC_MODULE_ID,
    .Ioctls          = g_MyArkTimerDpcIoctlTable,
    .IoctlCount      = ARRAYSIZE(g_MyArkTimerDpcIoctlTable),
    .Init            = MyArkTimerDpcOnInit,
    .Cleanup         = MyArkTimerDpcOnCleanup,
};

NTSTATUS MyArkTimerDpcInit(VOID)   { return MyArkTimerDpcOnInit(); }
VOID     MyArkTimerDpcCleanup(VOID) { MyArkTimerDpcOnCleanup(); }

#endif // MYARK_MODULE_TIMERDPC