// alpc R0 IOCTL table + descriptor.

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "myark_config.h"
#include "module_descriptor.h"
#include "ioctl_registry.h"
#include "../../dispatch/ioctl_helpers.h"
#include "alpc_descriptor.h"
#include "../../../shared/driver/MyArkAlpcIoctl.h"

#if MYARK_MODULE_ALPC

#define MYARK_TRACE_ALPC "[alpc] "

static NTSTATUS MyArkAlpcOnInit(VOID)
{
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
               MYARK_TRACE_ALPC "init ok\n");
    return STATUS_SUCCESS;
}

static VOID MyArkAlpcOnCleanup(VOID)
{
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
               MYARK_TRACE_ALPC "cleanup ok\n");
}

MYARK_IOCTL_ENTRY g_MyArkAlpcIoctlTable[] = {
    {
        IOCTL_MYARK_ALPC_ENUMERATE_PORTS,
        MyArkAlpcIoctlEnumeratePorts,
    },
    {
        IOCTL_MYARK_ALPC_CLOSE_PORT,
        MyArkAlpcIoctlClosePort,
    },
};

MYARK_MODULE_DESCRIPTOR g_MyArkModule_Alpc = {
    .ModuleName      = "alpc",
    .ModuleId        = MYARK_ALPC_MODULE_ID,
    .Ioctls          = g_MyArkAlpcIoctlTable,
    .IoctlCount      = ARRAYSIZE(g_MyArkAlpcIoctlTable),
    .Init            = MyArkAlpcOnInit,
    .Cleanup         = MyArkAlpcOnCleanup,
};

NTSTATUS MyArkAlpcInit(VOID)   { return MyArkAlpcOnInit(); }
VOID     MyArkAlpcCleanup(VOID) { MyArkAlpcOnCleanup(); }

#endif // MYARK_MODULE_ALPC
