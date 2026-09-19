// wsl R0 IOCTL table + descriptor.

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "myark_config.h"
#include "module_descriptor.h"
#include "ioctl_registry.h"
#include "../../dispatch/ioctl_helpers.h"
#include "wsl_descriptor.h"
#include "../../../shared/driver/MyArkWslIoctl.h"

#if MYARK_MODULE_WSL

#define MYARK_TRACE_WSL "[wsl] "

static NTSTATUS MyArkWslOnInit(VOID)
{
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
               MYARK_TRACE_WSL "init ok\n");
    return STATUS_SUCCESS;
}

static VOID MyArkWslOnCleanup(VOID)
{
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
               MYARK_TRACE_WSL "cleanup ok\n");
}

MYARK_IOCTL_ENTRY g_MyArkWslIoctlTable[] = {
    {
        IOCTL_MYARK_WSL_ENUMERATE_SILOS,
        MyArkWslIoctlEnumerateSilos,
    },
};

MYARK_MODULE_DESCRIPTOR g_MyArkModule_Wsl = {
    .ModuleName      = "wsl",
    .ModuleId        = MYARK_WSL_MODULE_ID,
    .Ioctls          = g_MyArkWslIoctlTable,
    .IoctlCount      = ARRAYSIZE(g_MyArkWslIoctlTable),
    .Init            = MyArkWslOnInit,
    .Cleanup         = MyArkWslOnCleanup,
};

NTSTATUS MyArkWslInit(VOID)   { return MyArkWslOnInit(); }
VOID     MyArkWslCleanup(VOID) { MyArkWslOnCleanup(); }

#endif // MYARK_MODULE_WSL
