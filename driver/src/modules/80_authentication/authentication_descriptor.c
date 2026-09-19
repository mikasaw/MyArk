// authentication R0 IOCTL table + descriptor.

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "myark_config.h"
#include "module_descriptor.h"
#include "ioctl_registry.h"
#include "../../dispatch/ioctl_helpers.h"
#include "authentication_descriptor.h"
#include "../../../shared/driver/MyArkAuthenticationIoctl.h"

#if MYARK_MODULE_AUTHENTICATION

#define MYARK_TRACE_AUTH "[authentication] "

static NTSTATUS MyArkAuthenticationOnInit(VOID)
{
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
               MYARK_TRACE_AUTH "init ok\n");
    return STATUS_SUCCESS;
}

static VOID MyArkAuthenticationOnCleanup(VOID)
{
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
               MYARK_TRACE_AUTH "cleanup ok\n");
}

MYARK_IOCTL_ENTRY g_MyArkAuthenticationIoctlTable[] = {
    {
        IOCTL_MYARK_AUTHENTICATION_VERIFY_FILE,
        MyArkAuthenticationIoctlVerifyFile,
    },
};

MYARK_MODULE_DESCRIPTOR g_MyArkModule_Authentication = {
    .ModuleName      = "authentication",
    .ModuleId        = MYARK_AUTHENTICATION_MODULE_ID,
    .Ioctls          = g_MyArkAuthenticationIoctlTable,
    .IoctlCount      = ARRAYSIZE(g_MyArkAuthenticationIoctlTable),
    .Init            = MyArkAuthenticationOnInit,
    .Cleanup         = MyArkAuthenticationOnCleanup,
};

NTSTATUS MyArkAuthenticationInit(VOID)     { return MyArkAuthenticationOnInit(); }
VOID     MyArkAuthenticationCleanup(VOID)   { MyArkAuthenticationOnCleanup(); }

#endif // MYARK_MODULE_AUTHENTICATION
