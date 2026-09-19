// bugcheck R0 IOCTL table + descriptor.

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "myark_config.h"
#include "module_descriptor.h"
#include "ioctl_registry.h"
#include "../../dispatch/ioctl_helpers.h"
#include "bugcheck_descriptor.h"
#include "../../../shared/driver/MyArkBugcheckIoctl.h"

#if MYARK_MODULE_BUGCHECK

#define MYARK_TRACE_BUGCHECK "[bugcheck] "

static NTSTATUS MyArkBugcheckOnInit(VOID)
{
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
               MYARK_TRACE_BUGCHECK "init ok\n");
    return STATUS_SUCCESS;
}

static VOID MyArkBugcheckOnCleanup(VOID)
{
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
               MYARK_TRACE_BUGCHECK "cleanup ok\n");
}

MYARK_IOCTL_ENTRY g_MyArkBugcheckIoctlTable[] = {
    {
        IOCTL_MYARK_BUGCHECK_QUERY,
        MyArkBugcheckIoctlQuery,
    },
    {
        IOCTL_MYARK_BUGCHECK_RENDER_DIAG,
        MyArkBugcheckIoctlRenderDiag,
    },
};

MYARK_MODULE_DESCRIPTOR g_MyArkModule_Bugcheck = {
    .ModuleName      = "bugcheck",
    .ModuleId        = MYARK_BUGCHECK_MODULE_ID,
    .Ioctls          = g_MyArkBugcheckIoctlTable,
    .IoctlCount      = ARRAYSIZE(g_MyArkBugcheckIoctlTable),
    .Init            = MyArkBugcheckOnInit,
    .Cleanup         = MyArkBugcheckOnCleanup,
};

NTSTATUS MyArkBugcheckInit(VOID)    { return MyArkBugcheckOnInit(); }
VOID     MyArkBugcheckCleanup(VOID)  { MyArkBugcheckOnCleanup(); }

#endif // MYARK_MODULE_BUGCHECK
