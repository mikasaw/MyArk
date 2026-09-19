// redirect R0 IOCTL table + descriptor.

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "myark_config.h"
#include "module_descriptor.h"
#include "ioctl_registry.h"
#include "../../dispatch/ioctl_helpers.h"
#include "redirect_descriptor.h"
#include "redirect_internal.h"
#include "../../../shared/driver/MyArkRedirectIoctl.h"

#if MYARK_MODULE_REDIRECT

#define MYARK_TRACE_REDIRECT "[redirect] "

static NTSTATUS MyArkRedirectOnInit(VOID)
{
    MyArkRedirectEngineInit();
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
               MYARK_TRACE_REDIRECT "init ok\n");
    return STATUS_SUCCESS;
}

static VOID MyArkRedirectOnCleanup(VOID)
{
    //
    // R2-9: a clear via SET_RULES(Count=0) is the normal restore path;
    // teardown only guarantees the Cm callback is gone on unload.
    //
    MyArkRedirectEngineTeardown();
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
               MYARK_TRACE_REDIRECT "cleanup ok\n");
}

MYARK_IOCTL_ENTRY g_MyArkRedirectIoctlTable[] = {
    {
        IOCTL_MYARK_REDIRECT_INSPECT,
        MyArkRedirectIoctlInspect,
    },
    {
        IOCTL_MYARK_REDIRECT_APPLY,
        MyArkRedirectIoctlApply,
    },
    {
        IOCTL_MYARK_REDIRECT_SET_RULES,
        MyArkRedirectIoctlSetRules,
    },
    {
        IOCTL_MYARK_REDIRECT_QUERY_STATUS,
        MyArkRedirectIoctlQueryStatus,
    },
};

MYARK_MODULE_DESCRIPTOR g_MyArkModule_Redirect = {
    .ModuleName      = "redirect",
    .ModuleId        = MYARK_REDIRECT_MODULE_ID,
    .Ioctls          = g_MyArkRedirectIoctlTable,
    .IoctlCount      = ARRAYSIZE(g_MyArkRedirectIoctlTable),
    .Init            = MyArkRedirectOnInit,
    .Cleanup         = MyArkRedirectOnCleanup,
};

NTSTATUS MyArkRedirectInit(VOID)    { return MyArkRedirectOnInit(); }
VOID     MyArkRedirectCleanup(VOID)  { MyArkRedirectOnCleanup(); }

#endif // MYARK_MODULE_REDIRECT
