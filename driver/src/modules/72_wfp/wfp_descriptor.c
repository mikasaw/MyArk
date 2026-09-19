// wfp R0 IOCTL table + descriptor.

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "myark_config.h"
#include "module_descriptor.h"
#include "ioctl_registry.h"
#include "../../dispatch/ioctl_helpers.h"
#include "wfp_descriptor.h"
#include "../../../shared/driver/MyArkWfpIoctl.h"

#if MYARK_MODULE_WFP

#define MYARK_TRACE_WFP "[wfp] "

static NTSTATUS MyArkWfpOnInit(VOID)
{
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
               MYARK_TRACE_WFP "init ok\n");
    return STATUS_SUCCESS;
}

static VOID MyArkWfpOnCleanup(VOID)
{
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
               MYARK_TRACE_WFP "cleanup ok\n");
}

MYARK_IOCTL_ENTRY g_MyArkWfpIoctlTable[] = {
    {
        IOCTL_MYARK_WFP_ENUMERATE_CALLOUTS,
        MyArkWfpIoctlEnumerateCallouts,
    },
    {
        IOCTL_MYARK_WFP_ADD_CALLOUT,
        MyArkWfpIoctlAddCallout,
    },
    {
        IOCTL_MYARK_WFP_REMOVE_CALLOUT,
        MyArkWfpIoctlRemoveCallout,
    },
    {
        IOCTL_MYARK_WFP_ENUM_NDIS_FILTERS,
        MyArkWfpIoctlEnumNdisFilters,
    },
    {
        IOCTL_MYARK_WFP_ENUM_CALLOUT_DRIVERS,
        MyArkWfpIoctlEnumCalloutDrivers,
    },
};

MYARK_MODULE_DESCRIPTOR g_MyArkModule_Wfp = {
    .ModuleName      = "wfp",
    .ModuleId        = MYARK_WFP_MODULE_ID,
    .Ioctls          = g_MyArkWfpIoctlTable,
    .IoctlCount      = ARRAYSIZE(g_MyArkWfpIoctlTable),
    .Init            = MyArkWfpOnInit,
    .Cleanup         = MyArkWfpOnCleanup,
};

NTSTATUS MyArkWfpInit(VOID)   { return MyArkWfpOnInit(); }
VOID     MyArkWfpCleanup(VOID) { MyArkWfpOnCleanup(); }

#endif // MYARK_MODULE_WFP
