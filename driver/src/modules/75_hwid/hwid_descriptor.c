// hwid R0 IOCTL table + descriptor.

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "myark_config.h"
#include "module_descriptor.h"
#include "ioctl_registry.h"
#include "../../dispatch/ioctl_helpers.h"
#include "hwid_descriptor.h"
#include "../../../shared/driver/MyArkHwidIoctl.h"

#if MYARK_MODULE_HWID

#include "hwid_spoof_internal.h"

#define MYARK_TRACE_HWID "[hwid] "

static NTSTATUS MyArkHwidOnInit(VOID)
{
    NTSTATUS status = MyArkHwidSpoofEngineInit();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   MYARK_TRACE_HWID "spoof engine init failed: 0x%08X\n", status);
        return status;
    }
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
               MYARK_TRACE_HWID "init ok\n");
    return STATUS_SUCCESS;
}

static VOID MyArkHwidOnCleanup(VOID)
{
    // Detach any still-applied spoof class and drop the GPU registry
    // callback so unload never leaves filters in device stacks.
    MyArkHwidSpoofEngineTeardown();
    MyArkHwidSpoofGpuTeardown();
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
               MYARK_TRACE_HWID "cleanup ok\n");
}

MYARK_IOCTL_ENTRY g_MyArkHwidIoctlTable[] = {
    {
        IOCTL_MYARK_HWID_ENUMERATE_MJ,
        MyArkHwidIoctlEnumerateMj,
    },
    {
        IOCTL_MYARK_HWID_REPLACE_MJ,
        MyArkHwidIoctlReplaceMj,
    },
    {
        IOCTL_MYARK_HWID_QUERY_SPOOF_STATUS,
        MyArkHwidIoctlQuerySpoofStatus,
    },
    {
        IOCTL_MYARK_HWID_SET_SPOOF_CONFIG,
        MyArkHwidIoctlSetSpoofConfig,
    },
    {
        IOCTL_MYARK_HWID_QUERY_SPOOF_CAPTURE,
        MyArkHwidIoctlQuerySpoofCapture,
    },
};

MYARK_MODULE_DESCRIPTOR g_MyArkModule_Hwid = {
    .ModuleName      = "hwid",
    .ModuleId        = MYARK_HWID_MODULE_ID,
    .Ioctls          = g_MyArkHwidIoctlTable,
    .IoctlCount      = ARRAYSIZE(g_MyArkHwidIoctlTable),
    .Init            = MyArkHwidOnInit,
    .Cleanup         = MyArkHwidOnCleanup,
};

NTSTATUS MyArkHwidInit(VOID)  { return MyArkHwidOnInit(); }
VOID     MyArkHwidCleanup(VOID) { MyArkHwidOnCleanup(); }

#endif // MYARK_MODULE_HWID
