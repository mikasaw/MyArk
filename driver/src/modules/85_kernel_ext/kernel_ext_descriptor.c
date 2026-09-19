// kernel-ext R0 IOCTL table + descriptor.

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "myark_config.h"
#include "module_descriptor.h"
#include "ioctl_registry.h"
#include "../../dispatch/ioctl_helpers.h"
#include "kernel_ext_descriptor.h"
#include "../../../shared/driver/MyArkKernelExtIoctl.h"

#if MYARK_MODULE_KERNEL_EXT

#define MYARK_TRACE_KERNEL_EXT "[kernel_ext] "

static NTSTATUS MyArkKernelExtOnInit(VOID)
{
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
               MYARK_TRACE_KERNEL_EXT "init ok\n");
    return STATUS_SUCCESS;
}

static VOID MyArkKernelExtOnCleanup(VOID)
{
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
               MYARK_TRACE_KERNEL_EXT "cleanup ok\n");
}

MYARK_IOCTL_ENTRY g_MyArkKernelExtIoctlTable[] = {
    {
        IOCTL_MYARK_KERNEL_EXT_QUERY_WIN11_INFO,
        MyArkKernelExtIoctlQueryWin11Info,
    },
    {
        IOCTL_MYARK_KERNEL_EXT_READ_SYSCALL_TABLE,
        MyArkKernelExtIoctlReadSyscallTable,
    },
};

MYARK_MODULE_DESCRIPTOR g_MyArkModule_KernelExt = {
    .ModuleName      = "kernel_ext",
    .ModuleId        = MYARK_KERNEL_EXT_MODULE_ID,
    .Ioctls          = g_MyArkKernelExtIoctlTable,
    .IoctlCount      = ARRAYSIZE(g_MyArkKernelExtIoctlTable),
    .Init            = MyArkKernelExtOnInit,
    .Cleanup         = MyArkKernelExtOnCleanup,
};

NTSTATUS MyArkKernelExtInit(VOID)
{
    return MyArkKernelExtOnInit();
}

VOID MyArkKernelExtCleanup(VOID)
{
    MyArkKernelExtOnCleanup();
}

#endif // MYARK_MODULE_KERNEL_EXT
