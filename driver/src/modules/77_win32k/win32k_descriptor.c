// win32k R0 IOCTL table + descriptor.

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "myark_config.h"
#include "module_descriptor.h"
#include "ioctl_registry.h"
#include "../../dispatch/ioctl_helpers.h"
#include "win32k_descriptor.h"
#include "../../../shared/driver/MyArkWin32kIoctl.h"

#if MYARK_MODULE_WIN32K

#define MYARK_TRACE_WIN32K "[win32k] "

static NTSTATUS MyArkWin32kOnInit(VOID)
{
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
               MYARK_TRACE_WIN32K "init ok\n");
    return STATUS_SUCCESS;
}

static VOID MyArkWin32kOnCleanup(VOID)
{
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
               MYARK_TRACE_WIN32K "cleanup ok\n");
}

MYARK_IOCTL_ENTRY g_MyArkWin32kIoctlTable[] = {
    {
        IOCTL_MYARK_WIN32K_ENUMERATE_GUI_THREADS,
        MyArkWin32kIoctlEnumerateGuiThreads,
    },
    {
        IOCTL_MYARK_WIN32K_ENUMERATE_HOOKS,
        MyArkWin32kIoctlEnumerateHooks,
    },
};

MYARK_MODULE_DESCRIPTOR g_MyArkModule_Win32k = {
    .ModuleName      = "win32k",
    .ModuleId        = MYARK_WIN32K_MODULE_ID,
    .Ioctls          = g_MyArkWin32kIoctlTable,
    .IoctlCount      = ARRAYSIZE(g_MyArkWin32kIoctlTable),
    .Init            = MyArkWin32kOnInit,
    .Cleanup         = MyArkWin32kOnCleanup,
};

NTSTATUS MyArkWin32kInit(VOID)    { return MyArkWin32kOnInit(); }
VOID     MyArkWin32kCleanup(VOID)  { MyArkWin32kOnCleanup(); }

#endif // MYARK_MODULE_WIN32K
