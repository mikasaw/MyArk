// MyArk handle module: descriptor + Init / Cleanup + IOCTL table.
//
// Every byte in this file is gated on MYARK_MODULE_HANDLE so a profile
// that omits the macro links nothing into the .sys. The walker logic
// lives in handle_walk.c; the IOCTL handlers themselves in handle_ioctl.c.

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "myark_config.h"
#include "module_descriptor.h"
#include "ioctl_registry.h"
#include "../../../shared/driver/MyArkHandleIoctl.h"
#include "handle_descriptor.h"
#include "handle_internal.h"

#if MYARK_MODULE_HANDLE

static MYARK_IOCTL_ENTRY g_HandleIoctls[] = {
    {
        IOCTL_MYARK_HANDLE_ENUM_PROCESS_HANDLES,
        MyArkHandleIoctlEnumProcessHandles,
        "IOCTL_MYARK_HANDLE_ENUM_PROCESS_HANDLES",
        0,
        0
    },
    {
        IOCTL_MYARK_HANDLE_QUERY_HANDLE,
        MyArkHandleIoctlQueryHandle,
        "IOCTL_MYARK_HANDLE_QUERY_HANDLE",
        0,
        0
    },
};

MYARK_MODULE_DESCRIPTOR g_MyArkModule_Handle = {
    "handle",                                       // ModuleName
    "Handle module - EPROCESS.ObjectTable walker (2 IOCTL)",
    MYARK_HANDLE_MODULE_ID,                         // ModuleId ('HNDL')
    RTL_NUMBER_OF(g_HandleIoctls),                  // IoctlCount
    g_HandleIoctls,                                 // Ioctls
    MyArkHandleInit,                                // Init
    MyArkHandleCleanup,                             // Cleanup
    FALSE                                           // Initialized (set by loader)
};

NTSTATUS
MyArkHandleInit(
    VOID)
{
    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_HANDLE,
                "MyArkHandleInit: handle module linked (%lu IOCTL)",
                (unsigned long)g_MyArkModule_Handle.IoctlCount);

    return STATUS_SUCCESS;
}

VOID
MyArkHandleCleanup(
    VOID)
{
    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_HANDLE,
                "MyArkHandleCleanup: handle module torn down");
}

#endif // MYARK_MODULE_HANDLE
