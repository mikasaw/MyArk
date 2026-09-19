// MyArk file module: descriptor + IOCTL table.

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "myark_config.h"
#include "module_descriptor.h"
#include "ioctl_registry.h"
#include "../../../shared/driver/MyArkFileIoctl.h"
#include "file_descriptor.h"
#include "file_internal.h"

#if MYARK_MODULE_FILE

NTSTATUS
MyArkFileIoctlSetIntegrity(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned);

NTSTATUS
MyArkFileIoctlQueryIntegrity(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned);

static MYARK_IOCTL_ENTRY g_FileIoctls[] = {
    {
        IOCTL_MYARK_FILE_DELETE_PATH,
        MyArkFileIoctlDeletePath,
        "IOCTL_MYARK_FILE_DELETE_PATH",
        0,
        0
    },
    {
        IOCTL_MYARK_FILE_QUERY_INFO,
        MyArkFileIoctlQueryInfo,
        "IOCTL_MYARK_FILE_QUERY_INFO",
        0,
        0
    },
    {
        IOCTL_MYARK_FILE_SET_INTEGRITY,
        MyArkFileIoctlSetIntegrity,
        "IOCTL_MYARK_FILE_SET_INTEGRITY",
        0,
        0
    },
    {
        IOCTL_MYARK_FILE_QUERY_INTEGRITY,
        MyArkFileIoctlQueryIntegrity,
        "IOCTL_MYARK_FILE_QUERY_INTEGRITY",
        0,
        0
    },
};

MYARK_MODULE_DESCRIPTOR g_MyArkModule_File = {
    "file",                                         // ModuleName
    "File module - R0 delete (3-tier) + query info + integrity label (4 IOCTL)",
    MYARK_FILE_MODULE_ID,                           // ModuleId ('FILE')
    RTL_NUMBER_OF(g_FileIoctls),                    // IoctlCount
    g_FileIoctls,                                   // Ioctls
    MyArkFileModuleInit,                            // Init
    MyArkFileModuleCleanup,                         // Cleanup
    FALSE                                           // Initialized (set by loader)
};

NTSTATUS
MyArkFileModuleInit(
    VOID)
{
    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_FILE,
                "MyArkFileModuleInit: file module linked (%lu IOCTL)",
                (unsigned long)g_MyArkModule_File.IoctlCount);

    return STATUS_SUCCESS;
}

VOID
MyArkFileModuleCleanup(
    VOID)
{
    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_FILE,
                "MyArkFileModuleCleanup: file module torn down");
}

#endif // MYARK_MODULE_FILE
