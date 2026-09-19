// MyArk storage module: descriptor + IOCTL table.

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "myark_config.h"
#include "module_descriptor.h"
#include "ioctl_registry.h"
#include "../../../shared/driver/MyArkStorageIoctl.h"
#include "storage_descriptor.h"
#include "storage_internal.h"

#if MYARK_MODULE_STORAGE

static MYARK_IOCTL_ENTRY g_StorageIoctls[] = {
    {
        IOCTL_MYARK_STORAGE_QUERY_VOLUME_STACK,
        MyArkStorageIoctlQueryVolumeStack,
        "IOCTL_MYARK_STORAGE_QUERY_VOLUME_STACK",
        0,
        0
    },
    {
        IOCTL_MYARK_STORAGE_QUERY_BITLOCKER,
        MyArkStorageIoctlQueryBitlocker,
        "IOCTL_MYARK_STORAGE_QUERY_BITLOCKER",
        0,
        0
    },
    {
        IOCTL_MYARK_STORAGE_QUERY_MOUNTMGR_MAPPING,
        MyArkStorageIoctlQueryMountmgrMapping,
        "IOCTL_MYARK_STORAGE_QUERY_MOUNTMGR_MAPPING",
        0,
        0
    },
    {
        IOCTL_MYARK_STORAGE_QUERY_FS_INTEGRITY,
        MyArkStorageIoctlQueryFsIntegrity,
        "IOCTL_MYARK_STORAGE_QUERY_FS_INTEGRITY",
        0,
        0
    },
};

MYARK_MODULE_DESCRIPTOR g_MyArkModule_Storage = {
    "storage",                                       // ModuleName
    "Storage module - filter stack + bitlocker + mountmgr + USN (4 IOCTL)",
    MYARK_STORAGE_MODULE_ID,                         // ModuleId ('STOR')
    RTL_NUMBER_OF(g_StorageIoctls),                  // IoctlCount
    g_StorageIoctls,                                 // Ioctls
    MyArkStorageInit,                                // Init
    MyArkStorageCleanup,                             // Cleanup
    FALSE                                            // Initialized (set by loader)
};

NTSTATUS
MyArkStorageInit(
    VOID)
{
    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_STORAGE,
                "MyArkStorageInit: storage module linked (%lu IOCTL)",
                (unsigned long)g_MyArkModule_Storage.IoctlCount);

    return STATUS_SUCCESS;
}

VOID
MyArkStorageCleanup(
    VOID)
{
    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_STORAGE,
                "MyArkStorageCleanup: storage module torn down");
}

#endif // MYARK_MODULE_STORAGE
