// MyArk dyndata module: descriptor + IOCTL table.
//
// S7.1 -- NtQuerySystemInformation-style kernel-side surface used by the
// rest of the S7 modules (callback / kernel object / wfp / mutation / etc.)
// to avoid hardcoding build-specific offsets in every consumer.
//
// All 9 IOCTLs are read-only and use the MyArk METHOD_BUFFERED convention.
// The descriptor symbol participates in the global g_AllModules[] table
// (see driver/src/module/module_registry.c) when MYARK_MODULE_DYNDATA is
// enabled in the active build profile.

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "myark_config.h"
#include "module_descriptor.h"
#include "ioctl_registry.h"
#include "../../../shared/driver/MyArkDyndataIoctl.h"
#include "dyndata_descriptor.h"
#include "dyndata_internal.h"

#if MYARK_MODULE_DYNDATA

//
// The dyndata IOCTL table. Static array so the address range stays in this
// translation unit; g_AllModules[] points at the descriptor which points
// at this array.
//
static MYARK_IOCTL_ENTRY g_DynDataIoctls[] = {
    {
        IOCTL_MYARK_DYNDATA_QUERY_PROCESS,
        MyArkDynDataIoctlQueryProcess,
        "IOCTL_MYARK_DYNDATA_QUERY_PROCESS",
        0,
        0
    },
    {
        IOCTL_MYARK_DYNDATA_QUERY_THREAD,
        MyArkDynDataIoctlQueryThread,
        "IOCTL_MYARK_DYNDATA_QUERY_THREAD",
        0,
        0
    },
    {
        IOCTL_MYARK_DYNDATA_QUERY_MODULE,
        MyArkDynDataIoctlQueryModule,
        "IOCTL_MYARK_DYNDATA_QUERY_MODULE",
        0,
        0
    },
    {
        IOCTL_MYARK_DYNDATA_QUERY_HANDLE,
        MyArkDynDataIoctlQueryHandle,
        "IOCTL_MYARK_DYNDATA_QUERY_HANDLE",
        0,
        0
    },
    {
        IOCTL_MYARK_DYNDATA_QUERY_FILE,
        MyArkDynDataIoctlQueryFile,
        "IOCTL_MYARK_DYNDATA_QUERY_FILE",
        0,
        0
    },
    {
        IOCTL_MYARK_DYNDATA_QUERY_SYSCALL,
        MyArkDynDataIoctlQuerySyscall,
        "IOCTL_MYARK_DYNDATA_QUERY_SYSCALL",
        0,
        0
    },
    {
        IOCTL_MYARK_DYNDATA_QUERY_TOKEN,
        MyArkDynDataIoctlQueryToken,
        "IOCTL_MYARK_DYNDATA_QUERY_TOKEN",
        0,
        0
    },
    {
        IOCTL_MYARK_DYNDATA_QUERY_OBJECT,
        MyArkDynDataIoctlQueryObject,
        "IOCTL_MYARK_DYNDATA_QUERY_OBJECT",
        0,
        0
    },
    {
        IOCTL_MYARK_DYNDATA_QUERY_SSDT,
        MyArkDynDataIoctlQuerySsdt,
        "IOCTL_MYARK_DYNDATA_QUERY_SSDT",
        0,
        0
    },
};

//
// Module descriptor wired into g_AllModules[] (see module_registry.c).
//
MYARK_MODULE_DESCRIPTOR g_MyArkModule_DynData = {
    "dyndata",                                          // ModuleName
    "DynData - NtQuerySystemInformation-style kernel-side surface (9 IOCTLs)",
    MYARK_DYNDATA_MODULE_ID,                            // ModuleId ('DYND')
    RTL_NUMBER_OF(g_DynDataIoctls),                     // IoctlCount
    g_DynDataIoctls,                                    // Ioctls
    MyArkDynDataInit,                                   // Init
    MyArkDynDataCleanup,                                // Cleanup
    FALSE                                               // Initialized (set by loader)
};

NTSTATUS
MyArkDynDataInit(
    VOID)
{
    NTSTATUS status = MyArkDynDataPagetableResolveAll();
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_WARNING,
                    MYARK_TRACE_DYNDATA,
                    "MyArkDynDataInit: pagetable resolve partial (status 0x%08X); IOCTLs will report empty results until resolved",
                    status);
    }

    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_DYNDATA,
                "MyArkDynDataInit: dyndata module linked (%lu IOCTLs)",
                (unsigned long)g_MyArkModule_DynData.IoctlCount);

    return STATUS_SUCCESS;
}

VOID
MyArkDynDataCleanup(
    VOID)
{
    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_DYNDATA,
                "MyArkDynDataCleanup: dyndata module torn down");
}

#endif // MYARK_MODULE_DYNDATA
