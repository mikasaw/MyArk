// MyArk process module: descriptor + Init / Cleanup entry points.
//
// All 13 IOCTLs are statically wired here so g_AllModules[] can hand the
// DriverEntry loader the descriptor with one pointer to follow. The actual
// IOCTL implementations live in process_ioctl.c; the helper functions
// (collect-views, fill-detail, fill-crossview, perform-action) live in
// process_query.c, process_detail.c, process_crossview.c, and
// process_actions.c.

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "myark_config.h"
#include "module_descriptor.h"
#include "ioctl_registry.h"
#include "../../framework/os_version.h"
#include "../../../shared/driver/MyArkProcessIoctl.h"
#include "process_descriptor.h"
#include "process_internal.h"

#if MYARK_MODULE_PROCESS

//
// The process IOCTL table. Static array so the address range stays in this
// translation unit; g_AllModules[] points at the descriptor which points
// at this array.
//
static MYARK_IOCTL_ENTRY g_ProcessIoctls[] = {
    {
        IOCTL_MYARK_PROCESS_ENUM,
        MyArkProcessIoctlEnum,
        "IOCTL_MYARK_PROCESS_ENUM",
        0,
        0
    },
    {
        IOCTL_MYARK_PROCESS_ENUM_THREAD,
        MyArkProcessIoctlEnumThread,
        "IOCTL_MYARK_PROCESS_ENUM_THREAD",
        0,
        0
    },
    {
        IOCTL_MYARK_PROCESS_DETAIL,
        MyArkProcessIoctlDetail,
        "IOCTL_MYARK_PROCESS_DETAIL",
        0,
        0
    },
    {
        IOCTL_MYARK_PROCESS_DETAIL_RUNTIME,
        MyArkProcessIoctlDetailRuntime,
        "IOCTL_MYARK_PROCESS_DETAIL_RUNTIME",
        0,
        0
    },
    {
        IOCTL_MYARK_PROCESS_CROSSVIEW,
        MyArkProcessIoctlCrossview,
        "IOCTL_MYARK_PROCESS_CROSSVIEW",
        0,
        0
    },
    {
        IOCTL_MYARK_PROCESS_TERMINATE,
        MyArkProcessIoctlTerminate,
        "IOCTL_MYARK_PROCESS_TERMINATE",
        0,
        0
    },
    {
        IOCTL_MYARK_PROCESS_SUSPEND,
        MyArkProcessIoctlSuspend,
        "IOCTL_MYARK_PROCESS_SUSPEND",
        0,
        0
    },
    {
        IOCTL_MYARK_PROCESS_SET_PPL_LEVEL,
        MyArkProcessIoctlSetPplLevel,
        "IOCTL_MYARK_PROCESS_SET_PPL_LEVEL",
        0,
        0
    },
    {
        IOCTL_MYARK_PROCESS_SET_INTEGRITY,
        MyArkProcessIoctlSetIntegrity,
        "IOCTL_MYARK_PROCESS_SET_INTEGRITY",
        0,
        0
    },
    {
        IOCTL_MYARK_PROCESS_SET_VISIBILITY,
        MyArkProcessIoctlSetVisibility,
        "IOCTL_MYARK_PROCESS_SET_VISIBILITY",
        0,
        0
    },
    {
        IOCTL_MYARK_PROCESS_SET_SPECIAL_FLAGS,
        MyArkProcessIoctlSetSpecialFlags,
        "IOCTL_MYARK_PROCESS_SET_SPECIAL_FLAGS",
        0,
        0
    },
    {
        IOCTL_MYARK_PROCESS_DKOM,
        MyArkProcessIoctlDkom,
        "IOCTL_MYARK_PROCESS_DKOM",
        0,
        0
    },
    {
        IOCTL_MYARK_PROCESS_INJECT,
        MyArkProcessIoctlInject,
        "IOCTL_MYARK_PROCESS_INJECT",
        0,
        0
    },
    {
        IOCTL_MYARK_PROCESS_QUERY_CIDTABLE,
        MyArkProcessIoctlQueryCidTable,
        "IOCTL_MYARK_PROCESS_QUERY_CIDTABLE",
        0,
        0
    },
};

//
// The descriptor that g_AllModules[] points at when MYARK_MODULE_PROCESS is
// on. The driver_entry loader calls Init, then registers the IOCTL array.
//
MYARK_MODULE_DESCRIPTOR g_MyArkModule_Process = {
    "process",                                       // ModuleName
    "Process module - public/PspCidTable/ActiveLinks cross-view + actions",
    MYARK_PROCESS_MODULE_ID,                         // ModuleId ('PROC')
    RTL_NUMBER_OF(g_ProcessIoctls),                  // IoctlCount
    g_ProcessIoctls,                                 // Ioctls
    MyArkProcessInit,                                // Init
    MyArkProcessCleanup,                             // Cleanup
    FALSE                                            // Initialized (set by loader)
};

NTSTATUS
MyArkProcessInit(
    VOID)
{
    //
    // Offsets are resolved at runtime instead of being pinned to one build
    // (see process_offsets.h): Tier A accessors cover pid/ppid/name/etc. on
    // every supported Win10/Win11 build, and the two structural list offsets
    // are discovered and self-validated. A discovery failure no longer makes
    // the whole module absent -- it only disables the list-walking views,
    // which report STATUS_NOT_SUPPORTED on their own.
    //
    NTSTATUS offsetsStatus = MyArkArkOffsetsInit();

    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_MODULE,
                "MyArkProcessInit: process module linked (%lu IOCTLs), "
                "offsets=%s",
                (unsigned long)g_MyArkModule_Process.IoctlCount,
                NT_SUCCESS(offsetsStatus) ? "resolved" : "unresolved");

    return STATUS_SUCCESS;
}

VOID
MyArkProcessCleanup(
    VOID)
{
    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_MODULE,
                "MyArkProcessCleanup: process module torn down");
}

#endif // MYARK_MODULE_PROCESS