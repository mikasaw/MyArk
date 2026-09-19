// MyArk thread module: descriptor + Init / Cleanup entry points.
//
// All 5 IOCTLs are statically wired here so g_AllModules[] can hand the
// DriverEntry loader the descriptor with one pointer to follow. The actual
// IOCTL implementations live in thread_ioctl.c; the per-feature helpers
// (enum / detail / crossview / actions) live in thread_query.c,
// thread_detail.c, thread_crossview.c, and thread_actions.c.

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "myark_config.h"
#include "module_descriptor.h"
#include "ioctl_registry.h"
#include "../../framework/os_version.h"
#include "../../../shared/driver/MyArkThreadIoctl.h"
#include "thread_descriptor.h"
#include "thread_internal.h"

#if MYARK_MODULE_THREAD

//
// The thread IOCTL table. Static array so the address range stays in this
// translation unit; g_AllModules[] points at the descriptor which points
// at this array.
//
static MYARK_IOCTL_ENTRY g_ThreadIoctls[] = {
    {
        IOCTL_MYARK_THREAD_ENUM,
        MyArkThreadIoctlEnum,
        "IOCTL_MYARK_THREAD_ENUM",
        0,
        0
    },
    {
        IOCTL_MYARK_THREAD_DETAIL,
        MyArkThreadIoctlDetail,
        "IOCTL_MYARK_THREAD_DETAIL",
        0,
        0
    },
    {
        IOCTL_MYARK_THREAD_DETAIL_RUNTIME,
        MyArkThreadIoctlDetailRuntime,
        "IOCTL_MYARK_THREAD_DETAIL_RUNTIME",
        0,
        0
    },
    {
        IOCTL_MYARK_THREAD_CROSSVIEW,
        MyArkThreadIoctlCrossview,
        "IOCTL_MYARK_THREAD_CROSSVIEW",
        0,
        0
    },
    {
        IOCTL_MYARK_THREAD_TERMINATE,
        MyArkThreadIoctlTerminate,
        "IOCTL_MYARK_THREAD_TERMINATE",
        0,
        0
    },
};

//
// The descriptor that g_AllModules[] points at when MYARK_MODULE_THREAD is
// on. The DriverEntry loader calls Init, then registers the IOCTL array.
//
MYARK_MODULE_DESCRIPTOR g_MyArkModule_Thread = {
    "thread",                                       // ModuleName
    "Thread module - ETHREAD enumeration + 3-view cross + actions",
    MYARK_THREAD_MODULE_ID,                         // ModuleId ('THRD')
    RTL_NUMBER_OF(g_ThreadIoctls),                  // IoctlCount
    g_ThreadIoctls,                                 // Ioctls
    MyArkThreadInit,                                // Init
    MyArkThreadCleanup,                             // Cleanup
    FALSE                                           // Initialized (set by loader)
};

NTSTATUS
MyArkThreadInit(
    VOID)
//
// Module-level one-shot: populate the StartAddress ownership cache from
// PsLoadedModuleList. The cache is module-global (g_MyArkThreadModuleRanges)
// so cross-view / enum / detail all share one consistent snapshot.
//
{
    //
    // Offsets are resolved at runtime (process_offsets.h): the ETHREAD
    // ThreadListEntry offset is discovered and self-validated, and thread id
    // / owner process / create time come from exported accessors that exist
    // on every supported build. Discovery failure disables only the
    // list-walking views; the module still loads.
    //
    NTSTATUS offsetsStatus = MyArkArkOffsetsInit();

    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_THREAD,
                "MyArkThreadInit: thread module linked (%lu IOCTLs), "
                "offsets=%s",
                (unsigned long)g_MyArkModule_Thread.IoctlCount,
                NT_SUCCESS(offsetsStatus) ? "resolved" : "unresolved");

    return STATUS_SUCCESS;
}

VOID
MyArkThreadCleanup(
    VOID)
{
    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_THREAD,
                "MyArkThreadCleanup: thread module torn down");
}

#endif // MYARK_MODULE_THREAD
