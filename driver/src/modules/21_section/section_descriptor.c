// MyArk section module: descriptor + IOCTL table.

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "myark_config.h"
#include "module_descriptor.h"
#include "ioctl_registry.h"
#include "../../../shared/driver/MyArkSectionIoctl.h"
#include "section_descriptor.h"
#include "section_internal.h"

#if MYARK_MODULE_SECTION

static MYARK_IOCTL_ENTRY g_SectionIoctls[] = {
    {
        IOCTL_MYARK_SECTION_QUERY_PROCESS,
        MyArkSectionIoctlQueryProcess,
        "IOCTL_MYARK_SECTION_QUERY_PROCESS",
        0,
        0
    },
    {
        IOCTL_MYARK_SECTION_QUERY_FILE_MAPPINGS,
        MyArkSectionIoctlQueryFileMappings,
        "IOCTL_MYARK_SECTION_QUERY_FILE_MAPPINGS",
        0,
        0
    },
};

MYARK_MODULE_DESCRIPTOR g_MyArkModule_Section = {
    "section",                                       // ModuleName
    "Section module - MmControlAreaListHead walker (2 IOCTL)",
    MYARK_SECTION_MODULE_ID,                         // ModuleId ('SCTN')
    RTL_NUMBER_OF(g_SectionIoctls),                  // IoctlCount
    g_SectionIoctls,                                 // Ioctls
    MyArkSectionInit,                                // Init
    MyArkSectionCleanup,                             // Cleanup
    FALSE                                            // Initialized (set by loader)
};

NTSTATUS
MyArkSectionInit(
    VOID)
{
    UNICODE_STRING name;
    RtlInitUnicodeString(&name, L"MmControlAreaListHead");
    g_MyArkSectionMmControlAreaListHead =
        (PLIST_ENTRY)MmGetSystemRoutineAddress(&name);

    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_SECTION,
                "MyArkSectionInit: section module linked (%lu IOCTL, list=%p)",
                (unsigned long)g_MyArkModule_Section.IoctlCount,
                g_MyArkSectionMmControlAreaListHead);

    return STATUS_SUCCESS;
}

VOID
MyArkSectionCleanup(
    VOID)
{
    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_SECTION,
                "MyArkSectionCleanup: section module torn down");
}

#endif // MYARK_MODULE_SECTION
