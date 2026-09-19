// MyArk memory module: descriptor + Init / Cleanup entry points.
//
// Every byte in this file is gated on MYARK_MODULE_MEMORY so a profile
// that omits the macro links nothing into the .sys. DriverEntry walks
// g_AllModules[] (defined in module_registry.c) which conditionally
// references g_MyArkModule_Memory.

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "myark_config.h"
#include "module_descriptor.h"
#include "ioctl_registry.h"
#include "../../../shared/driver/MyArkMemoryIoctl.h"
#include "memory_module.h"

#if MYARK_MODULE_MEMORY

//
// The memory IOCTL table. Array lives in this translation unit so the
// address range is contiguous; QueryCapabilities reverse-looks up the
// owning module by walking g_AllModules[].Ioctls (see core_ioctl_handlers.c).
//
// Order matches the issue body:
//   QUERY_VM / READ_VM / WRITE_VM / TRANSLATE_VA / QUERY_PT_ENTRY
//   READ_PHYSICAL / WRITE_PHYSICAL / QUERY_PHYSICAL_LAYOUT
//   SCAN_KERNEL_EXECUTABLE / SCAN_KERNEL_MEMORY_EVIDENCE
//
static MYARK_IOCTL_ENTRY g_MemoryIoctls[] = {
    {
        IOCTL_MYARK_MEMORY_QUERY_VM,
        MyArkMemoryIoctlQueryVm,
        "IOCTL_MYARK_MEMORY_QUERY_VM",
        0,
        0
    },
    {
        IOCTL_MYARK_MEMORY_READ_VM,
        MyArkMemoryIoctlReadVm,
        "IOCTL_MYARK_MEMORY_READ_VM",
        0,
        0
    },
    {
        IOCTL_MYARK_MEMORY_WRITE_VM,
        MyArkMemoryIoctlWriteVm,
        "IOCTL_MYARK_MEMORY_WRITE_VM",
        0,
        0
    },
    {
        IOCTL_MYARK_MEMORY_TRANSLATE_VA,
        MyArkMemoryIoctlTranslateVa,
        "IOCTL_MYARK_MEMORY_TRANSLATE_VA",
        0,
        0
    },
    {
        IOCTL_MYARK_MEMORY_QUERY_PT_ENTRY,
        MyArkMemoryIoctlQueryPtEntry,
        "IOCTL_MYARK_MEMORY_QUERY_PT_ENTRY",
        0,
        0
    },
    {
        IOCTL_MYARK_MEMORY_READ_PHYSICAL,
        MyArkMemoryIoctlReadPhysical,
        "IOCTL_MYARK_MEMORY_READ_PHYSICAL",
        0,
        0
    },
    {
        IOCTL_MYARK_MEMORY_WRITE_PHYSICAL,
        MyArkMemoryIoctlWritePhysical,
        "IOCTL_MYARK_MEMORY_WRITE_PHYSICAL",
        0,
        0
    },
    {
        IOCTL_MYARK_MEMORY_QUERY_PHYSICAL_LAYOUT,
        MyArkMemoryIoctlQueryPhysicalLayout,
        "IOCTL_MYARK_MEMORY_QUERY_PHYSICAL_LAYOUT",
        0,
        0
    },
    {
        IOCTL_MYARK_MEMORY_SCAN_KERNEL_EXECUTABLE,
        MyArkMemoryIoctlScanKernelExecutable,
        "IOCTL_MYARK_MEMORY_SCAN_KERNEL_EXECUTABLE",
        0,
        0
    },
    {
        IOCTL_MYARK_MEMORY_SCAN_KERNEL_MEMORY_EVIDENCE,
        MyArkMemoryIoctlScanKernelMemoryEvidence,
        "IOCTL_MYARK_MEMORY_SCAN_KERNEL_MEMORY_EVIDENCE",
        0,
        0
    },
};

//
// The descriptor that g_AllModules[] points at when MYARK_MODULE_MEMORY is on.
//
MYARK_MODULE_DESCRIPTOR g_MyArkModule_Memory = {
    "memory",                                          // ModuleName
    "Memory module - virtual + physical + pagetable + scan (10 IOCTL)",  // ModuleDescription
    MYARK_MEMORY_MODULE_ID,                            // ModuleId ('MEMM')
    RTL_NUMBER_OF(g_MemoryIoctls),                     // IoctlCount
    g_MemoryIoctls,                                    // Ioctls
    MyArkMemoryInit,                                   // Init
    MyArkMemoryCleanup,                                // Cleanup
    FALSE                                              // Initialized (set by loader)
};

NTSTATUS
MyArkMemoryInit(
    VOID)
{
    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_MEMORY,
                "MyArkMemoryInit: memory module linked (%lu IOCTL)",
                (unsigned long)g_MyArkModule_Memory.IoctlCount);

    return STATUS_SUCCESS;
}

VOID
MyArkMemoryCleanup(
    VOID)
{
    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_MEMORY,
                "MyArkMemoryCleanup: memory module torn down");
}

#endif // MYARK_MODULE_MEMORY