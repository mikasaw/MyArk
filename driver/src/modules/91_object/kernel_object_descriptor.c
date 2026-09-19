// kernel-object module R0 IOCTL table + descriptor (R3-4b).
//
// Read-only object-namespace surface: directory enumeration + named-pipe /
// mailslot IPC summary. Fills the S4-era MyArkKernelObjectIoctl.h
// placeholder; module ID 'KOBJ' was already reserved in MyArkPluginApi.h
// and MYARK_MODULE_KERNEL_OBJECT already gated on in myark_full.h.

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "myark_config.h"
#include "module_descriptor.h"
#include "ioctl_registry.h"
#include "kernel_object_descriptor.h"
#include "kernel_object_internal.h"

#if MYARK_MODULE_KERNEL_OBJECT

static NTSTATUS MyArkKobjOnInit(VOID)
{
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
               MYARK_TRACE_KOBJ "init ok\n");
    return STATUS_SUCCESS;
}

static VOID MyArkKobjOnCleanup(VOID)
{
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
               MYARK_TRACE_KOBJ "cleanup ok\n");
}

MYARK_IOCTL_ENTRY g_MyArkKobjIoctlTable[] = {
    {
        IOCTL_MYARK_KOBJ_ENUM_DIRECTORY,
        MyArkKobjIoctlEnumerateDirectory,
    },
    {
        IOCTL_MYARK_KOBJ_IPC_SUMMARY,
        MyArkKobjIoctlIpcSummary,
    },
};

MYARK_MODULE_DESCRIPTOR g_MyArkModule_KernelObject = {
    .ModuleName      = "kernel_object",
    .ModuleDescription = "kernel object namespace + IPC summary (R3-4b)",
    .ModuleId        = MYARK_KOBJ_MODULE_ID,
    .Ioctls          = g_MyArkKobjIoctlTable,
    .IoctlCount      = ARRAYSIZE(g_MyArkKobjIoctlTable),
    .Init            = MyArkKobjOnInit,
    .Cleanup         = MyArkKobjOnCleanup,
};

NTSTATUS MyArkKobjInit(VOID)   { return MyArkKobjOnInit(); }
VOID     MyArkKobjCleanup(VOID) { MyArkKobjOnCleanup(); }

#endif // MYARK_MODULE_KERNEL_OBJECT
