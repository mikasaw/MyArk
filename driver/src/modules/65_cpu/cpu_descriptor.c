// MyArk CPU module: descriptor + IOCTL table (R3-14).

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "myark_config.h"
#include "module_descriptor.h"
#include "ioctl_registry.h"
#include "cpu_descriptor.h"
#include "../../../shared/driver/MyArkCpuIoctl.h"
#include "cpu_internal.h"

#if MYARK_MODULE_CPU

static MYARK_IOCTL_ENTRY g_MyArkCpuIoctls[] = {
    {
        IOCTL_MYARK_CPU_SNAPSHOT,
        MyArkCpuIoctlSnapshot,
        "IOCTL_MYARK_CPU_SNAPSHOT",
        0,
        0
    },
};

MYARK_MODULE_DESCRIPTOR g_MyArkModule_Cpu = {
    "cpu",                                          // ModuleName
    "CPU per-core register snapshot (CR/MSR/GDT/IDT, read-only, R3-14)",
    MYARK_CPU_MODULE_ID,                            // ModuleId ('CPU1')
    RTL_NUMBER_OF(g_MyArkCpuIoctls),                // IoctlCount
    g_MyArkCpuIoctls,                               // Ioctls
    MyArkCpuModuleInit,                             // Init
    MyArkCpuModuleCleanup,                          // Cleanup
    FALSE                                           // Initialized
};

NTSTATUS MyArkCpuModuleInit(VOID)
{
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
               "[cpu] init ok\n");
    return STATUS_SUCCESS;
}

VOID MyArkCpuModuleCleanup(VOID)
{
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
               "[cpu] cleanup ok\n");
}

#endif // MYARK_MODULE_CPU
