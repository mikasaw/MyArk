// MyArk device-audit module: descriptor + IOCTL table.

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "myark_config.h"
#include "module_descriptor.h"
#include "ioctl_registry.h"
#include "../../../shared/driver/MyArkDeviceAuditIoctl.h"
#include "devaudit_descriptor.h"
#include "devaudit_internal.h"

#if MYARK_MODULE_DEVICE_AUDIT

static MYARK_IOCTL_ENTRY g_DeviceAuditIoctls[] = {
    {
        IOCTL_MYARK_DEVICE_AUDIT_QUERY_DEVICE_STACK,
        MyArkDeviceAuditIoctlQueryDeviceStack,
        "IOCTL_MYARK_DEVICE_AUDIT_QUERY_DEVICE_STACK",
        0,
        0
    },
    {
        IOCTL_MYARK_DEVICE_AUDIT_QUERY_USB_TOPOLOGY,
        MyArkDeviceAuditIoctlQueryUsbTopology,
        "IOCTL_MYARK_DEVICE_AUDIT_QUERY_USB_TOPOLOGY",
        0,
        0
    },
    {
        IOCTL_MYARK_DEVICE_AUDIT_QUERY_GPU_DISPLAY,
        MyArkDeviceAuditIoctlQueryGpuDisplay,
        "IOCTL_MYARK_DEVICE_AUDIT_QUERY_GPU_DISPLAY",
        0,
        0
    },
    {
        IOCTL_MYARK_DEVICE_AUDIT_QUERY_INPUT_STACK,
        MyArkDeviceAuditIoctlQueryInputStack,
        "IOCTL_MYARK_DEVICE_AUDIT_QUERY_INPUT_STACK",
        0,
        0
    },
    {
        IOCTL_MYARK_DEVICE_AUDIT_QUERY_WATCHDOG,
        MyArkDeviceAuditIoctlQueryWatchdog,
        "IOCTL_MYARK_DEVICE_AUDIT_QUERY_WATCHDOG",
        0,
        0
    },
};

MYARK_MODULE_DESCRIPTOR g_MyArkModule_DeviceAudit = {
    "device-audit",                                 // ModuleName
    "Device audit module - device stacks + USB + GPU + input + watchdog (5 IOCTL)",
    MYARK_DEVAUDIT_MODULE_ID,                       // ModuleId ('DEVA')
    RTL_NUMBER_OF(g_DeviceAuditIoctls),             // IoctlCount
    g_DeviceAuditIoctls,                            // Ioctls
    MyArkDeviceAuditInit,                           // Init
    MyArkDeviceAuditCleanup,                        // Cleanup
    FALSE                                           // Initialized (set by loader)
};

NTSTATUS
MyArkDeviceAuditInit(
    VOID)
{
    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_DEVAUDIT,
                "MyArkDeviceAuditInit: device-audit module linked (%lu IOCTL)",
                (unsigned long)g_MyArkModule_DeviceAudit.IoctlCount);

    return STATUS_SUCCESS;
}

VOID
MyArkDeviceAuditCleanup(
    VOID)
{
    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_DEVAUDIT,
                "MyArkDeviceAuditCleanup: device-audit module torn down");
}

#endif // MYARK_MODULE_DEVICE_AUDIT
