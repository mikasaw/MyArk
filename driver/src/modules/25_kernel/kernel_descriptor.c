// MyArk kernel module: descriptor + IOCTL table.

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "myark_config.h"
#include "module_descriptor.h"
#include "ioctl_registry.h"
#include "../../../shared/driver/MyArkKernelIoctl.h"
#include "kernel_descriptor.h"
#include "kernel_internal.h"

#if MYARK_MODULE_KERNEL

NTSTATUS
MyArkKernelIoctlScanInlineHooks(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned);

NTSTATUS
MyArkKernelIoctlPatchHook(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned);

NTSTATUS
MyArkKernelIoctlQueryPatchTarget(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned);

NTSTATUS
MyArkKernelIoctlEnumIatEat(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned);

NTSTATUS
MyArkKernelIoctlQueryShadowSsdt(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned);

NTSTATUS
MyArkKernelIoctlQueryIntegrity(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned);

NTSTATUS
MyArkKernelIoctlForceUnload(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned);

static MYARK_IOCTL_ENTRY g_KernelIoctls[] = {
    {
        IOCTL_MYARK_KERNEL_QUERY_SSDT,
        MyArkKernelIoctlQuerySsdt,
        "IOCTL_MYARK_KERNEL_QUERY_SSDT",
        0,
        0
    },
    {
        IOCTL_MYARK_KERNEL_SCAN_INLINE_HOOKS,
        MyArkKernelIoctlScanInlineHooks,
        "IOCTL_MYARK_KERNEL_SCAN_INLINE_HOOKS",
        0,
        0
    },
    {
        IOCTL_MYARK_KERNEL_PATCH_INLINE_HOOK,
        MyArkKernelIoctlPatchHook,
        "IOCTL_MYARK_KERNEL_PATCH_INLINE_HOOK",
        0,
        0
    },
    {
        IOCTL_MYARK_KERNEL_QUERY_PATCH_TARGET,
        MyArkKernelIoctlQueryPatchTarget,
        "IOCTL_MYARK_KERNEL_QUERY_PATCH_TARGET",
        0,
        0
    },
    {
        IOCTL_MYARK_KERNEL_ENUM_IAT_EAT,
        MyArkKernelIoctlEnumIatEat,
        "IOCTL_MYARK_KERNEL_ENUM_IAT_EAT",
        0,
        0
    },
    {
        IOCTL_MYARK_KERNEL_QUERY_SHADOW_SSDT,
        MyArkKernelIoctlQueryShadowSsdt,
        "IOCTL_MYARK_KERNEL_QUERY_SHADOW_SSDT",
        0,
        0
    },
    {
        IOCTL_MYARK_KERNEL_QUERY_INTEGRITY,
        MyArkKernelIoctlQueryIntegrity,
        "IOCTL_MYARK_KERNEL_QUERY_INTEGRITY",
        0,
        0
    },
    {
        IOCTL_MYARK_KERNEL_FORCE_UNLOAD,
        MyArkKernelIoctlForceUnload,
        "IOCTL_MYARK_KERNEL_FORCE_UNLOAD",
        0,
        0
    },
};

MYARK_MODULE_DESCRIPTOR g_MyArkModule_Kernel = {
    "kernel",                                       // ModuleName (friendly: "kernel" on the wire)
    "Kernel-side inspector - SSDT/shadow SSDT walker + hook scan/patch + IAT/EAT enum + integrity + force-unload (8 IOCTL)",
    MYARK_KERNEL_MODULE_ID,                         // ModuleId ('KRNL')
    RTL_NUMBER_OF(g_KernelIoctls),                  // IoctlCount
    g_KernelIoctls,                                 // Ioctls
    MyArkKernelInit,                                // Init
    MyArkKernelCleanup,                             // Cleanup
    FALSE                                           // Initialized (set by loader)
};

NTSTATUS
MyArkKernelInit(
    VOID)
{
    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_KERNEL,
                "MyArkKernelInit: kernel module linked (%lu IOCTL)",
                (unsigned long)g_MyArkModule_Kernel.IoctlCount);

    return STATUS_SUCCESS;
}

VOID
MyArkKernelCleanup(
    VOID)
{
    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_KERNEL,
                "MyArkKernelCleanup: kernel module torn down");
}

#endif // MYARK_MODULE_KERNEL
