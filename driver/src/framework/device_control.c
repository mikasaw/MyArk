// MyArk Core Driver: control device creation.
//
// The driver is a single non-PnP control device (\\Device\\MyArkCore with
// the symbolic link \\\\?\\MyArkCore), so DeviceAdd is wired to NULL and
// this function is invoked directly from DriverEntry after WdfDriverCreate.

#include <ntddk.h>
#include <wdf.h>
#include <initguid.h>
#include "Trace.h"
#include "MyArkCoreIoctl.h"
#include "ioctl_dispatch.h"

EVT_WDF_IO_QUEUE_IO_READ  MyArkCoreEvtIoRead;
EVT_WDF_IO_QUEUE_IO_WRITE MyArkCoreEvtIoWrite;

//
// SDDL string: SYSTEM + Administrators get generic-all; no other account
// may open the device. Every IOCTL here reaches kernel memory or process
// state, so a world-accessible device would hand non-admin callers an
// arbitrary-read/write primitive (and with WRITE_VM a one-call BSOD).
// R3 therefore needs an elevated process -- driver_check surfaces
// ERROR_ACCESS_DENIED with a "run as Administrator" hint.
//
#define MYARK_CORE_DEVICE_SDDL_W   L"O:SY" \
                                   L"G:SY" \
                                   L"D:(A;;GA;;;SY)(A;;GA;;;BA)"
DECLARE_CONST_UNICODE_STRING(MYARK_CORE_DEVICE_SDDL_U, MYARK_CORE_DEVICE_SDDL_W);

NTSTATUS
MyArkCoreCreateControlDevice(
    _In_ WDFDRIVER Driver)
{
    NTSTATUS              status;
    PWDFDEVICE_INIT       deviceInit = NULL;
    WDFDEVICE             device     = NULL;
    WDF_OBJECT_ATTRIBUTES deviceAttributes;
    UNICODE_STRING        symbolicNameUs;
    WDF_IO_QUEUE_CONFIG   queueConfig;
    WDFQUEUE              queue = NULL;
    DECLARE_CONST_UNICODE_STRING(deviceName, MYARK_CORE_DEVICE_NAME);
    DECLARE_CONST_UNICODE_STRING(symlinkName, MYARK_CORE_SYMBOLIC_LINK_NAME);

    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_DEVICE,
                "MyArkCoreCreateControlDevice");

    deviceInit = WdfControlDeviceInitAllocate(Driver, &MYARK_CORE_DEVICE_SDDL_U);
    if (deviceInit == NULL) {
        TraceEvents(TRACE_LEVEL_ERROR,
                    MYARK_TRACE_DEVICE,
                    "WdfControlDeviceInitAllocate failed");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    WdfDeviceInitSetDeviceType(deviceInit, FILE_DEVICE_UNKNOWN);
    WdfDeviceInitSetExclusive(deviceInit, FALSE);
    WdfDeviceInitSetIoType(deviceInit, WdfDeviceIoBuffered);

    status = WdfDeviceInitAssignName(deviceInit, &deviceName);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR,
                    MYARK_TRACE_DEVICE,
                    "WdfDeviceInitAssignName failed: 0x%08X", status);
        WdfDeviceInitFree(deviceInit);
        return status;
    }

    WDF_OBJECT_ATTRIBUTES_INIT(&deviceAttributes);
    deviceAttributes.SynchronizationScope = WdfSynchronizationScopeNone;

    status = WdfDeviceCreate(&deviceInit, &deviceAttributes, &device);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR,
                    MYARK_TRACE_DEVICE,
                    "WdfDeviceCreate failed: 0x%08X", status);
        return status;
    }

    //
    // Publish the DOS-device link so R3 can CreateFileW("\\\\.\\MyArkCore").
    // KMDF removes the link when the control device is deleted at unload.
    //
    status = WdfDeviceCreateSymbolicLink(device, &symlinkName);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR,
                    MYARK_TRACE_DEVICE,
                    "WdfDeviceCreateSymbolicLink failed: 0x%08X", status);
        return status;
    }

    //
    // No WdfDeviceCreateDeviceInterface here: on the control device the
    // KMDF runtime rejects it with STATUS_INVALID_DEVICE_REQUEST, and R3
    // opens the device exclusively through the \\. \MyArkCore symbolic
    // link above (single-link discipline), so an interface would be a
    // second, unused discovery path.
    //

    //
    // Default sequential queue so handlers run one request at a time --
    // simpler debugging during S2 and easier to reason about while the
    // IOCTL table is being built up.
    //
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig,
                                            WdfIoQueueDispatchSequential);
    queueConfig.EvtIoDeviceControl = MyArkCoreEvtIoDeviceControl;
    queueConfig.EvtIoRead          = MyArkCoreEvtIoRead;
    queueConfig.EvtIoWrite         = MyArkCoreEvtIoWrite;

    status = WdfIoQueueCreate(device,
                              &queueConfig,
                              WDF_NO_OBJECT_ATTRIBUTES,
                              &queue);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR,
                    MYARK_TRACE_DEVICE,
                    "WdfIoQueueCreate failed: 0x%08X", status);
        return status;
    }

    WdfControlFinishInitializing(device);

    RtlInitUnicodeString(&symbolicNameUs, MYARK_CORE_WIN32_NAME);
    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_DEVICE,
                "MyArkCoreCreateControlDevice: ready (%wZ)",
                &symbolicNameUs);

    return STATUS_SUCCESS;
}