// MyArk device-audit module: descriptor + IOCTL table.

#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "module_descriptor.h"

#if MYARK_MODULE_DEVICE_AUDIT

NTSTATUS MyArkDeviceAuditInit(VOID);
VOID     MyArkDeviceAuditCleanup(VOID);

NTSTATUS MyArkDeviceAuditIoctlQueryDeviceStack(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned);

NTSTATUS MyArkDeviceAuditIoctlQueryUsbTopology(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned);

NTSTATUS MyArkDeviceAuditIoctlQueryGpuDisplay(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned);

NTSTATUS MyArkDeviceAuditIoctlQueryInputStack(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned);

NTSTATUS MyArkDeviceAuditIoctlQueryWatchdog(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned);

extern MYARK_MODULE_DESCRIPTOR g_MyArkModule_DeviceAudit;

#endif // MYARK_MODULE_DEVICE_AUDIT
