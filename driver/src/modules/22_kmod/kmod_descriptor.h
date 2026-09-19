// MyArk kmod (kernel-driver enumeration) module: descriptor + IOCTL table.
//
// Walks IoDriverListHead to surface every loaded DRIVER_OBJECT plus the
// IRP_MJ_DEVICE_CONTROL dispatch function. The descriptor + R3 python
// package use the friendly name "module"; the header here is "kmod" to
// avoid clashing with the existing MyArkModuleIoctl.h (which carries the
// python-module registry IOCTLs).

#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "module_descriptor.h"

#if MYARK_MODULE_KMODULE

NTSTATUS MyArkKmodInit(VOID);
VOID     MyArkKmodCleanup(VOID);

NTSTATUS MyArkKmodIoctlQueryDriverObject(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned);

NTSTATUS MyArkKmodIoctlQueryIoctlRegistry(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned);

extern MYARK_MODULE_DESCRIPTOR g_MyArkModule_Kmod;

#endif // MYARK_MODULE_KMODULE
