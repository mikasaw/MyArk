// MyArk kernel-object module: descriptor + IOCTL handler prototypes.

#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "module_descriptor.h"

#if MYARK_MODULE_KERNEL_OBJECT

NTSTATUS MyArkKobjInit(VOID);
VOID     MyArkKobjCleanup(VOID);

NTSTATUS MyArkKobjIoctlEnumerateDirectory(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned);

NTSTATUS MyArkKobjIoctlIpcSummary(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned);

extern MYARK_MODULE_DESCRIPTOR g_MyArkModule_KernelObject;

#endif // MYARK_MODULE_KERNEL_OBJECT
