// MyArk capability module: descriptor + IOCTL handler prototypes.

#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "module_descriptor.h"

#if MYARK_MODULE_CAPABILITY

NTSTATUS MyArkCapabilityInit(VOID);
VOID     MyArkCapabilityCleanup(VOID);

NTSTATUS MyArkCapabilityIoctlReport(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned);

extern MYARK_MODULE_DESCRIPTOR g_MyArkModule_Capability;

#endif // MYARK_MODULE_CAPABILITY