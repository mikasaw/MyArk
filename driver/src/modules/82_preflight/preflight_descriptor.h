// MyArk preflight module: descriptor + IOCTL handler prototypes.

#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "module_descriptor.h"

#if MYARK_MODULE_PREFLIGHT

NTSTATUS MyArkPreflightInit(VOID);
VOID     MyArkPreflightCleanup(VOID);

NTSTATUS MyArkPreflightIoctlHealth(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned);

extern MYARK_MODULE_DESCRIPTOR g_MyArkModule_Preflight;

#endif // MYARK_MODULE_PREFLIGHT