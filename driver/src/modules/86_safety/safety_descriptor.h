// MyArk safety module: descriptor + IOCTL handler prototypes.

#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "module_descriptor.h"

#if MYARK_MODULE_SAFETY

NTSTATUS MyArkSafetyInit(VOID);
VOID     MyArkSafetyCleanup(VOID);

NTSTATUS MyArkSafetyIoctlEvalGate(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned);

extern MYARK_MODULE_DESCRIPTOR g_MyArkModule_Safety;

#endif // MYARK_MODULE_SAFETY