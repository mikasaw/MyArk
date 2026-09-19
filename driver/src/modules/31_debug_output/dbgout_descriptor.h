// MyArk debug-output module: descriptor + IOCTL table.
//
// Installs a single DbgPrint callback via DbgSetDebugPrintCallback,
// buffers every line into a 256-entry ring (each 512 bytes), and
// exposes CONTROL + DRAIN IOCTLs to R3.

#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "module_descriptor.h"

#if MYARK_MODULE_DEBUG_OUTPUT

NTSTATUS MyArkDebugOutputInit(VOID);
VOID     MyArkDebugOutputCleanup(VOID);

NTSTATUS MyArkDebugOutputIoctlControl(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned);

NTSTATUS MyArkDebugOutputIoctlDrain(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned);

extern MYARK_MODULE_DESCRIPTOR g_MyArkModule_DebugOutput;

#endif // MYARK_MODULE_DEBUG_OUTPUT
