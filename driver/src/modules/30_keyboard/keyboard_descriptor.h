// MyArk keyboard module: descriptor + IOCTL table.
//
// Reads win32k private structures (tagTHREADINFO->aphkStart[] +
// tagHOOK->phkNext). Offsets are hard-coded for Win11 24H2 / build
// 26100.x and will need refreshing when Microsoft shifts them -- S7
// pulls these from DynData.

#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "module_descriptor.h"

#if MYARK_MODULE_KEYBOARD

NTSTATUS MyArkKeyboardInit(VOID);
VOID     MyArkKeyboardCleanup(VOID);

NTSTATUS MyArkKeyboardIoctlEnumHotkeys(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned);

NTSTATUS MyArkKeyboardIoctlEnumHooks(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned);

extern MYARK_MODULE_DESCRIPTOR g_MyArkModule_Keyboard;

#endif // MYARK_MODULE_KEYBOARD
