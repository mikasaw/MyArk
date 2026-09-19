// MyArk hello module: public surface for descriptor + IOCTL handler.
//
// Forward decls only -- the bodies live in hello_descriptor.c (Init /
// Cleanup / g_MyArkModule_Hello) and hello_ioctl_handlers.c (Ping).
// Every declaration is gated on MYARK_MODULE_HELLO so callers can include
// the header unconditionally without dragging in a NULL function pointer
// when the profile disables the module.

#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "module_descriptor.h"

#if MYARK_MODULE_HELLO

NTSTATUS MyArkHelloInit(VOID);
VOID     MyArkHelloCleanup(VOID);

NTSTATUS MyArkHelloIoctlPing(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned);

NTSTATUS MyArkHelloIoctlGreet(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned);

extern MYARK_MODULE_DESCRIPTOR g_MyArkModule_Hello;

#endif // MYARK_MODULE_HELLO