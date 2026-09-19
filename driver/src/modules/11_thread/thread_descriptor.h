// MyArk thread module: descriptor + IOCTL handler prototypes.
//
// All 5 IOCTLs are statically wired here so g_AllModules[] can hand the
// DriverEntry loader the descriptor with one pointer to follow. The actual
// IOCTL implementations live in thread_ioctl.c; the helper functions live
// in thread_query.c, thread_detail.c, thread_crossview.c, and
// thread_actions.c.

#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "module_descriptor.h"

#if MYARK_MODULE_THREAD

NTSTATUS MyArkThreadIoctlEnum(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned);

NTSTATUS MyArkThreadIoctlDetail(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned);

NTSTATUS MyArkThreadIoctlDetailRuntime(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned);

NTSTATUS MyArkThreadIoctlCrossview(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned);

NTSTATUS MyArkThreadIoctlTerminate(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned);

NTSTATUS MyArkThreadInit(VOID);
VOID     MyArkThreadCleanup(VOID);

extern MYARK_MODULE_DESCRIPTOR g_MyArkModule_Thread;

#endif // MYARK_MODULE_THREAD
