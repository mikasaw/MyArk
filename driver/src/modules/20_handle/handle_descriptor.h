// MyArk handle module: descriptor + Init / Cleanup entry points.
//
// The handle module walks EPROCESS.ObjectTable (HANDLE_TABLE) directly
// to enumerate handles a process owns. ENUM_PROCESS_HANDLES + QUERY_HANDLE
// share the same OBJECT_HEADER-private-field access patterns; both rely
// on hard-coded offsets for Win11 24H2 / build 26100.x.
//
// Files in this directory:
//   handle_descriptor.c     -- this file (descriptor + table)
//   handle_internal.h       -- shared within-module helpers + offsets
//   handle_walk.c            -- HANDLE_TABLE walker + row fill
//   handle_ioctl.c           -- IOCTL handler entry points

#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "module_descriptor.h"

#if MYARK_MODULE_HANDLE

NTSTATUS MyArkHandleInit(VOID);
VOID     MyArkHandleCleanup(VOID);

NTSTATUS MyArkHandleIoctlEnumProcessHandles(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned);

NTSTATUS MyArkHandleIoctlQueryHandle(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned);

extern MYARK_MODULE_DESCRIPTOR g_MyArkModule_Handle;

#endif // MYARK_MODULE_HANDLE
