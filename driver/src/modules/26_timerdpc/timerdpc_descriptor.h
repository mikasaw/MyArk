// MyArk timerdpc module: descriptor + IOCTL handler prototypes.

#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "module_descriptor.h"

#if MYARK_MODULE_TIMERDPC

NTSTATUS MyArkTimerDpcInit(VOID);
VOID     MyArkTimerDpcCleanup(VOID);

//
// R3-3 (0x8A4/0x8A5): read-only per-CPU timer table + DPC queue
// snapshots. See shared/driver/MyArkTimerIoctl.h for the protocol and
// timerdpc_walk.c for the offset/discovery model.
//
NTSTATUS MyArkTimerDpcIoctlQueryTimer(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned);

NTSTATUS MyArkTimerDpcIoctlQueryDpc(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned);

extern MYARK_MODULE_DESCRIPTOR g_MyArkModule_TimerDpc;

#endif // MYARK_MODULE_TIMERDPC