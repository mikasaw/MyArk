// MyArk Core Driver: declarations of the five core IOCTL handlers.
//
// Each handler follows the MYARK_IOCTL_HANDLER convention. They are
// registered during MyArkIoctlRegistryInitCore() in ioctl_registry.c so
// they appear in the global table from DriverEntry time.
//
// Log / config IOCTLs (GET_LOG, SET_LOG_CONFIG) are placeholders here --
// the kernel ring buffer will land in S6 once the user-mode log consumer
// exists. Until then they return SUCCESS and zero records / accept the
// request.

#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "ioctl_registry.h"
#include "MyArkCoreIoctl.h"

NTSTATUS MyArkCoreIoctlGetVersion(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned);

NTSTATUS MyArkCoreIoctlQueryModules(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned);

NTSTATUS MyArkCoreIoctlQueryCapabilities(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned);

NTSTATUS MyArkCoreIoctlGetLog(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned);

NTSTATUS MyArkCoreIoctlSetLogConfig(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned);

NTSTATUS MyArkCoreIoctlGetSessionKey(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned);

NTSTATUS MyArkIoctlRegistryInitCore(VOID);