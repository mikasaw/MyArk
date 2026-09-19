// MyArk kernel module: descriptor + IOCTL table.
//
// Reads KeServiceDescriptorTable (the main SSDT) and emits one row per
// Nt* routine. The address-vs-.text comparison is a best-effort
// hook-detection primitive; R3 can independently verify against its
// own known SSDT map.

#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "module_descriptor.h"

#if MYARK_MODULE_KERNEL

NTSTATUS MyArkKernelInit(VOID);
VOID     MyArkKernelCleanup(VOID);

NTSTATUS MyArkKernelIoctlQuerySsdt(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned);

extern MYARK_MODULE_DESCRIPTOR g_MyArkModule_Kernel;

#endif // MYARK_MODULE_KERNEL
