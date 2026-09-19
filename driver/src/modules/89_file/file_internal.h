// MyArk file module: within-module helpers + handler declarations.

#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "../../../shared/driver/MyArkFileIoctl.h"
#include "../../../shared/driver/MyArkSafetyToken.h"

#if MYARK_MODULE_FILE

#define MYARK_TRACE_FILE                     MYARK_TRACE_MODULE

// The only path prefix the module accepts: DOS-drive NT paths. UNC and
// device paths are rejected to keep the delete surface bounded.
extern const WCHAR MyArkFileDosPrefix[];

// Rejects paths outside the "\??\" DOS-device namespace; terminates a
// local copy.
NTSTATUS
MyArkFileValidatePath(
    _In_ PCWSTR Path,
    _Out_ WCHAR LocalCopy[MYARK_FILE_PATH_CHARS]);

// -- IOCTL handlers (wired in file_descriptor.c) ---------------------------

NTSTATUS
MyArkFileIoctlDeletePath(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned);

NTSTATUS
MyArkFileIoctlQueryInfo(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned);

#endif // MYARK_MODULE_FILE
