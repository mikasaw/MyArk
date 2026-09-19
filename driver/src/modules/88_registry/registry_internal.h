// MyArk registry module: within-module helpers + handler declarations.

#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "../../../shared/driver/MyArkRegistryIoctl.h"
#include "../../../shared/driver/MyArkSafetyToken.h"

#if MYARK_MODULE_REGISTRY

#define MYARK_TRACE_REGISTRY                MYARK_TRACE_MODULE

// The only registry roots the module will touch. Everything else
// (including \Registry\A and raw \REGISTRY\ spellings) is rejected.
extern const WCHAR MyArkRegRootMachine[];
extern const WCHAR MyArkRegRootUser[];

// Rejects paths outside the two allowed roots; terminates a local copy.
NTSTATUS
MyArkRegistryValidatePath(
    _In_ PCWSTR Path,
    _Out_ WCHAR LocalCopy[MYARK_REGISTRY_KEY_PATH_CHARS]);

// Opens an existing key (OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE).
NTSTATUS
MyArkRegistryOpenKey(
    _In_ PCWSTR NtPath,
    _In_ ACCESS_MASK Access,
    _Out_ PHANDLE Handle);

// -- IOCTL handlers (wired in registry_descriptor.c) -----------------------

NTSTATUS
MyArkRegistryIoctlReadValue(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned);

NTSTATUS
MyArkRegistryIoctlEnumKey(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned);

NTSTATUS
MyArkRegistryIoctlSetValue(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned);

NTSTATUS
MyArkRegistryIoctlDeleteValue(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned);

NTSTATUS
MyArkRegistryIoctlCreateKey(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned);

NTSTATUS
MyArkRegistryIoctlDeleteKey(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned);

NTSTATUS
MyArkRegistryIoctlRenameValue(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned);

NTSTATUS
MyArkRegistryIoctlRenameKey(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned);

#endif // MYARK_MODULE_REGISTRY
