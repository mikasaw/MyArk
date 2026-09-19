// MyArk Core Driver: IOCTL buffer validation helpers.
//
// All MyArk core IOCTLs use METHOD_BUFFERED. These helpers centralise the
// WdfRequestRetrieve(Input|Output)Buffer calls so handlers don't repeat the
// same boilerplate; handlers call them before touching any pointer field.

#pragma once

#include <ntddk.h>
#include <wdf.h>

NTSTATUS MyArkIoctlFetchInputBuffer(
    _In_  WDFREQUEST Request,
    _In_  size_t     MinSize,
    _Outptr_result_bytebuffer_(*InputBufferLength) PVOID* InputBuffer,
    _Out_ size_t*    InputBufferLength);

NTSTATUS MyArkIoctlFetchOutputBuffer(
    _In_  WDFREQUEST Request,
    _In_  size_t     MinSize,
    _Outptr_result_bytebuffer_(*OutputBufferLength) PVOID* OutputBuffer,
    _Out_ size_t*    OutputBufferLength);