// MyArk Core Driver: S7.3-era 3-arg IOCTL buffer helper aliases.
//
// The canonical MyArkIoctlFetch(Input|Output)Buffer helpers in
// ioctl_validation.h take 4 args (Request, MinSize, Buffer*, *ActualLength);
// the S7.3 modules were written against a 3-arg shape that discards the
// actual length. This header preserves the S7.3 call-site shape via
// static inline wrappers that forward to WdfRequestRetrieve(Input|Output)
// Buffer directly.
//
// ioctl_validation.h is intentionally NOT included here -- its 4-arg
// declarations would collide with the inline 3-arg definitions below.
// A future S7.x-fix may merge the two helper families.
//
// The 20 S7.3 source files (72_wfp / 73_mutation / 74_redirect / 75_hwid /
// 76_bugcheck / 77_win32k / 78_wsl / 79_alpc / 80_authentication /
// 85_kernel_ext, each *_descriptor.c + *_ioctl.c) include this header via
// "../../dispatch/ioctl_helpers.h".

#pragma once

#include <ntddk.h>
#include <wdf.h>

static __inline
NTSTATUS
MyArkIoctlFetchInputBuffer(
    _In_  WDFREQUEST Request,
    _In_  size_t     MinSize,
    _Outptr_result_bytebuffer_(*InputBufferLength) PVOID* InputBuffer)
//
// 3-arg wrapper: discards *InputBufferLength. Mirrors the validation
// behaviour in ioctl_validation.c (returns STATUS_BUFFER_TOO_SMALL when
// the WDF-supplied length is below MinSize) but without the TraceEvents
// log line -- this header is included by every S7.3 IOCTL handler and
// we want the helpers to stay header-only.
//
{
    size_t actualLength = 0;
    NTSTATUS status;

    if (InputBuffer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *InputBuffer = NULL;

    if (MinSize == 0) {
        return STATUS_SUCCESS;
    }

    status = WdfRequestRetrieveInputBuffer(Request,
                                           MinSize,
                                           InputBuffer,
                                           &actualLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (actualLength < MinSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    return STATUS_SUCCESS;
}

static __inline
NTSTATUS
MyArkIoctlFetchOutputBuffer(
    _In_  WDFREQUEST Request,
    _In_  size_t     MinSize,
    _Outptr_result_bytebuffer_(*OutputBufferLength) PVOID* OutputBuffer)
//
// 3-arg wrapper: discards *OutputBufferLength. Same shape as the input
// helper above but with WdfRequestRetrieveOutputBuffer.
//
{
    size_t actualLength = 0;
    NTSTATUS status;

    if (OutputBuffer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *OutputBuffer = NULL;

    status = WdfRequestRetrieveOutputBuffer(Request,
                                            MinSize,
                                            OutputBuffer,
                                            &actualLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (actualLength < MinSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    return STATUS_SUCCESS;
}