// MyArk Core Driver: IOCTL buffer validation helpers.

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "ioctl_validation.h"

NTSTATUS
MyArkIoctlFetchInputBuffer(
    _In_  WDFREQUEST Request,
    _In_  size_t     MinSize,
    _Outptr_result_bytebuffer_(*InputBufferLength) PVOID* InputBuffer,
    _Out_ size_t*    InputBufferLength)
{
    NTSTATUS status;

    if (InputBuffer == NULL || InputBufferLength == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *InputBuffer = NULL;
    *InputBufferLength = 0;

    if (MinSize == 0) {
        return STATUS_SUCCESS;
    }

    status = WdfRequestRetrieveInputBuffer(Request,
                                           MinSize,
                                           InputBuffer,
                                           InputBufferLength);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_WARNING,
                    MYARK_TRACE_DISPATCH,
                    "RetrieveInputBuffer failed: 0x%08X", status);
        return status;
    }

    if (*InputBufferLength < MinSize) {
        TraceEvents(TRACE_LEVEL_WARNING,
                    MYARK_TRACE_DISPATCH,
                    "Input buffer too small: have %zu need %zu",
                    *InputBufferLength, MinSize);
        return STATUS_BUFFER_TOO_SMALL;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
MyArkIoctlFetchOutputBuffer(
    _In_  WDFREQUEST Request,
    _In_  size_t     MinSize,
    _Outptr_result_bytebuffer_(*OutputBufferLength) PVOID* OutputBuffer,
    _Out_ size_t*    OutputBufferLength)
{
    NTSTATUS status;

    if (OutputBuffer == NULL || OutputBufferLength == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *OutputBuffer = NULL;
    *OutputBufferLength = 0;

    status = WdfRequestRetrieveOutputBuffer(Request,
                                            MinSize,
                                            OutputBuffer,
                                            OutputBufferLength);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_WARNING,
                    MYARK_TRACE_DISPATCH,
                    "RetrieveOutputBuffer failed: 0x%08X", status);
        return status;
    }

    if (*OutputBufferLength < MinSize) {
        TraceEvents(TRACE_LEVEL_WARNING,
                    MYARK_TRACE_DISPATCH,
                    "Output buffer too small: have %zu need %zu",
                    *OutputBufferLength, MinSize);
        return STATUS_BUFFER_TOO_SMALL;
    }

    return STATUS_SUCCESS;
}