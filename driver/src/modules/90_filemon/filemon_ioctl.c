// MyArk file-monitor module: IOCTL handlers (R2-7).
//
// CONTROL (token-gated, 'FMR1'): arm/disarm with a DOS path prefix. All
// inputs are snapshotted into locals before the output buffer is fetched
// (METHOD_BUFFERED shares one buffer; a zeroed output must never be able to
// disturb inputs that are still in use).
//
// DRAIN / STATUS: read-only consumers, no token.

#include <fltKernel.h>
#include <wdf.h>
#include "Trace.h"
#include "myark_config.h"
#include "ioctl_validation.h"
#include "../../../shared/driver/MyArkFileMonitorIoctl.h"
#include "../../../shared/driver/MyArkSafetyToken.h"
#include "../../dispatch/safety_token.h"
#include "filemon_internal.h"

#if MYARK_MODULE_FILE_MONITOR

static
NTSTATUS
MyArkFileMonValidateToken(
    _In_ PMYARK_SAFETY_TOKEN Token,
    _In_ UINT32 Operation)
{
    return MyArkSafetyTokenValidate(Token,
                                    Operation,
                                    (UINT32)(UINT_PTR)PsGetCurrentProcessId());
}

//
// CONTROL.
//
NTSTATUS
MyArkFileMonIoctlControl(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned)
{
    PMYARK_FILEMON_CONTROL_INPUT  inBuf = NULL;
    PMYARK_FILEMON_CONTROL_OUTPUT outBuf = NULL;
    size_t inSize = 0;
    size_t outSize = 0;
    NTSTATUS status;
    UINT32 enable;
    WCHAR prefix[MYARK_FILEMON_PATH_CHARS];

    UNREFERENCED_PARAMETER(Device);

    if (InputBufferLength < sizeof(MYARK_FILEMON_CONTROL_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (OutputBufferLength < sizeof(MYARK_FILEMON_CONTROL_OUTPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_FILEMON_CONTROL_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = MyArkFileMonValidateToken(&inBuf->Token, MYARK_FILEMON_OP_CONTROL);
    if (!NT_SUCCESS(status)) {
        return STATUS_ACCESS_DENIED;
    }

    //
    // Snapshot before touching the output half of the shared buffer.
    //
    enable = inBuf->Enable;
    RtlCopyMemory(prefix, inBuf->PathPrefix, sizeof(prefix));
    prefix[MYARK_FILEMON_PATH_CHARS - 1] = L'\0';

    status = MyArkIoctlFetchOutputBuffer(Request,
                                         sizeof(MYARK_FILEMON_CONTROL_OUTPUT),
                                         (PVOID*)&outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = MyArkFileMonControl(enable, prefix, outBuf);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    *BytesReturned = sizeof(MYARK_FILEMON_CONTROL_OUTPUT);
    return STATUS_SUCCESS;
}

//
// DRAIN.
//
NTSTATUS
MyArkFileMonIoctlDrain(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned)
{
    PMYARK_FILEMON_DRAIN_INPUT inBuf = NULL;
    PVOID outBuf = NULL;
    size_t inSize = 0;
    size_t outSize = 0;
    NTSTATUS status;
    UINT32 maxEvents;

    UNREFERENCED_PARAMETER(Device);

    if (InputBufferLength < sizeof(MYARK_FILEMON_DRAIN_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (OutputBufferLength < sizeof(MYARK_FILEMON_DRAIN_OUTPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_FILEMON_DRAIN_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    maxEvents = inBuf->MaxEvents;

    status = MyArkIoctlFetchOutputBuffer(Request,
                                         sizeof(MYARK_FILEMON_DRAIN_OUTPUT),
                                         (PVOID*)&outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = MyArkFileMonDrain(maxEvents,
                               (PMYARK_FILEMON_DRAIN_OUTPUT)outBuf,
                               outSize,
                               BytesReturned);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    return STATUS_SUCCESS;
}

//
// STATUS.
//
NTSTATUS
MyArkFileMonIoctlStatus(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned)
{
    PMYARK_FILEMON_STATUS_OUTPUT outBuf = NULL;
    size_t outSize = 0;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(InputBufferLength);

    if (OutputBufferLength < sizeof(MYARK_FILEMON_STATUS_OUTPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = MyArkIoctlFetchOutputBuffer(Request,
                                         sizeof(MYARK_FILEMON_STATUS_OUTPUT),
                                         (PVOID*)&outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = MyArkFileMonQueryStatus(outBuf);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    *BytesReturned = sizeof(MYARK_FILEMON_STATUS_OUTPUT);
    return STATUS_SUCCESS;
}


//
// ENUM_FILTERS (R3-7): read-only system minifilter inventory.
//
NTSTATUS
MyArkFileMonIoctlEnumFilters(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned)
{
    PMYARK_FILEMON_ENUM_OUTPUT outBuf = NULL;
    size_t outSize = 0;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(InputBufferLength);

    if (OutputBufferLength < sizeof(MYARK_FILEMON_ENUM_OUTPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = MyArkIoctlFetchOutputBuffer(Request,
                                         sizeof(MYARK_FILEMON_ENUM_OUTPUT),
                                         (PVOID*)&outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Runs at PASSIVE_LEVEL on the sequential queue: FltEnumerateFilters
    // and the per-filter information queries allocate and wait.
    status = MyArkFileMonEnumFilters(outBuf);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    *BytesReturned = sizeof(MYARK_FILEMON_ENUM_OUTPUT);
    return STATUS_SUCCESS;
}

//
// BYPASS_PID (R3-7): QUERY is read-only; ADD/REMOVE/CLEAR are token-gated.
// METHOD_BUFFERED aliases one buffer for input and output, so the input is
// snapshotted before the output is zeroed -- reading inBuf afterwards would
// see the zeroed output, not the caller's bytes.
//
NTSTATUS
MyArkFileMonIoctlBypassPid(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned)
{
    MYARK_FILEMON_BYPASS_INPUT snap;
    PMYARK_FILEMON_BYPASS_INPUT inBuf = NULL;
    PMYARK_FILEMON_BYPASS_OUTPUT outBuf = NULL;
    size_t inSize = 0;
    size_t outSize = 0;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(Device);

    if (InputBufferLength < sizeof(MYARK_FILEMON_BYPASS_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (OutputBufferLength < sizeof(MYARK_FILEMON_BYPASS_OUTPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_FILEMON_BYPASS_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         sizeof(MYARK_FILEMON_BYPASS_OUTPUT),
                                         (PVOID*)&outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    snap = *inBuf;                               // aliasing snapshot
    RtlZeroMemory(outBuf, sizeof(*outBuf));

    if (snap.Action != MYARK_FILEMON_BYPASS_ACTION_QUERY) {
        status = MyArkFileMonValidateToken(&snap.Token,
                                           MYARK_FILEMON_OP_BYPASS_PID);
        if (!NT_SUCCESS(status)) {
            return STATUS_ACCESS_DENIED;
        }
    }
    if (snap.Action > MYARK_FILEMON_BYPASS_ACTION_CLEAR) {
        return STATUS_INVALID_PARAMETER;
    }

    status = MyArkFileMonBypass(snap.Action, snap.Pid, outBuf);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    *BytesReturned = sizeof(MYARK_FILEMON_BYPASS_OUTPUT);
    return STATUS_SUCCESS;
}

#endif // MYARK_MODULE_FILE_MONITOR
