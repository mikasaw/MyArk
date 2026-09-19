// MyArk safety module: IOCTL handlers.

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "myark_config.h"
#include "ioctl_validation.h"
#include "../../../shared/driver/MyArkSafetyIoctl.h"
#include "safety_descriptor.h"
#include "safety_internal.h"

#if MYARK_MODULE_SAFETY

//
// EVAL_GATE: evaluate the 6-step gate for a caller-supplied operation
// + step mask. Returns APPROVE / DENY / REQUIRE_TOKEN. When DENY is
// returned, FailedStep holds the (1-based) index of the first unmet
// step so the R3 client can show a precise "step N not completed"
// diagnostic.
//
NTSTATUS
MyArkSafetyIoctlEvalGate(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    UNREFERENCED_PARAMETER(Device);

    NTSTATUS                                  status;
    PMYARK_SAFETY_EVAL_INPUT                  inBuf = NULL;
    size_t                                    inSize = 0;
    PVOID                                     outBuf = NULL;
    size_t                                    outSize = 0;

    if (InputBufferLength < sizeof(MYARK_SAFETY_EVAL_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_SAFETY_EVAL_INPUT),
                                        (PVOID*)&inBuf,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (OutputBufferLength < sizeof(MYARK_SAFETY_EVAL_OUTPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         sizeof(MYARK_SAFETY_EVAL_OUTPUT),
                                         &outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    PMYARK_SAFETY_EVAL_OUTPUT out = (PMYARK_SAFETY_EVAL_OUTPUT)outBuf;
    RtlZeroMemory(out, sizeof(*out));

    UINT32 failed = 0;
    UINT32 decision = MyArkSafetyEvaluate(inBuf->OperationCode,
                                          inBuf->StepFlags,
                                          &failed);
    out->Decision   = decision;
    out->FailedStep = (decision == MYARK_SAFETY_DECISION_DENY) ? failed : 0;
    out->Reserved1  = 0;
    out->Reserved2  = 0;

    *BytesReturned = sizeof(MYARK_SAFETY_EVAL_OUTPUT);
    return STATUS_SUCCESS;
}

#endif // MYARK_MODULE_SAFETY