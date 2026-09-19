// redirect R0 IOCTL handlers.
//
// INSPECT    - in S7.3 returns Count=0 stub.
// APPLY      - reserved; STATUS_NOT_IMPLEMENTED.
// SET_RULES  - R2-9: token-gated atomic rule-set replace (staged then
//              committed so inputs survive the shared-buffer output zero).
// QUERY_STATUS - R2-9: read-only counters/state snapshot.

#include "redirect_descriptor.h"
#include "../../dispatch/ioctl_helpers.h"
#include "../../dispatch/safety_token.h"
#include "../../../shared/driver/MyArkRedirectIoctl.h"
#include "myark_config.h"
#include "redirect_internal.h"

#if MYARK_MODULE_REDIRECT

NTSTATUS MyArkRedirectIoctlInspect(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned)
{
    NTSTATUS                            status;
    PMYARK_REDIRECT_INSPECT_OUTPUT      out_buf;
    size_t                              out_size = sizeof(MYARK_REDIRECT_INSPECT_OUTPUT);

    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(InputBufferLength);

    if (OutputBufferLength < out_size) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = MyArkIoctlFetchOutputBuffer(Request, out_size, (PVOID*)&out_buf);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlZeroMemory(out_buf, out_size);
    out_buf->Count = 0;  // R0 walk deferred; S7.x-fix

    *BytesReturned = out_size;
    return STATUS_SUCCESS;
}

NTSTATUS MyArkRedirectIoctlApply(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned)
{
    NTSTATUS                          status;
    PMYARK_REDIRECT_APPLY_INPUT       in_buf;
    size_t                            in_size = sizeof(MYARK_REDIRECT_APPLY_INPUT);

    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (InputBufferLength < in_size) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = MyArkIoctlFetchInputBuffer(Request, in_size, (PVOID*)&in_buf);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    UNREFERENCED_PARAMETER(in_buf);
    *BytesReturned = 0;
    return STATUS_NOT_IMPLEMENTED;
}

//
// SET_RULES (R2-9). Token-gated. Two-phase so the rule array is consumed
// before the output half of the shared METHOD_BUFFERED input is zeroed.
//
NTSTATUS MyArkRedirectIoctlSetRules(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned)
{
    NTSTATUS                            status;
    PMYARK_REDIRECT_SET_RULES_INPUT     in_buf;
    PMYARK_REDIRECT_SET_RULES_OUTPUT    out_buf;
    const MYARK_REDIRECT_RULE*          rules;
    UINT32                              count;
    UINT32                              flags;
    SIZE_T                              headerSize = sizeof(MYARK_REDIRECT_SET_RULES_INPUT)
                                                     - sizeof(MYARK_REDIRECT_RULE);

    UNREFERENCED_PARAMETER(Device);

    if (InputBufferLength < headerSize ||
        OutputBufferLength < sizeof(MYARK_REDIRECT_SET_RULES_OUTPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = MyArkIoctlFetchInputBuffer(Request, headerSize, (PVOID*)&in_buf);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Token before anything else; the caller's identity is part of the
    // signature so validation must run before rules are interpreted.
    //
    {
        NTSTATUS tokenStatus;

        tokenStatus = MyArkSafetyTokenValidate(&in_buf->Token,
                                               MYARK_REDIRECT_OP_SET_RULES,
                                               (UINT32)(UINT_PTR)PsGetCurrentProcessId());
        if (!NT_SUCCESS(tokenStatus)) {
            return STATUS_ACCESS_DENIED;
        }
    }

    count = in_buf->Count;
    flags = in_buf->Flags;

    //
    // Reject an input whose rule tail cannot fully exist; snapshotted
    // values only, then stage (which deep-copies out of the shared buffer).
    //
    if (count > 0) {
        SIZE_T tailBytes = (SIZE_T)count * sizeof(MYARK_REDIRECT_RULE);

        if (InputBufferLength - headerSize < tailBytes) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        rules = in_buf->Rules;
    } else {
        rules = NULL;
    }

    status = MyArkRedirectStageRules(rules, count, flags);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = MyArkIoctlFetchOutputBuffer(Request,
                                         sizeof(MYARK_REDIRECT_SET_RULES_OUTPUT),
                                         (PVOID*)&out_buf);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = MyArkRedirectCommitRules(&out_buf->Accepted,
                                      &out_buf->FileRules,
                                      &out_buf->RegRules);
    out_buf->Status = (UINT32)status;
    if (!NT_SUCCESS(status)) {
        return status;
    }

    *BytesReturned = sizeof(MYARK_REDIRECT_SET_RULES_OUTPUT);
    return STATUS_SUCCESS;
}

//
// QUERY_STATUS (R2-9). Read-only.
//
NTSTATUS MyArkRedirectIoctlQueryStatus(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned)
{
    NTSTATUS                            status;
    PMYARK_REDIRECT_STATUS_OUTPUT       out_buf;
    size_t                              out_size = sizeof(MYARK_REDIRECT_STATUS_OUTPUT);

    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(InputBufferLength);

    if (OutputBufferLength < out_size) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = MyArkIoctlFetchOutputBuffer(Request, out_size, (PVOID*)&out_buf);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    MyArkRedirectQueryStatus(out_buf);
    *BytesReturned = out_size;
    return STATUS_SUCCESS;
}

#endif // MYARK_MODULE_REDIRECT
