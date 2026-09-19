// mutation R0 IOCTL handlers.
//
// INSPECT_TOKEN - in S7.3 returns all-zero output stub (TokenFlags=0);
//                 EPROCESS.Token walk deferred to S7.x-fix.
// SET_TOKEN     - reserved; STATUS_NOT_IMPLEMENTED.

#include "mutation_descriptor.h"
#include "../../dispatch/ioctl_validation.h"
#include "../../../shared/driver/MyArkMutationIoctl.h"
#include "myark_config.h"
#include "../../dispatch/safety_token.h"
#include "mutation_internal.h"

#if MYARK_MODULE_MUTATION

NTSTATUS MyArkMutationIoctlInspectToken(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned)
{
    NTSTATUS                                status;
    PMYARK_MUTATION_INSPECT_TOKEN_INPUT     in_buf;
    PMYARK_MUTATION_INSPECT_TOKEN_OUTPUT    out_buf;
    size_t                                  in_size  = sizeof(MYARK_MUTATION_INSPECT_TOKEN_INPUT);
    size_t                                  out_size = sizeof(MYARK_MUTATION_INSPECT_TOKEN_OUTPUT);

    UNREFERENCED_PARAMETER(Device);

    if (InputBufferLength < in_size || OutputBufferLength < out_size) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = MyArkIoctlFetchInputBuffer(Request, in_size, (PVOID*)&in_buf, &in_size);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = MyArkIoctlFetchOutputBuffer(Request, out_size, (PVOID*)&out_buf, &out_size);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    UNREFERENCED_PARAMETER(in_buf);
    RtlZeroMemory(out_buf, out_size);

    *BytesReturned = out_size;
    return STATUS_SUCCESS;
}

NTSTATUS MyArkMutationIoctlSetToken(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned)
{
    NTSTATUS                          status;
    PMYARK_MUTATION_SET_TOKEN_INPUT   in_buf;
    size_t                            in_size = sizeof(MYARK_MUTATION_SET_TOKEN_INPUT);

    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (InputBufferLength < in_size) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = MyArkIoctlFetchInputBuffer(Request, in_size, (PVOID*)&in_buf, &in_size);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    UNREFERENCED_PARAMETER(in_buf);
    *BytesReturned = 0;
    return STATUS_NOT_IMPLEMENTED;
}


//
// TX_PREPARE (R3-8): SAFETY_TOKEN-gated. Stages ops + snapshots originals.
//
NTSTATUS
MyArkMutationIoctlTxPrepare(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    MYARK_MUTATION_TX_PREPARE_INPUT snap;
    PMYARK_MUTATION_TX_PREPARE_INPUT inBuf = NULL;
    PMYARK_MUTATION_TX_PREPARE_OUTPUT outBuf = NULL;
    size_t inSize = 0;
    size_t outSize = 0;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(Device);

    if (InputBufferLength < sizeof(MYARK_MUTATION_TX_PREPARE_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (OutputBufferLength < sizeof(MYARK_MUTATION_TX_PREPARE_OUTPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_MUTATION_TX_PREPARE_INPUT),
                                        (PVOID*)&inBuf, &inSize);
    if (!NT_SUCCESS(status)) return status;
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         sizeof(MYARK_MUTATION_TX_PREPARE_OUTPUT),
                                         (PVOID*)&outBuf, &outSize);
    if (!NT_SUCCESS(status)) return status;

    snap = *inBuf;
    RtlZeroMemory(outBuf, sizeof(*outBuf));

    status = MyArkSafetyTokenValidate(&snap.Token,
                                      MYARK_MUTATION_OP_TX_PREPARE,
                                      (UINT32)(UINT_PTR)PsGetCurrentProcessId());
    if (!NT_SUCCESS(status)) {
        return STATUS_ACCESS_DENIED;
    }
    if (snap.OpCount == 0 || snap.OpCount > MYARK_MUTATION_TX_MAX_OPS) {
        return STATUS_INVALID_PARAMETER;
    }

    UINT32 txToken = (UINT32)-1;
    UINT32 accepted = 0;
    status = MyArkTxPrepare(snap.OpCount, snap.Ops, &txToken, &accepted);
    outBuf->Status = (UINT32)status;
    outBuf->TxToken = txToken;
    outBuf->OpsAccepted = accepted;
    if (!NT_SUCCESS(status)) {
        return status;
    }

    *BytesReturned = sizeof(MYARK_MUTATION_TX_PREPARE_OUTPUT);
    return STATUS_SUCCESS;
}

//
// Shared COMMIT/ROLLBACK handler.
//
static
NTSTATUS
MyArkMutationIoctlTxExec(
    _In_ WDFREQUEST Request,
    _In_ UINT32 OpTokenValue,
    _In_ BOOLEAN IsCommit,
    _Out_ size_t* BytesReturned)
{
    MYARK_MUTATION_TX_EXEC_INPUT snap;
    PMYARK_MUTATION_TX_EXEC_INPUT inBuf = NULL;
    PMYARK_MUTATION_TX_EXEC_OUTPUT outBuf = NULL;
    size_t inSize = 0;
    size_t outSize = 0;
    NTSTATUS status;


    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(MYARK_MUTATION_TX_EXEC_INPUT),
                                        (PVOID*)&inBuf, &inSize);
    if (!NT_SUCCESS(status)) return status;
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         sizeof(MYARK_MUTATION_TX_EXEC_OUTPUT),
                                         (PVOID*)&outBuf, &outSize);
    if (!NT_SUCCESS(status)) return status;

    snap = *inBuf;
    RtlZeroMemory(outBuf, sizeof(*outBuf));

    status = MyArkSafetyTokenValidate(&snap.Token,
                                      OpTokenValue,
                                      (UINT32)(UINT_PTR)PsGetCurrentProcessId());
    if (!NT_SUCCESS(status)) {
        return STATUS_ACCESS_DENIED;
    }

    UINT32 applied = 0, failed = 0, txState = 0;
    if (IsCommit) {
        status = MyArkTxCommit(snap.TxToken, &applied, &failed, &txState);
    } else {
        status = MyArkTxRollback(snap.TxToken, &applied, &txState);
        failed = 0;
    }
    outBuf->Status = (UINT32)status;
    outBuf->OpsApplied = applied;
    outBuf->OpsFailed = failed;
    outBuf->TxState = txState;
    if (!NT_SUCCESS(status)) {
        return status;
    }

    *BytesReturned = sizeof(MYARK_MUTATION_TX_EXEC_OUTPUT);
    return STATUS_SUCCESS;
}

NTSTATUS
MyArkMutationIoctlTxCommit(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    UNREFERENCED_PARAMETER(Device);
    if (InputBufferLength < sizeof(MYARK_MUTATION_TX_EXEC_INPUT) ||
        OutputBufferLength < sizeof(MYARK_MUTATION_TX_EXEC_OUTPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    return MyArkMutationIoctlTxExec(Request,
                                    MYARK_MUTATION_OP_TX_COMMIT,
                                    TRUE, BytesReturned);
}

NTSTATUS
MyArkMutationIoctlTxRollback(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    UNREFERENCED_PARAMETER(Device);
    if (InputBufferLength < sizeof(MYARK_MUTATION_TX_EXEC_INPUT) ||
        OutputBufferLength < sizeof(MYARK_MUTATION_TX_EXEC_OUTPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    return MyArkMutationIoctlTxExec(Request,
                                    MYARK_MUTATION_OP_TX_ROLLBACK,
                                    FALSE, BytesReturned);
}

//
// TX_LIST (R3-8): read-only inventory.
//
NTSTATUS
MyArkMutationIoctlTxList(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    PVOID  outBuf = NULL;
    size_t outSize = 0;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(InputBufferLength);

    if (OutputBufferLength < sizeof(MYARK_MUTATION_TX_LIST_OUTPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchOutputBuffer(Request,
                                         sizeof(MYARK_MUTATION_TX_LIST_OUTPUT),
                                         &outBuf, &outSize);
    if (!NT_SUCCESS(status)) return status;

    status = MyArkTxList((PMYARK_MUTATION_TX_LIST_OUTPUT)outBuf);
    if (!NT_SUCCESS(status)) return status;

    *BytesReturned = sizeof(MYARK_MUTATION_TX_LIST_OUTPUT);
    return STATUS_SUCCESS;
}

#endif // MYARK_MODULE_MUTATION
