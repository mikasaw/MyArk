// MyArk mutation module: internal types + transaction engine declarations.

#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "myark_config.h"
#include "../../../shared/driver/MyArkMutationIoctl.h"

#if MYARK_MODULE_MUTATION

#define MYARK_TRACE_MUTATION "[mutation] "

NTSTATUS
MyArkTxInit(VOID);

NTSTATUS
MyArkTxPrepare(
    _In_ UINT32 OpCount,
    _In_ PMYARK_MUTATION_TX_OP_SPEC Specs,
    _Out_ PUINT32 TxTokenOut,
    _Out_ PUINT32 OpsAcceptedOut);

NTSTATUS
MyArkTxCommit(
    _In_ UINT32 TxToken,
    _Out_ PUINT32 OpsAppliedOut,
    _Out_ PUINT32 OpsFailedOut,
    _Out_ PUINT32 TxStateOut);

NTSTATUS
MyArkTxRollback(
    _In_ UINT32 TxToken,
    _Out_ PUINT32 OpsRolledBackOut,
    _Out_ PUINT32 TxStateOut);

NTSTATUS
MyArkTxList(
    _Out_ PMYARK_MUTATION_TX_LIST_OUTPUT Output);

#endif // MYARK_MODULE_MUTATION
