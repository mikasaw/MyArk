// mutation R0 IOCTL table + descriptor.

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "myark_config.h"
#include "module_descriptor.h"
#include "ioctl_registry.h"
#include "../../dispatch/ioctl_helpers.h"
#include "mutation_descriptor.h"
#include "mutation_internal.h"
#include "../../../shared/driver/MyArkMutationIoctl.h"

#if MYARK_MODULE_MUTATION

#define MYARK_TRACE_MUTATION "[mutation] "

static NTSTATUS MyArkMutationOnInit(VOID)
{
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
               MYARK_TRACE_MUTATION "init ok\n");
    return STATUS_SUCCESS;
}

static VOID MyArkMutationOnCleanup(VOID)
{
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
               MYARK_TRACE_MUTATION "cleanup ok\n");
}

MYARK_IOCTL_ENTRY g_MyArkMutationIoctlTable[] = {
    {
        IOCTL_MYARK_MUTATION_INSPECT_TOKEN,
        MyArkMutationIoctlInspectToken,
    },
    {
        IOCTL_MYARK_MUTATION_SET_TOKEN,
        MyArkMutationIoctlSetToken,
    },
    {
        IOCTL_MYARK_MUTATION_TX_PREPARE,
        MyArkMutationIoctlTxPrepare,
        "IOCTL_MYARK_MUTATION_TX_PREPARE",
        0,
        0
    },
    {
        IOCTL_MYARK_MUTATION_TX_COMMIT,
        MyArkMutationIoctlTxCommit,
        "IOCTL_MYARK_MUTATION_TX_COMMIT",
        0,
        0
    },
    {
        IOCTL_MYARK_MUTATION_TX_ROLLBACK,
        MyArkMutationIoctlTxRollback,
        "IOCTL_MYARK_MUTATION_TX_ROLLBACK",
        0,
        0
    },
    {
        IOCTL_MYARK_MUTATION_TX_LIST,
        MyArkMutationIoctlTxList,
        "IOCTL_MYARK_MUTATION_TX_LIST",
        0,
        0
    },
};

MYARK_MODULE_DESCRIPTOR g_MyArkModule_Mutation = {
    .ModuleName      = "mutation",
    .ModuleId        = MYARK_MUTATION_MODULE_ID,
    .Ioctls          = g_MyArkMutationIoctlTable,
    .IoctlCount      = ARRAYSIZE(g_MyArkMutationIoctlTable),
    .Init            = MyArkMutationOnInit,
    .Cleanup         = MyArkMutationOnCleanup,
};

NTSTATUS MyArkMutationInit(VOID)    {
    NTSTATUS txStatus = MyArkTxInit();
    UNREFERENCED_PARAMETER(txStatus);
 return MyArkMutationOnInit(); }
VOID     MyArkMutationCleanup(VOID)  { MyArkMutationOnCleanup(); }

#endif // MYARK_MODULE_MUTATION
