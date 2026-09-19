// MyArk callback module: descriptor + IOCTL table.
//
// S7.2 -- read-only inspection surface for the 5 Windows kernel callback
// registration arrays (Ps / Cm / Ob / Image / Dbg). 12 IOCTLs total, of
// which 9 are read-only and 1 (STATS) is a pure aggregate; the REMOVE /
// RESTORE / BACKUP IOCTLs are reserved for the S7.2-fix stage and return
// STATUS_NOT_IMPLEMENTED on every dispatch.
//
// All 12 IOCTLs use the MyArk METHOD_BUFFERED convention. The descriptor
// symbol participates in the global g_AllModules[] table (see
// driver/src/module/module_registry.c) when MYARK_MODULE_CALLBACK is
// enabled in the active build profile.

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "myark_config.h"
#include "module_descriptor.h"
#include "ioctl_registry.h"
#include "../../../shared/driver/MyArkCallbackIoctl.h"
#include "callback_descriptor.h"
#include "callback_internal.h"

#if MYARK_MODULE_CALLBACK

//
// The callback IOCTL table. Static array so the address range stays in this
// translation unit; g_AllModules[] points at the descriptor which points
// at this array.
//
NTSTATUS
MyArkCallbackIoctlSetRules(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned);

NTSTATUS
MyArkCallbackIoctlRuntimeState(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned);

NTSTATUS
MyArkCallbackIoctlAskWait(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned);

NTSTATUS
MyArkCallbackIoctlAskAnswer(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned);

NTSTATUS
MyArkCallbackIoctlAskCancel(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned);

static MYARK_IOCTL_ENTRY g_CallbackIoctls[] = {
    {
        IOCTL_MYARK_CALLBACK_QUERY_PS,
        MyArkCallbackIoctlQueryPs,
        "IOCTL_MYARK_CALLBACK_QUERY_PS",
        0,
        0
    },
    {
        IOCTL_MYARK_CALLBACK_QUERY_CM,
        MyArkCallbackIoctlQueryCm,
        "IOCTL_MYARK_CALLBACK_QUERY_CM",
        0,
        0
    },
    {
        IOCTL_MYARK_CALLBACK_QUERY_OB,
        MyArkCallbackIoctlQueryOb,
        "IOCTL_MYARK_CALLBACK_QUERY_OB",
        0,
        0
    },
    {
        IOCTL_MYARK_CALLBACK_QUERY_IMAGE,
        MyArkCallbackIoctlQueryImage,
        "IOCTL_MYARK_CALLBACK_QUERY_IMAGE",
        0,
        0
    },
    {
        IOCTL_MYARK_CALLBACK_QUERY_DBG,
        MyArkCallbackIoctlQueryDbg,
        "IOCTL_MYARK_CALLBACK_QUERY_DBG",
        0,
        0
    },
    {
        IOCTL_MYARK_CALLBACK_ENUMERATE,
        MyArkCallbackIoctlEnumerate,
        "IOCTL_MYARK_CALLBACK_ENUMERATE",
        0,
        0
    },
    {
        IOCTL_MYARK_CALLBACK_REMOVE,
        MyArkCallbackIoctlRemove,
        "IOCTL_MYARK_CALLBACK_REMOVE",
        0,
        0
    },
    {
        IOCTL_MYARK_CALLBACK_RESTORE,
        MyArkCallbackIoctlRestore,
        "IOCTL_MYARK_CALLBACK_RESTORE",
        0,
        0
    },
    {
        IOCTL_MYARK_CALLBACK_BACKUP,
        MyArkCallbackIoctlBackup,
        "IOCTL_MYARK_CALLBACK_BACKUP",
        0,
        0
    },
    {
        IOCTL_MYARK_CALLBACK_STATS,
        MyArkCallbackIoctlStats,
        "IOCTL_MYARK_CALLBACK_STATS",
        0,
        0
    },
    {
        IOCTL_MYARK_CALLBACK_SET_RULES,
        MyArkCallbackIoctlSetRules,
        "IOCTL_MYARK_CALLBACK_SET_RULES",
        0,
        0
    },
    {
        IOCTL_MYARK_CALLBACK_RUNTIME_STATE,
        MyArkCallbackIoctlRuntimeState,
        "IOCTL_MYARK_CALLBACK_RUNTIME_STATE",
        0,
        0
    },
    {
        IOCTL_MYARK_CALLBACK_ASK_WAIT,
        MyArkCallbackIoctlAskWait,
        "IOCTL_MYARK_CALLBACK_ASK_WAIT",
        0,
        0
    },
    {
        IOCTL_MYARK_CALLBACK_ASK_ANSWER,
        MyArkCallbackIoctlAskAnswer,
        "IOCTL_MYARK_CALLBACK_ASK_ANSWER",
        0,
        0
    },
    {
        IOCTL_MYARK_CALLBACK_ASK_CANCEL,
        MyArkCallbackIoctlAskCancel,
        "IOCTL_MYARK_CALLBACK_ASK_CANCEL",
        0,
        0
    },
    {
        IOCTL_MYARK_CALLBACK_OB_PROTECT_SET,
        MyArkCallbackIoctlObProtectSet,
        "IOCTL_MYARK_CALLBACK_OB_PROTECT_SET",
        0,
        0
    },
    {
        IOCTL_MYARK_CALLBACK_OB_PROTECT_STATUS,
        MyArkCallbackIoctlObProtectStatus,
        "IOCTL_MYARK_CALLBACK_OB_PROTECT_STATUS",
        0,
        0
    },
};

//
// Module descriptor wired into g_AllModules[] (see module_registry.c).
//
MYARK_MODULE_DESCRIPTOR g_MyArkModule_Callback = {
    "callback",                                       // ModuleName
    "Callback - Ps/Cm/Ob/Image/Dbg inspection + process-create rule engine (17 IOCTLs)",
    MYARK_CALLBACK_MODULE_ID,                         // ModuleId ('CBLK')
    RTL_NUMBER_OF(g_CallbackIoctls),                  // IoctlCount
    g_CallbackIoctls,                                 // Ioctls
    MyArkCallbackInit,                                // Init
    MyArkCallbackCleanup,                             // Cleanup
    FALSE                                             // Initialized (set by loader)
};

NTSTATUS
MyArkCallbackInit(
    VOID)
{
    NTSTATUS status = MyArkCallbackPagetableResolveAll();
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_WARNING,
                    MYARK_TRACE_CALLBACK,
                    "MyArkCallbackInit: pagetable resolve partial (status 0x%08X); IOCTLs will report empty results until resolved",
                    status);
    }

    status = MyArkRulesInit();
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR,
                    MYARK_TRACE_CALLBACK,
                    "MyArkCallbackInit: process-notify registration failed 0x%08X",
                    status);
        return status;
    }

    status = MyArkObProtInit();
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR,
                    MYARK_TRACE_CALLBACK,
                    "MyArkCallbackInit: ObProt init failed 0x%08X",
                    status);
        return status;
    }
    // Arms at init: the PID list starts empty so no pre-op will strip
    // anything, but the ObCallbacks infrastructure is active from this point.
    status = MyArkObProtArm();
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_WARNING,
                    MYARK_TRACE_CALLBACK,
                    "MyArkCallbackInit: ObRegisterCallbacks failed 0x%08X "
                    "(stripping unavailable, list still maintained)",
                    status);
        // Non-fatal: the PID list still works, stripping just isn't active.
        status = STATUS_SUCCESS;
    }

    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_CALLBACK,
                "MyArkCallbackInit: callback module linked (%lu IOCTLs)",
                (unsigned long)g_MyArkModule_Callback.IoctlCount);

    return STATUS_SUCCESS;
}

VOID
MyArkCallbackCleanup(
    VOID)
{
    MyArkObProtDisarm();
    MyArkRulesCleanup();
    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_CALLBACK,
                "MyArkCallbackCleanup: callback module torn down");
}

#endif // MYARK_MODULE_CALLBACK