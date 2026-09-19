// MyArk actions module: descriptor + IOCTL table.
//
// S8.1 + R3-2 -- 8 IOCTLs for mixed (R0 + R3 fallback) actions: kill process,
// terminate thread, inject DLL, dump memory, set token, hide process,
// protect process. Every dispatch requires the caller to ship a
// MYARK_SAFETY_TOKEN as the prefix of the input buffer; the safety
// check lives in actions_internal.c.
//
// All 8 IOCTLs use the MyArk METHOD_BUFFERED convention with
// FILE_ANY_ACCESS so any process can open the device; the token + the
// required-step gate (86_safety) carry the authorization payload.
//
// The descriptor symbol participates in the global g_AllModules[]
// table (see driver/src/module/module_registry.c) when
// MYARK_MODULE_ACTIONS is enabled in the active build profile.

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "myark_config.h"
#include "module_descriptor.h"
#include "ioctl_registry.h"
#include "../../../shared/driver/MyArkActionsIoctl.h"
#include "actions_descriptor.h"
#include "actions_internal.h"

#if MYARK_MODULE_ACTIONS

//
// The actions IOCTL table. Static array so the address range stays in
// this translation unit; g_AllModules[] points at the descriptor which
// points at this array.
//
NTSTATUS
MyArkActionsIoctlInjectShellcode(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned);

static MYARK_IOCTL_ENTRY g_ActionsIoctls[] = {
    {
        IOCTL_MYARK_ACTION_KILL_PROCESS,
        MyArkActionsIoctlKillProcess,
        "IOCTL_MYARK_ACTION_KILL_PROCESS",
        0,
        0
    },
    {
        IOCTL_MYARK_ACTION_TERMINATE_THREAD,
        MyArkActionsIoctlTerminateThread,
        "IOCTL_MYARK_ACTION_TERMINATE_THREAD",
        0,
        0
    },
    {
        IOCTL_MYARK_ACTION_INJECT_DLL,
        MyArkActionsIoctlInjectDll,
        "IOCTL_MYARK_ACTION_INJECT_DLL",
        0,
        0
    },
    {
        IOCTL_MYARK_ACTION_DUMP_MEMORY,
        MyArkActionsIoctlDumpMemory,
        "IOCTL_MYARK_ACTION_DUMP_MEMORY",
        0,
        0
    },
    {
        IOCTL_MYARK_ACTION_SET_TOKEN,
        MyArkActionsIoctlSetToken,
        "IOCTL_MYARK_ACTION_SET_TOKEN",
        0,
        0
    },
    {
        IOCTL_MYARK_ACTION_HIDE_PROCESS,
        MyArkActionsIoctlHideProcess,
        "IOCTL_MYARK_ACTION_HIDE_PROCESS",
        0,
        0
    },
    {
        IOCTL_MYARK_ACTION_PROTECT_PROCESS,
        MyArkActionsIoctlProtectProcess,
        "IOCTL_MYARK_ACTION_PROTECT_PROCESS",
        0,
        0
    },
    {
        IOCTL_MYARK_ACTION_INJECT_SHELLCODE,
        MyArkActionsIoctlInjectShellcode,
        "IOCTL_MYARK_ACTION_INJECT_SHELLCODE",
        0,
        0
    },
};

//
// Module descriptor wired into g_AllModules[] (see module_registry.c).
//
MYARK_MODULE_DESCRIPTOR g_MyArkModule_Actions = {
    "actions",                                       // ModuleName
    "Actions - 7 mixed (R0+R3 fallback) action IOCTLs (kill/terminate/inject/dump/set-token/hide/protect)",
    MYARK_ACTIONS_MODULE_ID,                         // ModuleId ('ACTN')
    RTL_NUMBER_OF(g_ActionsIoctls),                  // IoctlCount
    g_ActionsIoctls,                                 // Ioctls
    MyArkActionsInit,                                // Init
    MyArkActionsCleanup,                             // Cleanup
    FALSE                                            // Initialized (set by loader)
};

NTSTATUS
MyArkActionsInit(
    VOID)
{
    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_ACTIONS,
                "MyArkActionsInit: actions module linked (%lu IOCTLs)",
                (unsigned long)g_MyArkModule_Actions.IoctlCount);
    return STATUS_SUCCESS;
}

VOID
MyArkActionsCleanup(
    VOID)
{
    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_ACTIONS,
                "MyArkActionsCleanup: actions module torn down");
}

#endif // MYARK_MODULE_ACTIONS
