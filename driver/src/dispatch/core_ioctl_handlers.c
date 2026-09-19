// MyArk Core Driver: implementation of the five core IOCTL handlers.

#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>
#include "Trace.h"
#include "ioctl_registry.h"
#include "ioctl_validation.h"
#include "module_registry.h"
#include "MyArkCoreIoctl.h"
#include "core_ioctl_handlers.h"
#include "safety_token.h"

//
// Copy a fixed-size ANSI string into a CHAR[] field, NUL-terminating and
// padding with zeros. Fits inside the MyArkCoreIoctlQueryModules path so we
// avoid pulling in RtlStringCbCopyA and SAL warnings on nullable inputs.
//
static
VOID
MyArkCoreCopyAnsiField(
    _Out_writes_bytes_(DestSize) PCHAR Dest,
    _In_ size_t DestSize,
    _In_opt_ PCSTR Source)
{
    ULONG i;

    if (Dest == NULL || DestSize == 0) {
        return;
    }

    RtlZeroMemory(Dest, DestSize);

    if (Source == NULL) {
        return;
    }

    for (i = 0; i + 1 < DestSize && Source[i] != '\0'; i++) {
        Dest[i] = Source[i];
    }
    Dest[i] = '\0';
}

static
UINT32
MyArkCoreCountEnabledModules(
    VOID)
{
    UINT32 enabled = 0;

    for (UINT32 i = 0; i < g_ModuleCount; i++) {
        PMYARK_MODULE_DESCRIPTOR module = g_AllModules[i];
        if (module != NULL) {
            enabled++;
        }
    }
    return enabled;
}

NTSTATUS
MyArkCoreIoctlGetVersion(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned)
{
    PMYARK_CORE_VERSION_OUTPUT out = NULL;
    size_t                      outSize = 0;
    NTSTATUS                    status;

    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    status = MyArkIoctlFetchOutputBuffer(Request,
                                         sizeof(MYARK_CORE_VERSION_OUTPUT),
                                         (PVOID*)&out,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlZeroMemory(out, sizeof(*out));
    out->Size                 = sizeof(*out);
    out->CoreProtocolVersion  = MYARK_CORE_PROTOCOL_VERSION;
    out->ModuleProtocolVersion = 1;
    out->BuildNumber          = MYARK_CORE_DRIVER_BUILD_NUMBER;
    out->ActiveModuleCount    = MyArkCoreCountEnabledModules();
    RtlStringCchCopyW(out->DisplayName,
                      RTL_NUMBER_OF(out->DisplayName),
                      MYARK_CORE_DISPLAY_NAME);

    *BytesReturned = sizeof(*out);

    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_DISPATCH,
                "GetVersion: protocol=%lu modules=%lu",
                out->CoreProtocolVersion,
                out->ActiveModuleCount);

    return STATUS_SUCCESS;
}

NTSTATUS
MyArkCoreIoctlQueryModules(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned)
{
    PMYARK_CORE_MODULE_LIST_OUTPUT list = NULL;
    size_t                         headerSize;
    size_t                         needed;
    NTSTATUS                       status;

    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(InputBufferLength);

    headerSize = FIELD_OFFSET(MYARK_CORE_MODULE_LIST_OUTPUT, Modules[0]);
    needed     = headerSize + (size_t)g_ModuleCount * sizeof(MYARK_CORE_MODULE_INFO);

    status = MyArkIoctlFetchOutputBuffer(Request, needed, (PVOID*)&list, &OutputBufferLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlZeroMemory(list, needed);
    list->Size  = (UINT32)needed;
    list->Count = g_ModuleCount;

    for (UINT32 i = 0; i < g_ModuleCount; i++) {
        PMYARK_MODULE_DESCRIPTOR  module = g_AllModules[i];
        PMYARK_CORE_MODULE_INFO   entry  = &list->Modules[i];

        if (module == NULL) {
            continue;
        }

        entry->ModuleId = module->ModuleId;
        MyArkCoreCopyAnsiField(entry->ModuleName,
                               sizeof(entry->ModuleName),
                               module->ModuleName);
        MyArkCoreCopyAnsiField(entry->ModuleDescription,
                               sizeof(entry->ModuleDescription),
                               module->ModuleDescription);
        entry->State     = module->Initialized
                            ? MYARK_MODULE_STATE_ENABLED
                            : MYARK_MODULE_STATE_DISABLED;
        entry->IoctlCount = module->IoctlCount;
        entry->LastError  = module->Initialized
                            ? STATUS_SUCCESS
                            : STATUS_NO_SUCH_DEVICE;
    }

    *BytesReturned = needed;

    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_DISPATCH,
                "QueryModules: count=%lu bytes=%zu",
                (unsigned long)list->Count, needed);

    return STATUS_SUCCESS;
}

NTSTATUS
MyArkCoreIoctlQueryCapabilities(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned)
{
    PMYARK_CORE_CAPABILITY_OUTPUT caps = NULL;
    size_t                         headerSize;
    size_t                         needed;
    NTSTATUS                       status;
    UINT32                         outIndex = 0;

    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(InputBufferLength);

    headerSize = FIELD_OFFSET(MYARK_CORE_CAPABILITY_OUTPUT, Entries[0]);
    needed     = headerSize + (size_t)g_IoctlCount * sizeof(MYARK_CORE_CAPABILITY_ENTRY);

    status = MyArkIoctlFetchOutputBuffer(Request, needed, (PVOID*)&caps, &OutputBufferLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlZeroMemory(caps, needed);
    caps->Size  = (UINT32)needed;
    caps->Count = g_IoctlCount;

    for (UINT32 i = 0; i < g_IoctlCount; i++) {
        PMYARK_IOCTL_ENTRY             src = &g_IoctlTable[i];
        PMYARK_CORE_CAPABILITY_ENTRY   dst = &caps->Entries[outIndex];
        UINT32                         moduleId = 0;
        PCSTR                          name;

        //
        // Reverse-lookup module id by scanning the module table for one
        // whose Ioctls[] points to (or just past) this entry. The descriptor
        // contract guarantees Ioctls[] is a contiguous array stored in the
        // same order the module pushed them; we just walk it linearly.
        //
        for (UINT32 m = 0; m < g_ModuleCount; m++) {
            PMYARK_MODULE_DESCRIPTOR module = g_AllModules[m];
            if (module == NULL || module->Ioctls == NULL || module->IoctlCount == 0) {
                continue;
            }
            if ((ULONG_PTR)src >= (ULONG_PTR)&module->Ioctls[0] &&
                (ULONG_PTR)src <  (ULONG_PTR)&module->Ioctls[module->IoctlCount]) {
                moduleId = module->ModuleId;
                break;
            }
        }

        dst->IoctlCode = src->IoctlCode;
        dst->ModuleId  = moduleId;
        name = src->Name ? src->Name : "UNKNOWN";
        MyArkCoreCopyAnsiField(dst->Name, sizeof(dst->Name), name);
        outIndex++;
    }

    *BytesReturned = needed;

    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_DISPATCH,
                "QueryCapabilities: count=%lu bytes=%zu",
                (unsigned long)caps->Count, needed);

    return STATUS_SUCCESS;
}

NTSTATUS
MyArkCoreIoctlGetLog(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned)
{
    PMYARK_CORE_LOG_OUTPUT log = NULL;
    size_t                 headerSize;

    UNREFERENCED_PARAMETER(Device);

    headerSize = FIELD_OFFSET(MYARK_CORE_LOG_OUTPUT, Records[0]);

    //
    // Kernel log ring lands in S6. For now return an empty list when the
    // caller's buffer is large enough for the header.
    //
    if (OutputBufferLength < headerSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (InputBufferLength != 0 && InputBufferLength < sizeof(MYARK_CORE_LOG_INPUT)) {
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS status = MyArkIoctlFetchOutputBuffer(Request,
                                                  headerSize,
                                                  (PVOID*)&log,
                                                  &OutputBufferLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlZeroMemory(log, headerSize);
    log->Size  = (UINT32)headerSize;
    log->Count = 0;

    *BytesReturned = headerSize;

    TraceEvents(TRACE_LEVEL_VERBOSE,
                MYARK_TRACE_DISPATCH,
                "GetLog: stub return (S6 will populate)");

    return STATUS_SUCCESS;
}

NTSTATUS
MyArkCoreIoctlSetLogConfig(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned)
{
    UNREFERENCED_PARAMETER(Device);

    if (InputBufferLength < sizeof(MYARK_CORE_LOG_CONFIG)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (OutputBufferLength < sizeof(MYARK_CORE_LOG_CONFIG)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    //
    // Mirror the request into the output buffer so callers can confirm what
    // the driver accepted; S6 will replace this with real config storage.
    //
    PMYARK_CORE_LOG_CONFIG cfg = NULL;
    size_t                 cb   = 0;

    NTSTATUS status = MyArkIoctlFetchOutputBuffer(Request,
                                                  sizeof(*cfg),
                                                  (PVOID*)&cfg,
                                                  &cb);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    PMYARK_CORE_LOG_CONFIG in = NULL;
    size_t                 inSize = 0;
    status = MyArkIoctlFetchInputBuffer(Request,
                                        sizeof(*in),
                                        (PVOID*)&in,
                                        &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    *cfg = *in;
    *BytesReturned = sizeof(*cfg);

    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_DISPATCH,
                "SetLogConfig: enabled=%lu level=%lu",
                (unsigned long)in->Enabled,
                (unsigned long)in->Level);

    return STATUS_SUCCESS;
}

NTSTATUS
MyArkCoreIoctlGetSessionKey(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned)
{
    PMYARK_CORE_SESSION_KEY_OUTPUT out = NULL;
    size_t                         outSize = 0;
    NTSTATUS                       status;

    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    status = MyArkIoctlFetchOutputBuffer(Request,
                                         sizeof(MYARK_CORE_SESSION_KEY_OUTPUT),
                                         (PVOID*)&out,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlZeroMemory(out, sizeof(*out));

    status = MyArkSafetyTokenGetSessionKey(out->Key);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    out->Size      = sizeof(*out);
    out->KeyLength = MYARK_SAFETY_TOKEN_KEY_SIZE;
    *BytesReturned = sizeof(*out);

    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_DISPATCH,
                "GetSessionKey: served %u bytes",
                (unsigned long)out->KeyLength);

    return STATUS_SUCCESS;
}

NTSTATUS
MyArkIoctlRegistryInitCore(
    VOID)
{
    static MYARK_IOCTL_ENTRY coreEntries[] = {
        {
            IOCTL_MYARK_CORE_GET_VERSION,
            MyArkCoreIoctlGetVersion,
            "IOCTL_MYARK_CORE_GET_VERSION",
            0,
            0
        },
        {
            IOCTL_MYARK_CORE_QUERY_MODULES,
            MyArkCoreIoctlQueryModules,
            "IOCTL_MYARK_CORE_QUERY_MODULES",
            0,
            0
        },
        {
            IOCTL_MYARK_CORE_QUERY_CAPABILITIES,
            MyArkCoreIoctlQueryCapabilities,
            "IOCTL_MYARK_CORE_QUERY_CAPABILITIES",
            0,
            0
        },
        {
            IOCTL_MYARK_CORE_GET_LOG,
            MyArkCoreIoctlGetLog,
            "IOCTL_MYARK_CORE_GET_LOG",
            0,
            MYARK_IOCTL_FLAG_QUIET_SUCCESS
        },
        {
            IOCTL_MYARK_CORE_SET_LOG_CONFIG,
            MyArkCoreIoctlSetLogConfig,
            "IOCTL_MYARK_CORE_SET_LOG_CONFIG",
            0,
            MYARK_IOCTL_FLAG_QUIET_SUCCESS
        },
        {
            IOCTL_MYARK_CORE_GET_SESSION_KEY,
            MyArkCoreIoctlGetSessionKey,
            "IOCTL_MYARK_CORE_GET_SESSION_KEY",
            0,
            MYARK_IOCTL_FLAG_QUIET_SUCCESS
        }
    };

    NTSTATUS status = MyArkIoctlRegistryAdd(coreEntries,
                                            RTL_NUMBER_OF(coreEntries));
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR,
                    MYARK_TRACE_DISPATCH,
                    "MyArkIoctlRegistryInitCore failed: 0x%08X",
                    status);
    }
    return status;
}