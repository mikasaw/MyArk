// MyArk capability module: shared internal helpers.

#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>
#include "Trace.h"
#include "module_descriptor.h"
#include "module_registry.h"
#include "myark_config.h"
#include "../../../shared/driver/MyArkCapabilityIoctl.h"
#include "capability_descriptor.h"
#include "capability_internal.h"

#if MYARK_MODULE_CAPABILITY

#pragma warning(push)
#pragma warning(disable: 4201 4244)

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
MyArkCapabilityCopyModuleName(
    _Out_writes_(MYARK_CAPABILITY_NAME_MAX) PWCHAR  Destination,
    _In_                                      PCSTR  Source)
{
    NTSTATUS  status;
    size_t    converted = 0;

    if (Destination == NULL) {
        return;
    }
    RtlZeroMemory(Destination, MYARK_CAPABILITY_NAME_MAX * sizeof(WCHAR));
    if (Source == NULL) {
        return;
    }
    status = RtlStringCchCopyNW(Destination,
                                 MYARK_CAPABILITY_NAME_MAX,
                                 (PCWCH)Source,
                                 (size_t)(strlen(Source)));
    if (!NT_SUCCESS(status)) {
        //
        // Truncation: leave the destination zero-terminated and fall
        // through. RtlStringCchCopyNW guarantees NUL termination on
        // truncation per its contract.
        //
    }
    UNREFERENCED_PARAMETER(converted);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
MyArkCapabilityEmitOne(
    _Out_writes_(MYARK_CAPABILITY_HARD_CAP) PMYARK_CAPABILITY_MODULE_ENTRY Destination,
    _In_                                     PMYARK_MODULE_DESCRIPTOR       Source,
    _In_                                     UINT32                          Index)
{
    if (Destination == NULL || Source == NULL) {
        return;
    }
    RtlZeroMemory(Destination, sizeof(*Destination));
    Destination->ModuleId   = Source->ModuleId;
    Destination->IoctlCount = Source->IoctlCount;
    Destination->Flags      = MYARK_CAPABILITY_FLAG_R0 | MYARK_CAPABILITY_FLAG_ENABLED;
    Destination->Reserved   = 0;
    MyArkCapabilityCopyModuleName(Destination->ModuleName, Source->ModuleName);
    UNREFERENCED_PARAMETER(Index);
}

#pragma warning(pop)

#endif // MYARK_MODULE_CAPABILITY