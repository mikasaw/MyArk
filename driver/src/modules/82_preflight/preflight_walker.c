// MyArk preflight module: shared internal helpers.

#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>
#include "Trace.h"
#include "module_registry.h"
#include "myark_config.h"
#include "../../../shared/driver/MyArkPreflightIoctl.h"
#include "preflight_descriptor.h"
#include "preflight_internal.h"

#if MYARK_MODULE_PREFLIGHT

#pragma warning(push)
#pragma warning(disable: 4201)

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
MyArkPreflightCollectKernelInfo(
    _Out_ PMYARK_PREFLIGHT_HEALTH_OUTPUT Out)
{
    if (Out == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Out, sizeof(*Out));

    //
    // OS version: prefer PsGetVersion (kernel-side); if it is not
    // available the R3 client will fill these via RtlGetVersion /
    // GetVersionEx.
    //
    ULONG major = 0, minor = 0;
    UNICODE_STRING name = {0};
    PsGetVersion(&major, &minor, NULL, NULL);
    Out->MajorVersion = major;
    Out->MinorVersion = minor;
    Out->BuildNumber  = 0;
    Out->Revision     = 0;
    UNREFERENCED_PARAMETER(name);

    //
    // Kernel base / size: not directly readable from kernel-mode
    // without MmGetSystemRoutineAddress tricks; leave 0 for the R3
    // client to fill via EnumDeviceDrivers.
    //
    Out->KernelBase = 0;
    Out->KernelSize = 0;

    //
    // Default Note.
    //
    RtlStringCchCopyW(Out->Note,
                      MYARK_PREFLIGHT_NOTE_MAX,
                      L"preflight: kernel-side scaffolding (R3 fills testsigning / Secure Boot)");

    return STATUS_SUCCESS;
}

#pragma warning(pop)

#endif // MYARK_MODULE_PREFLIGHT