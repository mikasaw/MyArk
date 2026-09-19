// MyArk capability module: IOCTL handlers.

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "myark_config.h"
#include "ioctl_validation.h"
#include "../../../shared/driver/MyArkCapabilityIoctl.h"
#include "capability_descriptor.h"
#include "capability_internal.h"

#if MYARK_MODULE_CAPABILITY

#include "module_registry.h"

//
// REPORT: emit the live capability table. The driver walks
// g_AllModules[] (populated by the linker) and copies every descriptor
// into the caller's output buffer, capped at MYARK_CAPABILITY_HARD_CAP.
//
NTSTATUS
MyArkCapabilityIoctlReport(
    _In_  WDFDEVICE   Device,
    _In_  WDFREQUEST  Request,
    _In_  size_t      InputBufferLength,
    _In_  size_t      OutputBufferLength,
    _Out_ size_t*     BytesReturned)
{
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(InputBufferLength);

    NTSTATUS                                  status;
    PVOID                                     outBuf = NULL;
    size_t                                    outSize = 0;

    status = MyArkIoctlFetchOutputBuffer(Request,
                                         FIELD_OFFSET(MYARK_CAPABILITY_REPORT_OUTPUT, Entries[0]),
                                         &outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    PMYARK_CAPABILITY_REPORT_OUTPUT out = (PMYARK_CAPABILITY_REPORT_OUTPUT)outBuf;
    RtlZeroMemory(out,
                  FIELD_OFFSET(MYARK_CAPABILITY_REPORT_OUTPUT, Entries[0]));

    ULONG  maxEntries = (ULONG)((OutputBufferLength
                                 - FIELD_OFFSET(MYARK_CAPABILITY_REPORT_OUTPUT, Entries[0]))
                                / sizeof(MYARK_CAPABILITY_MODULE_ENTRY));
    if (maxEntries > MYARK_CAPABILITY_HARD_CAP) {
        maxEntries = MYARK_CAPABILITY_HARD_CAP;
    }

    UINT32 moduleCount = g_ModuleCount;
    UINT32 totalIoctls = 0;
    UINT32 emitted = 0;

    for (UINT32 i = 0; i < moduleCount && emitted < maxEntries; i++) {
        PMYARK_MODULE_DESCRIPTOR module = g_AllModules[i];
        if (module == NULL) {
            continue;
        }
        MyArkCapabilityEmitOne(&out->Entries[emitted], module, i);
        totalIoctls += module->IoctlCount;
        emitted++;
    }

    out->DriverVersionMajor = 7;
    out->DriverVersionMinor = 3;
    out->DriverVersionBuild = 0;
    out->Reserved          = 0;
    out->TotalModules     = moduleCount;
    out->TotalIoctls      = totalIoctls;
    out->Reserved2        = 0;
    out->Reserved3        = 0;

    *BytesReturned = FIELD_OFFSET(MYARK_CAPABILITY_REPORT_OUTPUT, Entries[0])
                     + (size_t)emitted * sizeof(MYARK_CAPABILITY_MODULE_ENTRY);
    return STATUS_SUCCESS;
}

#endif // MYARK_MODULE_CAPABILITY