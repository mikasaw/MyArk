// MyArk Core Driver: EvtIoDeviceControl handler that fans out to the
// registered IOCTL table.

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "ioctl_registry.h"

VOID
MyArkCoreEvtIoDeviceControl(
    _In_ WDFQUEUE   Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t     OutputBufferLength,
    _In_ size_t     InputBufferLength,
    _In_ ULONG      IoControlCode)
{
    PMYARK_IOCTL_ENTRY  entry        = NULL;
    NTSTATUS            status       = STATUS_NOT_SUPPORTED;
    size_t              bytesReturned = 0;
    BOOLEAN             quietSuccess  = FALSE;

    UNREFERENCED_PARAMETER(Queue);

    entry = MyArkIoctlFind(IoControlCode);
    if (entry == NULL) {
        TraceEvents(TRACE_LEVEL_WARNING,
                    MYARK_TRACE_DISPATCH,
                    "EvtIoDeviceControl: unregistered IOCTL 0x%08lX",
                    IoControlCode);
        WdfRequestComplete(Request, STATUS_INVALID_DEVICE_REQUEST);
        return;
    }

    //
    // Capability gate (S7 will wire real capability tokens). Today every entry
    // is gated by RequiredCapability == 0 which always passes.
    //
    if (entry->RequiredCapability != 0) {
        TraceEvents(TRACE_LEVEL_WARNING,
                    MYARK_TRACE_DISPATCH,
                    "EvtIoDeviceControl: %s requires capability 0x%08lX (denied)",
                    entry->Name ? entry->Name : "?",
                    entry->RequiredCapability);
        WdfRequestComplete(Request, STATUS_ACCESS_DENIED);
        return;
    }

    status = entry->Handler(NULL,
                            Request,
                            InputBufferLength,
                            OutputBufferLength,
                            &bytesReturned);

    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_WARNING,
                    MYARK_TRACE_DISPATCH,
                    "EvtIoDeviceControl: %s failed 0x%08X",
                    entry->Name ? entry->Name : "?", status);
        WdfRequestComplete(Request, status);
        return;
    }

    if ((entry->Flags & MYARK_IOCTL_FLAG_QUIET_SUCCESS) == 0) {
        TraceEvents(TRACE_LEVEL_INFORMATION,
                    MYARK_TRACE_DISPATCH,
                    "EvtIoDeviceControl: %s -> 0x%08X (%zu bytes)",
                    entry->Name ? entry->Name : "?", status, bytesReturned);
    }
    quietSuccess = (entry->Flags & MYARK_IOCTL_FLAG_QUIET_SUCCESS) != 0;
    UNREFERENCED_PARAMETER(quietSuccess);

    WdfRequestCompleteWithInformation(Request, status, bytesReturned);
}