// MyArk Core Driver: default I/O queue callbacks.
//
// The queue itself is created in device_control.c together with the control
// device; this file provides the per-request callbacks that the queue uses.
// EvtIoDeviceControl lives in ioctl_dispatch.c (MyArkCoreEvtIoDeviceControl)
// -- this file owns Read and Write which the ARK interface does not yet
// use. We log every Read so the kernel debugger can confirm the device is
// wired up; Writes are rejected.

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"

VOID
MyArkCoreEvtIoRead(
    _In_ WDFQUEUE   Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t     Length)
{
    UNREFERENCED_PARAMETER(Queue);
    UNREFERENCED_PARAMETER(Length);

    TraceEvents(TRACE_LEVEL_VERBOSE,
                MYARK_TRACE_QUEUE,
                "MyArkCoreEvtIoRead (Length=%zu, no data path yet)",
                Length);

    WdfRequestComplete(Request, STATUS_NOT_SUPPORTED);
}

VOID
MyArkCoreEvtIoWrite(
    _In_ WDFQUEUE   Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t     Length)
{
    UNREFERENCED_PARAMETER(Queue);
    UNREFERENCED_PARAMETER(Length);

    TraceEvents(TRACE_LEVEL_VERBOSE,
                MYARK_TRACE_QUEUE,
                "MyArkCoreEvtIoWrite (Length=%zu, no data path yet)",
                Length);

    WdfRequestComplete(Request, STATUS_NOT_SUPPORTED);
}