// MyArk CPU module: IOCTL handler (R3-14). Read-only snapshot, no token.

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "myark_config.h"
#include "cpu_internal.h"
#include "../../../shared/driver/MyArkPoolAlloc.h"

#if MYARK_MODULE_CPU

NTSTATUS
MyArkCpuIoctlSnapshot(
    _In_ WDFDEVICE  Device,
    _In_ WDFREQUEST Request,
    _In_ size_t     InputBufferLength,
    _In_ size_t     OutputBufferLength,
    _Out_ size_t*   BytesReturned)
{
    PMYARK_CPU_SNAPSHOT_OUTPUT outBuf = NULL;
    size_t outSize = 0;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(InputBufferLength);

    if (OutputBufferLength < sizeof(MYARK_CPU_SNAPSHOT_OUTPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = WdfRequestRetrieveOutputBuffer(Request,
                                            sizeof(MYARK_CPU_SNAPSHOT_OUTPUT),
                                            (PVOID*)&outBuf,
                                            &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // The IPI broadcast needs one stable nonpaged pointer shared by every
    // CPU simultaneously; the snapshot is then copied out once, after all
    // processors have returned, keeping its lifetime independent of the
    // request.
    {
        PMYARK_CPU_SNAPSHOT_OUTPUT snap =
            (PMYARK_CPU_SNAPSHOT_OUTPUT)MyArkAllocatePool(
                NonPagedPoolNx,
                sizeof(MYARK_CPU_SNAPSHOT_OUTPUT),
                'UPCm');
        if (snap == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        status = MyArkCpuCaptureSnapshot(snap);
        if (NT_SUCCESS(status)) {
            RtlCopyMemory(outBuf, snap, sizeof(*outBuf));
        }
        ExFreePoolWithTag(snap, 'UPCm');
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }

    *BytesReturned = sizeof(MYARK_CPU_SNAPSHOT_OUTPUT);
    return STATUS_SUCCESS;
}

#endif // MYARK_MODULE_CPU
