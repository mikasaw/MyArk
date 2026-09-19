// win32k R0 IOCTL handlers.
//
// ENUMERATE_GUI_THREADS - R0 read-only; in S7.3 returns Count=0 stub.
// ENUMERATE_HOOKS       - R0 read-only; in S7.3 returns Count=0 stub.

#include "win32k_descriptor.h"
#include "../../dispatch/ioctl_helpers.h"
#include "../../../shared/driver/MyArkWin32kIoctl.h"
#include "myark_config.h"

#if MYARK_MODULE_WIN32K

static NTSTATUS MyArkWin32kFillZeroCount(
    _In_  WDFREQUEST Request,
    _In_  size_t     OutputBufferLength,
    _In_  size_t     OutputSize,
    _Out_ size_t*    BytesReturned)
{
    NTSTATUS status;
    PVOID    out_buf;

    if (OutputBufferLength < OutputSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = MyArkIoctlFetchOutputBuffer(Request, OutputSize, &out_buf);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlZeroMemory(out_buf, OutputSize);
    *(UINT32*)out_buf = 0;  // Count

    *BytesReturned = OutputSize;
    return STATUS_SUCCESS;
}

NTSTATUS MyArkWin32kIoctlEnumerateGuiThreads(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned)
{
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(InputBufferLength);
    return MyArkWin32kFillZeroCount(
        Request, OutputBufferLength, sizeof(MYARK_WIN32K_GUI_THREADS_OUTPUT), BytesReturned);
}

NTSTATUS MyArkWin32kIoctlEnumerateHooks(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned)
{
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(InputBufferLength);
    return MyArkWin32kFillZeroCount(
        Request, OutputBufferLength, sizeof(MYARK_WIN32K_HOOKS_OUTPUT), BytesReturned);
}

#endif // MYARK_MODULE_WIN32K
