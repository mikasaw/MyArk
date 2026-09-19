// win32k R0 IOCTL handlers.
//
// ENUMERATE_GUI_THREADS - R0 read-only; in S7.3 returns Count=0 stub.
// ENUMERATE_HOOKS       - R0 read-only; in S7.3 returns Count=0 stub.

#include "win32k_descriptor.h"
#include "win32k_internal.h"
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

//
// 0x772 ENUM_USER_HANDLES (R3-10a): walk the CALLER-process USER handle
// table via user32!gSharedInfo. Read-only, no SAFETY_TOKEN (enum surface).
// Runs in the caller's context, so the client process must be a GUI
// process on an interactive session -- the verifier and the R3 CLI always
// are.
//
NTSTATUS MyArkWin32kIoctlEnumerateUserHandles(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned)
{
    NTSTATUS status;
    PVOID    out_buf;
    size_t   out_size = sizeof(MYARK_WIN32K_USER_HANDLES_OUTPUT);
    ULONG    maxEntries = MYARK_WIN32K_HANDLE_CAP;

    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(InputBufferLength);

    if (OutputBufferLength < out_size) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchOutputBuffer(Request, out_size, &out_buf);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = MyArkWin32kEnumUserHandles(
        (PMYARK_WIN32K_USER_HANDLES_OUTPUT)out_buf, maxEntries);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    *BytesReturned = out_size;
    return STATUS_SUCCESS;
}

//
// 0x773 ENUM_TIMERS (R3-10b-iii): walk the session timer hash table via
// win32kbase!gTimerHashTable. Read-only, no SAFETY_TOKEN (enum surface).
// Caller context -- the client process must live in the session whose
// timers are being inspected (the verifier and the R3 CLI always do).
//
NTSTATUS MyArkWin32kIoctlEnumerateTimers(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned)
{
    NTSTATUS status;
    PVOID    out_buf;
    size_t   out_size = sizeof(MYARK_WIN32K_TIMERS_OUTPUT);
    ULONG    maxEntries = MYARK_WIN32K_TIMER_CAP;

    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(InputBufferLength);

    if (OutputBufferLength < out_size) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = MyArkIoctlFetchOutputBuffer(Request, out_size, &out_buf);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = MyArkWin32kEnumTimers(
        (PMYARK_WIN32K_TIMERS_OUTPUT)out_buf, maxEntries);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    *BytesReturned = out_size;
    return STATUS_SUCCESS;
}

#endif // MYARK_MODULE_WIN32K
