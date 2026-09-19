// MyArk hello module: IOCTL handler implementations.
//
// Two IOCTLs:
//   IOCTL_MYARK_HELLO_PING (0x900) -- ANSI greeting probe; name in /
//                                     greeting + build + tick out.
//   IOCTL_MYARK_HELLO_GREET (0x901) -- wide-char greeting probe; the same
//                                     round-trip carried in WCHAR with a
//                                     Timestamp field so callers can
//                                     measure driver-side dispatch
//                                     latency. A successful return
//                                     confirms the wide-char wire path
//                                     through the IOCTL dispatch table.

#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>
#include "Trace.h"
#include "myark_config.h"
#include "ioctl_validation.h"
#include "../../../shared/driver/MyArkHelloIoctl.h"
#include "MyArkCoreIoctl.h"
#include "hello_descriptor.h"

#if MYARK_MODULE_HELLO

NTSTATUS
MyArkHelloIoctlPing(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned)
{
    PMYARK_HELLO_PING_INPUT  inBuf   = NULL;
    PMYARK_HELLO_PING_OUTPUT outBuf  = NULL;
    size_t                   inSize  = 0;
    size_t                   outSize = 0;
    NTSTATUS                 status;
    PCSTR                    name;

    UNREFERENCED_PARAMETER(Device);

    if (OutputBufferLength < sizeof(MYARK_HELLO_PING_OUTPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    //
    // Input is optional: an empty buffer or an empty Name field both fall
    // back to "world". We still call FetchInputBuffer so the WDF buffer
    // validation path gets exercised on every call -- that's the gate we
    // want to prove.
    //
    if (InputBufferLength >= sizeof(MYARK_HELLO_PING_INPUT)) {
        status = MyArkIoctlFetchInputBuffer(Request,
                                            sizeof(MYARK_HELLO_PING_INPUT),
                                            (PVOID*)&inBuf,
                                            &inSize);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        name = (inBuf->Name[0] != '\0') ? inBuf->Name : "world";
    } else {
        name = "world";
    }

    status = MyArkIoctlFetchOutputBuffer(Request,
                                         sizeof(MYARK_HELLO_PING_OUTPUT),
                                         (PVOID*)&outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlStringCbPrintfA(outBuf->Greeting,
                       sizeof(outBuf->Greeting),
                       "Hello, %s! (from MyArk hello module)",
                       name);
    outBuf->BuildNumber = MYARK_CORE_DRIVER_BUILD_NUMBER;
    outBuf->ModuleId    = MYARK_HELLO_MODULE_ID;
    outBuf->TickCount   = 0;

    *BytesReturned = sizeof(*outBuf);

    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_DISPATCH,
                "MyArkHelloIoctlPing: name=%s -> %s",
                name,
                outBuf->Greeting);

    return STATUS_SUCCESS;
}

NTSTATUS
MyArkHelloIoctlGreet(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned)
//
// Wide-char companion to MyArkHelloIoctlPing. Same greeting semantics
// carried in WCHAR with a KeQueryPerformanceCounter Timestamp so callers
// can measure driver-side dispatch latency. Lives at 0x901 so the two
// IOCTLs coexist in the global table.
//
{
    PMYARK_HELLO_GREET_INPUT  inBuf   = NULL;
    PMYARK_HELLO_GREET_OUTPUT outBuf  = NULL;
    size_t                    inSize  = 0;
    size_t                    outSize = 0;
    NTSTATUS                  status;
    PCWSTR                    name;
    WCHAR                     fallback[] = L"world";

    UNREFERENCED_PARAMETER(Device);

    if (OutputBufferLength < sizeof(MYARK_HELLO_GREET_OUTPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (InputBufferLength >= sizeof(MYARK_HELLO_GREET_INPUT)) {
        status = MyArkIoctlFetchInputBuffer(Request,
                                            sizeof(MYARK_HELLO_GREET_INPUT),
                                            (PVOID*)&inBuf,
                                            &inSize);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        name = (inBuf->Name[0] != L'\0') ? inBuf->Name : fallback;
    } else {
        name = fallback;
    }

    status = MyArkIoctlFetchOutputBuffer(Request,
                                         sizeof(MYARK_HELLO_GREET_OUTPUT),
                                         (PVOID*)&outBuf,
                                         &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = RtlStringCbPrintfW(outBuf->Greeting,
                                sizeof(outBuf->Greeting),
                                L"Hello, %ws! (from MyArk hello module)",
                                name);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    outBuf->BuildNumber = MYARK_CORE_DRIVER_BUILD_NUMBER;
    outBuf->ModuleId    = MYARK_HELLO_MODULE_ID;
    outBuf->Timestamp   = (UINT64)KeQueryPerformanceCounter(NULL).QuadPart;

    *BytesReturned = sizeof(*outBuf);

    TraceEvents(TRACE_LEVEL_INFORMATION,
                MYARK_TRACE_DISPATCH,
                "MyArkHelloIoctlGreet: name=%ws -> %ws",
                name,
                outBuf->Greeting);

    return STATUS_SUCCESS;
}

#endif // MYARK_MODULE_HELLO