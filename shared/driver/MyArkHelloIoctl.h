// 2 IOCTLs (file content matches comment count after this patch).
// MyArk hello module: shared IOCTL protocol between R0 and R3.
//
// Function range 0x900..0x9FF reserved for the hello module. Core uses
// 0x800..0x8FF so hello sits in the next free block; future modules will
// pick their own contiguous block above 0x900.
//
// The hello module exists to verify two gates end-to-end:
//   1. Compile-time gate  -- every .c file is wrapped in
//                            `#if MYARK_MODULE_HELLO`, so toggling the
//                            profile macro alone decides whether the
//                            IOCTL entries are linked into the driver.
//   2. Runtime gate      -- HKLM\...\MyArkCore\Modules\hello = 0/1 lets
//                            an admin disable the module at sc start time
//                            without recompiling.
//
// A successful round-trip through IOCTL_MYARK_HELLO_PING proves both.
//
// Status (S10.3 audit, 2026-08-27):
//   IOCTL_MYARK_HELLO_PING (0x900) is implemented and is functionally
//   equivalent to plan v3's IOCTL_MYARK_HELLO_GREET (greeting probe). The
//   plan v3 name was renamed to PING in implementation because the
//   payload semantics are a name-in/greeting-out round-trip (a "ping"
//   through the IOCTL dispatch path). IOCTL_MYARK_HELLO_GREET is added
//   at 0x901 with a WCHAR greeting + Timestamp field so the two
//   coexist and tests can exercise the WCHAR wire path distinctly.

#pragma once

#include <ntddk.h>
#include <wdf.h>

#define IOCTL_MYARK_HELLO_PING \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_HELLO_GREET \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define MYARK_HELLO_MODULE_ID              0x48454C4CUL  // 'HELL' (ASCII, little-endian readable)
#define MYARK_HELLO_NAME_MAX               64
#define MYARK_HELLO_GREETING_MAX           128

typedef struct _MYARK_HELLO_PING_INPUT {
    CHAR Name[MYARK_HELLO_NAME_MAX];
} MYARK_HELLO_PING_INPUT, *PMYARK_HELLO_PING_INPUT;

typedef struct _MYARK_HELLO_PING_OUTPUT {
    CHAR     Greeting[MYARK_HELLO_GREETING_MAX];
    UINT32   BuildNumber;
    UINT32   ModuleId;
    UINT32   TickCount;
} MYARK_HELLO_PING_OUTPUT, *PMYARK_HELLO_PING_OUTPUT;

//
// IOCTL_MYARK_HELLO_GREET is the WCHAR variant of PING -- same greeting
// semantics, but the input name and output greeting use WCHAR (UTF-16) so
// the wire path exercises the unicode handling. The Timestamp field lets
// R3 measure driver-side dispatch latency for the IOCTL round-trip.
//
typedef struct _MYARK_HELLO_GREET_INPUT {
    WCHAR Name[MYARK_HELLO_NAME_MAX];
} MYARK_HELLO_GREET_INPUT, *PMYARK_HELLO_GREET_INPUT;

typedef struct _MYARK_HELLO_GREET_OUTPUT {
    WCHAR    Greeting[MYARK_HELLO_GREETING_MAX];
    UINT32   BuildNumber;
    UINT32   ModuleId;
    UINT64   Timestamp;                         // KeQueryPerformanceCounter value
} MYARK_HELLO_GREET_OUTPUT, *PMYARK_HELLO_GREET_OUTPUT;