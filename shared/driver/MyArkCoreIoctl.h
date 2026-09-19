// 5 IOCTLs (file content matches comment count after this patch).
// MyArk Core Driver: core IOCTL protocol.
//
// Defines the five core IOCTLs that are always present regardless of which
// functional modules are linked into MyArkCore.sys. Module-specific IOCTLs
// live in their own headers (e.g. MyArkProcessIoctl.h) and are registered
// by the module at DriverEntry time via MyArkIoctlRegistryAdd().
//
// Core IOCTL function codes occupy 0x800..0x8FF. Module IOCTLs start at
// 0x900 (HELLO) and march upward in contiguous blocks; see each module's
// own header for its reserved range.
//
// Status (S10.3 audit, 2026-08-27):
//   All five Core IOCTLs are implemented -- definitions below, handlers in
//   driver/src/dispatch/core_ioctl_handlers.c, registered in
//   MyArkIoctlRegistryInitCore. R3 ctypes mirror lives in
//   client/src/myark/protocol/core.py with structural pytest in
//   client/tests/test_core_ioctl.py. GET_LOG / SET_LOG_CONFIG return
//   empty / echo stubs; the kernel ring buffer lands later (S6 work).

#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "MyArkIoctl.h"

#define MYARK_CORE_DRIVER_BUILD_NUMBER      1
#define MYARK_CORE_DISPLAY_NAME             L"MyArk Core 0.1.0"

//
// Module states returned by IOCTL_MYARK_CORE_QUERY_MODULES.
//
#define MYARK_MODULE_STATE_DISABLED         0
#define MYARK_MODULE_STATE_ENABLED          1
#define MYARK_MODULE_STATE_FAILED           2

//
// Core IOCTL codes (function range 0x800..0x8FF reserved for core).
//
#define IOCTL_MYARK_CORE_GET_VERSION \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_CORE_QUERY_MODULES \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_CORE_QUERY_CAPABILITIES \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_CORE_GET_LOG \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_CORE_SET_LOG_CONFIG \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// Delivers the per-boot session key used to sign MYARK_SAFETY_TOKEN
// digests (see MyArkSafetyToken.h). The device SDDL restricts the device
// to SYSTEM/Administrators, so the key is only reachable by
// already-elevated callers; its job is to keep non-admin local processes
// from forging safety tokens and to rotate the token space every boot.
//
#define IOCTL_MYARK_CORE_GET_SESSION_KEY \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// IOCTL_MYARK_CORE_GET_VERSION output.
//
typedef struct _MYARK_CORE_VERSION_OUTPUT {
    UINT32  Size;
    UINT32  CoreProtocolVersion;
    UINT32  ModuleProtocolVersion;
    UINT32  BuildNumber;
    UINT32  ActiveModuleCount;
    WCHAR   DisplayName[64];
} MYARK_CORE_VERSION_OUTPUT, *PMYARK_CORE_VERSION_OUTPUT;

//
// IOCTL_MYARK_CORE_QUERY_MODULES element.
//
typedef struct _MYARK_CORE_MODULE_INFO {
    UINT32  ModuleId;
    CHAR    ModuleName[32];
    CHAR    ModuleDescription[128];
    UINT32  State;
    UINT32  IoctlCount;
    NTSTATUS LastError;
} MYARK_CORE_MODULE_INFO, *PMYARK_CORE_MODULE_INFO;

//
// IOCTL_MYARK_CORE_QUERY_MODULES output. Count variable-length modules
// follow immediately after the Count field; the caller computes the
// required buffer as sizeof(MYARK_CORE_MODULE_LIST_OUTPUT) - sizeof(MYARK_CORE_MODULE_INFO)
// + Count * sizeof(MYARK_CORE_MODULE_INFO).
//
typedef struct _MYARK_CORE_MODULE_LIST_OUTPUT {
    UINT32  Size;
    UINT32  Count;
    MYARK_CORE_MODULE_INFO Modules[1];
} MYARK_CORE_MODULE_LIST_OUTPUT, *PMYARK_CORE_MODULE_LIST_OUTPUT;

//
// IOCTL_MYARK_CORE_QUERY_CAPABILITIES element.
//
typedef struct _MYARK_CORE_CAPABILITY_ENTRY {
    ULONG   IoctlCode;
    CHAR    Name[64];
    UINT32  ModuleId;
} MYARK_CORE_CAPABILITY_ENTRY, *PMYARK_CORE_CAPABILITY_ENTRY;

//
// IOCTL_MYARK_CORE_QUERY_CAPABILITIES output. Variable-length Entries[]
// follows the Count field (sized same way as the module list above).
//
typedef struct _MYARK_CORE_CAPABILITY_OUTPUT {
    UINT32  Size;
    UINT32  Count;
    MYARK_CORE_CAPABILITY_ENTRY Entries[1];
} MYARK_CORE_CAPABILITY_OUTPUT, *PMYARK_CORE_CAPABILITY_OUTPUT;

//
// IOCTL_MYARK_CORE_GET_LOG element. The driver maintains a small ring of
// log records; the user-mode client retrieves batches by passing an
// input buffer describing the cursor (next index to read).
//
typedef struct _MYARK_CORE_LOG_RECORD {
    UINT32  Sequence;
    UINT32  Level;
    LARGE_INTEGER Timestamp;
    CHAR    Module[16];
    CHAR    Message[192];
} MYARK_CORE_LOG_RECORD, *PMYARK_CORE_LOG_RECORD;

typedef struct _MYARK_CORE_LOG_OUTPUT {
    UINT32  Size;
    UINT32  Count;
    MYARK_CORE_LOG_RECORD Records[1];
} MYARK_CORE_LOG_OUTPUT, *PMYARK_CORE_LOG_OUTPUT;

//
// IOCTL_MYARK_CORE_GET_LOG input. Cursor is the Sequence number of the next
// record the caller wants. Cursor == 0 means "from oldest available".
//
typedef struct _MYARK_CORE_LOG_INPUT {
    UINT32  Cursor;
    UINT32  MaxRecords;
} MYARK_CORE_LOG_INPUT, *PMYARK_CORE_LOG_INPUT;

//
// IOCTL_MYARK_CORE_SET_LOG_CONFIG input.
//
typedef struct _MYARK_CORE_LOG_CONFIG {
    UINT32  Enabled;
    UINT32  Level;
    UINT32  Reserved;
} MYARK_CORE_LOG_CONFIG, *PMYARK_CORE_LOG_CONFIG;

//
// IOCTL_MYARK_CORE_GET_SESSION_KEY output.
//
typedef struct _MYARK_CORE_SESSION_KEY_OUTPUT {
    UINT32  Size;                               // sizeof(this struct)
    UINT32  KeyLength;                          // bytes populated in Key[]
    UINT8   Key[32];                            // HMAC-SHA256 session key
} MYARK_CORE_SESSION_KEY_OUTPUT, *PMYARK_CORE_SESSION_KEY_OUTPUT;
