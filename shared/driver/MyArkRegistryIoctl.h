// MyArk registry module: shared IOCTL protocol between R0 and R3.
//
// Function range 0xE00..0xE07 reserved for the registry module (ROADMAP
// R1-1/R1-2). All paths passed by the caller use the NT registry format
// ("\Registry\Machine\..." or "\Registry\User\..."); the driver rejects
// every path outside those two roots before any access.
//
// Read/enumerate IOCTLs are open to any caller. Write IOCTLs (SET_VALUE,
// DELETE_VALUE, CREATE_KEY, DELETE_KEY, RENAME_VALUE, RENAME_KEY) carry a
// MYARK_SAFETY_TOKEN and are rejected with STATUS_ACCESS_DENIED when the
// token does not validate.
//
// The 8 IOCTLs use the MyArk METHOD_BUFFERED convention.

#pragma once

#include <ntddk.h>
#include <wdf.h>

#include "MyArkSafetyToken.h"


// ---------------------------------------------------------------------------
// Module identity + IOCTL function codes.
// ---------------------------------------------------------------------------

#define MYARK_REGISTRY_MODULE_ID              0x52454753UL  // 'REGS' ASCII (LE)

//
// 8 IOCTLs (function range 0xE00..0xE07). Method/Access match the rest of
// the driver: METHOD_BUFFERED + FILE_ANY_ACCESS.
//
#define IOCTL_MYARK_REGISTRY_READ_VALUE     CTL_CODE(FILE_DEVICE_UNKNOWN, 0xE00, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MYARK_REGISTRY_ENUM_KEY       CTL_CODE(FILE_DEVICE_UNKNOWN, 0xE01, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MYARK_REGISTRY_SET_VALUE      CTL_CODE(FILE_DEVICE_UNKNOWN, 0xE02, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MYARK_REGISTRY_DELETE_VALUE   CTL_CODE(FILE_DEVICE_UNKNOWN, 0xE03, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MYARK_REGISTRY_CREATE_KEY     CTL_CODE(FILE_DEVICE_UNKNOWN, 0xE04, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MYARK_REGISTRY_DELETE_KEY     CTL_CODE(FILE_DEVICE_UNKNOWN, 0xE05, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MYARK_REGISTRY_RENAME_VALUE   CTL_CODE(FILE_DEVICE_UNKNOWN, 0xE06, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MYARK_REGISTRY_RENAME_KEY     CTL_CODE(FILE_DEVICE_UNKNOWN, 0xE07, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ---------------------------------------------------------------------------
// Limits. Keep every input struct within ~1 KiB so the METHOD_BUFFERED
// system buffer stays comfortably small.
// ---------------------------------------------------------------------------

#define MYARK_REGISTRY_KEY_PATH_CHARS       256   // NT path incl. terminator
#define MYARK_REGISTRY_VALUE_NAME_CHARS     64
#define MYARK_REGISTRY_DATA_MAX             512
#define MYARK_REGISTRY_ENUM_MAX_ENTRIES     16

// SAFETY_TOKEN operations carried in the write tokens. The HMAC covers
// (Magic, Pid, Operation, Timestamp); both sides must agree on the number.
#define MYARK_REGISTRY_OP_SET_VALUE         1
#define MYARK_REGISTRY_OP_DELETE_VALUE      2
#define MYARK_REGISTRY_OP_CREATE_KEY        3
#define MYARK_REGISTRY_OP_DELETE_KEY        4
#define MYARK_REGISTRY_OP_RENAME_VALUE      5
#define MYARK_REGISTRY_OP_RENAME_KEY        6

// ---------------------------------------------------------------------------
// READ_VALUE.
//
// Input: NT key path + value name. Output: Status (in-band; the IOCTL
// itself returns STATUS_SUCCESS unless the transport fails), the Win32
// registry type (REG_DWORD/REG_SZ/...), and up to MYARK_REGISTRY_DATA_MAX
// bytes of the raw value. DataSize > MYARK_REGISTRY_DATA_MAX signals a
// truncation (Status carries STATUS_BUFFER_TOO_SMALL).
// ---------------------------------------------------------------------------

typedef struct _MYARK_REGISTRY_READ_INPUT {
    WCHAR KeyPath[MYARK_REGISTRY_KEY_PATH_CHARS];
    WCHAR ValueName[MYARK_REGISTRY_VALUE_NAME_CHARS];
} MYARK_REGISTRY_READ_INPUT, *PMYARK_REGISTRY_READ_INPUT;

typedef struct _MYARK_REGISTRY_READ_OUTPUT {
    UINT32  Status;                              // STATUS_*
    UINT32  Type;                                // REG_* value type
    UINT32  DataSize;                            // bytes in Data[]
    UINT8   Data[MYARK_REGISTRY_DATA_MAX];
} MYARK_REGISTRY_READ_OUTPUT, *PMYARK_REGISTRY_READ_OUTPUT;

// ---------------------------------------------------------------------------
// ENUM_KEY: batched subkey enumeration.
//
// Input: NT key path + 0-based start index + per-call cap. Output: up to
// MYARK_REGISTRY_ENUM_MAX_ENTRIES subkey names, the key's total subkey
// count, and the next index to continue from (== StartIndex when the key
// has no subkeys).
// ---------------------------------------------------------------------------

typedef struct _MYARK_REGISTRY_ENUM_INPUT {
    WCHAR   KeyPath[MYARK_REGISTRY_KEY_PATH_CHARS];
    UINT32  StartIndex;
    UINT32  MaxEntries;                          // driver caps at 16
} MYARK_REGISTRY_ENUM_INPUT, *PMYARK_REGISTRY_ENUM_INPUT;

typedef struct _MYARK_REGISTRY_NAME_ENTRY {
    WCHAR   Name[MYARK_REGISTRY_VALUE_NAME_CHARS];
} MYARK_REGISTRY_NAME_ENTRY, *PMYARK_REGISTRY_NAME_ENTRY;

typedef struct _MYARK_REGISTRY_ENUM_OUTPUT {
    UINT32  Status;                              // STATUS_*
    UINT32  Returned;                            // names written
    UINT32  TotalSubkeys;                        // full key information
    UINT32  NextIndex;                           // resume enumeration here
    MYARK_REGISTRY_NAME_ENTRY Names[MYARK_REGISTRY_ENUM_MAX_ENTRIES];
} MYARK_REGISTRY_ENUM_OUTPUT, *PMYARK_REGISTRY_ENUM_OUTPUT;

// ---------------------------------------------------------------------------
// SET_VALUE.
//
// Token-gated. Writes ValueName under KeyPath with the given type and
// payload. DataSize must be <= MYARK_REGISTRY_DATA_MAX and match the
// trailing bytes actually carried.
// ---------------------------------------------------------------------------

typedef struct _MYARK_REGISTRY_SET_VALUE_INPUT {
    MYARK_SAFETY_TOKEN Token;
    WCHAR   KeyPath[MYARK_REGISTRY_KEY_PATH_CHARS];
    WCHAR   ValueName[MYARK_REGISTRY_VALUE_NAME_CHARS];
    UINT32  ValueType;                           // REG_*
    UINT32  DataSize;                            // bytes in Data[]
    UINT8   Data[MYARK_REGISTRY_DATA_MAX];
} MYARK_REGISTRY_SET_VALUE_INPUT, *PMYARK_REGISTRY_SET_VALUE_INPUT;

// ---------------------------------------------------------------------------
// Simple status output shared by all mutating IOCTLs. The IOCTL returns
// STATUS_SUCCESS for transport-level success; the in-band Status carries
// the operation result so R3 can distinguish policy denials (which arrive
// as Win32 ERROR_ACCESS_DENIED on the IOCTL itself) from target failures.
// ---------------------------------------------------------------------------

typedef struct _MYARK_REGISTRY_STATUS_OUTPUT {
    UINT32  Status;                              // STATUS_*
} MYARK_REGISTRY_STATUS_OUTPUT, *PMYARK_REGISTRY_STATUS_OUTPUT;

// ---------------------------------------------------------------------------
// DELETE_VALUE / DELETE_KEY / CREATE_KEY inputs.
// ---------------------------------------------------------------------------

typedef struct _MYARK_REGISTRY_DELETE_VALUE_INPUT {
    MYARK_SAFETY_TOKEN Token;
    WCHAR   KeyPath[MYARK_REGISTRY_KEY_PATH_CHARS];
    WCHAR   ValueName[MYARK_REGISTRY_VALUE_NAME_CHARS];
} MYARK_REGISTRY_DELETE_VALUE_INPUT, *PMYARK_REGISTRY_DELETE_VALUE_INPUT;

typedef struct _MYARK_REGISTRY_CREATE_KEY_INPUT {
    MYARK_SAFETY_TOKEN Token;
    WCHAR   KeyPath[MYARK_REGISTRY_KEY_PATH_CHARS];
} MYARK_REGISTRY_CREATE_KEY_INPUT, *PMYARK_REGISTRY_CREATE_KEY_INPUT;

typedef struct _MYARK_REGISTRY_DELETE_KEY_INPUT {
    MYARK_SAFETY_TOKEN Token;
    WCHAR   KeyPath[MYARK_REGISTRY_KEY_PATH_CHARS];
} MYARK_REGISTRY_DELETE_KEY_INPUT, *PMYARK_REGISTRY_DELETE_KEY_INPUT;

// ---------------------------------------------------------------------------
// RENAME_VALUE (query old -> delete old -> write new, one kernel op) and
// RENAME_KEY (ZwRenameKey; fails with STATUS_CANNOT_DELETE while the key
// has subkeys -- documented behaviour, not retried recursively).
// ---------------------------------------------------------------------------

typedef struct _MYARK_REGISTRY_RENAME_VALUE_INPUT {
    MYARK_SAFETY_TOKEN Token;
    WCHAR   KeyPath[MYARK_REGISTRY_KEY_PATH_CHARS];
    WCHAR   OldName[MYARK_REGISTRY_VALUE_NAME_CHARS];
    WCHAR   NewName[MYARK_REGISTRY_VALUE_NAME_CHARS];
} MYARK_REGISTRY_RENAME_VALUE_INPUT, *PMYARK_REGISTRY_RENAME_VALUE_INPUT;

typedef struct _MYARK_REGISTRY_RENAME_KEY_INPUT {
    MYARK_SAFETY_TOKEN Token;
    WCHAR   KeyPath[MYARK_REGISTRY_KEY_PATH_CHARS];
    WCHAR   NewName[MYARK_REGISTRY_VALUE_NAME_CHARS];
} MYARK_REGISTRY_RENAME_KEY_INPUT, *PMYARK_REGISTRY_RENAME_KEY_INPUT;

