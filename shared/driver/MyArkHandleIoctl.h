// MyArk handle module: shared IOCTL protocol between R0 and R3.
//
// Function range 0xC00..0xC0F reserved for the handle module. Process
// uses 0xA00..0xAFF, memory 0xB00..0xBFF, so handle sits in the next free
// block. All 2 IOCTLs follow the MyArk METHOD_BUFFERED convention.
//
// The handle module walks EPROCESS.ObjectTable (HANDLE_TABLE) directly to
// enumerate handles a process owns, then resolves each handle to its
// underlying OBJECT_HEADER via ObReferenceObjectByHandle /
// ObDereferenceObjectFromDereferenceSide. OBJECT_HEADER private fields
// (HandleCount, PointerCount, TypeIndex) require DynData offsets; until
// S7.1 ships the offsets are hard-coded for Win11 24H2 / build 26100.x.
//
// Cross-process read: ENUM_PROCESS_HANDLES + QUERY_HANDLE use the
// non-invasive KeStackAttachProcess pattern so the target process can
// keep running while we walk its handle table.

#pragma once

#include <ntddk.h>
#include <wdf.h>

// ---------------------------------------------------------------------------
// Module identity + IOCTL function codes.
// ---------------------------------------------------------------------------

#define MYARK_HANDLE_MODULE_ID              0x4C444E48UL  // 'HNDL' ASCII (LE)
#define MYARK_HANDLE_NAME_MAX                64
#define MYARK_HANDLE_TYPE_NAME_MAX           32
#define MYARK_HANDLE_DEFAULT_MAX             256
#define MYARK_HANDLE_HARD_CAP                8192

//
// 2 IOCTLs (function range 0xC00..0xC01). Method/Access match the rest of
// the driver: METHOD_BUFFERED + FILE_ANY_ACCESS.
//
#define IOCTL_MYARK_HANDLE_ENUM_PROCESS_HANDLES \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xC00, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_HANDLE_QUERY_HANDLE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xC01, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ---------------------------------------------------------------------------
// ENUM_PROCESS_HANDLES input / output.
//
// Caller passes a Pid (or 0 for "self"). The driver walks the target's
// handle table and returns one row per handle with the public type name.
// Rows flagged HANDLE_FLAG_KERNEL_ONLY live in the kernel handle table
// (PsCidTable) but are not user-visible handles.
// ---------------------------------------------------------------------------

#define MYARK_HANDLE_FLAG_NONE              0x00000000
#define MYARK_HANDLE_FLAG_KERNEL_ONLY       0x00000001   // in PspCidTable, not in process table
#define MYARK_HANDLE_FLAG_PROTECTED        0x00000002   // ProtectedProcess audit hint
#define MYARK_HANDLE_FLAG_INHERITABLE       0x00000004

typedef struct _MYARK_HANDLE_ENTRY {
    UINT64  HandleValue;                                    // raw handle value (e.g. 0x0000000000000ABC)
    UINT32  HandleAttributes;                               // OBJ_INHERIT / OBJ_KERNEL_HANDLE / OBJ_PERMANENT ...
    UINT32  Flags;                                          // MYARK_HANDLE_FLAG_* bitmask
    UINT32  PointerCount;                                   // OBJECT_HEADER.PointerCount (best-effort)
    UINT32  HandleCount;                                    // OBJECT_HEADER.HandleCount
    UINT32  TypeIndex;                                      // OBJECT_TYPE.TypeIndex (Windows internal)
    WCHAR   TypeName[MYARK_HANDLE_TYPE_NAME_MAX];           // e.g. L"File", L"Process", L"Thread"
    WCHAR   Name[MYARK_HANDLE_NAME_MAX];                    // best-effort: for File -> device path
} MYARK_HANDLE_ENTRY, *PMYARK_HANDLE_ENTRY;

typedef struct _MYARK_HANDLE_ENUM_INPUT {
    UINT32  Pid;                                            // 0 = current process
    UINT32  MaxEntries;                                     // 0 = driver default
    UINT32  Reserved0;
    UINT32  Reserved1;
} MYARK_HANDLE_ENUM_INPUT, *PMYARK_HANDLE_ENUM_INPUT;

typedef struct _MYARK_HANDLE_ENUM_OUTPUT {
    UINT32  Size;
    UINT32  Count;
    UINT32  TotalSeen;                                      // total handles the walk produced
    UINT32  Reserved;
    MYARK_HANDLE_ENTRY Entries[1];                          // variable length
} MYARK_HANDLE_ENUM_OUTPUT, *PMYARK_HANDLE_ENUM_OUTPUT;

// ---------------------------------------------------------------------------
// QUERY_HANDLE input / output.
//
// Returns one deep row for a specific (Pid, HandleValue) pair: full
// OBJECT_HEADER fields, granted access mask, and the best-effort object
// name resolved from ObQueryNameString (may be empty for unnamed objects).
// ---------------------------------------------------------------------------

typedef struct _MYARK_HANDLE_QUERY_INPUT {
    UINT32  Pid;
    UINT32  Reserved0;
    UINT64  HandleValue;
} MYARK_HANDLE_QUERY_INPUT, *PMYARK_HANDLE_QUERY_INPUT;

typedef struct _MYARK_HANDLE_QUERY_OUTPUT {
    UINT32  Status;                                         // NTSTATUS of the underlying lookup
    UINT32  GrantedAccess;                                  // access mask the handle carries
    UINT32  PointerCount;
    UINT32  HandleCount;
    UINT32  TypeIndex;
    UINT32  Flags;
    UINT32  Reserved0;
    UINT32  Reserved1;
    WCHAR   TypeName[MYARK_HANDLE_TYPE_NAME_MAX];
    WCHAR   Name[MYARK_HANDLE_NAME_MAX];                    // ObQueryNameString result (best-effort)
} MYARK_HANDLE_QUERY_OUTPUT, *PMYARK_HANDLE_QUERY_OUTPUT;
