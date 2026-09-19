// MyArk dyndata module: shared IOCTL protocol between R0 and R3.
//
// Function range 0x700..0x708 reserved for the dyndata module (S7.1).
// The dyndata module provides a kernel-side NtQuerySystemInformation-style
// surface that other S7 modules (Callback / Kernel Object / WFP / Mutation /
// etc.) depend on for build-specific offsets and live enumerations.
//
// The 9 IOCTLs:
//
//   0x700  QUERY_PROCESS   - EPROCESS list via PsActiveProcessHead walk
//   0x701  QUERY_THREAD    - ETHREAD list via PsActiveThreadHead walk
//   0x702  QUERY_MODULE    - Kernel module list via PsLoadedModuleList
//   0x703  QUERY_HANDLE    - Handle table snapshot (SystemHandleInformation-like)
//   0x704  QUERY_FILE      - Open file object snapshot (SystemHandleInformation-like type 18)
//   0x705  QUERY_SYSCALL   - Live syscall-table inventory (Win32k + ntoskrnl stub map)
//   0x706  QUERY_TOKEN     - Token information snapshot for a single process
//   0x707  QUERY_OBJECT    - Object-type inventory (ObGetObjectType + per-type counts)
//   0x708  QUERY_SSDT      - Shadow SSDT walker (win32u!W32pServiceTable)
//
// All 9 IOCTLs use the MyArk METHOD_BUFFERED convention. None of the entries
// perform mutating operations; the module is read-only.

#pragma once

#include <ntddk.h>
#include <wdf.h>

// ---------------------------------------------------------------------------
// Module identity + IOCTL function codes.
// ---------------------------------------------------------------------------

#define MYARK_DYNDATA_MODULE_ID              0x444E5944UL  // 'DYND' ASCII (LE)
#define MYARK_DYNDATA_NAME_MAX               64
#define MYARK_DYNDATA_PATH_MAX               260
#define MYARK_DYNDATA_IMAGE_FILE_NAME_MAX    16
#define MYARK_DYNDATA_TOKEN_INFO_MAX         256
#define MYARK_DYNDATA_SYSCALL_DWELL_MAX      8

//
// Hard caps (defensive: callers can override via Input but never ask for
// an unbounded buffer).
//
#define MYARK_DYNDATA_PROCESS_HARD_CAP       4096
#define MYARK_DYNDATA_THREAD_HARD_CAP        8192
#define MYARK_DYNDATA_MODULE_HARD_CAP        1024
#define MYARK_DYNDATA_HANDLE_HARD_CAP        8192
#define MYARK_DYNDATA_FILE_HARD_CAP          4096
#define MYARK_DYNDATA_SYSCALL_HARD_CAP       2048
#define MYARK_DYNDATA_OBJECT_TYPE_HARD_CAP   64

//
// 9 IOCTLs (function range 0x700..0x708). Method/Access match the rest of
// the driver: METHOD_BUFFERED + FILE_ANY_ACCESS.
//
#define IOCTL_MYARK_DYNDATA_QUERY_PROCESS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x700, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_DYNDATA_QUERY_THREAD \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x701, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_DYNDATA_QUERY_MODULE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x702, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_DYNDATA_QUERY_HANDLE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x703, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_DYNDATA_QUERY_FILE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x704, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_DYNDATA_QUERY_SYSCALL \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x705, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_DYNDATA_QUERY_TOKEN \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x706, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_DYNDATA_QUERY_OBJECT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x707, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_DYNDATA_QUERY_SSDT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x708, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ---------------------------------------------------------------------------
// Source / flag bits shared across the QUERY_* outputs.
// ---------------------------------------------------------------------------

//
// DYNDATA_PROCESS_SRC_* mark which view populated a row:
//   ACTIVE_LINKS = EPROCESS.ActiveProcessLinks walk (DKOM-safe)
//   PspCidTable  = PspCidTable handle lookup (canonical kernel-side view)
//
#define MYARK_DYNDATA_PROCESS_SRC_NONE          0x00
#define MYARK_DYNDATA_PROCESS_SRC_ACTIVE_LINKS  0x01
#define MYARK_DYNDATA_PROCESS_SRC_PSPCIDTABLE   0x02

//
// DYNDATA_FLAG_* report the row's relation to ntoskrnl .text:
//   SUSPECT = address outside the resolved kernel .text range
//   HOOK    = low-bit set or trampoline present (best-effort)
//   POPULATED = the underlying entry was non-null at walk time
//
#define MYARK_DYNDATA_FLAG_NONE                 0x00000000
#define MYARK_DYNDATA_FLAG_POPULATED            0x00000001
#define MYARK_DYNDATA_FLAG_SUSPECT              0x00000002
#define MYARK_DYNDATA_FLAG_HOOK                 0x00000004

//
// DYNDATA_TOKEN_FLAG_* report which fields of MYARK_DYNDATA_TOKEN_ENTRY
// are valid. Each flag flips one output bit; R3 clients use them to
// decide whether to render the corresponding column.
//
#define MYARK_DYNDATA_TOKEN_FLAG_NONE           0x00000000
#define MYARK_DYNDATA_TOKEN_FLAG_USER_PRESENT   0x00000001
#define MYARK_DYNDATA_TOKEN_FLAG_INTEGRITY      0x00000002
#define MYARK_DYNDATA_TOKEN_FLAG_ELEVATION      0x00000004
#define MYARK_DYNDATA_TOKEN_FLAG_VIRTUALIZATION 0x00000008

//
// DYNDATA_SYSCALL_TABLE_* identify which kernel table the row belongs to.
//   NTOS    = KeServiceDescriptorTable (ntoskrnl Nt*)
//   WIN32K  = KeServiceDescriptorTableShadow + W32pServiceTable (win32k)
//   UNKNOWN = not yet classified (forward-compat)
//   SHADOW  = the shadow entry (NtUser* / NtGdi*) when both tables share an index
//
#define MYARK_DYNDATA_SYSCALL_TABLE_NTOS       0x00
#define MYARK_DYNDATA_SYSCALL_TABLE_WIN32K     0x01
#define MYARK_DYNDATA_SYSCALL_TABLE_SHADOW     0x02
#define MYARK_DYNDATA_SYSCALL_TABLE_UNKNOWN     0xFF

// ---------------------------------------------------------------------------
// QUERY_PROCESS: one row per EPROCESS visible to the kernel.
// ---------------------------------------------------------------------------

typedef struct _MYARK_DYNDATA_PROCESS_ENTRY {
    UINT32  Pid;
    UINT32  Ppid;
    UINT32  SessionId;
    UINT32  Flags;                                        // MYARK_DYNDATA_FLAG_*
    UINT64  EProcess;                                     // kernel VA (informational)
    UINT64  Peb;                                          // kernel VA (informational)
    UINT8   ImageFileName[MYARK_DYNDATA_IMAGE_FILE_NAME_MAX];
    UINT32  SourceMask;                                   // MYARK_DYNDATA_PROCESS_SRC_*
    UINT32  Reserved0;
    UINT64  CreateTime;                                   // LARGE_INTEGER (kernel time)
} MYARK_DYNDATA_PROCESS_ENTRY, *PMYARK_DYNDATA_PROCESS_ENTRY;

typedef struct _MYARK_DYNDATA_QUERY_PROCESS_INPUT {
    UINT32  MaxEntries;
    UINT32  PidFilter;                                    // 0 = no filter
    UINT32  Reserved0;
    UINT32  Reserved1;
} MYARK_DYNDATA_QUERY_PROCESS_INPUT, *PMYARK_DYNDATA_QUERY_PROCESS_INPUT;

typedef struct _MYARK_DYNDATA_QUERY_PROCESS_OUTPUT {
    UINT32  Size;
    UINT32  Count;
    UINT32  TotalSeen;
    UINT32  Reserved0;
    UINT64  PsActiveProcessHead;                          // resolved pointer (0 = unresolvable)
    UINT32  EntryStructSize;
    UINT32  Reserved1;
    MYARK_DYNDATA_PROCESS_ENTRY Entries[1];
} MYARK_DYNDATA_QUERY_PROCESS_OUTPUT, *PMYARK_DYNDATA_QUERY_PROCESS_OUTPUT;

// ---------------------------------------------------------------------------
// QUERY_THREAD: one row per ETHREAD seen in PsActiveThreadHead.
// ---------------------------------------------------------------------------

typedef struct _MYARK_DYNDATA_THREAD_ENTRY {
    UINT32  Tid;
    UINT32  OwnerPid;
    UINT32  State;                                        // ETHREAD state (Running/Ready/...)
    UINT32  BasePriority;
    UINT64  EThread;                                      // kernel VA (informational)
    UINT64  StartAddress;                                 // kernel VA (informational)
    UINT32  WaitReason;                                   // KWAIT_REASON
    UINT32  Flags;                                        // MYARK_DYNDATA_FLAG_*
    UINT64  CreateTime;                                   // LARGE_INTEGER (kernel time)
} MYARK_DYNDATA_THREAD_ENTRY, *PMYARK_DYNDATA_THREAD_ENTRY;

typedef struct _MYARK_DYNDATA_QUERY_THREAD_INPUT {
    UINT32  MaxEntries;
    UINT32  PidFilter;                                    // 0 = any
    UINT32  Reserved0;
    UINT32  Reserved1;
} MYARK_DYNDATA_QUERY_THREAD_INPUT, *PMYARK_DYNDATA_QUERY_THREAD_INPUT;

typedef struct _MYARK_DYNDATA_QUERY_THREAD_OUTPUT {
    UINT32  Size;
    UINT32  Count;
    UINT32  TotalSeen;
    UINT32  Reserved0;
    UINT64  PsActiveThreadHead;
    UINT32  EntryStructSize;
    UINT32  Reserved1;
    MYARK_DYNDATA_THREAD_ENTRY Entries[1];
} MYARK_DYNDATA_QUERY_THREAD_OUTPUT, *PMYARK_DYNDATA_QUERY_THREAD_OUTPUT;

// ---------------------------------------------------------------------------
// QUERY_MODULE: kernel-side module list via PsLoadedModuleList.
// ---------------------------------------------------------------------------

typedef struct _MYARK_DYNDATA_MODULE_ENTRY {
    UINT64  ImageBase;                                    // kernel VA (driver / kernel .text)
    UINT64  ImageSize;
    UINT32  Flags;                                        // MYARK_DYNDATA_FLAG_*
    UINT32  LoadOrderIndex;                               // position in PsLoadedModuleList
    UINT8   Name[MYARK_DYNDATA_NAME_MAX];
    UINT8   FullPath[MYARK_DYNDATA_PATH_MAX];
} MYARK_DYNDATA_MODULE_ENTRY, *PMYARK_DYNDATA_MODULE_ENTRY;

typedef struct _MYARK_DYNDATA_QUERY_MODULE_INPUT {
    UINT32  MaxEntries;
    UINT32  Reserved0;
    UINT32  Reserved1;
    UINT32  Reserved2;
} MYARK_DYNDATA_QUERY_MODULE_INPUT, *PMYARK_DYNDATA_QUERY_MODULE_INPUT;

typedef struct _MYARK_DYNDATA_QUERY_MODULE_OUTPUT {
    UINT32  Size;
    UINT32  Count;
    UINT32  TotalSeen;
    UINT32  Reserved0;
    UINT64  PsLoadedModuleList;
    UINT32  EntryStructSize;
    UINT32  Reserved1;
    MYARK_DYNDATA_MODULE_ENTRY Entries[1];
} MYARK_DYNDATA_QUERY_MODULE_OUTPUT, *PMYARK_DYNDATA_QUERY_MODULE_OUTPUT;

// ---------------------------------------------------------------------------
// QUERY_HANDLE: handle-table snapshot. R3 sees Pid / HandleValue / Object /
// TypeIndex / GrantedAccess. Object VA is informational.
// ---------------------------------------------------------------------------

typedef struct _MYARK_DYNDATA_HANDLE_ENTRY {
    UINT32  Pid;
    UINT32  HandleValue;
    UINT32  TypeIndex;                                    // ObHeaderCookie encoded (caller decodes)
    UINT32  GrantedAccess;
    UINT64  Object;                                       // kernel VA (informational)
    UINT32  Flags;                                        // MYARK_DYNDATA_FLAG_*
    UINT32  Reserved0;
} MYARK_DYNDATA_HANDLE_ENTRY, *PMYARK_DYNDATA_HANDLE_ENTRY;

typedef struct _MYARK_DYNDATA_QUERY_HANDLE_INPUT {
    UINT32  MaxEntries;
    UINT32  PidFilter;                                    // 0 = any
    UINT32  TypeIndexFilter;                              // 0xFFFFFFFF = any
    UINT32  Reserved0;
} MYARK_DYNDATA_QUERY_HANDLE_INPUT, *PMYARK_DYNDATA_QUERY_HANDLE_INPUT;

typedef struct _MYARK_DYNDATA_QUERY_HANDLE_OUTPUT {
    UINT32  Size;
    UINT32  Count;
    UINT32  TotalSeen;
    UINT32  Reserved0;
    UINT64  PspCidTable;                                  // resolved pointer (0 = unresolvable)
    UINT32  EntryStructSize;
    UINT32  Reserved1;
    MYARK_DYNDATA_HANDLE_ENTRY Entries[1];
} MYARK_DYNDATA_QUERY_HANDLE_OUTPUT, *PMYARK_DYNDATA_QUERY_HANDLE_OUTPUT;

// ---------------------------------------------------------------------------
// QUERY_FILE: file-object snapshot for a single process. One row per open
// file / device / pipe held by the process handle table.
// ---------------------------------------------------------------------------

typedef struct _MYARK_DYNDATA_FILE_ENTRY {
    UINT32  Pid;
    UINT32  HandleValue;
    UINT64  FileObject;                                   // kernel VA (informational)
    UINT64  DeviceObject;                                 // kernel VA (informational)
    UINT32  Flags;                                        // MYARK_DYNDATA_FLAG_*
    UINT32  ShareAccess;
    UINT8   Name[MYARK_DYNDATA_PATH_MAX];
} MYARK_DYNDATA_FILE_ENTRY, *PMYARK_DYNDATA_FILE_ENTRY;

typedef struct _MYARK_DYNDATA_QUERY_FILE_INPUT {
    UINT32  MaxEntries;
    UINT32  PidFilter;                                    // 0 = any process
    UINT32  Reserved0;
    UINT32  Reserved1;
} MYARK_DYNDATA_QUERY_FILE_INPUT, *PMYARK_DYNDATA_QUERY_FILE_INPUT;

typedef struct _MYARK_DYNDATA_QUERY_FILE_OUTPUT {
    UINT32  Size;
    UINT32  Count;
    UINT32  TotalSeen;
    UINT32  Reserved0;
    UINT64  ObTypeIndexList;                              // resolved ObTypeIndexTable
    UINT32  EntryStructSize;
    UINT32  Reserved1;
    MYARK_DYNDATA_FILE_ENTRY Entries[1];
} MYARK_DYNDATA_QUERY_FILE_OUTPUT, *PMYARK_DYNDATA_QUERY_FILE_OUTPUT;

// ---------------------------------------------------------------------------
// QUERY_SYSCALL: live syscall table inventory. R3 gets ordinal index, kernel
// VA, a truncated dwell-byte sample, and a table-id so the renderer can
// distinguish ntoskrnl Nt* from win32k NtUser*/NtGdi*.
// ---------------------------------------------------------------------------

typedef struct _MYARK_DYNDATA_SYSCALL_ENTRY {
    UINT32  ServiceIndex;
    UINT32  TableId;                                      // MYARK_DYNDATA_SYSCALL_TABLE_*
    UINT64  ServiceAddress;                               // kernel VA of Nt* / NtUser* / NtGdi*
    UINT32  Flags;                                        // MYARK_DYNDATA_FLAG_*
    UINT32  DwellBytesSize;                               // bytes copied (up to MYARK_DYNDATA_SYSCALL_DWELL_MAX)
    UINT8   DwellBytes[MYARK_DYNDATA_SYSCALL_DWELL_MAX];
    UINT32  Reserved0;
    UINT32  Reserved1;
} MYARK_DYNDATA_SYSCALL_ENTRY, *PMYARK_DYNDATA_SYSCALL_ENTRY;

typedef struct _MYARK_DYNDATA_QUERY_SYSCALL_INPUT {
    UINT32  MaxEntries;
    UINT32  TableMask;                                    // bit 0 = NTOS, bit 1 = WIN32K (0 = both)
    UINT32  Reserved0;
    UINT32  Reserved1;
} MYARK_DYNDATA_QUERY_SYSCALL_INPUT, *PMYARK_DYNDATA_QUERY_SYSCALL_INPUT;

typedef struct _MYARK_DYNDATA_QUERY_SYSCALL_OUTPUT {
    UINT32  Size;
    UINT32  Count;
    UINT32  TotalSeen;
    UINT32  Reserved0;
    UINT64  KeServiceDescriptorTable;                     // resolved address (0 = unresolvable)
    UINT64  W32pServiceTable;                             // resolved address (0 = unresolvable)
    UINT64  NtoskrnlTextBase;                             // suspect-range lower bound
    UINT64  NtoskrnlTextEnd;                              // suspect-range upper bound
    UINT32  EntryStructSize;
    UINT32  Reserved1;
    MYARK_DYNDATA_SYSCALL_ENTRY Entries[1];
} MYARK_DYNDATA_QUERY_SYSCALL_OUTPUT, *PMYARK_DYNDATA_QUERY_SYSCALL_OUTPUT;

// ---------------------------------------------------------------------------
// QUERY_TOKEN: token snapshot for a single PID. Mirrors the union of
// TOKEN_USER + TOKEN_MANDATORY_LABEL + TOKEN_ELEVATION + TOKEN_VIRTUALIZATION
// so the R3 renderer does not have to do a second round-trip.
// ---------------------------------------------------------------------------

typedef struct _MYARK_DYNDATA_TOKEN_ENTRY {
    UINT32  Pid;
    UINT32  Flags;                                        // MYARK_DYNDATA_TOKEN_FLAG_*
    UINT32  IntegrityLevel;                               // SECURITY_MANDATORY_* (RID form)
    UINT32  IntegrityFlags;
    UINT32  SessionId;
    UINT32  ElevationType;                                // TokenElevationType
    UINT32  IsElevated;                                   // 0 / 1
    UINT32  VirtualizationEnabled;                        // 0 / 1
    UINT32  UserRid;                                      // TOKEN_USER.User.Sid.SubAuthority[...]
    UINT32  Reserved0;
    UINT32  Reserved1;
    UINT64  Token;                                        // kernel VA (informational)
    UINT8   UserSidString[MYARK_DYNDATA_TOKEN_INFO_MAX];  // zero-terminated
} MYARK_DYNDATA_TOKEN_ENTRY, *PMYARK_DYNDATA_TOKEN_ENTRY;

typedef struct _MYARK_DYNDATA_QUERY_TOKEN_INPUT {
    UINT32  Pid;
    UINT32  Reserved0;
    UINT32  Reserved1;
    UINT32  Reserved2;
} MYARK_DYNDATA_QUERY_TOKEN_INPUT, *PMYARK_DYNDATA_QUERY_TOKEN_INPUT;

typedef struct _MYARK_DYNDATA_QUERY_TOKEN_OUTPUT {
    UINT32  Size;
    UINT32  Count;                                        // always 1 on success
    UINT32  Reserved0;
    UINT32  Reserved1;
    UINT32  EntryStructSize;
    UINT32  Reserved2;
    MYARK_DYNDATA_TOKEN_ENTRY Entries[1];
} MYARK_DYNDATA_QUERY_TOKEN_OUTPUT, *PMYARK_DYNDATA_QUERY_TOKEN_OUTPUT;

// ---------------------------------------------------------------------------
// QUERY_OBJECT: object-type inventory. One row per ObjectType in
// ObTypeObjectType / NtGlobalFlag-aware enumeration.
// ---------------------------------------------------------------------------

typedef struct _MYARK_DYNDATA_OBJECT_ENTRY {
    UINT32  TypeIndex;                                    // ObHeaderCookie encoded (caller decodes)
    UINT32  TotalNumberOfObjects;
    UINT32  TotalNumberOfHandles;
    UINT32  Flags;                                        // MYARK_DYNDATA_FLAG_*
    UINT64  TypeObject;                                   // kernel VA (informational)
    UINT8   Name[MYARK_DYNDATA_NAME_MAX];
} MYARK_DYNDATA_OBJECT_ENTRY, *PMYARK_DYNDATA_OBJECT_ENTRY;

typedef struct _MYARK_DYNDATA_QUERY_OBJECT_INPUT {
    UINT32  MaxEntries;
    UINT32  Reserved0;
    UINT32  Reserved1;
    UINT32  Reserved2;
} MYARK_DYNDATA_QUERY_OBJECT_INPUT, *PMYARK_DYNDATA_QUERY_OBJECT_INPUT;

typedef struct _MYARK_DYNDATA_QUERY_OBJECT_OUTPUT {
    UINT32  Size;
    UINT32  Count;
    UINT32  TotalSeen;
    UINT32  Reserved0;
    UINT64  ObTypeObjectType;                             // resolved pointer (0 = unresolvable)
    UINT32  EntryStructSize;
    UINT32  Reserved1;
    MYARK_DYNDATA_OBJECT_ENTRY Entries[1];
} MYARK_DYNDATA_QUERY_OBJECT_OUTPUT, *PMYARK_DYNDATA_QUERY_OBJECT_OUTPUT;

// ---------------------------------------------------------------------------
// QUERY_SSDT: shadow SSDT walker. Mirrors the kernel module's QUERY_SSDT
// (which walks the main SSDT) but the shadow entry lives in
// KeServiceDescriptorTableShadow + W32pServiceTable.
// ---------------------------------------------------------------------------

typedef struct _MYARK_DYNDATA_SSDT_ENTRY {
    UINT32  ServiceIndex;
    UINT32  TableId;                                      // MYARK_DYNDATA_SYSCALL_TABLE_*
    UINT64  ServiceAddress;                               // kernel VA of win32k!NtUser*/NtGdi*
    UINT32  Flags;                                        // MYARK_DYNDATA_FLAG_*
    UINT32  DwellBytesSize;
    UINT8   DwellBytes[MYARK_DYNDATA_SYSCALL_DWELL_MAX];
    UINT32  Reserved0;
    UINT32  Reserved1;
} MYARK_DYNDATA_SSDT_ENTRY, *PMYARK_DYNDATA_SSDT_ENTRY;

typedef struct _MYARK_DYNDATA_QUERY_SSDT_INPUT {
    UINT32  MaxEntries;
    UINT32  Reserved0;
    UINT32  Reserved1;
    UINT32  Reserved2;
} MYARK_DYNDATA_QUERY_SSDT_INPUT, *PMYARK_DYNDATA_QUERY_SSDT_INPUT;

typedef struct _MYARK_DYNDATA_QUERY_SSDT_OUTPUT {
    UINT32  Size;
    UINT32  Count;
    UINT32  TotalSeen;
    UINT32  Reserved0;
    UINT64  KeServiceDescriptorTableShadow;               // resolved pointer (0 = unresolvable)
    UINT64  W32pServiceTable;
    UINT64  Win32kTextBase;
    UINT64  Win32kTextEnd;
    UINT32  EntryStructSize;
    UINT32  Reserved1;
    MYARK_DYNDATA_SSDT_ENTRY Entries[1];
} MYARK_DYNDATA_QUERY_SSDT_OUTPUT, *PMYARK_DYNDATA_QUERY_SSDT_OUTPUT;
