// MyArk file module: shared IOCTL protocol between R0 and R3.
//
// Function range 0xE10..0xE1F reserved for the file module (ROADMAP R1-3).
// All paths use the NT format ("\??\C:\..." for DOS drives); the driver
// validates the prefix before any access.
//
// QUERY_FILE_INFO is open to any caller. DELETE_PATH carries a
// MYARK_SAFETY_TOKEN and is rejected with STATUS_ACCESS_DENIED when the
// token does not validate. Both IOCTLs use the MyArk METHOD_BUFFERED
// convention.

#pragma once

#include <ntddk.h>
#include <wdf.h>

#include "MyArkSafetyToken.h"


// ---------------------------------------------------------------------------
// Module identity + IOCTL function codes.
// ---------------------------------------------------------------------------

#define MYARK_FILE_MODULE_ID                  0x46494C45UL  // 'FILE' ASCII (LE)

//
// 2 IOCTLs (function range 0xE10..0xE1F). Method/Access match the rest of
// the driver: METHOD_BUFFERED + FILE_ANY_ACCESS.
//
#define IOCTL_MYARK_FILE_DELETE_PATH        CTL_CODE(FILE_DEVICE_UNKNOWN, 0xE10, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MYARK_FILE_QUERY_INFO         CTL_CODE(FILE_DEVICE_UNKNOWN, 0xE11, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MYARK_FILE_SET_INTEGRITY      CTL_CODE(FILE_DEVICE_UNKNOWN, 0xE12, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MYARK_FILE_QUERY_INTEGRITY    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xE13, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ---------------------------------------------------------------------------
// Limits.
// ---------------------------------------------------------------------------

#define MYARK_FILE_PATH_CHARS               520   // NT path incl. terminator (long-path capable)
#define MYARK_FILE_DELETE_FLAG_FORCE        0x00000001  // attempt POSIX-style delete even when opened by others

// SAFETY_TOKEN operations. DELETE_PATH keeps its historical value 1
// (shipped surface -- changing it is a protocol break); new operations
// use the distinct 'FILx' namespace.
#define MYARK_FILE_OP_DELETE_PATH           1
#define MYARK_FILE_OP_SET_INTEGRITY         0x324C4946UL  // 'FIL2' ASCII (LE)

// ---------------------------------------------------------------------------
// DELETE_PATH.
//
// Token-gated. Deletes a file (or an empty directory). Flags:
//   MYARK_FILE_DELETE_FLAG_FORCE -- retry with FILE_DISPOSITION_INFO_EX
//   (POSIX semantics) when the plain disposition reports a conflict. Note
//   POSIX semantics does NOT bypass sharing violations of handles opened
//   without FILE_SHARE_DELETE; it only changes same-handle delete rules.
// Output: in-band Status with the final NTSTATUS of the delete chain.
// ---------------------------------------------------------------------------

typedef struct _MYARK_FILE_DELETE_PATH_INPUT {
    MYARK_SAFETY_TOKEN Token;
    UINT32  Flags;                               // MYARK_FILE_DELETE_FLAG_*
    UINT32  Reserved1;
    WCHAR   Path[MYARK_FILE_PATH_CHARS];
} MYARK_FILE_DELETE_PATH_INPUT, *PMYARK_FILE_DELETE_PATH_INPUT;

typedef struct _MYARK_FILE_STATUS_OUTPUT {
    UINT32  Status;                              // STATUS_*
} MYARK_FILE_STATUS_OUTPUT, *PMYARK_FILE_STATUS_OUTPUT;

// ---------------------------------------------------------------------------
// QUERY_FILE_INFO.
//
// Returns FILE_BASIC_INFORMATION + FILE_STANDARD_INFORMATION derived
// fields for a file or directory. Open to any caller.
// ---------------------------------------------------------------------------

typedef struct _MYARK_FILE_QUERY_INFO_INPUT {
    WCHAR   Path[MYARK_FILE_PATH_CHARS];
} MYARK_FILE_QUERY_INFO_INPUT, *PMYARK_FILE_QUERY_INFO_INPUT;

typedef struct _MYARK_FILE_QUERY_INFO_OUTPUT {
    UINT32  Status;                              // STATUS_*
    UINT32  Attributes;                          // FILE_ATTRIBUTE_* mask
    UINT64  AllocationSize;
    UINT64  EndOfFile;
    UINT64  CreationTime;                        // 100-ns since 1601
    UINT64  LastAccessTime;
    UINT64  LastWriteTime;
    UINT32  Reserved1;
} MYARK_FILE_QUERY_INFO_OUTPUT, *PMYARK_FILE_QUERY_INFO_OUTPUT;

// ---------------------------------------------------------------------------
// SET_FILE_INTEGRITY (R2-10): token-gated write of a mandatory integrity
// label (SACL SYSTEM_MANDATORY_LABEL_ACE) onto an existing file. Win32
// paths are normalized to the NT prefix; the SYSTEM_MANDATORY_LABEL_NO_
// WRITE_UP policy bit can be requested through Flags. DEFERRED: the
// ZwSetSecurityObject write path wedges the guest (KNOWN_ISSUES
// 2026-09-16) -- the handler answers STATUS_NOT_SUPPORTED. The read-only
// QUERY (0xE13) parses the label kernel-side instead.
// ---------------------------------------------------------------------------

#define MYARK_FILE_SET_INTEGRITY_FLAG_NO_WRITE_UP   0x00000001

// Mandatory integrity RIDs (the label SID is S-1-16-<rid>).
#define MYARK_FILE_INTEGRITY_LEVEL_LOW              0x1000
#define MYARK_FILE_INTEGRITY_LEVEL_MEDIUM           0x2000
#define MYARK_FILE_INTEGRITY_LEVEL_HIGH             0x3000
#define MYARK_FILE_INTEGRITY_LEVEL_SYSTEM           0x4000

typedef struct _MYARK_FILE_SET_INTEGRITY_INPUT {
    MYARK_SAFETY_TOKEN Token;                        // op = MYARK_FILE_OP_SET_INTEGRITY
    UINT32  Level;                                   // MYARK_FILE_INTEGRITY_LEVEL_*
    UINT32  Flags;                                   // NO_WRITE_UP bit
    WCHAR   Path[MYARK_FILE_PATH_CHARS];
} MYARK_FILE_SET_INTEGRITY_INPUT, *PMYARK_FILE_SET_INTEGRITY_INPUT;

// QUERY_FILE_INTEGRITY output: the first SYSTEM_MANDATORY_LABEL_ACE on
// the object (LabelFound 0 when the SACL has no label ACE).
typedef struct _MYARK_FILE_QUERY_INTEGRITY_INPUT {
    WCHAR   Path[MYARK_FILE_PATH_CHARS];             // no token: read-only
} MYARK_FILE_QUERY_INTEGRITY_INPUT, *PMYARK_FILE_QUERY_INTEGRITY_INPUT;

typedef struct _MYARK_FILE_QUERY_INTEGRITY_OUTPUT {
    UINT32  Status;                                  // 0 = queried
    UINT32  LabelFound;                              // 1 when a label ACE exists
    UINT32  Level;                                   // label RID
    UINT32  Flags;                                   // policy mask
} MYARK_FILE_QUERY_INTEGRITY_OUTPUT, *PMYARK_FILE_QUERY_INTEGRITY_OUTPUT;
