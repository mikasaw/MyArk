// MyArk redirect module: shared IOCTL protocol between R0 and R3.
//
// Function range 0x740..0x741 reserved for the redirect module (S7.3).
// Redirect is read-only for S7.3: the IOCTL set inspects IoCallDriver
// / CmCallback redirection chains on the running build. The
// do-redirect IOCTLs are reserved for the S7.3-fix stage and return
// STATUS_NOT_IMPLEMENTED on dispatch.
//
// The 2 IOCTLs:
//
//   0x740  INSPECT_REDIRECT  - Inspect registered redirect targets
//   0x741  APPLY_REDIRECT    - Apply a redirect (reserved; S7.3-fix)
//
// All 2 IOCTLs use the MyArk METHOD_BUFFERED convention.

#pragma once

#include <ntddk.h>
#include <wdf.h>

#include "MyArkSafetyToken.h"

// ---------------------------------------------------------------------------
// Module identity + IOCTL function codes.
// ---------------------------------------------------------------------------

#define MYARK_REDIRECT_MODULE_ID              0x52454450UL  // 'REDP' ASCII (LE)
#define MYARK_REDIRECT_NAME_MAX               64
#define MYARK_REDIRECT_HARD_CAP               64

//
// 2 IOCTLs (function range 0x740..0x741). Method/Access match the rest
// of the driver: METHOD_BUFFERED + FILE_ANY_ACCESS.
//
#define IOCTL_MYARK_REDIRECT_INSPECT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x740, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_REDIRECT_APPLY \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x741, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// INSPECT_REDIRECT input: optional filter (0 = all).
// ---------------------------------------------------------------------------
//

typedef struct _MYARK_REDIRECT_INSPECT_INPUT {
    UINT32  TargetPid;
    UINT32  Reserved;
    UINT64  Reserved2;
} MYARK_REDIRECT_INSPECT_INPUT, *PMYARK_REDIRECT_INSPECT_INPUT;

//
// INSPECT_REDIRECT output: list of registered redirects.
// ---------------------------------------------------------------------------
//

typedef struct _MYARK_REDIRECT_ENTRY {
    UINT64  OriginalAddress;
    UINT64  RedirectAddress;
    UINT32  RedirectType;                          // IRP / Cm / Ob
    UINT32  Reserved;
    WCHAR   DriverName[MYARK_REDIRECT_NAME_MAX];
} MYARK_REDIRECT_ENTRY, *PMYARK_REDIRECT_ENTRY;

#define MYARK_REDIRECT_TYPE_NONE              0
#define MYARK_REDIRECT_TYPE_IRP               1
#define MYARK_REDIRECT_TYPE_CM                2
#define MYARK_REDIRECT_TYPE_OB                3

typedef struct _MYARK_REDIRECT_INSPECT_OUTPUT {
    UINT32  Count;
    UINT32  Reserved;
    MYARK_REDIRECT_ENTRY Entries[1];
} MYARK_REDIRECT_INSPECT_OUTPUT, *PMYARK_REDIRECT_INSPECT_OUTPUT;

//
// APPLY_REDIRECT input (reserved; S7.3-fix).
// ---------------------------------------------------------------------------
typedef struct _MYARK_REDIRECT_APPLY_INPUT {
    UINT64  OriginalAddress;
    UINT64  RedirectAddress;
    UINT32  RedirectType;
    UINT32  Reserved;
} MYARK_REDIRECT_APPLY_INPUT, *PMYARK_REDIRECT_APPLY_INPUT;

// ---------------------------------------------------------------------------
// R2-9: our own file/registry redirect engine (distinct from the S7.3
// INSPECT surface above, which only reports other drivers' redirects).
//
// SET_RULES atomically replaces the whole rule set (TOKEN-gated, 'RRD1');
// QUERY_STATUS is a read-only snapshot. With no rules armed nothing is
// hooked: the file side rides the R2-7 minifilter's IRP_MJ_CREATE pre-op
// (pass-through when no file rules), the registry side registers its
// CmCallback only while REG rules exist. File rules rewrite
// FILE_OBJECT->FileName (volume-relative remainder); REG rules rewrite
// the VALUE DATA at query time (CmCallback around NtQueryValueKey: pre
// parks the caller buffer in CallContext, post writes REG_SZ shadow
// data, buffer-too-small answers STATUS_BUFFER_OVERFLOW with the
// required size). Limits: value-content replacement only -- absent
// value names, enumeration and QueryMultipleValueKey are not served.
// (CompleteName swaps at pre-open are NOT honored: the path is parsed
// before the callback runs.)
// ---------------------------------------------------------------------------

// 2 IOCTLs (function range 0x827..0x828, ROADMAP R2-9).
#define IOCTL_MYARK_REDIRECT_SET_RULES     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x827, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_REDIRECT_QUERY_STATUS     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x828, METHOD_BUFFERED, FILE_ANY_ACCESS)

// SAFETY_TOKEN operation (distinct namespace, one per mutating surface).
#define MYARK_REDIRECT_OP_SET_RULES          0x31445252UL  // 'RRD1' ASCII (LE)

#define MYARK_REDIRECT_RULE_CHARS            260   // path cap incl. NUL
#define MYARK_REDIRECT_MAX_RULES             16
#define MYARK_REDIRECT_SET_FLAG_CLEAR_ALL    0x00000001

#define MYARK_REDIRECT_RULE_KIND_FILE        1     // DOS paths, exact match
#define MYARK_REDIRECT_RULE_KIND_REG         2     // full NT key paths

typedef struct _MYARK_REDIRECT_RULE {
    UINT32  Kind;                                // MYARK_REDIRECT_RULE_KIND_*
    UINT32  Flags;                               // reserved, must be 0
    WCHAR   Source[MYARK_REDIRECT_RULE_CHARS];   // file: "C:\dir\src" / reg: "\REGISTRY\MACHINE\..."
    WCHAR   Target[MYARK_REDIRECT_RULE_CHARS];   // FILE: DOS shadow path (same volume)
                                                 // REG:  value name to shadow
    WCHAR   Data[MYARK_REDIRECT_RULE_CHARS];     // REG only: shadow value data (REG_SZ)
} MYARK_REDIRECT_RULE, *PMYARK_REDIRECT_RULE;

// Input: header + Count rules (variable tail). Count=0 (or CLEAR_ALL) with
// a valid token clears the whole set and unregisters the Cm callback --
// that is the "restore after close" path.
typedef struct _MYARK_REDIRECT_SET_RULES_INPUT {
    MYARK_SAFETY_TOKEN Token;                    // op = MYARK_REDIRECT_OP_SET_RULES
    UINT32  Count;                               // 0..MYARK_REDIRECT_MAX_RULES
    UINT32  Flags;                               // MYARK_REDIRECT_SET_FLAG_*
    MYARK_REDIRECT_RULE Rules[1];                // Count entries
} MYARK_REDIRECT_SET_RULES_INPUT, *PMYARK_REDIRECT_SET_RULES_INPUT;

typedef struct _MYARK_REDIRECT_SET_RULES_OUTPUT {
    UINT32  Status;                              // in-band NTSTATUS
    UINT32  Accepted;                            // rules armed
    UINT32  FileRules;
    UINT32  RegRules;
} MYARK_REDIRECT_SET_RULES_OUTPUT, *PMYARK_REDIRECT_SET_RULES_OUTPUT;

// Read-only snapshot. Hits accumulate while armed and reset on CLEAR.
typedef struct _MYARK_REDIRECT_STATUS_OUTPUT {
    UINT32  Status;                              // 0 = queried
    UINT32  FileRules;                           // armed file rules
    UINT32  RegRules;                            // armed registry rules
    UINT32  FileHits;                            // pre-create rewrites served
    UINT32  RegHits;                             // Cm CompleteName swaps served
    UINT32  CmRegistered;                        // CmCallback attached (1/0)
    UINT32  Reserved1;                           // diagnostic: query-pre entries
    UINT32  Reserved2;                           // diagnostic: contexts parked
} MYARK_REDIRECT_STATUS_OUTPUT, *PMYARK_REDIRECT_STATUS_OUTPUT;
