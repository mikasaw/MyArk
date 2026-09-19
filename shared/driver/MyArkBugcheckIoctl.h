// MyArk bugcheck module: shared IOCTL protocol between R0 and R3.
//
// Function range 0x760..0x761 reserved for the bugcheck / crash
// diagnostic module (S7.3). Bugcheck inspection is read-only for S7.3:
// the IOCTL set reports the last bugcheck record and (optionally)
// renders diagnostic info to the SVGA framebuffer. The trigger-blue
// IOCTL is reserved for the S7.3-fix stage and returns
// STATUS_NOT_IMPLEMENTED on dispatch.
//
// The 2 IOCTLs:
//
//   0x760  QUERY             - Query last bugcheck parameters
//   0x761  RENDER_DIAG       - Render diagnostic to framebuffer
//
// All 2 IOCTLs use the MyArk METHOD_BUFFERED convention.

#pragma once

#include <ntddk.h>
#include <wdf.h>

// ---------------------------------------------------------------------------
// Module identity + IOCTL function codes.
// ---------------------------------------------------------------------------

#define MYARK_BUGCHECK_MODULE_ID              0x4243484BUL  // 'BCHK' ASCII (LE)
#define MYARK_BUGCHECK_TEXT_MAX               256

//
// 2 IOCTLs (function range 0x760..0x761). Method/Access match the rest
// of the driver: METHOD_BUFFERED + FILE_ANY_ACCESS.
//
#define IOCTL_MYARK_BUGCHECK_QUERY \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x760, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_BUGCHECK_RENDER_DIAG \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x761, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// QUERY output: last bugcheck record.
// ---------------------------------------------------------------------------
//

typedef struct _MYARK_BUGCHECK_RECORD {
    UINT32  BugCheckCode;
    UINT32  Reserved1;
    UINT64  Parameter1;
    UINT64  Parameter2;
    UINT64  Parameter3;
    UINT64  Parameter4;
    UINT64  Timestamp;                            // QPC tick
} MYARK_BUGCHECK_RECORD, *PMYARK_BUGCHECK_RECORD;

typedef struct _MYARK_BUGCHECK_QUERY_OUTPUT {
    UINT32  HasRecord;
    UINT32  Reserved;
    MYARK_BUGCHECK_RECORD Record;
} MYARK_BUGCHECK_QUERY_OUTPUT, *PMYARK_BUGCHECK_QUERY_OUTPUT;

//
// RENDER_DIAG input: UTF-16LE text + optional color.
// ---------------------------------------------------------------------------
typedef struct _MYARK_BUGCHECK_RENDER_INPUT {
    UINT32  ForegroundColor;
    UINT32  BackgroundColor;
    UINT32  X;
    UINT32  Y;
    WCHAR   Text[MYARK_BUGCHECK_TEXT_MAX];
} MYARK_BUGCHECK_RENDER_INPUT, *PMYARK_BUGCHECK_RENDER_INPUT;