// MyArk preflight module: shared IOCTL protocol between R0 and R3.
//
// Function range 0x7C0 reserved for the preflight (environment health
// check) module (S7.3). Preflight is R3-primary: bcdedit + GetVersionEx
// + WMI for driver signing state. The driver can also report OS build
// + kernel base for completeness.
//
// The 1 IOCTL:
//
//   0x7C0  HEALTH            - Environment health snapshot
//
// All 1 IOCTLs use the MyArk METHOD_BUFFERED convention.

#pragma once

#include <ntddk.h>
#include <wdf.h>

// ---------------------------------------------------------------------------
// Module identity + IOCTL function codes.
// ---------------------------------------------------------------------------

#define MYARK_PREFLIGHT_MODULE_ID             0x50464C54UL  // 'PFLT' ASCII (LE)
#define MYARK_PREFLIGHT_NOTE_MAX              128

//
// 1 IOCTL (function range 0x7C0). Method/Access match the rest of the
// driver: METHOD_BUFFERED + FILE_ANY_ACCESS.
//
#define IOCTL_MYARK_PREFLIGHT_HEALTH \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x7C0, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// HEALTH output: environment health snapshot.
// ---------------------------------------------------------------------------
//

typedef struct _MYARK_PREFLIGHT_HEALTH_OUTPUT {
    UINT32  MajorVersion;
    UINT32  MinorVersion;
    UINT32  BuildNumber;
    UINT32  Revision;
    UINT32  IsTestSigning;                        // bcdedit testsigning
    UINT32  IsSecureBoot;                         // from EFI variable
    UINT32  IsDriverSigned;                       // from g_ci state
    UINT32  Flags;                                // bit0 = safe-mode, bit1 = debug
    UINT64  KernelBase;
    UINT64  KernelSize;
    WCHAR   Note[MYARK_PREFLIGHT_NOTE_MAX];
} MYARK_PREFLIGHT_HEALTH_OUTPUT, *PMYARK_PREFLIGHT_HEALTH_OUTPUT;

#define MYARK_PREFLIGHT_FLAG_SAFE_MODE        0x00000001UL
#define MYARK_PREFLIGHT_FLAG_DEBUG            0x00000002UL