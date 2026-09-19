// MyArk capability module: shared IOCTL protocol between R0 and R3.
//
// Function range 0x7E0 reserved for the capability module (S7.3).
// Capability reporting is R0-primary: the driver publishes its
// build-time feature list (modules, IOCTL counts, version) so R3 can
// render a "what does this build support" view without probing each
// IOCTL.
//
// The 1 IOCTL:
//
//   0x7E0  REPORT             - Self-reported capability table
//
// All 1 IOCTLs use the MyArk METHOD_BUFFERED convention.

#pragma once

#include <ntddk.h>
#include <wdf.h>

// ---------------------------------------------------------------------------
// Module identity + IOCTL function codes.
// ---------------------------------------------------------------------------

#define MYARK_CAPABILITY_MODULE_ID            0x43415000UL  // 'CAP\0' ASCII (LE)
#define MYARK_CAPABILITY_NAME_MAX             32
#define MYARK_CAPABILITY_HARD_CAP             64

//
// 1 IOCTL (function range 0x7E0). Method/Access match the rest of the
// driver: METHOD_BUFFERED + FILE_ANY_ACCESS.
//
#define IOCTL_MYARK_CAPABILITY_REPORT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x7E0, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// REPORT output header + per-module rows.
// ---------------------------------------------------------------------------
//

typedef struct _MYARK_CAPABILITY_MODULE_ENTRY {
    UINT32  ModuleId;
    UINT32  IoctlCount;
    UINT32  Flags;                                // bit0 = R0, bit1 = R3, bit2 = enabled
    UINT32  Reserved;
    WCHAR   ModuleName[MYARK_CAPABILITY_NAME_MAX];
} MYARK_CAPABILITY_MODULE_ENTRY, *PMYARK_CAPABILITY_MODULE_ENTRY;

#define MYARK_CAPABILITY_FLAG_R0              0x00000001UL
#define MYARK_CAPABILITY_FLAG_R3              0x00000002UL
#define MYARK_CAPABILITY_FLAG_ENABLED         0x00000004UL

typedef struct _MYARK_CAPABILITY_REPORT_OUTPUT {
    UINT32  DriverVersionMajor;
    UINT32  DriverVersionMinor;
    UINT32  DriverVersionBuild;
    UINT32  Reserved;
    UINT32  TotalModules;
    UINT32  TotalIoctls;
    UINT32  Reserved2;
    UINT32  Reserved3;
    MYARK_CAPABILITY_MODULE_ENTRY Entries[1];
} MYARK_CAPABILITY_REPORT_OUTPUT, *PMYARK_CAPABILITY_REPORT_OUTPUT;