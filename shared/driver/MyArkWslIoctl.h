// MyArk WSL module: shared IOCTL protocol between R0 and R3.
//
// Function range 0x780 reserved for the WSL (Windows Subsystem for
// Linux) module (S7.3). WSL inspection is read-only for S7.3: the
// IOCTL set enumerates the active WSL silos on the running build.
//
// The 1 IOCTL:
//
//   0x780  ENUMERATE_SILOS   - List WSL silos
//
// All 1 IOCTLs use the MyArk METHOD_BUFFERED convention.

#pragma once

#include <ntddk.h>
#include <wdf.h>

// ---------------------------------------------------------------------------
// Module identity + IOCTL function codes.
// ---------------------------------------------------------------------------

#define MYARK_WSL_MODULE_ID                   0x57534C00UL  // 'WSL\0' ASCII (LE)
#define MYARK_WSL_DISTRO_NAME_MAX             64
#define MYARK_WSL_HARD_CAP                    16

//
// 1 IOCTL (function range 0x780). Method/Access match the rest of the
// driver: METHOD_BUFFERED + FILE_ANY_ACCESS.
//
#define IOCTL_MYARK_WSL_ENUMERATE_SILOS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x780, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// ENUMERATE_SILOS output: each WSL silo + distro name.
// ---------------------------------------------------------------------------
//

typedef struct _MYARK_WSL_SILO_ENTRY {
    UINT64  SiloAddress;
    UINT32  SiloId;
    UINT32  Flags;                                // bit0 = active, bit1 = default
    UINT32  DistroCount;
    UINT32  Reserved;
    WCHAR   DistroName[MYARK_WSL_DISTRO_NAME_MAX];
} MYARK_WSL_SILO_ENTRY, *PMYARK_WSL_SILO_ENTRY;

typedef struct _MYARK_WSL_SILOS_OUTPUT {
    UINT32  Count;
    UINT32  Reserved;
    MYARK_WSL_SILO_ENTRY Entries[1];
} MYARK_WSL_SILOS_OUTPUT, *PMYARK_WSL_SILOS_OUTPUT;