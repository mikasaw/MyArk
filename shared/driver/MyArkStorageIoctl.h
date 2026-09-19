// MyArk storage module: shared IOCTL protocol between R0 and R3.
//
// Function range 0xC30..0xC3F reserved for the storage module. Process
// 0xA00..0xAFF, memory 0xB00..0xBFF, handle 0xC00..0xC0F, section 0xC10..
// 0xC1F, kernel-module 0xC20..0xC2F -- so storage sits at 0xC30. All 4
// IOCTLs follow the MyArk METHOD_BUFFERED convention.
//
// The storage module walks the filter-driver stack:
//
//   VOLUME_STACK       -- IoVolumeDeviceObject->Vpb->DeviceObject (and
//                         each filter above it) for a given VolumeDevice
//   BITLOCKER          -- FltMgr callback list: surface the FVE filter
//                         per-volume plus the encrypted-bit count
//   MOUNTMGR_MAPPING   -- mountmgr's mount-point -> device-name map
//                         (DeviceName + SymbolicLinkName pairs)
//   FS_INTEGRITY       -- USN journal state (volume handle -> state flag
//                         and reason string); we do NOT parse USN records

#pragma once

#include <ntddk.h>
#include <wdf.h>

// ---------------------------------------------------------------------------
// Module identity + IOCTL function codes.
// ---------------------------------------------------------------------------

#define MYARK_STORAGE_MODULE_ID             0x524F5453UL  // 'STOR' ASCII (LE)
#define MYARK_STORAGE_NAME_MAX               64
#define MYARK_STORAGE_PATH_MAX               260
#define MYARK_STORAGE_DEFAULT_MAX            32
#define MYARK_STORAGE_HARD_CAP               1024

//
// 4 IOCTLs (function range 0xC30..0xC33). Method/Access match the rest of
// the driver: METHOD_BUFFERED + FILE_ANY_ACCESS.
//
#define IOCTL_MYARK_STORAGE_QUERY_VOLUME_STACK \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xC30, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_STORAGE_QUERY_BITLOCKER \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xC31, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_STORAGE_QUERY_MOUNTMGR_MAPPING \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xC32, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_STORAGE_QUERY_FS_INTEGRITY \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xC33, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ---------------------------------------------------------------------------
// VOLUME_STACK input / output.
//
// Input is the user-visible volume letter (e.g. L"C:") or a raw device
// path (e.g. L"\\Device\\HarddiskVolume2"). Output lists the device objects
// in the stack from top (FSD-relative) to bottom (storage port driver),
// each tagged with its driver name when available.
// ---------------------------------------------------------------------------

#define MYARK_VOLUME_LAYER_NONE             0
#define MYARK_VOLUME_LAYER_TOP              1             // FSD-relative top
#define MYARK_VOLUME_LAYER_FILTER           2
#define MYARK_VOLUME_LAYER_FS               3             // file system driver
#define MYARK_VOLUME_LAYER_VOLUME           4
#define MYARK_VOLUME_LAYER_DISK             5
#define MYARK_VOLUME_LAYER_PARTITION        6
#define MYARK_VOLUME_LAYER_BOTTOM           7

#define MYARK_VOLUME_FLAG_NONE              0x00000000
#define MYARK_VOLUME_FLAG_REMOVABLE         0x00000001
#define MYARK_VOLUME_FLAG_READ_ONLY         0x00000002
#define MYARK_VOLUME_FLAG_ENCRYPTED         0x00000004   // FVE filter present
#define MYARK_VOLUME_FLAG_HIDDEN            0x00000008   // mountmgr has it but no drive letter

typedef struct _MYARK_VOLUME_STACK_ENTRY {
    UINT64  DeviceObjectAddress;
    UINT32  Layer;                                          // MYARK_VOLUME_LAYER_*
    UINT32  Flags;                                          // MYARK_VOLUME_FLAG_*
    UINT32  StackDepth;                                     // 0 = top of stack
    UINT32  Reserved0;
    WCHAR   DriverName[MYARK_STORAGE_NAME_MAX];
    WCHAR   DeviceName[MYARK_STORAGE_PATH_MAX];
} MYARK_VOLUME_STACK_ENTRY, *PMYARK_VOLUME_STACK_ENTRY;

typedef struct _MYARK_STORAGE_VOLUME_STACK_INPUT {
    WCHAR   VolumeOrDevice[MYARK_STORAGE_PATH_MAX];         // e.g. L"C:" or L"\\Device\\HarddiskVolume2"
    UINT32  Reserved0;
    UINT32  Reserved1;
} MYARK_STORAGE_VOLUME_STACK_INPUT, *PMYARK_STORAGE_VOLUME_STACK_INPUT;

typedef struct _MYARK_STORAGE_VOLUME_STACK_OUTPUT {
    UINT32  Size;
    UINT32  Count;
    UINT32  Reserved0;
    UINT32  Reserved1;
    MYARK_VOLUME_STACK_ENTRY Entries[1];
} MYARK_STORAGE_VOLUME_STACK_OUTPUT, *PMYARK_STORAGE_VOLUME_STACK_OUTPUT;

// ---------------------------------------------------------------------------
// BITLOCKER output.
//
// One row per volume for which the FVE filter driver is attached. The
// driver walks the global IoDeviceObject tree and reports each device
// whose attached top-driver has the FVE service name.
// ---------------------------------------------------------------------------

typedef struct _MYARK_BITLOCKER_ENTRY {
    UINT64  VolumeDeviceAddress;
    UINT32  Encrypted;                                      // 1 if FVE filter active, 0 otherwise
    UINT32  Protection;                                     // bitmask: 1 = encrypted, 2 = locked, 4 = key protectors present (best-effort)
    UINT32  Reserved0;
    UINT32  Reserved1;
    WCHAR   VolumeName[MYARK_STORAGE_PATH_MAX];             // e.g. L"\\Device\\HarddiskVolume2"
} MYARK_BITLOCKER_ENTRY, *PMYARK_BITLOCKER_ENTRY;

typedef struct _MYARK_STORAGE_BITLOCKER_OUTPUT {
    UINT32  Size;
    UINT32  Count;
    UINT32  Reserved0;
    UINT32  Reserved1;
    MYARK_BITLOCKER_ENTRY Entries[1];
} MYARK_STORAGE_BITLOCKER_OUTPUT, *PMYARK_STORAGE_BITLOCKER_OUTPUT;

// ---------------------------------------------------------------------------
// MOUNTMGR_MAPPING output: symbolic-link -> device-name pairs.
//
// The driver queries the mount manager's device map via a private IOCTL
// path; if the mount manager is not available it falls back to walking
// the OBJECT_DIRECTORY for "\Global??". The OutputCount and TotalSeen
// help R3 distinguish "no mappings" from "mount manager unavailable".
// ---------------------------------------------------------------------------

typedef struct _MYARK_MOUNTMGR_ENTRY {
    WCHAR   SymbolicLink[MYARK_STORAGE_PATH_MAX];           // e.g. L"C:"
    WCHAR   DeviceName[MYARK_STORAGE_PATH_MAX];             // e.g. L"\\Device\\HarddiskVolume2"
    UINT32  Reserved0;
    UINT32  Reserved1;
} MYARK_MOUNTMGR_ENTRY, *PMYARK_MOUNTMGR_ENTRY;

typedef struct _MYARK_STORAGE_MOUNTMGR_OUTPUT {
    UINT32  Size;
    UINT32  Count;
    UINT32  Source;                                         // 0 = mount manager, 1 = Global?? fallback, 2 = both merged
    UINT32  Reserved;
    MYARK_MOUNTMGR_ENTRY Entries[1];
} MYARK_STORAGE_MOUNTMGR_OUTPUT, *PMYARK_STORAGE_MOUNTMGR_OUTPUT;

// ---------------------------------------------------------------------------
// FS_INTEGRITY output: per-volume USN journal state, NO record contents.
//
// The driver opens the USN journal metadata on each volume via
// FSCTL_QUERY_USN_JOURNAL and reports volume + state. We never copy
// USN_RECORD_V2 / V3 bytes -- record enumeration is out of scope for
// this module; R3 consumes USN via fsutil / managed APIs.
// ---------------------------------------------------------------------------

#define MYARK_FS_INTEGRITY_STATE_UNKNOWN    0
#define MYARK_FS_INTEGRITY_STATE_CLEAN      1
#define MYARK_FS_INTEGRITY_STATE_DIRTY      2
#define MYARK_FS_INTEGRITY_STATE_DISABLED   3
#define MYARK_FS_INTEGRITY_STATE_ERROR      4

typedef struct _MYARK_FS_INTEGRITY_ENTRY {
    WCHAR   VolumeName[MYARK_STORAGE_PATH_MAX];
    UINT32  State;                                          // MYARK_FS_INTEGRITY_STATE_*
    UINT32  Reserved0;
    UINT64  UsnJournalId;                                   // 0 when unknown
    UINT64  FirstUsn;                                       // 0 when unknown
    UINT64  NextUsn;                                        // 0 when unknown
} MYARK_FS_INTEGRITY_ENTRY, *PMYARK_FS_INTEGRITY_ENTRY;

typedef struct _MYARK_STORAGE_FS_INTEGRITY_OUTPUT {
    UINT32  Size;
    UINT32  Count;
    UINT32  Reserved0;
    UINT32  Reserved1;
    MYARK_FS_INTEGRITY_ENTRY Entries[1];
} MYARK_STORAGE_FS_INTEGRITY_OUTPUT, *PMYARK_STORAGE_FS_INTEGRITY_OUTPUT;
