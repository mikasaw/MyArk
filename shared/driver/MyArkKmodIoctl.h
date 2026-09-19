// MyArk "kmod" (kernel-driver enumeration) module: shared IOCTL protocol.
//
// Function range 0xC20..0xC2F reserved for the kernel-driver walker. This
// is *not* the python-module registry (which lives at 0x810..0x81F); it is
// the kernel-side DriverObject walker that powers the
// ``myark-cli module query-driver-object`` / ``query-ioctl-registry`` CLI.
//
// All 2 IOCTLs follow the MyArk METHOD_BUFFERED convention.
//
// Header name: "kmod" (kernel-module) so it does not collide with the
// python-module registry header MyArkModuleIoctl.h. The C-side module
// descriptor + R3 python package still use the friendly name "module".

#pragma once

#include <ntddk.h>
#include <wdf.h>

// ---------------------------------------------------------------------------
// Module identity + IOCTL function codes.
// ---------------------------------------------------------------------------

#define MYARK_KMODULE_MODULE_ID             0x444F4D4BUL  // 'KMOD' ASCII (LE)
#define MYARK_KMODULE_NAME_MAX               64
#define MYARK_KMODULE_DRIVER_PATH_MAX        260
#define MYARK_KMODULE_DEFAULT_MAX            128
#define MYARK_KMODULE_HARD_CAP               4096

//
// 2 IOCTLs (function range 0xC20..0xC21). Method/Access match the rest of
// the driver: METHOD_BUFFERED + FILE_ANY_ACCESS.
//
#define IOCTL_MYARK_MODULE_QUERY_DRIVER_OBJECT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xC20, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_MODULE_QUERY_IOCTL_REGISTRY \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xC21, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ---------------------------------------------------------------------------
// QUERY_DRIVER_OBJECT output: one row per driver on IoDriverListHead.
//
// DriverName is the service-key name (DriverObject->DriverName.Buffer up
// to the first backslash). DriverPath is the RegistryPath that was used
// to load the driver -- if MmLoadSystemImage loaded it anonymously this
// falls back to "<anonymous>". Flags surface the major-function-table
// presence and a tamper hint when none of the standard function indices
// are populated (a common DKOM tell).
// ---------------------------------------------------------------------------

#define MYARK_KMODULE_FLAG_NONE             0x00000000
#define MYARK_KMODULE_FLAG_HAS_MAJOR_TABLE  0x00000001   // DriverObject->MajorFunction populated
#define MYARK_KMODULE_FLAG_HAS_FAST_IO      0x00000002   // DriverObject->FastIoDispatch present
#define MYARK_KMODULE_FLAG_ANONYMOUS        0x00000004   // RegistryPath empty (MmLoadSystemImage)
#define MYARK_KMODULE_FLAG_BOOT_DRIVER      0x00000008   // loaded by boot loader (DriverStart != NULL but not IoCreateDriver)

typedef struct _MYARK_KMODULE_ENTRY {
    UINT64  DriverObjectAddress;                            // kernel VA of the DRIVER_OBJECT
    UINT64  DriverStartAddress;                             // image base
    UINT64  DriverSize;
    UINT32  Flags;                                          // MYARK_KMODULE_FLAG_*
    UINT32  MajorFunctionCount;                             // count of populated major-function slots (best-effort)
    WCHAR   DriverName[MYARK_KMODULE_NAME_MAX];
    WCHAR   DriverPath[MYARK_KMODULE_DRIVER_PATH_MAX];
} MYARK_KMODULE_ENTRY, *PMYARK_KMODULE_ENTRY;

typedef struct _MYARK_MODULE_QUERY_DRIVER_OBJECT_INPUT {
    UINT32  MaxEntries;                                     // 0 = driver default
    UINT32  Reserved0;
    UINT32  Reserved1;
    UINT32  Reserved2;
} MYARK_MODULE_QUERY_DRIVER_OBJECT_INPUT, *PMYARK_MODULE_QUERY_DRIVER_OBJECT_INPUT;

typedef struct _MYARK_MODULE_QUERY_DRIVER_OBJECT_OUTPUT {
    UINT32  Size;
    UINT32  Count;
    UINT32  TotalSeen;
    UINT32  Reserved;
    MYARK_KMODULE_ENTRY Entries[1];
} MYARK_MODULE_QUERY_DRIVER_OBJECT_OUTPUT, *PMYARK_MODULE_QUERY_DRIVER_OBJECT_OUTPUT;

// ---------------------------------------------------------------------------
// QUERY_IOCTL_REGISTRY output: one row per IRP_MJ_DEVICE_CONTROL entry on
// the major-function table across all loaded drivers.
//
// The driver walks every entry on IoDriverListHead, then walks the 28
// entries of MajorFunction[IRP_MJ_DEVICE_CONTROL] -- actually we only
// emit the IRP_MJ_DEVICE_CONTROL slot because the request asks for
// IOCTL dispatch table views. Each row carries the driver name + the
// kernel VA of the dispatch function. R3 can then compare against the
// known IOCTL map to detect hookers.
// ---------------------------------------------------------------------------

#define MYARK_IOCTL_REG_FLAG_NONE           0x00000000
#define MYARK_IOCTL_REG_FLAG_POPULATED      0x00000001   // dispatch != IopInvalidDeviceRequest
#define MYARK_IOCTL_REG_FLAG_SUSPECT        0x00000002   // dispatch lives outside the .text of the owning driver (heuristic)

typedef struct _MYARK_IOCTL_REG_ENTRY {
    UINT64  DriverObjectAddress;
    UINT64  DispatchAddress;                                // kernel VA of the IRP_MJ_DEVICE_CONTROL handler
    UINT32  Flags;                                          // MYARK_IOCTL_REG_FLAG_*
    UINT32  Reserved0;
    WCHAR   DriverName[MYARK_KMODULE_NAME_MAX];
} MYARK_IOCTL_REG_ENTRY, *PMYARK_IOCTL_REG_ENTRY;

typedef struct _MYARK_MODULE_QUERY_IOCTL_REGISTRY_INPUT {
    UINT32  MaxEntries;                                     // 0 = driver default
    UINT32  Reserved0;
    UINT32  Reserved1;
    UINT32  Reserved2;
} MYARK_MODULE_QUERY_IOCTL_REGISTRY_INPUT, *PMYARK_MODULE_QUERY_IOCTL_REGISTRY_INPUT;

typedef struct _MYARK_MODULE_QUERY_IOCTL_REGISTRY_OUTPUT {
    UINT32  Size;
    UINT32  Count;
    UINT32  TotalSeen;
    UINT32  Reserved;
    MYARK_IOCTL_REG_ENTRY Entries[1];
} MYARK_MODULE_QUERY_IOCTL_REGISTRY_OUTPUT, *PMYARK_MODULE_QUERY_IOCTL_REGISTRY_OUTPUT;
