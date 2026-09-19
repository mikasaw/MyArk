// MyArk storage module: descriptor + IOCTL table.
//
// Walks the filter-driver stack and the mount manager's mapping table
// to surface storage-related artifacts:
//
//   VOLUME_STACK       -- per-volume filter stack (top to bottom)
//   BITLOCKER          -- FVE filter presence per volume
//   MOUNTMGR_MAPPING   -- symbolic link -> device name pairs
//   FS_INTEGRITY       -- USN journal state per volume (no record contents)

#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "module_descriptor.h"

#if MYARK_MODULE_STORAGE

NTSTATUS MyArkStorageInit(VOID);
VOID     MyArkStorageCleanup(VOID);

NTSTATUS MyArkStorageIoctlQueryVolumeStack(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned);

NTSTATUS MyArkStorageIoctlQueryBitlocker(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned);

NTSTATUS MyArkStorageIoctlQueryMountmgrMapping(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned);

NTSTATUS MyArkStorageIoctlQueryFsIntegrity(
    _In_  WDFDEVICE  Device,
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ size_t*    BytesReturned);

extern MYARK_MODULE_DESCRIPTOR g_MyArkModule_Storage;

#endif // MYARK_MODULE_STORAGE
