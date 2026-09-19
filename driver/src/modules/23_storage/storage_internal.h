// MyArk storage module: within-module offsets + helpers.
//
// DEVICE_OBJECT layout (Win11 24H2):
//   0x000 Type                (USHORT)
//   0x008 AttachedDevice      (PDEVICE_OBJECT) -- the device above us
//   0x010 DeviceType          (DEVICE_TYPE)
//   0x018 Characteristics     (ULONG)
//   0x020 Flags               (ULONG -- DO_*)
//   0x030 DriverObject        (PVOID)
//   0x038 NextDevice          (PVOID)
//   0x040 AttachedTo          (PVOID) -- the device below us
//   0x048 Vpb                 (PVOID) -- volume parameter block (volumes only)
//   0x050 DeviceExtension     (PVOID)
//
// IoDeviceObjectListHead -- global walk of all device objects (kernel
// export).

#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "../../../shared/driver/MyArkStorageIoctl.h"

#if MYARK_MODULE_STORAGE

#define MYARK_OFF_DO_ATTACHED_DEVICE        0x008UL
#define MYARK_OFF_DO_DRIVER_OBJECT          0x030UL
#define MYARK_OFF_DO_NEXT_DEVICE            0x038UL
#define MYARK_OFF_DO_ATTACHED_TO            0x040UL
#define MYARK_OFF_DO_VPB                    0x048UL
#define MYARK_OFF_DO_TYPE                   0x000UL

extern LIST_ENTRY IoDeviceObjectListHead;

#define MYARK_TRACE_STORAGE                 MYARK_TRACE_MODULE

#endif // MYARK_MODULE_STORAGE
