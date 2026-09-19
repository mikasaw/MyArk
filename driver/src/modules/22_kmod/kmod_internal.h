// MyArk kmod module: within-module offsets + helpers.
//
// DRIVER_OBJECT layout (Win11 24H2):
//   0x00  Type                -- 4
//   0x08  DeviceObject        -- first device in the driver
//   0x10  Flags               -- DRVO_*
//   0x18  DriverStart         -- image base
//   0x20  DriverSize          -- image size
//   0x28  DriverSection       -- MmSection pointer
//   0x30  DriverExtension     -- _DRIVER_EXTENSION pointer
//   0x38  DriverName          -- UNICODE_STRING (length + buffer)
//   0x48  HardwareDatabase    -- device-map path
//   0x50  FastIoDispatch      -- _FAST_IO_DISPATCH pointer
//   0x58  DriverInit          -- entry point
//   0x60  DriverStartIo       -- legacy startio
//   0x68  DriverUnload        -- unload handler
//   0x70  MajorFunction[28]   -- IRP_MJ_* dispatch table
//
// IoDriverListHead is the global list head; the DriverObject link sits
// at offset 0x70 (the DriverEntry field of the _DRIVER_EXTENSION), but
// the linkage we're after is at offset 0x18 (DriverSection -> common
// record). For this stage we walk via the DriverObject struct itself
// using the loader list (DriverObject->DriverSection->ls.ListEntry).

#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "../../../shared/driver/MyArkKmodIoctl.h"

#if MYARK_MODULE_KMODULE

#define MYARK_OFF_DRV_TYPE                  0x000UL
#define MYARK_OFF_DRV_DEVICE_OBJECT         0x008UL
#define MYARK_OFF_DRV_FLAGS                 0x010UL
#define MYARK_OFF_DRV_DRIVER_START          0x018UL
#define MYARK_OFF_DRV_DRIVER_SIZE           0x020UL
#define MYARK_OFF_DRV_DRIVER_SECTION        0x028UL
#define MYARK_OFF_DRV_DRIVER_NAME           0x038UL
#define MYARK_OFF_DRV_FAST_IO_DISPATCH      0x050UL
#define MYARK_OFF_DRV_DRIVER_UNLOAD         0x068UL
#define MYARK_OFF_DRV_MAJOR_FUNCTION        0x070UL
#define MYARK_DRV_MAJOR_FUNCTION_COUNT      28UL

#define IRP_MJ_DEVICE_CONTROL               0x0EUL

//
// Kernel export -- the list head lives in ntifs.h but we redeclare it
// here with the NTKERNELAPI decoration so the linker resolves it
// regardless of which WDK header happens to be in scope.
//
extern NTKERNELAPI LIST_ENTRY IoDriverListHead;

#define MYARK_TRACE_KMOD                    MYARK_TRACE_MODULE

#endif // MYARK_MODULE_KMODULE
