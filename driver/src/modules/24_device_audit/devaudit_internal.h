// MyArk device-audit module: within-module offsets + helpers.

#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "../../../shared/driver/MyArkDeviceAuditIoctl.h"

#if MYARK_MODULE_DEVICE_AUDIT

extern LIST_ENTRY IoDeviceObjectListHead;

#define MYARK_OFF_DO_ATTACHED_DEVICE        0x008UL
#define MYARK_OFF_DO_DRIVER_OBJECT          0x030UL
#define MYARK_OFF_DO_NEXT_DEVICE            0x038UL
#define MYARK_OFF_DO_ATTACHED_TO            0x040UL
#define MYARK_OFF_DO_VPB                    0x048UL
#define MYARK_OFF_DO_TYPE                   0x000UL

#define MYARK_TRACE_DEVAUDIT                MYARK_TRACE_MODULE

#endif // MYARK_MODULE_DEVICE_AUDIT
