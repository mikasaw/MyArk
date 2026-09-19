// MyArk file-monitor module: descriptor export.

#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "module_descriptor.h"

#if MYARK_MODULE_FILE_MONITOR

extern MYARK_MODULE_DESCRIPTOR g_MyArkModule_FileMonitor;

NTSTATUS
MyArkFileMonModuleInit(
    VOID);

VOID
MyArkFileMonModuleCleanup(
    VOID);

#endif // MYARK_MODULE_FILE_MONITOR
