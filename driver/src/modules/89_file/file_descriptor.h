// MyArk file module: descriptor + IOCTL table declarations.

#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "module_descriptor.h"

#if MYARK_MODULE_FILE

extern MYARK_MODULE_DESCRIPTOR g_MyArkModule_File;

NTSTATUS
MyArkFileModuleInit(
    VOID);

VOID
MyArkFileModuleCleanup(
    VOID);

#endif // MYARK_MODULE_FILE
