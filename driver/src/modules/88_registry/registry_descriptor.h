// MyArk registry module: descriptor + IOCTL table declarations.

#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "module_descriptor.h"

#if MYARK_MODULE_REGISTRY

extern MYARK_MODULE_DESCRIPTOR g_MyArkModule_Registry;

NTSTATUS
MyArkRegistryModuleInit(
    VOID);

VOID
MyArkRegistryModuleCleanup(
    VOID);

#endif // MYARK_MODULE_REGISTRY
