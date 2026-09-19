// MyArk Core Driver: module registry public interface.
//
// g_AllModules is the compile-time list of MYARK_MODULE_DESCRIPTOR* pointers.
// Each module .c file contributes a `#if MYARK_MODULE_<NAME> &MyArkModule_<Name>`
// entry; the trailing NULL sentinel lets callers walk the array without a
// separate count. g_ModuleCount is populated by MyArkModuleRegistryInit() so
// lookups don't have to walk the array every call.

#pragma once

#include "module_descriptor.h"

// 36 slots were exactly exhausted when kernel_object (R3-4b) landed as the
// 36th descriptor; 40 leaves headroom so the next module cannot silently
// fall past the array sentinel.
#define MYARK_MAX_MODULES 40

extern MYARK_MODULE_DESCRIPTOR* g_AllModules[MYARK_MAX_MODULES + 1];
extern UINT32 g_ModuleCount;

NTSTATUS MyArkModuleRegistryInit(VOID);
VOID MyArkModuleRegistryCleanup(VOID);

PMYARK_MODULE_DESCRIPTOR MyArkModuleFindByName(_In_ PCSTR Name);
PMYARK_MODULE_DESCRIPTOR MyArkModuleFindById(_In_ UINT32 ModuleId);