// MyArk Core Driver: per-module enable mask loaded from the registry.
//
// The mask is a 64-bit bitmap indexed by the module's position in
// g_AllModules[]: bit i set means the i-th module is enabled. DriverEntry
// (S2.3) walks the registry first to populate the mask, then iterates
// g_AllModules and calls each enabled module's Init().
//
// Storage: HKLM\SYSTEM\CurrentControlSet\Services\MyArkCore\Modules\<Name>
// as REG_DWORD = 0 (disable) / non-zero (enable). Missing values default to
// enabled so the driver is useful straight after `sc start MyArkCore` even
// when no admin has curated the Modules subkey yet.

#pragma once

#include "module_descriptor.h"

extern UINT64 g_ModuleEnableMask;

NTSTATUS MyArkModuleMaskLoadFromRegistry(VOID);
BOOLEAN MyArkModuleIsEnabled(_In_ PMYARK_MODULE_DESCRIPTOR Module);