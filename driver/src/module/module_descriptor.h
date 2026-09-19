// MyArk Core Driver: module descriptor type.
//
// S2.1 introduces the descriptor struct that every MyArk module exports. The
// DriverEntry walker iterates g_AllModules[], consults the registry-driven
// enable mask, and calls each enabled module's Init() before its IOCTLs are
// folded into the global dispatch table (S2.2 will own that table).
//
// Modules are conditionally compiled: each one is wrapped in
// `#if MYARK_MODULE_<NAME>` and references its own descriptor symbol.

#pragma once

#include <ntddk.h>
#include <wdf.h>

//
// Forward decl for the IOCTL entry struct. The full definition lives in
// driver/src/dispatch/ioctl_registry.h (S2.2). Keeping it forward-only here
// lets module_descriptor.h be included without dragging in the dispatcher.
//
struct _MYARK_IOCTL_ENTRY;

typedef NTSTATUS (*MYARK_MODULE_INIT_FN)(VOID);
typedef VOID (*MYARK_MODULE_CLEANUP_FN)(VOID);

typedef struct _MYARK_MODULE_DESCRIPTOR {
    PCSTR ModuleName;
    PCSTR ModuleDescription;
    UINT32 ModuleId;
    UINT32 IoctlCount;
    struct _MYARK_IOCTL_ENTRY* Ioctls;
    MYARK_MODULE_INIT_FN Init;
    MYARK_MODULE_CLEANUP_FN Cleanup;
    BOOLEAN Initialized;
} MYARK_MODULE_DESCRIPTOR, *PMYARK_MODULE_DESCRIPTOR;