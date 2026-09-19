// MyArk Core Driver: module registration / query IOCTLs.
//
// Module registration happens at DriverEntry time (R0-side, in the kernel
// data segment) and does not require an IOCTL round-trip. The IOCTLs in
// this header are the R3-facing side of that machinery: they let a user-
// mode client ask the driver which module metadata it actually saw, and
// whether a given module's per-instance state is reachable.
//
// Function range 0x810..0x81F is reserved for module management IOCTLs.
// They live alongside the core IOCTLs (0x800..0x8FF) so the dispatcher
// can validate them in a single code path.
//
// Note: this file is the *python module registry* surface. The kernel-
// driver enumeration walker (DriverObject / IOCTL dispatch table) lives in
// MyArkKmodIoctl.h -- the two share the word "module" in their public
// name but describe very different things (Python module vs kernel driver
// module).
//
// Status (S10.3 audit, 2026-08-27):
//   All three module-management IOCTLs (0x810..0x812) are reserved in this
//   header. They are *not* listed in plan v3's "3 IOCTLs" budget but
//   exist as documented surface area; the gap audit treats them as
//   "pre-existing, not a gap". No new work needed here.

#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "MyArkIoctl.h"

//
// IOCTL codes.
//
#define IOCTL_MYARK_MODULE_QUERY_REGISTRY \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_MODULE_QUERY_STATE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x811, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_MODULE_TOGGLE_RUNTIME \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x812, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// IOCTL_MYARK_MODULE_QUERY_REGISTRY input: zero-length (the driver walks
// HKLM\...\MyArkCore\Modules\<Name> directly).
//
// IOCTL_MYARK_MODULE_QUERY_REGISTRY output: one entry per module key seen.
// MYARK_MODULE_REGISTRY_ENTRY::Name is the value-name (== module name);
// the Value field is what the driver will load into g_ModuleEnableMask at
// DriverEntry, normalized to 0/1.
//
typedef struct _MYARK_MODULE_REGISTRY_ENTRY {
    CHAR    Name[32];
    UINT32  Value;
    UINT32  Source;     // 0 = missing (default), 1 = registry
} MYARK_MODULE_REGISTRY_ENTRY, *PMYARK_MODULE_REGISTRY_ENTRY;

typedef struct _MYARK_MODULE_REGISTRY_OUTPUT {
    UINT32  Size;
    UINT32  Count;
    MYARK_MODULE_REGISTRY_ENTRY Entries[1];
} MYARK_MODULE_REGISTRY_OUTPUT, *PMYARK_MODULE_REGISTRY_OUTPUT;

//
// IOCTL_MYARK_MODULE_QUERY_STATE input/output pair.
//
typedef struct _MYARK_MODULE_STATE_INPUT {
    UINT32  ModuleId;
} MYARK_MODULE_STATE_INPUT, *PMYARK_MODULE_STATE_INPUT;

typedef struct _MYARK_MODULE_STATE_OUTPUT {
    UINT32  ModuleId;
    CHAR    ModuleName[32];
    UINT32  State;          // MYARK_MODULE_STATE_DISABLED / ENABLED / FAILED
    UINT32  IoctlCount;
    UINT32  RegisteredIoctlCount;
    NTSTATUS LastError;
} MYARK_MODULE_STATE_OUTPUT, *PMYARK_MODULE_STATE_OUTPUT;

//
// IOCTL_MYARK_MODULE_TOGGLE_RUNTIME input.
// Enabled == 0 flips the runtime mask bit off (without unloading the
// module's IOCTLs); Enabled == 1 turns it back on. The driver persists
// the choice to the registry so the next sc start keeps the new state.
//
typedef struct _MYARK_MODULE_TOGGLE_INPUT {
    UINT32  ModuleId;
    UINT32  Enabled;
} MYARK_MODULE_TOGGLE_INPUT, *PMYARK_MODULE_TOGGLE_INPUT;

typedef struct _MYARK_MODULE_TOGGLE_OUTPUT {
    UINT32  ModuleId;
    UINT32  PreviousState;
    UINT32  NewState;
    NTSTATUS Status;
} MYARK_MODULE_TOGGLE_OUTPUT, *PMYARK_MODULE_TOGGLE_OUTPUT;
