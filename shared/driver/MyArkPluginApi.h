// MyArk Core Driver: MYARK_MODULE_DESCRIPTOR contract.
//
// Every MyArk module exports one MYARK_MODULE_DESCRIPTOR instance whose
// symbol follows the naming convention MyArkModule_<Name>. The driver
// collects them at link time into g_AllModules[]; the dispatcher then
// walks that array to register IOCTLs, drive Init/Cleanup, and answer
// IOCTL_MYARK_CORE_QUERY_MODULES.
//
// This header is the canonical home of the struct definition. The
// driver-internal copy (driver/src/module/module_descriptor.h) is a
// thin wrapper that just includes this one and adds the S2.1 comment
// header; keeping the wire contract here means R3 tooling and tests can
// include only this header without dragging in any WDF/ntddk types they
// don't need.

#pragma once

#include <ntddk.h>
#include <wdf.h>

//
// Forward decl for the IOCTL entry struct. The full definition lives in
// ioctl_registry.h (S2.2), which lives under shared/driver/ as well so
// the forward reference resolves when both headers are pulled in.
//
struct _MYARK_IOCTL_ENTRY;

typedef NTSTATUS (*MYARK_MODULE_INIT_FN)(VOID);
typedef VOID     (*MYARK_MODULE_CLEANUP_FN)(VOID);

//
// The descriptor contract. Field order is part of the ABI: existing
// fields may not be reordered, only appended. The Init/Cleanup callbacks
// run under PASSIVE_LEVEL at DriverEntry / DriverUnload.
//
typedef struct _MYARK_MODULE_DESCRIPTOR {
    PCSTR    ModuleName;        // "process"
    PCSTR    ModuleDescription; // "Process enumeration and management"
    UINT32   ModuleId;          // 0x10
    UINT32   IoctlCount;
    struct _MYARK_IOCTL_ENTRY* Ioctls;
    MYARK_MODULE_INIT_FN     Init;
    MYARK_MODULE_CLEANUP_FN  Cleanup;
    BOOLEAN  Initialized;
} MYARK_MODULE_DESCRIPTOR, *PMYARK_MODULE_DESCRIPTOR;

//
// Module-id convention. Core reserves 0x00000000; functional modules
// pick four ASCII bytes (little-endian readable) so a debugger dump
// shows a familiar four-char tag instead of an opaque integer.
//
#define MYARK_MODULE_ID_CORE               0x00000000UL
#define MYARK_MODULE_ID_HELLO              0x48454C4CUL  // 'HELL'
#define MYARK_MODULE_ID_PROCESS            0x50524F43UL  // 'PROC'
#define MYARK_MODULE_ID_THREAD             0x54485244UL  // 'THRD'
#define MYARK_MODULE_ID_MEMORY             0x4D454D52UL  // 'MEMR'
#define MYARK_MODULE_ID_REGISTRY           0x5245474BUL  // 'REGK'
#define MYARK_MODULE_ID_FILE               0x46494C45UL  // 'FILE'
#define MYARK_MODULE_ID_FILE_MONITOR       0x464D4F4EUL  // 'FMON'
#define MYARK_MODULE_ID_KERNEL             0x4B524E4CUL  // 'KRNL'
#define MYARK_MODULE_ID_KERNEL_OBJECT      0x4B4F424AUL  // 'KOBJ'
#define MYARK_MODULE_ID_CALLBACK           0x43424B48UL  // 'CBKH'
#define MYARK_MODULE_ID_DYNDATA            0x44594E44UL  // 'DYND'
#define MYARK_MODULE_ID_CAPABILITY         0x43415041UL  // 'CAPA'
#define MYARK_MODULE_ID_HANDLE             0x484E444CUL  // 'HNDL'
#define MYARK_MODULE_ID_SECTION            0x53454354UL  // 'SECT'
#define MYARK_MODULE_ID_ALPC               0x414C5043UL  // 'ALPC'
#define MYARK_MODULE_ID_NETWORK            0x4E455457UL  // 'NETW'
#define MYARK_MODULE_ID_KEYBOARD           0x4B455942UL  // 'KEYB'
#define MYARK_MODULE_ID_HWID               0x48574944UL  // 'HWID'
#define MYARK_MODULE_ID_MUTATION           0x4D555441UL  // 'MUTA'
#define MYARK_MODULE_ID_REDIRECT           0x52454452UL  // 'REDR'
#define MYARK_MODULE_ID_DEBUG_OUTPUT       0x4442544FUL  // 'DBGO'
#define MYARK_MODULE_ID_BUGCHECK           0x42554743UL  // 'BUGC'
#define MYARK_MODULE_ID_SAFETY             0x53414645UL  // 'SAFE'
#define MYARK_MODULE_ID_TRUST              0x54525553UL  // 'TRUS'
#define MYARK_MODULE_ID_PREFLIGHT          0x5052464CUL  // 'PRFL'
#define MYARK_MODULE_ID_SECURITY_AUDIT     0x53454341UL  // 'SECA'
#define MYARK_MODULE_ID_STORAGE            0x53545247UL  // 'STRG'
#define MYARK_MODULE_ID_DEVICE_AUDIT       0x44455641UL  // 'DEVA'
#define MYARK_MODULE_ID_WIN32K             0x57494E4BUL  // 'WINK'
#define MYARK_MODULE_ID_WSL                0x57534C20UL  // 'WSL '
#define MYARK_MODULE_ID_ACTIONS            0x41435453UL  // 'ACTS'
