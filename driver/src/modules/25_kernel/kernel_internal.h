// MyArk kernel module: internal offsets + helpers (compile-time only).

#pragma once

#include <ntddk.h>
#include <wdf.h>

#if MYARK_MODULE_KERNEL

#define MYARK_TRACE_KERNEL MYARK_TRACE_MODULE

//
// Bound the search for the KeServiceDescriptorTable symbol in ntoskrnl.
// The symbol is exported but not declared in any public WDK 28000 header,
// so we resolve at IOCTL time via MmGetSystemRoutineAddress. We stash the
// resolved pointer in a module-local cache to avoid repeated lookups.
//
extern PVOID g_MyArkKernelKeServiceDescriptorTable;

extern UINT64 g_MyArkKernelNtoskrnlTextBase;
extern UINT64 g_MyArkKernelNtoskrnlTextEnd;

typedef struct _KSERVICE_TABLE_DESCRIPTOR {
    UINT32 Limit;
    PUINT8 Base;        // points to array of PUCHAR ServiceRoutine pointers (Win10+)
    PUINT8 Number;      // argument-count table (NULL-terminated counts)
    PUINT8 Unused;      // unused, sometimes NULL
} KSERVICE_TABLE_DESCRIPTOR, *PKSERVICE_TABLE_DESCRIPTOR;


VOID
MyArkKernelEnsureNtoskrnlBounds(
    VOID);

#endif // MYARK_MODULE_KERNEL
