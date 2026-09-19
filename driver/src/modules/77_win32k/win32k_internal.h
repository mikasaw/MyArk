// win32k internal types.

#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "myark_config.h"

#if MYARK_MODULE_WIN32K

#include "../../../shared/driver/MyArkWin32kIoctl.h"

#define MYARK_TRACE_WIN32K "[win32k] "

//
// PEB/Ldr module-walk offsets. LDR_DATA_TABLE_ENTRY has kept the x64 shape
// below since Vista (InLoadOrderLinks / DllBase / SizeOfImage / BaseDllName
// are the documented WALKED fields of the documented doubly-linked list);
// treated as Tier C stable, with every dereference SafeRead-guarded.
//
#define MYARK_WIN32K_PEB_LDR_OFFSET          0x018
#define MYARK_WIN32K_LDR_INLOADORDER_OFFSET  0x010
#define MYARK_WIN32K_LDR_ENTRY_DLLBASE       0x030
#define MYARK_WIN32K_LDR_ENTRY_BASEDLLNAME   0x058   // UNICODE_STRING

//
// The win32k HANDLEENTRY record as measured on 1903/22631 user-mapped
// aheList (HeEntrySize = 32): kernel pointer @0 is MASKED TO 0, user
// pointer @8, USHORT TYPE_* @24, USHORT unique/generation @26 (retained
// after free -- liveness MUST test the type field, not any-nonzero).
// Strides 16/24 are tolerated for down-level builds.
//
#define MYARK_WIN32K_HE_MAX_SLOTS            0x10000
#define MYARK_WIN32K_HE_FREE_TAIL            256     // consecutive free = end

//
// PsGetProcessPeb is exported by ntoskrnl but not declared by this WDK's
// ntddk (the PEB type itself is kernel-opaque here). We only ever read
// flat offsets from the returned base, so a PVOID mirror is ABI-identical.
//
NTKERNELAPI
PVOID
NTAPI
PsGetProcessPeb(_In_ PEPROCESS Process);

//
// R3-10a: walk the CALLER-process USER handle table (gSharedInfo.aheList).
// Caller must be a GUI process; PASSIVE_LEVEL, caller context throughout.
// All user- and session-space reads go through the guarded reader.
//
NTSTATUS
MyArkWin32kEnumUserHandles(
    _Out_ PMYARK_WIN32K_USER_HANDLES_OUTPUT Out,
    _In_  ULONG                             MaxEntries);

#endif
