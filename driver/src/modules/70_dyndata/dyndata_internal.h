// MyArk dyndata module: internal offsets + helpers (compile-time only).
//
// EPROCESS / ETHREAD / KLDR_DATA_TABLE_ENTRY offsets are pinned to Windows
// 11 24H2 / build 26100.x to match process_internal.h. DynData's job is to
// walk kernel data structures on behalf of other S7 modules; the actual
// per-build offsets used here can be replaced at runtime once a profile
// loader (PDB-driven) lands, but for the S7.1 acceptance the hardcoded
// values are the contract.
//
// Suppressions (kept local to this header):
//   4201 -- unnamed struct/union (LIST_ENTRY and friends are standard)
//   4214 -- non-int bitfield (KTHREAD state uses non-standard types)
//   4057 -- signed/unsigned mismatch from kernel prototypes we forward-decl

#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "Trace.h"
#include "module_descriptor.h"
#include "myark_config.h"
#include "../../../shared/driver/MyArkDyndataIoctl.h"

#if MYARK_MODULE_DYNDATA

#pragma warning(push)
#pragma warning(disable: 4201 4214 4057)

//
// Tracing helper: assign a stable prefix for dyndata-module lines.
//
#define MYARK_TRACE_DYNDATA                    MYARK_TRACE_MODULE

//
// ---------------------------------------------------------------------------
// EPROCESS offsets (Win11 24H2 / build 26100.x). Mirrors process_internal.h
// so S7.x modules can stop hardcoding these on their own. Consumers MUST
// gate on MyArkArkOffsetsGet()->ProfileMatched (see dyndata_ioctl.c): these
// constants are wrong on any other build, and node->EPROCESS back-offsets
// come from Tier B discovery instead of MYARK_OFF_EPROCESS_ACTIVE_PROCESS_LINKS.
// ---------------------------------------------------------------------------
//

#define MYARK_OFF_EPROCESS_UNIQUE_PROCESS_ID             0x1D0UL
#define MYARK_OFF_EPROCESS_INHERITED_FROM_UNIQUE_PID      0x540UL
#define MYARK_OFF_EPROCESS_ACTIVE_PROCESS_LINKS           0x1D8UL
#define MYARK_OFF_EPROCESS_PEB                            0x7C0UL
#define MYARK_OFF_EPROCESS_IMAGE_FILE_NAME                0x5A8UL
#define MYARK_OFF_EPROCESS_FLAGS2                         0x183UL
#define MYARK_OFF_EPROCESS_SESSION_ID                     0x448UL
#define MYARK_OFF_EPROCESS_CREATE_TIME                    0x580UL
#define MYARK_OFF_EPROCESS_EXIT_STATUS                    0x548UL
#define MYARK_OFF_EPROCESS_ACTIVE_THREADS                 0x5F0UL
#define MYARK_OFF_EPROCESS_THREAD_LIST_HEAD               0x5E0UL
#define MYARK_OFF_EPROCESS_BASE_PRIORITY                  0x55CUL
#define MYARK_OFF_EPROCESS_AFFINITY                       0x578UL
#define MYARK_OFF_EPROCESS_PROTECTION                     0x6B0UL

//
// ETHREAD offsets (Win11 24H2 / build 26100.x). Used by QUERY_THREAD and
// ETHREAD::Tcb.ApcState.Process owner-PID resolution.
//
#define MYARK_OFF_ETHREAD_UNIQUE_THREAD_ID                0x4E8UL
#define MYARK_OFF_ETHREAD_THREAD_LIST_ENTRY               0x4F8UL
#define MYARK_OFF_ETHREAD_STATE                           0x044UL
#define MYARK_OFF_ETHREAD_PRIORITY                        0x05CUL
#define MYARK_OFF_ETHREAD_WAIT_REASON                     0x098UL
#define MYARK_OFF_ETHREAD_CREATE_TIME                     0x3B8UL
#define MYARK_OFF_ETHREAD_START_ADDRESS                   0x450UL
#define MYARK_OFF_ETHREAD_APC_STATE_PROCESS               0x178UL

//
// KLDR_DATA_TABLE_ENTRY offsets (Win11 24H2). Used by QUERY_MODULE.
// Layout verified empirically on 1903 (KLDRDIAG probe, 2026-09-16):
// DllBase@0x30, EntryPoint@0x38, SizeOfImage@0x40 (page-aligned),
// FullDllName@0x48 (UNICODE_STRING, Length=0x42 for the 33-char
// ntoskrnl path), BaseDllName@0x58. The old 0x048 double-pinning of
// SIZE_OF_IMAGE + FULL_DLL_NAME handed QUERY_MODULE a misread size.
//
#define MYARK_OFF_KLDR_IN_LOAD_ORDER_LINKS                0x000UL
#define MYARK_OFF_KLDR_DLL_BASE                           0x030UL
#define MYARK_OFF_KLDR_SIZE_OF_IMAGE                      0x040UL
#define MYARK_OFF_KLDR_FULL_DLL_NAME                      0x048UL   // UNICODE_STRING
#define MYARK_OFF_KLDR_BASE_DLL_NAME                      0x058UL
#define MYARK_OFF_KLDR_LOAD_ORDER_INDEX                   0x004UL   // before InLoadOrderLinks

//
// HANDLE_TABLE / HANDLE_TABLE_ENTRY offsets (Win11 24H2). Used by
// QUERY_HANDLE and indirectly by QUERY_FILE.
//
#define MYARK_OFF_HANDLE_TABLE_TABLE_CODE                 0x008UL
#define MYARK_OFF_HANDLE_TABLE_QUOTA_PROCESS              0x010UL
#define MYARK_OFF_HANDLE_TABLE_UNIQUE_PROCESS_ID          0x058UL

//
// OB_HEADER offsets (Win11 24H2). Used by QUERY_OBJECT.
//
#define MYARK_OFF_OB_TYPE_INDEX                           0x018UL
#define MYARK_OFF_OB_NAME_INFO_OFFSET                     0x020UL
#define MYARK_OFF_OB_TYPE_OBJECT_TYPE                     0x030UL
#define MYARK_OFF_OB_TYPE_TOTAL_OBJECTS                   0x038UL
#define MYARK_OFF_OB_TYPE_TOTAL_HANDLES                   0x040UL
#define MYARK_OFF_OB_TYPE_NAME                            0x040UL   // UNICODE_STRING after TotalHandles

//
// EPROCESS token pointer (Win11 24H2 / build 26100.x).
//
#define MYARK_OFF_EPROCESS_TOKEN                          0x4B8UL

//
// KeServiceDescriptorTable is exported by ntoskrnl but the public struct
// type is not declared in any WDK 28000 header. Define it here so the
// QUERY_SYSCALL / QUERY_SSDT walkers can read the descriptor's fields
// (Limit / Base / Number / Unused) without a per-call sizeof dance.
//
typedef struct _KSERVICE_TABLE_DESCRIPTOR {
    UINT32 Limit;
    PUINT8 Base;
    PUINT8 Number;
    PUINT8 Unused;
} KSERVICE_TABLE_DESCRIPTOR, *PKSERVICE_TABLE_DESCRIPTOR;

//
// Forward decls for kernel-side types we touch but never fully dereference.
// The full definitions live in ntddk.h but only when the right subset of
// WDK headers is included; declaring forward decls here lets the IOCTL
// code compile without dragging the entire process-manager surface area.
//
struct _EPROCESS;
typedef struct _EPROCESS *PEPROCESS;
struct _ETHREAD;
typedef struct _ETHREAD *PETHREAD;

//
// ActiveProcessHead / ActiveThreadHead are exported symbols. We resolve them
// at runtime via MmGetSystemRoutineAddress and stash the pointers here.
//
extern PVOID g_MyArkDynDataPsActiveProcessHead;
extern PVOID g_MyArkDynDataPsActiveThreadHead;
extern PVOID g_MyArkDynDataPsLoadedModuleList;
extern PVOID g_MyArkDynDataKeServiceDescriptorTable;
extern PVOID g_MyArkDynDataKeServiceDescriptorTableShadow;
extern PVOID g_MyArkDynDataPspCidTable;
extern PVOID g_MyArkDynDataObTypeObjectType;

extern UINT64 g_MyArkDynDataNtoskrnlTextBase;
extern UINT64 g_MyArkDynDataNtoskrnlTextEnd;
extern UINT64 g_MyArkDynDataWin32kTextBase;
extern UINT64 g_MyArkDynDataWin32kTextEnd;
extern PVOID  g_MyArkDynDataW32pServiceTable;

//
// Forward-export resolver: called from MyArkDynDataInit, also lazy on each
// IOCTL handler that needs a particular symbol. The lazy path probes each
// uninitialised field and stops on the first failure.
//
NTSTATUS
MyArkDynDataPagetableResolveAll(
    VOID);

//
// Safe read helper used by every IOCTL walker. Returns the number of bytes
// actually copied (capped at RequestedSize) -- 0 if the source pointer is
// not resident.
//
ULONG
MyArkDynDataSafeRead(
    _In_  PVOID Source,
    _Out_writes_bytes_(RequestedSize) PUCHAR Destination,
    _In_  ULONG RequestedSize);

//
// Read up to MYARK_DYNDATA_SYSCALL_DWELL_MAX bytes from a kernel-side
// trampoline. Returns the byte count actually copied.
//
ULONG
MyArkDynDataReadDwell(
    _In_  PVOID ServiceAddress,
    _Out_writes_bytes_(MYARK_DYNDATA_SYSCALL_DWELL_MAX) PUCHAR OutBytes);

//
// Convert a kernel VA to its ntoskrnl .text relative flag. Returns the
// MYARK_DYNDATA_FLAG_* bits the walker should attach to a row.
//
UINT32
MyArkDynDataAddressFlags(
    _In_  UINT64 Address,
    _In_  UINT64 TextBase,
    _In_  UINT64 TextEnd);

//
// Pulled in from process / kmod patterns: use MmIsAddressValid + per-byte
// fallback to avoid touching an unmapped page. The MYARK_TRACE_DYNDATA
// prefix is used for TraceEvents so dyndata lines are easy to filter.
//

#pragma warning(pop)

#endif // MYARK_MODULE_DYNDATA
