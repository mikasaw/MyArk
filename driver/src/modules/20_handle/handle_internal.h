// MyArk handle module: within-module helpers + EPROCESS / HANDLE_TABLE offsets.
//
// Win11 24H2 / build 26100.x offsets are hard-coded. S7.1 (DynData) replaces
// these with a runtime-loaded profile. Until that lands, the module pins
// to a single Windows build.
//
// Each row of HANDLE_TABLE_ENTRY is a tagged union; the low 2 bits of the
// handle value encode the table level (0 = single, 1 = L1, 2 = L2, 3 = L3).
// For this stage we only walk the L0 (single-level) table -- multi-level
// tables are rare and an exercise for S7.

#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "../../../shared/driver/MyArkHandleIoctl.h"

#if MYARK_MODULE_HANDLE

//
// EPROCESS offsets (Win11 24H2).
//
#define MYARK_OFF_EPROCESS_OBJECT_TABLE        0x498UL  // EPROCESS.ObjectTable

//
// HANDLE_TABLE offsets (Win11 24H2). TableCode holds the table pointer
// ORed with the level in the low 2 bits.
//
#define MYARK_OFF_HT_TABLE_CODE               0x008UL
#define MYARK_OFF_HT_NEXT_HANDLE_TABLE        0x010UL  // linkage to sibling tables
#define MYARK_OFF_HT_HANDLE_COUNT             0x018UL  // real handle count

//
// HANDLE_TABLE_ENTRY offsets (Win11 24H2). The "Object" field at +0x008
// has the low bits masked to hold the audit / inherit / protected flags.
// The pointer back to OBJECT_HEADER is computed as Object & ~0xF.
//
#define MYARK_OFF_HTE_LOW_BITS                0x000UL
#define MYARK_OFF_HTE_OBJECT                  0x008UL

//
// OBJECT_HEADER offsets. The header sits in front of the object body;
// its size depends on the optional substructures present. For simplicity
// we hard-code the most common size: 0x30 bytes (TypeIndex + Flags +
// PointerCount + HandleCount + pEntry + Object).
//
#define MYARK_OFF_OBJ_HDR_TYPE_INDEX          0x018UL
#define MYARK_OFF_OBJ_HDR_FLAGS               0x01CUL  // OB_FLAG_* + InfoMask
#define MYARK_OFF_OBJ_HDR_POINTER_COUNT       0x028UL
#define MYARK_OFF_OBJ_HDR_HANDLE_COUNT        0x02CUL
#define MYARK_OFF_OBJ_HDR_NAME_INFO_OFFSET    0x020UL  // _OBJECT_HEADER_NAME_INFO pointer (optional)

#define MYARK_OBJ_HDR_FLAG_NAME_INFO          0x00000001UL

//
// Single-level table capacity. A L0 HANDLE_TABLE holds 1 << 10 = 1024
// entries; this constant is used to size the walk loop.
//
#define MYARK_HT_L0_CAPACITY                  512UL     // ACTUAL_HARDCODE: Win11 uses 512 entries per L0 table

//
// Trace prefix. Stable so log scrapers can grep on "HANDLE".
//
#define MYARK_TRACE_HANDLE                    MYARK_TRACE_MODULE

//
// Exported helpers -- defined in handle_walk.c. The IOCTL handler in
// handle_ioctl.c calls them, so we need the prototypes visible.
//
NTSTATUS
MyArkHandleWalkTable(
    _In_  PVOID   HandleTable,
    _Out_writes_(MaxEntries) PMYARK_HANDLE_ENTRY OutEntries,
    _In_  ULONG   MaxEntries,
    _Out_ PULONG  CountOut,
    _Out_ PULONG  TotalSeenOut);

NTSTATUS
MyArkHandleFillObjectHeaderFields(
    _In_  PVOID   Object,
    _Out_ PUINT32 PointerCount,
    _Out_ PUINT32 HandleCount,
    _Out_ PUINT32 TypeIndex,
    _Out_ PUINT32 ObFlags);

NTSTATUS
MyArkHandleResolveTypeName(
    _In_  UINT32 TypeIndex,
    _Out_writes_z_(Capacity) PWCHAR OutName,
    _In_  size_t Capacity);

NTSTATUS
MyArkHandleResolveObjectName(
    _In_  PVOID  ObjectBody,
    _Out_writes_z_(Capacity) PWCHAR OutName,
    _In_  size_t Capacity);

#endif // MYARK_MODULE_HANDLE
