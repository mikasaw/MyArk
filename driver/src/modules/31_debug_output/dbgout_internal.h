// MyArk debug-output module: ring buffer + refcount + callback context.
//
// The ring is a circular buffer of MYARK_DBG_OUTPUT_RING_ENTRIES slots,
// each MYARK_DBG_OUTPUT_MESSAGE_MAX bytes wide. We use an interlocked
// sequence number for write cursors; R3 sees a monotonic NextCursor that
// tracks the highest sequence emitted.
//
// Refcount semantics: when this module's callback is the only one in
// the system, refcount == 1 and we are the owner. When another driver
// later installs its own callback, our callback is silently replaced;
// DbgSetDebugPrintCallback returns STATUS_NOT_SET in that case but
// does NOT undo the change. We poll on every CONTROL=start to see if
// our function pointer is still bound.

#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "../../../shared/driver/MyArkDebugOutputIoctl.h"

#if MYARK_MODULE_DEBUG_OUTPUT

typedef struct _MYARK_DBG_RING_ENTRY {
    UINT64  Timestamp;
    UINT32  Level;
    UINT32  ComponentId;
    UINT32  MessageLength;
    UINT32  Sequence;
    CHAR    Message[MYARK_DBG_OUTPUT_MESSAGE_MAX];
} MYARK_DBG_RING_ENTRY, *PMYARK_DBG_RING_ENTRY;

typedef struct _MYARK_DBG_RING_STATE {
    volatile LONG       WriteCursor;
    volatile LONG       OverflowCount;
    MYARK_DBG_RING_ENTRY Entries[MYARK_DBG_OUTPUT_RING_ENTRIES];
} MYARK_DBG_RING_STATE, *PMYARK_DBG_RING_STATE;

//
// Module-private globals. All access guarded by the g_DbgRingLock
// fast-mutex (DbgPrint callback fires at DISPATCH_LEVEL so we use
// interlocked ops where possible).
//
extern MYARK_DBG_RING_STATE g_DbgRing;
extern FAST_MUTEX            g_DbgRingLock;
extern LONG                  g_DbgCallbackInstalled;
extern LONG                  g_DbgRefCount;

VOID
MyArkDebugOutputRingInit(
    VOID);

NTSTATUS
MyArkDebugOutputInstallCallback(
    _Out_writes_z_(NameCapacity) PWCHAR OutOwnerName,
    _In_ size_t NameCapacity,
    _Out_ PUINT32 OutPreviousState,
    _Out_ PUINT32 OutOwnerRefCount);

NTSTATUS
MyArkDebugOutputRemoveCallback(
    _Out_writes_z_(NameCapacity) PWCHAR OutOwnerName,
    _In_ size_t NameCapacity,
    _Out_ PUINT32 OutPreviousState,
    _Out_ PUINT32 OutOwnerRefCount);

NTSTATUS
MyArkDebugOutputDrainToBuffer(
    _In_ UINT64 Cursor,
    _Out_writes_bytes_to_(BufferSize, *BytesUsed) PUCHAR Buffer,
    _In_  ULONG BufferSize,
    _Out_ PULONG BytesUsed,
    _Out_ PUINT64 NextCursorOut);

#define MYARK_TRACE_DBGOUT                    MYARK_TRACE_MODULE

#endif // MYARK_MODULE_DEBUG_OUTPUT
