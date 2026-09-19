// MyArk debug-output module: shared IOCTL protocol between R0 and R3.
//
// Function range 0xC60..0xC6F reserved for the debug-output module.
// Process 0xA00..0xAFF, memory 0xB00..0xBFF, handle 0xC00..0xC0F,
// section 0xC10..0xC1F, kernel-module 0xC20..0xC2F, storage 0xC30..
// 0xC3F, device-audit 0xC40..0xC4F, keyboard 0xC50..0xC5F -- so
// debug-output sits at 0xC60. All 2 IOCTLs follow the MyArk
// METHOD_BUFFERED convention.
//
// The debug-output module installs a single DbgPrint callback via
// DbgSetDebugPrintCallback and buffers every line into a 256-entry
// ring (each entry holds 512 bytes -- 1 byte is the message length
// plus a NUL terminator guard). CONTROL IOCTL toggles the callback
// on / off; DRAIN IOCTL copies the ring to R3 and resets the read
// cursor.
//
// Single-callback caveat: the Windows API allows only one DbgPrint
// callback at a time. Multiple drivers competing for the slot is a
// real-world problem; we track an internal refcount and only register
// when the first CONTROL=start lands. Subsequent start / stop calls
// from other drivers are rejected with STATUS_DEVICE_BUSY. R3 sees
// STATUS_DEVICE_BUSY as a hint to skip the module on shared hosts.

#pragma once

#include <ntddk.h>
#include <wdf.h>

// ---------------------------------------------------------------------------
// Module identity + IOCTL function codes.
// ---------------------------------------------------------------------------

#define MYARK_DBG_OUTPUT_MODULE_ID          0x4F474244UL  // 'DBGO' ASCII (LE)
#define MYARK_DBG_OUTPUT_RING_ENTRIES        256
#define MYARK_DBG_OUTPUT_MESSAGE_MAX         512          // payload size per ring slot

//
// 2 IOCTLs (function range 0xC60..0xC61). Method/Access match the rest of
// the driver: METHOD_BUFFERED + FILE_ANY_ACCESS.
//
#define IOCTL_MYARK_DEBUG_OUTPUT_CONTROL \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xC60, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_DEBUG_OUTPUT_DRAIN \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xC61, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ---------------------------------------------------------------------------
// CONTROL input / output.
//
// Control == 0 stops the callback; Control == 1 starts it. The driver
// also accepts Control == 0xFFFFFFFF to query current state without
// changing anything.
// ---------------------------------------------------------------------------

#define MYARK_DBG_OUTPUT_CONTROL_QUERY      0xFFFFFFFFUL

typedef struct _MYARK_DEBUG_OUTPUT_CONTROL_INPUT {
    UINT32  Control;                                        // 0 = stop, 1 = start, MYARK_DBG_OUTPUT_CONTROL_QUERY = query
    UINT32  Reserved0;
    UINT32  Reserved1;
    UINT32  Reserved2;
} MYARK_DEBUG_OUTPUT_CONTROL_INPUT, *PMYARK_DEBUG_OUTPUT_CONTROL_INPUT;

typedef struct _MYARK_DEBUG_OUTPUT_CONTROL_OUTPUT {
    UINT32  PreviousState;                                  // 0 = stopped, 1 = started
    UINT32  CurrentState;
    UINT32  OwnerRefCount;                                  // how many MyArk instances hold the slot
    UINT32  Reserved;
    WCHAR   OwnerModuleName[32];                            // service-key name of whoever owns the slot
} MYARK_DEBUG_OUTPUT_CONTROL_OUTPUT, *PMYARK_DEBUG_OUTPUT_CONTROL_OUTPUT;

// ---------------------------------------------------------------------------
// DRAIN output: every ring slot in arrival order.
//
// Cursor is a monotonic counter -- caller passes the last cursor it saw
// and the driver returns entries strictly newer than that. The driver
// resets the internal read cursor when a CONTROL=stop is followed by
// CONTROL=start (the ring wraps before delivery).
// ---------------------------------------------------------------------------

typedef struct _MYARK_DBG_OUTPUT_ENTRY {
    UINT64  Timestamp;                                      // KeQuerySystemTime tick at capture
    UINT32  Level;                                          // DPFLTR_* mask from the DbgPrint callback
    UINT32  ComponentId;                                    // component id from the filter
    UINT32  MessageLength;                                  // bytes used (excluding NUL)
    UINT32  Reserved0;
    CHAR    Message[MYARK_DBG_OUTPUT_MESSAGE_MAX];
} MYARK_DBG_OUTPUT_ENTRY, *PMYARK_DBG_OUTPUT_ENTRY;

typedef struct _MYARK_DEBUG_OUTPUT_DRAIN_INPUT {
    UINT64  Cursor;                                         // 0 = drain everything
    UINT32  MaxEntries;                                     // 0 = driver default (= ring capacity)
    UINT32  Reserved0;
    UINT32  Reserved1;
    UINT32  Reserved2;
} MYARK_DEBUG_OUTPUT_DRAIN_INPUT, *PMYARK_DEBUG_OUTPUT_DRAIN_INPUT;

typedef struct _MYARK_DEBUG_OUTPUT_DRAIN_OUTPUT {
    UINT32  Size;
    UINT32  Count;
    UINT32  TotalSeen;                                      // total entries the ring holds
    UINT32  OverflowCount;                                  // entries dropped since last drain (ring wrapped)
    UINT64  NextCursor;                                     // caller passes this on the next call
    UINT64  Reserved0;
    MYARK_DBG_OUTPUT_ENTRY Entries[1];
} MYARK_DEBUG_OUTPUT_DRAIN_OUTPUT, *PMYARK_DEBUG_OUTPUT_DRAIN_OUTPUT;
