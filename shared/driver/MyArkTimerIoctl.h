// MyArk timer/DPC module: shared IOCTL protocol between R0 and R3.
//
// Function range 0x8A4..0x8A5 (R3-3). Both IOCTLs are read-only system
// introspection: they snapshot the per-CPU kernel timer table and the
// per-CPU DPC queues, decoding the obfuscated KTIMER.Dpc back-pointer
// (Win8+ KiWaitNever/KiWaitAlways scheme, see timerdpc_walk.c) so R3
// can attribute every pending timer to its owning module. Offsets are
// build-gated (Tier C profile, verified live on 18362 via KDNET);
// builds without a verified profile answer Status=NO_OFFSETS with an
// empty row list instead of guessing.
//
// All IOCTLs use the MyArk METHOD_BUFFERED convention.

#pragma once

#include <ntddk.h>
#include <wdf.h>

// ---------------------------------------------------------------------------
// Module identity + IOCTL function codes.
// ---------------------------------------------------------------------------

#define MYARK_TIMERDPC_MODULE_ID             0x544D4450UL  // 'TMDP' ASCII (LE)
#define MYARK_TIMERDPC_OWNER_MAX             48
#define MYARK_TIMER_HARD_CAP                 512
#define MYARK_DPC_HARD_CAP                   256

//
// 2 IOCTLs (function range 0x8A4..0x8A5).
//
#define IOCTL_MYARK_TIMER_QUERY \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8A4, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_DPC_QUERY \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8A5, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// Snapshot status (output header Status field).
//
#define MYARK_TDP_STATUS_OK                  0x00000000UL
#define MYARK_TDP_STATUS_NO_OFFSETS          0x00000001UL  // build w/o profile
#define MYARK_TDP_STATUS_NO_MODULELIST       0x00000002UL  // PsLoadedModuleList
                                                           // unresolved (owner
                                                           // names empty, rows
                                                           // still valid)

//
// TIMER row flags.
//
#define MYARK_TIMER_FLAG_EXPIRY              0x00000001UL  // from TimerExpiry[]
#define MYARK_TIMER_FLAG_NO_DPC              0x00000002UL  // notification timer
#define MYARK_TIMER_FLAG_NTROUTINE           0x00000004UL  // routine in nt text
#define MYARK_TIMER_FLAG_SUSPECT             0x00000008UL  // routine outside any
                                                           // known module

//
// DPC row flags.
//
#define MYARK_DPC_FLAG_THREADED              0x00000001UL  // DpcData[1] queue
#define MYARK_DPC_FLAG_NTROUTINE             0x00000002UL
#define MYARK_DPC_FLAG_SUSPECT               0x00000004UL

//
// QUERY_TIMER output row. Routine/Context are the decoded KDPC fields
// (0 when the KTIMER carries no DPC). Owner is the BaseDllName of the
// module containing Routine (ANSI, empty when unresolved or NO_DPC).
//
typedef struct _MYARK_TIMER_ENTRY {
    UINT64  Timer;                                     // KTIMER address
    UINT64  DueTime;                                   // KTIMER.DueTime (raw)
    UINT64  Dpc;                                       // decoded KTIMER.Dpc
    UINT64  Routine;                                   // KDPC.DeferredRoutine
    UINT64  Context;                                   // KDPC.DeferredContext
    UINT32  Cpu;
    UINT32  Period;                                    // 0 = one-shot
    UINT32  Flags;
    UINT32  Reserved;
    CHAR    Owner[MYARK_TIMERDPC_OWNER_MAX];
} MYARK_TIMER_ENTRY, *PMYARK_TIMER_ENTRY;

typedef struct _MYARK_TIMER_QUERY_OUTPUT {
    UINT32  Count;                                     // rows in Entries[]
    UINT32  Status;                                    // MYARK_TDP_STATUS_*
    UINT32  EntryStructSize;
    UINT32  Reserved;
    MYARK_TIMER_ENTRY Entries[1];                      // variable-length tail
} MYARK_TIMER_QUERY_OUTPUT, *PMYARK_TIMER_QUERY_OUTPUT;

//
// QUERY_DPC output row. The DPC queues are transient (entries are
// dequeued as they run), so Count may legitimately be 0 on a quiet
// system; the row set is a snapshot, not a registry.
//
typedef struct _MYARK_DPC_ENTRY {
    UINT64  Dpc;                                       // KDPC address
    UINT64  Routine;                                   // DeferredRoutine
    UINT64  Context;                                   // DeferredContext
    UINT32  Cpu;
    UINT32  QueueType;                                 // 0 = normal, 1 = threaded
    UINT32  Flags;
    UINT32  Reserved;
    CHAR    Owner[MYARK_TIMERDPC_OWNER_MAX];
} MYARK_DPC_ENTRY, *PMYARK_DPC_ENTRY;

typedef struct _MYARK_DPC_QUERY_OUTPUT {
    UINT32  Count;
    UINT32  Status;
    UINT32  EntryStructSize;
    UINT32  Reserved;
    MYARK_DPC_ENTRY Entries[1];
} MYARK_DPC_QUERY_OUTPUT, *PMYARK_DPC_QUERY_OUTPUT;

C_ASSERT(sizeof(MYARK_TIMER_ENTRY) == 40 + 16 + 48);
C_ASSERT(sizeof(MYARK_DPC_ENTRY) == 24 + 16 + 48);
C_ASSERT(sizeof(MYARK_TIMER_QUERY_OUTPUT) == 16 + sizeof(MYARK_TIMER_ENTRY));
C_ASSERT(sizeof(MYARK_DPC_QUERY_OUTPUT) == 16 + sizeof(MYARK_DPC_ENTRY));
