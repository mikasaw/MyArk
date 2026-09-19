// MyArk mutation module: shared IOCTL protocol between R0 and R3.
//
// Function range 0x730..0x731 reserved for the mutation module (S7.3).
// Mutation is read-only for S7.3: the IOCTL set inspects EPROCESS fields
// that another rootkit would mutate (Token, ImageFileName, DebugPort,
// etc.). The write-Token / set-mutation IOCTLs are reserved for the
// S7.3-fix stage and return STATUS_NOT_IMPLEMENTED on dispatch.
//
// The 2 IOCTLs:
//
//   0x730  INSPECT_TOKEN     - Inspect target EPROCESS Token state
//   0x731  SET_TOKEN         - Replace target Token (reserved; S7.3-fix)
//
// All 2 IOCTLs use the MyArk METHOD_BUFFERED convention.

#pragma once

#include <ntddk.h>
#include <wdf.h>

// ---------------------------------------------------------------------------
// Module identity + IOCTL function codes.
// ---------------------------------------------------------------------------

#define MYARK_MUTATION_MODULE_ID             0x4D55544EUL  // 'MUTN' ASCII (LE)
#define MYARK_MUTATION_NAME_MAX              64

//
// 2 IOCTLs (function range 0x730..0x731). Method/Access match the rest
// of the driver: METHOD_BUFFERED + FILE_ANY_ACCESS.
//
#define IOCTL_MYARK_MUTATION_INSPECT_TOKEN \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x730, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_MUTATION_SET_TOKEN \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x731, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// ---------------------------------------------------------------------------
// INSPECT_TOKEN input: target ProcessId + read-only inspection request.
// ---------------------------------------------------------------------------
//

typedef struct _MYARK_MUTATION_INSPECT_TOKEN_INPUT {
    UINT32  ProcessId;
    UINT32  Reserved;
    UINT64  Reserved2;
} MYARK_MUTATION_INSPECT_TOKEN_INPUT, *PMYARK_MUTATION_INSPECT_TOKEN_INPUT;

//
// INSPECT_TOKEN output: Token-relevant flags (integrity, elevation, UAC-restricted).
// ---------------------------------------------------------------------------
//

typedef struct _MYARK_MUTATION_INSPECT_TOKEN_OUTPUT {
    UINT32  TokenFlags;                            // bitfield (see below)
    UINT32  IntegrityLevel;                        // 0..System
    UINT32  IsElevated;                            // 0 / 1
    UINT32  IsUacRestricted;                       // 0 / 1
    UINT64  TokenAddress;                          // EPROCESS.Token address
    UINT64  Reserved;
} MYARK_MUTATION_INSPECT_TOKEN_OUTPUT, *PMYARK_MUTATION_INSPECT_TOKEN_OUTPUT;

#define MYARK_MUTATION_TOKEN_FLAG_VALID        0x00000001UL
#define MYARK_MUTATION_TOKEN_FLAG_ADMIN        0x00000002UL
#define MYARK_MUTATION_TOKEN_FLAG_SYSTEM       0x00000004UL

//
// SET_TOKEN input (reserved; S7.3-fix).
// ---------------------------------------------------------------------------
typedef struct _MYARK_MUTATION_SET_TOKEN_INPUT {
    UINT32  ProcessId;
    UINT32  Reserved;
    UINT64  TokenHandle;
    UINT64  Reserved2;
} MYARK_MUTATION_SET_TOKEN_INPUT, *PMYARK_MUTATION_SET_TOKEN_INPUT;

// ---------------------------------------------------------------------------
// R3-8: Mutation transaction (0x732 PREPARE / 0x733 COMMIT / 0x734 ROLLBACK
// / 0x735 TX_LIST).
//
// PREPARE stages a batch of mutation ops (PPL byte / Flags2 mask-and-set)
// against target PIDs and snapshots the current values into a transaction
// slot -- no mutation is applied. COMMIT atomically writes the staged new
// values. ROLLBACK is a no-op on a PREPARED slot (originals are still
// intact) but restores originals on a COMMITTED slot (undo). TX_LIST is a
// read-only inventory of all slots plus the audit ring (last 32 events).
//
// All mutating IOCTLs are SAFETY_TOKEN gated (op MYARK_MUTATION_OP_TX_*).
#include "MyArkSafetyToken.h"

// ---------------------------------------------------------------------------

#define IOCTL_MYARK_MUTATION_TX_PREPARE   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x732, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MYARK_MUTATION_TX_COMMIT    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x733, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MYARK_MUTATION_TX_ROLLBACK  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x734, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MYARK_MUTATION_TX_LIST      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x735, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define MYARK_MUTATION_OP_TX_PREPARE      0x364D5554UL  // 'TUM6' (LE)
#define MYARK_MUTATION_OP_TX_COMMIT       0x374D5554UL  // 'TUM7'
#define MYARK_MUTATION_OP_TX_ROLLBACK     0x384D5554UL  // 'TUM8'

#define MYARK_MUTATION_TX_MAX_SLOTS       8
#define MYARK_MUTATION_TX_MAX_OPS         4
#define MYARK_MUTATION_TX_MAGIC           0x54583131UL  // 'TX11'
#define MYARK_MUTATION_TX_AUDIT_RING      32

// Transaction states.
#define MYARK_MUTATION_TX_STATE_FREE      0
#define MYARK_MUTATION_TX_STATE_PREPARED  1
#define MYARK_MUTATION_TX_STATE_COMMITTED 2
#define MYARK_MUTATION_TX_STATE_ROLLED    3

// Mutation op types.
#define MYARK_MUTATION_TX_OP_PPL          1   // Protection.Level byte
#define MYARK_MUTATION_TX_OP_FLAGS2       2   // Flags2 mask-and-set

// Audit ring action codes.
#define MYARK_MUTATION_TX_AUDIT_PREPARE   1
#define MYARK_MUTATION_TX_AUDIT_COMMIT    2
#define MYARK_MUTATION_TX_AUDIT_ROLLBACK  3

// PREPARE input: one op spec (inside a fixed array in the input struct).
typedef struct _MYARK_MUTATION_TX_OP_SPEC {
    UINT32 OpType;                               // MYARK_MUTATION_TX_OP_*
    UINT32 Pid;                                  // target process
    UINT32 PplLevel;                             // PPL: level (bits [2:0])
    UINT32 FlagsMask;                            // Flags2: mask of bits to touch
    UINT32 FlagsValue;                           // Flags2: value under the mask
    UINT32 Reserved1;
} MYARK_MUTATION_TX_OP_SPEC, *PMYARK_MUTATION_TX_OP_SPEC;

typedef struct _MYARK_MUTATION_TX_PREPARE_INPUT {
    MYARK_SAFETY_TOKEN Token;                    // op = MYARK_MUTATION_OP_TX_PREPARE
    UINT32 OpCount;                              // 1..MYARK_MUTATION_TX_MAX_OPS
    UINT32 Reserved1;
    UINT32 Reserved2;
    MYARK_MUTATION_TX_OP_SPEC Ops[MYARK_MUTATION_TX_MAX_OPS];
} MYARK_MUTATION_TX_PREPARE_INPUT, *PMYARK_MUTATION_TX_PREPARE_INPUT;

typedef struct _MYARK_MUTATION_TX_PREPARE_OUTPUT {
    UINT32 Status;                               // in-band NTSTATUS
    UINT32 TxToken;                              // slot index (0-based) or -1
    UINT32 OpsAccepted;
    UINT32 Reserved1;
} MYARK_MUTATION_TX_PREPARE_OUTPUT, *PMYARK_MUTATION_TX_PREPARE_OUTPUT;

// COMMIT/ROLLBACK input: SAFETY_TOKEN + TxToken.
typedef struct _MYARK_MUTATION_TX_EXEC_INPUT {
    MYARK_SAFETY_TOKEN Token;                    // op = COMMIT or ROLLBACK
    UINT32 TxToken;                              // slot index from PREPARE
    UINT32 Reserved1;
    UINT32 Reserved2;
} MYARK_MUTATION_TX_EXEC_INPUT, *PMYARK_MUTATION_TX_EXEC_INPUT;

typedef struct _MYARK_MUTATION_TX_EXEC_OUTPUT {
    UINT32 Status;
    UINT32 OpsApplied;
    UINT32 OpsFailed;
    UINT32 TxState;                              // resulting state
} MYARK_MUTATION_TX_EXEC_OUTPUT, *PMYARK_MUTATION_TX_EXEC_OUTPUT;

// TX_LIST audit ring entry.
typedef struct _MYARK_MUTATION_TX_AUDIT_ENTRY {
    UINT64 Timestamp;                            // interrupt time
    UINT32 TxToken;
    UINT32 Action;                               // AUDIT_*
    UINT32 OpsCount;
    UINT32 Status;
} MYARK_MUTATION_TX_AUDIT_ENTRY, *PMYARK_MUTATION_TX_AUDIT_ENTRY;

// TX_LIST per-slot summary.
typedef struct _MYARK_MUTATION_TX_SLOT_INFO {
    UINT32 State;
    UINT32 OpCount;
    UINT32 Token;
    UINT32 Reserved1;
} MYARK_MUTATION_TX_SLOT_INFO, *PMYARK_MUTATION_TX_SLOT_INFO;

typedef struct _MYARK_MUTATION_TX_LIST_OUTPUT {
    UINT32 Status;
    UINT32 ActiveSlots;
    UINT32 AuditCount;                           // events in ring (<= 32)
    UINT32 AuditWriteIdx;
    MYARK_MUTATION_TX_SLOT_INFO Slots[MYARK_MUTATION_TX_MAX_SLOTS];
    MYARK_MUTATION_TX_AUDIT_ENTRY Audit[MYARK_MUTATION_TX_AUDIT_RING];
} MYARK_MUTATION_TX_LIST_OUTPUT, *PMYARK_MUTATION_TX_LIST_OUTPUT;

C_ASSERT(sizeof(MYARK_MUTATION_TX_OP_SPEC) == 24);
C_ASSERT(sizeof(MYARK_MUTATION_TX_PREPARE_INPUT) == 88 + MYARK_MUTATION_TX_MAX_OPS * 24);
C_ASSERT(sizeof(MYARK_MUTATION_TX_PREPARE_OUTPUT) == 16);
C_ASSERT(sizeof(MYARK_MUTATION_TX_EXEC_INPUT) == 88);
C_ASSERT(sizeof(MYARK_MUTATION_TX_EXEC_OUTPUT) == 16);
C_ASSERT(sizeof(MYARK_MUTATION_TX_AUDIT_ENTRY) == 24);
C_ASSERT(sizeof(MYARK_MUTATION_TX_SLOT_INFO) == 16);
