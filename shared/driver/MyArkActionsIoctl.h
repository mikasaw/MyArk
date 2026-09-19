// MyArk actions module: shared IOCTL protocol between R0 and R3.
//
// Function range 0x870 reserved for the actions (mixed R0+R3) module
// (S8.1). Actions are dangerous operations (kill process, inject DLL,
// set token, hide / protect process) -- every dispatch requires a
// caller-supplied MYARK_SAFETY_TOKEN so the driver's safety policy can
// gate the call without re-running the R3 dialog.
//
// All 7 IOCTLs use the MyArk METHOD_BUFFERED convention with
// FILE_ANY_ACCESS so any process can open the device; the token + the
// required-step gate (86_safety) carry the authorization payload.
//
// Tiered-degradation policy (plan v3):
//   * Default R3 implementation is the host-friendly fallback (Python
//     uses win32 TerminateProcess, CreateRemoteThread, ReadProcessMemory
//     etc.). R0 is only consulted when the .sys is loaded AND the call
//     is one of the R0-only actions (SET_TOKEN, HIDE_PROCESS,
//     PROTECT_PROCESS).
//   * The R0 handler validates the safety token and returns
//     STATUS_SUCCESS with an audit-trail result struct. VM-side
//     verification (S8.1-VM, run by the user in the Hyper-V guest)
//     exercises the destructive code path; Mode A (the agent) only
//     builds the protocol + handler structure.

#pragma once

#include <ntddk.h>
#include <wdf.h>

// ---------------------------------------------------------------------------
// Module identity + IOCTL function codes.
// ---------------------------------------------------------------------------

#define MYARK_ACTIONS_MODULE_ID              0x4143544EUL  // 'ACTN' ASCII (LE)

//
// 8 IOCTLs (function range 0x870..0x877). Method/Access match the rest
// of the driver: METHOD_BUFFERED + FILE_ANY_ACCESS.
//
#define IOCTL_MYARK_ACTION_KILL_PROCESS      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x870, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MYARK_ACTION_TERMINATE_THREAD  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x871, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MYARK_ACTION_INJECT_DLL        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x872, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MYARK_ACTION_DUMP_MEMORY       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x873, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MYARK_ACTION_SET_TOKEN         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x874, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MYARK_ACTION_HIDE_PROCESS      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x875, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MYARK_ACTION_PROTECT_PROCESS   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x876, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MYARK_ACTION_INJECT_SHELLCODE  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x877, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define MYARK_ACTION_KILL_MAX_REASON_CHARS   256
#define MYARK_ACTION_DLL_PATH_MAX_CHARS      260            // MAX_PATH

//
// ---------------------------------------------------------------------------
// MYARK_SAFETY_TOKEN lives in MyArkSafetyToken.h so the 10_process
// mutating IOCTLs can carry the same wire format. The Signature field is
// a real HMAC-SHA256 over the token's non-signature fields keyed with the
// per-boot session key (see MyArkSafetyToken.h) -- the driver rejects
// tokens whose digest does not verify.
// ---------------------------------------------------------------------------
//

#include "MyArkSafetyToken.h"

//
// Operation codes carried in MYARK_SAFETY_TOKEN.Operation. They are the
// action identifiers the policy engine + UI use to gate the call.
//
#define MYARK_ACTION_OP_KILL_PROCESS         1
#define MYARK_ACTION_OP_TERMINATE_THREAD     2
#define MYARK_ACTION_OP_INJECT_DLL           3
#define MYARK_ACTION_OP_DUMP_MEMORY          4
#define MYARK_ACTION_OP_SET_TOKEN            5
#define MYARK_ACTION_OP_HIDE_PROCESS         6
#define MYARK_ACTION_OP_PROTECT_PROCESS      7
#define MYARK_ACTION_OP_INJECT_SHELLCODE     8

//
// Result code returned in the OUTPUT struct's ResultCode. The driver
// reports back which tier actually executed (or whether the policy
// gate denied the call).
//
#define MYARK_ACTION_RESULT_APPROVED         0
#define MYARK_ACTION_RESULT_DENIED           1
#define MYARK_ACTION_RESULT_DENIED_NO_TOKEN  2
#define MYARK_ACTION_RESULT_DENIED_STEPS     3
#define MYARK_ACTION_RESULT_DEFERRED         4   // Mode A: R0 ack, real exec on VM
#define MYARK_ACTION_RESULT_FAILED           5
#define MYARK_ACTION_RESULT_R3_FALLBACK      6

//
// Common header returned by every action IOCTL. Each per-action output
// struct below extends this header with its own audit fields.
//
typedef struct _MYARK_ACTION_OUTPUT {
    UINT32 Size;                                // sizeof this output struct
    UINT32 ResultCode;
    UINT32 ExecutedTier;                        // 0=R0, 1=R3, 2=deferred
    UINT32 Reserved1;
    LARGE_INTEGER Timestamp;                    // driver time when action ack'd
    UINT8  AuditMessage[64];                    // short string for log
} MYARK_ACTION_OUTPUT, *PMYARK_ACTION_OUTPUT;

//
// Executed-tier values (mirror MYARK_ACTION_RESULT_DEFERRED etc. but as
// a stand-alone field so callers can distinguish the result code from
// the tier even when the action was approved under "deferred" semantics).
//
#define MYARK_ACTION_TIER_R0                  0
#define MYARK_ACTION_TIER_R3                  1
#define MYARK_ACTION_TIER_DEFERRED            2

//
// ---------------------------------------------------------------------------
// KILL_PROCESS: kill a process by PID. R0 fallback is NtTerminateProcess
// (only reachable after the safety token gate). The input carries the
// PID + a free-form Reason string (max 256 WCHAR).
// ---------------------------------------------------------------------------
//

typedef struct _MYARK_ACTION_KILL_INPUT {
    MYARK_SAFETY_TOKEN Token;
    UINT32             Pid;
    UINT32             ExitCode;
    UINT32             Reserved1;
    UINT32             Reserved2;
    WCHAR              Reason[MYARK_ACTION_KILL_MAX_REASON_CHARS];
} MYARK_ACTION_KILL_INPUT, *PMYARK_ACTION_KILL_INPUT;

typedef struct _MYARK_ACTION_KILL_OUTPUT {
    MYARK_ACTION_OUTPUT Header;
    UINT32              Pid;
    UINT32              ExitCode;
    UINT32              Reserved1;
    UINT32              Reserved2;
} MYARK_ACTION_KILL_OUTPUT, *PMYARK_ACTION_KILL_OUTPUT;

//
// ---------------------------------------------------------------------------
// TERMINATE_THREAD: kill one thread inside a process.
// ---------------------------------------------------------------------------
//

typedef struct _MYARK_ACTION_TERMINATE_THREAD_INPUT {
    MYARK_SAFETY_TOKEN Token;
    UINT32             Pid;
    UINT32             Tid;
    UINT32             ExitCode;
    UINT32             Reserved1;
} MYARK_ACTION_TERMINATE_THREAD_INPUT, *PMYARK_ACTION_TERMINATE_THREAD_INPUT;

typedef struct _MYARK_ACTION_TERMINATE_THREAD_OUTPUT {
    MYARK_ACTION_OUTPUT Header;
    UINT32              Pid;
    UINT32              Tid;
    UINT32              ExitCode;
    UINT32              Reserved1;
} MYARK_ACTION_TERMINATE_THREAD_OUTPUT, *PMYARK_ACTION_TERMINATE_THREAD_OUTPUT;

//
// ---------------------------------------------------------------------------
// INJECT_DLL: load a DLL into a process via CreateRemoteThread (R3) or
// NtCreateThreadEx (R0). DllPath is a null-terminated WCHAR string.
// ---------------------------------------------------------------------------
//

typedef struct _MYARK_ACTION_INJECT_DLL_INPUT {
    MYARK_SAFETY_TOKEN Token;
    UINT32             Pid;
    UINT32             Reserved1;
    UINT32             Reserved2;
    UINT32             Reserved3;
    WCHAR              DllPath[MYARK_ACTION_DLL_PATH_MAX_CHARS];
} MYARK_ACTION_INJECT_DLL_INPUT, *PMYARK_ACTION_INJECT_DLL_INPUT;

typedef struct _MYARK_ACTION_INJECT_DLL_OUTPUT {
    MYARK_ACTION_OUTPUT Header;
    UINT32              Pid;
    UINT32              Reserved1;
    UINT64              RemoteThreadHandle;
} MYARK_ACTION_INJECT_DLL_OUTPUT, *PMYARK_ACTION_INJECT_DLL_OUTPUT;

//
// ---------------------------------------------------------------------------
// DUMP_MEMORY: copy (Address, Size) bytes out of the target process into
// a caller-supplied buffer. R0 fallback is MmCopyVirtualMemory.
// ---------------------------------------------------------------------------
//

#define MYARK_ACTION_DUMP_MAX_BYTES          4096

typedef struct _MYARK_ACTION_DUMP_MEMORY_INPUT {
    MYARK_SAFETY_TOKEN Token;
    UINT32             Pid;
    UINT32             Reserved1;
    UINT64             Address;
    UINT64             Size;
} MYARK_ACTION_DUMP_MEMORY_INPUT, *PMYARK_ACTION_DUMP_MEMORY_INPUT;

typedef struct _MYARK_ACTION_DUMP_MEMORY_OUTPUT {
    MYARK_ACTION_OUTPUT Header;
    UINT32              Pid;
    UINT32              BytesReturned;
    UINT64              Address;
    UINT8               Data[MYARK_ACTION_DUMP_MAX_BYTES];
} MYARK_ACTION_DUMP_MEMORY_OUTPUT, *PMYARK_ACTION_DUMP_MEMORY_OUTPUT;

//
// ---------------------------------------------------------------------------
// SET_TOKEN: assign a primary or impersonation token to a process.
// R0-only (no R3 fallback; SeAssignPrimaryTokenPrivilege requires
// SeSinglePrivilegeCheck). TokenType selects primary vs. impersonation.
// ---------------------------------------------------------------------------
//

#define MYARK_ACTION_TOKEN_TYPE_PRIMARY      0
#define MYARK_ACTION_TOKEN_TYPE_IMPERSONATION 1

typedef struct _MYARK_ACTION_SET_TOKEN_INPUT {
    MYARK_SAFETY_TOKEN Token;
    UINT32             Pid;
    UINT32             TokenType;
    UINT32             Reserved1;
    UINT32             Reserved2;
} MYARK_ACTION_SET_TOKEN_INPUT, *PMYARK_ACTION_SET_TOKEN_INPUT;

typedef struct _MYARK_ACTION_SET_TOKEN_OUTPUT {
    MYARK_ACTION_OUTPUT Header;
    UINT32              Pid;
    UINT32              TokenType;
    UINT32              Reserved1;
    UINT32              Reserved2;
} MYARK_ACTION_SET_TOKEN_OUTPUT, *PMYARK_ACTION_SET_TOKEN_OUTPUT;

//
// ---------------------------------------------------------------------------
// HIDE_PROCESS: DKOM unlink from ActiveProcessLinks. R0-only.
// ---------------------------------------------------------------------------
//

typedef struct _MYARK_ACTION_HIDE_PROCESS_INPUT {
    MYARK_SAFETY_TOKEN Token;
    UINT32             Pid;
    UINT32             Reserved1;
    UINT32             Reserved2;
    UINT32             Reserved3;
} MYARK_ACTION_HIDE_PROCESS_INPUT, *PMYARK_ACTION_HIDE_PROCESS_INPUT;

typedef struct _MYARK_ACTION_HIDE_PROCESS_OUTPUT {
    MYARK_ACTION_OUTPUT Header;
    UINT32              Pid;
    UINT32              Reserved1;
    UINT32              Reserved2;
    UINT32              Reserved3;
} MYARK_ACTION_HIDE_PROCESS_OUTPUT, *PMYARK_ACTION_HIDE_PROCESS_OUTPUT;

//
// ---------------------------------------------------------------------------
// PROTECT_PROCESS: mark a process so subsequent TerminateProcess attempts
// from R3 fail with STATUS_ACCESS_DENIED. R0-only; uses the existing
// PS_PROTECTION field on EPROCESS when available, otherwise PspSet.
// ---------------------------------------------------------------------------
//

#define MYARK_ACTION_PROTECT_FLAG_NONE       0x00000000
#define MYARK_ACTION_PROTECT_FLAG_SIGNED      0x00000001
#define MYARK_ACTION_PROTECT_FLAG_LSA         0x00000002
#define MYARK_ACTION_PROTECT_FLAG_WINTCB      0x00000004

typedef struct _MYARK_ACTION_PROTECT_PROCESS_INPUT {
    MYARK_SAFETY_TOKEN Token;
    UINT32             Pid;
    UINT32             Flags;
    UINT32             Reserved1;
    UINT32             Reserved2;
} MYARK_ACTION_PROTECT_PROCESS_INPUT, *PMYARK_ACTION_PROTECT_PROCESS_INPUT;

typedef struct _MYARK_ACTION_PROTECT_PROCESS_OUTPUT {
    MYARK_ACTION_OUTPUT Header;
    UINT32              Pid;
    UINT32              Flags;
    UINT32              Reserved1;
    UINT32              Reserved2;
} MYARK_ACTION_PROTECT_PROCESS_OUTPUT, *PMYARK_ACTION_PROTECT_PROCESS_OUTPUT;

// ---------------------------------------------------------------------------
// INJECT_SHELLCODE (R3-2, T-C): write a caller-supplied payload into the
// target process (ZwAllocateVirtualMemory -> ZwWriteVirtualMemory ->
// ZwProtectVirtualMemory PAGE_EXECUTE_READ) and queue it as a
// user APC via KeInsertQueueApc (ZwCreateThreadEx is not an export). Caps:
// PayloadSize <= MYARK_ACTION_SHELLCODE_MAX_BYTES (256 KB) and non-zero.
// PPL targets are rejected at ZwOpenProcess (VM_WRITE against a protected
// process fails for a non-PPL driver) and surfaced as ACCESS_DENIED.
// Authorized-test-environment surface only; the payload comes entirely
// from the caller -- the repository ships no weaponized payload, only the
// benign ExitThread-style test stub used by the regression.
// ---------------------------------------------------------------------------

#define MYARK_ACTION_SHELLCODE_MAX_BYTES     (256 * 1024)

typedef struct _MYARK_ACTION_INJECT_SHELLCODE_INPUT {
    MYARK_SAFETY_TOKEN Token;                        // op = MYARK_ACTION_OP_INJECT_SHELLCODE
    UINT32             Pid;                          // target process
    UINT32             TargetTid;                    // thread the user APC queues to
    UINT32             PayloadSize;                  // bytes in Payload[]
    UINT32             Flags;                        // reserved, must be 0
    UINT8              Payload[1];                   // PayloadSize bytes
} MYARK_ACTION_INJECT_SHELLCODE_INPUT, *PMYARK_ACTION_INJECT_SHELLCODE_INPUT;

typedef struct _MYARK_ACTION_INJECT_SHELLCODE_OUTPUT {
    MYARK_ACTION_OUTPUT Header;                      // in-band result
    UINT32             Pid;
    UINT32             ThreadId;                     // new thread id (0 = unknown)
    UINT64             RemoteBase;                   // payload base in target
    UINT64             RemoteSize;                   // committed size
} MYARK_ACTION_INJECT_SHELLCODE_OUTPUT, *PMYARK_ACTION_INJECT_SHELLCODE_OUTPUT;
