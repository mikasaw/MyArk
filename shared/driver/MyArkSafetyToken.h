// MyArk shared safety-token wire format.
//
// MYARK_SAFETY_TOKEN rides at the front of every mutating IOCTL's input
// buffer (87_actions embeds it as Token; the 10_process mutating IOCTLs
// carry it the same way). The Signature field is HMAC-SHA256 over the
// token's own non-signature fields, keyed with the per-boot session key:
//
//     message = Magic (UINT32 LE) | Pid (UINT32 LE) |
//               Operation (UINT32 LE) | Timestamp (LARGE_INTEGER, 8B LE)
//     Signature = HMAC-SHA256(SessionKey, message)  (32 bytes)
//
// The session key is generated from SystemPrng at DriverEntry and is only
// retrievable through IOCTL_MYARK_CORE_GET_SESSION_KEY, which the device
// SDDL restricts to SYSTEM/Administrators. The validator enforces a
// freshness window on Timestamp so a captured buffer cannot be replayed
// in a later session (the key rotates every boot).
//
// R3 mirrors: client/src/myark/protocol/core.py (MYARK_SAFETY_TOKEN) and
// client/src/myark/client/safety_token.py (HMAC computation).

#pragma once

#include <ntddk.h>

#define MYARK_SAFETY_TOKEN_MAGIC             0x4D41524BUL  // 'MARK' ASCII (LE)
#define MYARK_SAFETY_TOKEN_SIGNATURE_SIZE    32
#define MYARK_SAFETY_TOKEN_KEY_SIZE          32

//
// Timestamp freshness window in 100-ns units: +/-120 seconds (1.2e9 ticks).
// Clock skew between the signing call and kernel validation on the same box
// is far below this, while a replayed token from a previous boot or a
// scripted capture falls outside it.
//
#define MYARK_SAFETY_TOKEN_TIME_WINDOW_100NS  ((LONGLONG)1200000000LL)

typedef struct _MYARK_SAFETY_TOKEN {
    UINT32        Magic;
    UINT32        Pid;
    UINT32        Operation;
    UINT32        Reserved1;               // not covered by the MAC
    LARGE_INTEGER Timestamp;
    UINT8         Signature[MYARK_SAFETY_TOKEN_SIGNATURE_SIZE];
    UINT8         Reserved2[16];
} MYARK_SAFETY_TOKEN, *PMYARK_SAFETY_TOKEN;
