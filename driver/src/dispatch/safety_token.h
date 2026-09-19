// MyArk Core Driver: SAFETY_TOKEN session key + HMAC validation API.
//
// The per-boot session key is generated from SystemPrng at
// MyArkSafetyTokenInit (DriverEntry) and kept in nonpaged memory. Mutating
// IOCTLs (87_actions and the 10_process mutating set) validate the
// caller-supplied MYARK_SAFETY_TOKEN against it via CNG HMAC-SHA256; the
// key itself is served to elevated R3 callers through
// IOCTL_MYARK_CORE_GET_SESSION_KEY (see core_ioctl_handlers.c).
//
// Callers run at PASSIVE_LEVEL behind the sequential default queue, so the
// single pre-allocated CNG hash-object buffer needs no locking.

#pragma once

#include <ntddk.h>
#include "MyArkSafetyToken.h"

//
// Generate the session key and open the CNG HMAC-SHA256 algorithm
// provider. Call once from DriverEntry before any module init.
//
NTSTATUS
MyArkSafetyTokenInit(
    VOID);

//
// Close the algorithm provider and free the hash-object buffer. Call from
// the driver unload path.
//
VOID
MyArkSafetyTokenUnload(
    VOID);

//
// Copy the per-boot session key into KeyOut (MYARK_SAFETY_TOKEN_KEY_SIZE
// bytes). Returns STATUS_INVALID_DEVICE_STATE when called before a
// successful init (the key must never be served zeroed).
//
NTSTATUS
MyArkSafetyTokenGetSessionKey(
    _Out_writes_bytes_(MYARK_SAFETY_TOKEN_KEY_SIZE) PUCHAR KeyOut);

//
// Validate a caller-supplied safety token:
//   1. Magic / ExpectedPid / ExpectedOperation must match,
//   2. Timestamp must be within MYARK_SAFETY_TOKEN_TIME_WINDOW_100NS,
//   3. Signature must equal HMAC-SHA256(key, Magic|Pid|Operation|Timestamp).
// Returns STATUS_SUCCESS or STATUS_ACCESS_DENIED (STATUS_INVALID_PARAMETER
// for a NULL token).
//
NTSTATUS
MyArkSafetyTokenValidate(
    _In_ PMYARK_SAFETY_TOKEN Token,
    _In_ UINT32              ExpectedOperation,
    _In_ UINT32              ExpectedPid);
