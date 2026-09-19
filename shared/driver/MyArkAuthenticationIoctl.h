// MyArk authentication module: shared IOCTL protocol between R0 and R3.
//
// Function range 0x7A0 reserved for the authentication (Authenticode)
// module (S7.3). Authenticode verification is read-only for S7.3: the
// IOCTL set inspects PE / catalog signatures via SeSinglePrivilegeCheck
// + the MmGetSystemRoutineAddress-wrapped WinVerifyTrust entry.
//
// The 1 IOCTL:
//
//   0x7A0  VERIFY_FILE       - Verify PE / catalog signature
//
// All 1 IOCTLs use the MyArk METHOD_BUFFERED convention.

#pragma once

#include <ntddk.h>
#include <wdf.h>

// ---------------------------------------------------------------------------
// Module identity + IOCTL function codes.
// ---------------------------------------------------------------------------

#define MYARK_AUTHENTICATION_MODULE_ID        0x41555448UL  // 'AUTH' ASCII (LE)
#define MYARK_AUTHENTICATION_PATH_MAX         260
#define MYARK_AUTHENTICATION_SUBJECT_MAX      128
#define MYARK_AUTHENTICATION_ISSUER_MAX       128

//
// 1 IOCTL (function range 0x7A0). Method/Access match the rest of the
// driver: METHOD_BUFFERED + FILE_ANY_ACCESS.
//
#define IOCTL_MYARK_AUTHENTICATION_VERIFY_FILE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x7A0, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// VERIFY_FILE input: target file path.
// ---------------------------------------------------------------------------
//

typedef struct _MYARK_AUTHENTICATION_VERIFY_INPUT {
    WCHAR   FilePath[MYARK_AUTHENTICATION_PATH_MAX];
} MYARK_AUTHENTICATION_VERIFY_INPUT, *PMYARK_AUTHENTICATION_VERIFY_INPUT;

//
// VERIFY_FILE output: signature state + subject/issuer (when present).
// ---------------------------------------------------------------------------
//

typedef struct _MYARK_AUTHENTICATION_VERIFY_OUTPUT {
    UINT32  Status;                               // 0 = trusted, 1 = untrusted, 2 = not-signed
    UINT32  Flags;                                // bit0 = catalog-signed, bit1 = embedded-sig
    WCHAR   Subject[MYARK_AUTHENTICATION_SUBJECT_MAX];
    WCHAR   Issuer[MYARK_AUTHENTICATION_ISSUER_MAX];
    UINT64  NotBefore;                            // FILETIME
    UINT64  NotAfter;                             // FILETIME
} MYARK_AUTHENTICATION_VERIFY_OUTPUT, *PMYARK_AUTHENTICATION_VERIFY_OUTPUT;

#define MYARK_AUTHENTICATION_TRUSTED          0
#define MYARK_AUTHENTICATION_UNTRUSTED        1
#define MYARK_AUTHENTICATION_NOT_SIGNED       2

#define MYARK_AUTHENTICATION_FLAG_CATALOG     0x00000001UL
#define MYARK_AUTHENTICATION_FLAG_EMBEDDED    0x00000002UL