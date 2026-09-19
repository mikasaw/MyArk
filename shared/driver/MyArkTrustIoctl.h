// MyArk trust module: shared IOCTL protocol between R0 and R3.
//
// Function range 0x7B0..0x7B1 reserved for the trust module (S7.3).
// Trust verification is R3-primary for S7.3: WinVerifyTrust runs in
// user mode, but the driver can act as a fallback when the R3 client
// is not allowed to call wintrust.dll (e.g. service context).
//
// The 2 IOCTLs:
//
//   0x7B0  VERIFY_PE         - Verify PE signature (R3/R0 hybrid)
//   0x7B1  VERIFY_CATALOG    - Verify catalog signature (R3/R0 hybrid)
//
// All 2 IOCTLs use the MyArk METHOD_BUFFERED convention.

#pragma once

#include <ntddk.h>
#include <wdf.h>

// ---------------------------------------------------------------------------
// Module identity + IOCTL function codes.
// ---------------------------------------------------------------------------

#define MYARK_TRUST_MODULE_ID                 0x54525553UL  // 'TRUS' ASCII (LE)
#define MYARK_TRUST_PATH_MAX                  260
#define MYARK_TRUST_SUBJECT_MAX               128
#define MYARK_TRUST_ISSUER_MAX                128

//
// 2 IOCTLs (function range 0x7B0..0x7B1). Method/Access match the rest
// of the driver: METHOD_BUFFERED + FILE_ANY_ACCESS.
//
#define IOCTL_MYARK_TRUST_VERIFY_PE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x7B0, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_TRUST_VERIFY_CATALOG \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x7B1, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// VERIFY_PE / VERIFY_CATALOG input: file path + flags.
// ---------------------------------------------------------------------------
//

typedef struct _MYARK_TRUST_VERIFY_INPUT {
    WCHAR   FilePath[MYARK_TRUST_PATH_MAX];
    UINT32  Flags;                                // bit0 = catalog-required
    UINT32  Reserved;
} MYARK_TRUST_VERIFY_INPUT, *PMYARK_TRUST_VERIFY_INPUT;

//
// VERIFY_PE / VERIFY_CATALOG output: trust result + signer info.
// ---------------------------------------------------------------------------
//

typedef struct _MYARK_TRUST_VERIFY_OUTPUT {
    UINT32  Status;                               // 0 = trusted, 1 = untrusted, 2 = not-signed
    UINT32  Flags;                                // bit0 = catalog, bit1 = embedded, bit2 = timestamp
    WCHAR   Subject[MYARK_TRUST_SUBJECT_MAX];
    WCHAR   Issuer[MYARK_TRUST_ISSUER_MAX];
    UINT64  NotBefore;
    UINT64  NotAfter;
} MYARK_TRUST_VERIFY_OUTPUT, *PMYARK_TRUST_VERIFY_OUTPUT;

#define MYARK_TRUST_TRUSTED                   0
#define MYARK_TRUST_UNTRUSTED                 1
#define MYARK_TRUST_NOT_SIGNED                2

#define MYARK_TRUST_FLAG_CATALOG              0x00000001UL
#define MYARK_TRUST_FLAG_EMBEDDED             0x00000002UL
#define MYARK_TRUST_FLAG_TIMESTAMP            0x00000004UL