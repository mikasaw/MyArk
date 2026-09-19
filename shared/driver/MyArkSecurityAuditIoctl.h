// MyArk security-audit module: shared IOCTL protocol between R0 and R3.
//
// Function range 0x7D0..0x7D2 reserved for the security-audit module
// (S7.3). Audit is R3-primary: Defender state / Secure Boot / Trusted
// Boot are read from WMI + bcdedit + the EFI variables. The driver
// acts as a fallback when R3 access is blocked.
//
// The 3 IOCTLs:
//
//   0x7D0  DEFENDER_STATE     - Defender activity state
//   0x7D1  SECURE_BOOT        - Secure Boot status
//   0x7D2  TRUSTED_BOOT       - Trusted Boot (measured boot) status
//
// All 3 IOCTLs use the MyArk METHOD_BUFFERED convention.

#pragma once

#include <ntddk.h>
#include <wdf.h>

// ---------------------------------------------------------------------------
// Module identity + IOCTL function codes.
// ---------------------------------------------------------------------------

#define MYARK_SECURITY_AUDIT_MODULE_ID        0x53454341UL  // 'SECA' ASCII (LE)
#define MYARK_SECURITY_AUDIT_NOTE_MAX         128

//
// 3 IOCTLs (function range 0x7D0..0x7D2). Method/Access match the rest
// of the driver: METHOD_BUFFERED + FILE_ANY_ACCESS.
//
#define IOCTL_MYARK_SECURITY_AUDIT_DEFENDER \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x7D0, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_SECURITY_AUDIT_SECURE_BOOT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x7D1, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_SECURITY_AUDIT_TRUSTED_BOOT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x7D2, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// DEFENDER_STATE output: Defender activity state.
// ---------------------------------------------------------------------------
//

typedef struct _MYARK_SECURITY_AUDIT_DEFENDER_OUTPUT {
    UINT32  IsInstalled;
    UINT32  IsRunning;
    UINT32  IsRealTimeProtectionEnabled;
    UINT32  Reserved;
    WCHAR   Note[MYARK_SECURITY_AUDIT_NOTE_MAX];
} MYARK_SECURITY_AUDIT_DEFENDER_OUTPUT, *PMYARK_SECURITY_AUDIT_DEFENDER_OUTPUT;

//
// SECURE_BOOT output: Secure Boot status.
// ---------------------------------------------------------------------------
//

typedef struct _MYARK_SECURITY_AUDIT_SECURE_BOOT_OUTPUT {
    UINT32  IsEnabled;
    UINT32  Reserved;
    WCHAR   Note[MYARK_SECURITY_AUDIT_NOTE_MAX];
} MYARK_SECURITY_AUDIT_SECURE_BOOT_OUTPUT, *PMYARK_SECURITY_AUDIT_SECURE_BOOT_OUTPUT;

//
// TRUSTED_BOOT output: Trusted Boot (measured boot) status.
// ---------------------------------------------------------------------------
//

typedef struct _MYARK_SECURITY_AUDIT_TRUSTED_BOOT_OUTPUT {
    UINT32  IsMeasuredBootEnabled;
    UINT32  IsEventLogPresent;
    UINT32  Reserved1;
    UINT32  Reserved2;
    WCHAR   Note[MYARK_SECURITY_AUDIT_NOTE_MAX];
} MYARK_SECURITY_AUDIT_TRUSTED_BOOT_OUTPUT, *PMYARK_SECURITY_AUDIT_TRUSTED_BOOT_OUTPUT;

// ---------------------------------------------------------------------------
// R3-6: SECURITY_POSTURE (0x7D3). One read-only snapshot of the platform
// security posture: hypervisor presence + vendor (CPUID), VBS / HVCI state
// and AppLocker enforcement (registry), WDAC active-policy file count
// (CodeIntegrity directory), and the BAM service start type.
// All-not-found states are reported as 2/0xFF-style sentinels, never
// silently coerced to "disabled".
// ---------------------------------------------------------------------------

#define IOCTL_MYARK_SECURITY_AUDIT_POSTURE     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x7D3, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Tri-state for *_ENABLED style fields: 0 = off, 1 = on, 2 = not found.
#define MYARK_SECPOST_OFF        0
#define MYARK_SECPOST_ON         1
#define MYARK_SECPOST_NOTFOUND   2

#define MYARK_SECPOST_HV_VENDOR_CHARS 16
#define MYARK_SECPOST_SERVICESTART_ABSENT 0xFF

typedef struct _MYARK_SECURITY_AUDIT_POSTURE_OUTPUT {
    UINT32 Status;                               // in-band NTSTATUS
    UINT32 HypervisorPresent;                    // CPUID leaf 1 ECX bit 31
    CHAR   HypervisorVendor[MYARK_SECPOST_HV_VENDOR_CHARS]; // leaf 0x40000000
    UINT32 VbsEnabled;                           // DeviceGuard EnableVBS
    UINT32 HvciEnabled;                          // HVCI scenario Enabled
    UINT32 HvciRunning;                          // WasRunningByHygiene
    UINT32 AppLockerCollections;                 // SrpV2 rule collections seen
    UINT32 AppLockerEnforced;                    // any collection enforcing
    UINT32 WdacPolicyCount;                      // active WDAC policy files
    UINT32 WdacDirPresent;                       // CI\CiPolicies\Active visible
    UINT32 BamServiceStart;                      // Services\BAM\Start (0xFF absent)
    UINT32 Reserved1;
    UINT64 Reserved64;
    WCHAR  Note[MYARK_SECURITY_AUDIT_NOTE_MAX];
} MYARK_SECURITY_AUDIT_POSTURE_OUTPUT, *PMYARK_SECURITY_AUDIT_POSTURE_OUTPUT;

C_ASSERT(sizeof(MYARK_SECURITY_AUDIT_POSTURE_OUTPUT) == 328);
