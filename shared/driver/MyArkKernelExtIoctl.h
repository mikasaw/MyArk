// MyArk kernel-ext module: shared IOCTL protocol between R0 and R3.
//
// Function range 0x7F0..0x7F1 reserved for the kernel-ext module (S7.3).
// Kernel-ext expands DynData with the Win11 25H2 NtQuerySystemInformation
// classes + a direct syscall-table read for callers that need raw service
// dispatch addresses.
//
// The 2 IOCTLs:
//
//   0x7F0  QUERY_WIN11_INFO   - Win11 25H2 new NtQuerySystemInformation classes
//   0x7F1  READ_SYSCALL_TABLE - Read raw syscall table (kernel-side)
//
// All 2 IOCTLs use the MyArk METHOD_BUFFERED convention.

#pragma once

#include <ntddk.h>
#include <wdf.h>

// ---------------------------------------------------------------------------
// Module identity + IOCTL function codes.
// ---------------------------------------------------------------------------

#define MYARK_KERNEL_EXT_MODULE_ID            0x4B455854UL  // 'KEXT' ASCII (LE)
#define MYARK_KERNEL_EXT_HARD_CAP             128

//
// 2 IOCTLs (function range 0x7F0..0x7F1). Method/Access match the rest
// of the driver: METHOD_BUFFERED + FILE_ANY_ACCESS.
//
#define IOCTL_MYARK_KERNEL_EXT_QUERY_WIN11_INFO \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x7F0, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_KERNEL_EXT_READ_SYSCALL_TABLE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x7F1, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// QUERY_WIN11_INFO input: SystemInformationClass (the 25H2-specific range
// starts at 0xAD per plan v3).
// ---------------------------------------------------------------------------
//

typedef struct _MYARK_KERNEL_EXT_QUERY_INPUT {
    UINT32  SystemInformationClass;
    UINT32  Reserved;
    UINT64  Reserved2;
} MYARK_KERNEL_EXT_QUERY_INPUT, *PMYARK_KERNEL_EXT_QUERY_INPUT;

//
// QUERY_WIN11_INFO output: opaque blob + length.
// ---------------------------------------------------------------------------
//

typedef struct _MYARK_KERNEL_EXT_QUERY_OUTPUT {
    UINT32  Status;
    UINT32  BytesReturned;
    UINT64  Reserved;
    UINT8   Data[1];                              // opaque blob
} MYARK_KERNEL_EXT_QUERY_OUTPUT, *PMYARK_KERNEL_EXT_QUERY_OUTPUT;

//
// READ_SYSCALL_TABLE output: each syscall index + address.
// ---------------------------------------------------------------------------
//

typedef struct _MYARK_KERNEL_EXT_SYSCALL_ENTRY {
    UINT32  SyscallIndex;
    UINT32  Reserved;
    UINT64  Address;
} MYARK_KERNEL_EXT_SYSCALL_ENTRY, *PMYARK_KERNEL_EXT_SYSCALL_ENTRY;

typedef struct _MYARK_KERNEL_EXT_SYSCALL_TABLE_OUTPUT {
    UINT32  Count;
    UINT32  Reserved;
    MYARK_KERNEL_EXT_SYSCALL_ENTRY Entries[1];
} MYARK_KERNEL_EXT_SYSCALL_TABLE_OUTPUT, *PMYARK_KERNEL_EXT_SYSCALL_TABLE_OUTPUT;