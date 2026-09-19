// MyArk ALPC module: shared IOCTL protocol between R0 and R3.
//
// Function range 0x790..0x791 reserved for the ALPC (Advanced Local
// Procedure Call) module (S7.3). ALPC inspection is read-only for
// S7.3: the IOCTL set enumerates ALPC ports on the running build.
// The close-port IOCTL is reserved for the S7.3-fix stage and returns
// STATUS_NOT_IMPLEMENTED on dispatch.
//
// The 2 IOCTLs:
//
//   0x790  ENUMERATE_PORTS   - List ALPC ports
//   0x791  CLOSE_PORT        - Close a port (reserved; S7.3-fix)
//
// All 2 IOCTLs use the MyArk METHOD_BUFFERED convention.

#pragma once

#include <ntddk.h>
#include <wdf.h>

// ---------------------------------------------------------------------------
// Module identity + IOCTL function codes.
// ---------------------------------------------------------------------------

#define MYARK_ALPC_MODULE_ID                  0x414C5043UL  // 'ALPC' ASCII (LE)
#define MYARK_ALPC_NAME_MAX                   64
#define MYARK_ALPC_HARD_CAP                   128

//
// 2 IOCTLs (function range 0x790..0x791). Method/Access match the rest
// of the driver: METHOD_BUFFERED + FILE_ANY_ACCESS.
//
#define IOCTL_MYARK_ALPC_ENUMERATE_PORTS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x790, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYARK_ALPC_CLOSE_PORT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x791, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// ENUMERATE_PORTS output: ALPC port descriptors.
// ---------------------------------------------------------------------------
//

typedef struct _MYARK_ALPC_PORT_ENTRY {
    UINT64  PortAddress;
    UINT32  PortId;
    UINT32  OwnerProcessId;
    UINT32  Flags;                                // bit0 = connected, bit1 = server
    UINT32  Reserved;
    WCHAR   PortName[MYARK_ALPC_NAME_MAX];
} MYARK_ALPC_PORT_ENTRY, *PMYARK_ALPC_PORT_ENTRY;

typedef struct _MYARK_ALPC_PORTS_OUTPUT {
    UINT32  Count;
    UINT32  Reserved;
    MYARK_ALPC_PORT_ENTRY Entries[1];
} MYARK_ALPC_PORTS_OUTPUT, *PMYARK_ALPC_PORTS_OUTPUT;

//
// CLOSE_PORT input (reserved; S7.3-fix).
// ---------------------------------------------------------------------------
typedef struct _MYARK_ALPC_CLOSE_INPUT {
    UINT32  PortId;
    UINT32  Reserved;
    UINT64  Reserved2;
} MYARK_ALPC_CLOSE_INPUT, *PMYARK_ALPC_CLOSE_INPUT;