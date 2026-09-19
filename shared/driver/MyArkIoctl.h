// MyArk Core Driver: shared IOCTL protocol header.
//
// This header is the single source of truth for IOCTL constants and
// device naming that every MyArk component (R0 driver, R3 client, tools,
// test rigs) must agree on. Anything protocol-shaped that two layers
// need to reference belongs here or in one of its sibling headers:
//
//   MyArkIoctl.h          -- device names, protocol version, IOCTL flags
//   MyArkCoreIoctl.h      -- 5 core IOCTLs + their struct payloads
//   MyArkModuleIoctl.h    -- module registration / query IOCTLs
//   MyArkPluginApi.h      -- MYARK_MODULE_DESCRIPTOR contract
//   MyArkSharedMemory.h   -- named section protocol for R0<->R3 bulk IO
//
// All five headers live under shared/driver/ and are installed into the
// driver's AdditionalIncludeDirectories so `#include "MyArk*.h"` resolves
// uniformly across the driver tree.

#pragma once

#include <ntddk.h>
#include <wdf.h>

//
// Driver / device identity. MYARK_CORE_WIN32_NAME is what R3 code passes
// to CreateFileW; MYARK_CORE_DEVICE_NAME is what the driver registers for
// the control device; MYARK_CORE_SYMBOLIC_LINK_NAME is the kernel-side
// DOS-device link (WdfDeviceCreateSymbolicLink) that makes the Win32 name
// resolvable. All are kept as wide strings so kernel code can drop them
// into UNICODE_STRING without an extra conversion.
//
#define MYARK_CORE_DEVICE_NAME             L"\\Device\\MyArkCore"
#define MYARK_CORE_WIN32_NAME              L"\\\\.\\MyArkCore"
#define MYARK_CORE_SYMBOLIC_LINK_NAME      L"\\??\\MyArkCore"

//
// Protocol version. Bump MYARK_CORE_PROTOCOL_VERSION whenever a struct in
// this directory changes layout or a new IOCTL is added; the value is
// surfaced via IOCTL_MYARK_CORE_GET_VERSION so R3 can detect skew.
//
#define MYARK_CORE_PROTOCOL_VERSION        1
#define MYARK_MODULE_PROTOCOL_VERSION      1

//
// IOCTL flags consumed by MYARK_IOCTL_ENTRY.Flags. They tell the dispatcher
// to suppress noisy log lines on routine success / completion paths, which
// keeps the kernel log readable under high-volume IOCTL traffic.
//
#define MYARK_IOCTL_FLAG_QUIET_SUCCESS     0x00000001
#define MYARK_IOCTL_FLAG_QUIET_COMPLETION  0x00000002

//
// Device interface GUID. Each MyArkCore installation publishes exactly one
// interface of this type; R3 enumerates it via SetupDi rather than hard-
// coding the symbolic link. A new GUID is generated for every MyArk release
// so installations cannot collide with other third-party ARK
// drivers that may have shipped with a stale copy of these headers.
//
DEFINE_GUID(GUID_DEVINTERFACE_MYARK_CORE,
    0xA3F2C1D4, 0x5B6E, 0x4F70, 0x8A, 0x1B, 0x2C, 0x3D, 0x4E, 0x5F, 0x60, 0x71);
