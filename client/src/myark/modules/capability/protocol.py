"""
capability R3 - protocol data structures (ctypes mirrors of MyArkCapabilityIoctl.h).

Mirrors ``shared/driver/MyArkCapabilityIoctl.h`` -- every structure here
has the exact same field order, type and size as the kernel struct. The
IOCTL codes match the kernel-side ``CTL_CODE(FILE_DEVICE_UNKNOWN, 0x7E0,
METHOD_BUFFERED, FILE_ANY_ACCESS)`` formula with FILE_DEVICE_UNKNOWN=0x22.
"""

from __future__ import annotations

import ctypes

from myark.protocol.core import _ctl_code


# ---------------------------------------------------------------------------
# IOCTL function code (mirror MyArkCapabilityIoctl.h).
# ---------------------------------------------------------------------------

IOCTL_MYARK_CAPABILITY_REPORT = _ctl_code(0x7E0)


# ---------------------------------------------------------------------------
# Flag bits (mirror MYARK_CAPABILITY_FLAG_*).
# ---------------------------------------------------------------------------

CAPABILITY_FLAG_R0 = 0x00000001
CAPABILITY_FLAG_R3 = 0x00000002
CAPABILITY_FLAG_ENABLED = 0x00000004


# ---------------------------------------------------------------------------
# One row per MyArk module (32 char UTF-16LE module name + 4 UINT32s).
# ---------------------------------------------------------------------------

class MYARK_CAPABILITY_MODULE_ENTRY(ctypes.Structure):
    _fields_ = [
        ("ModuleId", ctypes.c_uint32),
        ("IoctlCount", ctypes.c_uint32),
        ("Flags", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
        ("ModuleName", ctypes.c_wchar * 32),
    ]


class MYARK_CAPABILITY_REPORT_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("DriverVersionMajor", ctypes.c_uint32),
        ("DriverVersionMinor", ctypes.c_uint32),
        ("DriverVersionBuild", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
        ("TotalModules", ctypes.c_uint32),
        ("TotalIoctls", ctypes.c_uint32),
        ("Reserved2", ctypes.c_uint32),
        ("Reserved3", ctypes.c_uint32),
        ("Entries", MYARK_CAPABILITY_MODULE_ENTRY * 1),
    ]


HEADER_SIZE_CAPABILITY_REPORT = ctypes.sizeof(MYARK_CAPABILITY_REPORT_OUTPUT) - ctypes.sizeof(MYARK_CAPABILITY_MODULE_ENTRY)


def capability_report_buffer_size(count: int) -> int:
    return HEADER_SIZE_CAPABILITY_REPORT + count * ctypes.sizeof(MYARK_CAPABILITY_MODULE_ENTRY)