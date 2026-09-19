"""
preflight R3 - protocol data structures (ctypes mirrors of MyArkPreflightIoctl.h).

Mirrors ``shared/driver/MyArkPreflightIoctl.h`` -- every structure here
has the exact same field order, type and size as the kernel struct. The
IOCTL codes match the kernel-side ``CTL_CODE(FILE_DEVICE_UNKNOWN, 0x7C0,
METHOD_BUFFERED, FILE_ANY_ACCESS)`` formula with FILE_DEVICE_UNKNOWN=0x22.

The R3 client overlays R3 fallback data (bcdedit testsigning, Defender
state, Secure Boot) onto the driver reply so the caller gets a single
fully-populated health snapshot regardless of which subsystem answered.
"""

from __future__ import annotations

import ctypes

from myark.protocol.core import _ctl_code


# ---------------------------------------------------------------------------
# IOCTL function code (mirror MyArkPreflightIoctl.h).
# ---------------------------------------------------------------------------

IOCTL_MYARK_PREFLIGHT_HEALTH = _ctl_code(0x7C0)


# ---------------------------------------------------------------------------
# Flag bits (mirror MYARK_PREFLIGHT_FLAG_*).
# ---------------------------------------------------------------------------

PREFLIGHT_FLAG_SAFE_MODE = 0x00000001
PREFLIGHT_FLAG_DEBUG = 0x00000002


# ---------------------------------------------------------------------------
# MYARK_PREFLIGHT_HEALTH_OUTPUT (single fixed-size struct, no tail).
# ---------------------------------------------------------------------------

class MYARK_PREFLIGHT_HEALTH_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("MajorVersion", ctypes.c_uint32),
        ("MinorVersion", ctypes.c_uint32),
        ("BuildNumber", ctypes.c_uint32),
        ("Revision", ctypes.c_uint32),
        ("IsTestSigning", ctypes.c_uint32),
        ("IsSecureBoot", ctypes.c_uint32),
        ("IsDriverSigned", ctypes.c_uint32),
        ("Flags", ctypes.c_uint32),
        ("KernelBase", ctypes.c_uint64),
        ("KernelSize", ctypes.c_uint64),
        ("Note", ctypes.c_wchar * 128),
    ]