"""
security-audit R3 - protocol data structures (ctypes mirrors of MyArkSecurityAuditIoctl.h).
"""

from __future__ import annotations

import ctypes

from myark.protocol.core import _ctl_code


IOCTL_MYARK_SECURITY_AUDIT_DEFENDER = _ctl_code(0x7D0)
IOCTL_MYARK_SECURITY_AUDIT_SECURE_BOOT = _ctl_code(0x7D1)
IOCTL_MYARK_SECURITY_AUDIT_TRUSTED_BOOT = _ctl_code(0x7D2)


class MYARK_SECURITY_AUDIT_DEFENDER_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("IsInstalled", ctypes.c_uint32),
        ("IsRunning", ctypes.c_uint32),
        ("IsRealTimeProtectionEnabled", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
        ("Note", ctypes.c_wchar * 128),
    ]


class MYARK_SECURITY_AUDIT_SECURE_BOOT_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("IsEnabled", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
        ("Note", ctypes.c_wchar * 128),
    ]


class MYARK_SECURITY_AUDIT_TRUSTED_BOOT_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("IsMeasuredBootEnabled", ctypes.c_uint32),
        ("IsEventLogPresent", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
        ("Reserved2", ctypes.c_uint32),
        ("Note", ctypes.c_wchar * 128),
    ]