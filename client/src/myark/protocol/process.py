"""ctypes protocol definitions for the process module IOCTLs (0xA00..0xA0C).

Mirrors ``shared/driver/MyArkProcessIoctl.h`` -- every structure here has
the same field order, type and size as the kernel struct. The IOCTL
codes match the kernel-side ``CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA0X,
METHOD_BUFFERED, FILE_ANY_ACCESS)`` formula with FILE_DEVICE_UNKNOWN=0x22.

Only the structural definitions live here; the R3 enumeration / detail
parsers (psapi, advapi32, toolhelp) live in
``myark.modules.process.parser`` so this header stays a thin wire-format
mirror. Drivers are not installed in every test environment, so callers
that actually round-trip through the driver must use
``myark.client.ark_client.ArkClient.ioctl`` with the IOCTL code
defined here.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes

from .core import (
    FILE_DEVICE_UNKNOWN,
    FILE_ANY_ACCESS,
    METHOD_BUFFERED,
    MYARK_SAFETY_TOKEN,
)

# -----------------------------------------------------------------------------
# Windows IOCTL formula (must match the driver-side CTL_CODE).
# -----------------------------------------------------------------------------

def _ctl_code(function: int) -> int:
    return (FILE_DEVICE_UNKNOWN << 16) | (FILE_ANY_ACCESS << 14) | (function << 2) | METHOD_BUFFERED


# Process module IOCTL function codes (0xA00..0xA0C).
IOCTL_MYARK_PROCESS_ENUM = _ctl_code(0xA00)
IOCTL_MYARK_PROCESS_ENUM_THREAD = _ctl_code(0xA01)
IOCTL_MYARK_PROCESS_DETAIL = _ctl_code(0xA02)
IOCTL_MYARK_PROCESS_DETAIL_RUNTIME = _ctl_code(0xA03)
IOCTL_MYARK_PROCESS_CROSSVIEW = _ctl_code(0xA04)
IOCTL_MYARK_PROCESS_TERMINATE = _ctl_code(0xA05)
IOCTL_MYARK_PROCESS_SUSPEND = _ctl_code(0xA06)
IOCTL_MYARK_PROCESS_SET_PPL_LEVEL = _ctl_code(0xA07)
IOCTL_MYARK_PROCESS_SET_INTEGRITY = _ctl_code(0xA08)
IOCTL_MYARK_PROCESS_SET_VISIBILITY = _ctl_code(0xA09)
IOCTL_MYARK_PROCESS_SET_SPECIAL_FLAGS = _ctl_code(0xA0A)
IOCTL_MYARK_PROCESS_DKOM = _ctl_code(0xA0B)
IOCTL_MYARK_PROCESS_INJECT = _ctl_code(0xA0C)

# Process module identity.
MYARK_PROCESS_MODULE_ID = 0x50524F43  # 'PROC' ASCII (LE)
MYARK_PROCESS_NAME_MAX = 64
MYARK_PROCESS_PATH_MAX = 260
MYARK_PROCESS_USER_MAX = 64
MYARK_PROCESS_IMAGE_FILE_NAME_MAX = 16

# Source mask (3-view model).
PROCESS_SRC_NONE = 0x00
PROCESS_SRC_PUBLIC = 0x01
PROCESS_SRC_PSPCIDTABLE = 0x02
PROCESS_SRC_ACTIVE_LINKS = 0x04

PROCESS_HIDDEN_NONE = 0x00
PROCESS_HIDDEN_VIA_DKOM = 0x01


# -----------------------------------------------------------------------------
# ENUM input/output (process list + SourceMask + HiddenCount).
# -----------------------------------------------------------------------------

class MYARK_PROCESS_ENTRY(ctypes.Structure):
    _fields_ = [
        ("Pid", ctypes.c_uint32),
        ("Ppid", ctypes.c_uint32),
        ("Name", ctypes.c_wchar * MYARK_PROCESS_NAME_MAX),
        ("Path", ctypes.c_wchar * MYARK_PROCESS_PATH_MAX),
        ("User", ctypes.c_wchar * MYARK_PROCESS_USER_MAX),
        ("MemKb", ctypes.c_uint32),
        ("Ppl", ctypes.c_uint8),
        ("Hidden", ctypes.c_uint8),
        ("SourceMask", ctypes.c_uint8),
        ("Reserved", ctypes.c_uint8),
    ]


class MYARK_PROCESS_ENUM_INPUT(ctypes.Structure):
    _fields_ = [
        ("MaxEntries", ctypes.c_uint32),
        ("SourceMask", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
    ]


class MYARK_PROCESS_ENUM_OUTPUT(ctypes.Structure):
    """Variable-length: ``Entries[1]`` is a placeholder for one row."""
    _fields_ = [
        ("Size", ctypes.c_uint32),
        ("Count", ctypes.c_uint32),
        ("TotalSeen", ctypes.c_uint32),
        ("HiddenCount", ctypes.c_uint32),
        ("Entries", MYARK_PROCESS_ENTRY * 1),
    ]


# -----------------------------------------------------------------------------
# ENUM_THREAD input/output.
# -----------------------------------------------------------------------------

class MYARK_THREAD_ENTRY(ctypes.Structure):
    _fields_ = [
        ("Tid", ctypes.c_uint32),
        ("OwnerPid", ctypes.c_uint32),
        ("State", ctypes.c_uint32),
        ("Priority", ctypes.c_uint32),
        ("WaitReason", ctypes.c_uint32),
        ("CreateTime", ctypes.c_uint64),
    ]


class MYARK_PROCESS_ENUM_THREAD_INPUT(ctypes.Structure):
    _fields_ = [
        ("Pid", ctypes.c_uint32),
        ("MaxEntries", ctypes.c_uint32),
    ]


class MYARK_PROCESS_ENUM_THREAD_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Size", ctypes.c_uint32),
        ("Count", ctypes.c_uint32),
        ("OwnerPid", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
        ("Entries", MYARK_THREAD_ENTRY * 1),
    ]


# -----------------------------------------------------------------------------
# DETAIL (deep single-process dump).
# -----------------------------------------------------------------------------

class MYARK_PROCESS_DETAIL(ctypes.Structure):
    _fields_ = [
        ("Pid", ctypes.c_uint32),
        ("Ppid", ctypes.c_uint32),
        ("Flags2", ctypes.c_uint32),
        ("Ppl", ctypes.c_uint32),
        ("SignatureLevel", ctypes.c_uint32),
        ("SectionSignatureLevel", ctypes.c_uint32),
        ("Protection", ctypes.c_uint32),
        ("ExitStatus", ctypes.c_uint32),
        ("CreateTime", ctypes.c_uint64),
        ("KernelTime", ctypes.c_uint64),
        ("UserTime", ctypes.c_uint64),
        ("HandleCount", ctypes.c_uint32),
        ("ThreadCount", ctypes.c_uint32),
        ("BasePriority", ctypes.c_uint32),
        ("AffinityMask", ctypes.c_uint32),
        ("UniqueProcessIdOffset", ctypes.c_uint32),
        ("ImageFileNameOffset", ctypes.c_uint32),
        ("ActiveProcessLinksOffset", ctypes.c_uint32),
        ("InheritedFromUniqueProcessIdOffset", ctypes.c_uint32),
        ("PebOffset", ctypes.c_uint32),
        ("ThreadListHeadOffset", ctypes.c_uint32),
        ("EProcessKernelAddress", ctypes.c_uint64),
        ("Name", ctypes.c_wchar * MYARK_PROCESS_NAME_MAX),
        ("Path", ctypes.c_wchar * MYARK_PROCESS_PATH_MAX),
        ("User", ctypes.c_wchar * MYARK_PROCESS_USER_MAX),
        ("ImageFileName", ctypes.c_char * MYARK_PROCESS_IMAGE_FILE_NAME_MAX),
    ]


class MYARK_PROCESS_DETAIL_RUNTIME(ctypes.Structure):
    _fields_ = [
        ("Pid", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("PeakWorkingSetSize", ctypes.c_uint64),
        ("WorkingSetSize", ctypes.c_uint64),
        ("QuotaPeakPagedPoolUsage", ctypes.c_uint64),
        ("QuotaPagedPoolUsage", ctypes.c_uint64),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_uint64),
        ("QuotaNonPagedPoolUsage", ctypes.c_uint64),
        ("PagefileUsage", ctypes.c_uint64),
        ("PeakPagefileUsage", ctypes.c_uint64),
        ("PrivatePageCount", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
        ("CycleTime", ctypes.c_uint64),
    ]


# -----------------------------------------------------------------------------
# CROSSVIEW input/output.
# -----------------------------------------------------------------------------

class MYARK_PROCESS_CROSSVIEW_INPUT(ctypes.Structure):
    _fields_ = [
        ("Pid", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
        ("Reserved2", ctypes.c_uint32),
    ]


class MYARK_PROCESS_CROSSVIEW_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Size", ctypes.c_uint32),
        ("Count", ctypes.c_uint32),
        ("PublicOnly", ctypes.c_uint32),
        ("HiddenCount", ctypes.c_uint32),
        ("Entries", MYARK_PROCESS_ENTRY * 1),
    ]


# -----------------------------------------------------------------------------
# Mutating IOCTLs (terminate / suspend / set-ppl / set-integrity / etc.).
# Each input carries a leading HMAC-signed MYARK_SAFETY_TOKEN (mirror of
# shared/driver/MyArkSafetyToken.h; signed via myark.client.safety_token)
# and returns an _OUTPUT with the resulting status.
# -----------------------------------------------------------------------------


class MYARK_PROCESS_TERMINATE_INPUT(ctypes.Structure):
    _fields_ = [
        ("Token", MYARK_SAFETY_TOKEN),
        ("Pid", ctypes.c_uint32),
        ("ExitCode", ctypes.c_uint32),
        ("Force", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
    ]


class MYARK_PROCESS_TERMINATE_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Pid", ctypes.c_uint32),
        ("Status", ctypes.c_uint32),
        ("UsedR0Fallback", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
    ]


class MYARK_PROCESS_SUSPEND_INPUT(ctypes.Structure):
    _fields_ = [
        ("Token", MYARK_SAFETY_TOKEN),
        ("Pid", ctypes.c_uint32),
        ("Resume", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
    ]


class MYARK_PROCESS_SUSPEND_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Pid", ctypes.c_uint32),
        ("Suspended", ctypes.c_uint32),
        ("Status", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
    ]


class MYARK_PROCESS_SET_PPL_INPUT(ctypes.Structure):
    _fields_ = [
        ("Token", MYARK_SAFETY_TOKEN),
        ("Pid", ctypes.c_uint32),
        ("Level", ctypes.c_uint8),
        ("Audit", ctypes.c_uint8),
        ("Type", ctypes.c_uint8),
        ("Reserved", ctypes.c_uint8),
        ("Reserved0", ctypes.c_uint32),
    ]


class MYARK_PROCESS_SET_PPL_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Pid", ctypes.c_uint32),
        ("Status", ctypes.c_uint32),
        ("PreviousLevel", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
    ]


class MYARK_PROCESS_SET_INTEGRITY_INPUT(ctypes.Structure):
    _fields_ = [
        ("Token", MYARK_SAFETY_TOKEN),
        ("Pid", ctypes.c_uint32),
        ("IntegrityLevel", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
    ]


class MYARK_PROCESS_SET_INTEGRITY_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Pid", ctypes.c_uint32),
        ("Status", ctypes.c_uint32),
        ("PreviousIntegrity", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
    ]


class MYARK_PROCESS_SET_VISIBILITY_INPUT(ctypes.Structure):
    _fields_ = [
        ("Token", MYARK_SAFETY_TOKEN),
        ("Pid", ctypes.c_uint32),
        ("Hide", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
    ]


class MYARK_PROCESS_SET_VISIBILITY_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Pid", ctypes.c_uint32),
        ("Status", ctypes.c_uint32),
        ("Hidden", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
    ]


class MYARK_PROCESS_SET_SPECIAL_FLAGS_INPUT(ctypes.Structure):
    _fields_ = [
        ("Token", MYARK_SAFETY_TOKEN),
        ("Pid", ctypes.c_uint32),
        ("FlagsMask", ctypes.c_uint32),
        ("FlagsValue", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
    ]


class MYARK_PROCESS_SET_SPECIAL_FLAGS_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Pid", ctypes.c_uint32),
        ("Status", ctypes.c_uint32),
        ("PreviousFlags", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
    ]


class MYARK_PROCESS_DKOM_INPUT(ctypes.Structure):
    _fields_ = [
        ("Token", MYARK_SAFETY_TOKEN),
        ("Pid", ctypes.c_uint32),
        ("Action", ctypes.c_uint32),
        ("Flags", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
    ]


class MYARK_PROCESS_DKOM_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Pid", ctypes.c_uint32),
        ("Status", ctypes.c_uint32),
        ("Hidden", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
    ]


class MYARK_PROCESS_INJECT_INPUT(ctypes.Structure):
    _fields_ = [
        ("Token", MYARK_SAFETY_TOKEN),
        ("Pid", ctypes.c_uint32),
        ("Method", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
        ("DllPath", ctypes.c_wchar * MYARK_PROCESS_PATH_MAX),
    ]


class MYARK_PROCESS_INJECT_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Pid", ctypes.c_uint32),
        ("Status", ctypes.c_uint32),
        ("UsedR0Fallback", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
    ]


# -----------------------------------------------------------------------------
# Buffer-size helpers (mirrors the FIELD_OFFSET math in the driver side).
# -----------------------------------------------------------------------------

HEADER_SIZE_ENUM = ctypes.sizeof(MYARK_PROCESS_ENUM_OUTPUT) - ctypes.sizeof(MYARK_PROCESS_ENTRY)
HEADER_SIZE_ENUM_THREAD = (
    ctypes.sizeof(MYARK_PROCESS_ENUM_THREAD_OUTPUT) - ctypes.sizeof(MYARK_THREAD_ENTRY)
)
HEADER_SIZE_CROSSVIEW = (
    ctypes.sizeof(MYARK_PROCESS_CROSSVIEW_OUTPUT) - ctypes.sizeof(MYARK_PROCESS_ENTRY)
)


def enum_buffer_size(count: int) -> int:
    return HEADER_SIZE_ENUM + count * ctypes.sizeof(MYARK_PROCESS_ENTRY)


def enum_thread_buffer_size(count: int) -> int:
    return HEADER_SIZE_ENUM_THREAD + count * ctypes.sizeof(MYARK_THREAD_ENTRY)


def crossview_buffer_size(count: int) -> int:
    return HEADER_SIZE_CROSSVIEW + count * ctypes.sizeof(MYARK_PROCESS_ENTRY)


__all__ = [
    "IOCTL_MYARK_PROCESS_ENUM",
    "IOCTL_MYARK_PROCESS_ENUM_THREAD",
    "IOCTL_MYARK_PROCESS_DETAIL",
    "IOCTL_MYARK_PROCESS_DETAIL_RUNTIME",
    "IOCTL_MYARK_PROCESS_CROSSVIEW",
    "IOCTL_MYARK_PROCESS_TERMINATE",
    "IOCTL_MYARK_PROCESS_SUSPEND",
    "IOCTL_MYARK_PROCESS_SET_PPL_LEVEL",
    "IOCTL_MYARK_PROCESS_SET_INTEGRITY",
    "IOCTL_MYARK_PROCESS_SET_VISIBILITY",
    "IOCTL_MYARK_PROCESS_SET_SPECIAL_FLAGS",
    "IOCTL_MYARK_PROCESS_DKOM",
    "IOCTL_MYARK_PROCESS_INJECT",
    "MYARK_PROCESS_MODULE_ID",
    "MYARK_PROCESS_NAME_MAX",
    "MYARK_PROCESS_PATH_MAX",
    "MYARK_PROCESS_USER_MAX",
    "MYARK_PROCESS_IMAGE_FILE_NAME_MAX",
    "PROCESS_SRC_NONE",
    "PROCESS_SRC_PUBLIC",
    "PROCESS_SRC_PSPCIDTABLE",
    "PROCESS_SRC_ACTIVE_LINKS",
    "PROCESS_HIDDEN_NONE",
    "PROCESS_HIDDEN_VIA_DKOM",
    "MYARK_PROCESS_ENTRY",
    "MYARK_PROCESS_ENUM_INPUT",
    "MYARK_PROCESS_ENUM_OUTPUT",
    "MYARK_THREAD_ENTRY",
    "MYARK_PROCESS_ENUM_THREAD_INPUT",
    "MYARK_PROCESS_ENUM_THREAD_OUTPUT",
    "MYARK_PROCESS_DETAIL",
    "MYARK_PROCESS_DETAIL_RUNTIME",
    "MYARK_PROCESS_CROSSVIEW_INPUT",
    "MYARK_PROCESS_CROSSVIEW_OUTPUT",
    "MYARK_PROCESS_TERMINATE_INPUT",
    "MYARK_PROCESS_TERMINATE_OUTPUT",
    "MYARK_PROCESS_SUSPEND_INPUT",
    "MYARK_PROCESS_SUSPEND_OUTPUT",
    "MYARK_PROCESS_SET_PPL_INPUT",
    "MYARK_PROCESS_SET_PPL_OUTPUT",
    "MYARK_PROCESS_SET_INTEGRITY_INPUT",
    "MYARK_PROCESS_SET_INTEGRITY_OUTPUT",
    "MYARK_PROCESS_SET_VISIBILITY_INPUT",
    "MYARK_PROCESS_SET_VISIBILITY_OUTPUT",
    "MYARK_PROCESS_SET_SPECIAL_FLAGS_INPUT",
    "MYARK_PROCESS_SET_SPECIAL_FLAGS_OUTPUT",
    "MYARK_PROCESS_DKOM_INPUT",
    "MYARK_PROCESS_DKOM_OUTPUT",
    "MYARK_PROCESS_INJECT_INPUT",
    "MYARK_PROCESS_INJECT_OUTPUT",
    "HEADER_SIZE_ENUM",
    "HEADER_SIZE_ENUM_THREAD",
    "HEADER_SIZE_CROSSVIEW",
    "enum_buffer_size",
    "enum_thread_buffer_size",
    "crossview_buffer_size",
]
