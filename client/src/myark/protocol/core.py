"""ctypes protocol definitions for the five core IOCTLs.

Mirrors ``driver/src/dispatch/MyArkCoreIoctl.h`` -- every structure here has the
exact same field order, type and size as the kernel struct. The IOCTL codes
match the kernel-side ``CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80X, METHOD_BUFFERED,
FILE_ANY_ACCESS)`` formula with FILE_DEVICE_UNKNOWN=0x22.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes

# -----------------------------------------------------------------------------
# Windows IOCTL constants (must match the driver-side CTL_CODE formula).
#
# CTL_CODE(DeviceType, Function, Method, Access) =
#   (DeviceType << 16) | (Access << 14) | (Function << 2) | Method
#
# Kernel uses FILE_DEVICE_UNKNOWN=0x22, METHOD_BUFFERED=0, FILE_ANY_ACCESS=0.
# So an IOCTL is just (0x22 << 16) | (Function << 2) = 0x00220000 | (F<<2).
# -----------------------------------------------------------------------------

FILE_DEVICE_UNKNOWN = 0x00000022
METHOD_BUFFERED = 0x00000000
FILE_ANY_ACCESS = 0x00000000


def _ctl_code(function: int) -> int:
    return (FILE_DEVICE_UNKNOWN << 16) | (FILE_ANY_ACCESS << 14) | (function << 2) | METHOD_BUFFERED


IOCTL_MYARK_CORE_GET_VERSION = _ctl_code(0x800)
IOCTL_MYARK_CORE_QUERY_MODULES = _ctl_code(0x801)
IOCTL_MYARK_CORE_QUERY_CAPABILITIES = _ctl_code(0x802)
IOCTL_MYARK_CORE_GET_LOG = _ctl_code(0x803)
IOCTL_MYARK_CORE_SET_LOG_CONFIG = _ctl_code(0x804)

# Display strings copied verbatim from MyArkCoreIoctl.h so log messages and
# UI labels can stay aligned with the driver build.
MYARK_CORE_DEVICE_NAME = r"\\.\MyArkCore"
MYARK_CORE_WIN32_NAME = MYARK_CORE_DEVICE_NAME  # same string in this driver
MYARK_CORE_PROTOCOL_VERSION = 1
MYARK_CORE_DISPLAY_NAME = "MyArk Core 0.1.0"

# Module states returned by IOCTL_MYARK_CORE_QUERY_MODULES.
MODULE_STATE_DISABLED = 0
MODULE_STATE_ENABLED = 1
MODULE_STATE_FAILED = 2

# Logging levels (kept in sync with Trace.h TRACE_LEVEL_*).
LOG_LEVEL_CRITICAL = 1
LOG_LEVEL_ERROR = 2
LOG_LEVEL_WARNING = 3
LOG_LEVEL_INFORMATION = 4
LOG_LEVEL_VERBOSE = 5


# -----------------------------------------------------------------------------
# IOCTL_MYARK_CORE_GET_VERSION output.
# -----------------------------------------------------------------------------
class MYARK_CORE_VERSION_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Size", ctypes.c_uint32),
        ("CoreProtocolVersion", ctypes.c_uint32),
        ("ModuleProtocolVersion", ctypes.c_uint32),
        ("BuildNumber", ctypes.c_uint32),
        ("ActiveModuleCount", ctypes.c_uint32),
        ("DisplayName", ctypes.c_wchar * 64),
    ]


# -----------------------------------------------------------------------------
# IOCTL_MYARK_CORE_QUERY_MODULES structures.
# -----------------------------------------------------------------------------
class MYARK_CORE_MODULE_INFO(ctypes.Structure):
    _fields_ = [
        ("ModuleId", ctypes.c_uint32),
        ("ModuleName", ctypes.c_char * 32),
        ("ModuleDescription", ctypes.c_char * 128),
        ("State", ctypes.c_uint32),
        ("IoctlCount", ctypes.c_uint32),
        ("LastError", ctypes.c_uint32),
    ]


class MYARK_CORE_MODULE_LIST_OUTPUT(ctypes.Structure):
    """Variable-length: ``Modules[1]`` is a placeholder for one entry.

    The caller computes the real buffer size as
    ``FIELD_OFFSET(MYARK_CORE_MODULE_LIST_OUTPUT, Modules[0]) + count * sizeof(MYARK_CORE_MODULE_INFO)``.
    """
    _fields_ = [
        ("Size", ctypes.c_uint32),
        ("Count", ctypes.c_uint32),
        ("Modules", MYARK_CORE_MODULE_INFO * 1),
    ]


# -----------------------------------------------------------------------------
# IOCTL_MYARK_CORE_QUERY_CAPABILITIES structures.
# -----------------------------------------------------------------------------
class MYARK_CORE_CAPABILITY_ENTRY(ctypes.Structure):
    _fields_ = [
        ("IoctlCode", ctypes.c_uint32),
        ("Name", ctypes.c_char * 64),
        ("ModuleId", ctypes.c_uint32),
    ]


class MYARK_CORE_CAPABILITY_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Size", ctypes.c_uint32),
        ("Count", ctypes.c_uint32),
        ("Entries", MYARK_CORE_CAPABILITY_ENTRY * 1),
    ]


# -----------------------------------------------------------------------------
# IOCTL_MYARK_CORE_GET_LOG structures.
# -----------------------------------------------------------------------------
class MYARK_CORE_LOG_RECORD(ctypes.Structure):
    _fields_ = [
        ("Sequence", ctypes.c_uint32),
        ("Level", ctypes.c_uint32),
        ("Timestamp", ctypes.c_int64),  # LARGE_INTEGER
        ("Module", ctypes.c_char * 16),
        ("Message", ctypes.c_char * 192),
    ]


class MYARK_CORE_LOG_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Size", ctypes.c_uint32),
        ("Count", ctypes.c_uint32),
        ("Records", MYARK_CORE_LOG_RECORD * 1),
    ]


class MYARK_CORE_LOG_INPUT(ctypes.Structure):
    _fields_ = [
        ("Cursor", ctypes.c_uint32),
        ("MaxRecords", ctypes.c_uint32),
    ]


# -----------------------------------------------------------------------------
# IOCTL_MYARK_CORE_SET_LOG_CONFIG input/output.
# -----------------------------------------------------------------------------
class MYARK_CORE_LOG_CONFIG(ctypes.Structure):
    _fields_ = [
        ("Enabled", ctypes.c_uint32),
        ("Level", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
    ]


# -----------------------------------------------------------------------------
# IOCTL_MYARK_CORE_GET_SESSION_KEY output + safety-token wire format.
#
# The session key is generated per boot inside the driver (SystemPrng) and
# is only reachable through this IOCTL -- the device SDDL restricts the
# device to SYSTEM/Administrators. MYARK_SAFETY_TOKEN mirrors
# shared/driver/MyArkSafetyToken.h: Signature = HMAC-SHA256(key,
# Magic|Pid|Operation|Timestamp), validated kernel-side with a +/-120 s
# freshness window. R3 signing helpers live in myark.client.safety_token.
# -----------------------------------------------------------------------------
IOCTL_MYARK_CORE_GET_SESSION_KEY = _ctl_code(0x805)


class MYARK_CORE_SESSION_KEY_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Size", ctypes.c_uint32),
        ("KeyLength", ctypes.c_uint32),
        ("Key", ctypes.c_ubyte * 32),
    ]


MYARK_SAFETY_TOKEN_MAGIC = 0x4D41524B          # 'MARK' ASCII (LE)
MYARK_SAFETY_TOKEN_SIGNATURE_SIZE = 32
MYARK_SAFETY_TOKEN_KEY_SIZE = 32


class MYARK_SAFETY_TOKEN(ctypes.Structure):
    _fields_ = [
        ("Magic", ctypes.c_uint32),
        ("Pid", ctypes.c_uint32),
        ("Operation", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
        ("Timestamp", ctypes.c_int64),          # LARGE_INTEGER (FILETIME)
        ("Signature", ctypes.c_ubyte * MYARK_SAFETY_TOKEN_SIGNATURE_SIZE),
        ("Reserved2", ctypes.c_ubyte * 16),
    ]


# Convenience: sizes used when allocating receive buffers.
HEADER_SIZE_MODULE_LIST = ctypes.sizeof(MYARK_CORE_MODULE_LIST_OUTPUT) - ctypes.sizeof(MYARK_CORE_MODULE_INFO)
HEADER_SIZE_CAPABILITY = ctypes.sizeof(MYARK_CORE_CAPABILITY_OUTPUT) - ctypes.sizeof(MYARK_CORE_CAPABILITY_ENTRY)
HEADER_SIZE_LOG = ctypes.sizeof(MYARK_CORE_LOG_OUTPUT) - ctypes.sizeof(MYARK_CORE_LOG_RECORD)


def module_list_buffer_size(count: int) -> int:
    return HEADER_SIZE_MODULE_LIST + count * ctypes.sizeof(MYARK_CORE_MODULE_INFO)


def capability_buffer_size(count: int) -> int:
    return HEADER_SIZE_CAPABILITY + count * ctypes.sizeof(MYARK_CORE_CAPABILITY_ENTRY)


def log_buffer_size(count: int) -> int:
    return HEADER_SIZE_LOG + count * ctypes.sizeof(MYARK_CORE_LOG_RECORD)


# Re-export commonly used wintypes so callers don't need to import ctypes too.
INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value
GENERIC_READ_WRITE = 0xC0000000  # GENERIC_READ | GENERIC_WRITE
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x80
FILE_SHARE_READ_WRITE = 0x3


__all__ = [
    "IOCTL_MYARK_CORE_GET_VERSION",
    "IOCTL_MYARK_CORE_QUERY_MODULES",
    "IOCTL_MYARK_CORE_QUERY_CAPABILITIES",
    "IOCTL_MYARK_CORE_GET_LOG",
    "IOCTL_MYARK_CORE_SET_LOG_CONFIG",
    "IOCTL_MYARK_CORE_GET_SESSION_KEY",
    "MYARK_CORE_VERSION_OUTPUT",
    "MYARK_CORE_MODULE_INFO",
    "MYARK_CORE_MODULE_LIST_OUTPUT",
    "MYARK_CORE_CAPABILITY_ENTRY",
    "MYARK_CORE_CAPABILITY_OUTPUT",
    "MYARK_CORE_LOG_RECORD",
    "MYARK_CORE_LOG_OUTPUT",
    "MYARK_CORE_LOG_INPUT",
    "MYARK_CORE_LOG_CONFIG",
    "MYARK_CORE_SESSION_KEY_OUTPUT",
    "MYARK_SAFETY_TOKEN",
    "MYARK_SAFETY_TOKEN_MAGIC",
    "MYARK_SAFETY_TOKEN_SIGNATURE_SIZE",
    "MYARK_SAFETY_TOKEN_KEY_SIZE",
    "MYARK_CORE_DEVICE_NAME",
    "MYARK_CORE_WIN32_NAME",
    "MYARK_CORE_PROTOCOL_VERSION",
    "MYARK_CORE_DISPLAY_NAME",
    "MODULE_STATE_DISABLED",
    "MODULE_STATE_ENABLED",
    "MODULE_STATE_FAILED",
    "LOG_LEVEL_CRITICAL",
    "LOG_LEVEL_ERROR",
    "LOG_LEVEL_WARNING",
    "LOG_LEVEL_INFORMATION",
    "LOG_LEVEL_VERBOSE",
    "INVALID_HANDLE_VALUE",
    "GENERIC_READ_WRITE",
    "OPEN_EXISTING",
    "FILE_ATTRIBUTE_NORMAL",
    "FILE_SHARE_READ_WRITE",
    "module_list_buffer_size",
    "capability_buffer_size",
    "log_buffer_size",
]