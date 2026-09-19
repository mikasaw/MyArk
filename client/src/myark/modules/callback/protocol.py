"""
callback R3 - protocol data structures (ctypes mirrors of MyArkCallbackIoctl.h).

Mirrors ``shared/driver/MyArkCallbackIoctl.h`` -- every structure here has
the exact same field order, type and size as the kernel struct. The IOCTL
codes match the kernel-side ``CTL_CODE(FILE_DEVICE_UNKNOWN, 0x71X,
METHOD_BUFFERED, FILE_ANY_ACCESS)`` formula with FILE_DEVICE_UNKNOWN=0x22.

The callback module is R0-only (the kernel callback arrays are not
visible to R3) so there is no ``parser.py`` R3 fallback -- every query
delegates to the driver. If the driver is not installed the
``query_*`` helpers raise DriverError, which the CLI / UI catches and
renders as a friendly "driver not installed" message.
"""

from __future__ import annotations

import ctypes

from myark.protocol.core import _ctl_code


# ---------------------------------------------------------------------------
# IOCTL function codes (mirror MyArkCallbackIoctl.h).
# ---------------------------------------------------------------------------

IOCTL_MYARK_CALLBACK_QUERY_PS = _ctl_code(0x710)
IOCTL_MYARK_CALLBACK_QUERY_CM = _ctl_code(0x711)
IOCTL_MYARK_CALLBACK_QUERY_OB = _ctl_code(0x712)
IOCTL_MYARK_CALLBACK_QUERY_IMAGE = _ctl_code(0x713)
IOCTL_MYARK_CALLBACK_QUERY_DBG = _ctl_code(0x714)
IOCTL_MYARK_CALLBACK_ENUMERATE = _ctl_code(0x715)
IOCTL_MYARK_CALLBACK_REMOVE = _ctl_code(0x716)
IOCTL_MYARK_CALLBACK_RESTORE = _ctl_code(0x717)
IOCTL_MYARK_CALLBACK_BACKUP = _ctl_code(0x718)
IOCTL_MYARK_CALLBACK_STATS = _ctl_code(0x719)


# ---------------------------------------------------------------------------
# Shared category / flag / subtype bits.
# ---------------------------------------------------------------------------

CALLBACK_CATEGORY_PS = 0x01
CALLBACK_CATEGORY_CM = 0x02
CALLBACK_CATEGORY_OB = 0x04
CALLBACK_CATEGORY_IMAGE = 0x08
CALLBACK_CATEGORY_DBG = 0x10

CALLBACK_FLAG_NONE = 0x00000000
CALLBACK_FLAG_POPULATED = 0x00000001
CALLBACK_FLAG_SUSPECT = 0x00000002
CALLBACK_FLAG_HOOK = 0x00000004
CALLBACK_FLAG_UNSIGNED = 0x00000008
CALLBACK_FLAG_ALTITUDE = 0x00000010

CALLBACK_PS_SUBTYPE_PROCESS = 0x01
CALLBACK_PS_SUBTYPE_THREAD = 0x02
CALLBACK_PS_SUBTYPE_IMAGE = 0x03

CALLBACK_OB_OPERATION_PROCESS = 0x01
CALLBACK_OB_OPERATION_THREAD = 0x02

CALLBACK_DBG_SUBTYPE_DEBUG = 0x01
CALLBACK_DBG_SUBTYPE_BOUND = 0x02


# ---------------------------------------------------------------------------
# QUERY_PS: one row per populated PS callback slot.
# ---------------------------------------------------------------------------

class MYARK_CALLBACK_PS_ENTRY(ctypes.Structure):
    _fields_ = [
        ("Index", ctypes.c_uint32),
        ("SubType", ctypes.c_uint32),
        ("Flags", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("Callback", ctypes.c_uint64),
        ("DriverName", ctypes.c_ubyte * 32),
    ]


class MYARK_CALLBACK_QUERY_PS_INPUT(ctypes.Structure):
    _fields_ = [
        ("MaxEntries", ctypes.c_uint32),
        ("SubTypeMask", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
    ]


class MYARK_CALLBACK_QUERY_PS_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Size", ctypes.c_uint32),
        ("Count", ctypes.c_uint32),
        ("TotalSeen", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("PspCreateProcessNotifyRoutine", ctypes.c_uint64),
        ("PspCreateThreadNotifyRoutine", ctypes.c_uint64),
        ("PspLoadImageNotifyRoutine", ctypes.c_uint64),
        ("EntryStructSize", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
        ("Entries", MYARK_CALLBACK_PS_ENTRY * 1),
    ]


# ---------------------------------------------------------------------------
# QUERY_CM: one row per Cm callback registration.
# ---------------------------------------------------------------------------

class MYARK_CALLBACK_CM_ENTRY(ctypes.Structure):
    _fields_ = [
        ("Index", ctypes.c_uint32),
        ("Flags", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
        ("Callback", ctypes.c_uint64),
        ("Cookie", ctypes.c_uint64),
        ("DriverName", ctypes.c_ubyte * 32),
        ("Altitude", ctypes.c_ubyte * 64),
    ]


class MYARK_CALLBACK_QUERY_CM_INPUT(ctypes.Structure):
    _fields_ = [
        ("MaxEntries", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
        ("Reserved2", ctypes.c_uint32),
    ]


class MYARK_CALLBACK_QUERY_CM_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Size", ctypes.c_uint32),
        ("Count", ctypes.c_uint32),
        ("TotalSeen", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("CmpCallbackListHead", ctypes.c_uint64),
        ("EntryStructSize", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
        ("Entries", MYARK_CALLBACK_CM_ENTRY * 1),
    ]


# ---------------------------------------------------------------------------
# QUERY_OB: one row per Ob callback registration.
# ---------------------------------------------------------------------------

class MYARK_CALLBACK_OB_ENTRY(ctypes.Structure):
    _fields_ = [
        ("Index", ctypes.c_uint32),
        ("Operation", ctypes.c_uint32),
        ("Flags", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("Callback", ctypes.c_uint64),
        ("Altitude", ctypes.c_uint64),
        ("Cookie", ctypes.c_uint64),
        ("DriverName", ctypes.c_ubyte * 32),
        ("AltitudeString", ctypes.c_ubyte * 64),
    ]


class MYARK_CALLBACK_QUERY_OB_INPUT(ctypes.Structure):
    _fields_ = [
        ("MaxEntries", ctypes.c_uint32),
        ("OperationMask", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
    ]


class MYARK_CALLBACK_QUERY_OB_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Size", ctypes.c_uint32),
        ("Count", ctypes.c_uint32),
        ("TotalSeen", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("ObCallbackListHead", ctypes.c_uint64),
        ("EntryStructSize", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
        ("Entries", MYARK_CALLBACK_OB_ENTRY * 1),
    ]


# ---------------------------------------------------------------------------
# QUERY_IMAGE: one row per image-notify callback slot.
# ---------------------------------------------------------------------------

class MYARK_CALLBACK_IMAGE_ENTRY(ctypes.Structure):
    _fields_ = [
        ("Index", ctypes.c_uint32),
        ("Flags", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
        ("Callback", ctypes.c_uint64),
        ("DriverName", ctypes.c_ubyte * 32),
    ]


class MYARK_CALLBACK_QUERY_IMAGE_INPUT(ctypes.Structure):
    _fields_ = [
        ("MaxEntries", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
        ("Reserved2", ctypes.c_uint32),
    ]


class MYARK_CALLBACK_QUERY_IMAGE_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Size", ctypes.c_uint32),
        ("Count", ctypes.c_uint32),
        ("TotalSeen", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("PspLoadImageNotifyRoutine", ctypes.c_uint64),
        ("EntryStructSize", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
        ("Entries", MYARK_CALLBACK_IMAGE_ENTRY * 1),
    ]


# ---------------------------------------------------------------------------
# QUERY_DBG: one row per Dbg callback entry.
# ---------------------------------------------------------------------------

class MYARK_CALLBACK_DBG_ENTRY(ctypes.Structure):
    _fields_ = [
        ("Index", ctypes.c_uint32),
        ("SubType", ctypes.c_uint32),
        ("Flags", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("Object", ctypes.c_uint64),
        ("DriverName", ctypes.c_ubyte * 32),
    ]


class MYARK_CALLBACK_QUERY_DBG_INPUT(ctypes.Structure):
    _fields_ = [
        ("MaxEntries", ctypes.c_uint32),
        ("SubTypeMask", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
    ]


class MYARK_CALLBACK_QUERY_DBG_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Size", ctypes.c_uint32),
        ("Count", ctypes.c_uint32),
        ("TotalSeen", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("DbgkDebugObjectType", ctypes.c_uint64),
        ("EntryStructSize", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
        ("Entries", MYARK_CALLBACK_DBG_ENTRY * 1),
    ]


# ---------------------------------------------------------------------------
# ENUMERATE: flat list across all 5 callback arrays.
# ---------------------------------------------------------------------------

class MYARK_CALLBACK_ENUM_ENTRY(ctypes.Structure):
    _fields_ = [
        ("Category", ctypes.c_uint32),
        ("SubType", ctypes.c_uint32),
        ("Index", ctypes.c_uint32),
        ("Flags", ctypes.c_uint32),
        ("Callback", ctypes.c_uint64),
        ("Cookie", ctypes.c_uint64),
        ("DriverName", ctypes.c_ubyte * 32),
        ("Altitude", ctypes.c_ubyte * 64),
    ]


class MYARK_CALLBACK_ENUMERATE_INPUT(ctypes.Structure):
    _fields_ = [
        ("MaxEntries", ctypes.c_uint32),
        ("CategoryMask", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
    ]


class MYARK_CALLBACK_ENUMERATE_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Size", ctypes.c_uint32),
        ("Count", ctypes.c_uint32),
        ("TotalSeen", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("PsCount", ctypes.c_uint32),
        ("CmCount", ctypes.c_uint32),
        ("ObCount", ctypes.c_uint32),
        ("ImageCount", ctypes.c_uint32),
        ("DbgCount", ctypes.c_uint32),
        ("EntryStructSize", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
        ("Entries", MYARK_CALLBACK_ENUM_ENTRY * 1),
    ]


# ---------------------------------------------------------------------------
# REMOVE / RESTORE / BACKUP (S7.2-fix reserve).
# ---------------------------------------------------------------------------

class MYARK_CALLBACK_REMOVE_INPUT(ctypes.Structure):
    _fields_ = [
        ("Category", ctypes.c_uint32),
        ("Index", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
    ]


class MYARK_CALLBACK_REMOVE_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Size", ctypes.c_uint32),
        ("Status", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
    ]


class MYARK_CALLBACK_RESTORE_INPUT(ctypes.Structure):
    _fields_ = [
        ("Category", ctypes.c_uint32),
        ("Index", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
    ]


class MYARK_CALLBACK_RESTORE_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Size", ctypes.c_uint32),
        ("Status", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
    ]


class MYARK_CALLBACK_BACKUP_INPUT(ctypes.Structure):
    _fields_ = [
        ("MaxEntries", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
        ("Reserved2", ctypes.c_uint32),
    ]


class MYARK_CALLBACK_BACKUP_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Size", ctypes.c_uint32),
        ("Count", ctypes.c_uint32),
        ("TotalSeen", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("BackupBlob", ctypes.c_uint64),
        ("EntryStructSize", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
        ("Entries", MYARK_CALLBACK_ENUM_ENTRY * 1),
    ]


# ---------------------------------------------------------------------------
# STATS: fixed-size per-category totals.
# ---------------------------------------------------------------------------

class MYARK_CALLBACK_STATS_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Size", ctypes.c_uint32),
        ("PsCount", ctypes.c_uint32),
        ("CmCount", ctypes.c_uint32),
        ("ObCount", ctypes.c_uint32),
        ("ImageCount", ctypes.c_uint32),
        ("DbgCount", ctypes.c_uint32),
        ("TotalCount", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
    ]


# ---------------------------------------------------------------------------
# Header sizes used when allocating variable-length receive buffers.
# ---------------------------------------------------------------------------

HEADER_SIZE_PS = ctypes.sizeof(MYARK_CALLBACK_QUERY_PS_OUTPUT) - ctypes.sizeof(MYARK_CALLBACK_PS_ENTRY)
HEADER_SIZE_CM = ctypes.sizeof(MYARK_CALLBACK_QUERY_CM_OUTPUT) - ctypes.sizeof(MYARK_CALLBACK_CM_ENTRY)
HEADER_SIZE_OB = ctypes.sizeof(MYARK_CALLBACK_QUERY_OB_OUTPUT) - ctypes.sizeof(MYARK_CALLBACK_OB_ENTRY)
HEADER_SIZE_IMAGE = ctypes.sizeof(MYARK_CALLBACK_QUERY_IMAGE_OUTPUT) - ctypes.sizeof(MYARK_CALLBACK_IMAGE_ENTRY)
HEADER_SIZE_DBG = ctypes.sizeof(MYARK_CALLBACK_QUERY_DBG_OUTPUT) - ctypes.sizeof(MYARK_CALLBACK_DBG_ENTRY)
HEADER_SIZE_ENUM = ctypes.sizeof(MYARK_CALLBACK_ENUMERATE_OUTPUT) - ctypes.sizeof(MYARK_CALLBACK_ENUM_ENTRY)
HEADER_SIZE_BACKUP = ctypes.sizeof(MYARK_CALLBACK_BACKUP_OUTPUT) - ctypes.sizeof(MYARK_CALLBACK_ENUM_ENTRY)


__all__ = [
    # IOCTL codes
    "IOCTL_MYARK_CALLBACK_QUERY_PS",
    "IOCTL_MYARK_CALLBACK_QUERY_CM",
    "IOCTL_MYARK_CALLBACK_QUERY_OB",
    "IOCTL_MYARK_CALLBACK_QUERY_IMAGE",
    "IOCTL_MYARK_CALLBACK_QUERY_DBG",
    "IOCTL_MYARK_CALLBACK_ENUMERATE",
    "IOCTL_MYARK_CALLBACK_REMOVE",
    "IOCTL_MYARK_CALLBACK_RESTORE",
    "IOCTL_MYARK_CALLBACK_BACKUP",
    "IOCTL_MYARK_CALLBACK_STATS",
    # Category / flag / subtype bits
    "CALLBACK_CATEGORY_PS",
    "CALLBACK_CATEGORY_CM",
    "CALLBACK_CATEGORY_OB",
    "CALLBACK_CATEGORY_IMAGE",
    "CALLBACK_CATEGORY_DBG",
    "CALLBACK_FLAG_NONE",
    "CALLBACK_FLAG_POPULATED",
    "CALLBACK_FLAG_SUSPECT",
    "CALLBACK_FLAG_HOOK",
    "CALLBACK_FLAG_UNSIGNED",
    "CALLBACK_FLAG_ALTITUDE",
    "CALLBACK_PS_SUBTYPE_PROCESS",
    "CALLBACK_PS_SUBTYPE_THREAD",
    "CALLBACK_PS_SUBTYPE_IMAGE",
    "CALLBACK_OB_OPERATION_PROCESS",
    "CALLBACK_OB_OPERATION_THREAD",
    "CALLBACK_DBG_SUBTYPE_DEBUG",
    "CALLBACK_DBG_SUBTYPE_BOUND",
    # ctypes mirrors
    "MYARK_CALLBACK_PS_ENTRY",
    "MYARK_CALLBACK_QUERY_PS_INPUT",
    "MYARK_CALLBACK_QUERY_PS_OUTPUT",
    "MYARK_CALLBACK_CM_ENTRY",
    "MYARK_CALLBACK_QUERY_CM_INPUT",
    "MYARK_CALLBACK_QUERY_CM_OUTPUT",
    "MYARK_CALLBACK_OB_ENTRY",
    "MYARK_CALLBACK_QUERY_OB_INPUT",
    "MYARK_CALLBACK_QUERY_OB_OUTPUT",
    "MYARK_CALLBACK_IMAGE_ENTRY",
    "MYARK_CALLBACK_QUERY_IMAGE_INPUT",
    "MYARK_CALLBACK_QUERY_IMAGE_OUTPUT",
    "MYARK_CALLBACK_DBG_ENTRY",
    "MYARK_CALLBACK_QUERY_DBG_INPUT",
    "MYARK_CALLBACK_QUERY_DBG_OUTPUT",
    "MYARK_CALLBACK_ENUM_ENTRY",
    "MYARK_CALLBACK_ENUMERATE_INPUT",
    "MYARK_CALLBACK_ENUMERATE_OUTPUT",
    "MYARK_CALLBACK_REMOVE_INPUT",
    "MYARK_CALLBACK_REMOVE_OUTPUT",
    "MYARK_CALLBACK_RESTORE_INPUT",
    "MYARK_CALLBACK_RESTORE_OUTPUT",
    "MYARK_CALLBACK_BACKUP_INPUT",
    "MYARK_CALLBACK_BACKUP_OUTPUT",
    "MYARK_CALLBACK_STATS_OUTPUT",
    # Header sizes
    "HEADER_SIZE_PS",
    "HEADER_SIZE_CM",
    "HEADER_SIZE_OB",
    "HEADER_SIZE_IMAGE",
    "HEADER_SIZE_DBG",
    "HEADER_SIZE_ENUM",
    "HEADER_SIZE_BACKUP",
]