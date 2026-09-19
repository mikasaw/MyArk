"""
dyndata R3 - protocol data structures (ctypes mirrors of MyArkDyndataIoctl.h).

Mirrors ``shared/driver/MyArkDyndataIoctl.h`` -- every structure here has
the exact same field order, type and size as the kernel struct. The IOCTL
codes match the kernel-side ``CTL_CODE(FILE_DEVICE_UNKNOWN, 0x70X,
METHOD_BUFFERED, FILE_ANY_ACCESS)`` formula with FILE_DEVICE_UNKNOWN=0x22.

The dyndata module is R0-only (pure kernel-side inspection) so there is no
``parser.py`` R3 fallback -- every query delegates to the driver. If the
driver is not installed the ``query_*`` helpers raise DriverError, which
the CLI / UI catches and renders as a friendly "driver not installed"
message.
"""

from __future__ import annotations

import ctypes

from myark.protocol.core import _ctl_code


# ---------------------------------------------------------------------------
# IOCTL function codes (mirror MyArkDyndataIoctl.h).
# ---------------------------------------------------------------------------

IOCTL_MYARK_DYNDATA_QUERY_PROCESS = _ctl_code(0x700)
IOCTL_MYARK_DYNDATA_QUERY_THREAD = _ctl_code(0x701)
IOCTL_MYARK_DYNDATA_QUERY_MODULE = _ctl_code(0x702)
IOCTL_MYARK_DYNDATA_QUERY_HANDLE = _ctl_code(0x703)
IOCTL_MYARK_DYNDATA_QUERY_FILE = _ctl_code(0x704)
IOCTL_MYARK_DYNDATA_QUERY_SYSCALL = _ctl_code(0x705)
IOCTL_MYARK_DYNDATA_QUERY_TOKEN = _ctl_code(0x706)
IOCTL_MYARK_DYNDATA_QUERY_OBJECT = _ctl_code(0x707)
IOCTL_MYARK_DYNDATA_QUERY_SSDT = _ctl_code(0x708)


# ---------------------------------------------------------------------------
# Shared flag / source bits.
# ---------------------------------------------------------------------------

# Process source mask
DYNDATA_PROCESS_SRC_NONE = 0x00
DYNDATA_PROCESS_SRC_ACTIVE_LINKS = 0x01
DYNDATA_PROCESS_SRC_PSPCIDTABLE = 0x02

# Generic row flags
DYNDATA_FLAG_NONE = 0x00000000
DYNDATA_FLAG_POPULATED = 0x00000001
DYNDATA_FLAG_SUSPECT = 0x00000002
DYNDATA_FLAG_HOOK = 0x00000004

# Token flag bits
DYNDATA_TOKEN_FLAG_NONE = 0x00000000
DYNDATA_TOKEN_FLAG_USER_PRESENT = 0x00000001
DYNDATA_TOKEN_FLAG_INTEGRITY = 0x00000002
DYNDATA_TOKEN_FLAG_ELEVATION = 0x00000004
DYNDATA_TOKEN_FLAG_VIRTUALIZATION = 0x00000008

# Syscall table identifiers
DYNDATA_SYSCALL_TABLE_NTOS = 0x00
DYNDATA_SYSCALL_TABLE_WIN32K = 0x01
DYNDATA_SYSCALL_TABLE_SHADOW = 0x02
DYNDATA_SYSCALL_TABLE_UNKNOWN = 0xFF


# ---------------------------------------------------------------------------
# QUERY_PROCESS: one row per EPROCESS.
# ---------------------------------------------------------------------------

class MYARK_DYNDATA_PROCESS_ENTRY(ctypes.Structure):
    _fields_ = [
        ("Pid", ctypes.c_uint32),
        ("Ppid", ctypes.c_uint32),
        ("SessionId", ctypes.c_uint32),
        ("Flags", ctypes.c_uint32),
        ("EProcess", ctypes.c_uint64),
        ("Peb", ctypes.c_uint64),
        ("ImageFileName", ctypes.c_ubyte * 16),
        ("SourceMask", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("CreateTime", ctypes.c_uint64),
    ]


class MYARK_DYNDATA_QUERY_PROCESS_INPUT(ctypes.Structure):
    _fields_ = [
        ("MaxEntries", ctypes.c_uint32),
        ("PidFilter", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
    ]


class MYARK_DYNDATA_QUERY_PROCESS_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Size", ctypes.c_uint32),
        ("Count", ctypes.c_uint32),
        ("TotalSeen", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("PsActiveProcessHead", ctypes.c_uint64),
        ("EntryStructSize", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
        ("Entries", MYARK_DYNDATA_PROCESS_ENTRY * 1),
    ]


# ---------------------------------------------------------------------------
# QUERY_THREAD: one row per ETHREAD.
# ---------------------------------------------------------------------------

class MYARK_DYNDATA_THREAD_ENTRY(ctypes.Structure):
    _fields_ = [
        ("Tid", ctypes.c_uint32),
        ("OwnerPid", ctypes.c_uint32),
        ("State", ctypes.c_uint32),
        ("BasePriority", ctypes.c_uint32),
        ("EThread", ctypes.c_uint64),
        ("StartAddress", ctypes.c_uint64),
        ("WaitReason", ctypes.c_uint32),
        ("Flags", ctypes.c_uint32),
        ("CreateTime", ctypes.c_uint64),
    ]


class MYARK_DYNDATA_QUERY_THREAD_INPUT(ctypes.Structure):
    _fields_ = [
        ("MaxEntries", ctypes.c_uint32),
        ("PidFilter", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
    ]


class MYARK_DYNDATA_QUERY_THREAD_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Size", ctypes.c_uint32),
        ("Count", ctypes.c_uint32),
        ("TotalSeen", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("PsActiveThreadHead", ctypes.c_uint64),
        ("EntryStructSize", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
        ("Entries", MYARK_DYNDATA_THREAD_ENTRY * 1),
    ]


# ---------------------------------------------------------------------------
# QUERY_MODULE: one row per kernel module.
# ---------------------------------------------------------------------------

class MYARK_DYNDATA_MODULE_ENTRY(ctypes.Structure):
    _fields_ = [
        ("ImageBase", ctypes.c_uint64),
        ("ImageSize", ctypes.c_uint64),
        ("Flags", ctypes.c_uint32),
        ("LoadOrderIndex", ctypes.c_uint32),
        ("Name", ctypes.c_ubyte * 64),
        ("FullPath", ctypes.c_ubyte * 260),
    ]


class MYARK_DYNDATA_QUERY_MODULE_INPUT(ctypes.Structure):
    _fields_ = [
        ("MaxEntries", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
        ("Reserved2", ctypes.c_uint32),
    ]


class MYARK_DYNDATA_QUERY_MODULE_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Size", ctypes.c_uint32),
        ("Count", ctypes.c_uint32),
        ("TotalSeen", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("PsLoadedModuleList", ctypes.c_uint64),
        ("EntryStructSize", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
        ("Entries", MYARK_DYNDATA_MODULE_ENTRY * 1),
    ]


# ---------------------------------------------------------------------------
# QUERY_HANDLE: one row per handle-table entry.
# ---------------------------------------------------------------------------

class MYARK_DYNDATA_HANDLE_ENTRY(ctypes.Structure):
    _fields_ = [
        ("Pid", ctypes.c_uint32),
        ("HandleValue", ctypes.c_uint32),
        ("TypeIndex", ctypes.c_uint32),
        ("GrantedAccess", ctypes.c_uint32),
        ("Object", ctypes.c_uint64),
        ("Flags", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
    ]


class MYARK_DYNDATA_QUERY_HANDLE_INPUT(ctypes.Structure):
    _fields_ = [
        ("MaxEntries", ctypes.c_uint32),
        ("PidFilter", ctypes.c_uint32),
        ("TypeIndexFilter", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
    ]


class MYARK_DYNDATA_QUERY_HANDLE_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Size", ctypes.c_uint32),
        ("Count", ctypes.c_uint32),
        ("TotalSeen", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("PspCidTable", ctypes.c_uint64),
        ("EntryStructSize", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
        ("Entries", MYARK_DYNDATA_HANDLE_ENTRY * 1),
    ]


# ---------------------------------------------------------------------------
# QUERY_FILE: one row per open file object.
# ---------------------------------------------------------------------------

class MYARK_DYNDATA_FILE_ENTRY(ctypes.Structure):
    _fields_ = [
        ("Pid", ctypes.c_uint32),
        ("HandleValue", ctypes.c_uint32),
        ("FileObject", ctypes.c_uint64),
        ("DeviceObject", ctypes.c_uint64),
        ("Flags", ctypes.c_uint32),
        ("ShareAccess", ctypes.c_uint32),
        ("Name", ctypes.c_ubyte * 260),
    ]


class MYARK_DYNDATA_QUERY_FILE_INPUT(ctypes.Structure):
    _fields_ = [
        ("MaxEntries", ctypes.c_uint32),
        ("PidFilter", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
    ]


class MYARK_DYNDATA_QUERY_FILE_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Size", ctypes.c_uint32),
        ("Count", ctypes.c_uint32),
        ("TotalSeen", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("ObTypeIndexList", ctypes.c_uint64),
        ("EntryStructSize", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
        ("Entries", MYARK_DYNDATA_FILE_ENTRY * 1),
    ]


# ---------------------------------------------------------------------------
# QUERY_SYSCALL: one row per syscall-table entry (NTOS + win32k).
# ---------------------------------------------------------------------------

class MYARK_DYNDATA_SYSCALL_ENTRY(ctypes.Structure):
    _fields_ = [
        ("ServiceIndex", ctypes.c_uint32),
        ("TableId", ctypes.c_uint32),
        ("ServiceAddress", ctypes.c_uint64),
        ("Flags", ctypes.c_uint32),
        ("DwellBytesSize", ctypes.c_uint32),
        ("DwellBytes", ctypes.c_ubyte * 8),
        ("Reserved0", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
    ]


class MYARK_DYNDATA_QUERY_SYSCALL_INPUT(ctypes.Structure):
    _fields_ = [
        ("MaxEntries", ctypes.c_uint32),
        ("TableMask", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
    ]


class MYARK_DYNDATA_QUERY_SYSCALL_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Size", ctypes.c_uint32),
        ("Count", ctypes.c_uint32),
        ("TotalSeen", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("KeServiceDescriptorTable", ctypes.c_uint64),
        ("W32pServiceTable", ctypes.c_uint64),
        ("NtoskrnlTextBase", ctypes.c_uint64),
        ("NtoskrnlTextEnd", ctypes.c_uint64),
        ("EntryStructSize", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
        ("Entries", MYARK_DYNDATA_SYSCALL_ENTRY * 1),
    ]


# ---------------------------------------------------------------------------
# QUERY_TOKEN: one row per PID's token snapshot.
# ---------------------------------------------------------------------------

class MYARK_DYNDATA_TOKEN_ENTRY(ctypes.Structure):
    _fields_ = [
        ("Pid", ctypes.c_uint32),
        ("Flags", ctypes.c_uint32),
        ("IntegrityLevel", ctypes.c_uint32),
        ("IntegrityFlags", ctypes.c_uint32),
        ("SessionId", ctypes.c_uint32),
        ("ElevationType", ctypes.c_uint32),
        ("IsElevated", ctypes.c_uint32),
        ("VirtualizationEnabled", ctypes.c_uint32),
        ("UserRid", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
        ("Token", ctypes.c_uint64),
        ("UserSidString", ctypes.c_ubyte * 256),
    ]


class MYARK_DYNDATA_QUERY_TOKEN_INPUT(ctypes.Structure):
    _fields_ = [
        ("Pid", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
        ("Reserved2", ctypes.c_uint32),
    ]


class MYARK_DYNDATA_QUERY_TOKEN_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Size", ctypes.c_uint32),
        ("Count", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
        ("EntryStructSize", ctypes.c_uint32),
        ("Reserved2", ctypes.c_uint32),
        ("Entries", MYARK_DYNDATA_TOKEN_ENTRY * 1),
    ]


# ---------------------------------------------------------------------------
# QUERY_OBJECT: one row per object-type entry.
# ---------------------------------------------------------------------------

class MYARK_DYNDATA_OBJECT_ENTRY(ctypes.Structure):
    _fields_ = [
        ("TypeIndex", ctypes.c_uint32),
        ("TotalNumberOfObjects", ctypes.c_uint32),
        ("TotalNumberOfHandles", ctypes.c_uint32),
        ("Flags", ctypes.c_uint32),
        ("TypeObject", ctypes.c_uint64),
        ("Name", ctypes.c_ubyte * 64),
    ]


class MYARK_DYNDATA_QUERY_OBJECT_INPUT(ctypes.Structure):
    _fields_ = [
        ("MaxEntries", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
        ("Reserved2", ctypes.c_uint32),
    ]


class MYARK_DYNDATA_QUERY_OBJECT_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Size", ctypes.c_uint32),
        ("Count", ctypes.c_uint32),
        ("TotalSeen", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("ObTypeObjectType", ctypes.c_uint64),
        ("EntryStructSize", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
        ("Entries", MYARK_DYNDATA_OBJECT_ENTRY * 1),
    ]


# ---------------------------------------------------------------------------
# QUERY_SSDT: one row per shadow SSDT entry.
# ---------------------------------------------------------------------------

class MYARK_DYNDATA_SSDT_ENTRY(ctypes.Structure):
    _fields_ = [
        ("ServiceIndex", ctypes.c_uint32),
        ("TableId", ctypes.c_uint32),
        ("ServiceAddress", ctypes.c_uint64),
        ("Flags", ctypes.c_uint32),
        ("DwellBytesSize", ctypes.c_uint32),
        ("DwellBytes", ctypes.c_ubyte * 8),
        ("Reserved0", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
    ]


class MYARK_DYNDATA_QUERY_SSDT_INPUT(ctypes.Structure):
    _fields_ = [
        ("MaxEntries", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
        ("Reserved2", ctypes.c_uint32),
    ]


class MYARK_DYNDATA_QUERY_SSDT_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("Size", ctypes.c_uint32),
        ("Count", ctypes.c_uint32),
        ("TotalSeen", ctypes.c_uint32),
        ("Reserved0", ctypes.c_uint32),
        ("KeServiceDescriptorTableShadow", ctypes.c_uint64),
        ("W32pServiceTable", ctypes.c_uint64),
        ("Win32kTextBase", ctypes.c_uint64),
        ("Win32kTextEnd", ctypes.c_uint64),
        ("EntryStructSize", ctypes.c_uint32),
        ("Reserved1", ctypes.c_uint32),
        ("Entries", MYARK_DYNDATA_SSDT_ENTRY * 1),
    ]


# ---------------------------------------------------------------------------
# Header sizes used when allocating variable-length receive buffers.
# ---------------------------------------------------------------------------

HEADER_SIZE_PROCESS = ctypes.sizeof(MYARK_DYNDATA_QUERY_PROCESS_OUTPUT) - ctypes.sizeof(MYARK_DYNDATA_PROCESS_ENTRY)
HEADER_SIZE_THREAD = ctypes.sizeof(MYARK_DYNDATA_QUERY_THREAD_OUTPUT) - ctypes.sizeof(MYARK_DYNDATA_THREAD_ENTRY)
HEADER_SIZE_MODULE = ctypes.sizeof(MYARK_DYNDATA_QUERY_MODULE_OUTPUT) - ctypes.sizeof(MYARK_DYNDATA_MODULE_ENTRY)
HEADER_SIZE_HANDLE = ctypes.sizeof(MYARK_DYNDATA_QUERY_HANDLE_OUTPUT) - ctypes.sizeof(MYARK_DYNDATA_HANDLE_ENTRY)
HEADER_SIZE_FILE = ctypes.sizeof(MYARK_DYNDATA_QUERY_FILE_OUTPUT) - ctypes.sizeof(MYARK_DYNDATA_FILE_ENTRY)
HEADER_SIZE_SYSCALL = ctypes.sizeof(MYARK_DYNDATA_QUERY_SYSCALL_OUTPUT) - ctypes.sizeof(MYARK_DYNDATA_SYSCALL_ENTRY)
HEADER_SIZE_TOKEN = ctypes.sizeof(MYARK_DYNDATA_QUERY_TOKEN_OUTPUT) - ctypes.sizeof(MYARK_DYNDATA_TOKEN_ENTRY)
HEADER_SIZE_OBJECT = ctypes.sizeof(MYARK_DYNDATA_QUERY_OBJECT_OUTPUT) - ctypes.sizeof(MYARK_DYNDATA_OBJECT_ENTRY)
HEADER_SIZE_SSDT = ctypes.sizeof(MYARK_DYNDATA_QUERY_SSDT_OUTPUT) - ctypes.sizeof(MYARK_DYNDATA_SSDT_ENTRY)


__all__ = [
    # IOCTL codes
    "IOCTL_MYARK_DYNDATA_QUERY_PROCESS",
    "IOCTL_MYARK_DYNDATA_QUERY_THREAD",
    "IOCTL_MYARK_DYNDATA_QUERY_MODULE",
    "IOCTL_MYARK_DYNDATA_QUERY_HANDLE",
    "IOCTL_MYARK_DYNDATA_QUERY_FILE",
    "IOCTL_MYARK_DYNDATA_QUERY_SYSCALL",
    "IOCTL_MYARK_DYNDATA_QUERY_TOKEN",
    "IOCTL_MYARK_DYNDATA_QUERY_OBJECT",
    "IOCTL_MYARK_DYNDATA_QUERY_SSDT",
    # Flag / source bits
    "DYNDATA_PROCESS_SRC_NONE",
    "DYNDATA_PROCESS_SRC_ACTIVE_LINKS",
    "DYNDATA_PROCESS_SRC_PSPCIDTABLE",
    "DYNDATA_FLAG_NONE",
    "DYNDATA_FLAG_POPULATED",
    "DYNDATA_FLAG_SUSPECT",
    "DYNDATA_FLAG_HOOK",
    "DYNDATA_TOKEN_FLAG_NONE",
    "DYNDATA_TOKEN_FLAG_USER_PRESENT",
    "DYNDATA_TOKEN_FLAG_INTEGRITY",
    "DYNDATA_TOKEN_FLAG_ELEVATION",
    "DYNDATA_TOKEN_FLAG_VIRTUALIZATION",
    "DYNDATA_SYSCALL_TABLE_NTOS",
    "DYNDATA_SYSCALL_TABLE_WIN32K",
    "DYNDATA_SYSCALL_TABLE_SHADOW",
    "DYNDATA_SYSCALL_TABLE_UNKNOWN",
    # ctypes mirrors
    "MYARK_DYNDATA_PROCESS_ENTRY",
    "MYARK_DYNDATA_QUERY_PROCESS_INPUT",
    "MYARK_DYNDATA_QUERY_PROCESS_OUTPUT",
    "MYARK_DYNDATA_THREAD_ENTRY",
    "MYARK_DYNDATA_QUERY_THREAD_INPUT",
    "MYARK_DYNDATA_QUERY_THREAD_OUTPUT",
    "MYARK_DYNDATA_MODULE_ENTRY",
    "MYARK_DYNDATA_QUERY_MODULE_INPUT",
    "MYARK_DYNDATA_QUERY_MODULE_OUTPUT",
    "MYARK_DYNDATA_HANDLE_ENTRY",
    "MYARK_DYNDATA_QUERY_HANDLE_INPUT",
    "MYARK_DYNDATA_QUERY_HANDLE_OUTPUT",
    "MYARK_DYNDATA_FILE_ENTRY",
    "MYARK_DYNDATA_QUERY_FILE_INPUT",
    "MYARK_DYNDATA_QUERY_FILE_OUTPUT",
    "MYARK_DYNDATA_SYSCALL_ENTRY",
    "MYARK_DYNDATA_QUERY_SYSCALL_INPUT",
    "MYARK_DYNDATA_QUERY_SYSCALL_OUTPUT",
    "MYARK_DYNDATA_TOKEN_ENTRY",
    "MYARK_DYNDATA_QUERY_TOKEN_INPUT",
    "MYARK_DYNDATA_QUERY_TOKEN_OUTPUT",
    "MYARK_DYNDATA_OBJECT_ENTRY",
    "MYARK_DYNDATA_QUERY_OBJECT_INPUT",
    "MYARK_DYNDATA_QUERY_OBJECT_OUTPUT",
    "MYARK_DYNDATA_SSDT_ENTRY",
    "MYARK_DYNDATA_QUERY_SSDT_INPUT",
    "MYARK_DYNDATA_QUERY_SSDT_OUTPUT",
    # Header sizes
    "HEADER_SIZE_PROCESS",
    "HEADER_SIZE_THREAD",
    "HEADER_SIZE_MODULE",
    "HEADER_SIZE_HANDLE",
    "HEADER_SIZE_FILE",
    "HEADER_SIZE_SYSCALL",
    "HEADER_SIZE_TOKEN",
    "HEADER_SIZE_OBJECT",
    "HEADER_SIZE_SSDT",
]
