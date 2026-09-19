"""High-level client wrapping the MyArkCore device handle.

``ArkClient`` owns the file handle and exposes typed methods for each core
IOCTL. Methods raise ``DriverNotInstalledError`` when the device can't be
opened (most common on a fresh machine) and ``DriverCallError`` for any other
Win32 / IOCTL failure.
"""

from __future__ import annotations

import ctypes
from typing import Iterable, Optional

from ..protocol.core import (
    HEADER_SIZE_MODULE_LIST,
    HEADER_SIZE_CAPABILITY,
    HEADER_SIZE_LOG,
    IOCTL_MYARK_CORE_GET_SESSION_KEY,
    IOCTL_MYARK_CORE_GET_VERSION,
    IOCTL_MYARK_CORE_GET_LOG,
    IOCTL_MYARK_CORE_QUERY_CAPABILITIES,
    IOCTL_MYARK_CORE_QUERY_MODULES,
    IOCTL_MYARK_CORE_SET_LOG_CONFIG,
    MYARK_CORE_CAPABILITY_ENTRY,
    MYARK_CORE_CAPABILITY_OUTPUT,
    MYARK_CORE_DEVICE_NAME,
    MYARK_CORE_LOG_CONFIG,
    MYARK_CORE_LOG_INPUT,
    MYARK_CORE_LOG_OUTPUT,
    MYARK_CORE_LOG_RECORD,
    MYARK_CORE_MODULE_INFO,
    MYARK_CORE_MODULE_LIST_OUTPUT,
    MYARK_CORE_SESSION_KEY_OUTPUT,
    MYARK_CORE_VERSION_OUTPUT,
)
from . import transport


class DriverError(OSError):
    """Base class for any MyArk driver call failure."""


class DriverNotInstalledError(DriverError):
    """Raised when ``CreateFileW`` cannot open the device."""


class DriverCallError(DriverError):
    """Raised when ``DeviceIoControl`` returns an error code."""


class ArkClient:
    """Single-handle client bound to the ``\\\\.\\MyArkCore`` device."""

    def __init__(self, handle: int, device_path: str = MYARK_CORE_DEVICE_NAME):
        self._handle = handle
        self.device_path = device_path

    # ------------------------------------------------------------------ open

    @classmethod
    def open(cls, device_path: str = MYARK_CORE_DEVICE_NAME) -> "ArkClient":
        try:
            handle = transport.create_file(device_path)
        except OSError as exc:
            if exc.errno == 2:  # ERROR_FILE_NOT_FOUND
                raise DriverNotInstalledError(
                    exc.errno, f"{device_path} not found (driver not installed?)"
                ) from exc
            if exc.errno == 5:  # ERROR_ACCESS_DENIED
                raise DriverError(
                    exc.errno,
                    f"{device_path} access denied -- run as Administrator",
                ) from exc
            raise DriverError(exc.errno, str(exc)) from exc
        return cls(handle, device_path)

    @classmethod
    def open_or_null(cls, device_path: str = MYARK_CORE_DEVICE_NAME) -> Optional["ArkClient"]:
        """Open the device; return ``None`` instead of raising when missing."""
        try:
            return cls.open(device_path)
        except DriverNotInstalledError:
            return None

    @property
    def handle(self) -> int:
        return self._handle

    def close(self) -> None:
        if self._handle:
            transport.close_handle(self._handle)
            self._handle = 0

    def __enter__(self) -> "ArkClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    # ----------------------------------------------------------- core IOCTLs

    def get_version(self) -> MYARK_CORE_VERSION_OUTPUT:
        out = MYARK_CORE_VERSION_OUTPUT()
        self.ioctl(IOCTL_MYARK_CORE_GET_VERSION, b"", out)
        return out

    def query_modules(self) -> list[MYARK_CORE_MODULE_INFO]:
        # Two-shot: first call asks for the header so we know the count.
        header = MYARK_CORE_MODULE_LIST_OUTPUT()
        try:
            self.ioctl(IOCTL_MYARK_CORE_QUERY_MODULES, b"", header)
        except DriverCallError as exc:
            if exc.errno != 0x7A:  # ERROR_INSUFFICIENT_BUFFER
                raise
            # Fall through: header may not be filled, but the driver tells us
            # the count via a fixed-size probe. Easiest: ask for a generous
            # initial buffer.
            pass

        # If the header came back populated use its Count, otherwise allocate
        # a buffer that fits at least 64 entries (more than any Stage S3 build).
        capacity = header.Count if header.Size >= HEADER_SIZE_MODULE_LIST else 64
        if capacity == 0:
            return []

        buf_size = HEADER_SIZE_MODULE_LIST + capacity * ctypes.sizeof(MYARK_CORE_MODULE_INFO)
        buf = (ctypes.c_ubyte * buf_size)()
        self.ioctl(IOCTL_MYARK_CORE_QUERY_MODULES, b"", buf)

        list_out = MYARK_CORE_MODULE_LIST_OUTPUT.from_buffer(buf)
        # Clamp to the allocated capacity: the driver may report a larger
        # Count than we reserved and from_buffer_copy must never read past
        # the end of buf.
        count = min(list_out.Count, capacity)
        entry_size = ctypes.sizeof(MYARK_CORE_MODULE_INFO)
        base = ctypes.addressof(list_out.Modules)
        return [
            MYARK_CORE_MODULE_INFO.from_buffer_copy(
                ctypes.string_at(base + i * entry_size, entry_size),
            )
            for i in range(count)
        ]

    def query_capabilities(self) -> list[MYARK_CORE_CAPABILITY_ENTRY]:
        header = MYARK_CORE_CAPABILITY_OUTPUT()
        try:
            self.ioctl(IOCTL_MYARK_CORE_QUERY_CAPABILITIES, b"", header)
        except DriverCallError as exc:
            if exc.errno != 0x7A:
                raise

        capacity = header.Count if header.Size >= HEADER_SIZE_CAPABILITY else 64
        if capacity == 0:
            return []

        buf_size = HEADER_SIZE_CAPABILITY + capacity * ctypes.sizeof(MYARK_CORE_CAPABILITY_ENTRY)
        buf = (ctypes.c_ubyte * buf_size)()
        self.ioctl(IOCTL_MYARK_CORE_QUERY_CAPABILITIES, b"", buf)

        cap_out = MYARK_CORE_CAPABILITY_OUTPUT.from_buffer(buf)
        count = min(cap_out.Count, capacity)
        entry_size = ctypes.sizeof(MYARK_CORE_CAPABILITY_ENTRY)
        base = ctypes.addressof(cap_out.Entries)
        return [
            MYARK_CORE_CAPABILITY_ENTRY.from_buffer_copy(
                ctypes.string_at(base + i * entry_size, entry_size),
            )
            for i in range(count)
        ]

    def get_log(self, cursor: int = 0, max_records: int = 64) -> list[MYARK_CORE_LOG_RECORD]:
        inp = MYARK_CORE_LOG_INPUT(Cursor=cursor, MaxRecords=max_records)
        buf_size = HEADER_SIZE_LOG + max_records * ctypes.sizeof(MYARK_CORE_LOG_RECORD)
        buf = (ctypes.c_ubyte * buf_size)()
        self.ioctl(IOCTL_MYARK_CORE_GET_LOG, bytes(inp), buf)
        log_out = MYARK_CORE_LOG_OUTPUT.from_buffer(buf)
        count = min(log_out.Count, max_records)
        entry_size = ctypes.sizeof(MYARK_CORE_LOG_RECORD)
        base = ctypes.addressof(log_out.Records)
        return [
            MYARK_CORE_LOG_RECORD.from_buffer_copy(
                ctypes.string_at(base + i * entry_size, entry_size),
            )
            for i in range(count)
        ]

    def set_log_config(self, enabled: bool, level: int) -> MYARK_CORE_LOG_CONFIG:
        cfg = MYARK_CORE_LOG_CONFIG(Enabled=1 if enabled else 0, Level=level, Reserved=0)
        out = MYARK_CORE_LOG_CONFIG()
        self.ioctl(IOCTL_MYARK_CORE_SET_LOG_CONFIG, bytes(cfg), out)
        return out

    def get_session_key(self) -> MYARK_CORE_SESSION_KEY_OUTPUT:
        """Fetch the per-boot safety-token session key (elevated only).

        Used by :mod:`myark.client.safety_token` to HMAC-sign
        ``MYARK_SAFETY_TOKEN`` digests for mutating IOCTLs. Raises
        ``DriverCallError`` (ERROR_ACCESS_DENIED) when the process is not
        elevated, since the device SDDL only admits SYSTEM/Administrators.
        """
        out = MYARK_CORE_SESSION_KEY_OUTPUT()
        self.ioctl(IOCTL_MYARK_CORE_GET_SESSION_KEY, b"", out)
        return out

    # ------------------------------------------------------------------ io

    def ioctl(self, ioctl: int, in_bytes, out_buf) -> int:
        """Send one raw IOCTL and fill ``out_buf`` with the reply.

        ``in_bytes`` may be ``None``, ``bytes``, ``bytearray``, a ctypes
        array or a ctypes struct (``None`` / an empty array mean "no
        input"). ``out_buf`` is any ctypes array or struct the driver's
        response is written into. Returns the number of bytes the driver
        actually wrote (a short read returns less than
        ``ctypes.sizeof(out_buf)``); raises ``DriverCallError`` on failure.

        This is the public escape hatch for module code that needs a
        non-core IOCTL without a typed wrapper.
        """
        payload = b"" if in_bytes is None else bytes(in_bytes)
        out_size = ctypes.sizeof(out_buf)
        try:
            _bytes, _n = transport.device_io_control(self._handle, ioctl, payload, out_size)
        except OSError as exc:
            raise DriverCallError(exc.errno, str(exc)) from exc
        # Copy into the caller's buffer so callers can keep using their own
        # ctypes object (avoid double-allocation when receiving large lists).
        # byref accepts both ctypes arrays and plain structs as destination.
        ctypes.memmove(ctypes.byref(out_buf), _bytes, min(out_size, len(_bytes)))
        return _n


def open_driver() -> ArkClient:
    return ArkClient.open()


def open_driver_or_null() -> Optional[ArkClient]:
    return ArkClient.open_or_null()


__all__ = [
    "DriverError",
    "DriverNotInstalledError",
    "DriverCallError",
    "ArkClient",
    "open_driver",
    "open_driver_or_null",
]