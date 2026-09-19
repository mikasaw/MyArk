"""Low-level Windows device I/O bindings used by ``ArkClient``.

The driver is a KMDF non-PnP control device exposed at ``\\\\.\\MyArkCore``.
We open it via ``CreateFileW`` and call it via ``DeviceIoControl`` -- both
sourced from ``kernel32.dll``. Errors are surfaced as ``OSError`` with the
Win32 error code in ``errno`` and ``winerror`` so callers can branch on
``ERROR_FILE_NOT_FOUND`` / ``ERROR_ACCESS_DENIED`` etc.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from typing import Optional

from ..protocol.core import (
    FILE_ATTRIBUTE_NORMAL,
    FILE_SHARE_READ_WRITE,
    GENERIC_READ_WRITE,
    INVALID_HANDLE_VALUE,
    OPEN_EXISTING,
)

# Load kernel32 once. Using WinDLL keeps the GIL released for the blocking
# call, which matters for the GUI thread.
_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

_CreateFileW = _kernel32.CreateFileW
_CreateFileW.restype = wintypes.HANDLE
_CreateFileW.argtypes = [
    wintypes.LPCWSTR,  # lpFileName
    wintypes.DWORD,    # dwDesiredAccess
    wintypes.DWORD,    # dwShareMode
    ctypes.c_void_p,   # lpSecurityAttributes
    wintypes.DWORD,    # dwCreationDisposition
    wintypes.DWORD,    # dwFlagsAndAttributes
    wintypes.HANDLE,   # hTemplateFile
]

_DeviceIoControl = _kernel32.DeviceIoControl
_DeviceIoControl.restype = wintypes.BOOL
_DeviceIoControl.argtypes = [
    wintypes.HANDLE,   # hDevice
    wintypes.DWORD,    # dwIoControlCode
    ctypes.c_void_p,   # lpInBuffer
    wintypes.DWORD,    # nInBufferSize
    ctypes.c_void_p,   # lpOutBuffer
    wintypes.DWORD,    # nOutBufferSize
    ctypes.POINTER(wintypes.DWORD),  # lpBytesReturned
    ctypes.c_void_p,   # lpOverlapped
]

_CloseHandle = _kernel32.CloseHandle
_CloseHandle.restype = wintypes.BOOL
_CloseHandle.argtypes = [wintypes.HANDLE]

_GetLastError = _kernel32.GetLastError
_GetLastError.restype = wintypes.DWORD
_GetLastError.argtypes = []


def create_file(device_path: str) -> int:
    """Open ``device_path`` for GENERIC_READ|GENERIC_WRITE.

    Returns the raw Win32 handle (an integer) on success, or raises ``OSError``
    with ``winerror`` set to the underlying error code (``ERROR_FILE_NOT_FOUND``
    when the driver isn't loaded, ``ERROR_ACCESS_DENIED`` when running without
    admin rights, etc.).
    """
    handle = _CreateFileW(
        device_path,
        GENERIC_READ_WRITE,
        FILE_SHARE_READ_WRITE,
        None,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        None,
    )
    if handle == INVALID_HANDLE_VALUE or handle == -1:
        err = ctypes.get_last_error() or _GetLastError()
        raise OSError(err, f"CreateFileW({device_path!r}) failed")
    return int(handle)


def close_handle(handle: int) -> None:
    if handle and handle != INVALID_HANDLE_VALUE:
        _CloseHandle(wintypes.HANDLE(handle))


def device_io_control(
    handle: int,
    ioctl_code: int,
    in_buffer: Optional[bytes],
    out_size: int,
) -> tuple[bytes, int]:
    """Call ``DeviceIoControl`` with a sized output buffer.

    Returns ``(out_bytes, bytes_returned)``. Raises ``OSError`` on failure with
    the Win32 error code attached so callers can distinguish
    ``ERROR_INSUFFICIENT_BUFFER`` from other failures.
    """
    if in_buffer is None:
        in_bytes = b""
    else:
        in_bytes = in_buffer

    out_buf = (ctypes.c_ubyte * out_size)()
    bytes_returned = wintypes.DWORD(0)

    ok = _DeviceIoControl(
        wintypes.HANDLE(handle),
        ioctl_code,
        ctypes.c_char_p(in_bytes) if in_bytes else None,
        len(in_bytes),
        ctypes.cast(out_buf, ctypes.c_void_p),
        out_size,
        ctypes.byref(bytes_returned),
        None,
    )
    if not ok:
        err = ctypes.get_last_error() or _GetLastError()
        raise OSError(err, f"DeviceIoControl(0x{ioctl_code:X}) failed")

    # Slice off the trailing garbage so callers always see only the bytes the
    # driver actually wrote.
    n = bytes_returned.value
    if n > out_size:
        n = out_size
    return bytes(out_buf[:n]), n


__all__ = ["create_file", "close_handle", "device_io_control"]