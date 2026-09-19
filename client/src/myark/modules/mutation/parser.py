"""
mutation R3 - parser + R3 fallback.
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
from typing import Optional

from myark.client.ark_client import ArkClient, DriverError

from . import protocol as P


@dataclass
class TokenReport:
    process_id: int = 0
    token_flags: int = 0
    integrity_level: int = 0
    is_elevated: bool = False
    is_uac_restricted: bool = False
    token_address: int = 0
    source: str = ""


def _r3_fallback(process_id: int) -> TokenReport:
    return TokenReport(
        process_id=process_id,
        token_flags=0,
        integrity_level=0,
        is_elevated=False,
        is_uac_restricted=False,
        token_address=0,
        source="r3-fallback",
    )


def _send_inspect(client: Optional[ArkClient], process_id: int) -> Optional[TokenReport]:
    if client is None:
        return None
    in_size = ctypes.sizeof(P.MYARK_MUTATION_INSPECT_TOKEN_INPUT)
    in_buf = (ctypes.c_ubyte * in_size)()
    in_struct = ctypes.cast(in_buf, ctypes.POINTER(P.MYARK_MUTATION_INSPECT_TOKEN_INPUT)).contents
    in_struct.ProcessId = process_id

    out_size = ctypes.sizeof(P.MYARK_MUTATION_INSPECT_TOKEN_OUTPUT)
    out_buf = (ctypes.c_ubyte * out_size)()

    try:
        bytes_returned = client.ioctl(
            P.IOCTL_MYARK_MUTATION_INSPECT_TOKEN, in_buf, out_buf
        )
    except (DriverError, OSError):
        return None
    if bytes_returned < out_size:
        return None

    out = ctypes.cast(out_buf, ctypes.POINTER(P.MYARK_MUTATION_INSPECT_TOKEN_OUTPUT)).contents
    return TokenReport(
        process_id=process_id,
        token_flags=out.TokenFlags,
        integrity_level=out.IntegrityLevel,
        is_elevated=(out.IsElevated != 0),
        is_uac_restricted=(out.IsUacRestricted != 0),
        token_address=out.TokenAddress,
        source="r0",
    )


def inspect_token(client: Optional[ArkClient], process_id: int) -> TokenReport:
    r3 = _r3_fallback(process_id)
    r0 = _send_inspect(client, process_id)
    return r0 if r0 is not None else r3


def set_token(client: Optional[ArkClient], process_id: int, token_handle: int) -> bool:
    """Mutating IOCTL: reserved for S7.3-fix. Returns False for S7.3."""
    return False


__all__ = ["TokenReport", "inspect_token", "set_token"]
