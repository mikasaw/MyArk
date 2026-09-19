"""
module R3 - protocol / dataclasses

The "module" subsystem enumerates loaded modules of a process via
``EnumProcessModules`` + ``GetModuleFileNameExW`` + ``GetModuleInformation``
(R3 fallback). The driver-side equivalent (a PEB walk that also sees
unlinked modules) is a future R0 IOCTL and is currently out of scope.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class ModuleRow:
    """One row of the loaded-module listing returned by ``EnumProcessModules``.

    Attributes
    ----------
    pid:
        Target process id.
    base_address:
        Load address of the module (LPVOID as integer).
    size:
        ``SizeOfImage`` of the module in bytes.
    entry_point:
        Module entry-point VA (or 0 if the loader did not fill it).
    name:
        Base file name (``kernel32.dll``).
    path:
        Full path as reported by ``GetModuleFileNameExW``.
    """

    pid: int = 0
    base_address: int = 0
    size: int = 0
    entry_point: int = 0
    name: str = ""
    path: str = ""


class ModuleError(Exception):
    """Base error for the module subsystem."""


class AccessDeniedError(ModuleError):
    """Win32 error 5 -- caller lacks ``PROCESS_QUERY_LIMITED_INFORMATION``
    over the target process. Admin rights usually help."""


# Constants live next to the dataclass so the module package does not
# depend on the memory package (the two subsystems share psapi but not
# their wrapper types).
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000


__all__ = [
    "ModuleRow",
    "ModuleError",
    "AccessDeniedError",
    "PROCESS_QUERY_INFORMATION",
    "PROCESS_QUERY_LIMITED_INFORMATION",
]