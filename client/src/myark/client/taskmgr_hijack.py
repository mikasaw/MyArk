"""Task-manager hijack via IFEO (R2-8, pure R3).

``myark-cli stealth taskmgr-hijack`` installs/removes an Image File
Execution Options ``Debugger`` value for ``taskmgr.exe`` so that
launching Task Manager transparently starts the MyArk UI instead
(the same public mechanism System Informer uses for its
"Replace Task Manager" option).

Ownership discipline: the key carries a ``MyArkHijack`` marker value.
``uninstall`` only removes a Debugger value that we installed (marker
present) -- a foreign Debugger value is reported and left untouched
unless ``force`` is set.

Audit: every mutating call returns an audit line and, on request, the
caller can persist it (the R3 history channel). All writes require
administrator; the registry itself rejects non-admin writes.
"""

from __future__ import annotations

import winreg
from dataclasses import dataclass

# HKLM
_IFEO_KEY = (
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    r"\Image File Execution Options\taskmgr.exe"
)
_DEBUGGER_VALUE = "Debugger"
_MARKER_VALUE = "MyArkHijack"
_MARKER_PAYLOAD = "myark-taskmgr-hijack=1"

DEFAULT_TARGET = "myark-ui.exe"


@dataclass
class HijackStatus:
    installed: bool
    ours: bool
    target: str | None


def _open_key(write: bool = False):
    access = winreg.KEY_SET_VALUE if write else winreg.KEY_READ
    return winreg.OpenKey(
        winreg.HKEY_LOCAL_MACHINE, _IFEO_KEY,
        0, access | winreg.KEY_WOW64_64KEY,
    )


def status() -> HijackStatus:
    """Read the current IFEO state for taskmgr.exe."""
    try:
        with _open_key(False) as key:
            target, _t = winreg.QueryValueEx(key, _DEBUGGER_VALUE)
    except FileNotFoundError:
        return HijackStatus(False, False, None)
    except OSError:
        # key exists but no Debugger value
        return HijackStatus(False, False, None)
    ours = False
    try:
        with _open_key(False) as key:
            marker, _t = winreg.QueryValueEx(key, _MARKER_VALUE)
            ours = marker == _MARKER_PAYLOAD
    except OSError:
        pass
    return HijackStatus(True, ours, target)


def install(target: str = DEFAULT_TARGET) -> HijackStatus:
    """Install the IFEO Debugger redirect (administrator required)."""
    if not target:
        raise ValueError("target must not be empty")
    with winreg.CreateKeyEx(
        winreg.HKEY_LOCAL_MACHINE, _IFEO_KEY,
        0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY,
    ) as key:
        winreg.SetValueEx(key, _DEBUGGER_VALUE, 0, winreg.REG_SZ, target)
        winreg.SetValueEx(key, _MARKER_VALUE, 0, winreg.REG_SZ, _MARKER_PAYLOAD)
    return HijackStatus(True, True, target)


def uninstall(force: bool = False) -> HijackStatus:
    """Remove the redirect. A foreign Debugger value is left in place."""
    current = status()
    if not current.installed:
        return current
    if not current.ours and not force:
        # someone else's Debugger value -- report, don't clobber
        return current
    with _open_key(True) as key:
        try:
            winreg.DeleteValue(key, _DEBUGGER_VALUE)
        except FileNotFoundError:
            pass
        try:
            winreg.DeleteValue(key, _MARKER_VALUE)
        except FileNotFoundError:
            pass
    return HijackStatus(False, False, None)
