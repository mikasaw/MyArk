"""Safety-token dialog: confirms high-risk operations before they fire.

The MyArk UI exposes a handful of destructive operations -- ``process
terminate``, ``set-integrity``, ``inject``, future ``handle close``,
``DKOM unlink``, etc. Each of them should require the user to type a
short safety token (a random string the main window regenerates per
session) so a careless double-click does not silently take down a
critical process.

This module is the single source of truth for the dialog. Module UIs
call :func:`confirm` and get back a ``bool``; the actual token is held
in :class:`SafetyTokenAuthority`, which the main window owns.
"""

from __future__ import annotations

import secrets
import string
import tkinter as tk
from tkinter import messagebox, ttk
from typing import Optional


_DEFAULT_ALPHABET = string.ascii_uppercase + string.digits
_TOKEN_LEN = 6


class SafetyTokenAuthority:
    """Generates and validates per-session safety tokens.

    A new token is generated lazily on the first :meth:`token` call so
    the dialog never appears in tests / introspection paths. The token
    is invalidated as soon as it is consumed by :meth:`consume` -- a
    subsequent :meth:`consume` call requires a fresh ``rotate()`` round.
    """

    def __init__(self, *, length: int = _TOKEN_LEN, alphabet: str = _DEFAULT_ALPHABET):
        self._length = length
        self._alphabet = alphabet
        self._token: Optional[str] = None

    def token(self) -> str:
        if self._token is None:
            self._rotate()
        return self._token or ""

    def rotate(self) -> str:
        self._rotate()
        return self._token or ""

    def _rotate(self) -> None:
        self._token = "".join(secrets.choice(self._alphabet) for _ in range(self._length))

    def consume(self, candidate: str) -> bool:
        """Validate ``candidate`` and clear the token on success."""
        if not self._token:
            return False
        if secrets.compare_digest(candidate.strip().upper(), self._token):
            self._token = None
            return True
        return False

    def clear(self) -> None:
        self._token = None


class SafetyDialog(tk.Toplevel):
    """Modal ``Toplevel`` that asks the user to type the current token."""

    def __init__(
        self,
        master: tk.Misc,
        *,
        authority: SafetyTokenAuthority,
        action: str,
        target: str,
    ) -> None:
        super().__init__(master)
        self.title(f"Safety check -- {action}")
        self.transient(master)
        self.resizable(False, False)

        self._authority = authority
        self._result: bool = False

        outer = ttk.Frame(self, padding=12)
        outer.pack(fill=tk.BOTH, expand=True)

        ttk.Label(
            outer,
            text=f"Confirm: {action}",
            font=("Segoe UI", 12, "bold"),
        ).grid(row=0, column=0, columnspan=2, sticky=tk.W, pady=(0, 4))
        ttk.Label(
            outer,
            text=f"Target: {target}",
            foreground="#a00",
            wraplength=400,
            justify=tk.LEFT,
        ).grid(row=1, column=0, columnspan=2, sticky=tk.W, pady=(0, 8))
        ttk.Label(
            outer,
            text=(
                "This operation mutates a live Windows object. Type the "
                f"token below to confirm.\nToken: {authority.token()}"
            ),
            wraplength=400,
            justify=tk.LEFT,
        ).grid(row=2, column=0, columnspan=2, sticky=tk.W, pady=(0, 8))

        ttk.Label(outer, text="Token:").grid(row=3, column=0, sticky=tk.W)
        self._var = tk.StringVar()
        self._entry = ttk.Entry(outer, textvariable=self._var, width=20, font=("Consolas", 11))
        self._entry.grid(row=3, column=1, sticky=tk.W, pady=4)
        self._entry.focus_set()

        btns = ttk.Frame(outer)
        btns.grid(row=4, column=0, columnspan=2, sticky=tk.E, pady=(12, 0))
        ttk.Button(btns, text="Cancel", command=self._cancel).pack(side=tk.RIGHT, padx=2)
        ttk.Button(btns, text="Confirm", command=self._confirm).pack(side=tk.RIGHT, padx=2)

        self.bind("<Return>", lambda _e: self._confirm())
        self.bind("<Escape>", lambda _e: self._cancel())
        self._center(master)

    # ---------------------------------------------------------- helpers

    def _center(self, master: tk.Misc) -> None:
        try:
            self.update_idletasks()
            mx, my = master.winfo_rootx(), master.winfo_rooty()
            mw, mh = master.winfo_width(), master.winfo_height()
            w, h = self.winfo_width(), self.winfo_height()
            self.geometry(f"+{mx + (mw - w) // 2}+{my + max(40, (mh - h) // 3)}")
        except tk.TclError:
            pass

    def _confirm(self) -> None:
        candidate = self._var.get()
        if self._authority.consume(candidate):
            self._result = True
            self.destroy()
            return
        messagebox.showerror(
            "Safety check failed",
            "Token mismatch. The dialog will close and the operation is cancelled.",
            parent=self,
        )
        self._authority.rotate()
        self._result = False
        self.destroy()

    def _cancel(self) -> None:
        self._result = False
        self.destroy()

    @property
    def result(self) -> bool:
        return self._result


def confirm(
    master: tk.Misc,
    *,
    authority: SafetyTokenAuthority,
    action: str,
    target: str,
) -> bool:
    """Open the dialog modally and return whether the user confirmed."""
    dialog = SafetyDialog(master, authority=authority, action=action, target=target)
    master.wait_window(dialog)
    return dialog.result


__all__ = [
    "SafetyTokenAuthority",
    "SafetyDialog",
    "confirm",
]