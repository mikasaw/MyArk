"""MyArk File module: Tkinter UI for the file-attribute browser.

One tab in the central TabNotebook. Layout:

* toolbar    -- path entry + Browse button + operation picker.
* tree       -- attribute table (one row per FILE_ATTRIBUTE_* flag bit
  + file size + 3 FILETIME columns).
* SDDL panel -- read-only text widget showing the security descriptor
  (owner + DACL + integrity), updated when the user requests it.

The tab is read-only: this is an inspection tool, not a control
surface. Writes / DACL modifications live in the actions module (S8).

The driver-side ``client`` handle is unused -- this is a pure-R3 module.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Any, Optional

from myark.client.ark_client import ArkClient
from myark.client.module_query import CapabilityInfo
from myark.modules.file import cli as file_cli
from myark.modules.file import parser as file_parser
from myark.modules.file.protocol import COLUMN_WIDTHS
from myark.ui.scaling import scaled_width


# Tree columns for the attribute view. Kept in module scope so the
# test suite (and any future exporter) can introspect them.
ATTR_COLUMNS: tuple[str, ...] = ("name", "value")


# Default starting path: every Windows host ships with this file, and
# any non-admin can read its attributes + DACL.
DEFAULT_PATH: str = r"C:\Windows\notepad.exe"


def register(
    _client: Optional[ArkClient],
    _capabilities: list[CapabilityInfo],
) -> Any:
    """Re-expose the package-level ``register`` from ``plugin``.

    Mirrors the pattern in :mod:`myark.modules.registry.ui` -- some UI
    callers prefer to wire the entry-point factory directly rather than
    going through ``myark.plugin_loader``.
    """
    from myark.modules.file.plugin import register as _register
    return _register(_client, _capabilities)


def _build_ui(parent: Any, _client: Optional[ArkClient]) -> ttk.Frame:
    """Build the file module tab."""
    path_var = tk.StringVar(value=DEFAULT_PATH)
    status_var = tk.StringVar(value="(click Browse to load)")

    frame = ttk.Frame(parent, padding=8)

    ttk.Label(
        frame,
        text="File module",
        font=("Segoe UI", 12, "bold"),
    ).grid(row=0, column=0, columnspan=3, sticky=tk.W, pady=(0, 4))
    ttk.Label(
        frame,
        text=(
            "Pure-R3 browser over kernel32 / advapi32 / sddl. "
            "Reads file attributes, owner SID, DACL (SDDL), and "
            "integrity level. No driver required."
        ),
        wraplength=600,
        justify=tk.LEFT,
    ).grid(row=1, column=0, columnspan=3, sticky=tk.W, pady=(0, 8))

    # ---- toolbar
    toolbar = ttk.Frame(frame)
    toolbar.grid(row=2, column=0, columnspan=3, sticky=tk.W + tk.E, pady=(0, 8))

    ttk.Label(toolbar, text="Path:").grid(row=0, column=0, padx=(0, 4))
    path_entry = ttk.Entry(toolbar, textvariable=path_var, width=64)
    path_entry.grid(row=0, column=1, sticky=tk.W + tk.E)

    ttk.Button(
        toolbar,
        text="Browse",
        command=lambda: _refresh_all(path_var, attr_tree, sddl_text, status_var),
    ).grid(row=0, column=2, padx=(4, 0))

    toolbar.columnconfigure(1, weight=1)

    # ---- attribute tree (top half)
    tree_frame = ttk.LabelFrame(frame, text="File attributes")
    tree_frame.grid(row=3, column=0, columnspan=3, sticky=tk.N + tk.S + tk.W + tk.E, pady=(0, 8))

    attr_tree = ttk.Treeview(
        tree_frame,
        columns=ATTR_COLUMNS,
        show="headings",
        selectmode="browse",
    )
    for col, label, width_key in [
        ("name",  "Property",  "name"),
        ("value", "Value",     "size"),
    ]:
        attr_tree.heading(col, text=label)
        attr_tree.column(col, width=scaled_width(attr_tree, COLUMN_WIDTHS.get(width_key, 220)), anchor=tk.W)

    vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=attr_tree.yview)
    attr_tree.configure(yscrollcommand=vsb.set)
    attr_tree.grid(row=0, column=0, sticky=tk.N + tk.S + tk.W + tk.E)
    vsb.grid(row=0, column=1, sticky=tk.N + tk.S)
    tree_frame.columnconfigure(0, weight=1)
    tree_frame.rowconfigure(0, weight=1)

    # ---- SDDL panel (bottom half)
    sddl_frame = ttk.LabelFrame(frame, text="Security descriptor (SDDL)")
    sddl_frame.grid(row=4, column=0, columnspan=3, sticky=tk.N + tk.S + tk.W + tk.E)

    sddl_text = tk.Text(
        sddl_frame,
        height=8,
        wrap=tk.NONE,
        font=("Consolas", 10),
        background="#1e1e1e",
        foreground="#d4d4d4",
        insertbackground="#d4d4d4",
    )
    sddl_hsb = ttk.Scrollbar(sddl_frame, orient="horizontal", command=sddl_text.xview)
    sddl_vsb = ttk.Scrollbar(sddl_frame, orient="vertical", command=sddl_text.yview)
    sddl_text.configure(
        xscrollcommand=sddl_hsb.set,
        yscrollcommand=sddl_vsb.set,
    )
    sddl_text.grid(row=0, column=0, sticky=tk.N + tk.S + tk.W + tk.E)
    sddl_vsb.grid(row=0, column=1, sticky=tk.N + tk.S)
    sddl_hsb.grid(row=1, column=0, sticky=tk.W + tk.E)
    sddl_frame.columnconfigure(0, weight=1)
    sddl_frame.rowconfigure(0, weight=1)

    frame.columnconfigure(0, weight=1)
    frame.rowconfigure(3, weight=1)
    frame.rowconfigure(4, weight=1)

    # ---- status
    status = ttk.Label(frame, textvariable=status_var, anchor=tk.W)
    status.grid(row=5, column=0, columnspan=3, sticky=tk.W + tk.E, pady=(8, 0))

    # Initial load so the tab is useful without an extra click.
    frame.after(50, lambda: _refresh_all(path_var, attr_tree, sddl_text, status_var))

    return frame


# ---------------------------------------------------------------------------
# UI actions.
# ---------------------------------------------------------------------------


def _refresh_all(
    path_var: tk.StringVar,
    attr_tree: ttk.Treeview,
    sddl_text: tk.Text,
    status_var: tk.StringVar,
) -> None:
    """Reload the attribute tree + SDDL panel for the path in ``path_var``."""
    path = path_var.get().strip()
    if not path:
        status_var.set("path is empty")
        return

    # ---- attributes
    try:
        info = file_parser.get_file_info(path)
    except OSError as exc:
        status_var.set(f"file info failed: {exc}")
        attr_tree.delete(*attr_tree.get_children())
        sddl_text.delete("1.0", tk.END)
        sddl_text.insert("1.0", f"(file info failed: {exc})")
        return

    attr_tree.delete(*attr_tree.get_children())
    attr_tree.insert("", "end", values=("path",     info["path"]))
    attr_tree.insert("", "end", values=("size",     f"{info['size']} bytes"))
    attr_tree.insert("", "end", values=("created",  info["created"]))
    attr_tree.insert("", "end", values=("accessed", info["accessed"]))
    attr_tree.insert("", "end", values=("modified", info["modified"]))
    attr_tree.insert("", "end", values=("flags_raw", f"0x{info['flags']:08X}"))
    for flag_name in info["flags_list"]:
        attr_tree.insert("", "end", values=("flag", flag_name))

    # ---- security descriptor
    _refresh_sddl(path, sddl_text, status_var)

    kind = "directory" if info["is_directory"] else "file"
    status_var.set(f"{kind}: {path} ({len(info['flags_list'])} flag(s))")


def _refresh_sddl(path: str, sddl_text: tk.Text, status_var: tk.StringVar) -> None:
    """Refresh only the SDDL panel.

    Owner resolution is the slow path -- it involves a SID-to-name
    lookup that may talk to a domain controller on a corporate host --
    so we split it out from :func:`_refresh_all` and tolerate failure
    for owner / DACL / integrity independently. The panel still gets
    filled in with whatever sub-pieces succeeded.
    """
    sddl_text.delete("1.0", tk.END)

    parts: list[str] = []

    # ---- owner
    try:
        owner = file_parser.get_file_owner(path)
        if owner["account"] == "(no owner)" and not owner["sid"]:
            parts.append("[owner] (no owner)")
        else:
            full = (
                f"{owner['domain']}\\{owner['account']}"
                if owner["domain"]
                else owner["account"]
            )
            parts.append(f"[owner] {full}")
            parts.append(f"        sid={owner['sid']}  use={owner['use']}")
    except OSError as exc:
        parts.append(f"[owner] FAILED: {exc}")

    # ---- DACL
    try:
        dacl = file_parser.get_file_dacl(path)
        if dacl.get("sddl"):
            parts.append("[dacl]")
            parts.append(f"        {dacl.get('dacl') or '(none)'}")
        else:
            parts.append("[dacl] (empty)")
    except OSError as exc:
        parts.append(f"[dacl] FAILED: {exc}")

    # ---- integrity
    try:
        integrity = file_parser.get_file_integrity(path)
        if integrity["rid"] is None:
            parts.append("[integrity] (none)")
        else:
            parts.append(
                f"[integrity] {integrity['name']} "
                f"(rid=0x{integrity['rid']:X})"
            )
    except OSError as exc:
        parts.append(f"[integrity] FAILED: {exc}")

    sddl_text.insert("1.0", "\n".join(parts))


__all__ = ["register", "_build_ui", "ATTR_COLUMNS", "DEFAULT_PATH"]