"""MyArk Registry module: Tkinter UI for the registry browser.

One tab in the central TabNotebook. Layout:

* toolbar    -- path entry + Browse button
* tree      -- two columns: value-name and value-data
* status bar -- most recent operation result

The tab is read-only by default: list / read are always available, but
write / delete operations are gated behind a Tk ``messagebox.askyesno``
confirmation because they mutate the live registry. The current user
might lack write permission to HKLM, in which case every mutation
surfaces a ``PermissionError`` and the status line shows the error.

The driver-side ``client`` handle is unused -- this is a pure-R3 module.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
from typing import Any, Optional

import winreg

from myark.client.ark_client import ArkClient
from myark.client.module_query import CapabilityInfo
from myark.modules.registry import cli as reg_cli
from myark.modules.registry import parser as reg_parser
from myark.ui.scaling import scaled_width


TREE_COLUMNS = ("name", "type", "data")


def register(
    _client: Optional[ArkClient],
    _capabilities: list[CapabilityInfo],
) -> Any:
    """Re-expose the package-level ``register`` from ``plugin``.

    Some UI callers prefer to wire the entry-point factory directly
    rather than going through ``myark.plugin_loader``. This alias keeps
    that pattern working without forcing the spec'd ``plugin.py`` to
    double as the UI factory.
    """
    from myark.modules.registry.plugin import register as _register
    return _register(_client, _capabilities)


def _build_ui(parent: Any, _client: Optional[ArkClient]) -> ttk.Frame:
    """Build the registry module tab."""
    status_var = tk.StringVar(value="(type a path and click Browse)")
    path_var = tk.StringVar(
        value=r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    )

    frame = ttk.Frame(parent, padding=8)

    ttk.Label(
        frame,
        text="Registry module",
        font=("Segoe UI", 12, "bold"),
    ).grid(row=0, column=0, columnspan=3, sticky=tk.W, pady=(0, 4))
    ttk.Label(
        frame,
        text=(
            "Pure-R3 browser over winreg. No driver required. Use short "
            "(HKLM, HKCU) or long (HKEY_LOCAL_MACHINE) hive prefixes."
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

    ttk.Button(toolbar, text="Browse", command=lambda: _refresh(tree, path_var, status_var)).grid(
        row=0, column=2, padx=(4, 0)
    )
    ttk.Button(toolbar, text="Read",  command=lambda: _read_selected(tree, path_var, status_var)).grid(
        row=0, column=3, padx=(4, 0)
    )
    ttk.Button(toolbar, text="Write value...", command=lambda: _write_dialog(path_var, status_var, tree)).grid(
        row=0, column=4, padx=(4, 0)
    )

    toolbar.columnconfigure(1, weight=1)

    # ---- tree
    tree_frame = ttk.Frame(frame)
    tree_frame.grid(row=3, column=0, columnspan=3, sticky=tk.N + tk.S + tk.W + tk.E)

    tree = ttk.Treeview(
        tree_frame,
        columns=TREE_COLUMNS,
        show="headings",
        selectmode="browse",
    )
    for col, label, width in [
        ("name", "Name", 220),
        ("type", "Type", 100),
        ("data", "Data", 320),
    ]:
        tree.heading(col, text=label)
        tree.column(col, width=scaled_width(tree, width), anchor=tk.W)

    vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=tree.yview)
    hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=tree.xview)
    tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
    tree.grid(row=0, column=0, sticky=tk.N + tk.S + tk.W + tk.E)
    vsb.grid(row=0, column=1, sticky=tk.N + tk.S)
    hsb.grid(row=1, column=0, sticky=tk.W + tk.E)

    frame.columnconfigure(0, weight=1)
    frame.rowconfigure(3, weight=1)
    tree_frame.columnconfigure(0, weight=1)
    tree_frame.rowconfigure(0, weight=1)

    # ---- status
    status = ttk.Label(frame, textvariable=status_var, anchor=tk.W)
    status.grid(row=4, column=0, columnspan=3, sticky=tk.W + tk.E, pady=(8, 0))

    # Initial load so the tab is useful without an extra click.
    frame.after(50, lambda: _refresh(tree, path_var, status_var))

    return frame


# ---------------------------------------------------------------------------
# UI actions.
# ---------------------------------------------------------------------------


def _refresh(tree: ttk.Treeview, path_var: tk.StringVar, status_var: tk.StringVar) -> None:
    """Reload the tree from the path in ``path_var``."""
    path = path_var.get().strip()
    if not path:
        status_var.set("path is empty")
        return

    try:
        hive, subkey = reg_parser.parse_path(path)
        key = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ)
    except (ValueError, FileNotFoundError, OSError) as exc:
        status_var.set(f"open failed: {exc}")
        return

    try:
        tree.delete(*tree.get_children())

        sub_count = 0
        i = 0
        while True:
            try:
                sub = winreg.EnumKey(key, i)
            except OSError:
                break
            tree.insert("", "end", values=(sub + "\\", "(key)", ""))
            i += 1
            sub_count += 1

        val_count = 0
        j = 0
        while True:
            try:
                name, raw, type_code = winreg.EnumValue(key, j)
            except OSError:
                break
            shown_name = name if name else "(Default)"
            shown_type = reg_parser.value_kind_name(type_code)
            shown_data = reg_cli._format_value(raw, type_code)
            tree.insert("", "end", values=(shown_name, shown_type, shown_data))
            j += 1
            val_count += 1
    finally:
        key.Close()

    status_var.set(f"{path}: {sub_count} subkeys, {val_count} values")


def _read_selected(
    tree: ttk.Treeview, path_var: tk.StringVar, status_var: tk.StringVar
) -> None:
    """Display the selected row's full data in the status line."""
    sel = tree.selection()
    if not sel:
        status_var.set("select a row first")
        return
    item = tree.item(sel[0])
    name, type_name, data = item["values"]
    if type_name == "(key)":
        # Drill into the subkey by rewriting the path.
        path_var.set(path_var.get().rstrip("\\") + "\\" + str(name).rstrip("\\"))
        _refresh(tree, path_var, status_var)
        return
    status_var.set(f"{name}  [{type_name}]  {data}")


def _write_dialog(
    path_var: tk.StringVar,
    status_var: tk.StringVar,
    tree: ttk.Treeview,
) -> None:
    """Prompt for name / type / value and write via ``winreg.SetValueEx``."""
    path = path_var.get().strip()
    if not path:
        status_var.set("path is empty")
        return

    name = simpledialog.askstring("Write value", "Value name:", parent=tree)
    if name is None:
        return

    type_name = simpledialog.askstring(
        "Write value",
        "Value type (REG_SZ, REG_DWORD, REG_MULTI_SZ, ...):",
        initialvalue="REG_SZ",
        parent=tree,
    )
    if not type_name:
        return

    value = simpledialog.askstring(
        "Write value",
        "Value payload:",
        parent=tree,
    )
    if value is None:
        return

    if not messagebox.askyesno(
        "Confirm write",
        f"Write to\n{path}\nname={name!r}\ntype={type_name}\nvalue={value!r}\n\nContinue?",
        parent=tree,
    ):
        return

    try:
        type_code = reg_parser.parse_type_name(type_name)
        payload = reg_parser.readable_to_value(value, type_code)
        hive, subkey = reg_parser.parse_path(path)
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ | winreg.KEY_WRITE) as key:
            winreg.SetValueEx(key, name, 0, type_code, payload)
    except (ValueError, FileNotFoundError, PermissionError, OSError) as exc:
        status_var.set(f"write failed: {exc}")
        return

    status_var.set(f"wrote {name!r} ({type_name}) under {path}")
    _refresh(tree, path_var, status_var)


__all__ = ["register", "_build_ui"]