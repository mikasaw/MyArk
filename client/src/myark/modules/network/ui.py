"""MyArk Network module: Tkinter UI for the TCP/UDP endpoint browser.

One tab in the central TabNotebook. Layout:

* toolbar    -- protocol chooser (TCP / UDP) + Refresh button + PID filter
                + Active only checkbox.
* tree       -- five columns for TCP (state, local, remote, pid) and
                four columns for UDP (local, pid). The Active only view
                reuses the TCP column layout for both protocols: UDP rows
                carry a ``UDP`` state marker and a blank remote column.
* status bar -- row count + last refresh time; the Active only view
                reports ``active: N TCP + M UDP``, matching the tail line
                of ``myark-cli network active``.

The tab is read-only: this is a listing tool, not a control surface.
The IP Helper API is a snapshot, so the tree does not auto-refresh -- a
network that churns through dozens of short-lived connections would
otherwise drown the user in scroll churn. Click *Refresh* to re-snapshot.

The *Active only* checkbox mirrors ``myark-cli network active``: the
data source switches to ``cli.get_active_rows()`` (every TCP endpoint
not LISTENING, merged with all UDP rows), and the protocol chooser
greys out while the view is in force -- the view is protocol-agnostic.
Checking the box refreshes immediately, exactly like the protocol
switch does, so the new source is on screen without an extra click.

The driver-side ``client`` handle is unused -- this is a pure-R3 module.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Any, Optional

from myark.client.ark_client import ArkClient
from myark.client.module_query import CapabilityInfo
from myark.modules.network import cli as net_cli
from myark.modules.network.protocol import COLUMN_WIDTHS
from myark.ui.scaling import scaled_width


# Tree columns for each protocol view. Kept in module scope so the
# test suite (and any future exporter) can introspect them.
TCP_COLUMNS: tuple[str, ...] = ("state", "local", "remote", "pid")
UDP_COLUMNS: tuple[str, ...] = ("local", "pid")

# ``PID_ALL`` is the toolbar sentinel that means "do not filter by PID".
PID_ALL: str = "(any PID)"


def register(
    _client: Optional[ArkClient],
    _capabilities: list[CapabilityInfo],
) -> Any:
    """Re-expose the package-level ``register`` from ``plugin``.

    Mirrors the pattern in :mod:`myark.modules.registry.ui` -- some UI
    callers prefer to wire the entry-point factory directly rather than
    going through ``myark.plugin_loader``.
    """
    from myark.modules.network.plugin import register as _register
    return _register(_client, _capabilities)


def _build_ui(parent: Any, _client: Optional[ArkClient]) -> ttk.Frame:
    """Build the network module tab."""
    proto_var = tk.StringVar(value="TCP")
    pid_var = tk.StringVar(value=PID_ALL)
    active_var = tk.BooleanVar(value=False)
    status_var = tk.StringVar(value="(click Refresh to load)")

    frame = ttk.Frame(parent, padding=8)

    ttk.Label(
        frame,
        text="Network module",
        font=("Segoe UI", 12, "bold"),
    ).grid(row=0, column=0, columnspan=4, sticky=tk.W, pady=(0, 4))
    ttk.Label(
        frame,
        text=(
            "Pure-R3 browser over IP Helper API (GetTcpTable2 / GetUdpTable). "
            "Snapshot only -- no auto-refresh. No driver required."
        ),
        wraplength=600,
        justify=tk.LEFT,
    ).grid(row=1, column=0, columnspan=4, sticky=tk.W, pady=(0, 8))

    # ---- toolbar
    toolbar = ttk.Frame(frame)
    toolbar.grid(row=2, column=0, columnspan=4, sticky=tk.W + tk.E, pady=(0, 8))

    ttk.Label(toolbar, text="Protocol:").grid(row=0, column=0, padx=(0, 4))
    proto_combo = ttk.Combobox(
        toolbar,
        textvariable=proto_var,
        values=("TCP", "UDP"),
        state="readonly",
        width=8,
    )
    proto_combo.grid(row=0, column=1, padx=(0, 8))
    # Switching protocol swaps the column set, so wire a callback.
    proto_combo.bind(
        "<<ComboboxSelected>>",
        lambda _evt: _refresh(
            tree,
            proto_var.get(),
            pid_var.get(),
            status_var,
            active_var.get(),
        ),
    )

    ttk.Label(toolbar, text="PID:").grid(row=0, column=2, padx=(0, 4))
    pid_entry = ttk.Entry(toolbar, textvariable=pid_var, width=12)
    pid_entry.grid(row=0, column=3, padx=(0, 8))

    ttk.Button(
        toolbar,
        text="Refresh",
        command=lambda: _refresh(
            tree,
            proto_var.get(),
            pid_var.get(),
            status_var,
            active_var.get(),
        ),
    ).grid(row=0, column=4, padx=(4, 0))

    def _on_active_toggle() -> None:
        # The Active only view is protocol-agnostic, so grey the chooser
        # out while it is in force and restore it when cleared.
        proto_combo.configure(state="disabled" if active_var.get() else "readonly")
        _refresh(tree, proto_var.get(), pid_var.get(), status_var, active_var.get())

    ttk.Checkbutton(
        toolbar,
        text="Active only",
        variable=active_var,
        command=_on_active_toggle,
    ).grid(row=0, column=5, padx=(8, 0))

    # ---- tree
    tree_frame = ttk.Frame(frame)
    tree_frame.grid(row=3, column=0, columnspan=4, sticky=tk.N + tk.S + tk.W + tk.E)

    # Start with the TCP columns; the refresh callback re-configures on
    # protocol switch.
    tree = ttk.Treeview(
        tree_frame,
        columns=TCP_COLUMNS,
        show="headings",
        selectmode="browse",
    )
    _configure_columns(tree, "TCP")

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
    status.grid(row=4, column=0, columnspan=4, sticky=tk.W + tk.E, pady=(8, 0))

    # Initial load so the tab is useful without an extra click.
    frame.after(
        50,
        lambda: _refresh(
            tree, proto_var.get(), pid_var.get(), status_var, active_var.get()
        ),
    )

    return frame


# ---------------------------------------------------------------------------
# UI actions.
# ---------------------------------------------------------------------------


def _configure_columns(tree: ttk.Treeview, protocol: str) -> None:
    """Reset the tree to the columns appropriate for ``protocol``.

    Tkinter does not allow a single ``ttk.Treeview`` to switch its
    column tuple on the fly, so we tear the existing tree down and
    replace its config. The tree is owned by the caller; we only
    retarget the columns here.
    """
    if protocol.upper() == "UDP":
        columns = UDP_COLUMNS
        # Rebuild column metadata.
        tree.configure(columns=columns)
        for col in tree["columns"]:
            tree.heading(col, text="")
            tree.column(col, width=0)
        for col, label, width_key in [
            ("local", "Local endpoint", "local"),
            ("pid",   "PID",            "pid"),
        ]:
            tree.heading(col, text=label)
            tree.column(col, width=scaled_width(tree, COLUMN_WIDTHS.get(width_key, 100)), anchor=tk.W)
        return

    # Default / TCP
    columns = TCP_COLUMNS
    tree.configure(columns=columns)
    for col in tree["columns"]:
        tree.heading(col, text="")
        tree.column(col, width=0)
    for col, label, width_key in [
        ("state",  "State",        "state"),
        ("local",  "Local",        "local"),
        ("remote", "Remote",       "remote"),
        ("pid",    "PID",          "pid"),
    ]:
        tree.heading(col, text=label)
        tree.column(col, width=scaled_width(tree, COLUMN_WIDTHS.get(width_key, 100)), anchor=tk.W)


def _parse_pid(text: str) -> Optional[int]:
    """Resolve the PID toolbar text to an int, or ``None`` for any-PID."""
    s = text.strip()
    if not s or s == PID_ALL:
        return None
    try:
        v = int(s)
    except ValueError:
        return None
    if v <= 0:
        return None
    return v


def _active_row_values(row: dict[str, Any]) -> tuple[str, str, str, int]:
    """Render one mixed protocol row into the fixed TCP column layout.

    :func:`net_cli.get_active_rows` returns TCP and UDP dicts in a
    single list. UDP rows carry no state / remote endpoint, so the
    state column shows the ``"UDP"`` marker and remote stays blank.
    """
    if row.get("protocol") == "UDP":
        return ("UDP", f"{row['local_addr']}:{row['local_port']}", "", row["pid"])
    return (
        row.get("state_name") or f"STATE_{row['state']}",
        f"{row['local_addr']}:{row['local_port']}",
        f"{row['remote_addr']}:{row['remote_port']}",
        row["pid"],
    )


def _refresh(
    tree: ttk.Treeview,
    protocol: str,
    pid_text: str,
    status_var: tk.StringVar,
    active_only: bool = False,
) -> None:
    """Reload the tree from the IP Helper API.

    With ``active_only`` the fetch goes through
    :func:`net_cli.get_active_rows` and the columns stay fixed to the
    TCP layout regardless of ``protocol``.
    """
    proto = protocol.upper()
    pid = _parse_pid(pid_text)

    _configure_columns(tree, "TCP" if active_only else proto)

    try:
        if active_only:
            rows = net_cli.get_active_rows()
        elif proto == "UDP":
            rows = net_cli.get_udp_rows()
        else:
            rows = net_cli.get_tcp_rows()
        if pid is not None:
            rows = [r for r in rows if int(r.get("pid", 0)) == pid]
    except OSError as exc:
        status_var.set(f"IP Helper call failed: {exc}")
        tree.delete(*tree.get_children())
        return
    except ValueError as exc:
        status_var.set(f"parse failed: {exc}")
        tree.delete(*tree.get_children())
        return

    tree.delete(*tree.get_children())

    if active_only:
        for row in rows:
            tree.insert("", "end", values=_active_row_values(row))
    elif proto == "UDP":
        for row in rows:
            tree.insert(
                "",
                "end",
                values=(
                    f"{row['local_addr']}:{row['local_port']}",
                    row["pid"],
                ),
            )
    else:
        for row in rows:
            tree.insert(
                "",
                "end",
                values=(
                    row.get("state_name") or f"STATE_{row['state']}",
                    f"{row['local_addr']}:{row['local_port']}",
                    f"{row['remote_addr']}:{row['remote_port']}",
                    row["pid"],
                ),
            )

    suffix = f", pid={pid}" if pid is not None else ""
    if active_only:
        # Same counts, same split as the CLI's
        # "({n} active TCP + {m} UDP endpoints)" tail line.
        n_tcp = sum(1 for r in rows if r.get("protocol") == "TCP")
        status_var.set(f"active: {n_tcp} TCP + {len(rows) - n_tcp} UDP{suffix}")
    else:
        status_var.set(f"{proto}: {len(rows)} endpoints{suffix}")


__all__ = ["register", "_build_ui", "TCP_COLUMNS", "UDP_COLUMNS", "PID_ALL"]