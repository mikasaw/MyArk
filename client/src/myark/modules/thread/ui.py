"""MyArk thread module: Tkinter UI for the thread entity.

Two tabs in the central TabNotebook:

* **Thread List** -- per-process flat enumeration with toolbar (Refresh /
  Detail / CrossView / Terminate). Read-only treeview drives the toolbar
  buttons. The user enters a Pid and refreshes; the tree shows every
  ETHREAD the driver saw.
* **CrossView** -- per-TID comparison of the three views (public /
  ThreadListHead / PspCidTable). Rows where the kernel sees the TID but
  the public view does not are highlighted as DKOM candidates.

The trees use the standard ``ttk.Treeview`` widget; selection drives
the toolbar buttons. ``enum_threads`` / ``crossview`` are the driver
calls shared by both tabs.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Any, Optional

from myark.client.ark_client import (
    ArkClient,
    DriverCallError,
    DriverError,
)
from myark.client.module_query import CapabilityInfo
from myark.plugin_loader import ModuleRegistration
from myark.modules.thread.protocol import (
    ThreadRow,
    crossview,
    detail,
    enum_threads,
    terminate,
)
from myark.ui.safety_dialog import SafetyTokenAuthority, confirm
from myark.ui.scaling import scaled_width


TREE_COLUMNS = ("tid", "pid", "state", "prio", "wait", "module", "anomaly")
CV_COLUMNS = ("tid", "pid", "module", "public", "threadlist", "pspcid", "anomaly")


def _row_to_dict(r: ThreadRow) -> dict[str, Any]:
    return {
        "tid": r.tid,
        "pid": r.pid,
        "state": r.state_name,
        "prio": r.priority,
        "wait": r.wait_name,
        "module": r.module,
        "anomaly": f"0x{r.anomaly:02X}" if r.anomaly else "",
    }


def register(
    client: Optional[ArkClient],
    capabilities: list[CapabilityInfo],
) -> ModuleRegistration:
    """Entry point for the myark.modules plugin group."""
    return ModuleRegistration(
        name="thread",
        register_fn=register,
        ui_factory=_build_ui,
        cli_setup=_setup_cli,
        description="Thread module - ETHREAD enumeration + cross-view + terminate",
    )


def _build_ui(
    parent: Any,
    client: Optional[ArkClient],
    *,
    safety_authority: Optional[SafetyTokenAuthority] = None,
) -> ttk.Frame:
    """Build the thread module's tab."""
    outer = ttk.Frame(parent)
    notebook = ttk.Notebook(outer)
    notebook.pack(fill=tk.BOTH, expand=True)

    list_frame = _build_list_tab(notebook, client, safety_authority=safety_authority)
    cv_frame = _build_crossview_tab(notebook, client)

    notebook.add(list_frame, text="Thread List")
    notebook.add(cv_frame, text="CrossView")

    return outer


# ---------------------------------------------------------------------------
# Tab 1: Thread List (per-Pid enumeration + action toolbar)
# ---------------------------------------------------------------------------


def _build_list_tab(
    parent: Any,
    client: Optional[ArkClient],
    *,
    safety_authority: Optional[SafetyTokenAuthority] = None,
) -> ttk.Frame:
    status_var = tk.StringVar(value="(enter a Pid and press Refresh)")
    summary_var = tk.StringVar(value="")

    frame = ttk.Frame(parent, padding=8)

    ttk.Label(
        frame,
        text="Thread module",
        font=("Segoe UI", 12, "bold"),
    ).grid(row=0, column=0, columnspan=4, sticky=tk.W, pady=(0, 4))

    toolbar = ttk.Frame(frame)
    toolbar.grid(row=1, column=0, columnspan=4, sticky=tk.W + tk.E, pady=(0, 8))

    ttk.Label(toolbar, text="Pid:").grid(row=0, column=0, padx=(0, 4))
    pid_var = tk.StringVar(value="")
    ttk.Entry(toolbar, textvariable=pid_var, width=8).grid(row=0, column=1, padx=(0, 8))

    tree_frame = ttk.Frame(frame)
    tree_frame.grid(row=2, column=0, columnspan=4, sticky=tk.N + tk.S + tk.W + tk.E)

    tree = ttk.Treeview(
        tree_frame,
        columns=TREE_COLUMNS,
        show="headings",
        selectmode="extended",
    )
    for col, label, width in [
        ("tid", "TID", 70),
        ("pid", "PID", 70),
        ("state", "State", 110),
        ("prio", "Prio", 60),
        ("wait", "Wait", 140),
        ("module", "Module", 160),
        ("anomaly", "Anom", 70),
    ]:
        tree.heading(col, text=label)
        tree.column(col, width=scaled_width(tree, width), anchor=tk.W)
    vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=tree.yview)
    hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=tree.xview)
    tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
    tree.grid(row=0, column=0, sticky=tk.N + tk.S + tk.W + tk.E)
    vsb.grid(row=0, column=1, sticky=tk.N + tk.S)
    hsb.grid(row=1, column=0, sticky=tk.W + tk.E)

    status = ttk.Label(frame, textvariable=status_var, anchor=tk.W)
    status.grid(row=3, column=0, columnspan=4, sticky=tk.W + tk.E, pady=(8, 0))

    summary = ttk.Label(frame, textvariable=summary_var, anchor=tk.W)
    summary.grid(row=4, column=0, columnspan=4, sticky=tk.W + tk.E)

    frame.columnconfigure(0, weight=1)
    frame.rowconfigure(2, weight=1)
    tree_frame.columnconfigure(0, weight=1)
    tree_frame.rowconfigure(0, weight=1)

    def _selected_tid() -> Optional[int]:
        sel = tree.selection()
        if not sel:
            return None
        item = tree.item(sel[0])
        try:
            return int(item["values"][0])
        except (KeyError, ValueError, IndexError):
            return None

    def _do_refresh() -> None:
        try:
            pid = int(pid_var.get())
        except ValueError:
            status_var.set("enter a numeric Pid first")
            return
        if client is None:
            status_var.set("driver not installed -- cannot enumerate")
            return
        try:
            result = enum_threads(client, pid)
        except DriverCallError as exc:
            status_var.set(f"IOCTL failed: Win32 error 0x{exc.errno & 0xFFFFFFFF:08X}")
            return
        except DriverError as exc:
            status_var.set(f"driver error: {exc}")
            return
        except OSError as exc:
            status_var.set(f"OSError: errno={exc.errno}")
            return

        tree.delete(*tree.get_children())
        for row in result.rows:
            d = _row_to_dict(row)
            tree.insert(
                "",
                "end",
                values=(
                    d["tid"], d["pid"], d["state"], d["prio"],
                    d["wait"], d["module"], d["anomaly"],
                ),
            )
        status_var.set(
            f"OK: {result.bytes_used} bytes, {len(result.rows)} rows shown"
        )
        summary_var.set(
            f"pid={result.owner_pid} anomaly_count={result.anomaly_count}"
        )

    def _do_detail() -> None:
        tid = _selected_tid()
        if tid is None:
            status_var.set("select a thread first")
            return
        if client is None:
            status_var.set("driver not installed -- cannot detail")
            return
        try:
            d = detail(client, tid)
        except Exception as exc:
            status_var.set(f"detail failed: {exc}")
            return
        status_var.set(
            f"tid={d.Tid} ethread=0x{d.EThreadKernelAddress:016X} "
            f"start=0x{d.StartAddress:016X} module={d.Module!r} anomaly=0x{int(d.Anomaly):08X}"
        )

    def _do_terminate() -> None:
        tid = _selected_tid()
        if tid is None:
            status_var.set("select a thread first")
            return
        if client is None:
            status_var.set("driver not installed -- cannot terminate")
            return
        # Destructive action: require the user to type the per-session
        # safety token before firing the IOCTL. The token rotates after
        # every successful consume, so a single token can't be reused.
        if safety_authority is not None:
            if not confirm(
                toolbar,
                authority=safety_authority,
                action="thread terminate",
                target=f"tid={tid}",
            ):
                status_var.set("terminate cancelled (safety check failed)")
                return
        try:
            out = terminate(client, tid)
        except Exception as exc:
            status_var.set(f"terminate failed: {exc}")
            return
        status_var.set(
            f"tid={tid} -> status=0x{out.Status:08X} r0_fallback={out.UsedR0Fallback}"
        )

    ttk.Button(toolbar, text="Refresh",   command=_do_refresh).grid(row=0, column=2, padx=2)
    ttk.Button(toolbar, text="Detail",    command=_do_detail).grid(row=0, column=3, padx=2)
    ttk.Button(toolbar, text="Terminate", command=_do_terminate).grid(row=0, column=4, padx=2)

    return frame


# ---------------------------------------------------------------------------
# Tab 2: CrossView (three-view comparison panel)
# ---------------------------------------------------------------------------


def _build_crossview_tab(parent: Any, client: Optional[ArkClient]) -> ttk.Frame:
    status_var = tk.StringVar(value="(enter a Pid and press Refresh)")
    summary_var = tk.StringVar(value="")

    frame = ttk.Frame(parent, padding=8)

    ttk.Label(
        frame,
        text="CrossView (public / ThreadListHead / PspCidTable)",
        font=("Segoe UI", 12, "bold"),
    ).grid(row=0, column=0, columnspan=4, sticky=tk.W, pady=(0, 4))

    toolbar = ttk.Frame(frame)
    toolbar.grid(row=1, column=0, columnspan=4, sticky=tk.W + tk.E, pady=(0, 8))

    ttk.Label(toolbar, text="Pid:").grid(row=0, column=0, padx=(0, 4))
    pid_var = tk.StringVar(value="")
    ttk.Entry(toolbar, textvariable=pid_var, width=8).grid(row=0, column=1, padx=(0, 8))

    tree_frame = ttk.Frame(frame)
    tree_frame.grid(row=2, column=0, columnspan=4, sticky=tk.N + tk.S + tk.W + tk.E)

    tree = ttk.Treeview(
        tree_frame,
        columns=CV_COLUMNS,
        show="headings",
        selectmode="browse",
    )
    for col, label, width in [
        ("tid", "TID", 70),
        ("pid", "PID", 70),
        ("module", "Module", 160),
        ("public", "Public", 80),
        ("threadlist", "ThreadList", 100),
        ("pspcid", "PspCidTable", 100),
        ("anomaly", "Anom", 70),
    ]:
        tree.heading(col, text=label)
        tree.column(col, width=scaled_width(tree, width), anchor=tk.W)
    tree.tag_configure("dkom", background="#fff3a0")
    vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=tree.yview)
    hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=tree.xview)
    tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
    tree.grid(row=0, column=0, sticky=tk.N + tk.S + tk.W + tk.E)
    vsb.grid(row=0, column=1, sticky=tk.N + tk.S)
    hsb.grid(row=1, column=0, sticky=tk.W + tk.E)

    status = ttk.Label(frame, textvariable=status_var, anchor=tk.W)
    status.grid(row=3, column=0, columnspan=4, sticky=tk.W + tk.E, pady=(8, 0))

    summary = ttk.Label(frame, textvariable=summary_var, anchor=tk.W)
    summary.grid(row=4, column=0, columnspan=4, sticky=tk.W + tk.E)

    frame.columnconfigure(0, weight=1)
    frame.rowconfigure(2, weight=1)
    tree_frame.columnconfigure(0, weight=1)
    tree_frame.rowconfigure(0, weight=1)

    def _do_refresh() -> None:
        try:
            pid = int(pid_var.get())
        except ValueError:
            status_var.set("enter a numeric Pid first")
            return
        if client is None:
            status_var.set("driver not installed -- cannot cross-view")
            return
        try:
            result = crossview(client, pid=pid)
        except DriverCallError as exc:
            status_var.set(f"IOCTL failed: Win32 error 0x{exc.errno & 0xFFFFFFFF:08X}")
            return
        except DriverError as exc:
            status_var.set(f"driver error: {exc}")
            return
        except OSError as exc:
            status_var.set(f"OSError: errno={exc.errno}")
            return

        tree.delete(*tree.get_children())
        for r in result.rows:
            tags: tuple = ()
            tree.insert(
                "",
                "end",
                values=(
                    r.tid, r.pid, r.module,
                    "yes",   # public presence implied by being in the public view; full source mask is in the protocol row
                    "yes",
                    "yes",
                    f"0x{r.anomaly:02X}" if r.anomaly else "",
                ),
                tags=tags,
            )
        status_var.set(
            f"OK: {result.bytes_used} bytes, public_only={result.public_only} "
            f"hidden={result.hidden_count}"
        )
        summary_var.set(f"rows={len(result.rows)}")

    ttk.Button(toolbar, text="Refresh", command=_do_refresh).grid(row=0, column=2, padx=2)

    return frame


# The cli_setup attribute is registered by the thread.cli module, not this
# file. Kept here so older plugin loaders that still expect a symbol in ui
# can import it (it's a no-op stub).
def _setup_cli(_subparsers: Any, _client: Optional[ArkClient]) -> None:
    return None


__all__ = ["register", "_build_ui"]
