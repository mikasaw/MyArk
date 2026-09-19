"""MyArk main window: Tkinter UI for the R3 side of the tool.

The layout is a three-pane horizontal split:

* **Left**   -- module list (click to switch to a module tab) +
               free-text filter (substr / pinyin). Above the splitter,
               a top toolbar binds the Ctrl+P command palette and the
               sidebar advanced-search dialog.
* **Center** -- ``ttk.Notebook`` with one tab per registered module.
               Per-module UI lives in ``myark.modules.<name>.ui``.
* **Right**  -- capability panel (driver IOCTLs) + search buttons
               (Ctrl+P palette, advanced search).
* **Bottom** -- ``StatusBar`` showing driver / module count / last
               refresh.

Windows DPI awareness is opted into before any Tk widget is built so
the default 150 % scale on Windows 11 does not blur the rendered text.
"""

from __future__ import annotations

import sys
import tkinter as tk
from tkinter import messagebox, ttk
from typing import Optional

from .. import __version__ as APP_VERSION
from ..client.ark_client import ArkClient, DriverError
from ..client.driver_check import (
    driver_not_installed_message,
    probe_driver,
)
from ..client.module_query import ModuleQuery
from ..plugin_loader import ModuleRegistration, load_modules
from .layout import LayoutState, load_layout, save_layout
from .safety_dialog import SafetyTokenAuthority
from .search import (
    AdvancedFilter,
    MatchMode,
    build_index,
    open_palette,
    open_panel,
)
from .widgets import (
    ActionsPanel,
    CapabilityPanel,
    ModulesPanel,
    MyArkSplitter,
    R3ModulePanel,
    StatusBar,
    TreeTable,
)
from .widgets.detail_window import DetailWindow
from .widgets.diff_window import DiffWindow
from .widgets.filter_window import FilterWindow
from .widgets.history_window import HistoryWindow
from .keybindings import PopupStack, bind_keys


APP_TITLE = "MyArk"
DEFAULT_FILTER_HINT = "filter (substring / pinyin)..."


def _enable_dpi_awareness() -> None:
    """Set the process DPI awareness so Tk scales correctly on Win10/11.

    The call is best-effort: pre-Win10 hosts don't have ``shcore``; macOS
    / Linux Tk does not need it. Any failure is swallowed silently.
    """
    try:
        import ctypes

        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            # Either pre-1.3 (Win 8.0) or non-Windows.
            try:
                ctypes.windll.user32.SetProcessDPIAware()
            except Exception:
                pass
    except Exception:
        pass


def _filter_from_dict(data: dict) -> AdvancedFilter:
    """Rebuild an :class:`AdvancedFilter` from its dict form."""
    fields = data.get("fields") or {}
    raw_ranges = data.get("ranges") or {}
    ranges: dict = {}
    for k, pair in raw_ranges.items():
        if isinstance(pair, (list, tuple)) and len(pair) == 2:
            ranges[k] = (
                int(pair[0]) if pair[0] is not None else None,
                int(pair[1]) if pair[1] is not None else None,
            )
        else:
            ranges[k] = (None, None)
    try:
        mode = MatchMode(data.get("mode", MatchMode.PINYIN.value))
    except ValueError:
        mode = MatchMode.PINYIN
    return AdvancedFilter(fields={k: str(v) for k, v in fields.items()},
                          ranges=ranges, mode=mode)


def _filter_to_dict(flt: Optional[AdvancedFilter]) -> Optional[dict]:
    """Inverse of :func:`_filter_from_dict`."""
    if flt is None or not flt.is_active():
        return None
    return {
        "fields": dict(flt._fields),
        "ranges": {k: list(v) for k, v in flt._ranges.items()},
        "mode": flt.mode.value,
    }


class MainWindow(tk.Tk):
    """Top-level window for ``myark-ui``."""

    def __init__(self) -> None:
        _enable_dpi_awareness()
        super().__init__()
        self.title(f"{APP_TITLE} {APP_VERSION}")
        self._initial_layout = load_layout()
        if self._initial_layout.geometry:
            self.geometry(self._initial_layout.geometry)
        else:
            self.geometry("1280x800")
        self.minsize(900, 600)

        # 1. Probe the driver first so the status bar shows the right state
        #    before any UI is drawn.
        self._probe = probe_driver()
        self._client: Optional[ArkClient] = None
        if self._probe.installed and self._probe.version_output is not None:
            try:
                self._client = ArkClient.open()
            except DriverError:
                self._client = None

        # 2. Discover capabilities + modules (no-op when driver absent).
        self._capabilities: list = []
        self._modules: list = []
        if self._client is not None:
            try:
                mq = ModuleQuery(self._client)
                self._capabilities = mq.query_capabilities()
                self._modules = mq.query_modules()
            except DriverError:
                self._capabilities = []
                self._modules = []

        # 3. Load plugin modules via entry points.
        self._registered: dict[str, ModuleRegistration] = load_modules(
            self._client,
            self._capabilities,
        )

        # 3b. Per-session safety token authority. Modules that expose
        #     destructive actions (terminate / inject / set-integrity / ...)
        #     gate those actions through this authority. The authority is
        #     created lazily on first use, so import + tests do not show
        #     a token unless they explicitly ask for one.
        self._safety: SafetyTokenAuthority = SafetyTokenAuthority()

        # 3c. Popup stack: tracks open Detail/Diff/Filter/History
        #     windows so Ctrl+Tab / Ctrl+W can cycle / close them.
        self._popup_stack: PopupStack = PopupStack(self)

        # 4. Build the menu and the body.
        self._active_advanced: Optional[AdvancedFilter] = None
        self._build_menu()
        self._build_toolbar()
        self._build_body()
        self._refresh_status()

        # 5. Global keybindings.
        self.bind_all("<Control-p>", lambda _e: self._open_palette())
        self.bind_all("<Control-P>", lambda _e: self._open_palette())
        self.bind_all("<Control-Shift-f>", lambda _e: self._open_adv_search())
        bind_keys(
            self,
            on_f1=self._open_help,
            on_f5=self._refresh_current_tab,
            on_ctrl_tab=self._cycle_popup,
            on_ctrl_w=self._close_popup,
        )

        # 6. Restore the persisted sash position (geometry was applied
        #    above). ``update_idletasks`` lets the splitter compute its
        #    real pixel positions before we push the saved offset in.
        if self._initial_layout.sash_positions:
            self.update_idletasks()
            try:
                self._splitter.restore_sash_positions(
                    self._initial_layout.sash_positions
                )
            except Exception:
                pass

        # 7. Restore the active module tab + advanced filter from the
        #    last session. Both are best-effort.
        if self._initial_layout.active_module:
            for tab_id in self._notebook.tabs():
                if self._notebook.tab(tab_id, "text") == self._initial_layout.active_module:
                    try:
                        self._notebook.select(tab_id)
                    except tk.TclError:
                        pass
                    break

        if self._initial_layout.advanced_filter:
            try:
                self._active_advanced = _filter_from_dict(
                    self._initial_layout.advanced_filter
                )
                if self._active_advanced.is_active():
                    self._adv_label_var.set(self._active_advanced.describe())
            except Exception:
                self._active_advanced = None

        # 8. Persist on close.
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        # If the driver was missing, surface a banner so users don't think
        # the empty UI is a real empty result.
        if self._client is None:
            self.after(
                200,
                lambda: messagebox.showwarning(
                    APP_TITLE,
                    driver_not_installed_message(),
                    parent=self,
                ),
            )

    # --------------------------------------------------------------- menu

    def _build_menu(self) -> None:
        menubar = tk.Menu(self)

        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Exit", accelerator="Alt+F4", command=self.destroy)
        menubar.add_cascade(label="File", menu=file_menu)

        search_menu = tk.Menu(menubar, tearoff=0)
        search_menu.add_command(
            label="Command Palette",
            accelerator="Ctrl+P",
            command=self._open_palette,
        )
        search_menu.add_command(
            label="Advanced Search...",
            accelerator="Ctrl+Shift+F",
            command=self._open_adv_search,
        )
        menubar.add_cascade(label="Search", menu=search_menu)

        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(
            label="Detail (selected row)...",
            accelerator="F1",
            command=self._open_detail,
        )
        view_menu.add_command(
            label="Compare two rows...",
            command=self._open_diff,
        )
        view_menu.add_command(
            label="Filter builder...",
            command=self._open_filter_builder,
        )
        view_menu.add_command(
            label="Action history...",
            accelerator="Ctrl+Shift+H",
            command=self._open_history,
        )
        menubar.add_cascade(label="View", menu=view_menu)

        driver_menu = tk.Menu(menubar, tearoff=0)
        driver_menu.add_command(label="Re-probe driver", command=self._reprobe)
        driver_menu.add_separator()
        driver_menu.add_command(label="Help (F1)", command=self._open_help)
        driver_menu.add_command(label="About", command=self._show_about)
        menubar.add_cascade(label="Driver", menu=driver_menu)

        self.config(menu=menubar)

    # -------------------------------------------------------------- toolbar

    def _build_toolbar(self) -> None:
        """Top toolbar: Modules strip + search actions."""
        bar = ttk.Frame(self, padding=(6, 4))
        bar.pack(fill=tk.X, side=tk.TOP, before=self._body_placeholder())

        ttk.Button(bar, text="Ctrl+P  Command Palette",
                   command=self._open_palette).pack(side=tk.LEFT)
        ttk.Button(bar, text="Advanced Search...",
                   command=self._open_adv_search).pack(side=tk.LEFT, padx=(6, 0))

        # Top modules strip: 7 R3 modules + their driver-side state.
        self._modules_panel = ModulesPanel(bar)
        self._modules_panel.set_modules(
            self._modules,
            registered=sorted(self._registered.keys()),
        )
        self._modules_panel.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(12, 0))

        self._module_var = tk.StringVar(value="(no module)")
        ttk.Label(bar, textvariable=self._module_var, foreground="#888").pack(
            side=tk.RIGHT
        )

    def _body_placeholder(self) -> Optional[tk.Widget]:
        """Return the topmost widget below the toolbar so ``pack(before=)``
        anchors correctly. The body frame is created in ``_build_body``."""
        return getattr(self, "_body_frame", None)

    # --------------------------------------------------------------- body

    def _build_body(self) -> None:
        # Vertical: body (top) + status bar (bottom).
        self._body_frame = ttk.Frame(self)
        self._body_frame.pack(fill=tk.BOTH, expand=True)

        outer = self._body_frame

        self._splitter = MyArkSplitter(outer, orient=tk.HORIZONTAL)
        self._splitter.pack(fill=tk.BOTH, expand=True)

        # ---- left pane: module list + free-text filter
        left = ttk.Frame(self._splitter)
        ttk.Label(left, text="Modules", anchor=tk.W).pack(fill=tk.X, padx=4, pady=(4, 0))
        self._filter_var = tk.StringVar()
        self._filter_var.trace_add("write", lambda *_: self._apply_filter())
        self._filter_entry = ttk.Entry(left, textvariable=self._filter_var)
        self._filter_entry.pack(fill=tk.X, padx=4, pady=2)
        ttk.Label(left, text=DEFAULT_FILTER_HINT, foreground="#888").pack(
            anchor=tk.W, padx=4, pady=(0, 2)
        )

        self._module_table = TreeTable(
            left,
            columns=("module", "description"),
            height=18,
        )
        self._module_table.pack(fill=tk.BOTH, expand=True, padx=4, pady=(0, 4))
        self._populate_module_table()
        self._splitter.add_pane(left, weight=1)

        # ---- center pane: module tabs (Notebook)
        center = ttk.Frame(self._splitter)
        self._notebook = ttk.Notebook(center)
        self._notebook.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        self._populate_module_tabs()
        self._notebook.bind("<<NotebookTabChanged>>", lambda _e: self._on_tab_changed())
        self._splitter.add_pane(center, weight=3)

        # ---- right pane: capability sidebar + advanced filter strip
        right = ttk.Frame(self._splitter)

        sidebar = ttk.LabelFrame(right, text="Capabilities")
        self._capability_panel = CapabilityPanel(sidebar)
        self._capability_panel.set_capabilities(self._capabilities)
        self._capability_panel.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
        sidebar.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        adv_frame = ttk.LabelFrame(right, text="Advanced filter (active)")
        adv_frame.pack(fill=tk.X, padx=4, pady=(0, 4))
        self._adv_label_var = tk.StringVar(value="(none)")
        ttk.Label(adv_frame, textvariable=self._adv_label_var,
                  foreground="#888", wraplength=280, justify=tk.LEFT).pack(
            fill=tk.X, padx=4, pady=2
        )
        ttk.Button(adv_frame, text="Clear advanced filter",
                   command=self._clear_advanced).pack(anchor=tk.W, padx=4, pady=(0, 4))

        self._splitter.add_pane(right, weight=2)

        # ---- bottom: status bar
        self._status_bar = StatusBar(self._body_frame)
        self._status_bar.pack(fill=tk.X, side=tk.BOTTOM)

    def _populate_module_table(self) -> None:
        rows = [
            (name, reg.description or "")
            for name, reg in sorted(self._registered.items())
        ]
        self._module_table.set_rows(rows)

    def _populate_module_tabs(self) -> None:
        """Add one tab per registered module; add an Overview tab if driver OK."""
        if self._client is not None:
            overview = self._build_overview_tab()
            self._notebook.add(overview, text="Overview")

        for name in sorted(self._registered.keys()):
            reg = self._registered[name]
            try:
                widget = reg.make_ui(
                    self._notebook,
                    self._client,
                    safety_authority=self._safety,
                )
            except Exception as exc:
                print(f"[MainWindow] module {name} ui_factory failed: {exc}",
                      file=sys.stderr)
                continue
            if widget is None:
                if name == "actions":
                    # S10.5: the actions module is CLI-only for now; show
                    # its IOCTL surface instead of a bare placeholder tab.
                    panel = ActionsPanel(self._notebook)
                    panel.set_capabilities(self._capabilities)
                    self._notebook.add(panel, text=name)
                else:
                    # S10.6: every other UI-less module gets the generic
                    # protocol-mirror panel instead of a dead placeholder.
                    panel = R3ModulePanel(self._notebook, name,
                                          module_id=self._driver_module_id(name))
                    panel.set_capabilities(self._capabilities)
                    self._notebook.add(panel, text=name)
                continue
            self._notebook.add(widget, text=name)

        if not self._notebook.tabs():
            placeholder = ttk.Frame(self._notebook, padding=20)
            ttk.Label(
                placeholder,
                text=(
                    "No modules registered.\n\n"
                    + driver_not_installed_message()
                    if self._client is None
                    else "No modules registered.\n"
                ),
                justify=tk.CENTER,
            ).pack(expand=True)
            self._notebook.add(placeholder, text="(empty)")

    def _driver_module_id(self, name: str) -> Optional[int]:
        """Map a registered module name to its driver module id.

        ``QUERY_MODULES`` reports one ``ModuleInfo`` per in-tree module
        ('CBLK'-style ids); R3 plugin names match the driver's
        ``ModuleName`` strings. Returns ``None`` when the driver is
        offline (or the module is R3-only) -- R3ModulePanel then keys
        off protocol-mirror IOCTL codes instead.
        """
        for info in self._modules:
            if info.name == name:
                return info.module_id
        return None

    def _build_overview_tab(self) -> ttk.Frame:
        frame = ttk.Frame(self._notebook, padding=8)
        if self._probe.version_output is None:
            ttk.Label(frame, text="driver probe incomplete").pack(anchor=tk.W)
            return frame

        ver = self._probe.version_output
        rows = [
            ("Display name", ver.DisplayName),
            ("Core protocol", ver.CoreProtocolVersion),
            ("Module protocol", ver.ModuleProtocolVersion),
            ("Build number", ver.BuildNumber),
            ("Active modules", ver.ActiveModuleCount),
        ]
        for k, v in rows:
            row = ttk.Frame(frame)
            row.pack(fill=tk.X, pady=1)
            ttk.Label(row, text=f"{k}:", width=18, anchor=tk.W).pack(side=tk.LEFT)
            ttk.Label(row, text=str(v), anchor=tk.W).pack(side=tk.LEFT, fill=tk.X, expand=True)
        return frame

    # ----------------------------------------------------------- actions

    def _apply_filter(self) -> None:
        # Use the matcher on the module table; the per-module tab UI does
        # its own filtering (its widgets already have refresh logic).
        needle = self._filter_var.get().strip()
        rows = [
            (name, reg.description or "")
            for name, reg in sorted(self._registered.items())
        ]
        if needle:
            from .search.matcher import MatchMode as _MM, match
            rows = [
                r for r in rows
                if match(needle, r[0], _MM.PINYIN)
                or match(needle, r[1], _MM.PINYIN)
            ]
        self._module_table.set_rows(rows)
        try:
            self._status_bar.set_rows(len(rows))
        except AttributeError:
            pass
        self._status_bar.set_refresh_time()

    def _open_palette(self) -> None:
        """Build a fresh palette on Ctrl+P. The picker callback jumps
        to the matching module's tab; if the entry has ``kind == 'row'``
        we additionally forward focus to the module's first Refresh."""
        try:
            entries = build_index(self._client, self._capabilities)
        except Exception as exc:
            messagebox.showerror(APP_TITLE,
                                 f"build_index failed: {exc}", parent=self)
            return

        def _pick(entry) -> None:
            name = entry.module
            for tab_id in self._notebook.tabs():
                tab_text = self._notebook.tab(tab_id, "text")
                if tab_text == name:
                    self._notebook.select(tab_id)
                    self._module_var.set(f"module: {name}")
                    return

        open_palette(self, entries=entries, on_pick=_pick)

    def _open_adv_search(self) -> None:
        panel = open_panel(self, initial=self._active_advanced)
        self.wait_window(panel)
        result = panel.result
        if result is None:
            return
        self._active_advanced = result
        self._adv_label_var.set(result.describe())
        self._refresh_status()

    def _clear_advanced(self) -> None:
        self._active_advanced = None
        self._adv_label_var.set("(none)")
        self._refresh_status()

    def _on_tab_changed(self) -> None:
        try:
            tab_text = self._notebook.tab(self._notebook.select(), "text")
        except tk.TclError:
            tab_text = "?"
        self._module_var.set(f"module: {tab_text}")

    def _refresh_current_tab(self) -> None:
        # Per-tab refresh is best-effort -- module UIs may or may not
        # expose a refresh hook. The status bar message is updated so
        # the user knows the keypress was received.
        try:
            tab_text = self._notebook.tab(self._notebook.select(), "text")
        except tk.TclError:
            return
        self._status_bar.set_message(f"F5: refresh requested for '{tab_text}'")

    # ---------------------------------------------------------------- popups

    def _open_detail(self) -> None:
        """Open a DetailWindow for the first selected row in the module table."""
        item = self._module_table.selected_iid()
        if item is None:
            self._status_bar.set_message("Detail: select a module row first")
            return
        row = self._module_table.tree.item(item, "values")
        if not row:
            return
        keys = ("module", "description")
        data = {str(k): str(v) for k, v in zip(keys, row)}
        win = DetailWindow(self, item=data, title=f"Module: {data.get('module', '')}")
        self._popup_stack.register(win)

    def _open_diff(self) -> None:
        """Open a DiffWindow comparing the two most-recent selections.

        For now the comparison is a placeholder -- we build an empty
        shell so the user sees the dialog. Module UIs can wire their
        own selection tracking in a later iteration.
        """
        win = DiffWindow(
            self,
            item_a={"left": "(no selection)"},
            item_b={"right": "(no selection)"},
            kind="generic",
            title="Compare two rows",
        )
        self._popup_stack.register(win)

    def _open_filter_builder(self) -> None:
        """Open the filter builder; apply result via the existing advanced
        filter slot so the right-side panel reflects the new filter."""
        win = FilterWindow(
            self,
            initial=self._active_advanced,
            on_apply=self._apply_builder_filter,
            title="Filter builder",
        )
        self._popup_stack.register(win)

    def _apply_builder_filter(self, flt: AdvancedFilter) -> None:
        if flt.is_active():
            self._active_advanced = flt
            self._adv_label_var.set(flt.describe())
        else:
            self._active_advanced = None
            self._adv_label_var.set("(none)")
        self._refresh_status()

    def _open_history(self) -> None:
        """Open the per-session action history popup."""
        win = HistoryWindow(self)
        self._popup_stack.register(win)

    def _open_help(self) -> None:
        """Show a one-page help dialog with the keyboard shortcuts."""
        win = tk.Toplevel(self)
        win.title(f"{APP_TITLE} -- help")
        win.transient(self)
        win.resizable(True, True)
        win.minsize(420, 280)

        text = (
            f"{APP_TITLE} {APP_VERSION}\n\n"
            "Keyboard shortcuts:\n"
            "  Ctrl+P         Command palette\n"
            "  Ctrl+Shift+F   Advanced search / filter builder\n"
            "  F1             This help dialog\n"
            "  F5             Refresh current tab\n"
            "  Ctrl+Tab       Cycle focus between popups (Shift reverses)\n"
            "  Ctrl+W         Close current popup\n"
            "  Ctrl+Shift+H   Action history popup\n\n"
            "Multi-window popups (View menu):\n"
            "  Detail...       show a single row's full key/value map\n"
            "  Compare...      diff two rows side-by-side\n"
            "  Filter...       multi-criteria filter builder\n"
            "  History...      recent destructive actions\n\n"
            "All modules run in pure R3 -- no driver required for browsing."
        )
        body = ttk.Frame(win, padding=10)
        body.pack(fill=tk.BOTH, expand=True)
        ttk.Label(body, text=text, justify=tk.LEFT, wraplength=420).pack(
            fill=tk.BOTH, expand=True
        )
        ttk.Button(body, text="Close", command=win.destroy).pack(anchor=tk.E, pady=(8, 0))
        win.bind("<Escape>", lambda _e: win.destroy())
        self._popup_stack.register(win)

    def _cycle_popup(self, reverse: bool = False) -> None:
        """Ctrl+Tab handler: cycle focus to the next popup (or the master)."""
        self._popup_stack.focus_next(reverse=bool(reverse))

    def _close_popup(self) -> None:
        """Ctrl+W handler: destroy the topmost popup, if any."""
        if not self._popup_stack.close_top():
            # No popups open -- Ctrl+W on the main window is a no-op
            # so the user does not lose work by accident.
            pass

    def _refresh_status(self) -> None:
        if self._client is not None and self._probe.version_output is not None:
            self._status_bar.set_driver(True, self._probe.version_output.DisplayName)
        else:
            self._status_bar.set_driver(False)
        self._status_bar.set_module_count(
            sum(1 for m in self._modules if m.state == "enabled"),
            len(self._modules),
        )
        suffix = ""
        if self._active_advanced and self._active_advanced.is_active():
            suffix = f"  |  filter: {self._active_advanced.describe()}"
        self._status_bar.set_message(
            f"registered: {', '.join(sorted(self._registered.keys())) or '(none)'}{suffix}"
        )

    def _reprobe(self) -> None:
        self._probe = probe_driver()
        if self._probe.installed:
            self._status_bar.set_message("driver re-probe: ok")
        else:
            self._status_bar.set_message(
                f"driver re-probe: missing (err 0x{self._probe.error_code or 0:X})"
            )

    def _show_about(self) -> None:
        messagebox.showinfo(
            APP_TITLE,
            f"{APP_TITLE} {APP_VERSION}\n\n"
            "R3 client for the MyArkCore KMDF driver (127 IOCTLs).\n"
            "Driver-backed data panels for process / registry / file / network\n"
            "and more, plus pure-R3 panels when no driver is loaded.\n"
            "Three-layer search: left-column filter, Ctrl+P command palette,\n"
            "advanced sidebar filter builder (Chinese / pinyin aware).\n"
            "Multi-window popups: Detail / Diff / Filter / History.\n"
            "All modules run in pure R3 -- no driver required for browsing.",
            parent=self,
        )

    def _on_close(self) -> None:
        """Save the layout before the window goes away."""
        try:
            state = LayoutState()
            try:
                state.geometry = self.geometry()
            except tk.TclError:
                state.geometry = ""
            try:
                state.sash_positions = self._splitter.current_sash_positions()
            except (tk.TclError, AttributeError):
                state.sash_positions = []
            try:
                tab_id = self._notebook.select()
                state.active_module = self._notebook.tab(tab_id, "text")
            except tk.TclError:
                state.active_module = self._initial_layout.active_module
            state.advanced_filter = _filter_to_dict(self._active_advanced)
            save_layout(state)
        except Exception as exc:  # pragma: no cover -- IO failure
            print(f"[MainWindow] layout save failed: {exc}", file=sys.stderr)
        finally:
            self.destroy()


def main() -> int:
    """Console-script entry point declared in ``pyproject.toml``."""
    MainWindow().mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())


__all__ = ["MainWindow", "main", "APP_TITLE", "APP_VERSION"]