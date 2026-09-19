"""MyArk thread module -- R3 client for IOCTL_MYARK_THREAD_*.

Driver-side code lives in ``driver/src/modules/11_thread/``; shared wire
protocol in ``shared/driver/MyArkThreadIoctl.h``. This Python module
mirrors that protocol via ctypes and exposes:

* ``protocol`` -- low-level ctypes structs, IOCTL codes, and one function
  per IOCTL. Use these directly from scripts that don't need UI/CLI.
* ``parser``   -- pure-R3 helpers (toolhelp32 snapshot, OpenThread,
  GetThreadTimes, GetThreadContext, TerminateThread). Backs the
  ``myark-cli thread ...`` R3 default so the CLI works on hosts without
  MyArkCore.sys.
* ``ui``       -- Tkinter factory wired into the central TabNotebook.
* ``cli``      -- argparse subcommands for ``myark-cli thread ...``.

``register()`` is re-exported from ``plugin.py`` so third-party
consumers can do either ``from myark.modules.thread import register`` or
``from myark.modules.thread.plugin import register``.
"""

from myark.modules.thread.plugin import register

__all__ = ["register", "protocol", "parser", "ui", "cli"]