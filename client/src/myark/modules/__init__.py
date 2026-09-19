"""MyArk R3 modules -- one subpackage per driver module.

Each subpackage exposes a ``register(client, capabilities)`` function that
the :mod:`myark.plugin_loader` discovers through the ``myark.modules``
entry point group declared in ``pyproject.toml``. Modules are *opt-in*:
shipping the package does not register the entry point -- the operator
adds it to ``pyproject.toml`` when the matching driver ``MYARK_MODULE_<NAME>``
profile gate is enabled.

Why a separate subpackage per module? It mirrors the driver layout (each
module is its own ``driver/src/modules/<name>/`` directory with its own
descriptor + IOCTL handlers) and lets future third-party plugins ship as
separate distributions that follow the same contract.
"""