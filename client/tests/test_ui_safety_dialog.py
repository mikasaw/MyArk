"""Tests for the SafetyTokenAuthority + its wiring into module UIs.

The MyArk UI ships a :class:`SafetyTokenAuthority` so destructive
actions (thread terminate / process kill / DLL inject / set-integrity
/ ...) must ask the user to type a per-session token before they fire.
These tests cover two angles:

* the authority itself (token lifecycle + comparison semantics);
* the ``safety_authority`` kwarg that :meth:`ModuleRegistration.make_ui`
  now propagates, so module UIs can gate destructive actions through
  :func:`myark.ui.safety_dialog.confirm`.

The Tk-side confirm flow needs a real display, so we mock the dialog
here and only exercise the authority + the make_ui plumbing.
"""

from __future__ import annotations

import os
import unittest

from myark.plugin_loader import ModuleRegistration
from myark.ui.safety_dialog import SafetyTokenAuthority


HARNESS_HAS_TK = os.name == "nt" or os.environ.get("DISPLAY")


class TestSafetyTokenAuthority(unittest.TestCase):
    def test_token_is_six_chars(self):
        a = SafetyTokenAuthority()
        t = a.token()
        self.assertEqual(len(t), 6)
        # Alphabet is uppercase letters + digits, so no lowercase ever.
        self.assertTrue(all(c.isalnum() for c in t))
        self.assertFalse(any(c.islower() for c in t))

    def test_token_rotate_changes(self):
        a = SafetyTokenAuthority()
        t1 = a.token()
        a.rotate()
        t2 = a.token()
        self.assertNotEqual(t1, t2)

    def test_consume_clears_token(self):
        a = SafetyTokenAuthority()
        t = a.token()
        self.assertTrue(a.consume(t))
        # A second consume with the same token must fail because the
        # token was cleared on the first success.
        self.assertFalse(a.consume(t))

    def test_consume_is_case_insensitive(self):
        a = SafetyTokenAuthority()
        t = a.token()
        self.assertTrue(a.consume(t.lower()))

    def test_consume_trims_whitespace(self):
        a = SafetyTokenAuthority()
        t = a.token()
        self.assertTrue(a.consume(f"  {t}  "))

    def test_consume_rejects_wrong_token(self):
        a = SafetyTokenAuthority()
        a.token()
        self.assertFalse(a.consume("XXXXXX"))
        # After a failed consume the token is still valid for a retry.
        self.assertTrue(a.consume(a.token()))

    def test_consume_rejects_when_no_token(self):
        a = SafetyTokenAuthority()
        # No token has been generated yet.
        self.assertFalse(a.consume("ABCDEF"))

    def test_clear_invalidates_token(self):
        a = SafetyTokenAuthority()
        t = a.token()
        a.clear()
        self.assertFalse(a.consume(t))


class TestSafetyAuthorityWiring(unittest.TestCase):
    """``ModuleRegistration.make_ui`` must forward ``safety_authority``."""

    def _registration(self, received):
        def _factory(parent, client, *, safety_authority=None):
            received["safety_authority"] = safety_authority
            return object()

        return ModuleRegistration(
            name="probe",
            register_fn=lambda _c, _caps: ModuleRegistration(
                name="probe",
                register_fn=lambda *_: None,
                ui_factory=_factory,
            ),
            ui_factory=_factory,
        )

    def test_make_ui_passes_authority(self):
        received: dict = {}
        reg = self._registration(received)
        authority = SafetyTokenAuthority()
        reg.make_ui(object(), None, safety_authority=authority)
        self.assertIs(received["safety_authority"], authority)

    def test_make_ui_defaults_authority_to_none(self):
        received: dict = {}
        reg = self._registration(received)
        reg.make_ui(object(), None)
        self.assertIsNone(received["safety_authority"])

    def test_legacy_ui_factory_still_works(self):
        """Old ``_build_ui(parent, client)`` factories keep working."""

        def legacy(parent, client):
            return ("legacy", parent, client)

        reg = ModuleRegistration(
            name="legacy",
            register_fn=lambda *_: None,
            ui_factory=legacy,
        )
        result = reg.make_ui("parent", "client", safety_authority=SafetyTokenAuthority())
        self.assertEqual(result, ("legacy", "parent", "client"))

    def test_thread_ui_accepts_authority_kwarg(self):
        # The thread module is the first module that exposes a
        # destructive action (terminate), so it must accept the
        # ``safety_authority`` kwarg. We just check the signature here
        # to keep the test fully headless.
        import inspect
        from myark.modules.thread.ui import _build_list_tab, _build_ui

        self.assertIn("safety_authority", inspect.signature(_build_ui).parameters)
        self.assertIn("safety_authority", inspect.signature(_build_list_tab).parameters)


if __name__ == "__main__":
    unittest.main()
