"""S5 acceptance: history.log DPAPI encryption + plaintext compatibility.

The history store must stay readable across format transitions: the
reader accepts both plaintext JSON lines and ``ENC1:`` DPAPI lines, the
writer's format is controlled by an explicit knob (module flag /
``MYARK_HISTORY_ENCRYPT``), and an in-place migration converts legacy
plaintext files without losing records.
"""

from __future__ import annotations

import pytest

from myark import history


@pytest.fixture(autouse=True)
def _isolated_history(tmp_path):
    """Every test gets its own history file and a clean encryption knob."""
    path = tmp_path / "history.log"
    history.set_history_path(path)
    history.set_encryption_enabled(False)
    yield path
    history.reset_encryption_enabled()
    history.reset_history_path()


def _record(action: str = "kill", target: str = "4242") -> history.HistoryRecord:
    return history.HistoryRecord(
        timestamp=1726358400.0,
        action=action,
        target=target,
        result="ok",
        detail="unit-test",
    )


class TestEncryptionKnob:
    def test_default_off(self, monkeypatch) -> None:
        monkeypatch.delenv("MYARK_HISTORY_ENCRYPT", raising=False)
        history.reset_encryption_enabled()
        assert history.encryption_enabled() is False

    def test_env_var_enables(self, monkeypatch) -> None:
        monkeypatch.setenv("MYARK_HISTORY_ENCRYPT", "1")
        history.reset_encryption_enabled()
        assert history.encryption_enabled() is True

    def test_env_var_accepts_true_on_yes(self, monkeypatch) -> None:
        for value in ("true", "ON", "Yes"):
            monkeypatch.setenv("MYARK_HISTORY_ENCRYPT", value)
            history.reset_encryption_enabled()
            assert history.encryption_enabled() is True

    def test_module_flag_overrides_env(self, monkeypatch) -> None:
        monkeypatch.setenv("MYARK_HISTORY_ENCRYPT", "1")
        history.set_encryption_enabled(False)
        assert history.encryption_enabled() is False
        history.set_encryption_enabled(True)
        assert history.encryption_enabled() is True


class TestEncryptedRoundtrip:
    def test_appended_line_is_not_plaintext(self, tmp_path) -> None:
        history.set_encryption_enabled(True)
        history.record("kill", "4242", "ok")
        raw = (tmp_path / "history.log").read_text(encoding="utf-8")
        assert raw.startswith(history._ENC_LINE_PREFIX)
        assert "4242" not in raw
        assert '"action"' not in raw

    def test_roundtrip_read_back(self) -> None:
        history.set_encryption_enabled(True)
        history.record("kill", "4242", "ok")
        records = history.read_recent()
        assert len(records) == 1
        assert records[0].action == "kill"
        assert records[0].target == "4242"


class TestPlaintextCompatibility:
    def test_default_format_unchanged(self, tmp_path) -> None:
        history.record("kill", "7", "ok")
        raw = (tmp_path / "history.log").read_text(encoding="utf-8")
        assert '"action": "kill"' in raw
        assert history._ENC_LINE_PREFIX not in raw

    def test_mixed_file_readable_with_encryption_off(self, tmp_path) -> None:
        # A legacy plaintext line and an ENC1 line coexist; the reader
        # must decode both shapes.
        history.set_encryption_enabled(True)
        history.record("kill", "1", "ok")
        history.set_encryption_enabled(False)
        history.record("kill", "2", "ok")
        records = history.read_recent()
        assert [r.target for r in records] == ["1", "2"]

    def test_undecodable_line_skipped(self, tmp_path) -> None:
        history.set_encryption_enabled(True)
        history.record("kill", "1", "ok")
        path = tmp_path / "history.log"
        lines = path.read_text(encoding="utf-8").splitlines()
        lines.append(history._ENC_LINE_PREFIX + "!!!not-base64!!!")
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        records = history.read_recent()
        assert [r.target for r in records] == ["1"]


class TestMigration:
    def test_migrate_converts_and_preserves(self, tmp_path) -> None:
        history.record("kill", "1", "ok")
        history.record("kill", "2", "ok")
        path = tmp_path / "history.log"

        converted, unchanged = history.migrate_to_encrypted()
        assert (converted, unchanged) == (2, 0)

        raw = path.read_text(encoding="utf-8")
        assert raw.count(history._ENC_LINE_PREFIX) == 2
        assert '"action"' not in raw

        # The records survive the rewrite.
        targets = [r.target for r in history.read_recent()]
        assert targets == ["1", "2"]

    def test_migrate_keeps_already_encrypted_lines(self, tmp_path) -> None:
        history.set_encryption_enabled(True)
        history.record("kill", "1", "ok")
        history.set_encryption_enabled(False)
        history.record("kill", "2", "ok")

        converted, unchanged = history.migrate_to_encrypted()
        assert converted == 1
        assert unchanged == 1
        assert [r.target for r in history.read_recent()] == ["1", "2"]

    def test_migrate_missing_file_is_noop(self, tmp_path) -> None:
        assert history.migrate_to_encrypted(path=tmp_path / "absent.log") == (0, 0)

    def test_migrate_garbage_lines_preserved(self, tmp_path) -> None:
        path = tmp_path / "history.log"
        path.write_text("not json at all\n", encoding="utf-8")
        converted, unchanged = history.migrate_to_encrypted()
        assert (converted, unchanged) == (0, 1)
        assert "not json at all" in path.read_text(encoding="utf-8")
