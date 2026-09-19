"""
kernel_ext client (parser) tests.
"""

from __future__ import annotations

from myark.modules.kernel_ext import parser as P
from myark.modules.kernel_ext import protocol as PP


def test_win11_info_blob_defaults():
    b = P.Win11InfoBlob()
    assert b.info_class == 0
    assert b.status == 0
    assert b.bytes_returned == 0
    assert b.source == ""


def test_syscall_entry_defaults():
    e = P.SyscallEntry()
    assert e.index == 0
    assert e.address == 0


def test_syscall_table_defaults():
    t = P.SyscallTable(entries=[], source="r3-fallback")
    assert t.entries == []
    assert t.source == "r3-fallback"


def test_query_win11_info_r3_fallback_when_no_driver():
    b = P.query_win11_info(None, 0xAD)
    assert b.source == "r3-fallback"
    assert b.info_class == 0xAD
    assert b.status == 0xC0000002
    assert b.bytes_returned == 0


def test_read_syscall_table_r3_fallback_when_no_driver():
    t = P.read_syscall_table(None)
    assert t.source == "r3-fallback"
    assert t.entries == []


def test_status_not_implemented_constant():
    # 0xC0000002 is NTSTATUS STATUS_NOT_IMPLEMENTED
    assert P._r3_fallback_query(0xAD).status == 0xC0000002


def test_query_with_various_classes():
    for cls in [0xAD, 0xAE, 0xAF, 0xB0]:
        b = P.query_win11_info(None, cls)
        assert b.info_class == cls
        assert b.source == "r3-fallback"


def test_syscall_table_can_hold_entries():
    t = P.SyscallTable(
        entries=[P.SyscallEntry(index=1, address=0xFFFFF80000001000)],
        source="r0",
    )
    assert len(t.entries) == 1
    assert t.entries[0].index == 1
    assert t.entries[0].address == 0xFFFFF80000001000
