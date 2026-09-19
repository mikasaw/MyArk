# R3-1b bring-up: VPD 0x83 disk inventory + NSI capture sampling.
#
# Run inside the test guest from the driver test directory:
#   python hwid_arp_calib.py > calib_out.txt 2>&1
#
# Prints:
#   [0x83] per-disk STORAGE_DEVICE_ID_DESCRIPTOR diagnostics (identifier
#          count + offsets + raw head) for PhysicalDrive0..3;
#   [NSI]  capture tuples + the full 4KB dump hex of the last
#          enumerate-shaped response seen on \Device\Nsi, with the
#          neighbor-table query driven from CHILD processes (fresh nsi
#          handles -- the verify process caches its own from earlier
#          sections, which bypasses a late-attached filter).

import os
import struct
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from verify_core import (  # noqa: E402
    DEVICE_PATH,
    IOCTL_MYARK_CORE_GET_SESSION_KEY,
    IOCTL_MYARK_HWID_QUERY_SPOOF_CAPTURE,
    IOCTL_MYARK_HWID_SET_SPOOF_CONFIG,
    MYARK_HWID_OP_SPOOF_CONFIG,
    MYARK_HWID_CLASS_ARP,
    MYARK_HWID_ACTION_CAPTURE,
    SAFETY_TOKEN_KEY_SIZE,
    SAFETY_TOKEN_SIZE,
    _MYARK_FLAG_CAPTURE_START,
    _ctl_code,
    _ioctl,
    _ioctl_raw,
    _open_driver,
    nt_filetime_now,
    sign_token,
)

IOCTL_STORAGE_QUERY_PROPERTY = (0x2D << 16) | (0x500 << 2)
KERNEL32 = __import__("ctypes").windll.kernel32
GENERIC_READ = 0x80000000
FILE_SHARE_RW = 0x1 | 0x2
OPEN_EXISTING = 3


def _open_disk(disk):
    path = "\\\\.\\PhysicalDrive%d" % disk
    h = KERNEL32.CreateFileW(path, GENERIC_READ, FILE_SHARE_RW, None,
                             OPEN_EXISTING, 0, None)
    if h in (-1, 0xFFFFFFFFFFFFFFFF):
        return None
    return h


def dump_083_inventory():
    print("=" * 72)
    print("[0x83] STORAGE_DEVICE_ID_DESCRIPTOR inventory")
    for disk in range(4):
        h = _open_disk(disk)
        if h is None:
            print("  PhysicalDrive%d: open failed" % disk)
            continue
        try:
            ok, blob, err = _ioctl_raw(h, IOCTL_STORAGE_QUERY_PROPERTY,
                                       struct.pack("<III", 2, 0, 0), 4096)
            if not ok:
                print("  PhysicalDrive%d: query failed err=%d" % (disk, err))
                continue
            if len(blob) < 12:
                print("  PhysicalDrive%d: short response %d" % (disk, len(blob)))
                continue
            version, size, num = struct.unpack_from("<III", blob, 0)
            offs = [struct.unpack_from("<I", blob, 12 + 4 * i)[0]
                    for i in range(min(num, 8))] if len(blob) >= 12 + 4 * min(num, 8) else []
            print("  PhysicalDrive%d: version=%d size=%d identifiers=%d offs=%s"
                  % (disk, version, size, num, offs))
            for i, off in enumerate(offs):
                if off + 4 <= len(blob):
                    ln_be = (blob[off + 2] << 8) | blob[off + 3]
                    ln_le = (blob[off + 3] << 8) | blob[off + 2]
                    data = blob[off + 4:off + 4 + min(ln_be, 48)]
                    print("    ident[%d] off=%d lenBE=%d lenLE=%d codeset=%d type=%d data=%s"
                          % (i, off, ln_be, ln_le, blob[off], blob[off + 1],
                             data.hex()))
        finally:
            KERNEL32.CloseHandle(h)


def _hwid_in_buf(token, cls, action, flags, value, disk=0):
    buf = (token
           + struct.pack("<IIIII", cls, action, flags, disk, len(value))
           + b"\x00" * 4 + b"\x00" * 8 + value)
    return buf + b"\x00" * (232 - len(buf))


def read_capture(handle, token):
    payload = _ioctl(handle, IOCTL_MYARK_HWID_QUERY_SPOOF_CAPTURE,
                     _hwid_in_buf(token, 0, 0, 0, b""), 5288)
    magic, armed, tcount, dlen = struct.unpack_from("<IIII", payload, 0)
    seq = struct.unpack_from("<Q", payload, 16)[0]
    tuples = []
    reserved = []
    for i in range(8):
        base = 24 + i * 144
        code, in_len, out_len, res = struct.unpack_from("<IIII", payload, base)
        if code == 0 and in_len == 0 and out_len == 0:
            continue
        head = min(in_len, 128)  # Input[] is capped at 128 by the driver
        tuples.append((code, in_len, out_len,
                       payload[base + 16:base + 16 + head]))
        reserved.append(res)
    dnc, dif, dnb, dbg2 = struct.unpack_from("<IIII", payload, 5272)
    return {"armed": armed, "tcount": tcount, "seq": seq, "dlen": dlen,
            "tuples": tuples, "reserved": reserved,
            "diag": (dnc, dif, dnb, dbg2),
            "dump": payload[1176:1176 + dlen]}


IOCTL_MYARK_HWID_QUERY_SPOOF_STATUS = _ctl_code(0x22, 0x752, 0, 0)


def read_arp_status(handle):
    payload = _ioctl(handle, IOCTL_MYARK_HWID_QUERY_SPOOF_STATUS, b"", 208)
    count = struct.unpack_from("<I", payload, 0)[0]
    for i in range(count):
        base = 16 + i * 32
        c, flags, spoof_len, cache_len, rewritten, attached, queries, last = \
            struct.unpack_from("<8I", payload, base)
        if c == 5:
            return {"flags": flags, "attached": attached, "queries": queries,
                    "rewritten": rewritten, "last": last}
    return None


def nsi_capture_round(handle, session_key):
    print("=" * 72)
    print("[NSI] capture round: arm -> child-process traffic -> read 0x754")
    pid = os.getpid() & 0xFFFFFFFF
    token = sign_token(session_key, pid, MYARK_HWID_OP_SPOOF_CONFIG,
                       nt_filetime_now())
    ok, payload, err = _ioctl_raw(
        handle, IOCTL_MYARK_HWID_SET_SPOOF_CONFIG,
        _hwid_in_buf(token, MYARK_HWID_CLASS_ARP, MYARK_HWID_ACTION_CAPTURE,
                     _MYARK_FLAG_CAPTURE_START, b""), 288)
    if not ok:
        print("  [FAIL] CAPTURE START err=%d" % err)
        return
    print("  capture armed, status=#%08x" % struct.unpack_from("<I", payload, 0)[0])

    # Fresh-handle traffic from LONG-LIVED children: a child that exits
    # immediately races the completion (the SEH derefs then fail on a
    # dying address space). Sleep keeps the caller alive while the
    # capture reads its buffers.
    procs = []
    for i in range(1):
        try:
            child_src = (
                "import ctypes,time\n"
                "w=ctypes.windll.iphlpapi\n"
                "t=ctypes.c_void_p()\n"
                "rc=0\n"
                "for i in range(20):\n"
                "    if t.value:\n"
                "        w.FreeMibTable(t)\n"
                "        t=ctypes.c_void_p()\n"
                "    rc=w.GetIpNetTable2(2,ctypes.byref(t))\n"
                "    time.sleep(0.2)\n"
                "open('gtt_out.txt','w').write('%d' % rc)\n"
                "time.sleep(2)\n"
            )
            p = subprocess.Popen(["python", "-c", child_src],
                                 creationflags=0x08000000)
            procs.append(p)
            if i == 0:
                print("  child[0] pid=%d loop 20x GetIpNetTable2" % p.pid)
            time.sleep(0.6)
        except Exception as exc:  # noqa: BLE001
            print("  child spawn failed: %s" % exc)
    time.sleep(2.0)

    st = read_arp_status(handle)
    print("  0x752 ARP class: %s" % st)
    cap = read_capture(handle, token)
    print("  readback: armed=%d tuples=%d seq=%d dump=%d diag(ncaller,infail,notbig,big)=%s"
          % (cap["armed"], cap["tcount"], cap["seq"], cap["dlen"], cap["diag"],))
    for i, (code, in_len, out_len, head) in enumerate(cap["tuples"]):
        print("  tup[%d] code=#%08x in=%d out=%d reserved=#%x"
              % (i, code, in_len, out_len, cap["reserved"][i]))
        print("       params=%s" % head.hex())
    print("  --- dump %d bytes ---" % cap["dlen"])
    d = cap["dump"]
    for off in range(0, len(d), 32):
        print("  dump+%04x %s" % (off, d[off:off + 32].hex()))

    ok, payload, err = _ioctl_raw(
        handle, IOCTL_MYARK_HWID_SET_SPOOF_CONFIG,
        _hwid_in_buf(token, MYARK_HWID_CLASS_ARP, MYARK_HWID_ACTION_CAPTURE,
                     0, b""), 288)
    print("  capture stop ok=%s status=#%08x err=%d"
          % (ok, struct.unpack_from("<I", payload, 0)[0] if ok else 0, err))


def main():
    try:
        sys.stdout.reconfigure(errors="replace")
    except (AttributeError, OSError):
        pass
    handle = _open_driver()
    print("[CALIB] opened %s" % DEVICE_PATH)
    out_size = 40                          # Size4 + KeyLength4 + Key[32]
    ok, payload, err = _ioctl_raw(handle, IOCTL_MYARK_CORE_GET_SESSION_KEY,
                                  b"", out_size)
    if not ok or len(payload) < out_size:
        print("[CALIB] session key failed err=%d" % err)
        return 1
    session_key = payload[8:40]
    dump_083_inventory()
    nsi_capture_round(handle, session_key)
    return 0


if __name__ == "__main__":
    sys.exit(main())
