# Decode the flat neighbor table served by NsiAllocateAndGetTable.
# Runs in the guest; prints the raw GetIpNetTable bytes plus the parsed
# IP->MAC pairs so the entry stride / offsets can be pinned offline.

import ctypes
import struct
import socket

iphlpapi = ctypes.windll.iphlpapi
size = ctypes.c_uint32(0)
rc = iphlpapi.GetIpNetTable(None, ctypes.byref(size), 0)
if rc != 122:
    print("sizing rc=%d" % rc)
    raise SystemExit(1)
buf = ctypes.create_string_buffer(size.value)
rc = iphlpapi.GetIpNetTable(buf, ctypes.byref(size), 0)
print("rc=%d total=%d" % (rc, size.value))
raw = buf.raw[:size.value]
num = struct.unpack_from("<I", raw, 0)[0]
print("dwNumEntries=%d" % num)

# MIB_IPNETROW (classic, 32-bit-flavored but used by GetIpNetTable on x64):
#   DWORD dwIndex; DWORD dwPhysAddrLen; BYTE bPhysAddr[MAX_PHYSADDR_LEN=8];
#   DWORD dwAddr; DWORD dwType  -> 24 bytes
for i in range(num):
    base = 4 + i * 24
    if base + 24 <= len(raw):
        idx, maclen = struct.unpack_from("<II", raw, base)
        mac = raw[base + 8:base + 16]
        ip, typ = struct.unpack_from("<II", raw, base + 16)
        print("row[%d] idx=%d maclen=%d mac=%s ip=%s type=%d"
              % (i, idx, maclen, mac[:maclen].hex(),
                 socket.inet_ntoa(struct.pack("<I", ip)), typ))

print("--- raw %d bytes ---" % len(raw))
for off in range(0, len(raw), 32):
    print("raw+%04x %s" % (off, raw[off:off + 32].hex()))
