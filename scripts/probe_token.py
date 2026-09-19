"""One-shot KILL_PROCESS token probe for debugger work (guest-side)."""
import ctypes
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import verify_core as vc

handle = vc._open_driver()

# Full session key, hex-dumped for host-side comparison.
payload = vc._ioctl(handle, vc.IOCTL_MYARK_CORE_GET_SESSION_KEY, b"", 40)
key = payload[8:40]
print("session key:", key.hex())

token = vc.sign_token(key, 0, 1, vc.nt_filetime_now())
print("token      :", token.hex())
print("mac msg    :", vc._mac_message(0, 1, struct.unpack_from("<q", token, 16)[0]).hex())

out_size = vc.ACTION_OUTPUT_SIZE[0x870]
ok, resp, err = vc._ioctl_raw(handle, vc.function_code_ioctl(0x870),
                              token + vc._action_tail(0x870, 0), out_size)
print("result     :", "OK" if ok else f"DENIED err={err}")
vc._kernel32.CloseHandle(handle)
