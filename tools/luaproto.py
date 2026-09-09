#!/usr/bin/env python3
"""Read a Lua 5.1 Proto (WoW build: 8-byte object prefix) out of the live client.
usage: luaproto.py <pid> <proto-addr-hex>"""
import ctypes, sys
from ctypes import wintypes
k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.OpenProcess.restype = wintypes.HANDLE
k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
k32.ReadProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPCVOID, wintypes.LPVOID,
                                  ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
PID = int(sys.argv[1])
h = k32.OpenProcess(0x0010 | 0x0400, False, PID)
if not h: sys.exit("OpenProcess failed %d" % ctypes.get_last_error())

def rd(a, n):
    b = (ctypes.c_char*n)(); g = ctypes.c_size_t(0)
    if not k32.ReadProcessMemory(h, ctypes.c_void_p(a), b, n, ctypes.byref(g)): return None
    return bytes(b[:g.value])

def tstring(a):
    """WoW Lua TString: +08 tt, +0C hash, +10 len, +14 chars"""
    d = rd(a, 0x18)
    if not d: return None
    tt = d[8]
    if tt != 4: return None
    ln = int.from_bytes(d[0x10:0x14], "little")
    if not (0 < ln < 4096): return None
    s = rd(a + 0x14, ln)
    if s is None: return None
    try: return s.decode("latin1")
    except Exception: return None

proto = int(sys.argv[2], 16)
d = rd(proto, 0x60)
if not d: sys.exit("proto unreadable")
print("Proto @%08X" % proto)
for i in range(0, 0x60, 4):
    v = int.from_bytes(d[i:i+4], "little")
    s = tstring(v) if v > 0x10000 else None
    note = ("   STR %r" % s) if s else ""
    print("   +%02X: %08X%s" % (i, v, note))
