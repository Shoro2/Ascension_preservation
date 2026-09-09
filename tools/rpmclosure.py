#!/usr/bin/env python3
"""Read a Lua 5.1 closure object out of the live client (READ-ONLY RPM).
usage: rpmclosure.py <pid> <addr-hex> [<addr-hex> ...]"""
import ctypes, sys
from ctypes import wintypes

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.OpenProcess.restype = wintypes.HANDLE
k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
k32.ReadProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPCVOID,
                                  wintypes.LPVOID, ctypes.c_size_t,
                                  ctypes.POINTER(ctypes.c_size_t)]
PROCESS_VM_READ, PROCESS_QUERY_INFORMATION = 0x0010, 0x0400

pid = int(sys.argv[1])
h = k32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
if not h:
    sys.exit("OpenProcess failed: %d" % ctypes.get_last_error())

def rd(addr, n):
    buf = (ctypes.c_char * n)()
    got = ctypes.c_size_t(0)
    if not k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, n, ctypes.byref(got)):
        return None
    return bytes(buf[:got.value])

for a in sys.argv[2:]:
    addr = int(a, 16)
    d = rd(addr, 0x20)
    if d is None:
        print("%08X: <unreadable>" % addr); continue
    tt, marked, isC, nup = d[4], d[5], d[6], d[7]
    env = int.from_bytes(d[0x0c:0x10], "little")
    fn  = int.from_bytes(d[0x10:0x14], "little")
    print("%08X: tt=%d marked=%02x isC=%d nupvalues=%d env=%08X  fn/proto=0x%08X"
          % (addr, tt, marked, isC, nup, env, fn))
    print("         raw: %s" % d[:0x18].hex())
