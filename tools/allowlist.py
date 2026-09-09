# -*- coding: utf-8 -*-
"""Read-only: is our world endpoint on the client's allow-list?

This is the trigger for ERROR #132 signature B (TROUBLESHOOTING.md entry 3, SOLVED).
Extensions.dll+0xA3C950 does, in effect:

    s = the cstring at Ascension.exe 0x00C79C9E      # "127.0.0.1:<world port>"
    it = find(allowlist.begin(), allowlist.end(), s)
    sete [ebp-0x41], (it == end)                     # guard = NOT FOUND
    if guard:
        GetProcAddress(GetModuleHandleA("kernel32.dll"), "ExitProcess")   # discarded
        VirtualProtect(0x00403340, 3, PAGE_EXECUTE_READWRITE, &old)
        *(WORD*)0x00403340 = 0x016A       # push 1
        *(BYTE*)0x00403342 = 0xE8         # call
        # *(DWORD*)0x00403343 = ExitProcess - 0x00403347   <-- NEVER WRITTEN
        VirtualProtect(0x00403340, 3, old, NULL)

The kill-switch was meant to be `push 1; call ExitProcess` -- a silent exit -- but the
displacement is never stored.  0x00403340 is already inline-hooked by Extensions.dll
(`E9 <rel32> CC CC`), so the bytes left at +3 become the call's displacement and the
next per-frame tick calls 0x00403347 + 0xCCCC6xxx, which is unmapped: ERROR #132 at a
fixed EIP of 0xCD0CA1xx a few seconds after the world draws.

The allow-list is PLAINTEXT in Extensions.dll's .rdata, so the authoritative check needs
no running client at all -- that is the STATIC half below, and it is the one the verdict
uses.  Only three loopback endpoints are on it: 127.0.0.1:8085, :8087 and :8088.

  python tools\\allowlist.py [pid]        # pid optional; static check runs regardless

Correction, 2026-09-01: this tool used to XOR the 0x00C79C9E blob with key[i]=0x78*(i+1)
and print the result as `decoded`.  The blob is NOT obfuscated -- it is written there by
Ascension.exe+0x6B3156 with the format string "%d.%d.%d.%d:%u" at 0x009E8AC8 -- so that
line was always garbage.  It is gone.  Read the ASCII.
"""
import ctypes
import ctypes.wintypes as w
import re
import subprocess
import sys

PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400

DLL = r"C:\AzerothRealm\client-ascension\Extensions.dll"
BLOB = 0x00C79C9E          # the endpoint cstring in Ascension.exe's BSS
LIST_BEGIN_RVA = 0xD3D708  # Extensions.dll RVA of the vector<std::string>'s begin
LIST_END_RVA = 0xD3D70C
STRIDE = 0x18              # sizeof(MSVC std::string) in this build

ENDPOINT = re.compile(rb"(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}")

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.OpenProcess.restype = w.HANDLE
k32.ReadProcessMemory.argtypes = [w.HANDLE, w.LPCVOID, w.LPVOID,
                                  ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]


class MODULEENTRY32(ctypes.Structure):
    _fields_ = [("dwSize", w.DWORD), ("th32ModuleID", w.DWORD),
                ("th32ProcessID", w.DWORD), ("GlblcntUsage", w.DWORD),
                ("ProccntUsage", w.DWORD),
                ("modBaseAddr", ctypes.POINTER(ctypes.c_byte)),
                ("modBaseSize", w.DWORD), ("hModule", w.HMODULE),
                ("szModule", ctypes.c_char * 256),
                ("szExePath", ctypes.c_char * 260)]


def static_list():
    """Every host:port literal in Extensions.dll.  No client needed."""
    with open(DLL, "rb") as f:
        data = f.read()
    return [(m.start(), m.group().decode()) for m in ENDPOINT.finditer(data)]


def find_pid():
    out = subprocess.run(
        ["powershell.exe", "-NoProfile", "-Command",
         "Get-Process Ascension -ErrorAction SilentlyContinue | "
         "Select-Object -First 1 -ExpandProperty Id"],
        capture_output=True, text=True).stdout.strip()
    return int(out) if out else 0


def module_base(pid, name):
    snap = k32.CreateToolhelp32Snapshot(0x08 | 0x10, pid)
    if snap == -1:
        return 0, 0
    me = MODULEENTRY32()
    me.dwSize = ctypes.sizeof(me)
    ok = k32.Module32First(snap, ctypes.byref(me))
    while ok:
        if me.szModule.decode("mbcs", "replace").lower() == name:
            k32.CloseHandle(snap)
            return (ctypes.cast(me.modBaseAddr, ctypes.c_void_p).value or 0,
                    me.modBaseSize)
        ok = k32.Module32Next(snap, ctypes.byref(me))
    k32.CloseHandle(snap)
    return 0, 0


def read(h, addr, n):
    buf = (ctypes.c_char * n)()
    got = ctypes.c_size_t(0)
    if not k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, n,
                                 ctypes.byref(got)):
        return b""
    return bytes(buf[:got.value])


def dw(h, addr):
    d = read(h, addr, 4)
    return int.from_bytes(d, "little") if len(d) == 4 else None


def read_cstr(h, addr, cap=64):
    d = read(h, addr, cap)
    z = d.find(b"\x00")
    return d[:z if z >= 0 else cap]


def read_stdstring(h, addr):
    """MSVC std::string: 16-byte SSO union, size at +0x10, capacity at +0x14."""
    blk = read(h, addr, STRIDE)
    if len(blk) != STRIDE:
        return None
    size = int.from_bytes(blk[0x10:0x14], "little")
    cap = int.from_bytes(blk[0x14:0x18], "little")
    if size > 0x200:
        return None
    if cap > 15:
        return read(h, int.from_bytes(blk[0:4], "little"), size)
    return blk[:min(size, 16)]


def main():
    entries = static_list()
    loopback = [(o, s) for o, s in entries if s.startswith("127.0.0.1:")]
    print("=== the allow-list, read statically from Extensions.dll ===")
    print("  %d host:port literal(s); the loopback ones are the only usable ones:" %
          len(entries))
    for off, s in loopback:
        print("    file 0x%06X  %s" % (off, s))
    legal = set(s for _, s in entries)

    pid = int(sys.argv[1]) if len(sys.argv) > 1 else find_pid()
    if not pid:
        print("\n(no Ascension.exe running -- static half only)")
        print("\nWhatever archive_ports.py sets WORLD_PORT to, "
              "127.0.0.1:<that> must appear above.")
        return 0

    h = k32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not h:
        print("\nOpenProcess failed: %d" % ctypes.get_last_error())
        return 1
    base, size = module_base(pid, "extensions.dll")
    print("\n=== live: pid %d, Extensions.dll base=%08X size=%X ===" %
          (pid, base or 0, size or 0))

    raw = read_cstr(h, BLOB)
    txt = raw.decode("ascii", "replace")
    print("\n=== the endpoint the client is checking (BSS 0x%08X) ===" % BLOB)
    print("  hex   : %s" % (raw.hex(" ") if raw else "(empty -- not connected yet)"))
    print("  ascii : %r" % txt)

    # The runtime vector is informational: its entries are not stored the same way as
    # the .rdata literals, and the static list above is what the verdict uses.
    if base:
        b0, b1 = dw(h, base + LIST_BEGIN_RVA), dw(h, base + LIST_END_RVA)
        if b0 and b1 and b1 > b0:
            print("\n=== runtime vector at Extensions.dll+%X (informational) ===" %
                  LIST_BEGIN_RVA)
            print("  begin=%08X end=%08X  %d entr(y/ies)" %
                  (b0, b1, (b1 - b0) // STRIDE))

    if not raw:
        print("\nVERDICT: no endpoint written yet -- run this after the world handshake.")
        return 0
    if txt in legal:
        print("\nVERDICT: %s IS on the list -- the kill-switch stays disarmed." % txt)
    else:
        print("\nVERDICT: %s is NOT on the list -> Extensions.dll will write the broken "
              "kill-switch at 0x00403340 -> ERROR #132 at 0xCD0CA1xx within seconds.\n"
              "         Set WORLD_PORT in archive_ports.py to 8085, 8087 or 8088." % txt)
    return 0


if __name__ == "__main__":
    sys.exit(main())
