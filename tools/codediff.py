# -*- coding: utf-8 -*-
"""Read-only: diff Ascension.exe's live .text against the file on disk and
decode every hot-patch, so the whole hook population is visible at once.

Built for the ERROR #132 signature-B hunt.  0x00403340 is patched by
Extensions.dll to `E9 <rel32>` (jmp to extensions.dll+0x276680, with the two
orphaned bytes filled 0xCC).  Around world entry something rewrites the first
THREE bytes only, to `6A 01 E8`, giving

    00403340  6A 01                push 1
    00403342  E8 <old jmp disp+2>  call 0xCD0CA1xx   -> unmapped, ERROR #132

i.e. a `push imm8; call rel32` form whose displacement was never written: it
reuses bytes +3..+6, which still hold the *previous* patch's rel32 high half
plus its 0xCC filler.  An `E9` puts its rel32 at +1, an `E8` at +3, so a second
engine that assumed its own encoding was already in place lands two bytes off.

This tool answers the question that follows: is 0x00403340 the only site like
that, or is there a whole family of `push imm8; call rel32` hooks of which this
one alone is malformed?

Nothing here writes.  OpenProcess asks for VM_READ|QUERY_INFORMATION only and
there is no WriteProcessMemory import (handoff s8).

  python tools\codediff.py <pid> [--quiet]
"""
import ctypes
import ctypes.wintypes as w
import sys

import pefile

EXE = r"C:\AzerothRealm\client-ascension\Ascension.exe"
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400

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


def modules(pid):
    out = {}
    snap = k32.CreateToolhelp32Snapshot(0x08 | 0x10, pid)
    if snap == -1:
        return out
    me = MODULEENTRY32()
    me.dwSize = ctypes.sizeof(me)
    ok = k32.Module32First(snap, ctypes.byref(me))
    while ok:
        out[me.szModule.decode("mbcs", "replace").lower()] = (
            ctypes.cast(me.modBaseAddr, ctypes.c_void_p).value or 0, me.modBaseSize)
        ok = k32.Module32Next(snap, ctypes.byref(me))
    k32.CloseHandle(snap)
    return out


def attribute(mods, addr):
    for name, (base, size) in mods.items():
        if base <= addr < base + size:
            return "%s+%X" % (name, addr - base)
    return "UNMAPPED"


def read(h, addr, n):
    buf = (ctypes.c_char * n)()
    got = ctypes.c_size_t(0)
    if not k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, n,
                                 ctypes.byref(got)):
        return b""
    return bytes(buf[:got.value])


def decode(va, live, mods):
    """Classify a patch by its first bytes."""
    if live[0] == 0xE9 or live[0] == 0xE8:
        rel = int.from_bytes(live[1:5], "little", signed=True)
        tgt = (va + 5 + rel) & 0xFFFFFFFF
        kind = "jmp " if live[0] == 0xE9 else "call"
        return "%s %08X (%s)" % (kind, tgt, attribute(mods, tgt))
    if live[0] == 0x6A and live[2] == 0xE8:
        rel = int.from_bytes(live[3:7], "little", signed=True)
        tgt = (va + 7 + rel) & 0xFFFFFFFF
        who = attribute(mods, tgt)
        bad = "   <<<< TARGET UNMAPPED -- MALFORMED" if who == "UNMAPPED" else ""
        return "push %d; call %08X (%s)%s" % (live[1], tgt, who, bad)
    if live[0] == 0x68 and live[5] == 0xE8:
        rel = int.from_bytes(live[6:10], "little", signed=True)
        tgt = (va + 10 + rel) & 0xFFFFFFFF
        return "push %08X; call %08X (%s)" % (
            int.from_bytes(live[1:5], "little"), tgt, attribute(mods, tgt))
    if live[0] == 0xFF and live[1] == 0x25:
        p = int.from_bytes(live[2:6], "little")
        return "jmp [%08X]" % p
    if live[0] == 0xC3:
        return "ret (function neutered)"
    return "?"


def main():
    pid = int(sys.argv[1])
    quiet = "--quiet" in sys.argv
    h = k32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not h:
        print("OpenProcess failed: %d" % ctypes.get_last_error())
        return 1
    mods = modules(pid)
    pe = pefile.PE(EXE, fast_load=True)
    ib = pe.OPTIONAL_HEADER.ImageBase
    text = [s for s in pe.sections if s.Name.rstrip(b"\x00") == b".text"][0]
    lo = ib + text.VirtualAddress
    size = min(text.Misc_VirtualSize, text.SizeOfRawData)
    disk = pe.__data__[text.PointerToRawData:text.PointerToRawData + size]

    print("pid %d  .text %08X..%08X (%d bytes)" % (pid, lo, lo + size, size))
    live = bytearray()
    CH = 0x10000
    for off in range(0, size, CH):
        d = read(h, lo + off, min(CH, size - off))
        if len(d) != min(CH, size - off):
            print("  short read at %08X (%d bytes) - stopping" % (lo + off, len(d)))
            size = off + len(d)
            live += d
            break
        live += d
    live = bytes(live[:size])
    disk = disk[:size]

    runs = []
    i = 0
    while i < size:
        if live[i] != disk[i]:
            j = i
            gap = 0
            while j < size and gap < 8:
                if live[j] == disk[j]:
                    gap += 1
                else:
                    gap = 0
                j += 1
            runs.append((i, j - gap))
            i = j
        else:
            i += 1

    print("%d differing run(s)" % len(runs))
    malformed = []
    for a, b in runs:
        va = lo + a
        n = min(16, size - a)
        d = decode(va, live[a:a + n], mods)
        line = "  %08X  %-3d B  live=%s  disk=%s  %s" % (
            va, b - a, live[a:a + 8].hex(" "), disk[a:a + 8].hex(" "), d)
        if "MALFORMED" in d:
            malformed.append(line)
        if not quiet or "MALFORMED" in d:
            print(line)
    if malformed:
        print("\n*** %d MALFORMED PATCH(ES) ***" % len(malformed))
        for line in malformed:
            print(line)
    else:
        print("\nno malformed patches right now")
    return 0


if __name__ == "__main__":
    sys.exit(main())
