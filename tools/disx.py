#!/usr/bin/env python3
"""Disassemble Extensions.dll at a virtual address, or find references to one.

    python dis.py 0x10152920 [count]      disassemble
    python dis.py --xref 0x10172xxx       find code that references a VA/global
    python dis.py --store 0x10abc123 0x24 find writes of [<global>] + offset

Image base is whatever the PE says (0x10000000).  Read-only.
"""
import struct
import sys

import capstone

DLL = r"C:\AzerothRealm\client-ascension\Extensions.dll"


def load():
    data = open(DLL, "rb").read()
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    nsec = struct.unpack_from("<H", data, pe + 6)[0]
    optsz = struct.unpack_from("<H", data, pe + 20)[0]
    base = struct.unpack_from("<I", data, pe + 52)[0]
    secs = []
    off = pe + 24 + optsz
    for i in range(nsec):
        s = data[off + i * 40: off + (i + 1) * 40]
        name = s[:8].rstrip(b"\0").decode("latin1")
        vsize, va, rawsz, rawptr = struct.unpack_from("<IIII", s, 8)
        secs.append((name, va, vsize, rawptr, rawsz))
    return data, base, secs


DATA, BASE, SECS = load()


def va2off(va):
    r = va - BASE
    for name, sva, vsize, rawptr, rawsz in SECS:
        if sva <= r < sva + max(vsize, rawsz):
            o = rawptr + (r - sva)
            if o < len(DATA):
                return o
    return None


def off2va(off):
    for name, sva, vsize, rawptr, rawsz in SECS:
        if rawptr <= off < rawptr + rawsz:
            return BASE + sva + (off - rawptr)
    return None


MD = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
MD.detail = False


def dis(va, count=60, stop_at_ret=True):
    o = va2off(va)
    if o is None:
        print("  <va 0x%08x not mapped>" % va)
        return
    code = DATA[o:o + count * 10]
    n = 0
    for ins in MD.disasm(code, va):
        print("  0x%08x  %-24s %-8s %s" % (
            ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str))
        n += 1
        if n >= count:
            break
        if stop_at_ret and ins.mnemonic.startswith("ret"):
            break


def text_range():
    t = [s for s in SECS if s[0] == ".text"][0]
    return BASE + t[1], BASE + t[1] + t[2], t[3], t[4]


def xrefs(va):
    """every dword in .text equal to va, plus every call/jmp reaching it."""
    tlo, thi, rawptr, rawsz = text_range()
    pat = struct.pack("<I", va)
    out = []
    i = rawptr
    end = rawptr + rawsz
    while True:
        i = DATA.find(pat, i, end)
        if i < 0:
            break
        out.append(("imm/ptr", off2va(i)))
        i += 1
    # relative calls: E8 rel32 / E9 rel32
    for opc in (0xE8, 0xE9):
        i = rawptr
        while i < end - 5:
            j = DATA.find(bytes([opc]), i, end)
            if j < 0:
                break
            rel = struct.unpack_from("<i", DATA, j + 1)[0]
            src = off2va(j)
            if src is not None and src + 5 + rel == va:
                out.append(("call" if opc == 0xE8 else "jmp", src))
            i = j + 1
    return out


def main():
    a = sys.argv[1:]
    if not a:
        print(__doc__)
        return
    if a[0] == "--xref":
        va = int(a[1], 0)
        for kind, src in xrefs(va):
            print("%-8s from 0x%08x" % (kind, src))
        return
    if a[0] == "--secs":
        print("base 0x%08x" % BASE)
        for name, sva, vsize, rawptr, rawsz in SECS:
            print("  %-8s va=0x%08x vsz=0x%06x raw=0x%06x rsz=0x%06x"
                  % (name, BASE + sva, vsize, rawptr, rawsz))
        return
    va = int(a[0], 0)
    count = int(a[1]) if len(a) > 1 else 60
    dis(va, count)


if __name__ == "__main__":
    main()
