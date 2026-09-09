#!/usr/bin/env python3
"""Locate a Lua C-binding inside Extensions.dll and disassemble it.

Ascension registers its C_* namespaces with the usual {name, lua_CFunction}
table, so a pointer to the ASCII name in .rdata sits right next to a pointer to
the implementation.  Find the string, find pointers to it, and the neighbouring
pointer that lands inside .text is the function.

    python findfn.py GetEntriesByClass [instructions]

Read-only: the DLL is opened for reading and never written.
"""
import struct
import sys

import capstone

DLL = r"C:\AzerothRealm\client-ascension\Extensions.dll"


def load():
    data = open(DLL, "rb").read()
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    assert data[pe:pe + 4] == b"PE\0\0", "not a PE"
    nsec = struct.unpack_from("<H", data, pe + 6)[0]
    optsz = struct.unpack_from("<H", data, pe + 20)[0]
    magic = struct.unpack_from("<H", data, pe + 24)[0]
    base = struct.unpack_from("<I", data, pe + 52)[0] if magic == 0x10B else \
        struct.unpack_from("<Q", data, pe + 48)[0]
    secs = []
    off = pe + 24 + optsz
    for i in range(nsec):
        s = data[off + i * 40: off + (i + 1) * 40]
        name = s[:8].rstrip(b"\0").decode("latin1")
        vsize, va, rawsz, rawptr = struct.unpack_from("<IIII", s, 8)
        secs.append((name, va, vsize, rawptr, rawsz))
    return data, base, secs


def va2off(secs, base, va):
    r = va - base
    for name, sva, vsize, rawptr, rawsz in secs:
        if sva <= r < sva + max(vsize, rawsz):
            return rawptr + (r - sva)
    return None


def off2va(secs, base, off):
    for name, sva, vsize, rawptr, rawsz in secs:
        if rawptr <= off < rawptr + rawsz:
            return base + sva + (off - rawptr)
    return None


def find_strings(data, needle):
    out, i = [], 0
    b = needle.encode() + b"\0"
    while True:
        i = data.find(b, i)
        if i < 0:
            break
        # must start a string (preceded by NUL or padding)
        if i == 0 or data[i - 1] in (0, 0xCC):
            out.append(i)
        i += 1
    return out


def main():
    name = sys.argv[1] if len(sys.argv) > 1 else "GetEntriesByClass"
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 160

    data, base, secs = load()
    print("image base 0x%08x" % base)
    for s in secs:
        print("  %-8s va=0x%08x vsz=0x%06x raw=0x%06x" % (s[0], base + s[1], s[2], s[3]))

    hits = find_strings(data, name)
    print("\nstring %r at file offsets: %s" % (name, [hex(h) for h in hits]))
    vas = [off2va(secs, base, h) for h in hits]
    print("  -> VAs: %s" % [hex(v) for v in vas if v])

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = False

    text = [s for s in secs if s[0] == ".text"][0]
    tlo, thi = base + text[1], base + text[1] + text[2]

    for sva in vas:
        if sva is None:
            continue
        pat = struct.pack("<I", sva)
        i = 0
        while True:
            i = data.find(pat, i)
            if i < 0:
                break
            ptr_va = off2va(secs, base, i)
            if ptr_va is None:
                i += 1
                continue
            # neighbouring dwords, the classic {name, fn} pair either order
            for delta in (4, -4, 8, -8):
                o = va2off(secs, base, ptr_va + delta)
                if o is None or o + 4 > len(data):
                    continue
                cand = struct.unpack_from("<I", data, o)[0]
                if tlo <= cand < thi:
                    print("\n=== ref at 0x%08x, neighbour%+d -> fn 0x%08x ===" % (ptr_va, delta, cand))
                    fo = va2off(secs, base, cand)
                    code = data[fo:fo + count * 8]
                    n = 0
                    for ins in md.disasm(code, cand):
                        print("  0x%08x  %-10s %s" % (ins.address, ins.mnemonic, ins.op_str))
                        n += 1
                        if n >= count or ins.mnemonic == "ret":
                            break
                    break
            i += 1


if __name__ == "__main__":
    main()
