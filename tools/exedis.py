#!/usr/bin/env python3
"""Disassemble a VA range out of Ascension.exe (read-only). usage: exedis.py <va-hex> [nbytes]"""
import struct, sys, capstone
EXE = r"C:\AzerothRealm\client-ascension\Ascension.exe"
d = open(EXE, "rb").read()
pe = struct.unpack_from("<I", d, 0x3C)[0]
nsec = struct.unpack_from("<H", d, pe + 6)[0]
optsz = struct.unpack_from("<H", d, pe + 20)[0]
BASE = struct.unpack_from("<I", d, pe + 52)[0]
SECS = []
_o = pe + 24 + optsz
for i in range(nsec):
    s = d[_o + i * 40:_o + (i + 1) * 40]
    nm = s[:8].rstrip(b"\0").decode("latin1")
    vs, va, rs, rp = struct.unpack_from("<IIII", s, 8)
    SECS.append((nm, va, vs, rp, rs))

def va2off(va):
    r = va - BASE
    for nm, sva, vs, rp, rs in SECS:
        if sva <= r < sva + max(vs, rs):
            return rp + (r - sva)

def cstr(va):
    o = va2off(va)
    if o is None: return None
    e = d.find(b"\x00", o)
    if e < 0 or e - o > 120: return None
    s = d[o:e]
    return s.decode("latin1") if s and all(0x20 <= c <= 0x7e for c in s) else None

def dis(va, n=0x100):
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    o = va2off(va)
    for ins in md.disasm(d[o:o + n], va):
        note = ""
        for tok in ins.op_str.replace(",", " ").replace("[", " ").replace("]", " ").split():
            if tok.startswith("0x") and len(tok) >= 8:
                s = cstr(int(tok, 16))
                if s: note = '   ; "%s"' % s
        print("  0x%08x  %-9s %s%s" % (ins.address, ins.mnemonic, ins.op_str, note))

if __name__ == "__main__":
    dis(int(sys.argv[1], 16), int(sys.argv[2], 0) if len(sys.argv) > 2 else 0x100)
