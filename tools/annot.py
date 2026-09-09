#!/usr/bin/env python3
"""Disassemble a VA range of Extensions.dll, annotating any immediate that
resolves to an ASCII string in the image.  Used to read the CA entry -> Lua
table builder, where each field name push sits next to the struct offset it
reads."""
import sys, re
sys.path.insert(0, '.')
import disx, capstone

def strat(va):
    o = disx.va2off(va)
    if o is None: return None
    e = disx.DATA.find(b'\x00', o, o + 96)
    if e < 0 or e == o: return None
    s = disx.DATA[o:e]
    if not re.fullmatch(rb'[\x20-\x7e]+', s): return None
    return s.decode()

lo = int(sys.argv[1], 0); hi = int(sys.argv[2], 0)
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
code = disx.DATA[disx.va2off(lo):disx.va2off(hi)]
for ins in md.disasm(code, lo):
    ann = ""
    for m in re.finditer(r'0x[0-9a-f]{6,8}', ins.op_str):
        s = strat(int(m.group(0), 16))
        if s: ann += "   ; %r" % s
    print("0x%08x  %-8s %s%s" % (ins.address, ins.mnemonic, ins.op_str, ann))
