#!/usr/bin/env python3
"""Enumerate Ascension's custom opcode -> handler registrations in Extensions.dll.

The client registers each custom SMSG with
    push 0 / push <handler> / push <opcode> / call 0x102c4590
so a byte-pattern sweep of .text recovers the whole table.  Read-only.
"""
import struct, sys, importlib.util
spec = importlib.util.spec_from_file_location("disx", r"C:\AzerothRealm\realms\ascension\tools\disx.py")
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)

REG = int(sys.argv[1], 0) if len(sys.argv) > 1 else 0x102c4590
tlo, thi, rawptr, rawsz = m.text_range()
D = m.DATA
out = {}
i = rawptr
end = rawptr + rawsz
while i < end - 20:
    j = D.find(b"\x6a\x00\x68", i, end)
    if j < 0:
        break
    i = j + 1
    handler = struct.unpack_from("<I", D, j + 3)[0]
    if not (tlo <= handler < thi):
        continue
    if D[j + 7] != 0x68:
        continue
    opcode = struct.unpack_from("<I", D, j + 8)[0]
    if opcode > 0xFFFF:
        continue
    if D[j + 12] != 0xE8:
        continue
    rel = struct.unpack_from("<i", D, j + 13)[0]
    src = m.off2va(j + 12)
    if src + 5 + rel != REG:
        continue
    out[opcode] = (handler, src)
for op in sorted(out):
    h, src = out[op]
    print("0x%04x  %5d   handler 0x%08x   (site 0x%08x)" % (op, op, h, src))
print("total %d opcodes" % len(out))
