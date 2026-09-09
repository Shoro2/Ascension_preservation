import os
BASE = os.path.dirname(os.path.abspath(__file__)); CAP = os.path.join(BASE, "e0-captures")
def H(t): return open(os.path.join(CAP, "%s_c00_hello.bin" % t), "rb").read()
def asc(b): return "".join(chr(x) if 32 <= x < 127 else "." for x in b)

# confirm 0x271 constant across E0
e0 = ["s001","s002","s003","s004","s005","s006","s007","s008"]
print("byte 0x271 across E0:", sorted(set("%02x" % H(s)[0x271] for s in e0)))

print("\n--- USERNAME field candidate 0x135..0x148 (20B) ---")
for s, lbl in [("s008","E0 user"),("s011","user#1"),("s012","user#2")]:
    f = H(s)[0x135:0x149]
    print("  %-8s %s  |%s|" % (lbl, f.hex(), asc(f)))

print("\n--- wider view 0x130..0x150 (context around it) ---")
for s, lbl in [("s008","E0 user"),("s011","user#1"),("s012","user#2")]:
    f = H(s)[0x130:0x150]
    print("  %-8s %s  |%s|" % (lbl, f.hex(), asc(f)))

print("\n--- PASSWORD region: 0x271 byte + tail 0x275.. ---")
for s, lbl in [("s008","E0 pass"),("s009","pass#1"),("s010","pass#2"),("s011","E0pass/u1"),("s012","E0pass/u2")]:
    h = H(s); bpw = h[0x271]; tail = h[0x275:]
    print("  %-9s 0x271=%02x  tail(%2dB)=%s  |%s|" % (lbl, bpw, len(tail), tail.hex(), asc(tail)))

print("\n--- full crc + is A/M1 04-placeholder or memtable? per new session ---")
for s in ["s008","s009","s010","s011","s012"]:
    p = open(os.path.join(CAP, "%s_c01_proof.bin" % s), "rb").read()
    A=p[1:33]; amode = "zero" if set(A)=={0} else ("04ph" if A[:2]==b"\x04\x00" else "memtbl")
    print("  %-6s A=%s crc=%s" % (s, amode, p[53:73].hex()))
