"""Compare the ONE live (production) capture we already hold on disk against the E0
control set. No new captures, no network. Purpose:

  1. Is the 553-byte static hello skeleton the SAME between the live capture and the
     E0 harness captures? The hello is emitted by the client BEFORE any server reply,
     so any difference is client-state / credential driven, not server driven.
        - skeleton identical  -> skeleton is client-constant (NOT credential-derived)
        - skeleton differs     -> skeleton encodes something that changed (creds? build?)
     (Caveat: we do not know whether the username/password typed into the harness for
      E0 matched the live account; this measures, it does not conclude.)

  2. In the live proof, are the A(32) and M1(20) fields real SRP-looking values, or the
     same apparent-uninitialised-memory we see in E0? That decides whether "standard
     SRP6 with client-side padding" is even viable, or the real auth material lives
     entirely in the 20-byte crc_hash slot / hello skeleton.
"""
import os

BASE = os.path.dirname(os.path.abspath(__file__))
WA   = os.path.join(BASE, "wire-analysis")
CAP  = os.path.join(BASE, "e0-captures")

live_hello = open(os.path.join(WA, "hello_L_c1_645.bin"), "rb").read()
live_proof = open(os.path.join(WA, "live_CLIENT_msg2_75.bin"), "rb").read()
e0_hello   = open(os.path.join(CAP, "s001_c00_hello.bin"), "rb").read()
e0_proofs  = {s: open(os.path.join(CAP, "%s_c01_proof.bin" % s), "rb").read()
              for s in ("s001", "s004", "s005")}

def ranges(offsets):
    out = []
    for o in offsets:
        if out and o == out[-1][1] + 1:
            out[-1][1] = o
        else:
            out.append([o, o])
    return [(a, b) for a, b in out]

print("=" * 74)
print("LIVE (production, held on disk) vs E0 CONTROL")
print("=" * 74)
print("live hello len=%d   e0 hello len=%d" % (len(live_hello), len(e0_hello)))

# ---- 1. hello skeleton comparison ----
n = min(len(live_hello), len(e0_hello))
diff = [i for i in range(n) if live_hello[i] != e0_hello[i]]
KNOWN = [(0x008, 0x017, "V1"), (0x235, 0x270, "V3"), (0x275, 0x284, "tail")]
def classify(i):
    for a, b, name in KNOWN:
        if a <= i <= b:
            return name
    return "SKELETON"
by = {}
for i in diff:
    by.setdefault(classify(i), []).append(i)
print("\n[1] hello differences live-vs-e0: %d/%d bytes" % (len(diff), n))
for name in ("V1", "V3", "tail", "SKELETON"):
    offs = by.get(name, [])
    rs = ranges(offs)
    span = ", ".join("0x%03x..0x%03x" % (a, b) for a, b in rs)
    print("    %-9s %4d bytes  %s" % (name, len(offs), span if offs else "(identical)"))
print("    -> if SKELETON=0, the 553B skeleton is byte-identical between a production")
print("       login and the local harness login (client-constant, not server-driven).")

# ---- 2. live proof structure ----
def dump_proof(tag, p):
    A   = p[1:33]
    M1  = p[33:53]
    crc = p[53:73]
    nk  = p[73]
    sf  = p[74]
    print("  %-6s op=0x%02x" % (tag, p[0]))
    print("         A   [01:33] = %s" % A.hex())
    print("         M1  [33:53] = %s" % M1.hex())
    print("         crc [53:73] = %s" % crc.hex())
    print("         num_keys=%d  sec_flags=0x%02x" % (nk, sf))
    print("         A all-zero? %s   M1 all-zero? %s   crc all-zero? %s"
          % (set(A) == {0}, set(M1) == {0}, set(crc) == {0}))

print("\n[2] proof layout = standard 75B AUTH_LOGON_PROOF_C (cmd|A32|M1_20|crc20|nk|sf)")
print("\n  --- LIVE proof (the one that completed against production) ---")
dump_proof("LIVE", live_proof)
print("\n  --- E0 proofs (local harness, three memory 'modes') ---")
for s in ("s001", "s004", "s005"):
    dump_proof(s, e0_proofs[s])

# does live A/M1 match any e0 proof exactly?
print("\n[3] does the LIVE proof equal any E0 proof? (would prove proof is credential-")
print("    /session-independent constant)")
for s, p in e0_proofs.items():
    print("    live == %s ? %s" % (s, p == live_proof))
