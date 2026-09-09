"""E1/E2 analysis: locate the credential fields in the hello.

Capture order the user followed (harness auto-numbered):
  s009 = (E0 username, NEW password #1)   E1
  s010 = (E0 username, NEW password #2)   E1
  s011 = (NEW username #1, E0 password)   E2
  s012 = (NEW username #2, E0 password)   E2
Baseline = E0 set s001..s008 (E0 username, E0 password), all 645B.

E0 proved: the 553B skeleton has ZERO per-launch variation; only V1(0x08,16),
V3(0x235,60), tail(0x275,16) are per-connection noise. So ANY skeleton byte that
moves under a changed credential is credential-derived. Length now varies, so we
must also find WHERE the length change sits (a field before it shifts everything
after it out of fixed-offset alignment).
"""
import os

BASE = os.path.dirname(os.path.abspath(__file__))
CAP  = os.path.join(BASE, "e0-captures")

def load(tag, kind):
    return open(os.path.join(CAP, "%s_%s.bin" % (tag, kind)), "rb").read()

E0   = ["s001", "s002", "s003", "s004", "s005", "s006", "s007", "s008"]
NEW  = ["s009", "s010", "s011", "s012"]
LBL  = {"s009": "E1 pw#1", "s010": "E1 pw#2", "s011": "E2 user#1", "s012": "E2 user#2"}
hello = {s: load(s, "c00_hello") for s in E0 + NEW}
proof = {s: load(s, "c01_proof") for s in E0 + NEW}
base  = hello["s008"]                 # a 645B baseline instance

# Per-connection windows in the 645B frame (to ignore as noise)
NOISE = [(0x08, 16), (0x235, 60), (0x275, 16)]
def in_noise(i):
    return any(a <= i < a + n for a, n in NOISE)

# skeleton bytes that are constant across ALL E0 (offset -> byte), excluding noise
skel = {}
for i in range(645):
    if in_noise(i):
        continue
    vals = set(hello[s][i] for s in E0)
    if len(vals) == 1:
        skel[i] = vals.pop()
print("E0 skeleton: %d fixed non-noise offsets (of %d)" % (len(skel), 645 - sum(n for _, n in NOISE)))

MID = (0x18, 0x235)   # S1 + 0x135-block + S2 : the big static middle
def lcp(a, b):
    n = 0
    while n < len(a) and n < len(b) and a[n] == b[n]:
        n += 1
    return n
def lcs(a, b):
    n = 0
    while n < len(a) and n < len(b) and a[-1 - n] == b[-1 - n]:
        n += 1
    return n

print("\n" + "=" * 74)
for s in NEW:
    h = hello[s]
    bs = h[2] | (h[3] << 8)
    print("--- %s [%s]  len=%d  body=%d  (baseline len=645 body=641) ---"
          % (s, LBL[s], len(h), bs))
    # (a) is the big static middle block unchanged & unshifted?
    mid_same = h[MID[0]:MID[1]] == base[MID[0]:MID[1]] if len(h) >= MID[1] else False
    print("    middle block [0x18:0x235] == baseline? %s  -> change is %s"
          % (mid_same, "AFTER 0x235 (V3/tail region)" if mid_same else "AT/BEFORE 0x235"))
    # (b) common prefix / suffix vs baseline to bracket the edited span
    p = lcp(h, base); sfx = lcs(h, base)
    print("    common prefix=%d (0x%03x)  common suffix=%d  -> edited span 0x%03x..end-%d"
          % (p, p, sfx, p, sfx))
    # (c) if same length as baseline, list non-noise offsets that differ
    if len(h) == 645:
        diff = [i for i in range(645) if not in_noise(i) and h[i] != base[i]]
        rng = []
        for i in diff:
            if rng and i == rng[-1][1] + 1:
                rng[-1][1] = i
            else:
                rng.append([i, i])
        span = ", ".join("0x%03x..0x%03x(%dB)" % (a, b, b - a + 1) for a, b in rng)
        print("    non-noise skeleton diffs vs baseline: %s" % (span or "(NONE)"))

print("\n" + "=" * 74)
print("PAIRWISE (isolate one credential):")
def pair(x, y, what):
    a, b = hello[x], hello[y]
    print("  %s vs %s  (%s)  lens %d/%d" % (x, y, what, len(a), len(b)))
    print("    common prefix=0x%03x  common suffix=%d" % (lcp(a, b), lcs(a, b)))
pair("s009", "s010", "both E0-user, different passwords -> password field")
pair("s011", "s012", "both E0-pass, different usernames -> username field")
pair("s011", "s008", "E2 user#1 vs E0 baseline (same pass) -> username field")
pair("s009", "s008", "E1 pw#1 vs E0 baseline (same user) -> password field")

print("\n" + "=" * 74)
print("TAIL region bytes (from 0x235 to end) for baseline + new sessions:")
for s in ["s008"] + NEW:
    h = hello[s]
    print("  %-6s len=%d  [0x235:]=%s" % (s, len(h), h[0x235:].hex()))

print("\n" + "=" * 74)
print("PROOF crc_hash[53:73] + A-mode per new session:")
for s in ["s008"] + NEW:
    p = proof[s]
    A = p[1:33]
    amode = "zero" if set(A) == {0} else ("04-placeholder" if A[0] == 4 and A[1] == 0 else "memtable")
    print("  %-6s crc=%s  A=%s" % (s, p[53:73].hex(), amode))
