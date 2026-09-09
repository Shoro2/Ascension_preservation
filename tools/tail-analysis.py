"""Offline: locate the client ephemeral public in the 645-byte challenge tail.
Uses only captured bytes - no process access.  If the tail is raw key material
(not keystream-covered) a local server can extract the client public and compute
K, unlocking a safe wire-only recovery of the M1/M2 formula."""
import os, math
D = os.path.dirname(os.path.abspath(__file__))

def load(n):
    with open(os.path.join(D, n), "rb") as f:
        return f.read()

def ent(b):
    if not b: return 0.0
    from collections import Counter
    c = Counter(b); n = len(b)
    return -sum((v/n)*math.log2(v/n) for v in c.values())

a = load("live-client-challenge.bin")      # 645
b = load("ascension-challenge.bin")        # 636
print("live-client-challenge.bin len", len(a))
print("ascension-challenge.bin    len", len(b))

print("\n-- per-32-byte Shannon entropy (bits/byte) of the 645 challenge --")
for i in range(0, len(a), 32):
    chunk = a[i:i+32]
    print("  off %3d..%3d  H=%.2f  %s" % (i, i+len(chunk)-1, ent(chunk),
          chunk.hex()))

print("\n-- tail of 645 challenge (last 112 bytes), 16/line --")
tail_start = len(a) - 112
for i in range(tail_start, len(a), 16):
    print("  %3d  %s" % (i, a[i:i+16].hex(" ")))

# align both challenges at their END and mark equal (constant) vs differing
print("\n-- END-aligned diff live(645) vs ascension(636): '.'=equal '#'=differ --")
m = min(len(a), len(b))
at = a[-m:]; bt = b[-m:]
line = "".join("." if at[i]==bt[i] else "#" for i in range(m))
# print with absolute offsets into the 645 blob (a is longer)
base = len(a) - m
for i in range(0, m, 64):
    print("  a@%3d  %s" % (base+i, line[i:i+64]))

# longest run of differing bytes near the tail (candidate ephemeral region)
runs=[]; s=None
for i in range(m):
    if at[i]!=bt[i]:
        if s is None: s=i
    else:
        if s is not None: runs.append((s,i)); s=None
if s is not None: runs.append((s,m))
runs=[(base+x, base+y, y-x) for (x,y) in runs]
runs.sort(key=lambda r:-r[2])
print("\n-- largest differing runs (abs offset in 645 blob) --")
for st,en,ln in runs[:6]:
    print("  off %3d..%3d  len %d" % (st, en-1, ln))
