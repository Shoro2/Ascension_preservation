"""Analyze the E0 control captures.

Question set (all vs a constant server challenge, identical credentials):
  A. Which hello offsets are GLOBALLY constant vs variable across all 8 sessions?
  B. Per-connection vs per-process: launch 1 = {s001,s002,s003} are three Login
     clicks in ONE client process; s004..s008 are six separate processes.
       - per-connection window = varies WITHIN launch 1
       - per-process window    = constant within launch 1 but differs across launches
  C. The 75B proof: confirm the launch-1 triplet is byte-identical, then locate
     exactly which proof bytes vary across the six processes.
  D. Correlation: does any variable hello window equal (or contain) the variable
     proof bytes? i.e. is the proof copying a hello window?
No crypto labels are assigned; this only measures where bytes move.
"""
import os, hashlib

BASE = os.path.dirname(os.path.abspath(__file__))
CAP  = os.path.join(BASE, "e0-captures")

# session -> launch grouping (per the user: 3 clicks on run 1, then 5 more runs)
LAUNCHES = [["s001", "s002", "s003"], ["s004"], ["s005"], ["s006"], ["s007"], ["s008"]]
ALL = [s for grp in LAUNCHES for s in grp]

def load(tag, kind):
    with open(os.path.join(CAP, "%s_%s.bin" % (tag, kind)), "rb") as f:
        return f.read()

hellos = {s: load(s, "c00_hello") for s in ALL}
proofs = {s: load(s, "c01_proof") for s in ALL}

def varmask(seqs):
    """Return list of offsets where the byte differs across the given sequences.
    Assumes equal length; if not, returns None and the length set."""
    lens = set(len(x) for x in seqs)
    if len(lens) != 1:
        return None, lens
    n = lens.pop()
    diff = [i for i in range(n) if len(set(x[i] for x in seqs)) > 1]
    return diff, {n}

def ranges(offsets):
    """Compress a sorted offset list into (start,end_inclusive) runs."""
    out = []
    for o in offsets:
        if out and o == out[-1][1] + 1:
            out[-1][1] = o
        else:
            out.append([o, o])
    return [(a, b) for a, b in out]

def show_runs(label, offsets, total):
    rs = ranges(offsets)
    span = ", ".join("0x%03x..0x%03x(%dB)" % (a, b, b - a + 1) for a, b in rs)
    print("  %-28s %d/%d bytes vary  ->  %s" % (label, len(offsets), total, span or "(none)"))
    return rs

print("=" * 78)
print("E0 CONTROL ANALYSIS  (8 sessions, identical credentials, constant challenge)")
print("=" * 78)

# ---- sanity: lengths + challenge constant ----
hlens = set(len(hellos[s]) for s in ALL)
plens = set(len(proofs[s]) for s in ALL)
chs = set(hashlib.sha256(load(s, "s00_challenge_sent")).hexdigest() for s in ALL)
print("\n[sanity] hello lengths=%s  proof lengths=%s  distinct challenges sent=%d"
      % (hlens, plens, len(chs)))
print("         (E0 held only if exactly 1 distinct challenge)")

# =====================================================================
print("\n--- A. GLOBAL hello variation across all 8 sessions ---")
gdiff, glen = varmask([hellos[s] for s in ALL])
if gdiff is None:
    print("  hello lengths differ:", glen)
else:
    total = glen.pop()
    gruns = show_runs("global-variable", gdiff, total)

# =====================================================================
print("\n--- B. per-CONNECTION vs per-PROCESS (launch 1 triplet) ---")
tri = ["s001", "s002", "s003"]
condiff, _ = varmask([hellos[s] for s in tri])
show_runs("per-connection (within run1)", condiff, len(hellos["s001"]))

# per-process: take ONE connection per launch (first of each), see what varies
firsts = [grp[0] for grp in LAUNCHES]   # s001,s004,s005,s006,s007,s008
procdiff, _ = varmask([hellos[s] for s in firsts])
show_runs("across-launch (1 conn each)", procdiff, len(hellos["s001"]))

# classify: process-only = varies across launches but NOT within run1
conset, procset = set(condiff), set(procdiff)
process_only = sorted(procset - conset)
conn_level   = sorted(conset)
show_runs("  -> per-connection windows", conn_level, len(hellos["s001"]))
show_runs("  -> per-process-only windows", process_only, len(hellos["s001"]))

# stable-everywhere within run1 AND across launches? (should equal skeleton)
# =====================================================================
print("\n--- C. proof (0x01, 75B) variation ---")
print("  launch-1 triplet identical? ",
      len(set(proofs[s] for s in tri)) == 1,
      " (sha %s)" % hashlib.sha256(proofs["s001"]).hexdigest()[:16])
pdiff_all, _ = varmask([proofs[s] for s in ALL])
show_runs("proof variable (all 8)", pdiff_all, 75)
pdiff_proc, _ = varmask([proofs[s] for s in firsts])
show_runs("proof variable (per-launch)", pdiff_proc, 75)

# =====================================================================
print("\n--- D. does the proof copy a hello window? ---")
# Extract the variable proof bytes per session and every variable hello window,
# check for equality/containment.
if pdiff_proc:
    pr = ranges(pdiff_proc)
    pa, pb = pr[0][0], pr[-1][1]
    print("  proof variable span: 0x%02x..0x%02x (%dB)" % (pa, pb, pb - pa + 1))
    for s in firsts:
        pv = proofs[s][pa:pb + 1]
        found = []
        h = hellos[s]
        # search the whole hello for this exact byte run
        idx = h.find(pv)
        while idx != -1:
            found.append("0x%03x" % idx)
            idx = h.find(pv, idx + 1)
        print("    %s proof[%02x:%02x]=%s  in-hello@ %s"
              % (s, pa, pb + 1, pv.hex(), ",".join(found) or "NOT FOUND"))
else:
    print("  proof has no per-launch variation (identical across all launches).")

# =====================================================================
print("\n--- E. per-session fingerprint of each variable window ---")
def w(s, a, ln):
    return hellos[s][a:a + ln].hex()
windows = [("V1", 0x08, 16), ("V2", 0x135, 16), ("V3", 0x235, 60)]
hdr = "  %-6s " % "sess" + " ".join("%-*s" % (max(len(n) + 1, ln * 2 + 1), n) for n, _, ln in windows)
print(hdr)
for s in ALL:
    cells = " ".join("%-*s" % (max(len(n) + 1, ln * 2 + 1), w(s, a, ln)) for n, a, ln in windows)
    print("  %-6s %s" % (s, cells))
print("\n  tail (0x275..end) per session:")
for s in ALL:
    print("    %s len=%d  %s" % (s, len(hellos[s]) - 0x275, hellos[s][0x275:].hex()))
