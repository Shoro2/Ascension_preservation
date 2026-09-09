"""Crack the account (0x135) and password (tail) transforms using known plaintext.

Known plaintext (throwaway strings the user typed):
  s009 password = "REDACTED_PW_A"        (7)   -> tail 7B
  s010 password = "REDACTED_PW_B"/"REDACTED_PW_B" (10) -> tail 10B
  s011 username = "testusername1"  (13)
  s012 username = "anothername"    (11)
  s008/E0 username+password = unknown (baseline)

We have deterministic account fields (constant across a process's connections) and
per-connection password tails. Test simple reversible models; report what fits.
"""
import os, hashlib
BASE = os.path.dirname(os.path.abspath(__file__)); CAP = os.path.join(BASE, "e0-captures")
def H(t): return open(os.path.join(CAP, "%s_c00_hello.bin" % t), "rb").read()
def xb(a, b): return bytes(x ^ y for x, y in zip(a, b))
def hx(b): return b.hex()

ACC = 0x135
def acct(t): return H(t)[ACC:ACC+20]
def tail(t): return H(t)[0x275:]
def v1(t): return H(t)[0x08:0x18]
def v3(t): return H(t)[0x235:0x271]

users = {"s011": "testusername1", "s012": "anothername", "s008": "<account-email-redacted>"}
pws   = {"s009": "REDACTED_PW_A", "s010": "REDACTED_PW_B"}

print("="*70); print("ACCOUNT FIELD @0x135 (20B), deterministic per username")
for s, u in users.items():
    print("  %s '%s'(%d)  field=%s" % (s, u, len(u), hx(acct(s))))

def try_models(name, field):
    up = name.upper().encode(); lo = name.encode()
    res = {}
    for label, pt in (("lower", lo), ("UPPER", up)):
        pt20 = pt + bytes(20 - len(pt)) if len(pt) < 20 else pt[:20]
        # model 1: pure XOR stream  ks = field XOR pt
        res[("xorstream", label)] = xb(field, pt20)
        # model 2: additive stream  ks = field - pt (mod256)
        res[("addstream", label)] = bytes((field[i]-pt20[i]) & 0xff for i in range(20))
        # model 3: xor-CBC  ks[i] = field[i]^pt[i]^field[i-1] (field[-1]=0)
        cbc = bytes(field[i]^pt20[i]^(field[i-1] if i else 0) for i in range(20))
        res[("xorcbc", label)] = cbc
    return res

derived = {s: try_models(u, acct(s)) for s, u in users.items()}
print("\n  Does a derived keystream MATCH across ALL usernames? (=> that model is the transform)")
for key in next(iter(derived.values())):
    kss = {s: derived[s][key] for s in users}
    # agreement per byte position across all three
    n = 20
    agree = sum(1 for i in range(n) if len(set(kss[s][i] for s in users)) == 1)
    full = len(set(bytes(kss[s]) for s in users)) == 1
    print("    %-22s %s  (%d/20 positions agree across all 3)"
          % (str(key), "<== FULL MATCH" if full else "", agree))
    for s in users:
        print("        %-5s %s" % (s, hx(kss[s])))

print("\n" + "="*70); print("PASSWORD TAIL, per-connection.  ks = tail XOR password")
for s in ("s009", "s010"):
    for label, pw in ((s, pws[s]), (s+"_UP", pws[s].upper()), (s+"_Cap", pws[s].capitalize())):
        p = pw.encode() if isinstance(pw, str) else pw
        if len(p) != len(tail(s)):
            continue
        ks = xb(tail(s), p)
        print("  %-10s pw=%-12s ks=%s" % (label, pw, hx(ks)))
    # where could this keystream come from? compare vs V1, V3 head, hashes of challenge
    ks = xb(tail(s), pws[s].encode())
    n = len(ks)
    chal = open(os.path.join(BASE, "live-server-challenge-response.bin"), "rb").read()
    cands = {
        "V1[:n]": v1(s)[:n], "V1[-n:]": v1(s)[-n:],
        "V3[:n]": v3(s)[:n], "V3[-n:]": v3(s)[-n:],
        "sha1(V1)[:n]": hashlib.sha1(v1(s)).digest()[:n],
        "sha1(V3)[:n]": hashlib.sha1(v3(s)).digest()[:n],
        "sha1(chal)[:n]": hashlib.sha1(chal).digest()[:n],
        "md5(V1)[:n]": hashlib.md5(v1(s)).digest()[:n],
    }
    print("    keystream(%s) = %s   sources:" % (s, hx(ks)))
    for cn, cv in cands.items():
        mark = " <==MATCH" if cv == ks else ""
        print("       %-16s %s%s" % (cn, hx(cv), mark))

print("\n" + "="*70); print("Do the two passwords' keystreams relate? (per-connection vs per-process)")
print("  s009 ks head:", hx(xb(tail("s009"), b"REDACTED_PW_A")))
print("  s010 ks head:", hx(xb(tail("s010"), b"REDACTED_PW_B")[:7]))
