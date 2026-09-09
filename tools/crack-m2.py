"""Offline known-answer attack on the Ascension M2 / session-key derivation.

We ruled out password-based a=0 SRP empirically (the shim's full identity x S-formula
sweep was rejected by the client). If K is instead PASSWORD-INDEPENDENT (derived from the
per-connection client nonces + our challenge), we don't need the client at all: the live
capture is a complete solved instance — hello (V1/V3 nonces), proof (A/M1/crc), challenge
(B/salt/vchal), and the server's ACCEPTED M2. Find the (K, M2-form) that reproduces M2_L.

Everything here is a public-protocol algorithm search over the user's own captured bytes;
no Ascension secret, no password needed (that's the point — if a match needs the password
we can't do it offline and must go back to the client).
"""
import os, hashlib, itertools

BASE = os.path.dirname(os.path.abspath(__file__))
WA = os.path.join(BASE, "wire-analysis")
def R(p): return open(os.path.join(WA, p), "rb").read()

chal  = R("live_SERVER_msg1_119.bin")
proof = R("live_CLIENT_msg2_75.bin")
m2r   = R("live_SERVER_msg2_44.bin")
hello = R("live_CLIENT_msg1_645.bin")

N = int("894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7", 16)
N_LE = N.to_bytes(32, "little")
K_PAD = bytes.fromhex("28a668efc006e2b5ab81c32acb0842b237219774")

def sha1(*p):
    h = hashlib.sha1()
    for x in p: h.update(x)
    return h.digest()
def md5(*p):
    h = hashlib.md5()
    for x in p: h.update(x)
    return h.digest()

# ---- live fields ----
B_L    = chal[3:35]
salt_L = chal[70:102]
vchal  = chal[102:118]
A_L    = proof[1:33]
M1_L   = proof[33:53]
crc_L  = proof[53:73]
M2_L   = m2r[2:22]
tail_m2 = m2r[22:44]
V1     = hello[0x08:0x18]        # 16
V3     = hello[0x235:0x271]      # 60
V3a    = hello[0x235:0x255]      # first 32 of V3
acctf  = hello[0x135:0x149]      # 20 (obfuscated)
acct   = bytes(a ^ b for a, b in zip(acctf, K_PAD)).split(b"\x00", 1)[0]
htail  = hello[0x275:]

print("account decoded from live hello: %r" % acct)
print("M2_L (target)  = %s" % M2_L.hex())
for nm, v in [("B_L",B_L),("salt_L",salt_L),("vchal",vchal),("A_L",A_L),("M1_L",M1_L),
              ("crc_L",crc_L),("V1",V1),("V3a",V3a)]:
    print("  %-6s %s" % (nm, v.hex()))
print()

def interleave(S):  # WoW SHA1Interleave on a 32-byte-ish value -> 40 bytes
    t = bytearray(S)
    while t and t[-1] == 0: t.pop()
    if len(t) % 2: t.pop()
    K = bytearray(40)
    K[0::2] = sha1(bytes(t[0::2]))
    K[1::2] = sha1(bytes(t[1::2]))
    return bytes(K)

def xor(a, b):
    n = min(len(a), len(b))
    return bytes(a[i] ^ b[i] for i in range(n))

def rev(b): return b[::-1]
def sha256_20(*p):
    h = hashlib.sha256()
    for x in p: h.update(x)
    return h.digest()[:20]
import hmac as _hmac
def hmac1(key, msg): return _hmac.new(key, msg, hashlib.sha1).digest()

# ---- named byte-strings available to the server (NO password) ----
fields = {
    "A": A_L, "M1": M1_L, "crc": crc_L, "B": B_L, "salt": salt_L, "vchal": vchal,
    "N": N_LE, "V1": V1, "V3": V3, "V3a": V3a, "acctf": acctf, "acct": acct,
    "acctU": acct.upper(), "g": bytes([7]),
    "V3b": hello[0x241:0x261], "V3c": hello[0x255:0x271], "htail": htail,
    "Br": rev(B_L), "Ar": rev(A_L), "V3ar": rev(V3a), "V1r": rev(V1),
    "saltr": rev(salt_L), "crcr": rev(crc_L),
}

# ---- build a big pool of K candidates (20B and 40B) ----
Ks = {}
def addK(name, val): Ks[name] = val

for nm, v in fields.items():
    addK("raw(%s)" % nm, v)                 # field used directly as K
    addK("sha1(%s)" % nm, sha1(v))
    addK("md5(%s)" % nm, md5(v))
    addK("sha256_20(%s)" % nm, sha256_20(v))
# interleave-based (SRP-style) K from 32-byte values and simple combos
for nm, v in [("B",B_L),("A",A_L),("V3a",V3a),("salt",salt_L),("N",N_LE),
              ("B^A",xor(B_L,A_L)),("B^V3a",xor(B_L,V3a)),("B^salt",xor(B_L,salt_L)),
              ("V3a^A",xor(V3a,A_L))]:
    addK("iv(%s)" % nm, interleave(v))
# pairwise hashes (order matters) over the most likely nonce/challenge pairs
pairsrc = {k: fields[k] for k in ("B","salt","vchal","A","M1","crc","V1","V3","V3a","acct","acctU","N")}
for (n1, v1), (n2, v2) in itertools.permutations(pairsrc.items(), 2):
    addK("sha1(%s|%s)" % (n1, n2), sha1(v1, v2))
# a few triples with B as the server-fresh element
for a, b, c in [("crc","B","salt"),("V1","B","salt"),("V3a","B","salt"),
                ("acct","crc","B"),("crc","vchal","B"),("V1","vchal","B")]:
    addK("sha1(%s|%s|%s)" % (a,b,c), sha1(fields[a],fields[b],fields[c]))

print("K candidates: %d" % len(Ks))

# ---- outer M2 forms to test against M2_L ----
def test_all():
    hits = []
    # A) M2 = SHA1(pre + K + post) for stock-ish outer forms
    outer = [
        ("K==M2",          lambda K: K),
        ("H(A|M1|K)",      lambda K: sha1(A_L, M1_L, K)),
        ("H(A|K)",         lambda K: sha1(A_L, K)),
        ("H(K)",           lambda K: sha1(K)),
        ("H(B|K)",         lambda K: sha1(B_L, K)),
        ("H(A|M1|K|salt)", lambda K: sha1(A_L, M1_L, K, salt_L)),
        ("H(K|A|M1)",      lambda K: sha1(K, A_L, M1_L)),
        ("H(A|B|K)",       lambda K: sha1(A_L, B_L, K)),
        ("H(salt|K)",      lambda K: sha1(salt_L, K)),
        ("H(acctU|K)",     lambda K: sha1(acct.upper(), K)),
        ("H(A|M1|K|vchal)",lambda K: sha1(A_L, M1_L, K, vchal)),
        ("H(K|vchal)",     lambda K: sha1(K, vchal)),
        ("H(vchal|K)",     lambda K: sha1(vchal, K)),
        ("H(crc|K)",       lambda K: sha1(crc_L, K)),
        ("H(K|crc)",       lambda K: sha1(K, crc_L)),
        ("H(B|A|M1|K)",    lambda K: sha1(B_L, A_L, M1_L, K)),
        ("H(A|M1|B|K)",    lambda K: sha1(A_L, M1_L, B_L, K)),
        ("H(acctU|K|salt)",lambda K: sha1(acct.upper(), K, salt_L)),
        ("HMAC(K,A|M1)",   lambda K: hmac1(K, A_L + M1_L)),
        ("HMAC(K,B)",      lambda K: hmac1(K, B_L)),
        ("HMAC(K,vchal)",  lambda K: hmac1(K, vchal)),
    ]
    for kn, K in Ks.items():
        for on, fn in outer:
            try:
                if fn(K) == M2_L:
                    hits.append("%s  with K=%s" % (on, kn))
            except Exception:
                pass
    # B) M2 = SHA1(X) directly, X a concat of 1-4 known fields in any order
    pool = {k: fields[k] for k in ("A","M1","crc","B","salt","vchal","V1","V3a","V3","acct","acctU","N","htail")}
    names = list(pool)
    for r in (1, 2, 3, 4):
        for combo in itertools.permutations(names, r):
            if sha1(*[pool[c] for c in combo]) == M2_L:
                hits.append("H(%s) direct" % "|".join(combo))
    return hits

hits = test_all()
print()
if hits:
    print("*** MATCH(es) FOUND ***")
    for hcand in hits: print("   ", hcand)
else:
    print("no match: M2_L is not any tested (password-free) K/outer form.")
    print("=> either M2/K depends on the password (needs client + known local pw),")
    print("   or the derivation is outside this candidate set (widen next).")
