"""
Ascension login server-proof (M2) reference implementation.

Recovered by STATIC reverse-engineering of client-ascension/Extensions.dll
(read-only; pefile+capstone). This REPLACES the SRP6/SHA1 hypothesis in
shim3799.py -- that direction is wrong. The real scheme is X25519 ECDH +
HMAC-SHA256, NOT SRP6/SHA1.

Evidence chain (all RVAs vs ImageBase 0x10000000):
  * Auth-session singleton object @ [0x10bdbc04], getter 0xe5cd0, ctor 0xe3840.
      obj layout: two CURVE25519 contexts @ +0x20 and +0xa0; 32-byte session
      key K @ +0x120 (zeroed in ctor at 0xe38bd..0xe38e1).
  * Crypto descriptor @ 0x10b7db40 = {keysize=0x20, name->"CURVE25519"@0xb7db90,
      algo=9, basepoint u=9 @ 0xb7db48}.  -> the primitive is X25519.
  * X25519 wrapper API in Extensions.dll:
      0xadaed0 ctx_init          0xadaf00 set_private_key (clamps scalar,
                                          computes pubkey, canonical X25519
                                          clamp: [0]&=0xf8; [31]&=0x7f; [31]|=0x40)
      0xadae80 import_public_key (peer pub -> ctx+0x10, from the WIRE, NOT pinned)
      0xadadb0 export_public_key 0xadca10 scalar-mult (Montgomery ladder)
      0xadafb0 dh_agree  ->  shared = X25519(our_priv@ctx+0x40, peer_pub@ctx+0x10)
      0xadad70 endianness helper: mode==1 => byte-REVERSE the 32-byte value,
                                  else plain 32-byte copy.
  * Server-proof VERIFY (native, the "prize") @ 0xe5dd0:
        key  = obj+0x120            (the 32-byte session key K)
        algo = 6                    (SHA-256; IV confirmed @ 0xadbfc0)
        msg  = the 2 ASCII bytes "OK" (0x4F 0x4B ; built as `mov word,0x4b4f`)
        tag  = HMAC-SHA256(K, "OK") (32 bytes)
        then a CONSTANT-TIME compare of tag[0:32] vs the received 32 bytes;
        mismatch -> caller drops the socket.
    hmac_init(algo=6) @ 0xadbad0->0xadbaf0, hmac_update @ 0xadbe90,
    hmac_final @ 0xadb860.

Wire mapping (44-byte 0x01 server response):
    [0]=01 [1]=00 [2:34]=M2 (32-byte HMAC-SHA256 tag) [34:44]=10-byte tail.
    (The old "M2=[2:22] 20B + 22B tail" split cut the 32-byte tag in half.)

SCOPE GATE: CLEAR. No embedded secret. K is the per-session X25519 ECDH shared
secret; the server uses its OWN freshly-generated keypair and the client's
wire-supplied public key -- ECDH symmetry makes the two K's equal. The client
imports the server public key from challenge[3:35] (0xadae80), it does not pin
a hardcoded server key, so a local server may substitute its own keypair.

RESIDUAL UNKNOWNS (the copy shared->K and the byte-order 'mode' bits live in the
VMProtect VM and are not statically readable). Hence derive_K() enumerates the
few plausible variants; the shim should try each until the client sends 0x10.
"""

import hmac
import hashlib
import os

# ---------------------------------------------------------------------------
# X25519 (RFC 7748) -- pure python so this file is self-contained.
# If pynacl/cryptography is available, prefer it (faster & constant-time);
# the raw-scalar path here matches Extensions.dll's 0xadca10 ladder.
# ---------------------------------------------------------------------------
_P = 2 ** 255 - 19
_A24 = 121665  # (486662-2)/4 ; ladder constant seen near 0xade4xx


def _decode_u(u: bytes) -> int:
    u = bytearray(u[:32])
    u[31] &= 0x7F  # mask top bit per RFC 7748
    return int.from_bytes(u, "little")


def _decode_scalar(k: bytes) -> int:
    k = bytearray(k[:32])
    k[0] &= 0xF8
    k[31] &= 0x7F
    k[31] |= 0x40  # exactly the clamp at 0xadaf44..0xadaf4e
    return int.from_bytes(k, "little")


def _cswap(swap, a, b):
    if swap:
        return b, a
    return a, b


def x25519(scalar32: bytes, upoint32: bytes) -> bytes:
    """32-byte scalar * u-coordinate -> 32-byte shared, little-endian (RFC 7748)."""
    k = _decode_scalar(scalar32)
    x1 = _decode_u(upoint32)
    x2, z2, x3, z3 = 1, 0, x1, 1
    swap = 0
    for t in range(254, -1, -1):
        kt = (k >> t) & 1
        swap ^= kt
        x2, x3 = _cswap(swap, x2, x3)
        z2, z3 = _cswap(swap, z2, z3)
        swap = kt
        A = (x2 + z2) % _P
        AA = (A * A) % _P
        B = (x2 - z2) % _P
        BB = (B * B) % _P
        E = (AA - BB) % _P
        C = (x3 + z3) % _P
        D = (x3 - z3) % _P
        DA = (D * A) % _P
        CB = (C * B) % _P
        x3 = pow((DA + CB) % _P, 2, _P)
        z3 = (x1 * pow((DA - CB) % _P, 2, _P)) % _P
        x2 = (AA * BB) % _P
        z2 = (E * ((AA + (_A24 * E) % _P) % _P)) % _P
    x2, x3 = _cswap(swap, x2, x3)
    z2, z3 = _cswap(swap, z2, z3)
    res = (x2 * pow(z2, _P - 2, _P)) % _P
    return res.to_bytes(32, "little")


def x25519_base(scalar32: bytes) -> bytes:
    """public key = X25519(scalar, 9)  -- basepoint u=9 (0xb7db48)."""
    return x25519(scalar32, b"\x09" + b"\x00" * 31)


def gen_server_keypair():
    """Server's own EPHEMERAL keypair. No secret required (scope-gate clear)."""
    priv = bytearray(os.urandom(32))
    priv[0] &= 0xF8
    priv[31] &= 0x7F
    priv[31] |= 0x40
    priv = bytes(priv)
    return priv, x25519_base(priv)


# ---------------------------------------------------------------------------
# K derivation + M2.  The exact byte-order 'mode' and any final copy live in
# the VM, so we expose the variant space.  Order below = most→least likely.
# ---------------------------------------------------------------------------
def derive_K(server_priv: bytes, client_pub: bytes,
             rev_pub=False, rev_out=False, kdf=None) -> bytes:
    """
    K = session key at obj+0x120.
      rev_pub : peer pubkey was stored byte-reversed by import_public_key
                (0xadae80 -> 0xadad70 mode==1) before the ladder.
      rev_out : dh_agree (0xadafb0 -> 0xadad70) byte-reversed the shared secret.
      kdf     : None -> K = shared directly (most likely; DH out is 32B == K).
                'sha256' -> K = SHA256(shared) fallback.
    """
    cp = client_pub[::-1] if rev_pub else client_pub
    shared = x25519(server_priv, cp)          # 0xadca10 ladder
    if rev_out:
        shared = shared[::-1]                  # 0xadad70 mode==1
    if kdf == "sha256":
        return hashlib.sha256(shared).digest()
    return shared


def compute_m2(K: bytes) -> bytes:
    """Server proof = HMAC-SHA256(K, "OK"), 32 bytes.  (verify site 0xe5dd0)."""
    return hmac.new(K, b"OK", hashlib.sha256).digest()


def m2_variants(server_priv: bytes, client_pub: bytes):
    """Yield (label, M2) for each plausible K derivation. Try in order."""
    combos = [
        ("shared",            dict(rev_pub=False, rev_out=False, kdf=None)),
        ("rev_out",           dict(rev_pub=False, rev_out=True,  kdf=None)),
        ("rev_pub",           dict(rev_pub=True,  rev_out=False, kdf=None)),
        ("rev_pub+rev_out",   dict(rev_pub=True,  rev_out=True,  kdf=None)),
        ("sha256(shared)",    dict(rev_pub=False, rev_out=False, kdf="sha256")),
        ("sha256(rev_out)",   dict(rev_pub=False, rev_out=True,  kdf="sha256")),
    ]
    for label, kw in combos:
        K = derive_K(server_priv, client_pub, **kw)
        yield label, K, compute_m2(K)


# ---------------------------------------------------------------------------
# Wire helpers.
# ---------------------------------------------------------------------------
CLIENT_PUB_OFF = 0x235   # hello[0x235:0x255] = client X25519 public key (32B, per-connection)


def client_pub_from_hello(hello: bytes) -> bytes:
    return hello[CLIENT_PUB_OFF:CLIENT_PUB_OFF + 32]


def build_challenge_B(server_pub: bytes, rev_pub_on_wire=False) -> bytes:
    """Put the server's X25519 public key where vanilla puts SRP 'B' (challenge[3:35])."""
    return server_pub[::-1] if rev_pub_on_wire else server_pub


def build_proof_response(M2_32: bytes, tail10: bytes = None) -> bytes:
    """44-byte 0x01 response: 01 00 | M2(32) | tail(10)."""
    if tail10 is None:
        # observed live tail bytes ([34:44]); adjust if your build differs
        tail10 = bytes.fromhex("00008000000000000100")
    assert len(M2_32) == 32 and len(tail10) == 10
    return b"\x01\x00" + M2_32 + tail10


if __name__ == "__main__":
    # self-consistency demo: two parties agree the same K, hence the same M2.
    c_priv, c_pub = gen_server_keypair()   # stand-in for the client
    s_priv, s_pub = gen_server_keypair()   # our local server
    K_server = x25519(s_priv, c_pub)
    K_client = x25519(c_priv, s_pub)
    assert K_server == K_client, "ECDH mismatch"
    print("ECDH K   :", K_server.hex())
    print("M2       :", compute_m2(K_server).hex())
    print("proof(44):", build_proof_response(compute_m2(K_server)).hex())
    print("\nvariants a server would try against a captured client_pub:")
    for label, K, M2 in m2_variants(s_priv, c_pub):
        print("  %-16s K=%s M2=%s" % (label, K.hex()[:16] + "..", M2.hex()[:16] + ".."))
