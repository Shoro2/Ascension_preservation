"""Ascension local auth-compat SHIM  -- X25519 + HMAC-SHA256 model (round 5).

STATIC RE of client-ascension/Extensions.dll (read-only, pefile+capstone) overturned the
SRP6/SHA1 hypothesis. The real login proof, confirmed against disassembled bytes:

    * verify site 0xe5dd0:  M2 = HMAC-SHA256(K, "OK")   (algo id 6; msg = 2 bytes 'O','K';
      32-byte tag; constant-time compared to the received 32 bytes; mismatch -> socket drop)
    * K = per-session X25519 ECDH shared secret (curve descriptor "CURVE25519" @0xb7db40,
      canonical clamp @0xadaf00, ladder @0xadca10, dh_agree @0xadafb0). K lives at authobj+0x120.
    * client's X25519 public key is on the wire at hello[0x235:0x255]; the server's public key
      goes where vanilla puts SRP 'B' -> challenge[3:35]. ECDH symmetry => a LOCAL server can use
      its OWN freshly-generated keypair; no Ascension secret is needed (scope-gate CLEAR).

So this shim: frames the 645-ish B hello, reads the client pubkey, generates an X25519 keypair,
sends the pubkey in the challenge, tolerates the decoy 75-byte proof, then sends
    01 00 | HMAC-SHA256(K,"OK")(32) | tail(10)
and watches: client sends 0x10 (realm list) => M2 ACCEPTED; socket close => rejected.

The only bytes NOT statically readable (they live in the VMProtect VM) are the byte-ORDER of the
public keys on the wire and of the shared secret, and whether a KDF wraps it. That is a tiny
variant space; the shim auto-advances one variant per connection (one Login click each).

Usage:  python shim3799.py [account] [password]   (creds only used for the account-match log now)
Point the client realmList at 127.0.0.1:3799 and click Login once per variant. Ctrl-C to stop.
"""
import socket, os, sys, hashlib, hmac, secrets, select, time, threading

BASE = os.path.dirname(os.path.abspath(__file__))
PORT = 3799
sys.path.insert(0, BASE)
from ascension_x25519_m2 import x25519, x25519_base  # reviewed RFC-7748 impl (same dir)
import rpm_readk  # passive ReadProcessMemory of the client's session key K (obj+0x120)

ACCOUNT  = sys.argv[1] if len(sys.argv) > 1 else "test"
PASSWORD = sys.argv[2] if len(sys.argv) > 2 else "test"

# Tee stdout to a logfile so the result is readable even when this runs elevated in the
# user's own console (RPM of the elevated client requires equal integrity => user launches it).
LOGPATH = os.path.join(BASE, "shim_log.txt")
class _Tee:
    def __init__(self, *streams): self.streams = streams
    def write(self, s):
        for st in self.streams:
            try: st.write(s); st.flush()
            except Exception: pass
    def flush(self):
        for st in self.streams:
            try: st.flush()
            except Exception: pass
try:
    sys.stdout = _Tee(sys.__stdout__, open(LOGPATH, "a", buffering=1, encoding="utf-8"))
except Exception:
    pass

# cracked constant: account field @0x135 = name(ASCII, NUL-pad 20) XOR K
K_PAD = bytes.fromhex("28a668efc006e2b5ab81c32acb0842b237219774")

# canonical WoW SRP6 params kept ONLY to fill the (now-decoy) challenge fields the client's
# parser may still walk; the real auth ignores them.
g = 7
N = int("894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7", 16)
N_LE = N.to_bytes(32, "little")

def _load(name, default):
    p = os.path.join(BASE, name)
    return open(p, "rb").read() if os.path.exists(p) else default
_live_chal = _load("live-server-challenge-response.bin", b"")
VERSION_CHALLENGE = _live_chal[102:118] if len(_live_chal) >= 118 else bytes(16)
SALT = _live_chal[70:102] if len(_live_chal) >= 102 else \
       bytes.fromhex("9078563412896745239178563412896745239178563412896745239178563412")
_live_proof = _load("live-server-proof-response.bin", b"")
# real proof-response layout is 01 00 | M2(32) | tail(10); tail = post-M2 fields (acctFlags/survey/unk)
M2_TAIL = _live_proof[34:44] if len(_live_proof) >= 44 else bytes.fromhex("00008000000000000100")

CLIENT_PUB_OFF = (0x235, 0x255)   # hello -> client X25519 public key (32 B, per-connection)

# ---------- helpers ----------
def recv_until(sock, buf, need):
    while len(buf) < need:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            return False
        if not chunk:
            return False
        buf += chunk
    return True

def read_0x00(sock, buf):
    if not recv_until(sock, buf, 4):
        print("      !! got only %d/4 header bytes then stall/close -> client sent NO hello"
              "  raw=%s" % (len(buf), buf.hex()))
        return None
    size = buf[2] | (buf[3] << 8)
    total = 4 + min(size, 65536)
    print("      hdr=%s  cmd=0x%02x b1=0x%02x size=%d -> expect %d bytes total (have %d)"
          % (buf[:4].hex(), buf[0], buf[1], size, total, len(buf)))
    if not recv_until(sock, buf, total):
        print("      !! STALLED reading hello: have %d/%d bytes  first32=%s"
              % (len(buf), total, bytes(buf[:32]).hex()))
        return None
    msg = bytes(buf[:total]); del buf[:total]
    return msg

def decode_account(hello):
    raw = bytes(a ^ b for a, b in zip(hello[0x135:0x149], K_PAD))
    return raw.split(b"\x00", 1)[0].decode("latin1", "replace")

# ---------- wire builders ----------
def build_challenge(server_pub_wire):
    out = bytearray([0x00, 0x00, 0x00])          # cmd, error, result=success
    out += server_pub_wire                        # 32 B  -> vanilla 'B' slot = our X25519 pubkey
    out += bytes([1, g])                          # g_len, g   (decoy)
    out += bytes([32]) + N_LE                     # N_len, N   (decoy)
    out += SALT                                   # salt       (decoy)
    out += VERSION_CHALLENGE                       # 16
    out += bytes([0x00])                          # security flags
    return bytes(out)

def build_proof_response(M2_32):
    assert len(M2_32) == 32 and len(M2_TAIL) == 10
    return b"\x01\x00" + M2_32 + M2_TAIL          # 44 bytes

from archive_ports import REALM_ADDR    # our local world server; every realm dials here

def _rebuild_local_realmlist():
    """Replay the REAL captured Ascension realm list (live-realmlist-raw.bin) but point every
    realm at our local world. The captured 0x10 body is the standard 3.3.5a categorized format:
    42 records = 21 CONNECTABLE realms (name + 'ip:port') followed by 21 METADATA twins in
    category 27 whose *name* field is the '!'-delimited string
    'RealmName!expansion!gamemode!image!unlocked!page!index!descSpell' (page 1 = the visible
    playable realms). A hand-built single realm has no metadata twin, so the client files it to
    the hidden dev page and the main screen stays blank -- THIS is the fix. We keep the whole
    structure (so the categorized UI builds exactly as it did live), rewrite only the non-empty
    addresses to our local world, and clear the lock byte + offline flag so every realm is
    selectable. No Ascension data leaves the machine; this is the user's own capture, addresses
    localized. Falls back to a minimal 1-realm+metadata list if the capture is missing."""
    cap = os.path.join(BASE, "live-realmlist-raw.bin")
    try:
        raw = open(cap, "rb").read()
    except Exception:
        return _minimal_local_realmlist()
    body = raw[3:] if raw[:1] == b"\x10" else raw     # strip 10 | size(2) transport header
    try:
        p = 0
        unused = body[p:p+4]; p += 4
        n = int.from_bytes(body[p:p+2], "little"); p += 2
        out = bytearray(unused) + n.to_bytes(2, "little")
        for _ in range(n):
            icon = body[p]; lock = body[p+1]; flags = body[p+2]; p += 3
            z = body.index(b"\x00", p); name = body[p:z]; p = z + 1
            z = body.index(b"\x00", p); addr = body[p:z]; p = z + 1
            pop = body[p:p+4]; p += 4
            nchar = body[p]; cat = body[p+1]; rid = body[p+2]; p += 3
            build = b""
            if flags & 0x04:                          # SpecifyBuild -> 5 trailing version bytes
                build = body[p:p+5]; p += 5
            new_addr = (REALM_ADDR.encode() if addr else b"")   # only real (addressed) realms
            new_lock = 0                              # unlock everything for local play
            new_flags = flags & ~0x02                 # clear REALM_FLAG_OFFLINE -> show online
            out += bytes([icon, new_lock, new_flags]) + name + b"\x00" + new_addr + b"\x00"
            out += pop + bytes([nchar, cat, rid]) + build
        out += body[p:p+2] if len(body) - p >= 2 else b"\x10\x00"   # trailer (numRealms echo)
        return bytes([0x10]) + len(out).to_bytes(2, "little") + bytes(out)
    except Exception:
        return _minimal_local_realmlist()

# The realm's NAME is load-bearing, not decoration.  GlueXML/CharacterCreate.lua
# gates the whole archetype creation flow on it:
#     function C_CharacterCreate.CanCreateArchetype()
#         return GetRealmName() == "Area 52 - Free-Pick" and ...
# and GetRealmName() (Ascension.exe 0x00510e00) just reads the "realmName" CVar,
# "Last realm connected to", which the client writes from the realm LIST when it
# connects.  So the archive has to advertise the production realm's exact name
# here, or the client refuses to offer archetypes no matter what the world server
# says.  (This is also the name the live client would write, so nothing about the
# shared Config.wtf changes.)
#
# Both records below are the ones the live login server actually sent -- records
# 7 and 31 of live-realmlist-raw.bin -- with only the address redirected at our
# local world server:
#     rec  7  icon=1 lock=0 flags=0x00 pop=0.0 nchar=1 cat=1  rid=11  <- connectable
#     rec 31  icon=1 lock=0 flags=0x00 pop=0.0 nchar=1 cat=27 rid=62  <- metadata twin
# The category-27 twin carries no address; its name IS the payload, in the form
#     RealmName!expansion!gamemode!image!unlocked!page!index!descSpell
# which the custom realm-select UI parses to draw the realm's card.
ARCHIVE_REALM_NAME = "Area 52 - Free-Pick"
ARCHIVE_REALM_META = "Area 52 - Free-Pick!1!0!Area52!true!1!6!13977862"


def _minimal_local_realmlist():
    """Fallback: the real Free-Pick realm + its category-27 metadata twin."""
    real = bytes([1, 0, 0]) + (ARCHIVE_REALM_NAME + "\x00").encode() \
           + (REALM_ADDR + "\x00").encode() \
           + b"\x00\x00\x00\x00" + bytes([1, 1, 11])
    meta = bytes([1, 0, 0]) + (ARCHIVE_REALM_META + "\x00").encode() + b"\x00" \
           + b"\x00\x00\x00\x00" + bytes([1, 27, 62])
    payload = b"\x00\x00\x00\x00" + (2).to_bytes(2, "little") + real + meta + b"\x02\x00"
    return bytes([0x10]) + len(payload).to_bytes(2, "little") + payload

_REALMLIST_CACHE = None
def build_realmlist():
    global _REALMLIST_CACHE
    if _REALMLIST_CACHE is None:
        _REALMLIST_CACHE = _rebuild_local_realmlist()
        print("      realm list built: %d bytes (real 42-record capture, addrs -> %s)"
              % (len(_REALMLIST_CACHE), REALM_ADDR))
    return _REALMLIST_CACHE

# ---------- variant space ----------------------------------------------------
# The client's ephemeral pubkey in the hello is NOT raw X25519 (no 32-byte slice in the
# 60-byte per-connection window [0x235:0x271] has a consistent MSB<0x80) -> it's obfuscated
# like the account/password fields, so we can't feed it straight into ECDH. Instead LEAD with
# the CURVE25519 low-order-point interaction, which makes K a KNOWN CONSTANT without needing
# the client's pubkey at all:
#   send B (server pubkey) = a low-order u  =>  client computes shared = X25519(client_priv,u) = 0
#   (dh_agree @0xadafb0 has NO all-zero-output check; it only enforces peer_pub[31]<0x80, which
#    u=0 and u=1 both satisfy).  Then K is 0^32 (or a KDF of it) -> M2 is a fixed value.
# B = all-zeros is endian-invariant (reverse(0)=0), so it works regardless of the client's
# import byte-order. Fall back to real-ECDH variants (in case the pubkey IS raw after all).
ZERO32 = bytes(32)
def _sha(b): return hashlib.sha256(b).digest()

def gen_keypair():
    priv = bytearray(secrets.token_bytes(32))
    priv[0] &= 0xF8; priv[31] &= 0x7F; priv[31] |= 0x40
    priv = bytes(priv)
    return priv, x25519_base(priv)

def _ecdh_K(server_priv, client_pub_wire, wire_rev, shared_rev, kdf):
    client_pub = client_pub_wire[::-1] if wire_rev else client_pub_wire
    shared = x25519(server_priv, client_pub)
    if shared_rev:
        shared = shared[::-1]
    return _sha(shared) if kdf == "sha256" else shared

# each variant: fixed (spub,K) low-order pair, OR an 'ecdh' (wire_rev,shared_rev,kdf) tuple.
VARIANTS = [
    {"label": "lo_u0_Kzero",   "spub": ZERO32,              "K": ZERO32},
    {"label": "lo_u0_Ksha",    "spub": ZERO32,              "K": _sha(ZERO32)},
    {"label": "lo_u1le_Kzero", "spub": b"\x01" + bytes(31), "K": ZERO32},
    {"label": "lo_u1be_Kzero", "spub": bytes(31) + b"\x01", "K": ZERO32},
    {"label": "ecdh_std",      "ecdh": (False, False, None)},
    {"label": "ecdh_wirerev",  "ecdh": (True,  False, None)},
    {"label": "ecdh_sha",      "ecdh": (False, False, "sha256")},
    {"label": "ecdh_revsha",   "ecdh": (True,  False, "sha256")},
]
NUM_VARIANTS = len(VARIANTS)

# ---------- per-connection handler ----------
def handle(conn, cid):
    conn.settimeout(30)
    buf = bytearray()
    tag = "c%03d" % cid
    hello = read_0x00(conn, buf)
    if hello is None:
        print("%s: no complete hello; closed" % tag); return
    acct = decode_account(hello)
    match = "OK" if acct.lower() == ACCOUNT.lower() else "config='%s'" % ACCOUNT
    print("%s: hello %dB  account='%s'  (%s)" % (tag, len(hello), acct, match))

    cmd0 = hello[0]
    try:
        with open(os.path.join(BASE, "hello_%s_cmd%02x.bin" % (tag, cmd0)), "wb") as f:
            f.write(hello)
    except Exception:
        pass
    if cmd0 == 0x02:
        print("      NOTE: cmd=0x02 RECONNECT challenge (client already holds a session K). "
              "Saved %dB for analysis; the logon/M2 path below is best-effort for this type." % len(hello))

    client_pub_wire = hello[CLIENT_PUB_OFF[0]:CLIENT_PUB_OFF[1]]
    print("      client_pub(hello[0x235:0x255]) = %s" % client_pub_wire.hex())

    # RPM path: send a NORMAL ephemeral B so the client computes a real K, then read that
    # exact K out of the client's memory (obj+0x120) and answer with it. No KDF/depad needed.
    server_priv, server_pub = gen_keypair()
    conn.sendall(build_challenge(server_pub))
    print("      -> challenge sent  B(our ephemeral pub)=%s.." % server_pub.hex()[:16])

    pbuf = buf
    if not recv_until(conn, pbuf, 75):
        print("%s: client closed before proof (challenge/B rejected)" % tag); return
    proof = bytes(pbuf[:75]); del pbuf[:75]
    A_LE, M1c, crc = proof[1:33], proof[33:53], proof[53:73]
    amode = "zero" if set(A_LE) == {0} else ("04ph" if A_LE[:2] == b"\x04\x00" else "memtbl")
    print("      proof rx: A=%s M1=%s crc=%s" % (amode, M1c.hex()[:12] + "..", crc.hex()[:12] + ".."))

    # the client has now computed K (it needed B, sent above). Read it from memory.
    K = None; ksrc = ""
    rr = rpm_readk.read_k()
    if rr and rr[3] is not None:
        pid, base, objptr, K = rr
        ksrc = "RPM pid=%d base=0x%x obj=0x%x" % (pid, base, objptr)
        print("      RPM read K = %s   [%s]" % (K.hex(), ksrc))
    else:
        print("      !! RPM read FAILED (%s) -- falling back to variant guess" %
              ("no live obj/K" if rr else "access denied / not elevated?"))
        v = VARIANTS[(cid - 1) % NUM_VARIANTS]
        K = _ecdh_K(server_priv, client_pub_wire, *v["ecdh"]) if "ecdh" in v else v["K"]
        ksrc = "fallback:" + v["label"]
    M2 = hmac.new(K, b"OK", hashlib.sha256).digest()

    # is the client waiting for M2, or did it already bail?
    r, _, _ = select.select([conn], [], [], 1.5)
    if r:
        try:
            peek = conn.recv(1, socket.MSG_PEEK)
        except OSError:
            peek = b""
        if peek == b"":
            print("      !! client CLOSED before reading M2 => B rejected upstream  [%s]" % ksrc)
            return

    print("      K=%s  M2=%s  [%s]" % (K.hex()[:16] + "..", M2.hex(), ksrc))
    conn.sendall(build_proof_response(M2))
    print("      -> M2 sent (32B HMAC-SHA256(K,'OK'))  [%s]" % ksrc)
    label = ksrc

    try:
        nxt = conn.recv(64)
    except socket.timeout:
        nxt = b""
    if nxt and nxt[0] == 0x10:
        print("      ***** M2 ACCEPTED — client requested realm list (0x10)  [variant: %s] *****" % label)
        conn.sendall(build_realmlist())
        print("      -> realm list sent (%s)" % REALM_ADDR)
        # KEEP THE AUTH SOCKET OPEN. The client holds this connection while it sits on the
        # realm-select screen; if we close it, the client treats the session as lost, opens a
        # fresh reconnect (cmd 0x02), and when that fails shows "Session Expired". Stay here and
        # answer realm-list refreshes (0x10) on the SAME socket until the client leaves the screen.
        conn.settimeout(600)
        while True:
            try:
                more = conn.recv(64)
            except socket.timeout:
                print("      (idle on realm screen; still holding auth socket open)")
                continue
            except OSError:
                return
            if not more:
                print("      client closed auth socket (picked a realm / quit) — login phase complete.")
                return
            if more[0] == 0x10:
                conn.sendall(build_realmlist())
                print("      -> realm list re-sent (client 0x10 refresh)")
            else:
                print("      post-realm msg cmd=0x%02x len=%d (socket held open, ignored)"
                      % (more[0], len(more)))
    elif not nxt:
        print("      M2 rejected: client closed with no realm-list request  [%s]" % label)
    else:
        print("      unexpected post-M2 byte 0x%02x (len %d)  [%s]" % (nxt[0], len(nxt), label))

def _serve(conn, cid):
    try:
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError:
        pass
    try:
        handle(conn, cid)
    except Exception as e:
        print("c%03d: error %r" % (cid, e))
    finally:
        try: conn.close()
        except OSError: pass
    print()

def main():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", PORT)); srv.listen(4)
    print("=" * 72)
    print("Ascension shim (RPM mode) on 127.0.0.1:%d   log-> %s" % (PORT, LOGPATH))
    print("M2 = HMAC-SHA256(K,'OK');  K read live from client memory (obj+0x120).")
    print("account (for match log): '%s'" % ACCOUNT)
    # startup self-check: can we read the client's memory at this integrity level?
    pids = rpm_readk.find_pids()
    print("Ascension.exe PIDs seen: %s" % (pids or "NONE (client not running yet)"))
    if pids:
        rr = rpm_readk.read_k()
        if rr and rr[3] is not None:
            print("RPM SELF-CHECK OK: pid=%d base=0x%x obj=0x%x K=%s"
                  % (rr[0], rr[1], rr[2], rr[3].hex()))
        elif rr:
            print("RPM SELF-CHECK: reachable but no live auth-object yet (obj=0x%x) -- normal "
                  "before first Login; K appears once you click." % (rr[2],))
        else:
            print("RPM SELF-CHECK FAILED: access denied -> run this shim ELEVATED "
                  "(same integrity as the client). Will fall back to variant guesses otherwise.")
    print("Now: click Login. Watch for 'M2 ACCEPTED'.  Ctrl-C to stop.")
    print("=" * 72 + "\n")
    cid = 1
    try:
        while True:
            conn, addr = srv.accept()
            print("c%03d: accepted TCP from %s -- waiting for client's hello ..." % (cid, addr))
            # One thread per connection: the realm-select keep-alive holds a socket open for a
            # long time, so serving concurrently means a reconnect/refresh can't get stuck behind it.
            threading.Thread(target=_serve, args=(conn, cid), daemon=True).start()
            cid += 1
    except KeyboardInterrupt:
        print("\nstopped after %d connection(s)." % (cid - 1))

if __name__ == "__main__":
    main()
