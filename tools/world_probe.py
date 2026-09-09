"""World-handshake PROBE for the Ascension client (Phase 3, step 1).

Goal: learn how the client authenticates the WORLD connection (127.0.0.1:8085) so we can
later stand up a real world server it accepts. It is the minimum active step: speak first
with a valid SMSG_AUTH_CHALLENGE, capture the client's CMSG_AUTH_SESSION, then confirm --
by a known-plaintext search -- whether the client's world digest is the STOCK 3.3.5a formula
keyed on the per-session key K we already read via ReadProcessMemory.

Nothing is patched. We only:
  * send one server->client packet (the standard challenge), and
  * read the client's own session key out of its memory (same passive RPM the shim uses).

--- Exact layout, taken from the user's AzerothCore tree (WorldSocket.cpp) ---
SMSG_AUTH_CHALLENGE (server->client, first packet, UNENCRYPTED):
    wire = size(uint16 BE = 2+40) | opcode(uint16 LE = 0x01EC) | body
    body = uint32(1) | authSeed(4 bytes) | 32 random bytes                 (= 40 bytes)

CMSG_AUTH_SESSION (client->server, first packet, header UNENCRYPTED):
    wire = size(uint16 BE) | opcode(uint32 LE = 0x01ED) | body ; body = size-4
    body = Build(u32) LoginServerID(u32) Account(cstr) LoginServerType(u32)
           LocalChallenge(4) RegionID(u32) BattlegroupID(u32) RealmID(u32)
           DosResponse(u64) Digest(20) AddonInfo(zlib rest)

Digest = SHA1( Account            (chars, no NUL)
             | 00 00 00 00
             | LocalChallenge      (4 bytes, = clientSeed)
             | authSeed            (4 bytes, = our serverSeed)
             | SessionKey )        (stock AC = 40 bytes; OUR RPM K = 32 -> that's the question)

The probe fixes authSeed to a constant so the result is reproducible, reads a generous block
around the client auth object (obj+0x120 = K), and slides 32- and 40-byte windows (forward and
reversed) through it, trying account as-sent / upper / lower and both seed orders, to find the
exact bytes + length the client used as its world SessionKey. A hit tells us precisely what to
feed AzerothCore's account.SessionKey (and whether stock 40-byte expectation needs adjusting).

Run ELEVATED (RPM of the elevated client needs equal integrity), after stopping
world8085_capture.py so 8085 is free.  Usage:  python world_probe.py
"""
import socket, os, sys, time, hashlib, ctypes, struct

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)
import rpm_readk as R                    # passive RPM plumbing (OpenProcess VM_READ + RPM only)

LOG = os.path.join(BASE, "world_probe_log.txt")
SMSG_AUTH_CHALLENGE = 0x01EC
CMSG_AUTH_SESSION   = 0x01ED

# Fixed, logged server seed so every run is reproducible and the digest math is checkable.
SERVER_SEED = bytes.fromhex("11223344")            # authSeed (4 bytes)
CHALLENGE_TAIL = bytes(32)                          # 32 "encryption seed" bytes (unused by digest)

def log(msg):
    line = "[%s] %s" % (time.strftime("%H:%M:%S"), msg)
    print(line, flush=True)
    try:
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass

# ---- SMSG_AUTH_CHALLENGE ----------------------------------------------------
def build_challenge():
    body = struct.pack("<I", 1) + SERVER_SEED + CHALLENGE_TAIL          # 4 + 4 + 32 = 40
    size = 2 + len(body)                                                # opcode(2) + body
    return struct.pack(">H", size) + struct.pack("<H", SMSG_AUTH_CHALLENGE) + body

# ---- CMSG_AUTH_SESSION parse ------------------------------------------------
def recv_cmsg(conn, timeout=12.0):
    conn.settimeout(timeout)
    buf = b""
    t0 = time.time()
    while time.time() - t0 < timeout:
        # need 6-byte header first: size(2 BE) + opcode(4 LE)
        if len(buf) >= 6:
            size = struct.unpack(">H", buf[:2])[0]
            total = 2 + size                       # 2 size bytes + (opcode+body)
            if len(buf) >= total:
                return buf[:total], buf[total:]
        try:
            b = conn.recv(8192)
        except socket.timeout:
            break
        except OSError:
            break
        if not b:
            break
        buf += b
    return (buf, b"") if buf else (None, b"")

def parse_cmsg(pkt):
    size = struct.unpack(">H", pkt[:2])[0]
    opcode = struct.unpack("<I", pkt[2:6])[0]
    body = pkt[6:2 + size]
    f = {"size": size, "opcode": opcode, "body_len": len(body)}
    p = 0
    def u32():
        nonlocal p; v = struct.unpack_from("<I", body, p)[0]; p += 4; return v
    def u64():
        nonlocal p; v = struct.unpack_from("<Q", body, p)[0]; p += 8; return v
    f["build"] = u32()
    f["loginServerID"] = u32()
    z = body.index(b"\x00", p); f["account"] = body[p:z]; p = z + 1
    f["loginServerType"] = u32()
    f["localChallenge"] = body[p:p + 4]; p += 4       # clientSeed (raw 4 bytes)
    f["regionID"] = u32()
    f["battlegroupID"] = u32()
    f["realmID"] = u32()
    f["dosResponse"] = u64()
    f["digest"] = body[p:p + 20]; p += 20
    f["addon_len"] = len(body) - p
    return f

# ---- read a generous block of the client's auth object (K lives at obj+0x120) ----
def read_keyblock(span_before=0x40, span_len=0x100):
    r = R.read_k()                                    # (pid, base, objptr, K) for the live client
    if not r:
        return None
    pid, base, objptr, K = r
    if not objptr:
        return {"pid": pid, "base": base, "objptr": 0, "K": None, "block_off": 0, "block": b""}
    h = R._open(pid)
    if not h:
        return {"pid": pid, "base": base, "objptr": objptr, "K": K, "block_off": 0, "block": b""}
    try:
        start = objptr + R.K_OFFSET_IN_OBJ - span_before
        block = R._read(h, start, span_len) or b""
    finally:
        ctypes.windll.kernel32.CloseHandle(h)
    return {"pid": pid, "base": base, "objptr": objptr, "K": K,
            "block_off": R.K_OFFSET_IN_OBJ - span_before, "block": block}

# ---- known-plaintext search for the world SessionKey ------------------------
def sha1(*parts):
    h = hashlib.sha1()
    for p in parts:
        h.update(p)
    return h.digest()

def find_key(f, kb):
    digest = f["digest"]
    cseed = f["localChallenge"]
    sseed = SERVER_SEED
    acct = f["account"]
    acct_variants = [("as-sent", acct), ("upper", acct.upper()), ("lower", acct.lower())]
    seed_orders = [("client,server", cseed, sseed), ("server,client", sseed, cseed)]
    zeros = b"\x00\x00\x00\x00"
    block = kb["block"]
    results = []
    if block:
        for klen in (40, 32):
            for off in range(0, len(block) - klen + 1):
                win = block[off:off + klen]
                for wname, w in (("fwd", win), ("rev", win[::-1])):
                    for aname, a in acct_variants:
                        for sname, s1, s2 in seed_orders:
                            if sha1(a, zeros, s1, s2, w) == digest:
                                abs_off = kb["objptr"] + kb["block_off"] + off
                                results.append({
                                    "keylen": klen, "abs_off": "0x%x" % abs_off,
                                    "rel_to_K": (kb["block_off"] + off) - R.K_OFFSET_IN_OBJ,
                                    "dir": wname, "account": aname, "seed_order": sname,
                                    "key": w.hex()})
    return results

# ---- main -------------------------------------------------------------------
def main():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(("127.0.0.1", 8085))
    except OSError as e:
        log("BIND FAILED on 8085: %r  (stop world8085_capture.py first)" % e)
        return
    srv.listen(8)
    log("=" * 66)
    log("world PROBE listening on 127.0.0.1:8085   serverSeed=%s   log-> %s"
        % (SERVER_SEED.hex(), LOG))
    log("Now click 'Select Realm' on any realm in the client.")
    cid = 0
    while True:
        conn, addr = srv.accept()
        cid += 1
        log("-" * 66)
        log("w%03d: connection from %s -> sending SMSG_AUTH_CHALLENGE (authSeed=%s)"
            % (cid, addr, SERVER_SEED.hex()))
        try:
            conn.sendall(build_challenge())
        except OSError as e:
            log("w%03d: send failed: %r" % (cid, e)); conn.close(); continue

        pkt, _extra = recv_cmsg(conn)
        if not pkt:
            log("w%03d: no CMSG received (client sent nothing). If this repeats, the challenge "
                "length/opcode is wrong for this client." % cid)
            conn.close(); continue

        raw = os.path.join(BASE, "world_cmsg_w%03d.bin" % cid)
        try:
            open(raw, "wb").write(pkt)
        except Exception:
            pass
        log("w%03d: received %dB, saved -> %s" % (cid, len(pkt), os.path.basename(raw)))

        opcode = struct.unpack("<I", pkt[2:6])[0] if len(pkt) >= 6 else -1
        if opcode != CMSG_AUTH_SESSION:
            log("w%03d: FIRST opcode = 0x%04x (expected CMSG_AUTH_SESSION 0x01ED). "
                "Client speaks a NON-stock world opening. Raw: %s" % (cid, opcode, pkt[:32].hex()))
            conn.close(); continue

        try:
            f = parse_cmsg(pkt)
        except Exception as e:
            log("w%03d: parse error %r  raw=%s" % (cid, e, pkt[:64].hex()))
            conn.close(); continue

        log("w%03d: CMSG_AUTH_SESSION parsed:" % cid)
        log("        build=%d (0x%x)  account=%r  realmID=%d  loginSrvID=%d loginSrvType=%d"
            % (f["build"], f["build"], f["account"], f["realmID"], f["loginServerID"], f["loginServerType"]))
        log("        clientSeed=%s  serverSeed(ours)=%s  region=%d bg=%d dos=0x%x addon=%dB"
            % (f["localChallenge"].hex(), SERVER_SEED.hex(), f["regionID"], f["battlegroupID"],
               f["dosResponse"], f["addon_len"]))
        log("        digest=%s" % f["digest"].hex())

        kb = read_keyblock()
        if not kb:
            log("w%03d: RPM read failed (no live client / not elevated?). Cannot match digest." % cid)
            conn.close(); continue
        log("w%03d: RPM pid=%d objptr=0x%x  K(obj+0x120,32B)=%s"
            % (cid, kb["pid"], kb["objptr"], kb["K"].hex() if kb["K"] else "<null>"))

        hits = find_key(f, kb)
        if hits:
            log("w%03d: *** WORLD DIGEST CRACKED -- stock 3.3.5a formula confirmed ***" % cid)
            for hcand in hits:
                log("        keylen=%d  loc=%s (K%+d)  dir=%s  account=%s  seeds=%s"
                    % (hcand["keylen"], hcand["abs_off"], hcand["rel_to_K"], hcand["dir"],
                       hcand["account"], hcand["seed_order"]))
                log("        SessionKey=%s" % hcand["key"])
        else:
            log("w%03d: no session-key window in obj+0x%x..+0x%x reproduces the digest."
                % (cid, kb["block_off"], kb["block_off"] + len(kb["block"])))
            log("        => world key is NOT a raw slice of the auth object near K, or the account/"
                "seed layout differs. Digest inputs are logged above for offline analysis.")
        try:
            conn.close()
        except OSError:
            pass

if __name__ == "__main__":
    main()
