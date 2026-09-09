"""E0 capture harness - a deliberately boring, deterministic local authserver stand-in.

PURPOSE (experiment E0 from WIRE-SPEC.md sec.10): hold the server side of the login
completely constant and capture what the Ascension client sends across repeated launches,
so we can measure the client's natural per-launch variation before changing any input.

What it does, and ONLY this:
  1. Listens on 127.0.0.1:<port> (default 3799 - the port launch-client.ps1 already aims
     the client at).
  2. Reads one complete client 0x00 message, framed by its own length field
     (cmd,err,size16le,body[size]) - NOT by recv() boundaries.
  3. Sends the SAME 119-byte challenge on every connection, byte-for-byte, loaded from a
     file (default: the known-good challenge from the successful live capture). It never
     synthesises B, salt, or anything else.
  4. Reads one complete 75-byte client 0x01 proof (fixed length, buffered).
  5. Closes immediately. It NEVER sends an 0x01 / M2 response, so the client can never
     complete auth - we only want its proof.

Determinism guarantees (so E0 provably held):
  * The only bytes ever written to the wire are the fixed challenge file. No M2, no
    per-session generation, no randomness, no timestamps on the wire.
  * Each session saves the EXACT challenge bytes transmitted (sNNN_s00_challenge_sent.bin),
    not a label, plus the client's 0x00 and 0x01 messages as raw .bin, plus a human hex
    record and a machine-readable TSV index line (sha256s are deterministic fingerprints,
    not randomness).
  * Session IDs are a monotonic counter that continues past the highest existing sNNN in
    the output dir, so restarts never overwrite and numbering stays ordered.

Usage:
    python e0-harness.py [port] [challenge.bin]      # run; point client realmList here
    python e0-harness.py --selftest                  # no client needed; proves framing
"""
import socket, os, sys, hashlib

BASE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CHALLENGE = os.path.join(BASE, "live-server-challenge-response.bin")
RECV_TIMEOUT = 120          # safety net only; never sends anything, never alters the wire
MAX_BODY     = 65536        # defensive cap on the 0x00 body size field
PROOF_LEN    = 75           # fixed 0x01 length per WIRE-SPEC.md sec.5


def hexdump(b, indent="    "):
    out = []
    for i in range(0, len(b), 16):
        chunk = b[i:i+16]
        hexed = " ".join("%02x" % x for x in chunk)
        text  = "".join(chr(x) if 32 <= x < 127 else "." for x in chunk)
        out.append("%s%04x  %-47s  %s" % (indent, i, hexed, text))
    return "\n".join(out) if out else indent + "(empty)"


def next_session_id(outdir):
    hi = 0
    if os.path.isdir(outdir):
        for n in os.listdir(outdir):
            if len(n) > 1 and n[0] == "s" and n[1:4].isdigit():
                hi = max(hi, int(n[1:4]))
    return hi + 1


def recv_until(sock, buf, need):
    """Read into buf until it holds >= need bytes. Return True if reached, False on EOF."""
    while len(buf) < need:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            return False
        if not chunk:
            return False
        buf += chunk
    return True


def read_client_0x00(sock, buf):
    """Return the complete 0x00 message using its length field, or None if truncated."""
    if not recv_until(sock, buf, 4):
        return None
    size = buf[2] | (buf[3] << 8)          # uint16 LE
    total = 4 + min(size, MAX_BODY)
    if not recv_until(sock, buf, total):
        return None
    msg = bytes(buf[:total])
    del buf[:total]
    return msg


def read_client_fixed(sock, buf, n):
    """Return exactly n bytes (buffered), or whatever arrived before EOF (partial)."""
    recv_until(sock, buf, n)               # partial is informative; keep what we got
    take = min(n, len(buf))
    msg = bytes(buf[:take])
    del buf[:take]
    return msg


def handle(conn, sid, challenge, outdir, humanlog, indexlog):
    conn.settimeout(RECV_TIMEOUT)
    buf = bytearray()
    tag = "s%03d" % sid

    hello = read_client_0x00(conn, buf)
    if hello is None:
        print("%s: client closed before a complete 0x00 - nothing saved" % tag)
        return
    open(os.path.join(outdir, tag + "_c00_hello.bin"), "wb").write(hello)

    # The one and only thing we ever transmit. Save the exact bytes sent.
    conn.sendall(challenge)
    open(os.path.join(outdir, tag + "_s00_challenge_sent.bin"), "wb").write(challenge)

    proof = read_client_fixed(conn, buf, PROOF_LEN)
    open(os.path.join(outdir, tag + "_c01_proof.bin"), "wb").write(proof)
    leftover = len(buf)

    # Close without an M2 - deliberately. try/except: client may have gone already.
    try:
        conn.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    conn.close()

    hop = hello[0] if hello else -1
    pop = proof[0] if proof else -1
    hsha = hashlib.sha256(hello).hexdigest()
    psha = hashlib.sha256(proof).hexdigest() if proof else "-"
    csha = hashlib.sha256(challenge).hexdigest()

    rec = []
    rec.append("=== session %d (%s) ===" % (sid, tag))
    rec.append("client 0x00  len=%d  op=0x%02x  sha256=%s" % (len(hello), hop, hsha))
    rec.append(hexdump(hello))
    rec.append("server 0x00 SENT  len=%d  sha256=%s" % (len(challenge), csha))
    rec.append(hexdump(challenge))
    rec.append("client 0x01  len=%d  op=0x%02x  sha256=%s%s"
               % (len(proof), pop, psha,
                  ("  (PARTIAL, expected %d)" % PROOF_LEN) if len(proof) != PROOF_LEN else ""))
    rec.append(hexdump(proof))
    if leftover:
        rec.append("NOTE: %d unexpected trailing byte(s) after the proof" % leftover)
    rec.append("")
    with open(humanlog, "a", encoding="utf8") as f:
        f.write("\n".join(rec) + "\n")

    new = not os.path.exists(indexlog)
    with open(indexlog, "a", encoding="utf8") as f:
        if new:
            f.write("session\thello_len\thello_op\tproof_len\tproof_op\t"
                    "hello_sha256\tproof_sha256\tchallenge_sha256\n")
        f.write("%d\t%d\t0x%02x\t%d\t0x%02x\t%s\t%s\t%s\n"
                % (sid, len(hello), hop, len(proof), pop, hsha, psha, csha))

    print("%s: hello %dB (op 0x%02x), proof %dB (op 0x%02x)%s -> saved"
          % (tag, len(hello), hop, len(proof), pop,
             "" if len(proof) == PROOF_LEN else "  [PARTIAL]"))


def load_challenge(path):
    ch = open(path, "rb").read()
    if len(ch) != 119:
        sys.exit("REFUSING TO RUN: challenge %s is %d bytes, expected exactly 119."
                 % (path, len(ch)))
    return ch


def run(port, challenge_path):
    challenge = load_challenge(challenge_path)
    outdir   = os.path.join(BASE, "e0-captures")
    os.makedirs(outdir, exist_ok=True)
    humanlog = os.path.join(outdir, "E0-sessions.hex.txt")
    indexlog = os.path.join(outdir, "E0-index.tsv")

    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(4)
    sid = next_session_id(outdir)
    print("E0 harness on 127.0.0.1:%d" % port)
    print("fixed challenge: %s  sha256=%s" % (challenge_path, hashlib.sha256(challenge).hexdigest()))
    print("output dir: %s" % outdir)
    print("point the client realmList at 127.0.0.1:%d and click Login; Ctrl-C to stop." % port)
    print("next session id: %d" % sid)
    try:
        while True:
            conn, _ = srv.accept()
            try:
                conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError:
                pass
            handle(conn, sid, challenge, outdir, humanlog, indexlog)
            sid += 1
    except KeyboardInterrupt:
        print("\nstopped after %d session(s)." % (sid - next_session_id(outdir) + (sid - 1 if False else 0) or 0))


def selftest():
    """Prove framing + determinism without the real client, using recorded live messages.
    Sends the hello and proof in FRAGMENTS so one recv() != one message is exercised."""
    import threading, time
    ch = load_challenge(DEFAULT_CHALLENGE)
    hello = open(os.path.join(BASE, "wire-analysis", "hello_L_c1_645.bin"), "rb").read()
    proof = open(os.path.join(BASE, "wire-analysis", "live_CLIENT_msg2_75.bin"), "rb").read()

    outdir = os.path.join(BASE, "e0-captures", "selftest")
    if os.path.isdir(outdir):
        for n in os.listdir(outdir):
            os.remove(os.path.join(outdir, n))
    os.makedirs(outdir, exist_ok=True)
    humanlog = os.path.join(outdir, "E0-sessions.hex.txt")
    indexlog = os.path.join(outdir, "E0-index.tsv")

    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    got = {}
    def server():
        conn, _ = srv.accept()
        handle(conn, 1, ch, outdir, humanlog, indexlog)
    t = threading.Thread(target=server); t.start()

    c = socket.create_connection(("127.0.0.1", port))
    # hello in 3 fragments straddling the header and body boundaries
    for frag in (hello[:2], hello[2:100], hello[100:]):
        c.sendall(frag); time.sleep(0.02)
    back = b""
    while len(back) < 119:
        back += c.recv(4096)
    got["challenge_ok"] = (back == ch)
    # proof in 2 fragments
    c.sendall(proof[:40]); time.sleep(0.02); c.sendall(proof[40:])
    time.sleep(0.05)
    c.close(); t.join()

    def same(name, expect):
        p = os.path.join(outdir, name)
        b = open(p, "rb").read() if os.path.exists(p) else b""
        return b == expect
    checks = {
        "challenge echoed to client byte-for-byte": got.get("challenge_ok", False),
        "hello captured whole across 3 fragments":  same("s001_c00_hello.bin", hello),
        "challenge_sent recorded == challenge":     same("s001_s00_challenge_sent.bin", ch),
        "proof captured whole across 2 fragments":  same("s001_c01_proof.bin", proof),
    }
    print("SELFTEST")
    ok = True
    for k, v in checks.items():
        print("  [%s] %s" % ("PASS" if v else "FAIL", k)); ok &= v
    print("  result:", "ALL PASS" if ok else "FAILURE")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--selftest":
        selftest()
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 3799
    challenge_path = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_CHALLENGE
    run(port, challenge_path)
