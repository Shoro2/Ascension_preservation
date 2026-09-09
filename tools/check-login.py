"""Prove a realm's logon path end to end by speaking the 3.3.5a auth protocol.

Reading `account` rows only shows that a credential exists. This walks the whole
handshake against a running authserver - SRP6 challenge, proof, realm list - so
it answers the real question: can this client build log in with this account, and
what realm does the server then offer?

It is deliberately usable with a throwaway bot account, so no human credential
has to be typed or stored to test the path. The password is never printed, and
it is passed by argument only - nothing is written to disk.

Usage:  python check-login.py <ACCOUNT> <PASSWORD> [host] [port]
        python check-login.py <ACCOUNT> --challenge-only
        python check-login.py RNDBOT0 RNDBOT0
"""
import hashlib, socket, struct, sys

BUILD = 12340

# AuthResult, verbatim from apps/authserver/Authentication/AuthCodes.h
NAMES = {0x00: "success", 0x03: "banned", 0x04: "unknown account",
         0x05: "incorrect password", 0x06: "already online",
         0x07: "no time left", 0x08: "database busy",
         0x09: "client version rejected", 0x0C: "suspended",
         0x0D: "no access", 0x10: "locked"}
N = int("894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7", 16)
g = 7
k = 3


def rev(b):
    return b[::-1]


def sha1(*parts):
    h = hashlib.sha1()
    for p in parts:
        h.update(p)
    return h.digest()


def challenge(sock, account):
    acc = account.upper().encode("ascii")
    body = (b"WoW\x00" + bytes([3, 3, 5]) + struct.pack("<H", BUILD)
            + b"68x\x00" + b"niW\x00" + b"SUne"
            + struct.pack("<i", 0) + struct.pack(">I", 0x7F000001)
            + bytes([len(acc)]) + acc)
    sock.sendall(bytes([0x00, 0x06]) + struct.pack("<H", len(body)) + body)

    head = sock.recv(3)
    if len(head) < 3:
        raise RuntimeError("authserver closed the connection without answering")
    if head[2] != 0x00:
        raise RuntimeError("logon challenge refused: %s" % NAMES.get(head[2],
                           "error 0x%02X" % head[2]))
    # B[32] + g_len + g + N_len + N[32] + s[32] + versionChallenge[16] + flags
    want = 116
    rest = b""
    while len(rest) < want:
        chunk = sock.recv(want - len(rest))
        if not chunk:
            raise RuntimeError("short challenge response (%d of %d bytes)"
                               % (len(rest), want))
        rest += chunk
    B = int.from_bytes(rest[0:32], "little")
    glen = rest[32]
    gg = int.from_bytes(rest[33:33 + glen], "little")
    nlen = rest[33 + glen]
    o = 34 + glen
    NN = int.from_bytes(rest[o:o + nlen], "little")
    s = rest[o + nlen:o + nlen + 32]
    return B, gg, NN, s


def proof(sock, account, password, B, gg, NN, s):
    acc = account.upper().encode("ascii")
    cred = (account.upper() + ":" + password.upper()).encode("ascii")
    x = int.from_bytes(rev(sha1(s, sha1(cred))), "big")
    a = int.from_bytes(hashlib.sha1(b"check-login fixed client secret").digest(), "big")
    A = pow(gg, a, NN)
    Ab = rev(A.to_bytes(32, "big"))
    Bb = rev(B.to_bytes(32, "big"))
    u = int.from_bytes(rev(sha1(Ab, Bb)), "big")
    S = pow((B - k * pow(gg, x, NN)) % NN, a + u * x, NN)

    # K is the two halves of S hashed separately and interleaved back together.
    Sb = rev(S.to_bytes(32, "big"))
    even = sha1(Sb[0::2])
    odd = sha1(Sb[1::2])
    K = bytes(b for pair in zip(even, odd) for b in pair)

    nh = sha1(rev(NN.to_bytes(32, "big")))
    gh = sha1(bytes([gg]))
    xor = bytes(p ^ q for p, q in zip(nh, gh))
    M1 = sha1(xor, sha1(acc), s, Ab, Bb, K)

    sock.sendall(bytes([0x01]) + Ab + M1 + bytes(20) + bytes([0, 0]))
    head = sock.recv(2)
    if len(head) < 2:
        raise RuntimeError("authserver closed the connection during proof")
    if head[1] != 0x00:
        raise RuntimeError("logon proof refused: %s" % NAMES.get(head[1],
                           "error 0x%02X" % head[1]))
    # M2[20] + accountFlags[4] + surveyId[4] + unkFlags[2]. Under-reading here
    # leaves stale bytes that corrupt the realm-list reply that follows.
    want = 30
    got = b""
    while len(got) < want:
        chunk = sock.recv(want - len(got))
        if not chunk:
            break
        got += chunk
    return True


def realmlist(sock):
    sock.sendall(bytes([0x10]) + struct.pack("<I", 0))
    head = sock.recv(3)
    size = struct.unpack("<H", head[1:3])[0]
    buf = b""
    while len(buf) < size:
        chunk = sock.recv(size - len(buf))
        if not chunk:
            break
        buf += chunk
    count = struct.unpack("<H", buf[4:6])[0]
    at, out = 6, []
    for _ in range(count):
        icon, lock, flags = buf[at], buf[at + 1], buf[at + 2]
        at += 3
        end = buf.index(b"\x00", at)
        name = buf[at:end].decode("utf8", "replace")
        at = end + 1
        end = buf.index(b"\x00", at)
        addr = buf[at:end].decode("utf8", "replace")
        at = end + 1
        pop = struct.unpack("<f", buf[at:at + 4])[0]
        chars, tz = buf[at + 4], buf[at + 5]
        at += 7
        out.append(dict(name=name, address=addr, icon=icon, lock=lock,
                        flags=flags, population=pop, characters=chars, timezone=tz))
    return out


def main(argv):
    if not argv or (len(argv) < 2 and "--challenge-only" not in argv):
        print(__doc__)
        return 2
    only = "--challenge-only" in argv
    argv = [a for a in argv if not a.startswith("--")]
    account = argv[0]
    password = argv[1] if len(argv) > 1 else ""
    host = argv[2] if len(argv) > 2 else "127.0.0.1"
    port = int(argv[3]) if len(argv) > 3 else 3724

    sock = socket.create_connection((host, port), timeout=15)
    try:
        print("connected to %s:%d" % (host, port))
        B, gg, NN, s = challenge(sock, account)
        print("challenge accepted for %s (server offered its SRP6 parameters)"
              % account.upper())
        if only:
            # The challenge alone proves the authserver knows this account on
            # this realm and will talk to it. No password is sent, so nothing
            # is recorded against the account either way.
            print("account is known to this realm and not refused at challenge;"
                  " stopping before the password step as asked")
            return 0
        proof(sock, account, password, B, gg, NN, s)
        print("PROOF ACCEPTED - the password for %s is correct on this realm"
              % account.upper())
        realms = realmlist(sock)
        print("realm list returned %d realm(s):" % len(realms))
        for r in realms:
            print("   %-24s %-22s chars=%-3d lock=%d flags=0x%02X pop=%.1f"
                  % (r["name"], r["address"], r["characters"], r["lock"],
                     r["flags"], r["population"]))
    finally:
        sock.close()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
