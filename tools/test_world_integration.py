"""End-to-end integration test for world_server.handle_client.

Runs the REAL server loop over a loopback socket against a mock client that speaks
the actual plaintext wire protocol: challenge -> auth-session -> char-enum ->
char-create -> char-enum -> player-login -> world-entry burst. Exercises send_pkt
framing, the recv/dispatch loop, JSON persistence, and the full world-entry burst
WITHOUT the real client or elevation (read_world_key is forced to None -> plaintext).

Run:  python test_world_integration.py
"""
import sys, os, types, struct, socket, threading, tempfile

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)

_stub = types.ModuleType("rpm_readk")
_stub.find_pids = lambda: []
_stub.module_base = lambda pid: 0
_stub._open = lambda pid: 0
_stub._read = lambda h, a, n: b""
_stub.STATIC_OBJ_SLOT_RVA = 0
_stub.K_OFFSET_IN_OBJ = 0x120
_stub.k32 = types.SimpleNamespace(CloseHandle=lambda h: None)
sys.modules["rpm_readk"] = _stub

import world_server as W

# force the plaintext-only path (no client memory to read) and a throwaway store
W.read_world_key = lambda: None
_tmp = tempfile.NamedTemporaryFile(prefix="chars_it_", suffix=".json", delete=False)
_tmp.close()
W.CHARS_PATH = _tmp.name

FAILS = []
def check(cond, msg):
    print(("  ok " if cond else " FAIL") + "  " + msg)
    if not cond:
        FAILS.append(msg)

def recvn(sock, n):
    buf = b""
    while len(buf) < n:
        d = sock.recv(n - len(buf))
        if not d:
            raise EOFError("socket closed with %d/%d bytes" % (len(buf), n))
        buf += d
    return buf

def read_smsg(sock):
    """Read one S->C packet; returns (opcode, body). Handles 4- and 5-byte headers."""
    b0 = recvn(sock, 1)
    if b0[0] & 0x80:
        rest = recvn(sock, 4)
        size = ((b0[0] & 0x7F) << 16) | (rest[0] << 8) | rest[1]
        opcode = rest[2] | (rest[3] << 8)
    else:
        rest = recvn(sock, 3)
        size = (b0[0] << 8) | rest[0]
        opcode = rest[1] | (rest[2] << 8)
    return opcode, recvn(sock, size - 2)

def cmsg(opcode, body=b""):
    return struct.pack(">H", len(body) + 4) + struct.pack("<I", opcode) + body


def run_server_once(port, ready):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(1)
    ready.set()
    conn, _ = srv.accept()
    try:
        W.handle_client(conn, 1)
    except Exception as e:
        print("  server thread ended: %r" % e)
    finally:
        try: conn.close()
        except OSError: pass
        srv.close()


def main():
    port = 18085
    ready = threading.Event()
    t = threading.Thread(target=run_server_once, args=(port, ready), daemon=True)
    t.start(); ready.wait(5)

    s = socket.create_connection(("127.0.0.1", port), timeout=10)
    s.settimeout(10)

    # 1) SMSG_AUTH_CHALLENGE
    opc, body = read_smsg(s)
    check(opc == W.SMSG_AUTH_CHALLENGE, "recv SMSG_AUTH_CHALLENGE (0x%03X)" % opc)

    # 2) CMSG_AUTH_SESSION (digest unverified on server since key is absent)
    ab = b""
    ab += struct.pack("<I", 12340)                 # build
    ab += struct.pack("<I", 0)                     # loginServerID
    ab += b"TEST\x00"                              # account
    ab += struct.pack("<I", 0)                     # loginServerType
    ab += b"\x11\x22\x33\x44"                      # localChallenge (clientSeed)
    ab += struct.pack("<I", 0)                     # regionID
    ab += struct.pack("<I", 0)                     # battlegroupID
    ab += struct.pack("<I", 23)                    # realmID (Rexxar)
    ab += struct.pack("<Q", 0)                     # dosResponse
    ab += bytes(20)                                # digest (ignored)
    ab += struct.pack("<I", 0)                     # addon blob (uncompressedSize=0, no data)
    s.sendall(cmsg(W.CMSG_AUTH_SESSION, ab))

    # 3) post-auth burst: AUTH_RESPONSE, ADDON_INFO, CLIENTCACHE_VERSION, TUTORIAL_FLAGS
    burst = [read_smsg(s)[0] for _ in range(4)]
    check(W.SMSG_AUTH_RESPONSE in burst, "burst contains SMSG_AUTH_RESPONSE")
    check(W.SMSG_TUTORIAL_FLAGS in burst, "burst contains SMSG_TUTORIAL_FLAGS")

    # 4) CMSG_CHAR_ENUM -> empty list
    s.sendall(cmsg(W.CMSG_CHAR_ENUM))
    opc, body = read_smsg(s)
    check(opc == W.SMSG_CHAR_ENUM and body[0] == 0, "empty SMSG_CHAR_ENUM (count=0)")

    # 5) CMSG_CHAR_CREATE (Troll Female, class 3) -> success
    cbody = b"Zubarra\x00" + bytes([8, 3, 1, 5, 2, 7, 4, 1, 0])
    s.sendall(cmsg(W.CMSG_CHAR_CREATE, cbody))
    opc, body = read_smsg(s)
    check(opc == W.SMSG_CHAR_CREATE and body[0] == 0x2F, "SMSG_CHAR_CREATE success (0x2F)")

    # 6) CMSG_CHAR_ENUM again -> the created character
    s.sendall(cmsg(W.CMSG_CHAR_ENUM))
    opc, body = read_smsg(s)
    check(opc == W.SMSG_CHAR_ENUM and body[0] == 1, "SMSG_CHAR_ENUM now has 1 character")
    guid = struct.unpack_from("<Q", body, 1)[0]
    check(guid >= 1, "enum guid = %d" % guid)

    # 7) CMSG_PLAYER_LOGIN -> world-entry burst
    s.sendall(cmsg(W.CMSG_PLAYER_LOGIN, struct.pack("<Q", guid)))
    seen = {}
    # read until we have the key world-entry packets (or timeout)
    for _ in range(20):
        try:
            opc, body = read_smsg(s)
        except (EOFError, socket.timeout):
            break
        seen[opc] = body
        if W.SMSG_MOTD in seen and W.SMSG_UPDATE_OBJECT in seen:
            break
    check(W.SMSG_LOGIN_VERIFY_WORLD in seen, "world-entry: SMSG_LOGIN_VERIFY_WORLD sent")
    check(W.SMSG_LOGIN_SETTIMESPEED in seen, "world-entry: SMSG_LOGIN_SETTIMESPEED sent")
    check(W.SMSG_UPDATE_OBJECT in seen, "world-entry: SMSG_UPDATE_OBJECT (self create) sent")
    check(W.SMSG_TIME_SYNC_REQ in seen, "world-entry: SMSG_TIME_SYNC_REQ sent")

    # parse LOGIN_VERIFY_WORLD
    if W.SMSG_LOGIN_VERIFY_WORLD in seen:
        vw = seen[W.SMSG_LOGIN_VERIFY_WORLD]
        mp = struct.unpack_from("<I", vw, 0)[0]
        check(mp == 1, "LOGIN_VERIFY_WORLD map == 1 (Durotar)")

    # parse UPDATE_OBJECT enough to confirm it frames cleanly through send_pkt
    if W.SMSG_UPDATE_OBJECT in seen:
        uo = seen[W.SMSG_UPDATE_OBJECT]
        blocks = struct.unpack_from("<I", uo, 0)[0]
        utype = uo[4]
        check(blocks == 1 and utype == 3, "UPDATE_OBJECT framed: blockCount=1, CREATE_OBJECT2")

    # 8) a ping still answered after world entry
    s.sendall(cmsg(W.CMSG_PING, struct.pack("<I", 0x1234)))
    opc, body = read_smsg(s)
    check(opc == W.SMSG_PONG and struct.unpack("<I", body[:4])[0] == 0x1234, "post-entry CMSG_PING -> SMSG_PONG echo")

    s.close()

    # persistence: the character survived to disk
    import json
    with open(W.CHARS_PATH, "r", encoding="utf-8") as fp:
        db = json.load(fp)
    check(any(c["name"] == "Zubarra" for c in db.get("TEST", [])), "character persisted to characters.json")

    try: os.unlink(W.CHARS_PATH)
    except OSError: pass

    print("\n" + "=" * 60)
    if FAILS:
        print("RESULT: %d FAILURE(S):" % len(FAILS))
        for m in FAILS: print("   - " + m)
        sys.exit(1)
    print("RESULT: END-TO-END SESSION OK -- create + enum + world-entry all frame correctly.")
    sys.exit(0)


if __name__ == "__main__":
    main()
