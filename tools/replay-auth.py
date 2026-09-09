"""Stand-alone LOCAL authserver that replays our four CAPTURED handshake packets.

There is NO upstream: this process never contacts Ascension.  It only echoes
bytes we recorded during the one successful live login, plus the captured realm
list rewritten to localhost.  It answers a single question that decides whether a
local single-player rebuild is even possible:

    Does the client accept a login from a server that merely replays recorded
    bytes, with no fresh per-session cryptography?

If yes, the client does not bind the login to session-specific server material -
its 32-byte M2 is either unverified or deterministic for this account - and a
local authserver can wave every login through.  If no, WHERE the client balks
(silent drop after the proof response, a specific auth error, no realm-list
request) tells us exactly what is session-bound and aims the Extensions.dll
analysis at the right function.

Decisive signal:  a client that reaches the realm screen has ACCEPTED the
replayed proof response.  The realm-list request (opcode 0x10) is sent only after
auth succeeds, so the moment we receive a 0x10 the question is answered YES.

Nothing here touches the real servers, the client binary, or the acore_* DBs.
It replays the player's own recorded login of their own account, locally.

Usage:  python replay-auth.py            # listens on 127.0.0.1:3799
        point the client's realmList at 127.0.0.1:3799 and click Login
"""
import socket, struct, os, sys, time, threading, re

BASE   = os.path.dirname(os.path.abspath(__file__))
LISTEN = int(sys.argv[1]) if len(sys.argv) > 1 else 3799
DEADPT = 8900                                   # local world port (nothing serves it)

CHAL  = open(os.path.join(BASE, "live-server-challenge-response.bin"), "rb").read()  # 119
PROOF = open(os.path.join(BASE, "live-server-proof-response.bin"),    "rb").read()   # 44
RLRAW = open(os.path.join(BASE, "live-realmlist-raw.bin"),            "rb").read()    # 2306

ADDR = re.compile(rb"(?:\d{1,3}\.){3}\d{1,3}:\d{1,5}")

def build_realmlist():
    """Rewrite every world address to 127.0.0.1:DEADPT and fix the outer size."""
    assert RLRAW[0] == 0x10
    payload = RLRAW[3:3 + struct.unpack_from("<H", RLRAW, 1)[0]]
    new = ADDR.sub(b"127.0.0.1:%d" % DEADPT, payload)
    return b"\x10" + struct.pack("<H", len(new)) + new

REALMLIST = build_realmlist()

lock = threading.Lock()
def say(msg):
    line = "%s  %s" % (time.strftime("%H:%M:%S"), msg)
    with lock:
        print(line, flush=True)
        with open(os.path.join(BASE, "replay-auth.log"), "a", encoding="utf8") as f:
            f.write(line + "\n")

def handle(cli, addr, n):
    say("connection %d from %s:%d" % (n, addr[0], addr[1]))
    stage = {"chal": False, "proof": False, "realm": False}
    try:
        while True:
            data = cli.recv(65536)
            if not data:
                say("  client closed")
                break
            op = data[0]
            if op == 0x00:
                say("  <- CHALLENGE (%d bytes); replaying 119-byte challenge response" % len(data))
                cli.sendall(CHAL); stage["chal"] = True
            elif op == 0x01:
                say("  <- PROOF (%d bytes); replaying 44-byte proof response (SUCCESS + 32B M2)" % len(data))
                cli.sendall(PROOF); stage["proof"] = True
            elif op == 0x10:
                say("  <- REALM-LIST request (%d bytes)" % len(data))
                say("  ****************************************************************")
                say("  ***  CLIENT ACCEPTED THE REPLAYED PROOF - auth is REPLAYABLE ***")
                say("  ***  serving %d-byte realm list (all realms -> 127.0.0.1:%d) ***" % (len(REALMLIST), DEADPT))
                say("  ****************************************************************")
                cli.sendall(REALMLIST); stage["realm"] = True
            else:
                say("  <- UNKNOWN opcode 0x%02X (%d bytes): %s" % (op, len(data), data[:16].hex()))
    except OSError as e:
        say("  relay error: %s" % e)
    finally:
        if stage["proof"] and not stage["realm"]:
            say("  NOTE: client received the proof response but did NOT request the")
            say("        realm list before closing -> it likely REJECTED our M2 or")
            say("        another session-bound field.  That is the finding: something")
            say("        in the proof is not replayable; check the Extensions.dll M2 path.")
        try: cli.shutdown(socket.SHUT_RDWR)
        except OSError: pass
        cli.close()

def main():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", LISTEN)); srv.listen(4)
    say("replay authserver on 127.0.0.1:%d  (NO upstream - pure replay)" % LISTEN)
    say("realm list ready: %d bytes, %d addresses -> 127.0.0.1:%d"
        % (len(REALMLIST), len(ADDR.findall(REALMLIST)), DEADPT))
    say("point the client's realmList at 127.0.0.1:%d and click Login" % LISTEN)
    n = 0
    while True:
        cli, addr = srv.accept(); n += 1
        try: cli.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError: pass
        threading.Thread(target=handle, args=(cli, addr, n), daemon=True).start()

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: say("stopped")
