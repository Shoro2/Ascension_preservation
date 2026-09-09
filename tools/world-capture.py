"""Capture the WORLD handshake, the second half Ascension never lets us see.

Auth alone gets the client to the realm screen (see auth-proxy.py).  The realm
list the auth server returns names the *world* server for each realm - a raw
IP:port - and the client dials that directly, not through the auth proxy.  So to
record the world handshake we have to bend that connection back through here.

This does both halves in one process:

  1. Auth relay on 3799 -> the real Ascension auth server.  Transparent, exactly
     like auth-proxy.py, EXCEPT that once the client asks for the realm list
     (opcode 0x10) every world address in the server's reply is rewritten from
     its real IP:port to 127.0.0.1:<a local port>.  The outer packet length is
     fixed up by the byte delta; nothing else in the realm-list body is touched,
     so we never have to understand Ascension's extended realm format - the
     address is a null-terminated string and the null stays put.

  2. A world forwarder per distinct real address, spun up on demand.  Whichever
     realm the player picks, its rewritten address points at the matching local
     forwarder, which relays to the real world server and dumps the handshake.
     So the player just enters the realm they normally play - no need to know
     which of the 42 it is in advance.

The world stream turns on header encryption after SMSG_AUTH_CHALLENGE, but the
two packets that matter - SMSG_AUTH_CHALLENGE (server seed) and CMSG_AUTH_SESSION
(the client's account name and session-key proof) - are sent before that, so
they land in the clear.  Each forwarder hexdumps the first 8 KB per direction,
which covers the whole handshake, then just counts bytes.

Nothing here touches the real servers' state, the client binary, or the local
acore_* databases.  It is a localhost man-in-the-middle on the player's own
traffic to their own account, run for archival before the 2026-09-04 shutdown.

The per-realm world logs and the auth log carry a real login on the wire and are
treated like credentials.txt: never copied into committed files or chat.

Usage:  python world-capture.py
"""
import socket, struct, sys, threading, time, re, os

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
AUTH_LISTEN = 3799
REAL_AUTH   = ("51.210.230.10", 3724)
WORLD_BASE  = 8800                     # first local world-forwarder port

ADDR_RE = re.compile(rb"(?:\d{1,3}\.){3}\d{1,3}:\d{1,5}")

def nodelay(s):
    """Turn off Nagle so relayed segments are not held back.  Proxy latency
    that lets a world packet arrive before Extensions.dll finishes patching
    its opcode handlers is the leading suspect for the zone-in crash."""
    try:
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError:
        pass

lock       = threading.Lock()
addr_map   = {}                        # b"ip:port" (real) -> local port
started    = set()                     # local ports already listening
main_log   = None


def _write(path, line):
    with lock:
        with open(path, "a", encoding="utf8") as f:
            f.write(line + "\n")


def say(msg, path=None):
    line = "%s  %s" % (time.strftime("%H:%M:%S"), msg)
    print(line, flush=True)
    _write(os.path.join(BASE_DIR, "world-capture-auth.log"), line)
    if path:
        _write(path, line)


def hexdump(data, path, indent="        ", limit=8192):
    for i in range(0, min(len(data), limit), 16):
        chunk = data[i:i + 16]
        hexed = " ".join("%02X" % b for b in chunk)
        text  = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        _write(path, "%s%04X  %-47s  %s" % (indent, i, hexed, text))
    if len(data) > limit:
        _write(path, "%s... (+%d more bytes not dumped)" % (indent, len(data) - limit))


# ------------------------------------------------------------------ world side

def world_pump(src, dst, label, path, counters):
    dumped = counters.setdefault(label, 0)
    try:
        while True:
            data = src.recv(65536)
            if not data:
                say("%s closed" % label, path)
                break
            say("%s -> %d bytes" % (label, len(data)), path)
            if counters[label] < 8192:
                hexdump(data, path, limit=8192 - counters[label])
            counters[label] += len(data)
            dst.sendall(data)
    except OSError as e:
        say("%s stopped: %s" % (label, e), path)
    finally:
        for s in (src, dst):
            try: s.shutdown(socket.SHUT_RDWR)
            except OSError: pass


def world_server(local_port, real_ip, real_port):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", local_port))
    srv.listen(4)
    n = 0
    while True:
        client, addr = srv.accept()
        nodelay(client)
        n += 1
        path = os.path.join(BASE_DIR, "world-%d-%s-%d.log" % (local_port, real_ip, real_port))
        say("WORLD :%d connection %d -> %s:%d (log %s)"
            % (local_port, n, real_ip, real_port, os.path.basename(path)), path)
        try:
            up = socket.create_connection((real_ip, real_port), timeout=15)
            nodelay(up)
        except OSError as e:
            say("WORLD :%d could not reach %s:%d - %s" % (local_port, real_ip, real_port, e), path)
            client.close()
            continue
        counters = {}
        threading.Thread(target=world_pump, daemon=True,
                         args=(client, up, "W-CLIENT", path, counters)).start()
        threading.Thread(target=world_pump, daemon=True,
                         args=(up, client, "W-SERVER", path, counters)).start()


def assign_port(real_bytes):
    """Map a real 'ip:port' to a local forwarder port, starting it on first use."""
    with lock:
        if real_bytes not in addr_map:
            lp = WORLD_BASE + len(addr_map)
            addr_map[real_bytes] = lp
    lp = addr_map[real_bytes]
    if lp not in started:
        started.add(lp)
        ip, port = real_bytes.decode().split(":")
        threading.Thread(target=world_server, daemon=True,
                         args=(lp, ip, int(port))).start()
        say("world forwarder 127.0.0.1:%d -> %s" % (lp, real_bytes.decode()))
    return lp


def rewrite_realm_addresses(payload):
    def repl(m):
        return b"127.0.0.1:%d" % assign_port(m.group(0))
    return ADDR_RE.sub(repl, payload)


# ------------------------------------------------------------------- auth side

def auth_client_to_server(cli, srv, phase):
    try:
        while True:
            data = cli.recv(65536)
            if not data:
                say("CLIENT closed"); break
            if data[0] == 0x10:                       # realm-list request
                if phase["p"] != "realm":
                    say("client requested realm list - rewriting from here on")
                phase["p"] = "realm"
            srv.sendall(data)
    except OSError as e:
        say("CLIENT relay stopped: %s" % e)
    finally:
        for s in (cli, srv):
            try: s.shutdown(socket.SHUT_RDWR)
            except OSError: pass


def auth_server_to_client(srv, cli, phase):
    buf = b""
    try:
        while True:
            data = srv.recv(65536)
            if not data:
                say("SERVER closed"); break
            if phase["p"] != "realm":
                cli.sendall(data)                     # pass auth responses untouched
                continue
            buf += data
            out = b""
            while len(buf) >= 3 and buf[0] == 0x10:
                size = struct.unpack_from("<H", buf, 1)[0]
                if len(buf) < 3 + size:
                    break                             # wait for the rest of the frame
                payload = buf[3:3 + size]
                buf = buf[3 + size:]
                new = rewrite_realm_addresses(payload)
                out += b"\x10" + struct.pack("<H", len(new)) + new
                if len(new) != len(payload):
                    say("realm list rewritten: %d -> %d payload bytes (%d realms mapped)"
                        % (len(payload), len(new), len(addr_map)))
            if out:
                cli.sendall(out)
            if buf and buf[0] != 0x10:
                cli.sendall(buf); buf = b""           # anything unexpected: pass through
    except OSError as e:
        say("SERVER relay stopped: %s" % e)
    finally:
        for s in (srv, cli):
            try: s.shutdown(socket.SHUT_RDWR)
            except OSError: pass


def serve():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", AUTH_LISTEN))
    srv.listen(4)
    say("auth relay on 127.0.0.1:%d -> %s:%d" % (AUTH_LISTEN, REAL_AUTH[0], REAL_AUTH[1]))
    say("point the client's realmList at 127.0.0.1:%d, log in MANUALLY, pick a realm, enter world"
        % AUTH_LISTEN)
    n = 0
    while True:
        cli, addr = srv.accept()
        nodelay(cli)
        n += 1
        say("")
        say("=" * 60)
        say("auth connection %d from %s:%d" % (n, addr[0], addr[1]))
        try:
            up = socket.create_connection(REAL_AUTH, timeout=15)
            nodelay(up)
        except OSError as e:
            say("could not reach the auth server: %s" % e)
            cli.close(); continue
        phase = {"p": "auth"}
        threading.Thread(target=auth_client_to_server, daemon=True, args=(cli, up, phase)).start()
        threading.Thread(target=auth_server_to_client, daemon=True, args=(up, cli, phase)).start()


if __name__ == "__main__":
    try:
        serve()
    except KeyboardInterrupt:
        say("stopped")
