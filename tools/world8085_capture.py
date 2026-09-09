"""Passive world-port capture: bind 127.0.0.1:8085 and log what the Ascension client
sends when it tries to connect to the realm's world server.

READ-ONLY DIAGNOSTIC -- no RPM, no client writes, no handshake attempt. It only:
  * confirms the client actually dials 8085 (i.e. it parsed & used the realm address), and
  * reveals who speaks first on the world channel (WoW world proto is normally
    SERVER-speaks-first: server sends SMSG_AUTH_CHALLENGE, then the client replies).
This does NOT implement a world server; it just observes the opening move so Phase 2
can be planned. Loopback accepts work across integrity levels, so this need not be elevated.
"""
import socket, os, time

BASE = os.path.dirname(os.path.abspath(__file__))
LOG = os.path.join(BASE, "world8085_log.txt")

def log(msg):
    line = "[%s] %s" % (time.strftime("%H:%M:%S"), msg)
    print(line, flush=True)
    try:
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass

def main():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(("127.0.0.1", 8085))
    except OSError as e:
        log("BIND FAILED on 8085: %r  (is a world server already listening there?)" % e)
        return
    srv.listen(8)
    log("=" * 60)
    log("world capture listening on 127.0.0.1:8085   log-> %s" % LOG)
    log("Now click the realm [Ascension-Local] in the client.")
    cid = 0
    while True:
        conn, addr = srv.accept()
        cid += 1
        log("w%03d: WORLD connection from %s -- client DID reach 8085 (address parsed OK)" % (cid, addr))
        conn.settimeout(3.0)
        first = b""
        t0 = time.time()
        while time.time() - t0 < 4.0:
            try:
                b = conn.recv(4096)
            except socket.timeout:
                break
            except OSError:
                break
            if not b:
                break
            first += b
            if len(first) >= 8192:
                break
        if first:
            log("w%03d: client sent %dB FIRST: %s" % (cid, len(first), first.hex()))
            try:
                dump = os.path.join(BASE, "world_first_w%03d.bin" % cid)
                with open(dump, "wb") as f:
                    f.write(first)
                log("w%03d: saved -> %s" % (cid, dump))
            except Exception:
                pass
        else:
            log("w%03d: client sent NOTHING in 4s -> SERVER-SPEAKS-FIRST world protocol "
                "(client waits for SMSG_AUTH_CHALLENGE). Reaching 8085 is confirmed." % cid)
        try:
            conn.close()
        except OSError:
            pass

if __name__ == "__main__":
    main()
