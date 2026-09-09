"""Reproduce the +5 s session death and prove the fix, with no client.

A server-side socket is put in the session state handle_client() uses
(settimeout(ARCHIVE_AURA_TICK_MIN) = 0.1 s).  The peer -- standing in for the
Ascension client during its post-world-entry stall -- reads NOTHING for
STALL seconds.  We fill the send buffer, then send one small packet the way
the server sends SMSG_QUERY_TIME_RESPONSE:

  * raw conn.sendall()          -> TimeoutError after ~0.1 s   (the old code path)
  * world_server.sock_sendall() -> completes once the peer drains (the fix)

Run from the server directory (repo: server/) so world_server imports cleanly:
    cd server && python ../tools/test_send_timeout.py
"""
import os, socket, sys, threading, time

sys.path.insert(0, os.getcwd())
_SERVER = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "server")
if os.path.isdir(_SERVER):
    sys.path.insert(0, _SERVER)
import world_server as W

STALL = 1.5      # s the fake client refuses to read; > 0.1 s poll, < 30 s send deadline


def pair():
    srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)
    cli = socket.create_connection(srv.getsockname())
    conn, _ = srv.accept(); srv.close()
    conn.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
    cli.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
    conn.settimeout(W.ARCHIVE_AURA_TICK_MIN)          # exactly what handle_client sets
    return conn, cli


def fill(conn):
    """Stuff the socket until a 0.1 s-timeout write would block."""
    conn.setblocking(False)
    chunk = b"\0" * 65536; total = 0
    try:
        while True:
            total += conn.send(chunk)
    except BlockingIOError:
        pass
    conn.settimeout(W.ARCHIVE_AURA_TICK_MIN)
    return total


def drain_later(cli, after):
    def run():
        time.sleep(after)
        try:
            cli.setblocking(True)
            while cli.recv(1 << 20):
                pass
        except OSError:
            pass          # the old-path trial closes the pair before we get here
    t = threading.Thread(target=run, daemon=True); t.start(); return t


def trial(label, send):
    conn, cli = pair()
    buffered = fill(conn)
    drain_later(cli, STALL)
    pkt = W.frame_pkt(None, W.SMSG_QUERY_TIME_RESPONSE, W.smsg_query_time_response())
    t0 = time.monotonic()
    try:
        send(conn, pkt)
        outcome = "sent after %.2fs; poll timeout restored=%s" % (
            time.monotonic() - t0, conn.gettimeout() == W.ARCHIVE_AURA_TICK_MIN)
    except (socket.timeout, TimeoutError) as e:
        outcome = "%r after %.2fs" % (e, time.monotonic() - t0)
    finally:
        cli.close(); conn.close()
    print("%-28s buffered=%6d B  %s" % (label, buffered, outcome))
    return outcome


old = trial("old: conn.sendall", lambda c, b: c.sendall(b))
new = trial("new: sock_sendall", W.sock_sendall)
assert "timed out" in old, "the old path should reproduce the failure"
assert new.startswith("sent after") and "restored=True" in new, new
print("PASS: old path dies with TimeoutError, sock_sendall survives a %.1fs client stall" % STALL)
