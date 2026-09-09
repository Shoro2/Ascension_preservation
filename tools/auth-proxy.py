"""Sit between the Ascension client and the local authserver and record the wire.

The client reaches 127.0.0.1:3724 now, gets as far as LOGIN_STATE_AUTHENTICATING
and is then dropped by the server with no auth result code - not "unknown
account", not "incorrect password", just a closed socket.  A stock 3.3.5a client
(realms/ascension/check-login.py) is accepted by the same server on the same
port, so the difference is in what Ascension's client puts on the wire.

Nothing else can answer that: the authserver logs a malformed packet by closing
the connection, and connection.log only reports the client's own state machine.

Point the client's realmList at 127.0.0.1:<listen port> and this forwards every
byte to the real authserver, dumping both directions annotated.  The server is
not touched, restarted or reconfigured, and the proxy is transparent - if the
handshake would have worked it still works.

Usage:  python auth-proxy.py [listen_port] [server_host] [server_port]
        python auth-proxy.py 3799 127.0.0.1 3724
"""
import socket, struct, sys, threading, time

# Opcode names from apps/authserver/Server/AuthSession.cpp
CMD = {0x00: "AUTH_LOGON_CHALLENGE", 0x01: "AUTH_LOGON_PROOF",
       0x02: "AUTH_RECONNECT_CHALLENGE", 0x03: "AUTH_RECONNECT_PROOF",
       0x10: "REALM_LIST", 0x32: "XFER_INITIATE", 0x33: "XFER_DATA"}

# AuthResult, verbatim from apps/authserver/Authentication/AuthCodes.h
RESULT = {0x00: "SUCCESS", 0x03: "BANNED", 0x04: "UNKNOWN_ACCOUNT",
          0x05: "INCORRECT_PASSWORD", 0x06: "ALREADY_ONLINE",
          0x07: "NO_TIME", 0x08: "DB_BUSY", 0x09: "VERSION_INVALID",
          0x0A: "VERSION_UPDATE", 0x0C: "SUSPENDED", 0x0D: "NO_ACCESS",
          0x10: "PARENTAL_CONTROL"}

lock = threading.Lock()
out = None


def say(msg):
    line = "%s  %s" % (time.strftime("%H:%M:%S"), msg)
    with lock:
        print(line, flush=True)
        if out:
            out.write(line + "\n")
            out.flush()


def hexdump(data, indent="        "):
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hexed = " ".join("%02X" % b for b in chunk)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        say("%s%04X  %-47s  %s" % (indent, i, hexed, text))


def describe_client(data):
    """Annotate a client->server packet as far as it parses."""
    if not data:
        return
    op = data[0]
    say("    opcode 0x%02X %s, %d bytes total" % (op, CMD.get(op, "?"), len(data)))
    if op != 0x00 or len(data) < 34:
        return
    # error, size, gamename[4], version[3], build, platform[4], os[4],
    # country[4], timezone_bias, ip, srp_I_len, srp_I
    size = struct.unpack_from("<H", data, 2)[0]
    say("    declared body size    %d   (actual body %d)" % (size, len(data) - 4))
    say("    gamename              %r" % data[4:8])
    say("    version               %d.%d.%d" % (data[8], data[9], data[10]))
    say("    build                 %d" % struct.unpack_from("<H", data, 11)[0])
    say("    platform / os / lang  %r %r %r" % (data[13:17], data[17:21], data[21:25]))
    say("    timezone bias         %d" % struct.unpack_from("<i", data, 25)[0])
    say("    ip                    %d.%d.%d.%d" % tuple(data[29:33]))
    ilen = data[33]
    say("    account name length   %d" % ilen)
    if len(data) >= 34 + ilen:
        say("    account name          %r" % data[34:34 + ilen])
        extra = len(data) - (34 + ilen)
        if extra:
            say("    *** %d EXTRA BYTES after the account name ***" % extra)
            hexdump(data[34 + ilen:])
        else:
            say("    (no trailing bytes - matches the stock layout)")
    else:
        say("    *** packet is SHORTER than its own account-name length ***")


def describe_server(data):
    if not data:
        return
    op = data[0]
    say("    opcode 0x%02X %s, %d bytes" % (op, CMD.get(op, "?"), len(data)))
    if op in (0x00, 0x02) and len(data) >= 3:
        say("    result 0x%02X %s" % (data[2], RESULT.get(data[2], "?")))
    elif op == 0x01 and len(data) >= 2:
        say("    result 0x%02X %s" % (data[1], RESULT.get(data[1], "?")))


def pump(src, dst, label, describer, state):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                say("%s CLOSED the connection" % label)
                break
            state[label] = state.get(label, 0) + 1
            say("%s -> %d bytes (message %d)" % (label, len(data), state[label]))
            describer(data)
            hexdump(data)
            dst.sendall(data)
    except OSError as e:
        say("%s relay stopped: %s" % (label, e))
    finally:
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def serve(listen_port, server_host, server_port):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", listen_port))
    srv.listen(4)
    say("listening on 127.0.0.1:%d, forwarding to %s:%d"
        % (listen_port, server_host, server_port))
    say("point the client's realmList at 127.0.0.1:%d and log in" % listen_port)
    n = 0
    while True:
        client, addr = srv.accept()
        n += 1
        say("")
        say("=" * 70)
        say("connection %d from %s:%d" % (n, addr[0], addr[1]))
        try:
            upstream = socket.create_connection((server_host, server_port), timeout=15)
        except OSError as e:
            say("could not reach the authserver: %s" % e)
            client.close()
            continue
        state = {}
        threading.Thread(target=pump, daemon=True,
                         args=(client, upstream, "CLIENT", describe_client, state)).start()
        threading.Thread(target=pump, daemon=True,
                         args=(upstream, client, "SERVER", describe_server, state)).start()


def main(argv):
    global out
    listen_port = int(argv[0]) if argv else 3799
    host = argv[1] if len(argv) > 1 else "127.0.0.1"
    port = int(argv[2]) if len(argv) > 2 else 3724
    logname = argv[3] if len(argv) > 3 else "auth-proxy.log"
    import os
    out = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            logname), "a", encoding="utf8")
    try:
        serve(listen_port, host, port)
    except KeyboardInterrupt:
        say("stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
