r"""
Ascension client -> local server redirector (WinDivert / pydivert).

ORIGINAL PREMISE (kept for the record, and now only *partly* true)
------------------------------------------------------------------
    "The Ascension client dials a hard-coded/obfuscated portal IP for the auth
     server. Nothing on disk (Config.wtf, realmlist.wtf, hosts, launcher cache)
     changes that."

Config.wtf really does not hold -- that half was measured independently and is
correct: write 127.0.0.1 into Config.wtf, and by the time the login screen is up
the realmList CVar reads back as the portal address again. Something native
restores it after the file is parsed.

But there IS a disk-side answer, and it is one file: a LOOSE
`Interface\GlueXML\AccountLogin.lua` in the client root. The client prefers a
loose Interface file over the copy inside Data\patch-B.MPQ, glue Lua is the last
code that runs before ConnectToServer(), and Ascension's own realm dropdown
already drives the realm this exact way (AccountLoginDropDown_OnClick calls
SetCVar("realmList", ...)). Force the CVar there and the client dials wherever
you point it -- no admin, no kernel driver, no NAT.

See `force-realm-glue.lua` next to this file, and README.md §1.

SO WHY IS THIS SCRIPT STILL HERE?
---------------------------------
Two reasons, both real:

  1. As a capture/diagnostic tool. The hexdump of the first N data packets each
     way is genuinely useful, and it works without patching anything.

  2. Port remapping (--map, new here) is the *only* known way past a trap in
     the world-server step that will otherwise cost you a night. Extensions.dll
     compares the world endpoint STRING the client stored against a 91-entry
     plaintext allow-list in .rdata; only three loopback endpoints are on it:
     127.0.0.1:8085, :8087, :8088. Because the check is on the string the client
     wrote -- not on the socket's real peer -- you can let the client dial an
     allow-listed port and NAT the packets to any port you like. README.md §3.

USAGE
-----
    python redirect.py --real 192.168.1.50
    python redirect.py --real 192.168.1.50 --ports 3724 8085
    python redirect.py --real 127.0.0.1 --map 8087:9087        # see §3 caveats
    python redirect.py --real 192.168.1.50 --no-dump

Run from an ELEVATED terminal (WinDivert loads a kernel driver), THEN launch
the client. Ctrl+C to stop.
"""

import argparse
import ipaddress
import sys

try:
    import pydivert
except ImportError:
    print("pydivert not installed. Run:  python -m pip install pydivert")
    sys.exit(1)


# The portal IP the stock client hard-dials for auth. Not a personal setting --
# this is Ascension's own address, and it is the same value seen in independent
# captures of a live login, so it is a sane default.
DEFAULT_FAKE_IP = "51.210.230.10"


def parse_map(items):
    """--map 8087:9087  ->  {8087: 9087}"""
    out = {}
    for it in items or []:
        try:
            a, b = it.split(":", 1)
            out[int(a)] = int(b)
        except ValueError:
            raise SystemExit("bad --map %r (want CLIENTPORT:SERVERPORT)" % it)
    return out


def build_args():
    p = argparse.ArgumentParser(
        description="Redirect the Ascension client's hard-dialled endpoint to your own server.")
    p.add_argument("--real", required=True, metavar="IP",
                   help="your server's IP (e.g. 192.168.1.50, or 127.0.0.1 -- read the "
                        "loopback caveat in README.md before using 127.0.0.1)")
    p.add_argument("--fake", default=DEFAULT_FAKE_IP, metavar="IP",
                   help="the IP the client dials (default: %(default)s)")
    p.add_argument("--ports", type=int, nargs="+", default=[3724], metavar="P",
                   help="ports to redirect (default: 3724 = auth). Add the world port only "
                        "if a capture shows the client dialling --fake on it; normally the "
                        "auth server hands out the world address itself.")
    p.add_argument("--map", action="append", metavar="C:S", default=[],
                   help="EXPERIMENTAL, and untested by the author of this edit: also rewrite "
                        "the destination port, C -> S. Use to get past the world-endpoint "
                        "allow-list (README.md §3).")
    p.add_argument("--no-dump", action="store_true", help="do not hexdump payloads")
    p.add_argument("--dump-count", type=int, default=12, metavar="N",
                   help="hexdump the first N data packets each way (default: %(default)s)")
    return p.parse_args()


def hexdump(prefix, data):
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        hexpart = " ".join("%02x" % b for b in chunk)
        asciipart = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print("%s %04x  %-47s  %s" % (prefix, off, hexpart, asciipart))


def main():
    a = build_args()
    fake_ip, real_ip = a.fake, a.real
    ports = set(a.ports)
    portmap = parse_map(a.map)
    # server-side ports we must catch on the way back in
    server_ports = set(portmap.get(p, p) for p in ports)

    real_is_loopback = ipaddress.ip_address(real_ip).is_loopback

    dst_ports = " or ".join("tcp.DstPort == %d" % p for p in ports)
    src_ports = " or ".join("tcp.SrcPort == %d" % p for p in sorted(server_ports))
    flt = ("tcp and ("
           "(ip.DstAddr == %s and (%s)) or "
           "(ip.SrcAddr == %s and (%s))"
           ")" % (fake_ip, dst_ports, real_ip, src_ports))

    print("=" * 68)
    print(" Ascension redirector")
    print("   %s:%s  <==>  %s:%s" % (fake_ip, sorted(ports), real_ip, sorted(server_ports)))
    if portmap:
        print("   port map: " + ", ".join("%d->%d" % kv for kv in sorted(portmap.items())))
        print("   NOTE: --map is experimental. See README.md §3.")
    if real_is_loopback:
        print("   NOTE: --real is loopback; source rewriting is on. See README.md §2.")
        print("         If you are pointing at a server on THIS machine, you almost")
        print("         certainly want the glue-Lua method instead (README.md §1) --")
        print("         it needs no driver and no admin.")
    print("   Leave this window open. Ctrl+C to stop.")
    print("=" * 68)

    out_count = in_count = 0
    out_dumped = in_dumped = 0
    dump = not a.no_dump
    # For the loopback case only: remember each connection's original client
    # address so inbound packets can be put back the way the socket expects.
    origin = {}          # client tcp src port -> original client ip
    unmap = {v: k for k, v in portmap.items()}   # server port -> port the client dialled

    try:
        with pydivert.WinDivert(flt) as w:
            print("[redirect] WinDivert active. Launch the client and log in now.\n")
            for packet in w:
                # ---- client -> server -------------------------------------
                if packet.dst_addr == fake_ip and packet.dst_port in ports:
                    if real_is_loopback:
                        # A packet with src=<LAN ip> dst=127.0.0.1 is not
                        # deliverable; the source has to move to loopback too.
                        origin[packet.src_port] = packet.src_addr
                        packet.src_addr = real_ip
                    new_port = portmap.get(packet.dst_port, packet.dst_port)
                    old_port = packet.dst_port
                    packet.dst_addr = real_ip
                    if new_port != old_port:
                        packet.dst_port = new_port
                    out_count += 1
                    if out_count == 1 or out_count % 200 == 0:
                        print("[out] client -> %s:%d  =>  %s:%d  (#%d)"
                              % (fake_ip, old_port, real_ip, new_port, out_count))
                    if dump and out_dumped < a.dump_count and packet.payload:
                        out_dumped += 1
                        print("--- CLIENT->SERVER payload #%d (%d bytes) ---"
                              % (out_dumped, len(packet.payload)))
                        hexdump("  C>S", bytes(packet.payload))

                # ---- server -> client -------------------------------------
                elif packet.src_addr == real_ip and packet.src_port in server_ports:
                    # Undo the port map, so the client sees the port it dialled.
                    old_port = packet.src_port
                    new_port = unmap.get(old_port, old_port)
                    packet.src_addr = fake_ip
                    if new_port != old_port:
                        packet.src_port = new_port
                    if real_is_loopback:
                        client_ip = origin.get(packet.dst_port)
                        if client_ip:
                            packet.dst_addr = client_ip
                    in_count += 1
                    if in_count == 1 or in_count % 200 == 0:
                        print("[in ] %s:%d  =>  looks like %s:%d  (#%d)"
                              % (real_ip, old_port, fake_ip, new_port, in_count))
                    if dump and in_dumped < a.dump_count and packet.payload:
                        in_dumped += 1
                        print("--- SERVER->CLIENT payload #%d (%d bytes) ---"
                              % (in_dumped, len(packet.payload)))
                        hexdump("  S>C", bytes(packet.payload))

                w.send(packet)
    except KeyboardInterrupt:
        print("\n[redirect] stopped. rewritten out=%d in=%d" % (out_count, in_count))
    except OSError as e:
        print("\n[redirect] ERROR: %s" % e)
        print("[redirect] This must be run AS ADMINISTRATOR (WinDivert driver load).")
        sys.exit(1)


if __name__ == "__main__":
    main()
