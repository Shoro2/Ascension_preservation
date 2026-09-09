# -*- coding: utf-8 -*-
"""The two TCP ports the Ascension archive stack binds, in one place.

THE WORLD PORT IS NOT FREE TO CHOOSE.  Read this before changing it.
=====================================================================
Extensions.dll ships a hard-coded allow-list of 91 "host:port" endpoint
strings (plaintext, .rdata file offset 0xB5FF5C.., vector<std::string> at
Extensions.dll+0xD3D708).  After the world handshake Ascension.exe formats
the endpoint it actually connected to into its BSS at 0x00C79C9E with
"%d.%d.%d.%d:%u", and Extensions.dll+0xA3C950 searches the list for it.
Miss the list and it arms a kill-switch that is *itself buggy* -- it rewrites
only 3 of the 7 bytes of the per-frame tick at 0x00403340, leaving a `call`
with no displacement, so the next frame jumps to unmapped memory and the
client dies with ERROR #132 at a fixed EIP of 0xCD0CA1xx a few seconds after
the world draws.  See TROUBLESHOOTING.md entry (3).

The only loopback endpoints on that list are:

    127.0.0.1:8085      <-- AzerothCore's default WorldServerPort; taken
    127.0.0.1:8087      <-- what we use
    127.0.0.1:8088      <-- spare

Anything else -- 8095, a MITM relay on 8813, whatever -- crashes on entry.
That is why the archive world CANNOT simply be moved to a free high port to
get out of AzerothCore's way, which is what broke it on 2026-09-01 at 19:26.

Why the archive moves at all: 8085 is AzerothCore's default and every realm
profile in this hub (vanilla, SpellDraft, the AzerothCore Ascension profile)
uses it, so archive and realm were mutually exclusive -- whichever started
second died on "address already in use" and the archive could not be worked
on while a realm was being played.  8087 is on the client's allow-list AND
off AzerothCore's, so it satisfies both constraints.  The real realms keep
the stock triple 3724 / 8085 / 7878: their worldserver.conf, their auth DB
`realmlist` rows and their clients' realmlist.wtf are all untouched.

The auth port is never checked against the list -- only the world endpoint
reaches 0x00C79C9E -- so 3799 (ours, vs AzerothCore's 3724) is fine.

Why a module and not two literals: the world address has to agree across two
separate processes -- shim3799.py ADVERTISES it inside the realm list it serves,
world_server.py BINDS it -- and a mismatch there fails as a client that logs in
fine and then hangs forever at "Connecting", which looks nothing like a port
number typed once.
"""

import os

HOST = "127.0.0.1"
AUTH_PORT = 3799        # shim3799.py.  The client's realmlist.wtf must name it
                        # explicitly -- a bare "127.0.0.1" dials 3724 and fails.

# Two world servers can answer the client, and the realm list decides which one
# it dials, so the choice has to be made in ONE place that both processes read:
#
#   8087  world_server.py     -- the Python reimplementation.  Owns character
#                                creation, the Character Advancement stack and
#                                every Ascension-custom opcode, but has no world.
#   8088  ascension_bridge.py -- translates onto AzerothCore (server-ascension,
#                                port 8086), which has the actual 155k creature
#                                spawns, gossip, vendors, trainers and quests.
#
# Set ASC_WORLD_PORT to switch.  Restart shim3799.py after changing it -- the
# port is baked into the realm list it serves, and a client that already has the
# old list will keep dialling the old port until it returns to the login screen.
BRIDGE_PORT = 8088
PY_WORLD_PORT = 8087

WORLD_PORT = int(os.environ.get("ASC_WORLD_PORT", PY_WORLD_PORT))
if WORLD_PORT not in (8085, 8087, 8088):
    raise SystemExit(
        "ASC_WORLD_PORT=%d is not on the client's endpoint allow-list; only "
        "8085, 8087 and 8088 are. See the note above -- anything else crashes "
        "the client with ERROR #132 seconds after the world draws." % WORLD_PORT)

REALM_ADDR = "%s:%d" % (HOST, WORLD_PORT)
