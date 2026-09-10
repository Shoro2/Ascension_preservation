# Handoff — setting this archive up on a fresh machine

> **Authentication update (2026-09-09): AuthGate is now the default.** Follow the
> [current original-client guide](../HOW-THE-REDIRECT-WORKS.md) and
> [AuthGate package](../../contrib/AscensionAuthGate/README.md) for login and launch.
> The shim-on-3799, permissive-password and standalone-world boot steps below
> are historical alternatives. Keep this handoff for its data/core prerequisites
> and research; do not use its old auth steps as the default.

This is the maintainer's reply to a handoff written by someone standing the
archive up from this repository on their own PC, whose session died about five
seconds after world entry. It is written for their AI assistant to consume
directly. Everything it answers is now also fixed or documented in the repo, so
the next person does not need to ask.

Section numbers below mirror the incoming handoff (§4 blocker, §5 layout deltas,
§6 questions) so it can be read side by side.

---

## 0. TL;DR — what to do right now

1. `git pull`. The fix for the +5 s death is in `server/world_server.py`
   (`sock_sendall`, see §4.1). Delete any copies of `world_server.py`,
   `shim3799.py`, `archive_ports.py`, `ascension_x25519_m2.py`, `chardata.py`
   and the seed JSON you moved around; the shipped layout now runs as-is.
2. Extract the two CA DBCs the world server needs from `patch-M.MPQ` into
   `server/rexxar-reference/ca-dbc/` (or point `ASC_CA_REF` at wherever you put
   them). They are `.dbc` and are deliberately not in the repo. Without them the
   server boots but hands out no essence (§5.4).
3. Start the world server. It now prints a **resolved-path report** at boot:
   every path it will read, `ok` or `MISSING`, plus the three env overrides. Fix
   anything `MISSING` before launching the client.
4. Launch the client fresh (not a reconnect) and log in. If the session survives
   a couple of minutes in-world you are past the blocker.

The full runbook stays in `HANDOFF-ARCHIVE-SESSION.md` §2; the corrections to it
are in §5 below and have been folded into `HOW-THE-REDIRECT-WORKS.md`.

---

## 4. The blocker — `handler error TimeoutError('timed out')`

### 4.1 Your diagnosis is correct, and the fix is now in the tree

The trace you sent is exactly what the old code produces:

```
05:22:05 w001: <- CMSG_QUERY_TIME                  (0 B body)
05:22:05 w001: handler error TimeoutError('timed out')
```

Mechanism, confirmed by reading CPython's `sock_sendall`: a socket timeout set by
`settimeout()` binds **every** blocking operation on that socket, including
`sendall()`. `handle_client()` sets `conn.settimeout(ARCHIVE_AURA_TICK_MIN)`
(0.1 s) so that `recv()` doubles as the idle tick, and `send_pkt` /
`send_batch` called `conn.sendall()` on the same socket with nothing around them.
Any write that cannot drain into the kernel send buffer inside 100 ms raised
`socket.timeout` (a `TimeoutError` subclass on 3.10+), and `send_pkt` logs
*after* the send returns, so the outbound line is missing from the log. The
exception is uncaught in `handle_client()` and lands in `main()`'s
`handler error %r`, which closes the socket. Everything you wrote about it is
right.

The fix is the "separate send deadline" option from your question 2:

```python
ARCHIVE_SEND_TIMEOUT = 30.0   # a send deadline, distinct from the 0.1 s recv poll

def sock_sendall(conn, buf):
    """conn.sendall(buf) with the send deadline, restoring the poll timeout after."""
    prev = conn.gettimeout()
    if prev is None or prev >= ARCHIVE_SEND_TIMEOUT:
        conn.sendall(buf)
        return
    conn.settimeout(ARCHIVE_SEND_TIMEOUT)
    try:
        conn.sendall(buf)
    finally:
        conn.settimeout(prev)
```

`send_pkt` and `send_batch` now go through `sock_sendall`. Nothing else changed:
the 0.1 s poll on `recv` is still what drives `_idle()`, so aura ticks and the
10 s `SMSG_TIME_SYNC_REQ` cadence are untouched. Thirty seconds is deliberately
generous: a client that has not read its socket for 30 s is gone, and closing
the session then is correct.

Why not a selector or a retry loop: `handle_client` is one synchronous thread
per session and every send is followed by a log line that assumes the bytes
went out. Swapping the socket for a non-blocking selector would touch every
handler; a retry-on-timeout wrapper would re-enter `sendall` with a partially
written buffer, which `sendall` does not support (you cannot know how much went
out). Raising the deadline only around the write is the smallest change that is
also correct.

### 4.2 Proof without a client

`tools/test_send_timeout.py` (new) reproduces the failure and the fix with no
client: it puts a socketpair in the exact state `handle_client` uses (0.1 s
timeout), fills the kernel send buffer, has the fake client refuse to read for
1.5 s, then sends one framed `SMSG_QUERY_TIME_RESPONSE`:

```
old: conn.sendall            buffered=2818048 B  TimeoutError('timed out') after 0.10s
new: sock_sendall            buffered=2818048 B  sent after 1.50s; poll timeout restored=True
PASS: old path dies with TimeoutError, sock_sendall survives a 1.5s client stall
```

Run it from `server/` (`python ../tools/test_send_timeout.py`; the buffered byte count
is whatever your kernel accepts and will differ). The pre-existing
`tools/test_world_offline.py` fails at import on this tree for an unrelated
reason (`struct.error` in a float pack); it did before this change and is not a
regression.

### 4.3 Honest answer to question 1: no, we never saw this line

Our world logs and session records do not contain `handler error
TimeoutError('timed out')`. The in-world disconnects we *did* hit and fix were:

| When | Cause | Fix (already shipped) |
|---|---|---|
| +31 s | client expected a periodic time-sync | `SMSG_TIME_SYNC_REQ` re-sent every 10 s on `CMSG_PING` |
| ~20 s (bridge route) | AzerothCore over-speed ping kick | `MaxOverspeedPings = 0` in `worldserver-bridge.conf` |
| ~10 min (bridge route) | Warden `0x2E6` kick | `Warden.Enabled = 0` |
| loading bar | CA-tree burst sent before the client could take it | deferred to `CMSG_SET_ACTIVE_MOVER` |

So the bug was real and latent in our tree; whether it fires depends on how long
*your* client stalls its socket after world entry, and that is a property of the
machine (disk speed while the addon suite loads, how much the 224 KB essence
burst backs up, CPU contention). On our box the client always drained within
100 ms. Do not read our silence as "it can't happen"; it happened to you, and
the test above shows the old code fails at exactly 0.10 s the moment the client
pauses.

### 4.4 Question 3: the reconnect that opens with `0x561`

```
05:23:03 w002: FIRST opcode 0x561 != CMSG_AUTH_SESSION -- non-stock opening. hdr=000c61050000
```

`0x561` is a known **client→server request stub**: body `00000000 01000000`,
12-byte frame, exactly the header you decoded. The name in
`reference/ascension_opcodes.json` (`SMSG_DRAFT_ROLL_RESULT`) comes from the
client's opcode table, and that table is direction-unreliable for custom ids;
several `SMSG_`-named entries are things the client *sends*. During a normal
in-world session the client emits `0x561` periodically and this server ignores
it. So the frame is being read correctly and the id is not being reused; you
were seeing a packet that is ordinary mid-session traffic arriving as the first
thing on a new TCP connection.

That happens because the client is trying to **resume** the dropped world
session, not re-authenticate. The Python world server does not support resuming:
there is no session table to resume into, and the ARC4 header crypt for a new
connection has to be re-keyed from a fresh `CMSG_AUTH_SESSION`. We never saw a
`0x561` opening because our sessions never died this way. It does not recover
and it is not meant to: **restart the client and log in again** (the shim
re-reads the session key from client memory at connect time, so a fresh login
is the resume path). With §4.1 applied the drop that triggers it should not
occur.

---

## 5. Your layout deltas — each one accepted, and what changed

Everything in §5 was right. The code now runs in the repository layout without
moving files, and the docs say what you found.

**5.1 MPQ tooling.** `mpqcat` and `mpqfind` are our own small StormLib programs.
Their sources and build scripts are now in `contrib/mpqtools/` with a README.
They need Visual Studio 2022 and a StormLib checkout (any recent StormLib
builds them; the include and lib paths are the only two things in the `.bat`
to edit). `tools/extract_ui.py` and `tools/extract_tree.py` now take `MPQCAT` /
`MPQFIND` from the environment so you can point them at either binary or at a
wrapper around your reader. **Yes, please share `mpq_extract.py`**: a pure-Python
reader with the PKWARE DCL exploder removes the compiler dependency entirely,
and `contrib/mpqtools/` is the place for it. Your archive-of-record table
(AccountLogin.lua in `patch-B`, the CA DBCs and `ChrClasses.dbc` in `patch-M`,
`Spell.dbc` in `patch-T`) matches ours and is now in the README there.

**5.2 `archive_ports` / `ascension_x25519_m2` / `chardata` under `tools/`.**
Both servers now append `../tools` (relative to their own file) to `sys.path`
when it exists. No copying. `tools/archive_ports.py` was also refreshed to the
current version (`world_port()` / `world_addr()` probe which world is
listening; the old module resolved the port at import time).

**5.3 Seed data read from `BASE` instead of `BASE\data`.** `world_server.py`
now has `DATA_DIR`: `<server>/data` if that directory exists, else `<server>`,
overridable with `ASC_DATA_DIR`. Every seed/state file (characters, account
data, default bindings, known entries, builds, action bars) is under it. Move
the JSON back into `server/data/`. The quiet `-- not seeding` failure you hit
is now loud: the boot path report lists `default-bindings.wtf` with `MISSING`.

**5.4 `SPELL_DBC` / `CHRCLASSES_DBC` resolved via `..\..\server-ascension`.**
Now `DBC_DIR`, overridable with `ASC_DBC_DIR`, defaulting to the old relative
location. Likewise the CA reference files: `CA_REF_DIR` (`ASC_CA_REF`) defaults
to `<server>/rexxar-reference`, and the two DBC names are accepted with or
without the `DBFilesClient_` prefix, so a file extracted as
`CharacterAdvancementEssence.dbc` works unrenamed. `entries.csv` is found in
either `rexxar-reference/ca-dbc-export/` or the shipped `data/ca-export/`.

What you must supply (all `.dbc`, all gitignored on purpose):

| Server constant | Default location | Source archive |
|---|---|---|
| `ESSENCE_DBC` | `server/rexxar-reference/ca-dbc/[DBFilesClient_]CharacterAdvancementEssence.dbc` | `patch-M.MPQ` |
| `CA_CLASSTYPES_DBC` | `server/rexxar-reference/ca-dbc/[DBFilesClient_]CharacterAdvancementClassTypes.dbc` | `patch-M.MPQ` |
| `CHRCLASSES_DBC` | `<ASC_DBC_DIR>/ChrClasses.dbc` | `patch-M.MPQ` |
| `SPELL_DBC` | `<ASC_DBC_DIR>/Spell.dbc` | `patch-T.MPQ` |

Your essence extraction (201,620 B = 20 + 5600 × 36) is byte-correct; that is
the file.

**5.5 `AccountLogin_OnShow` call site.** Correct, and now documented. The call
goes **after** the `if IsGMClient and realmList then ... end` block, because that
block does its own `SetCVar("realmList", ...)`. Our live glue has it at line 103,
after that block ends at line 98, which is what the "≈ line 103" in the doc was
pointing at without saying why. `HOW-THE-REDIRECT-WORKS.md` §2 now says it.

**5.6 The glue must be the whole file.** `contrib/AscensionRedirect/force-realm-glue.lua`
now says at the top, in capitals, that it is a snippet to paste into the
extracted stock file and not a drop-in, and its placeholder port is `3799` (it
said `3724`, which was the contributor's own port; the doc's `3799` was right).

**5.7 `realmName = "Area 52 - Free-Pick"`.** Correct and load-bearing.
`CharacterCreate.lua` gates `CanCreateArchetype` on the realm name string, and
`shim3799.py`'s `ARCHIVE_REALM_NAME` must match it. Keep it.

**5.8 Launch.** Correct on both counts. The `finally`-block trap is in
`HOW-THE-REDIRECT-WORKS.md` §3a; the wrapper is only for the maintainer's
attended runs.

**Ports (not in your list, but it bit the docs).** The Python world server's
default is **8087**, not 8085. The client's world-address allow-list (in
`Extensions.dll`) accepts only `127.0.0.1` on `8085`, `8087` or `8088`;
anything else crashes the client at the realm list. 8085 is AzerothCore's
default and is normally taken by a real realm on the maintainer's box, so the
archive uses 8087 (Python world) and 8088 (bridge). `archive_ports.py` is the
one place this is decided. The docs that said 8085 have been corrected.

---

## 6. AzerothCore questions

### Q4. Which AzerothCore, and are the binaries stock?

Not stock, and the README line "nothing is recompiled" was wrong; it is now
corrected. The worldserver behind the bridge is a **local MSVC build** of the
mod-playerbots fork:

| | |
|---|---|
| Repo | `https://github.com/mod-playerbots/azerothcore-wotlk.git` |
| Branch | `Playerbot` |
| Commit | `9fb906bb7296212ff42fc95ff73a92aaf8554f0d` (2026-08-21) |
| Modules compiled in | mod-playerbots, mod-ah-bot, mod-aoe-loot, mod-autobalance, mod-dk-talents, mod-dungeon-clear, mod-easy-respawn, mod-individual-progression, mod-junk-to-gold, mod-no-bot-achievements, mod-ollama-chat, mod-raid-roster, mod-shared-quest-loot, mod-solo-lfg |

None of those modules is needed for the archive. The bridge speaks stock
3.3.5a (build 12340) to the core, so **upstream `azerothcore-wotlk` `master`
with no modules will do**, stock release binaries included. If you build from
source on Windows, pin CMake 3.31 (not 4.x) and OpenSSL 3.5.x LTS; both newer
lines break the build in ways that look like your fault.

### Q5. Map data: from Ascension's MPQ chain, or a clean 3.3.5a client?

**Clean 3.3.5a client.** The `maps/`, `vmaps/` and `mmaps/` trees on this box
(5,744 / 12,494 / 3,780 files) are byte-identical across all three server
profiles, and they were produced once by the stock extractors against a stock
enUS 3.3.5a install. The extractors were **never run against Ascension's
`patch-C*` chain**, and you should not try: Ascension's custom zones and
terrain edits are in those archives, and the stock extractors will either choke
on the custom DBC shapes or produce maps the vanilla-DBC worldserver cannot
index. Custom content lives only in the DB on the bridge route. The
consequence is that Ascension-only zones are unwalkable on the bridge realm;
that is a known limitation, not a setup error.

### Q6. World DB setup and `worldserver-bridge.conf`

**`data/sanitized-for-core.json` is not world content, and `import-world.py`
does not read it.** The README and `data/MANIFEST.md` mislabelled it; both are
fixed. It is the changelog written by `tools/sanitize-for-core.py`: the 11,730
enum clamps it applied to Ascension's DBCs so the *standalone* worldserver could
load them (spell `Effect ≥ 165`, `ApplyAuraName ≥ 317`, achievement criteria
type `≥ 124`). You only need it if you run that standalone profile (Q7).

The DB the bridge realm actually plays on is built like this, all in `tools/`:

1. `clone-base.py`: copy `acore_world` and `acore_auth` **with data**, and
   `acore_characters` / playerbots **schema only**, into `asc_world`, `asc_auth`,
   `asc_characters`. So the base is a stock, fully populated AzerothCore world.
2. `seed-characters.py`: refill the fixed tables of `asc_characters` from the
   source SQL.
3. Overlay the recovered Ascension data (items, creatures + models, gameobjects
   + quest items, quests, page text, npc text) onto `asc_world` with
   **`tools/import_world.py` from
   [hertigservices/ascension-cache-consolidator](https://github.com/hertigservices/ascension-cache-consolidator)**.
   That is the public, portable importer: it reads the gzipped `cachedata/` in
   that repository directly (no unpacking, no `ASC_ARCHIVE`), takes the database
   name, host and user on the command line and the password by prompt or
   option file, finds `mysql` on `PATH`, previews before it writes, backs the
   tables up with `mysqldump`, and is a no-op when re-run:

   ```
   python -B tools/import_world.py --db asc_world --ask-password
   python -B tools/import_world.py --db asc_world --ask-password --apply
   python -B tools/import_world.py --db asc_world --source conquest-of-azeroth --ask-password --apply
   ```

   Its `docs/USING-THE-DATA.md` covers what the recovered records can and cannot
   make a realm do (an imported creature is a nameplate with no spawn, loot or
   faction; an imported item is complete) and the **client cache version**
   handshake — `worldserver.conf` `ClientCacheVersion` / `version.cache_id`
   must match the number in the client's `Cache\WDB` headers or the client
   deletes the installed caches at login. Pair it with that repository's
   `tools/install.py` on the client side.

   `import-world.py` in this repo's `tools/` is the private predecessor: it needs
   an unpacked harvest at `ASC_ARCHIVE`, has `MY = C:\AzerothRealm\mysql\bin\mysql.exe`
   hard-coded and reads credentials through `tools/ascreds.py`. Its quest field
   map (derived against the 9,454 quests both sides share) is what the public
   importer inherited; the trainer-list import is the one thing it does that the
   public tool does not yet.

`server/worldserver-bridge.conf`, beyond the three `CHANGEME_DB_PASSWORD`
lines, has these deliberate settings and you need all of them:

| Key | Value | Why |
|---|---|---|
| `WorldServerPort` | `8086` | the bridge's upstream; the client never sees it |
| `BindIP` | `"127.0.0.1"` | loopback only |
| `DataDir` | `"C:/AzerothRealm/server/Data"` | **vanilla** DBCs + maps (see Q7); change to your path |
| `LogsDir` | separate `logs-bridge` dir | keeps the bridge realm's logs apart |
| `Updates.EnableDatabases` | `0` | the `asc_*` clones must not be auto-migrated |
| `SOAP.Enabled` / `SOAP.Port` | `1` / `7879` | `.send items` and GM commands from tooling |
| `MaxOverspeedPings` | `0` | the client pings faster than stock; default kicks it at ~20 s |
| `Warden.Enabled` | `0` | Warden's `0x2E6` kicked the client at ~10 min |

`RealmID = 1`; make `asc_auth.realmlist` row 1 point at `127.0.0.1:8086` with
the name from §5.7.

### Q7. Does AzerothCore ingest Ascension's 209 k-row `Spell.dbc`?

**On the bridge route it never sees it.** `worldserver-bridge.conf` runs with
the vanilla `DataDir`, so the core loads stock `Spell.dbc` (49 k rows) and the
Ascension client, which carries its own `Spell.dbc` in `patch-T.MPQ`, tolerates
spell ids the server does not know. That is why the bridge realm "just works"
for entering and playing the vanilla world.

`fix-dbc.py` and `sanitize-for-core.py` exist for the **other** profile, the
standalone `server-ascension` worldserver on 8085 with Ascension's 249 DBCs as
its `DataDir`:

- `fix-dbc.py` is lossless: `Spell.dbc` junk locale offsets, `WorldMapArea`
  `0xFFFFFFFF` rows, the `TaxiPathNode` gap. Without it the core refuses the
  files outright.
- `sanitize-for-core.py` is lossy: the enum clamps above. Without it the core
  asserts on the first out-of-range effect. Its record of what it changed is
  `data/sanitized-for-core.json`.

Ascension's `Spell.dbc` is 209,509 records × 234 fields × 936 B and loads fine
after both passes. Do not attempt that profile until the bridge realm is up;
it is more work for a world that still lacks the CoA server logic.

### Q8. Bridge on 8088 → core on 8086, and opcode translation

Yes, exactly that: `ascension_bridge.py` listens on 8088 (`ASC_BRIDGE_PORT`,
must stay in the 8085/8087/8088 allow-list) and connects to 8086
(`ASC_AC_PORT`). The bridge forwards opcodes verbatim; the translation it does
is body-level, and you inherit all of it by using the shipped file:

- **Widened bodies.** Ascension widened some stock packets; `0x266` / `0x267`
  are 10 bytes on this client, not 6. Forwarding them unchanged crashes the
  client inconsistently, which is why it took a while to find.
- **Realm flavour + `SMSG_REALM_INFO (0x9BC)`** injected after auth so the
  custom addons pass their loadability gate.
- **CoA mode** (`--coa` or `ASC_COA=1`): a character *is* a custom class via
  the `UNIT_FIELD_BYTES_0` class byte, so the bridge rewrites the class the core
  reports into the CoA carrier class the client expects, and serves the CA tree,
  essence and known-entries packets itself from `data/ca-export/`. Without
  `--coa` you get the real world with stock classes and no CoA panel.
- The two non-bugs in `docs/KNOWN-ISSUES.md` (a pump thread dying inside a log
  call reads as "the core never replied"; non-ASCII chat killing the session).

Two things to know before you file a bridge bug: any exception in a pump loop
kills that direction silently, so check the bridge log before the core; and a
leftover bridge process is reused by the launcher because helper identity is
the port, so kill it explicitly between config changes.

### Q9. Starting level and the "Unlocks at level 10" gate

There is a command: **`.level <n>`** (1–80) in the Python world server, persisted
to `characters.json`. `ARCHIVE_GM_LEVEL = 3` so a fresh account can use it. On
the bridge route the core's own `.level` works through the GM account.

Do **not** raise `ARCHIVE_NEW_CHAR_LEVEL` from 1. The archetype build chosen at
character creation is applied on first login only if the character is at
level 1 (that is how the live realm behaved and how the client expects it);
starting higher skips it and the new character has no build. Create at 1,
`.level 80`, then open the panel. `ARCHIVE_LEVEL = 80` is the display cap the
panel was measured against.

---

## 7. What changed in the repo for this handoff

| Path | Change |
|---|---|
| `server/world_server.py` | `sock_sendall` + `ARCHIVE_SEND_TIMEOUT` (§4.1); `DATA_DIR`, `CA_REF_DIR`, `DBC_DIR` with `ASC_DATA_DIR` / `ASC_CA_REF` / `ASC_DBC_DIR`; `../tools` on `sys.path`; boot path report |
| `server/shim3799.py` | `../tools` on `sys.path`; current `world_addr()` import |
| `server/ascension_bridge.py` | synced to the current bridge (CoA mode, widened bodies) |
| `tools/archive_ports.py` | current version (`world_port()` / `world_addr()`) |
| `tools/test_send_timeout.py` | new; the proof in §4.2 |
| `tools/extract_ui.py`, `tools/extract_tree.py`, `tools/ca_export.py` | paths from env (`MPQCAT`, `MPQFIND`, `ASC_CA_REF`) |
| `contrib/mpqtools/` | new; `mpqcat.cpp`, `mpqfind.cpp`, build scripts, README |
| `docs/KNOWN-ISSUES.md` | entries 6 (`TimeoutError`) and 7 (`0x561` opening) |
| `docs/HOW-THE-REDIRECT-WORKS.md` | port 8087 + allow-list; OnShow call after `IsGMClient`; whole-file glue |
| `README.md`, `data/MANIFEST.md` | port; `sanitized-for-core.json` described correctly; "nothing is recompiled" corrected; CA DBCs listed as bring-your-own |
| `contrib/AscensionRedirect/force-realm-glue.lua` | snippet warning; placeholder port 3799 |

If anything here disagrees with what your machine does, send the boot path
report and the first 60 lines of `world_server_log.txt` after world entry.
