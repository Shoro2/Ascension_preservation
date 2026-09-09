# Ascension archive realm

> **Hit an error?** Check `TROUBLESHOOTING.md` at the hub root first — it is the
> symptom-indexed ledger of every failure this hub has hit and the fix that ended
> it. Solve something new, add it there the same day.

A local, single-player rebuild of Project Ascension, which shuts down 2026-09-04.
It runs the **stock AzerothCore binaries** — nothing was recompiled — against the
**Ascension client's own DBCs** and a world database rebuilt from the client
caches harvested into `ascension-archive/`.

Status: **the world boots and the realm is live.** `World Initialized In 0
Minutes 38 Seconds`, no crash reports, authserver on 3724, worldserver on
8085/7878, all bound to 127.0.0.1. The launcher lists it as active / serverUp /
ready. It has not yet been played — see [Open items](#open-items).

---

## Layout

| Path | What it is |
| --- | --- |
| `server-ascension/` | Copy of the vanilla server tree; **its own** `Data/dbc` (245 files from the client's MPQs) and `configs/` |
| `server-ascension/Data/{maps,vmaps,mmaps}` | Junctions to the vanilla server's — terrain is unchanged, so it is not duplicated |
| `client-ascension/` | Junction to `C:\Ascension\Launcher\resources\ascension-live` — the 43 GB client is not copied |
| `realms/ascension/` | Everything in this directory: the build tooling and this file |
| `tools/launch-ascension.vbs` | What the launcher's Ascension tile runs |

Databases: `asc_auth`, `asc_world`, `asc_characters`, `asc_playerbots`, reached
as MySQL user **`ascore`**. That user has no grant on `acore_*`; the grant, not
the separate directories, is what fences this realm off from the progression
realm's data.

---

## How the client is redirected

**The Electron launcher never sets the realm, so there is nothing in it to
hook.** Grepping the whole `app.asar` — including the bytenode-compiled
`main.jsc` — for `realmlist`, `realmList` or `Config.wtf` returns zero hits.
`Ascension.exe` itself carries the stock 3.3.5a strings (`realmlist.wtf`,
`Config.wtf`, `realmList`, "Address of realm list server"). The launcher is also
useless offline: it authenticates against `https://api.ascension.gg/api`, which
dies with the service.

So the launcher is bypassed and the client is pointed at the local realm the way
the client itself does it:

- `Data/enUS/realmlist.wtf` is **deliberately neutered by Ascension** — exactly
  13 bytes, the literal `set realmlist` with no value — so it cannot override
  anything. It is left untouched.
- `WTF/Config.wtf` is where the real value lives. `launch-client.ps1` rewrites
  only its `realmList` and `realmName` lines, launches the client, waits, and
  restores the file in a `finally` block.
- The first run copies the untouched file to `Config.wtf.ascension-official`
  and **never refreshes it** — that backup is the surviving record of what the
  live service's realm list looked like.

The client writes that file as BOM-less, LF-terminated ASCII, so the script
writes bytes directly (`UTF8Encoding($false)`) rather than using
`Set-Content -Encoding utf8`, which would add a BOM and CRLFs. Verified: after
`-Restore` the file is byte-identical to the backup (SHA-256 match, 939 bytes,
no BOM, zero CR bytes).

```powershell
# point the client at the local realm, launch it, restore on exit
powershell -File realms\ascension\launch-client.ps1
# rewrite the realm lines but do not launch (what the byte checks used)
powershell -File realms\ascension\launch-client.ps1 -NoLaunch
# put the official realm list back by hand
powershell -File realms\ascension\launch-client.ps1 -Restore
```

### No UAC prompt

`Ascension.exe` ships a manifest asking for `requireAdministrator`, so every
launch used to raise a consent dialog. The client does not need those
privileges - it writes only inside `client-ascension` (WTF, Cache, Logs), which
the user owns - so `launch-client.ps1` sets `__COMPAT_LAYER=RunAsInvoker` on
its own process before starting the client. That is a process-scoped
environment variable: **nothing is written to the registry and the binary is not
patched**, and it is gone when the script exits.

`Start-Process` also gained `-NoNewWindow`, which is the safety half of the
pair. It makes PowerShell call `CreateProcess` instead of `ShellExecute`, and
`CreateProcess` *cannot* show a consent dialog - so if the shim ever stops
applying, the launch fails loudly with error 740 ("requires elevation") instead
of quietly going back to prompting.

Measured, with a control, on a purpose-built exe carrying the identical
manifest:

```
control: no shim   -> BLOCKED: native error 740 - The requested operation requires elevation
__COMPAT_LAYER     -> started, output: running; elevated=False
```

and then end to end through the launcher's own `tools/launch-ascension.vbs`:

```
launched via the launcher's own vbs -> pid 20808 : not elevated
UAC consent.exe processes present: 0
```

### Config.wtf alone does not redirect the client - measured 2026-08-29

**Everything above about `Config.wtf` is true and still does not redirect the
client.** It reads the file (it writes `showToolsUI` and `fogOverride` back into
it on a clean exit) and then dials the official realm anyway. From
`client-ascension/Logs/connection.log`, with `SET realmList "127.0.0.1"` in the
file at the moment the process started:

```
GRUNT: state: RESPONSE_CONNECTED result: LOGIN_OK 51.210.230.10:3724
```

Ruled out, one at a time:

| tried | result |
| --- | --- |
| `SET realmList "127.0.0.1"` in `Config.wtf` | dialled 51.210.230.10 |
| `SET realmList "10.99.99.99"` (bogus, to catch a stale read) | dialled 51.210.230.10 |
| `-realmlist 127.0.0.1` on the command line | dialled 51.210.230.10 |
| something rewriting the file behind us | no - polled every 1.5 s through a
  whole launch, the line stayed `127.0.0.1` |
| the address hard-coded in the binaries | no - `51.210.230.10` appears nowhere
  in `Ascension.exe` or `Extensions.dll`, as text, as packed bytes, or under any
  single-byte XOR |

**Where it really comes from - and it is not the network.** Two measurements
settle it.

With Wi-Fi and Ethernet both disabled, the login screen still showed our
`realmName` ("Ascension Archive", straight out of our `Config.wtf`) and still
refused to use our `realmList`:

```
GRUNT: state: LOGIN_STATE_CONNECTING result: LOGIN_OK
GRUNT: state: LOGIN_STATE_FAILED result: LOGIN_SERVER_DOWN     (4 ms later)
```

The local authserver was up and accepting on 127.0.0.1:3724 throughout, so the
client did not dial it. It does not fall back to the local `realmList` even with
no network at all.

Then glue Lua was made to report the CVar directly (see the loose
`AccountLogin.lua` below). With `SET realmList "127.0.0.1"` in `Config.wtf` at
the moment the process started, at the login screen:

```
ASCARCHIVE realmList cvar before = 51.210.230.10
```

So the value is **restored in memory after the file is parsed**, by the client
itself, offline, before a key is pressed. `realmName` from the same file is left
alone - only `realmList` is put back. The launcher's HTTP cache
(`%APPDATA%/projectascension/Cache/Cache_Data/data_2`) does hold the same pair
as a cloud-synced CVar set, but the offline run proves that cache is a copy of
this behaviour, not its cause.

An earlier draft of this section concluded the address was server-side account
state fetched at runtime. The offline test disproves that; it is local.

Two things this does *not* break:

- The client still speaks **stock GRUNT/SRP6** - `LOGIN_STATE_AUTHENTICATING`,
  `CHECKINGVERSIONS`, `HANDSHAKING`, `AUTHENTICATED` - so an AzerothCore
  authserver is the right shape of thing to point it at.
- **Autologin arguments work**, and they are the launcher's own:
  `-login <account> -password <token>` (found in `app.asar`; the launcher passes
  a game auth token, not the site password). `C_Config` in `Extensions.dll`
  names the rest: `config controller gxWindow realm realmName login password
  autologin renderdebug character realmList`.

  **But autologin cannot be redirected.** It is native and does not go through
  glue Lua: with `-login/-password` the client dialled at `23:25:53.262` while
  `AccountLogin_OnShow` had not yet run, and `AccountLogin_Login` - which is
  what the Login button calls - was never entered at all. `launch-client.ps1`
  therefore passes no autologin arguments.

### The fix - a loose `AccountLogin.lua`

`Data\patch-B.MPQ` is the only archive in the client that carries any of
`GlueXML.toc`, `FrameXML.toc`, `AccountLogin.lua` or `RealmList\RealmList.lua`,
and **the client prefers a loose `Interface\` file over the MPQ copy**. That was
measured, not assumed - a probe copy logged `loose AccountLogin.lua IS ACTIVE`
through `C_Logger.LUA` into `Logs/LUA.txt`.

So `client-ascension\Interface\GlueXML\AccountLogin.lua` is a loose copy of the
archived file that forces the CVar:

```lua
ASCENSION_ARCHIVE_REALMLIST = "127.0.0.1";   -- launch-client.ps1 rewrites this
```

`AscensionArchive_ForceRealm()` is called twice - from `AccountLogin_OnShow`,
and from `AccountLogin_Login` immediately before `ConnectToServer()`, so that
anything restoring the address in between is overruled. This is exactly the
mechanism Ascension's own realm picker uses: `AccountLoginDropDown_OnClick`
calls `SetCVar("realmList", self.value)` and lets the engine dial it. (That
dropdown is dead on this build - `RealmChoices` is initialised to `{}` and
nothing ever fills it.)

Nothing in the archive is modified. `Data\patch-B.MPQ` and the binaries are
untouched, and **deleting the loose file restores stock behaviour exactly**.
`launch-client.ps1 -Restore` does the softer version: it blanks the address, at
which point `AscensionArchive_ForceRealm()` returns without touching anything.

Two dead ends ruled out along the way, both worth not re-walking:

- `Data\enUS\realmlist.wtf` is a 13-byte stub, the literal text `set realmlist`
  with no value, dated 2024. It overrides nothing.
- `GetLastAccount()` returns `account=ADMIN realmList=nil`, and `IsGMClient` is
  `nil`, so the `SetCVar("realmList", ...)` at `AccountLogin.lua:56-59` - which
  looks exactly like the culprit - never executes.

`WTF\Custom\*.json` (`GlueConfig.json`, `MysticEnchantSaved.json`,
`NewCharacterSetup.json`) are written by `WriteCustomWTF`/`ReadCustomWTF` in
`Extensions.dll` and are obfuscated - all three begin `Jr`, over an alphabet of
letters, digits and `()`. It is not LibDeflate `EncodeForPrint`; six alphabet and
bit-order combinations were tried and none inflates. `GlueConfig.json` is
rewritten 43 ms after a login attempt. Undecoded, and not needed for the
redirect.

The client reports build **12340**, and `asc_auth.realmlist` is `127.0.0.1:8085`
with `gamebuild 12340`, so the auth build check passes unmodified.

---

## The four things that had to be repaired

All four were found the same way, and none is visible by comparing field counts
and record sizes — every one of these files looks identical in shape to
vanilla's. **The crash report is the fast path:**
`server-ascension/Crashes/*.txt` carries a symbolised stack with source file and
line, and each boot failure named its own culprit.

Two rules made the difference between diagnosing and guessing:

1. **Always run the same check against the stock `server/Data/dbc` as a
   control.** A rule that fires on vanilla is a wrong rule, because vanilla data
   demonstrably loads. This killed 13 false positives on the first pass.
2. **Read the core's source for the frame in the stack**, rather than reasoning
   about what a DBC "should" contain.

### Lossless — `fix-dbc.py`

| # | File | Problem | Repair |
| --- | --- | --- | --- |
| 1 | `Spell.dbc` | 7,029 of the seven unused locale slots of SpellName/Rank hold junk. The client never reads them; the core reads every locale column its format declares and walks off the string block — `ASSERT(stringOffset < file.stringSize)`, `DBCFileLoader.h:75` | Point each out-of-range offset at the string block's final NUL, so the column reads as the empty string. No size changes, no other offset moves |
| 2 | `WorldMapArea.dbc` | 25 rows with an id of `0xFFFFFFFF`. `AutoProduceData` sizes its lookup table as *(max id + 1)*, that addition overflows to zero, and the next line writes through the zero-length table — `DBCFileLoader.cpp:231` | Drop the rows. An id of `0xFFFFFFFF` cannot be looked up by anything, so they are unreachable data, not content (310 → 285) |
| 3 | `TaxiPathNode.dbc` | Path 1984 numbers its nodes 1–29 instead of 0–28. `DBCStores.cpp:585` sizes each path's vector as *(highest index + 1)* and fills it by index, leaving a null in the middle; the first walk over every node dereferences it at `ObjectMgr.cpp:6294` | Renumber that path's nodes contiguously from zero, keeping their order. `index` is an ordinal used only for sequencing the flight |

Vanilla has **zero** of all three. `.orig` backups sit beside each rewritten file.

### Lossy — `sanitize-for-core.py`

Ascension extended several client enums past the fixed-size arrays these
binaries compile against, and the core turns those values straight into array
subscripts. This is the one place fidelity is actually lost, which is why it is
a separate tool with a separate manifest.

| File / bound | Read from | Limit | Found | Action |
| --- | --- | --- | --- | --- |
| `Spell.dbc` Effect ≥ `TOTAL_SPELL_EFFECTS` | `SharedDefines.h` | 165 | 6,536 slots | set to 0 |
| `Spell.dbc` ApplyAuraName ≥ `TOTAL_AURAS` | `SpellAuraDefines.h` | 317 | 5,149 slots | set to 0 |
| `Achievement_Criteria.dbc` requiredType ≥ `ACHIEVEMENT_CRITERIA_TYPE_TOTAL` | `DBCEnums.h` | 124 | 45 rows | drop the row |

Every bound is parsed out of the core's own header rather than hard-coded, so
the numbers follow the tree if it is ever patched. Vanilla returns 0 hits on all
three rules.

- **What this costs:** 10,359 of 209,509 spells (**4.94%**) lose their
  Ascension-specific effect or aura in at least one slot. They keep their name,
  cost, range, icon and other effects — only the slot the core cannot represent
  goes quiet. 31 custom spell effects and 44 custom auras are involved.
- **The achievement rows have no neutral value** — a criterion with its type
  zeroed would still be evaluated, as type 0, and would silently corrupt an
  unrelated achievement — so those 45 are dropped instead. Values seen: 131,
  133, 134, 136, none of which exist in vanilla.
- **Everything is recorded.** `sanitized-for-core.json` (183 KB) holds
  `[rowId, field, originalValue]` for all 11,730 changes, so the whole set can
  be put back the day these enums are widened and the core rebuilt.

### Not a problem, despite appearances

- **`fieldCount != strlen(format)`** is survivable: `AutoProduceData` bails,
  `storage.Load()` fails, and `LoadDBC` falls back to `storage.LoadFromDB()`.
  Every stock `gt*.dbc` is in this state on a healthy server. *(It does mean
  Ascension's `gt*` values are ignored in favour of the vanilla world tables —
  see Open items.)*
- **A `recordSize` mismatch** is harmless: `DBCFileLoader` never checks it and
  reads every field through `fieldsOffset`. Stock `PowerDisplay.dbc` is like
  this.
- **DBC file-side field sizes:** `b` and `X` are 1 byte; **every other format
  character, `d` and `x` included, is 4 bytes.** `GetFormatRecordSize` treats
  `d` as 0 only for the destination struct, not the file.

---

## The database side

`clone-base.py` cloned the vanilla databases into `asc_*`, opening the sources
read-only (`mysqldump` only — nothing here writes to `acore_*`). World and auth
were cloned **with** data; characters and playerbots **without**, so no
character, guild, mail or bot row could cross over from the progression realm.

That was right, and it also dropped the handful of tables the base and module
SQL populate as fixed content. The first one missing is not survivable:

```
ASSERT(result, "active_arena_season can't be empty")      ArenaSeasonMgr.cpp:112
```

`seed-characters.py` refills them — **from the source tree's own `.sql` files,
never from `acore_characters`**, so nothing from the reference realm can arrive
by the back door. Only the `INSERT` statements are taken: the schema already
matches the current core, and `DROP`/`CREATE` from a base file would roll
individual tables back to their pre-update shape. Only tables that are empty
right now are touched, so re-running is a no-op.

Seeded: `active_arena_season`, `addons`, `mail_server_template{,_conditions,_items}`,
`mod_ollama_chat_personality_templates`, `playerbots_names` (100,000),
`playerbots_guild_names`, `playerbots_arena_team_names`, `pool_quest_save`,
`warden_action`, `world_state`.

`updates`/`updates_include` are deliberately **not** seeded: this realm runs
`Updates.EnableDatabases = 0`, and base-level bookkeeping would misdescribe a
schema that was cloned from an already-updated database.

> The tool verifies rather than trusting the exit code. On the first run one
> statement in the batch left its table empty while `mysql` still returned 0, so
> a silent partial seed is a failure mode this has actually had.

---

## Accounts

The same account works here as on the other realms, because `clone-base.py`
copied `acore_auth` **with** its data. All 165 rows in `asc_auth.account` carry
the same `salt` and `verifier` as the vanilla realm, so the password is
literally the same secret, not a re-entered copy of it — nothing was re-hashed
and no password had to be typed anywhere.

Verified over the wire rather than by inspection. `check-login.py` is a real
3.3.5a SRP6 client: it sends a logon challenge, computes the proof, and reads
the realm list back, which is exactly what the game client does.

```
PROOF ACCEPTED - the password for RNDBOT0 is correct on this realm
realm list returned 1 realm(s):
   Ascension                127.0.0.1:8085   chars=0 lock=0 flags=0x00 pop=0.0
```

Human accounts were checked with `--challenge-only`, which stops before the
password step, so no credential was sent and no failed-login counter moved:

```
ADMIN           challenge accepted
PANELGM         challenge accepted
NOSUCHACCOUNT   logon challenge refused: unknown account   <- control
```

The control matters: without an account that is *supposed* to fail, "challenge
accepted" would not prove the test can tell the difference.

State on this realm: `ADMIN` and `PANELGM` keep gmlevel 3 on RealmID -1,
expansion 2 (WotLK), `locked = 0`, no country lock, and `asc_auth` holds zero
active account bans and zero IP bans.

Two consequences worth knowing:

- **Characters start fresh.** `asc_characters` was cloned schema-only, so it has
  0 rows. Nothing from the progression realm can appear here, by design.
- **The three auth databases are independent snapshots.** A password changed on
  one realm will not propagate to the others; they would have to be changed on
  each. Only the three real accounts (`ADMIN`, `AHBOT`, `PANELGM`) share
  credentials across all three — SpellDraft's 150 bot accounts were regenerated
  with their own passwords and only match by name.

---

## What the realm holds

| | Ascension | Vanilla realm |
| --- | --- | --- |
| items (`item_template`) | 46,096 | 46,096 |
| creatures (`creature_template`) | 127,502 | 30,178 |
| gameobjects | 21,584 | 21,584 |
| quests | 18,601 | 9,505 |
| spells (named, from `Spell.dbc`) | 208,192 | 49,839 |

The launcher's Reference tab reads `control/refdata-ascension.json`, built by
`rebuild-refdata.py` from **this realm's** world DB and **this realm's**
`Spell.dbc`, so it no longer mixes realms.

---

## Tools in this directory

| File | What it does |
| --- | --- |
| `ascreds.py` | Builds a 0600 temp MySQL defaults-file from `credentials.txt`, cleaned up at exit. Nothing here ever puts a password on a command line |
| `clone-base.py` | `acore_*` → `asc_*`, sources read-only |
| `import-world.py` | Loads the harvested archive into `asc_world` |
| `seed-characters.py` | Refills the static `asc_characters` tables from the shipped SQL |
| `check-dbc-fmt.py` | Applies the core's own format strings (parsed from `DBCfmt.h` + `DBCStores.cpp`) to a dbc dir and reports what would crash. Vanilla: 114 load, 0 crash. Ascension: same |
| `fix-dbc.py` | The three lossless repairs |
| `sanitize-for-core.py` | The lossy enum clamps, with `--check-vanilla` and `--dry-run` |
| `sanitized-for-core.json` | Every lossy change, restorable |
| `check-login.py` | A real 3.3.5a SRP6 client: challenge, proof, realm list. `--challenge-only` proves an account exists without sending a password |
| `launch-client.ps1` | The Config.wtf realm redirect |
| `trainer-templates.json` | Decoded `NPCTrainer.dbc` |

Re-running the DBC pipeline on a fresh extract:

```bash
python check-dbc-fmt.py "C:/AzerothRealm/server-ascension/Data/dbc"
```

---

## Open items

**Fidelity**

- The 31 custom spell effects and 44 custom auras are clamped, not implemented.
  The alternative is to widen `TOTAL_SPELL_EFFECTS` / `TOTAL_AURAS` with stub
  handlers and rebuild the core — a decision worth making deliberately, since
  it means this realm no longer runs stock binaries.
- Ascension's `gt*.dbc` values are ignored: the core falls back to the
  `gtcombatratings_dbc` etc. world tables, which hold **vanilla's** numbers.
  Importing the client's values into those tables would close this.
- **Classless character logic is not implemented.** `ChrClasses.dbc` has 32 rows
  against the core's compiled `MAX_CLASSES`. The archetype data is decoded
  (`CharacterCreationArchetypes.dbc`, 56 rows) but nothing consumes it yet.
- `item_template` is still vanilla's 46,096 — no Ascension item import has been
  done, even though the client ships 563,765 items.
- Vendor inventories were never captured; they are server-sent
  (`SMSG_LIST_INVENTORY`), so they died with the service unless a capture exists.
- 139 non-stock DBCs remain mostly undecoded: `ItemSpells`, `ItemStat`,
  `MysticEnchant`, `SkillCard`, `SpellRank`, `SpellTags`, `Manastorm*`,
  `Mythic*`, `CharacterAdvancement*`.
- 141 negative `NPCTrainer` spell ids and 11 missing quest ids are still
  unresolved.

**Config**

- `OllamaChat.RAGDataPath` in this realm's `mod_ollama_chat.conf` still points at
  `C:/AzerothRealm/server/rag/` — the **vanilla** server's directory. It loads
  and works, but the facts it feeds bots describe the other realm's world.

**Untested**

- No client has connected yet. The next step is to launch through the tile and
  report what actually works versus breaks — character creation is the obvious
  first failure candidate, given the classless gap above.

### The login protocol is Ascension's own, and it is encrypted - measured 2026-08-30

The realm redirect works: the client dialled `127.0.0.1` and `connection.log`
recorded `RESPONSE_CONNECTED result: LOGIN_OK 127.0.0.1:3724`. It then reached
`LOGIN_STATE_AUTHENTICATING` and AzerothCore dropped the socket with no auth
result code. A capture proxy on `127.0.0.1:3799` forwarding to `3724` shows why.

A stock 3.3.5a client (`check-login.py`) through the same proxy sends the
textbook 39-byte challenge - gamename `WoW`, version 3.3.5, build 12340,
platform/os/lang, account name, nothing trailing - and the server answers
`SUCCESS` in 119 bytes. The Ascension client sends **636 bytes**: a four-byte
plaintext GRUNT header (`00 08 78 02` - opcode 0, protocol 8, declared size 632,
which matches the body exactly) followed by 632 bytes that are
indistinguishable from random - 7.658 bits/byte, 233 distinct byte values, four
zero bytes, and not one repeated 4-gram. AzerothCore cannot parse it, so it
closes the connection. The bytes are kept in `ascension-challenge.bin`.

**Where the change lives.** `Ascension.exe` is a byte-patched stock 12340
`Wow.exe`: identical PE timestamp `0x4C2452FE`, identical section table, and
only 107 differing bytes in `.text` (20 clusters), 47 in `.rdata`, none in
`.data`. Not one of those patches touches networking. The challenge builder at
`0x008CA580` - the function that writes `3, 3, 5` and `0x3034` inline - is
byte-identical to stock, and a live memory diff of the running client confirms
it is not hooked either. One of the 20 patches is the whole loader: eight bytes
at `0x0040B7D0` detour to a stub at `0x004E5CB0` that sets a flag, calls
`LoadLibraryA("Extensions.dll")` **without checking the result**, replays the
overwritten prologue and jumps back.

Diffing the running client against the file on disk shows what the DLL then
does: 3,677 bytes changed across **591 runtime patches** in `.text`, exactly one
redirected pointer in `.rdata`, and none in `.data`. The `ws2_32` IAT is clean
and no `ws2_32` export is inline-hooked, so the interception is inside the
client's own network classes. Inside the Grunt code proper there are only three
edits, and two of them are the tell: the immediates pushed at `0x008CC7FB` and
`0x008CC857` change from `0x14` to `0x20`, twenty bytes to thirty-two - SHA-1
replaced by a 32-byte hash in the logon-proof path. `Extensions.dll` carries
ChaCha20 and Salsa20 constants and imports `CryptGenRandom`, and imports no
socket functions at all, so it patches memory rather than wrapping Winsock.

So Ascension did not extend GRUNT, they replaced it: different hash, different
packet, encrypted body.

**What that rules out.** Teaching AzerothCore to answer this means reversing a
12 MB obfuscated DLL, and if the body is sealed to their server's public key it
cannot be answered at all without their private key - no amount of work on our
side would recover it. The one measurement that separates those two worlds is
whether the ciphertext is deterministic: two logins with the same account name
producing identical bytes would mean a fixed key (obfuscation, recoverable),
different bytes mean real per-session crypto.

**The escape hatch, and why it is not one.** Because the loader ignores
`LoadLibraryA`'s result, renaming `Extensions.dll` away leaves a client that
still runs - tested 2026-08-30, 690 MB resident, window up, glue loaded - and
which necessarily speaks stock GRUNT, since every hook came from the DLL. But
the custom UI collapses with it: `C_Realm`, `C_ClassInfo`, `C_CharacterCreate`,
`ReadCustomWTF` and `RegisterSavedCVar` are all nil, so character creation and
every Ascension panel are gone. That is a stock 3.3.5a client wearing
Ascension's artwork, which is what the vanilla client already offers. It is not
a way to play Ascension.

The archive itself is untouched by any of this: the DLL was renamed and renamed
back, keeping its 2026-08-13 13:17:26 mtime, and nothing was ever written into
the running process.

### The answer: the ciphertext is deterministic - measured 2026-08-30

Three logins were captured through the proxy: two from one client process
(23:39:39 and 23:50:17, pid 19536) and one from a process started afterwards
(00:03:00, pid 9656, with the client stopped, `Extensions.dll` renamed away and
back, and the client relaunched in between). All three packets are 636 bytes
and **553 of those bytes are identical in every one** - the same 553 whether the
two captures come from the same process or from different ones. There is no
per-session key protecting the bulk of this packet.

The field map falls out of the comparison:

| packet offset | size | behaviour |
| --- | --- | --- |
| 0..3 | 4 | header `00 08 78 02`, plaintext |
| 4..7 | 4 | constant `fc f4 f4 e6` |
| 8..23 | 16 | fresh random every connection |
| 24..564 | 541 | **constant**, 7.607 bits/byte, survives process restart |
| 565..624 | 60 | fresh random every connection |
| 625..628 | 4 | constant |
| 629..635 | 7 | fresh random every connection |

So 545 constant bytes and 83 freshly random ones. The 541-byte blob is kept in
`ascension-const-blob.bin`. It appears nowhere in the client tree outside the
MPQs - 359 files scanned - so it is computed at runtime from something stable,
or hardcoded inside `Extensions.dll` in a form that is not a literal byte match.
Whether it is account-derived is still unmeasured: every capture so far used the
same account name, and one login under a made-up name would settle it.

What this rules in and out. It rules out the worst case - a body sealed under a
per-session key or under Ascension's public key with random padding, which no
amount of local work could ever answer. The static bulk means the key material
is fixed and lives in `Extensions.dll`, so the scheme is recoverable in
principle. It does not make it cheap: recovering it means reversing the packet
builder inside a 12 MB DLL and then implementing its counterpart in AzerothCore's
authserver, and the SHA-1-to-32-byte change in the proof path implies the world
handshake's session-key derivation moved too.

The important scheduling consequence is that **this work is not time-critical**.
The client, `Extensions.dll` and the MPQs are already archived locally and will
still be here after the 4th. What expires with the service is the chance to
capture a *successful* handshake - the server's half of this protocol, which
cannot be reconstructed from the client alone and which no later effort can
recover.

### It is XOR, and the account name sits at offset 309 - measured 2026-08-30

The made-up-account test was run: one login as a four-character name against the
capture proxy, everything else unchanged. It answers far more than it was asked.

**The packet got exactly one byte shorter.** 636 bytes for the five-character
real account, 635 for the four-character test one, so `length = 631 + namelen`.
The plaintext size field at offsets 2..3 tracks it (`0x0278` -> `0x0277`),
confirming the first four bytes are genuinely unencrypted.

**Only three bytes moved inside the 541-byte constant block**, at offsets 309,
311 and 313. Offsets 310 and 312 - sitting between them - are byte-identical, as
is every other byte of 24..564. That single observation kills the block-cipher
hypothesis outright: any 16-byte block mode would have scrambled the whole of
304..319. Byte-aligned, byte-local differences mean an additive (XOR) stream
cipher.

**And the mask is the same on every connection.** For `C = P ^ K`, two captures
give `C1 ^ C2 = P1 ^ P2` - the keystream cancels. The observed ciphertext XOR
across those six offsets is `0C 00 06 00 73 00`, which is exactly the XOR of the
two upper-cased account names against each other, the second one space-padded.
Two independent facts fall out of that: the client upper-cases the name the way
stock GRUNT does, and the name lives in a **space-padded fixed-width slot**, not
a length-prefixed one.

The check was done the honest way round. A keystream derived *only* from the
test capture, assuming nothing but `"FAKE"` plus space padding -

```
offset 309..324:  28 86 48 CF E0 26 C2 95 8B A1 E3 0A EB 28 62 92
```

- was then applied to the *other* capture, which contributed nothing to it. It
decrypts to a five-character uppercase alphanumeric name followed by spaces.
Nothing about the real account went into the keystream, so this is a genuine
prediction rather than a fit.

Only offsets 309..313 are confirmed; 314..324 assume the padding continues, and
one login under a sixteen-character name would nail the slot width and hand over
the whole mask for it.

**The mask is a real keystream, not a repeating key.** The constant region
carries 7.619 bits/byte over 561 bytes, uses 226 of 256 byte values, contains
zero repeated 8-byte sequences, and shows no coincidence spike at any shift from
1 to 128 (best 1.1% against a 0.4% baseline). So it cannot be recovered by
analysis - only at offsets where known plaintext can be forced. That matches the
ChaCha20 and Salsa20 sigma constants already found in `Extensions.dll`: a fixed
key with a fixed nonce.

Note what did *not* change. The 16 random bytes at 8..23 differ on every
connection, yet the keystream over 24..564 does not depend on them - the same
mask is used regardless. Whatever that nonce is for, it is not seeding the mask
for the constant region.

**Where the variable byte went.** The name slot at 309 does not shift, so the
length difference is in the tail: 565..end, which is freshly random on every
connection and is where the ephemeral key material presumably lives.

#### What this changes

Reversing the packet builder is no longer on the critical path for the *client's*
half. The authserver does not need to decrypt the 541-byte blob at all - it is a
constant, already captured in `ascension-const-blob.bin`. It needs only to
recognise the four-byte plaintext header, and read the account name at offset 309
by XORing a sixteen-byte mask we can recover completely from one more login.

What is still entirely unknown is the *server's* half: what those 636 bytes are
supposed to elicit. The tail's ephemeral material, the 32-byte hash that replaced
SHA-1 in the proof path, and the response layout are all on the server's side of
the wire. No amount of local work on the client recovers them.

So the conclusion from the previous section inverts. This is now the single
time-critical item in the whole archive: a capture of one *successful* handshake
against the live service before 2026-09-04. Everything else here survives the
shutdown; that does not.

### The successful handshake, captured against the live service - 2026-08-30

The one irreplaceable capture is done: a full, successful logon against
`51.210.230.10:3724`, recorded through the proxy, before the shutdown. It
reassembles with no gaps (81 messages) and the four handshake packets are saved
verbatim next to this file:

| file | bytes | what |
|---|---|---|
| `live-client-challenge.bin` | 645 | the wrapped client challenge |
| `live-server-challenge-response.bin` | 119 | the server's reply |
| `live-client-proof.bin` | 75 | the client proof |
| `live-server-proof-response.bin` | 44 | the server's `SUCCESS` |

`auth-proxy-live.log` holds the raw exchange. It carries a real login on the
wire, so it stays out of every committed file and out of chat - same rule as
`credentials.txt`.

**The server's half is structurally stock, and that is the headline.** The
119-byte challenge response parses cleanly as a stock 3.3.5a GRUNT
`AUTH_LOGON_CHALLENGE` response: `cmd 0x00, err 0x00, result 0x00 SUCCESS`, then
a 32-byte `B`, `g_len 1 / g = 0x07`, `N_len 32`, and the modulus `N` is a
**byte-for-byte match for the stock WoW 3.3.5a SRP6 modulus**
(`b79b3e2a...5e644b89`), followed by a 32-byte per-account salt, the 16-byte
version challenge, and one security-flags byte. No custom parameters. The server
is speaking ordinary SRP6a group constants.

**The proof widened from SHA-1 to a 32-byte hash, exactly as the `.text` diff
predicted.** The proof response is 44 bytes = stock 32 + 12, and the 12 extra
bytes are a 32-byte `M2` where stock carries 20. Its tail is a stock-shaped
`accountFlags(4) / surveyId(4) / loginFlags(2)`. So the wire proof is
SHA-256-width, matching the `6a 14 -> 6a 20` (push 20 -> push 32) immediates
found earlier in the client.

**But the client is not doing real SRP6a - and this is what actually matters.**
The 75-byte client proof is *plaintext*, not wrapped (it is mostly zeroes; a
keystream would have made it high-entropy), and its 32-byte `A` field is
degenerate - near-all-zero with a stray `0x04` every twelfth byte. A genuine
`A = g^a mod N` would be 32 full-entropy bytes. The only high-entropy content is
a ~19-byte run at offset 53 (where stock puts the client version hash). So the
visible SRP proof exchange is a shell: the client sends a dummy `A` and the
server returns `SUCCESS` anyway. The real authenticator is not in these fields -
it is in the 645-byte challenge blob (the 541-byte constant plus the tail's
ephemeral material), which the server evidently consumes and rubber-stamps the
proof.

#### What this means for a local reimplementation

It is *more* tractable than "reverse a 12 MB packet builder", not less, because
for a **local, single-player** realm we never have to verify Ascension's
authenticator. The local authserver only has to keep the client's state machine
happy:

1. Recognise the four-byte plaintext header and the oversized challenge.
2. XOR-extract the account name at offset 309 (mask recoverable from a known
   login) - enough to pick the local account row.
3. Emit a stock 119-byte challenge response - which AzerothCore already builds -
   using that account's salt and a `B`.
4. Accept the proof packet regardless of the degenerate `A`.
5. Emit the 44-byte, 32-byte-`M2` success.

The open risk is step 5's converse: **does the client verify the server's
`M2`?** If it does, the check uses Ascension's custom 32-byte scheme (the
ChaCha/Salsa material in `Extensions.dll`), and we must reproduce it or the
client rejects the login even though the server said yes. That is the one thing
this capture cannot answer - it shows what a *genuine* server sent, not what the
client would accept from a *substitute* one. Resolving it means the DLL analysis
we already started, now with a concrete target: the function that consumes the
44-byte proof response and decides whether to proceed.

#### Still uncaptured: the world handshake

Auth is only the first server. The realm-list response (opcode 0x10, the
2306-byte server messages) names Ascension's *world* server, and when a
character actually enters the world the client dials that host directly - not
through this proxy. The world handshake is where the 32-byte session key is
used, and it is a separate capture needing a second proxy on the world port.
It is the logical next thing to record while the service is still up, if full
in-world fidelity is wanted; the auth capture alone is enough to reach the realm
screen.

### The world handshake, captured (2026-08-30)

Recorded with `world-capture.py`: a transparent auth relay on 3799 that, once
the client asks for the realm list (opcode 0x10), rewrites every world address
in the reply to a local forwarder. The player logged in manually, picked
**Rexxar - Conquest of Azeroth** (realm id 23), and the forwarder on
127.0.0.1:8813 relayed the whole handshake to the real world server
`91.134.31.192:8100`. Verbatim packets saved as `world-smsg-auth-challenge.bin`
(44 B) and `world-cmsg-auth-session.bin` (298 B); the on-the-wire logs are
private (real login) and treated like `credentials.txt`.

**The headline: the world protocol is stock WotLK 3.3.5a.** Nothing in the
handshake is widened or reshaped the way the auth logon was.

`SMSG_AUTH_CHALLENGE` (the server speaks first):

    size 0x002A (BE)  opcode 0x01EC   <- stock SMSG_AUTH_CHALLENGE
    uint32 = 1
    auth seed  DC 1F EF B7
    32 bytes of encryption seed material

That is the exact stock 40-byte body (`uint32(1)`, 4-byte auth seed, two 16-byte
seeds). No extra fields, no widened seed.

`CMSG_AUTH_SESSION` (the client's reply, before header encryption engages):

    size 0x0128 (BE)  opcode 0x01ED   <- stock CMSG_AUTH_SESSION
    build            12344
    loginServerID    0
    account          <email, PLAINTEXT>       (null-terminated, stock slot)
    loginServerType  0
    clientSeed       A0 37 50 A0
    region/bg/realm  0 / 0 / 23
    dosResponse      0x0000000000000001
    digest           20 bytes  10 DB 3E D1 D1 50 C1 B4 B3 22 B1 D4 52 57 35 9A BA C9 6B AC
    addon block      212 B zlib -> 670 B, decompresses CLEANLY to 23 Blizzard
                     load-on-demand addons (the standard 3.3.5 set)

Two things matter here. First, the **digest is 20 bytes - stock SHA-1**, *not*
the 32-byte SHA-256 the auth *proof* used. The hash-widening we found in the
logon path was auth-proof-only; the world session digest was left alone.
Second, the account travels in **plaintext** in the normal slot and the addon
list decompresses with an off-the-shelf zlib parser - i.e. AzerothCore's
worldserver, which already builds `SMSG_AUTH_CHALLENGE` and parses this exact
`CMSG_AUTH_SESSION`, speaks this protocol as-is.

So the world server needs no protocol work. The single thing that must line up
is the **session key**: the client computes `digest = SHA1(account | 0 |
clientSeed | authSeed | sessionKey)` and the server recomputes it, so both sides
have to derive the *same* 40-byte session key from the auth step. For a genuine
Ascension server that key came out of the custom logon crypto; for a local
substitute it only has to be the key our reimplemented authserver and the client
both arrive at. That folds the world side back into the one open auth question
(the `Extensions.dll` key/`M2` scheme) rather than adding a new one.

#### The zone-in crash is post-capture, not a capture failure

The client rendered the character (Reekvm) into **The Barrens** (Kalimdor, map
1) and then died: ERROR #132 ACCESS_VIOLATION, EIP == fault address
`0xCD0CA176` in no loaded module - a jump through a garbage function pointer -
reached via Ascension.exe frames `...0047F2E1 -> 004E5CCF`, that last one inside
the `0x004E5Cxx` Extensions.dll loader-stub region. It happened *after* the full
handshake and after zone-in, so every packet that matters was already recorded;
the crash costs nothing.

Most likely trigger is proxy latency: a relayed world packet arriving before
`Extensions.dll` finishes patching its runtime opcode-handler table dispatches
through an uninitialised entry and jumps to garbage. (Anti-tamper reacting to
the localhost MITM - the client logged its connection as `127.0.0.1:8813` - is
the other candidate; TCP itself is byte-transparent, so the relay did not
corrupt the stream.) `world-capture.py` now sets `TCP_NODELAY` on all four relay
sockets to cut that latency, which is the cheap thing to try first if a longer
in-world capture is wanted. But for recording the handshake, the job is done.

### Replay test: the client verifies M2, and M2 is session-bound (2026-08-30)

`replay-auth.py` is a standalone local authserver with **no upstream** - it only
echoes the four captured handshake packets plus the captured realm list
(rewritten to localhost). The point was to answer the one open question: will the
client accept a login from a server that merely replays recorded bytes?

It will not, and the failure is precise (`replay-auth.log`):

    <- CHALLENGE (645 bytes); replayed the 119-byte challenge response
    <- PROOF    (75 bytes);  replayed the 44-byte proof response
       client closed - no realm-list request  ->  "Unable to connect"

The client accepted the replayed **challenge response** (it used our `B`/salt/`N`
to compute and send its proof), then **rejected the replayed proof response** (it
closed instead of asking for the realm list). The validation point in SRP-style
exchanges is the server's `M2`, so this says plainly:

- **The client verifies the server's 32-byte `M2`.** This is the question the
  live capture could not answer, now answered: yes.
- **`M2` is session-bound.** Each login mints fresh ephemeral material - the
  variable tail of the 645-byte challenge blob that we already saw change between
  captures - and the correct `M2` is a function of it. A canned `M2` from a
  different session cannot match this session's derivation, so the client drops
  it. This is textbook: you cannot replay one side of a real key agreement.

**This overturns the earlier "rubber-stamp" reading.** The degenerate `A` field
in the visible proof is a red herring; the genuine ephemeral is inside the
challenge blob and the exchange is a real custom key agreement. A local
authserver therefore **cannot echo a proof response - it must compute the correct
`M2`** for each login, which means reproducing Ascension's key-agreement / `M2`
scheme from `Extensions.dll`.

The good news about the timing: that computation is the *client's* verification
code, and the client (`Extensions.dll`) is on disk permanently. Cracking `M2` is
static reversing we can do at any time - it is **not** a race against the
2026-09-04 shutdown. What is perishable is live-server *observation* (real world
traffic), which needs a working login and can only be had via the
relay-to-real-server proxy while the service is up.

### The handshake crypto is libsodium/NaCl: X25519 + Salsa/ChaCha-Poly1305 + SHA-256 (2026-08-30)

`Extensions.dll` (12.1 MB, `client-ascension/Extensions.dll`, permanent on disk)
was fingerprinted for crypto primitives. The result is unambiguous and it is not
a bespoke cipher - it is the NaCl/libsodium family:

- **X25519 (Curve25519)**: the scalar-mult base point `09 00...00` (32 bytes) at
  0xB7C948, the `CURVE25519` label at 0xB7C990, and the field constant 121666.
- **Salsa/ChaCha**: the sigma constants `expand 32-byte k` / `expand 16-byte k`
  at 0xB7CC10, and 0x61707865 / 0x3320646e in the constant pool.
- **Poly1305**: the clamp constant 0x0ffffffc - so an AEAD
  (X)Salsa20/ChaCha20-Poly1305, i.e. libsodium `crypto_box`/`secretbox`.
- **SHA-256 and SHA-512**: H0 0x6a09e667 and K0 0x428a2f98 present - the source
  of the 32-byte `M2` and the 32-byte packet fields (matches the earlier
  `push 20 -> push 32` widening: the proof hash is SHA-256, not SHA-1).
- Also present but likely from other client subsystems, not the handshake:
  SHA-1, MD5, RC4, TEA, AES, RSA, CRC32 (Warden, cache, patching). BLAKE2 is
  absent, so the KDF is not libsodium `crypto_kx`/`generichash` - more likely
  `crypto_box`'s HSalsa20-of-DH or a raw scalarmult then SHA-256/512.

There are also 19 `SRP` strings: consistent with what the packets already showed
- a stock GRUNT/SRP-shaped **envelope** (opcodes, field order, the stock `N` and
  `g=7`) wrapping a real **X25519** key agreement whose 32-byte public keys and
  SHA-256 outputs sit in the slots stock SRP fills with `B`, salt, and `M2`.

**Why this is the good outcome.** These are standard, documented, deterministic
primitives with a drop-in local implementation (libsodium / PyNaCl). The
reimplementation problem shrinks from "reverse an unknown 12 MB cipher" to one
bounded question: **which libsodium construction, over which inputs, produces the
`M2` the client verifies?** And crucially, a *local* server does not need
Ascension's server private key - as the server, it generates its **own** X25519
keypair; the client does `X25519(client_ephemeral_priv, our_pub)`, derives the
same shared secret and `K`, and accepts our `M2` as long as we compute it by the
same formula. So the only thing left to extract from the binary is that one
formula: keygen -> scalarmult -> KDF (which hash over what) -> `M1`/`M2`. That is
the concrete next reversing target, and it is on the permanent binary - no
shutdown race.

Remaining unknowns to pin from the handshake routine (near the 0xB7Cxxx constant
pool and the proof-parsing code): (1) where the client's ephemeral X25519 public
sits in the 645-byte challenge; (2) whether `K = HSalsa20(X25519(...))` (crypto_box)
or `SHA-512/256(shared | pubs)`; (3) the exact `M2 = SHA256(...)` input tuple.
Once those three are known the local authserver is a few dozen lines of PyNaCl.

### Reversing Extensions.dll: the handshake's crypto architecture (2026-08-30)

Static analysis with capstone (no IDA/Ghidra on the box; `pefile` + capstone
5.0.7). `Extensions.dll` is x86, preferred base `0x10000000` (runtime base was
`0x6E480000` per the crash report - subtract 0x6E480000 and add 0x10000000 to map
a live address to these). libsodium is **statically linked** (no crypto DLL
imports; randomness via `CryptGenRandom`). There is a small `.vm_sec` section
(33 KB) - a code virtualizer, relevant below.

**Located primitive functions (VAs at preferred base 0x10000000):**

- `0x10ADCA10` = `crypto_scalarmult_curve25519(out, scalar, point)` - the X25519
  core. Confirmed by the base point `09 00..` at `0x10B7DB48` and the exact
  clamping right before a call site (`and [esi],0xF8` / `and al,0x7F` / `or
  al,0x40`).
- `0x10ADAFB0` = key-agreement, `crypto_box_beforenm`-shaped: it calls
  scalarmult with **my private x their public** (site `0x10ADB033`:
  `point=[objB+0x10]`, `scalar=[objA+0x40]`, `out=stackbuf`), then moves the
  shared secret to the caller via `0x10ADAD70`.
- `0x10ADAD70` = a 32-byte **copy** (SSE `movups` path, plus a byte-reversed
  path when arg3==1) - **not a hash**. So the box routine itself applies no
  hash KDF; K is the raw (or endian-swapped) X25519 shared secret, unless the
  hashing happens in the (indirect) caller.
- Keypair object layout: `+0x10` public(32), `+0x40` private(32), `+0x64` flags
  (bit1 = public present, bit2 = private loaded). Load-private-and-derive-public
  methods at `~0x10ADADE9` and `~0x10ADAF00`.
- `0x10ADBFC0` = `sha256_init` (immediates 0x6a09e667..). SHA-256 transform uses
  the K-table at `0x10B7DC60` (inner loop at `0x10ADC45D`).
- **HMAC-SHA256 is present** (ipad/opad `0x36..`/`0x5c..` in the image; the
  init-pair `0x10ADC82F`/`0x10ADC84F` is the inner/outer init). So the proof/KDF
  is very likely HMAC-based (HKDF or an HMAC proof), not a bare SHA-256.
- The libsodium auth/hash callers cluster in `0x10AD9xxx`-`0x10ADAxxx`; the
  SHA-256 wrappers (`0x10ADC820`, `0x10ADC940`) have direct callers there.

**The wall.** The key-agreement `0x10ADAFB0` has **zero direct callers** (E8
scan). The handshake's top-level orchestration - parse the 645-byte challenge,
pull the peer's X25519 public out of it, run the key-agreement, compute `M1`/`M2`
- reaches these primitives **indirectly** (function pointers / vtable, or from
the `.vm_sec` virtualized region). So following direct call-xrefs upward from the
primitives to the `M2` formula does not connect. The libsodium leaf layer is
fully readable x86; the glue above it is not statically reachable the easy way.

**What this means for finishing.** Two routes to the exact `M2`/KDF construction:
(1) keep tracing statically through the HMAC/SHA-256 callers in the
`0x10AD9xxx`-`0x10ADAxxx` cluster to find the sequence that folds K + the two
public keys into a 32-byte output - safe, but slow and may dead-end at the
indirect/VM boundary; (2) dynamic trace - breakpoint or read-only-inspect the
running client at `0x10ADAFB0` (key-agreement) and the SHA-256 wrappers to
capture the actual input/output buffers of one real handshake, from which the KDF
and `M2` formulas fall out immediately. Route 2 is the efficient finish but must
be done carefully against the anti-tamper (`Extensions.dll` is the Warden-like
layer; the `.vm_sec` virtualizer and the zone-in crash show it reacts). The
concrete dynamic target is `0x10ADAFB0` +/- the SHA-256 wrappers, mapped to the
live base (`+0x5E480000` offset from these VAs).

### Dynamic trace blocked: kernel anti-tamper strips handle rights (2026-08-30)

Track 1 (reverse the M2 formula by watching the running client) ran into a hard
wall that is not the virtualizer - it is the operating system.

Built a purpose-made hardware-breakpoint tracer (trace-handshake.py): a 64-bit
ctypes debugger that attaches with the Windows debug API, resolves Extensions.dll
at its live base, and sets DR0-DR3 execute breakpoints on the four libsodium
leaf functions that see everything M2 is built from (KEYAGREE 0x00ADAFB0,
SHA_INIT 0x00ADBFC0, SHA_W1 0x00ADC820, SHA_W2 0x00ADC940 as RVAs).  It modifies
no code, so a self-checksumming protector sees an unmodified image, and it was
designed to run against the OFFLINE replay server so there is no account risk.
It self-tests clean (WOW64_CONTEXT 716 bytes, DEBUG_EVENT union at +16).

It cannot attach.  While the client was running (pid 16940, ~942 MB, with its
companion MMgr64.exe up one second after launch), an access-tier probe found:

  process        QUERY_LIMITED  QUERY_INFO  VM_READ  ALL_ACCESS  SYNCHRONIZE
  Ascension.exe       OK          DENIED     DENIED    DENIED         OK
  MMgr64.exe          OK          DENIED     DENIED    DENIED         OK
  PowerToys (benign)  OK           OK         OK        OK            OK

Same-user OpenProcess returning ERROR_ACCESS_DENIED (5) for VM_READ/QUERY/ALL is
impossible from user mode alone - there is no user-mode way to make same-user
OpenProcess fail.  It requires a kernel callback (ObRegisterCallbacks) stripping
those rights from every handle opened to the protected set.  MMgr64.exe is the
enforcement helper and it protects both the game and itself; only the two rights
Task Manager needs (QUERY_LIMITED_INFORMATION, SYNCHRONIZE) survive.  This is the
same technique commercial anticheats use.

Consequences:
- No user-mode debugger can attach or read the client: not this tracer, not
  x64dbg, cdb, WinDbg, or Frida.  DebugActiveProcess needs a full-access handle,
  which the callback denies.
- Admin / SeDebugPrivilege does not help: an Ob callback strips rights from all
  requestors including SYSTEM.  This is launch-time and always-on (MMgr64 is up
  from second one), so the "login screen is pre-anti-tamper" idea is wrong for
  this client - that only ever applied to the world-side Warden layer.

The safe OFFLINE alternative was also checked and is blocked for a different
reason.  As the local server we would need the client's ephemeral X25519 public
to compute K and turn the client's wire-sent M1 into a known-plaintext oracle.
But the whole 645-byte challenge is stream-ciphered: every 32-byte block reads
H = 4.6-5.0 bits/byte (tail-analysis.py), so the public is not raw in the tail -
it is XORed with the same keystream as everything else and cannot be read off.

What is left, all heavier, to still log the real Ascension client in locally:
  (A) Hypervisor/VM trace - run the client in a VM and trap the crypto from
      OUTSIDE the guest (EPT).  The in-guest kernel anti-tamper cannot see or
      strip hypervisor breakpoints, so this defeats MMgr64 cleanly and yields K
      plus the M2 inputs.  Biggest lift; the client may also resist running in a
      VM.  This is the technically-correct way to beat a kernel anticheat.
  (B) Static devirtualization of .vm_sec - lift the custom VM bytecode from the
      on-disk DLL to recover the M2 formula (and possibly the challenge keystream
      generator, which would revive route (A)-offline).  No process access, no
      anti-tamper fight; large, uncertain RE project.
  (C) Pivot to Path B - stock 3.3.5a client + the AzerothCore realm with
      Ascension data imported.  Needs none of the crypto; loses only Ascension's
      client-side custom presentation.

Cheap bounded probe worth doing before committing to (A)/(B): is the challenge
stream-cipher / keystream generator (NOT the M2 KDF) statically readable in
Extensions.dll?  If the encryption setup is plain libsodium in normal code, the
keystream can be regenerated offline, the challenge decrypted, the client public
extracted, and the safe wire-only M1/M2 recovery reopened - no VM, no debugger.
