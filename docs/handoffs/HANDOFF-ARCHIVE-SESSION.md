# Ascension Archive — session handoff & boot runbook

> **SUPERSEDED as the active runbook (2026-09-01).** Start at
> **HANDOFF-SPELLS-TALENTS-CLASSES.md** -- spells, talent trees and custom
> classes are the current goal. Archetype / Build Creator work (section 4.12)
> is TABLED until those land. This document stays the reference for everything
> already solved.

**START HERE for a new session.** Written 2026-08-31 (late). Supersedes the
"boot" guidance scattered in `HANDOFF-CA-REXXAR.md` (that file remains the deep
render-contract reference). Goal recap: a local, single-player *play-reader*
archive of Project Ascension (classless custom 3.3.5a). We replicate the CoA /
Character-Advancement hero-class tree UI (Tinker, etc.) offline. Ascension shuts
down 2026-09-04; this is the post-shutdown archive.

---

## 0. Current state (as of this handoff)

**THE CoA TREE RENDERS. The archive is working.** Verified end-to-end on
2026-09-01 ~02:50 against a live client run: login → world → Character
Advancement panel → class → spec tab → populated spell column *and* populated
talent grid. Screenshots in the session scratchpad (`coa_80.png`,
`final_frost.png`).

- **The full local login path WORKS**, unattended. §2's `__COMPAT_LAYER =
  'RunAsInvoker'` launch is the whole trick — it satisfies the client's
  `requireAdministrator` manifest *without* elevating, which matters because the
  shim and world server RPM-read the client and so it must stay unelevated. An
  ordinary agent session can now drive the entire boot: launch, click Login
  (client 640,590), click Enter World (client 640,657).
- **Both CoA root causes are fixed and both are now VERIFIED against a client:**
  - Fix #1 realm-flavour bytes → `IsLive=true, IsProduction=true`.
  - Fix #2 opcode `0x725` (`SMSG_CA_ACTIVE_SPEC`) → the probe that used to take
    the process down with a C-level access violation now returns cleanly.
  - Result: `GetEntriesByClass` went from **0 entries in all 159 class|tab
    buckets** to **153 populated buckets / 8873 visible entries / 42 classes**.
  - Read **§4** before touching anything CoA-related.
- **Character level is now 80** (`ARCHIVE_LEVEL` in `world_server.py`, and the
  persisted `characters.json`). This was a real blocker, not cosmetic: the panel
  greys its whole talent half behind *"Unlocks at level 10"*, and individual
  nodes gate on `RequiredLevel` (Mage's own column runs 1..75). The dataset
  itself is **not** level-filtered — `GetEntriesByClass` returns the identical
  8873/153 at level 1 and at level 80 — so this is purely a UI gate, and the fix
  is server-side (report a real level), not a client patch.
- **Keybinds / account data now work like the real realm** — the archive
  implements the 3.3.5a account-data exchange and seeds a default keymap for
  every new character. See **§3A**; the old client-side Lua keybind hack has
  been deleted and must not come back.
- **Logout works** (`CMSG_LOGOUT_REQUEST`), so you no longer have to kill the
  client to get back to character select.
- **Ghost input is measured, not guessed:** background keys / `/run` Lua /
  occluded screenshots all work; background *clicking at coordinates* is
  impossible because WoW polls the physical cursor. See **§3**.
- Running processes (leave them or restart per §2):
  - shim `shim3799.py TEST TEST` — pid 38272, listening `127.0.0.1:3799`
  - world `world_server.py` — pid 12212, listening `127.0.0.1:8085`.
    `load_chars()` is called **per connection**, so editing `characters.json`
    only needs a client relog, not a server restart.
  - client `Ascension.exe` — pid 44044, in-world as *Name* (guid 1, level 80).
    Started **directly**, not via `launch-client.ps1`, which cost the autorun its
    first login — it works from the reconnect onward. Read the table at the end
    of §4.9 before you rely on `ASC_IsArchive()`.
- **Proof it's local, not live:** the login screen footer reads
  `[Ascension-Local]`, char-select reads `[Ascension-Local] (Hybrid)`, the
  loading bar reads *"Switching realm data: Ascension Archive"*, and
  `shim_log.txt` shows `M2 ACCEPTED` → `realm list sent (127.0.0.1:8085)`.
  (`172.67.x.x:443/80` is Cloudflare CDN for `api.ascension.gg` asset pings —
  harmless, NOT the game server.)
- **Chat readback works and is the primary probe channel.** `CoAReader_Say()`
  pushes over `SendChatMessage` (language 0 = Universal, so no racial-language
  grant is needed — that old queued item is moot); `world_server.py` logs every
  `CMSG_MESSAGECHAT` as `>>> CHAT[...]`. Caveat: the client's own spam throttle
  silently drops most of a burst sent in one frame, so use it for **scalars**
  and read bulk data from SavedVariables instead.

- **All four of the previous handoff's open items are now closed**, each
  verified against a running client on 2026-09-01: learned CA entries
  (`0x726`, §4.9), the tree's edge graph (`ConnectedNodes`, §4.10), build
  activation (`0x5C2`, §4.11), and both cosmetics. Note §4.11 corrects a wrong
  premise — `ActivateBuild` was never silent, the archive just did not know the
  opcode; the packet had been sitting in `world_unhandled_w003_5C2.bin` all
  along.

### Open items — **all four now CLOSED** (kept for the record)

1. ~~**Archetype builds never apply.**~~ — **SOLVED. The premise was wrong.**
   `C_BuildCreator.ActivateBuild(buildID, true, true)` does *not* "emit nothing":
   it sends **`CMSG_BUILD_ACTIVATE` (`0x5C2`)**, and the archive had already
   captured it as an unknown opcode (`world_unhandled_w003_5C2.bin`, 39 bytes)
   without recognising it. Decoded, implemented and verified live — see §4.11.
2. ~~**Opcode `0x726`**~~ — **decoded and implemented**, see §4.9. It is *not*
   the essence packet (that was `0x722`, already implemented and shipping the
   real curve): `0x726` is the **known-entries** packet, the set of CA entries
   the character has learned. **Implemented and VERIFIED against a running
   client** (counts, `IsKnownID`, rank, and the add/remove diff path both ways).
3. ~~`ConnectedNodes`~~ — **SOLVED, and exported.** It is not findable as a
   fixed DBC column and never will be: the engine holds it as a heap vector at
   `entry+0xE8` (entry→Lua builder `0x1016ce32` pushes it there, with `Group`
   at `+0xF4` and `PositionX/Y` at `+0xF8/+0xFC`), parsed out of the packed
   region rather than read from one place. So the archive took the direct
   route: `CoAReader_DoEdges` dumped the whole graph out of the live engine and
   it now ships as `rexxar-reference\ca-dbc-export\edges.json`. See §4.10.
4. Cosmetic: ~~`UnicodeEncodeError` at the end of `tools/extract_ui.py`~~
   (fixed — `main()` now reconfigures stdout/stderr to UTF-8 with
   `errors="replace"`; the extraction was always fine, only the report could
   not be spelled in cp1252); ~~the `CMSG_STANDSTATECHANGE` flood~~ (fixed —
   the three no-reply opcodes now log once per session and are counted after
   that, with the tally printed when the session ends).

---

### THE bug that ate a session (do not repeat)
The client dials the **realmList port literally**. `realmList "127.0.0.1"`
(no port) makes it connect to the WoW default **3724**, where nothing listens →
`LOGIN_SERVER_DOWN` → on-screen *"Unable to connect."* The shim is on **3799**.
**The realmList MUST be `127.0.0.1:3799`.** This is now fixed in three places:
- `client-ascension\WTF\Config.wtf` → `SET realmList "127.0.0.1:3799"` (cosmetic; the client rewrites this on exit — see below)
- `client-ascension\Interface\GlueXML\AccountLogin.lua` → `ASCENSION_ARCHIVE_REALMLIST = "127.0.0.1:3799";` (**this is the real control**)
- `realms\ascension\launch-client.ps1` default `-RealmList` → `'127.0.0.1:3799'`

Distinguish the two failure dialogs:
- *"The information you have entered is not valid"* = the client reached the
  **LIVE** auth server and it rejected `test`. **Stop — you're pointed at live.**
- *"Unable to connect. Please try again later."* = the client reached
  `127.0.0.1` but nothing answered on the port (usually the 3724 vs 3799 bug).

---

## 1. Why realmList is fragile (the glue is the real lever)

The Ascension client does **not** honour `Config.wtf`'s `realmList`. It reads the
file (realmName reaches the login screen), but by the time the login screen
shows, the CVar has been put back to the official address in memory. So the
address is forced in **glue Lua** instead — the last code before
`ConnectToServer()`:
- `client-ascension\Interface\GlueXML\AccountLogin.lua` defines
  `ASCENSION_ARCHIVE_REALMLIST` and `AscensionArchive_ForceRealm()`, called at
  `AccountLogin_OnShow` (line ~103) **and** immediately before `ConnectToServer()`
  inside `AccountLogin_Login()` (line ~283).
- Verify it fired: `client-ascension\Logs\LUA.txt` shows e.g.
  `ASCARCHIVE AccountLogin_OnShow: realmList 51.210.230.10 -> 127.0.0.1:3799`.
- The client **rewrites Config.wtf on exit**, putting `realmList` back to the
  official `51.210.230.10` and sometimes `realmName "[Ascension-Local]"`. That's
  fine — the glue re-forces `127.0.0.1:3799` at the next login. Config.wtf is
  cosmetic; **the glue constant is what matters.**

### ⚠️ JUNCTION LEAK WARNING (important)
`client-ascension` is a **Windows junction into the LIVE install**
(`C:\Ascension\Launcher\resources\ascension-live`). This loose glue file forces
realmList **unconditionally**, so if the **real Ascension launcher/client** is
started while this file exists, it will also be redirected to `127.0.0.1:3799`
and fail to reach live. Before using the live client (if ever, pre-shutdown):
run `launch-client.ps1 -Restore`, **or** delete/rename the loose glue
`Interface\GlueXML\AccountLogin.lua` (the file header says it's safe to delete to
restore stock). A future improvement is to gate `AscensionArchive_ForceRealm` on
an archive-only sentinel so it can't leak. See memory `ascension-client-junction-leak`.

---

## 2. Boot runbook (copy/paste)

Run all three unelevated, same user. The servers RPM-read the client's session
key, so the **client must be unelevated too** (RunAsInvoker); no UAC needed.

**Preflight — make sure the glue points at the shim (survives the client's Config.wtf rewrite):**
```bash
grep -n "ASCENSION_ARCHIVE_REALMLIST" "/c/AzerothRealm/client-ascension/Interface/GlueXML/AccountLogin.lua"
# must read:  ASCENSION_ARCHIVE_REALMLIST = "127.0.0.1:3799";
```

**1) Auth shim (listens 127.0.0.1:3799, logs to shim_log.txt):**
```powershell
cd C:\AzerothRealm\realms\ascension; python shim3799.py TEST TEST
```
(run in background). It replays a cracked `M2 = HMAC-SHA256(K,'OK')` where `K` is
read live from the client's memory (`obj+0x120`) via `rpm_readk.read_k()` at
connect time — so it finds the client PID **dynamically**; starting the shim
before the client is fine.

**2) World server (listens 127.0.0.1:8085):**
```powershell
cd C:\AzerothRealm\realms\ascension; python world_server.py
```
(run in background). RPM-reads the world SessionKey from the client, ARC4 header
crypt, char enum, drops the client into the world.

**3) Client — launch DIRECTLY. Do NOT use the launch-client.ps1 Start-Job /
Wait-Process / finally pattern** — its `finally` restores the official realm and
blanks the glue ~2 s after launch (that's the trap that pointed us at live):
```powershell
$env:__COMPAT_LAYER = 'RunAsInvoker'
Start-Process -FilePath 'C:\AzerothRealm\client-ascension\Ascension.exe' `
  -WorkingDirectory 'C:\AzerothRealm\client-ascension' -NoNewWindow -PassThru
```
(`launch-client.ps1 -NoLaunch` is still fine to *set* config+glue without
launching; just never let its launch+finally run while you want the client
alive.)

**4) Log in.** Account `test`, any password (password does NOT gate — the shim
authenticates by reading K, not by checking the password). Click **Login** once.

**Verify local, not live:**
```bash
tail -6 "/c/AzerothRealm/realms/ascension/shim_log.txt"          # want: hello ... account='test' (OK) / M2 ACCEPTED / realm list sent (127.0.0.1:8085)
tail -4 "/c/AzerothRealm/client-ascension/Logs/connection.log"   # want: LOGIN_OK (not SERVER_DOWN, not "information not valid")
```
```powershell
Get-NetTCPConnection -OwningProcess <clientpid> -State Established | ? RemotePort -in 3799,8085,3724
# want an established 127.0.0.1:8085 (world). 51.210.230.10 = LIVE = wrong.
```

---

## 3. Driving the client without stealing the mouse

**Measured 2026-09-01: you cannot ghost-*click* this client, and no amount of
PostMessage work will change that.** WoW polls the OS cursor itself (its own
`GetCursorPosition()` returns the physical pointer scaled by UIParent); the
`lParam` you put on a posted `WM_MOUSEMOVE`/`WM_LBUTTONDOWN` is ignored for hit
testing, so a posted click lands wherever the real pointer happens to be sitting.
Proof, with the game window in the background:

```
ghostinput.ps1 -Action move -X 100 -Y 100        # posted "move" to (100,100)
ghostinput.ps1 -Action lua  -Text "local x,y=GetCursorPosition() dprint(x,y)"
   -> 724 382     # == the REAL pointer at client (679,361), scaled by UIParent
```

Everything *else* works in the background, which is enough — see the recipes
below. Two harnesses live in `realms\ascension\tools\`:

- **`ghostinput.ps1`** — BACKGROUND, `PostMessage` only. The cursor never moves
  and focus is never stolen, so the user can keep working. **Use this by
  default.** Actions:
  - `key -Text ENTER|ESCAPE|TAB|UP|DOWN|F1..` — works without focus. This is how
    you drive the glue screens (login, char select) and the ESC menu.
  - `char -Text "..."` — `WM_CHAR` per character, 15 ms apart. **Do not lower
    that delay**: at 10 ms the client drops characters and you get a red
    *"UI Error"* line from a mangled command.
  - `lua -Text "<lua>"` — ENTER, type `/run <lua>`, ENTER. The real workhorse.
  - `luaclick -Text FrameName` — `/run FrameName:Click()`. Clicks a *named*
    frame, which is the working substitute for a coordinate click.
  - `slash -Text "/who"` — any slash command.
  - `shot -Out x.png` — `PrintWindow(..., PW_RENDERFULLCONTENT)`, cropped to the
    client rect. **Captures correctly while the window is occluded or behind
    other windows** on this D3D client (unlike the WowUnreal client, which needs
    `CopyFromScreen`). It samples a 24x24 grid and falls back to `CopyFromScreen`
    if the frame came back uniform, so a black result means a real black frame.
  - `click`/`rclick`/`move` — present but **unreliable, see above**. Kept only
    because they do work on the pure-GDI glue dialogs sometimes.
- **`wowin.ps1`** — FOREGROUND input (scan-code `keybd_event`, `SetCursorPos`,
  `CopyFromScreen`). Reliable for anything, including real clicks, but it
  **takes focus and moves the physical mouse**. The user has explicitly asked
  that this not be used while they are at the machine. Treat it as a
  last-resort/AFK-only tool.

**The dependable no-focus recipes:**
- *Glue screens*: `key ENTER` / `key TAB` / arrows / `key ESCAPE`. The login
  button and Enter World are the default-focused controls.
- *In-world UI*: `lua` and `luaclick`. Note the frame names in this client are
  **not** all stock — `CharacterMicroButton:Click()` and
  `ToggleCharacter("PaperDollFrame")` both no-op here (`dprint` reports
  `TOGGLED nil`), so look the real name up first with
  `/run for k in pairs(_G) do ... end` or from `rexxar-reference\ui-source`.
- *Reading results*: `dprint(...)` to chat (the world server logs every
  `CMSG_MESSAGECHAT`) for scalars, SavedVariables on disk for bulk.
- Keep each `/run` short. Long lines are where the dropped-character UI errors
  come from.

**The truly input-free path** is still the best one where it applies: we own the
addon, so drive everything from Lua + SavedVariables on disk — make `CoAReader`
auto-run on `PLAYER_LOGIN` (archive-gated) and read
`WTF\Account\<acct>\SavedVariables\Ascension_CoAReader.lua`. Zero OS input.
(A `/reload` to pick up new addon code still needs one `lua` command.)

---

## 3A. Account data — the WTF caches are SERVER state

**Symptom that started this:** a freshly created character had no keybinds at
all. Not "wrong" keybinds — none. `GetCurrentBindingSet()` returned `0` and
every `GetBindingKey()` was `nil`, so W/A/S/D did nothing, ESC opened nothing,
and the action bars were dead.

**It was never a client bug.** In 3.3.5a the five `WTF\...\*-cache.wtf` files
are exactly that — *caches*. The server owns the data and ships it at login:

```
SMSG_ACCOUNT_DATA_TIMES  0x209   u32 gametime | u8 1 | u32 mask | u32 time[popcount(mask)]
CMSG_REQUEST_ACCOUNT_DATA 0x20A  u32 type
SMSG_UPDATE_ACCOUNT_DATA 0x20C   u64 guid | u32 type | u32 time | u32 rawlen | zlib(raw)
CMSG_UPDATE_ACCOUNT_DATA 0x20B   u32 type | u32 time | u32 rawlen | zlib(raw)
SMSG_UPDATE_ACCOUNT_DATA_COMPLETE 0x463   u32 type | u32 0
```

Types: `0 GLOBAL_CONFIG, 1 PER_CHAR_CONFIG, 2 GLOBAL_BINDINGS,
3 PER_CHAR_BINDINGS, 4 GLOBAL_MACROS, 5 PER_CHAR_MACROS, 6 PER_CHAR_LAYOUT,
7 PER_CHAR_CHAT`. `GLOBAL_CACHE_MASK = 0x15` is sent at
`CMSG_READY_FOR_ACCOUNT_DATA_TIMES`; `PER_CHARACTER_CACHE_MASK = 0xEA` is sent
at `PLAYER_LOGIN` — same split AzerothCore uses.

`world_server.py` used to answer `ACCOUNT_DATA_TIMES` with a hardcoded
**`mask = 0`**, which is a perfectly well-formed *"I hold no account data"*. The
client believed it, never sent a single `CMSG_REQUEST_ACCOUNT_DATA`, and
correctly came up with nothing bound. That one integer was the whole bug.

**Now implemented** (backups `world_server.py.pre-acctdata`, `.pre-logout`):
- A JSON store at `realms\ascension\accountdata.json` — globals keyed by
  account, per-character keyed by guid. Both directions: the client's own
  uploads (`CMSG_UPDATE_ACCOUNT_DATA`) are inflated, stored, and acked, so
  config/layout/macros/chat now persist server-side like the real realm.
- `acctdata_seed_bindings()` seeds `realms\ascension\default-bindings.wtf`
  into `GLOBAL_BINDINGS` (and `PER_CHAR_BINDINGS` at login) for any account or
  character that has none. **Edit that file to change the archive default** — it
  is a byte copy of the `Name` profile's `bindings-cache.wtf` (1275 B), the
  profile the user nominated. Seeding is *once per key*, so any rebind the
  player makes uploads over it and wins permanently.
- `CMSG_REQUEST_ACCOUNT_DATA` / `CMSG_UPDATE_ACCOUNT_DATA` were removed from the
  silently-swallowed opcode tuple and given real handlers.

**Verified end to end**, server log + client files + in-game Lua:

```
seeded default keymap (1275 B) for GLOBAL_BINDINGS
ACCOUNT_DATA_TIMES global mask=0x15 times=[0, 1788279690, 0]
   ... client uploads type=2 <- 1275 B
ACCOUNT_DATA_TIMES per-char mask=0xEA times=[0, 1788279749, 0, 0, 0]
   ... CMSG_REQUEST_ACCOUNT_DATA -> type=3 (PER_CHAR_BINDINGS) -> 1275 B
client wrote WTF\Account\TEST\Area 52 - Free-Pick\Testbeta\bindings-cache.wtf
/run dprint(GetCurrentBindingSet(), GetBindingKey("MOVEFORWARD"))  ->  2  W
```

`bindings-cache.wtf` format: first line `BINDINGMODE 0` (0 *is* normal — the
genuine pre-archive live file has it), then `bind <KEY> <ACTION>` lines, LF.

**Consequently the client-side keybind hack is GONE.** The
`ASCARCHIVE KEYBIND RESTORE` block in
`client-ascension\Interface\FrameXML\Util\GlobalOverwrites.lua` (a
`LoadBindings(0)` + `SetBinding` loop + `SaveBindings(1)` at
`PLAYER_ENTERING_WORLD`) has been removed and replaced with a tombstone comment;
backup `GlobalOverwrites.lua.pre-keybind-retire`. Leaving it in would have
overwritten the server's bindings — including the player's own rebinds — on
every login. **Do not reintroduce it.** While in there, the ASCP5 measurement
probe was made opt-in (`/run ASC_Diag()`, or `ASC_DIAG = true`); it had been
painting ten lines of diagnostics over the play screen at every login.

**Logout also works now.** `CMSG_LOGOUT_REQUEST 0x04B` had no handler, so the
ESC menu's Logout button did nothing and the only way back to character select
was to kill the client. The archive answers instantly
(`SMSG_LOGOUT_RESPONSE = <u32 0><u8 1>` then an empty `SMSG_LOGOUT_COMPLETE`) —
there is nothing here to make a player wait for.

> **Opcode-table trap.** `ascension-opcodes.txt` is **off by one** in this range
> (it lists `0x4FE CMSG_READY_FOR_ACCOUNT_DATA_TIMES`, the client sends `0x4FF`;
> `0x208` vs. the real `0x209`) and wildly wrong higher up (`0x7F6` vs. the
> proven `0x9BC` for `SMSG_REALM_INFO`). This client uses **stock 3.3.5a
> numbering** for the low/mid opcodes. The captured unhandled dumps
> `world_unhandled_w001_04B.bin` / `_04E.bin` are an independent confirmation
> (`CMSG_LOGOUT_REQUEST` / `_CANCEL`). Always confirm against a capture.

---

## 4. THE CoA TREE — corrected root-cause chain

**§4 in the previous handoff was wrong and is replaced.** It claimed the tree
rendered with blank icons and blamed a missing spell/WDB cache. Neither holds:
the tree area was *completely empty* (zero nodes), and the icon names are in the
dataset all along. The real chain is two **server-side** faults, both now fixed
in `world_server.py`. Nothing about it is client-side, and no icon overlay is
needed — the old "Fix A" is withdrawn.

### 4.1 Fault #1 — every entry was invisible (fixed)

`GetEntriesByClass` (`0x10177050`) filters each entry through
`IsEntryVisible` (`0x101c6cc0`), which ends:

```
if (entry[+0x128] && RealmInfo[+0x40] /*IsLive*/)        return true;
if (entry[+0x129] && RealmInfo[+0x41] /*IsSeasonal*/)    return true;
if (entry[+0x12a] && RealmInfo[+0x42] /*IsLeague*/)      return true;
if (entry[+0x12b] && RealmInfo[+0x43] /*IsPTR*/)         return true;
if (!entry[+0x12c]) return false;
return RealmInfo[+0x44] /*IsDevelopment*/;
```

Our `SMSG_REALM_INFO` (0x9BC) sent that whole flavour cluster as zeroes, so
**no entry was ever visible** and every tree came back empty. `world_server.py`
now sends `REALM_FLAVOUR_LIVE = (1,0,0,0,0,0,0,0)` — `IsLive=1`, the rest off.

### 4.2 Fault #2 — visible entries then crashed the client (fixed, VERIFIED)

Making entries visible immediately produced **ERROR #132**
(`Errors\2026-09-01 01.41.16 Crash.txt`): `0xC0000005` reading `0x00000024`,
`Current Addon: Ascension_CoAReader`, faulting at `Extensions.dll+0x152920`.

`0x10152920` is a map lookup — `mov edx,[ecx+0x24]` — and `ecx` was NULL. Its
caller is the per-entry filter `0x101c6bd0`, which for every entry whose
`flags(+0x124)` have **bit 19** set does:

```
state = [CASingleton+0x24]        ; 0x101722e0 -> 0x1016fdc0, CASingleton = 0x10bde440
hit   = state->find(entry->id)    ; 0x10152920  <-- faults when state is NULL
if (!hit) return HIDDEN
```

`CASingleton+0x24` is the per-character *pending build* object. Its constructor
(`0x1016bde0`) zeroes it (`0x1016be7e: mov [edi+0x24],0`); **only the server
makes the client allocate it.** With flavour bytes zeroed no bit-19 entry was
ever reachable, so the null went unnoticed until fault #1 was fixed.

The allocator is `0x10173d00` (`push 0x278; call 0x10ae5d20` -> store at
`0x10173d61: mov [esi+0x24],eax`). Of its six callers the one the live realm
drives at world entry is opcode **`0x725`**, handler `0x10171d90` — found by
sweeping `.text` for the registration pattern (see `opcode-handlers.txt`).

**`SMSG_CA_ACTIVE_SPEC` (0x725)** — body is exactly two u32, read at
`0x10171e23..0x10171e3b`:

| field | -> | note |
|-------|----|------|
| `u32 activeSpecIndex` | `CAContainer[+0x14]` | `GetActiveSpecID` returns this **+1** |
| `u32 specSlotCount`   | `CAContainer[+0x18]` | upper bound for loadout lookups |

On the first 0x725 of a session (`[CASingleton+0x00]` still null) the handler
also builds the per-GUID container from the local player GUID (the client's own
getter is `Ascension.exe!0x4d3790`) and calls `0x10173d00` — the allocation that
was missing. It then fires
`ASCENSION_CA_SPECIALIZATION_ACTIVE_ID_CHANGED` with `"%u"` of index+1.

The copy source `0x1016f390` safely returns the static empty build `0x10bde8a8`
when there is no active loadout, so this cannot crash on a fresh character.
With an empty-but-valid state, bit-19 entries are simply **hidden** — which is
the authentic result for a character that has unlocked nothing — instead of
faulting.

`world_server.py` now sends 0x725 in the `CMSG_PLAYER_LOGIN` burst, right after
`SMSG_TIME_SYNC_REQ`. **This is written and syntax-checked but NOT yet verified
in a running client** (see 4.4).

**Safety net if the packet turns out to be insufficient:**
`C_CharacterAdvancement.CancelPendingBuild()` (`0x10175ea0`, 15 bytes, tail-calls
`0x10173d00`) performs the same allocation from Lua.

### 4.3 Opening the panel

Open it with `Collections:GoToTab(Collections.Tabs.CharacterAdvancement)`.
Never `:Show()` the `CharacterAdvancement` child frame directly — see memory
`ascension-coa-render-contract`.

### 4.4 VERIFIED — what the client actually reported

Both fixes were run against a live client on 2026-09-01. **The elevation problem
in the previous handoff was a false blocker**: `Ascension.exe` does embed
`<requestedExecutionLevel level="requireAdministrator">` (manifest at file offset
`0x7567bb`), but `__COMPAT_LAYER = 'RunAsInvoker'` (§2) launches it *unelevated*
from an ordinary agent session. The earlier `Start-Process` failures had simply
not set that variable. Do not patch the manifest — the client directory is a
junction into the live install (§1).

Measured, before → after:

| probe | before both fixes | after |
|---|---|---|
| `C_Realm.IsLive` | `false` | `true` (also `IsProduction=true`) |
| `GetEntriesByClass` populated buckets | **0 of 159** | **153 of 159** |
| `GetAllEntries()` | 10255, then crashed the process | **8873**, clean |
| `Tinker/Class` | 0 | 36 entries / 24 spells / 12 talents |
| `GetEntryPosition` | n/a | real grid cells (`4,2`, `3,1`, `2,3`) |

Notes on those numbers:

- **8873, not 10255.** 10255 is the raw `CharacterAdvancement.dbc` record count.
  8873 is the subset visible on a **Live** realm — `IsEntryVisible` filters the
  rest as seasonal/league/PTR/dev-only. `hType` splits it exactly:
  `Ability=3144 + Talent=5472 + TalentAbility=257 = 8873`. So the offline export
  is the superset and this is the authentic live view of it.
- **The 6 empty buckets are correct, not a bug.** `Mage/Class`, `Hero/Class` and
  `General/General1` legitimately hold nothing — base classes browse a pool, they
  do not get a laid-out "Class" tab.
- **The dataset is level-independent.** Identical 8873/153 at level 1 and at
  level 80. Only the *UI* gates on level (§0).

The 42 classes that returned entries, i.e. the whole Ascension roster:
Barbarian, Chronomancer, Cultist, DeathKnight, DemonHunter, Druid, Guardian,
Hunter, KnightOfXoroth, Mage, Monk, Necromancer, Paladin, Priest, Primalist,
Pyromancer, Ranger, Reaper, RebornDeathKnight, RebornDruid, RebornHunter,
RebornMage, RebornPaladin, RebornPriest, RebornRogue, RebornShaman,
RebornWarlock, RebornWarrior, Rogue, Runemaster, Shaman, SonOfArugal,
Starcaller, Stormbringer, SunCleric, Tinker, Venomancer, Warlock, Warrior,
WitchDoctor, WitchHunter.

**Live confirmation of the offline DBC decode.** The engine's own entry for
ID 5116 came back as:

```
ID=5116  Name="Clockwork Ingenuity"  Class=Tinker  Tab=Class  Type=Ability
Icon=t_roboticon  NodeType=SpendCircle  Color=TEAL  Anchor=TOP
PositionX=4  PositionY=2  SizeX=1  SizeY=1  Row=0  Column=0
ConnectedNodes={5998, 6001}  Spells={505336}  AECost=1  Quality=Poor
```

`PositionX/PositionY` match the four misaligned LE floats this session decoded at
DBC byte offset `0x18E` **exactly**, and `GetEntryPosition` returns the same pair
— an independent validation of §4.5. `SizeX/SizeY` show the same bimodal 1.0 /
64.0 split found offline. `Row` and `Column` are `0`, which is why the earlier
dword-aligned grid sweep found nothing: the layout is Position-based, and
Row/Column are vestigial.

### 4.4b How to re-verify in one pass

1. Launch per §2 (`RunAsInvoker`), click Login `(640,590)`, Enter World `(640,657)`.
2. The `Ascension_CoAReader` addon auto-runs on `PLAYER_LOGIN` (archive-gated).
   `AUTORUN_PLAN` is `"tree known edges report"`; the `report` step pushes every
   scalar over `SendChatMessage`, so `world_server_log.txt` has the answer with
   no input. **The gate is `ASC_IsArchive()`, which reads the `realmList` CVar,
   so this only fires if you launched via `launch-client.ps1`** — see the
   warning at the end of §4.9, and call `CoAReader_Do*()` directly if it does
   not fire.
3. For bulk data, `/reload` once and read
   `WTF\Account\TEST\SavedVariables\Ascension_CoAReader.lua` (a lupa one-liner
   parses it; see the session scratchpad `sv.py`).
4. `tools\wowin.ps1 -Action run -Text '/run ...'` opens chat, types and submits in
   one call. **Invoke it with `& $path`, never `powershell -File $path`** — the
   nested parse eats the double quotes inside the Lua.

### 4.5 The dataset is offline — no client run needed for it

`DBFilesClient\CharacterAdvancement.dbc` (in **patch-M.MPQ**) is the engine's
real entry table: **10255 records, exactly the `GetAllEntries()` count.** It is
extracted, decoded and exported to `rexxar-reference\ca-dbc-export\`
(entries.json / entries.csv / classes / tabs / categories), with the recovered
schema and the evidence for every named column in
`rexxar-reference\ca-dbc-export\SCHEMA.md`.

Two parsing traps, both documented there: the header's `field_count` (179)
contradicts `record_size` (692 = 173 dwords) and only `record_size` is real; and
**the tree geometry is not dword-aligned** — `PositionX/PositionY/SizeX/SizeY`
are four floats at byte offset `0x18E`, i.e. 2 mod 4. Read as dwords they look
like garbage, which is why a naive sweep concludes the grid isn't in the file.
Read correctly: PositionX 0..10, PositionY 0..9 over 3716 entries, and
`Tinker/Mechanics` comes straight out as a laid-out tree.

Only the **custom hero-class trees are positioned**. Base classes (`Mage/Arcane`
and friends) carry no geometry at all because that pool is browsed, not laid
out — expect that, don't chase it.

This supersedes `rexxar-reference\ca-export\` (wrong dataset) and
`Data\Content\CharacterAdvancementData.json` (a UI-side companion, 23709
entries, *not* what the engine loads — useful only as a cross-check; it agrees
on Name and Icon, which is how the column mapping was independently confirmed).


### 4.6 The probe now reports over the wire, one step per frame

`CoAReader.lua` was hardened after the ERROR #132 run, because every readback
channel it had failed at once:

- `pcall` does **not** contain a C-level access violation — the fault inside
  `GetEntriesByClass` killed the process and no Lua error handler ran.
- SavedVariables are written only on a **clean** exit/reload, so the crash took
  the whole `CoAReaderDB` with it.
- `Screenshot()` is queued to end-of-frame, so it is worthless as a breadcrumb
  when the entire probe runs inside one `PLAYER_LOGIN` frame. (This is why the
  newest PNG on disk was from the previous day.)

Two changes:

1. **`CoAReader_Say(msg)`** mirrors every line to `SendChatMessage(chunk,"SAY",0)`.
   Language **0 is Universal**, so it does not depend on the character knowing a
   racial language — which is what the queued "grant racial language" fidelity
   fix was wrongly blamed for. `world_server.py` already logs these as
   `>>> CHAT[type=1 lang=0]: ...`; the channel had simply never been fed, because
   nothing in the probe ever called `SendChatMessage`.
   **Read them in `realms\ascension\world_server_log.txt`.**
2. **The autorun runs one plan word per frame** (0.25 s apart) via an `OnUpdate`
   stepper, and says `step i/N -> <word>` before and `step i (<word>) returned`
   after. A crash in step N therefore leaves steps 1..N-1 fully recorded on the
   server, and pinpoints the failing step without a Lua stack.

`AUTORUN_PLAN` is now **`"tree why"`** — `tree` is the cheap decisive probe,
`why` is the full dataset sweep, deliberately second so it cannot cost us the
`tree` result. Edit the constant on disk (near the top of the autorun block);
it is a Lua constant, **not** SavedVariables, because `ReloadUI()` rewrites
SavedVariables on the way out.

### 4.7 Where the hero classes are — and why the CA panel does not show them

The Character Advancement panel's class row shows **only the 10 base WotLK
classes**. That is authentic, not a gap. Confirmed two independent ways:

- Live: `CHARACTER_ADVANCEMENT_CLASS_ORDER` = `DEATHKNIGHT DRUID HUNTER MAGE
  PALADIN PRIEST ROGUE SHAMAN WARLOCK WARRIOR`.
- Source: `CharacterAdvancementMixin:SelectClass(classFile, specFile)`
  (`ui-source/Ascension_CharacterAdvancement/CharacterAdvancement.lua:828`)
  falls back to `next(self.ClassButtons)` for an unknown `classFile`, then
  **returns early** unless `CHARACTER_ADVANCEMENT_CLASS_SPEC_ORDER[classFile]`
  exists. Neither table has hero classes. So there is no supported way to drive
  a hero tree through this panel, and forcing one would be a client hack.

The name mapping does exist though — `CharacterAdvancementUtil.GetClassDBCByFile`
returns `TINKER→Tinker`, `RANGER→Ranger`, `BARBARIAN→Barbarian`,
`DEMONHUNTER→DemonHunter`, `HERO→Hero` (`PRIMALIST` errors, so its file token is
spelled differently). And the *data* is fully served: all 42 classes above come
back from `GetEntriesByClass` right now.

Hero classes are reached through the **Archetypes** bottom tab. `CMSG 0x62E`
(the *"describe game mode &lt;name&gt;"* query that used to spin on a black panel)
**is implemented** — `world_server.py` answers `0x62F` with
`chunkIndex 0 / version 0 / recordCount 0`, the honest "this mode exists and has
no records". The archetype **creation** wizard works: *Testbeta* was created with
the *Hoplite* archetype.

Still open there: the archetype's **build** never gets applied. The client stores
`archetypeBuildID` in a WTF blob and calls `C_BuildCreator.ActivateBuild(id,
true, true)` on the character's first login — that runs, but emits nothing on
the wire, so nothing is learned. Also lower priority: opcode `0x726` (handler
`0x10171260`) would fill *Ability Essence* / *Talent Essence* and un-grey the
four "Choose Your Path" icons.

---

### 4.8 Character creation shows three class pages — and none of them filter by race

Reported symptom: *"I only see 9 classes at the character select screen... missing
classes like Tinker"*, with a guess that the client had filtered by race.
**It does not.** `C_CharacterCreate.CanCreateClass` (`Extensions.dll
0x1018d550`) takes only a classID and never looks at the selected race —
disassembled end to end:

```
classID > 0x20              -> false
classID 12..32 (CoA)        -> jump table, ALL 21 arms -> 0x1018ae90
                               = RealmInfo[+0x46] (CoA) || RealmInfo[+0x44] (IsDevelopment)
classID 1..11 (classic)     -> jump table; 6 (DEATHKNIGHT) and 10 (HERO) -> false
                               everything else -> 0x1018aec0
                               = RealmInfo[+0x47] (Wildcard) || RealmInfo[+0x44]
```

Those are the **same realm-flavour bytes we already send** in `SMSG_REALM_INFO`
(§ `smsg_realm_info`, `REALM_FLAVOUR_DEV` sets `+0x44`), one offset below the
`+0x48` addon gate. So on this archive every class in both lists is available.

There are **three** class pages, and `CharCreateSwapClassesButton` cycles them
`FREEPICK -> REGULAR -> COA -> FREEPICK` (`CharacterCreate_SwapClasses`,
`ui-source/GlueXML/CharacterCreate.lua:1783`). The button only exists at all when
`C_Realm.IsDevelopment()` — another thing `REALM_FLAVOUR_DEV` buys us.

- **REGULAR** iterates `CLASSIC_CLASS_ORDER`, which has **11** entries (the 10
  base classes + `HERO`). Death Knight and HERO are hard-rejected above, so it
  draws exactly **9 buttons**. That is the "9 classes" — not a race filter.
- **COA** iterates `COA_CLASS_ORDER`, 21 entries, `TINKER` sixth. **Tinker is
  there**, one more press of *Switch Classes*.
- Race *is* used, but only in the optional **Class Guide** flow
  (`CharacterCreateUtil.IsRaceClassEnabledAndValid`), which is a different panel.

Confirmed live in-game rather than inferred (`SendChatMessage` readback through
the world log):

```
Enum.Class.TINKER = 28   Enum.Class.CustomStart = 12   Enum.Class.HERO = 10
GetClassInfo(28)  = "Tinker" / "TINKER"
```

28 is inside the CoA range, so `CanCreateClass(28)` is true here and
`GetClassInfo` gives the button a name and an icon file — both conditions
`CharacterCreate_ShowCoAClasses` needs. Coming back to character creation lands
on whichever page matches the *last selected class*
(`CharacterCreate_RefreshClassButtons`), which is why the page appears to change
by itself between visits.

### 4.9 Opcode `0x726` — the known-entries packet (decoded, implemented, VERIFIED)

The previous handoff guessed `0x726` was "the loadout/build content packet" that
would fill *Ability Essence* / *Talent Essence*. **That guess was wrong on both
counts.** Essence comes from `0x722`, which is already implemented and streams
Ascension's own per-level curve out of `CharacterAdvancementEssence.dbc`.
`0x726` is the set of **CA entries this character has learned** — what makes a
node draw as learned instead of greyed, and what `IsKnownID` answers from.

Handler `0x10171260`, registered at `0x10172249`, one slot after `0x725` in the
CA registration block `0x1017222c..0x101722d7` (the family is `0x659`, `0x65b`,
`0x6e2`, `0x725`, `0x726`, `0x728..0x72c`).

**Wire format.** The body is a length-prefixed vector read by `0x10166760`
straight off the ByteBuffer. The element is 0x20 bytes in memory but only **21
bytes on the wire** — the sequential reads at `0x101668b0..0x10166900` fill
exactly the fields the element constructor `0x10150020` zero-initialises:

```
u32 count
count x {
    u32 entryId    -> rec[+0x04]   CharacterAdvancement.dbc entry ID; the map key
    u32 rank       -> rec[+0x08]   copied to the resident store's +0x0C
    u32 unk0C      -> rec[+0x0C]
    u8  flag       -> rec[+0x10]   diffed against the old state's GetFlag (0x10155640)
    u32 unk18      -> rec[+0x18]
    u32 unk1C      -> rec[+0x1C]
}
```

`rec[+0x00]` is constructor-set and never on the wire; `rec[+0x14]` is pure
padding after the byte. The archive sends 0 for the four unknowns — the
constructor default, i.e. what a plainly-known entry looks like.

**It is a diff, not a store.** The handler compares the vector against the state
the client already holds and fires one Lua event per change —
`ASCENSION_KNOWN_ENTRY_UPDATED` (`"%u%u"` of id, rank),
`ASCENSION_ENTRY_UPDATED`, `ASCENSION_KNOWN_ENTRY_REMOVED`, then
`ASCENSION_KNOWN_ENTRIES_UPDATED` once at the end. So **re-sending the full set
is the supported way to change it**, removals included; the client works out the
deltas itself. That is exactly what `send_known_entries()` does.

**Where the client reads it back.** `C_CharacterAdvancement.IsKnownID`
(`0x1017c830`) and `GetTalentRankByID` (`0x1017b410`) go through `0x10a31720` /
`0x10a31bb0`, which walk a resident **0x2C-stride** store, matching the id at
`+0x00` and returning the rank from `+0x0C`. The `0x20`-stride vector above is
the wire/diff shape; `0x2C` is the resident shape. The link between them is
`0x10171523` (`mov [eax+0xc], esi`), which stores the wire record's `+0x08` into
the resident record's `+0x0C` — i.e. **wire `rank` is resident `rank`**.

**Ordering matters.** At `0x10171376` the handler looks up the per-GUID CA
container and, if it is missing, allocates the pending build (`0x10173d00`) and
returns *without applying anything*. `0x725` is what builds that container at
world entry, so `0x726` must follow it — which is also the order the live realm
uses. The world-entry burst sends `0x725`, then the essence budget, then
`0x726`.

**The archive's side.** `realms\ascension\knownentries.json` — `{ guid: [{id,
rank}, ...] }` — is replayed at every world entry, empty count included (a
zero-count `0x726` is the well-formed "you know nothing", and it still drives
the refresh event). It is edited with a new dot-command:

```
.known                       list learned entries (names from the DBC export)
.known add <id> [rank]       learn one entry by CharacterAdvancement.dbc ID
.known remove <id>           forget one
.known class <Class> [Tab]   learn a whole class, or one tab of it
.known clear                 forget everything
```

`.known class` resolves names through `rexxar-reference\ca-dbc-export\entries.csv` (lazy-loaded, 10255 rows; the CSV rather than the 17 MB JSON).
`.known class Tinker Class` learns 36 entries; `.known class Tinker` learns all
158 across Class / Firearms / Invention / Mechanics.

This is also the archive's answer to open item 1: the archetype build never
applies because `ActivateBuild` emits nothing on the wire, but the *state* it
would have produced is now settable directly, server-side.

**Status: VERIFIED against a running client, 2026-09-01 11:19–11:26.**
Every part of the decode above held up on the wire:

- **World entry.** The burst logged
  `1376 essence record(s): AE 80 / TE 71 at level 80, 36 known CA entry/entries`,
  and the engine answered `GetKnownSpellEntries=24  GetKnownTalentEntries=12`
  — 36 total, split exactly the way the DBC splits the `Tinker/Class` bucket
  (`tree.Tinker/Class entries=36 spells=24 talents=12`). The same probe on the
  previous run reported `knownSpellEntries=0`, so this is a clean before/after.
- **`IsKnownID` / `GetTalentRankByID` agree.** Every spot-checked id came back
  `IsKnownID=true rank=1`, canary 5116 included.
- **The `rank` field is confirmed, not inferred.** `.known add 5116 3` →
  `GetTalentRankByID(5116)` returned **3**, with all 35 other entries left at 1.
  That is the wire `rec[+0x08]` → resident `+0x0C` link (`0x10171523`)
  observed end to end.
- **The diff path works in both directions, mid-session, with no relog.**
  `.known clear` sent a 4-byte body (count 0) and the engine dropped to
  `GetKnownSpellEntries=0  GetKnownTalentEntries=0`; `.known class Tinker Class`
  sent **760 bytes = 4 + 36 x 21**, exactly the format above, and it went
  straight back to 24/12.
- **No regression.** The `tree` probe still reports 7414 entries / 157 class|tab
  pairs / 152 populated buckets, unchanged from before the change.

⚠ **The autorun silently does nothing on a fresh client's FIRST login.**
`CoAReader`'s autorun is gated on `ASC_IsArchive()`, which tests the
**`realmList` CVar**. Measured on this run, with the client started by calling
`Ascension.exe` directly (so half 1 of §1, rewriting `Config.wtf`, never
happened):

| when | `GetCVar("realmList")` | `ASC_IsArchive()` | autorun |
|------|------------------------|-------------------|---------|
| 1st world entry after process start | `51.210.230.10` | `false` | **skipped** |
| 2nd, after a reconnect in the same process | `127.0.0.1:3799` | `true` | ran |

So the native restore-to-official documented in §1 fires **once**, between the
first login screen and the first world entry; glue Lua's force then sticks for
every later login in that process. The *connection* is local and correct
either way — only the archive-gated Lua is affected, and it fails silently.
**Launch via `launch-client.ps1`** (which rewrites `Config.wtf` and makes the
first login behave), or just reconnect once. Do *not* work around it with
`SetCVar("realmList", ...)` in the world: `Config.wtf` is on the junction and is
rewritten on exit, so that leaks onto the live install. The probes themselves
are not gated — only `Dispatch()` and the autorun are — so the direct call
always works: `ghostinput.ps1 -ProcId <pid> -Action lua -Text 'CoAReader_DoKnown()'`.

Two smaller things worth knowing when driving this by hand:
- `SendChatMessage(msg, "SAY", 0)` fails with **`Unknown language`** on this
  character; drop the language argument. (`CoAReader_Say` already pcalls and
  falls back, which is why its own output was unaffected.)
- `ghostinput.ps1 -Action slash` did not deliver a leading-`.` command. Send it
  as `-Action lua -Text 'SendChatMessage(".known clear","SAY")'` instead —
  `world_server.py` only needs the `CMSG_MESSAGECHAT` to start with `.`.

---

### 4.10 `ConnectedNodes` — the tree's edge graph (SOLVED, exported)

Dumped out of the live engine on 2026-09-01 by `CoAReader_DoEdges`, which walks
`CA.GetAllEntries()` and harvests `e.ConnectedNodes` into `CoAReaderDB.edges`.
The engine reported **7414 entries, 3517 with edges, 5597 edges, max degree 5**,
and the parse of `WTF\Account\TEST\SavedVariables\Ascension_CoAReader.lua` reproduces those three numbers
exactly. It ships as `rexxar-reference\ca-dbc-export\edges.json` — `{ "<entryId>":
[entryId, ...] }`, 93 KB.

**The edges are directed, and they point at prerequisites.** Four independent
checks, all from the exported data:

- **Zero of the 5597 endpoints are reciprocated.** This is not an adjacency
  list; if it were symmetric, ~all of them would be.
- **Every edge goes to a lower `PositionY`**: delta −1 in 4906 cases, −2 in 574,
  0 in 109, −4 in 5, and **never positive**.
- **Every node with no `ConnectedNodes` sits at `PositionY = 0`** — all 280 of
  them, no exceptions. Top-row nodes have nothing above them to require.
- The 109 zero-delta edges are *all* between row-0 nodes, i.e. the same-row
  links at the top of a tab, not a counter-example.

So `entry.ConnectedNodes` = "the nodes I descend from", pointing up toward row 0.
Note this is the multi-parent generalisation of the separate scalar `ParentNode`
field (5116 has `ParentNode=0` but two `ConnectedNodes`), so a renderer wanting
the real graph must use this, not `ParentNode`.

**Two more invariants for a renderer:**
- **No edge crosses a class/tab boundary** — 0 of 5594 resolvable edges. Every
  tab's graph is self-contained, so it can be laid out independently.
- Max in-degree is 5, same as max out-degree.

**One wart:** three edge targets (`6451`, `7181`, `17567`) are not rows in
`entries.csv`. 3 dangling out of 5597; drop them rather than failing the import.

Canary, matching what the engine reported live:

```
 5116  Y=2 X=4  Clockwork Ingenuity     Tinker/Class -> [5998, 6001]
 5998  Y=1 X=3  Explosive Personality   Tinker/Class -> [29203, 31113]
 6001  Y=1 X=5  Refined Gunpowder       Tinker/Class -> [29203, 29813]
```

---

### 4.11 `ActivateBuild` — opcode `0x5C2` (SOLVED, VERIFIED)

The previous handoff's open item 1 said `C_BuildCreator.ActivateBuild(buildID,
true, true)` "emits nothing on the wire". **It emits.** The archive had been
capturing the packet the whole time and simply did not know the opcode:
`world_unhandled_w003_5C2.bin`, 39 bytes, logged at 10:04:06 as
`<- 0x5C2 (39 B body)`. Before hunting a silent client, grep the unhandled
captures.

`ActivateBuild` is a C binding after all — `findfn.py` misses it, but the name
string is at `0x10b2e6d0` and the binding table that installs it is written at
`0x1010df63`, giving handler **`0x10101740`**. Reading it straight through:

```
0x101017bf  call 0x10309e50   validation on arg 1; returns 0 -> bail at 0x101017c9,
                              return false, SEND NOTHING.  The only silent path.
0x101017df  call 0x84f9f0     lua_tolstring(arg 1) -- the build ID is a STRING
0x101018a0  push 0x5c2        packet ctor; this is the opcode
0x101018bb  0x10087390 / 0x100b97a0    append the id as a CString
0x101018d7  [0x10bc90dc](&b, 1) x2     append the two booleans, one byte each
0x1010190d  send
```

Body:

```
CString buildID    a 36-char UUID, e.g. "1ef4bae3-780c-444c-833f-ecf46149de94"
u8      arg2       the first  `true`
u8      arg3       the second `true`
```

36 + 1 + 1 + 1 = **39**, exactly the captured length, and the capture's tail is
`\x01\x01` — the two `true`s.

**How the archive answers it.** An activated build *is* a set of learned
entries, so applying one means applying its entry list and re-sending
`SMSG_CA_KNOWN_ENTRIES` (§4.9). Ascension kept the real build contents
server-side and that store did not survive, so the archive keeps its own in
`builds.json`, populated from whatever `.known` currently holds:

```
.build                     list stored builds
.build save <id> [name]    record the current .known set as build <id>
.build apply <id>          activate a stored build now
.build forget <id>         delete one
```

An id with no stored build is **reported, not guessed at**: the handler logs it
and re-sends the character's existing set unchanged, so the client's pending
activation resolves against real state instead of hanging.

**Verified live, 2026-09-01 11:41–11:42**, in this order:

1. `.build save 1ef4bae3-... Hoplite` → 36 entries written to `builds.json`.
2. `.known clear` → engine drops to `GetKnownSpellEntries=0 GetKnownTalentEntries=0`.
3. `C_BuildCreator.ActivateBuild("1ef4bae3-...", true, true)` → returned **`true`**
   (so the `0x10309e50` validation passes for a plain well-formed UUID), and the
   server logged
   `<- CMSG_BUILD_ACTIVATE (39 B body)` →
   `BUILD_ACTIVATE 1ef4bae3-... (args 1,1) -> applied 'Hoplite': 36 entry/entries learned`.
4. The client came back to `GetKnownSpellEntries=24  GetKnownTalentEntries=12`,
   `IsKnownID=true` on every spot-check. **0 → 36 across one activation.**

What is still *not* known is what Ascension's own archetype builds contained —
that data was on their server. The mechanism is complete; the content has to be
authored with `.build save`.

---

### 4.12 Archetype builds — the client-side contract (list/detail, schema recovered)

the maintainer confirmed the Archetypes screenshots are from the **LIVE** realm, not the archive. That is exactly the point: the build *content* has never been in our client. Grep proves it — `Wind Rager` appears nowhere under `Data\Content\*.json` or `Interface\`. Builds arrive **entirely over the wire**, which is why the archive's Archetypes tab is empty.

The *consumer*, however, is local and complete: `Interface\AddOns\Ascension_BuildCreator\` (4786 lines). It pins the contract exactly.

**API surface (`C_BuildCreator`)** — `QueryAllBuilds(category)`, `QueryBuild(buildID)`, `GetNumBuilds`, `GetBuildAtIndex`, `GetBuild(buildID)`, `GetSpell`, `UpdateFilter(text, classFilter, sort)`, `CanActivateBuild(id) -> canActivate, reasons`, `ActivateBuild`, `DeleteBuild`, `RateBuild`, `IsUpvotedBuild`, `IsOwnedBuild`, `BookmarkBuild`, `GetNumBookmarkedBuilds`, `GetBookmarkedBuildAtIndex`. The "Create a Build" flow is a separate namespace: `C_BuildEditor.GetPendingBuild` / `.PublishBuild`.

**Events — these are the SMSG landing points to implement:**
`BUILD_CREATOR_CATEGORY_RESULT`, `BUILD_CREATOR_BUILD_RESULT`, `BUILD_CREATOR_ACTIVATE_RESULT`, `BUILD_CREATOR_DEACTIVATE_RESULT`, `BUILD_CREATOR_SAVE_RESULT`, `BUILD_CREATOR_CREATE_RESULT`, `BUILD_CREATOR_DELETE_RESULT`, `BUILD_CREATOR_RATE_RESULT`.

**It is a two-stage list/detail protocol** — the archive needs two responses, not one. `QueryAllBuilds(category)` -> `CATEGORY_RESULT` fills the scroll list; clicking a row calls `QueryBuild(buildID)` -> `BUILD_RESULT` with the full record. `BuildCreatorMixin:ViewBuildID` (BuildCreator.lua:506) shows the caching rule: try `GetBuild` first, only query on a miss.

**Build record** (names are exact — the UI indexes them by name):
`ID`, `Name`, `Category`, `Icon`, `Description`, `AuthorName`, `PrimaryStat`, `Roles`, `ArmorTypes`, `WeaponTypes`, `DifficultyRating`, `Upvotes`, `UpdatedTime`, `LegendaryEnchant`, `RandomEnchants`, `Spells`, `NeedsRepairs`, `LevelingID`, `EndGameIDPVE`, `EndGameIDPVP`, plus eight counts: `NumCore/Optimal/Empowering/Synergistic` x `Spells/Talents/Abilities`.

Mapped onto the live screenshots: `Name`=Wind Rager, `AuthorName`=Ascension, `PrimaryStat`=Strength, `DifficultyRating` -> "Complexity: Intermediate", `Upvotes`=1934 (labelled "Rating"), `LegendaryEnchant`=Wind Rager (the signature shown beside the name), `Category`=Featured / Leveling Builds. Note the three buttons `View PvE Build` / `View PvP Build` / `View Leveling Build` are `EndGameIDPVE` / `EndGameIDPVP` / `LevelingID` — **an archetype is a set of three linked builds, not one.**

**Spell entry (`build.Spells[i]`)**: `Spell` (the ID), `TalentID`, `Comment`, and four flags — `IsCoreAbility`, `IsOptimalAbility`, `IsEmpoweringAbility`, `IsSynergisticAbility` — which drive the Core/Optimal/Empowering/Synergistic checkboxes in the detail view. The "Level 1 / Level 4 / Level 6" grouping and the "Rank 1/5" suffix are rendered from the CA entry itself, not stored on the build row.

**This independently confirms the `0x5C2` trailing bytes.** The detail view carries exactly two controls above the build: `Activate Build` and a checked `Auto-Learn Spells`. Our live capture was `args 1,1`. The second `u8` is **Auto-Learn Spells**; the first is the activate/confirm flag. The §4.11 handler currently ignores both — honouring `auto-learn = 0` (set the pending build without learning it) is the natural next increment.

**Bottom line for the archive:** the activation mechanism (§4.11) is done and the record schema is now known, so builds can be authored and served offline. What is *not* locally recoverable is Ascension's own build library — those rows only ever existed on their server.

## 5. Scope / safety (still in force — from the user)
- Local environment + provided client files ONLY. Do NOT target Ascension
  production infra, external accounts, credentials/secrets, anti-cheat, or any
  third-party system.
- Do NOT patch `Extensions.dll` on disk (reading/disassembling/RPM-reading is OK).
  RPM/Frida instrumentation is READ-ONLY. Do NOT WriteProcessMemory to flip flags.
  Do NOT ask for the real Ascension password. Do NOT run the launcher repair
  (reverts our work). Do NOT add auto-running/account-mutating code to shared
  FrameXML without an archive gate (junction leak).
- Editing our loose client Lua, `world_server.py`, `shim3799.py`, and our auth
  server IS in scope.

## 6. Key files
- `realms\ascension\shim3799.py` (+ `rpm_readk.py`), `world_server.py`, `launch-client.ps1`
- `realms\ascension\accountdata.json` (server-side WTF caches), `default-bindings.wtf`
  (the seeded default keymap — edit this to change it), `restart-world-clean.ps1`
- `realms\ascension\builds.json` (build id → entry list, applied on
  `CMSG_BUILD_ACTIVATE`; edited with `.build` — see §4.11)
- `realms\ascension\knownentries.json` (learned CA entries per guid, replayed as
  `SMSG_CA_KNOWN_ENTRIES`; edited with `.known` — see §4.9)
- `realms\ascension\tools\wowin.ps1`, `tools\ghostinput.ps1`
- `client-ascension\Interface\GlueXML\AccountLogin.lua` (realm force — loose, on the junction)
- `client-ascension\Interface\AddOns\Ascension_CoAReader\` (our reader; `/coa <plan>`,
  autorun selected by the `AUTORUN_PLAN` constant near the top of `CoAReader.lua`
  — *not* SavedVariables, because `ReloadUI()` rewrites those on the way out)

**Static-analysis tools (read-only; the DLL is never written):**
- `tools\disx.py` — capstone disassembler for `Extensions.dll`.
  `disx.py <va> [n]`, `--xref <va>`, `--secs`. Importable (`DATA`, `BASE`,
  `va2off`, `off2va`). Must NOT be renamed `dis.py` — it shadows the stdlib.
- `tools\annot.py <lo> <hi>` — disassemble a range, annotating immediates that
  resolve to strings. This is what read the entry→Lua table builder.
- `tools\opcmap.py` — sweeps `.text` for the opcode registration pattern
  (`push 0 / push handler / push opcode / call 0x102c4590`).
- `tools\luabind.py <lo> <hi>` — recovers `{name, lua_CFunction}` pairs.
  Use the region form; `--fn` brute mode is buggy.
- `tools\findfn.py <name>` — locate one Lua binding via its `.rdata` string.
- `tools\dbcprof.py <file.dbc>` — column profiler for schema-less DBCs.
- `tools\ca_export.py` — builds the CoA dataset export from the DBCs.
- `tools\edges_import.py` — imports the tree's edge graph out of the
  CoAReader SavedVariables into `ca-dbc-export\edges.json`, re-checking every
  invariant in §4.10. `--check` validates without writing.
- `tools\extract_ui.py <Addon>` — pulls a FrameXML addon out of the MPQ chain by
  following TOC/XML references (Ascension's patches ship no listfile).

**Reference material recovered (`realms\ascension\rexxar-reference\`):**
- `opcode-handlers.txt` — **361** custom opcode → handler VAs. Note `0x9BC`
  (`SMSG_REALM_INFO`) is *not* in it; that one dispatches elsewhere.
- `ca-lua-bindings.txt` — all **133** `C_CharacterAdvancement` bindings with VAs,
  validated against the client's own `CA_keys`.
- `ca-dbc\` — the 9 extracted DBCs (CA set + ChrSpecs + SpellTags), all from
  `patch-M.MPQ` except SpellTags/SpellTagTypes (`patch-S.MPQ`).
- `ca-dbc-export\edges.json` — the tree's edge graph, dumped from the
  live engine: 5597 directed prerequisite edges over 3517 nodes. See §4.10.
- `ca-dbc-export\` — **the authentic CoA dataset**: 10255 entries, 46 classes,
  94 tabs, 51 categories, as JSON + CSV. Read `ca-dbc-export\SCHEMA.md` first.
- `ui-source\` — extracted FrameXML for `Ascension_CharacterAdvancement`,
  `…Season9`, `Ascension_CoATalents`, `Ascension_PathToAscension`.

**Superseded — do not use:**
- `rexxar-reference\ca-export\` (45 classes) — built from the wrong dataset.
- `client-ascension\Data\Content\CharacterAdvancementData.json` — a UI-side
  companion file, not what the engine loads. Useful only as a cross-check.

- Deep render contract: `realms\ascension\HANDOFF-CA-REXXAR.md`; memory
  `ascension-coa-render-contract`.


