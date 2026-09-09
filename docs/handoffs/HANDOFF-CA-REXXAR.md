# HANDOFF — Rexxar (Conquest-of-Azeroth) Character-Advancement UI

**Written:** 2026-08-31 (evening) · **For:** a fresh session to continue overnight
**Local archive project.** Read the SCOPE/SAFETY section before doing anything.

---

## 0. TL;DR

- **DONE (foundation, proven live):** the Ascension custom-UI addon-loadability gate is open
  end-to-end against the local emulator, and the classless **Character Advancement UI opens via
  `/ca`** and is interactive.
- **GOAL for tonight:** replicate the **Rexxar realm's** Character-Advancement menus — the
  **Conquest-of-Azeroth (CoA) hero classes** (Tinker, Necromancer, Reaper, …) with their
  **icons / talents / spells / masteries**. Rexxar did **not** use standard WoW classes; its
  menus are the **CoA hero-class UI**, which is a *different* addon than the one `/ca` opens today.
- **The data and the UI code are already on disk.** ~~The missing piece is server-side state.~~
  **SUPERSEDED 2026-08-31 (late) — see §0.5.** The tree render turns out to be **static** and
  **client-drivable**: no server state, no level-10 grind, and it works for **all 45 classes** from
  the local data. A gated reader addon that drives the real frame is **shipped**.

---

## 0.5. UPDATE 2026-08-31 (late) — render is STATIC; client-side reader SHIPPED  *(supersedes the "need server state" framing in §3/§5/§6)*

**Key discovery.** The CoA tree render does **not** depend on the logged-in character. It is a
**static class+tab lookup**, proven by the fact that the **Inspect UI already renders other
players' arbitrary class+spec builds** with the same calls. So we can drive the real frame for any
class **without owning it and without being level 10.**

**The exact render contract (all CONFIRMED by reading the addon source this session):**
- `Ascension_TalentUI.xml` template attributes wire the tree to:
  `getEntries = global:C_CharacterAdvancement.GetEntriesByClass` (called as `(class, tab, false)`),
  `getPosition = global:CharacterAdvancementUtil.GetEntryPosition` (reads the entry's own
  `PositionX/PositionY`), `getNodeTemplate = …GetDisplayTemplateForEntry`,
  `getConnectionTemplate = …GetDisplayTemplateForConnection` (uses `entry.ConnectedNodes`).
- `CoATalentFrameMixin:UpdateActiveSpec()` (`CoATalentFrame.lua:186`) is **the switch**:
  `GetActiveChrSpec()` **nil → ShowSpecView()** (the "Choose Your Path" chooser);
  **non-nil → ShowTreeView() + TreeView:SetSpecID(specID)** (the rendered two-tree view).
- `CoATreeViewMixin:SetSpecID(specID)` (`CoATreeViewMixin.lua:230`) drives the **right/Spec** tree:
  `C_ClassInfo.GetSpecInfoByID(specID)` → `{Class, Spec, Name}` →
  `GetSpecDBCByFile`/`GetClassDBCByFile` → `SpecTree:SetClassTab(classDBC, specDBC)`. **No ownership
  check.**
- `CoATreeViewMixin:OnLoad` (`:60`) binds the **left/Class** tree to `UnitClass("player")` — so a
  play-reader must **re-point it**: `ClassTree:SetClassTab(GetClassDBCByFile(<Class>), "Class")`.
- **Collections gate is bypassable:** the CoA tab exists only when `IsCustomClass()` is true
  (`Collections.lua:37`) and is disabled below level 10 (`:133`). The reader **drives `CoATalentFrame`
  directly** (reparents to `UIParent`, `:Show()`), so neither gate applies.
- **Icons come from the node's Spell**, not `entry.Icon` (which is often null). The in-client frame
  resolves spell icons natively → **Path A gives true icon fidelity for free**; a standalone renderer
  would need a spell→icon table.

**SHIPPED this session:**
1. **All-class data export** — `rexxar-reference/ca-export/` : `ca-classes-index.json` +
   `ca-tree-<Class>.json` for **all 45 classes** (one run, no per-class work). Of 23,709 entries,
   **3,559 carry numeric `PositionX`, 3,587 carry `ConnectedNodes`** — those are the rendered nodes.
   Tinker positioned nodes/tab: **Class 51, Firearms 36, Invention 40, Mechanics 33** (all connected).
   Exporter: `…\scratchpad\export_all_ca_trees.py`.
2. **`Ascension_CoAReader` addon** — installed at
   `client-ascension\Interface\AddOns\Ascension_CoAReader\` (`.toc` + `CoAReader.lua`, lua52 syntax-OK).
   **Self-gated on `ASC_IsArchive()`; no deps, no events, no auto-run → 100% inert on the live realm.**
   Commands (archive only):
   - **`/coa probe`** — resolves the empirical unknowns and saves them to `CoAReaderDB.probe`
     (readable afterward at `WTF\Account\<acct>\SavedVariables\Ascension_CoAReader.lua`):
     (a) `C_ClassInfo.GetAllSpecs` shape + **the real Tinker ChrSpecialization spec IDs**;
     (b) whether `GetEntriesByClass("Tinker", tab, false)` returns data cross-class;
     (c) nil-safety of the OnShow updaters (`GetPendingRemainingAE/TE`, `IsPending`,
     `CanApplyPendingBuild`); (d) `GetClassDBCByFile/GetSpecDBCByFile`; (e) `C_CharacterAdvancement`
     table writability.
   - **`/coa list [Class]`** — enumerate classes, or one class's spec IDs.
   - **`/coa show <Class> [n]`** — render that class's trees (n = which spec, default 1). Reparents
     `CoATalentFrame` to UIParent, installs restorable nil-safe point shims, re-points the Class tree,
     and drives `TreeView:SetSpecID`. Every step pcall-guarded and reported.

**NEXT ARCHIVE SESSION (run order):** boot the archive (auth `:3799` + `world_server.py :8085`) →
log the archive char in → enable **"CoA Reader (Archive)"** in the AddOns list → **`/coa probe`**
(then tell me / let me read `CoAReaderDB`) → **`/coa show Tinker 1`**. If a tree is blank, the probe
output says which tab/lookup failed. Do **not** run any of this on the live realm (it no-ops there
anyway). Do **not** boot/drive a client while the live client is logged in on the same exe.

**Safety correction to §9:** `C:\Ascension` is **not** a separate untouched tree —
`client-ascension` is a **junction into it** (`…\resources\ascension-live`). There is ONE physical
client. Our `GlobalOverwrites.lua` edits are gated on `ASC_IsArchive()` so the live realm stays pure
stock; the `CoAReader` addon is gated the same way. See memory `ascension-client-junction-leak`.

---

## 1. What already works (your foundation)

| Piece | State | Where |
|---|---|---|
| Addon gate | **OPEN** — `world_server.py` sends `SMSG_REALM_INFO` (raw wire opcode **0x9BC**, 68-byte body) → `RealmInfo[+0x48]=1` → all 36 LoadOnDemand addons loadable | `world_server.py` `smsg_realm_info()`, sent in the post-auth burst after `SMSG_TUTORIAL_FLAGS` |
| `/ca` command | **WORKS** — opens the classless CA panel via the game's real path `Collections:GoToTab(Collections.Tabs.CharacterAdvancement)` | `Interface/FrameXML/Util/GlobalOverwrites.lua` → `ASC_ShowCA()`, registered on `PLAYER_LOGIN` |
| Client input harness | staged `key/type/key`, screenshot loop | scratchpad `wowin.ps1` |
| Read-only live introspection | RPM offsets + runtime↔file map | scratchpad `rpm_*.py`; memory `ascension-addon-loadability-gate` |

The gate flag lives in the client C++ `RealmInfo` singleton and **persists across `/reload`**
(reload re-runs Lua only), so once the server has sent 0x9BC, addons stay loadable.

---

## 2. The goal, precisely

"Replicate Rexxar's UI menus" = get the **CoA hero-class advancement UI** to open and populate
for a CoA class. Concretely, on a **Tinker** character you want to see the three Tinker spec
trees — **Firearms / Invention / Mechanics** — plus **Talents** and **Masteries**, with the
correct icons and spells, matching the real realm (see `rexxar-reference/`).

Today `/ca` opens `Ascension_CharacterAdvancement` (the *classless* "High Skill" ability browser),
which shows **standard** classes as ability pools (Arms/Fury/Protection = Warrior, etc.). That is
the wrong UI for Rexxar. The right one is **`Ascension_CoATalents`**.

---

## 3. Architecture — how the CA menus get their content  *(CONFIRMED)*

1. **The UI is data-driven by the client C API** `C_CharacterAdvancement.*`
   (`GetCategories`, `GetTalentsByClass`, `GetMasteriesByClass`, `GetImplicitByClass`,
   `GetFilteredEntriesByCategory`, `GetCategoryDisplayInfo`, `GetLearnedAE/TE`, …), plus
   `C_Player`, `C_GameMode`, `C_Config`, `C_BuildEditor`, `C_CVar`. **No Lua data tables** — the
   Lua only renders what the C API returns.
2. **That C API is fed by the client loading** `Data/Content/CharacterAdvancementData.json`
   (7.8 MB, 23,709 entries) at startup. **Icons, spells, tabs, classes, prereqs all live there.**
3. **Which subset the UI shows is filtered by per-character + realm + gamemode STATE that the
   SERVER establishes via packets.** Our emulator does not set that state yet → the UI falls back
   to standard classless pools + an empty "Choose Your Path".

### Two CA UIs — they are different addons *(CONFIRMED)*
- **`Ascension_CharacterAdvancement`** (+ `…Season9` variant): classless ability browser. **This
  is what `/ca` opens now.**
- **`Ascension_CoATalents`**: the CoA hero-class talent UI (Tinker et al.).
  `LoadOnDemand: 1`; `Dependencies: Ascension_TalentUI, Ascension_Collections`. Main mixin
  `CoATalentFrameMixin` (`CoATalentFrame.lua/.xml`), has `ShowTreeView()` / `ShowSpecView()`.
- **Routing quirk (important):** the *stock* `LoadAddOn` logic routes
  `LoadAddOn("Ascension_CharacterAdvancement")` → **`Ascension_CoATalents`** *when
  `IsCustomClass()` is true*. That logic still exists in
  `GlobalOverwrites.lua` (lines ~483-497) but is **dead-coded** by our no-op override
  (`if ASC_ALLOW_REAL_LOAD then return _LoadAddOn(name) end` returns early with the plain name).
  → So once `IsCustomClass()` is true, the **existing `/ca` entry point can auto-load the CoA UI**
  if you **restore that routing** (or make `/ca`/`/coa` load `Ascension_CoATalents` directly).

---

## 4. The data — `CharacterAdvancementData.json`  *(CONFIRMED)*

Flat JSON **list**, 23,709 entries. Per-entry schema (superset):
```
{ ID, Name, Class, Tab, Type, Icon, Spells[], RequiredIDs[], RequiredLevel,
  AECost, AECost_Random, Quality, QualityCost, Quality_Random, Flags, Group,
  Expansion, Realms }
```
- **`Class`** — 44 distinct: standard (Warrior…Druid), `Reborn*` (RebornWarlock…), and **~25 CoA
  custom classes**: `Tinker, Necromancer, Chronomancer, Runemaster, Starcaller, Cultist,
  SunCleric, Venomancer, WitchDoctor, Primalist, Ranger, WitchHunter, Pyromancer, SonOfArugal,
  Barbarian, KnightOfXoroth, Monk, Guardian, DemonHunter, Stormbringer, Reaper` (+ `ConquestOfAzeroth` meta).
- **`Type`** — `Trait` (11657), `Ability` (6953), `Talent` (4522), `TalentAbility` (573).
- **`Tab`** — 84 spec trees. **Tinker = `Firearms`, `Invention`, `Mechanics`.**
- **`Icon`** — texture name (e.g. `"Trade_Engineering"`). **`Spells`** — spell IDs.
  **`RequiredIDs`** — prereq entry IDs (the tree/graph connectivity).
- **`Realms`** — a `u32` **bitmask** gating which realms show the entry (Tinker = `4294967295` =
  `0xFFFFFFFF` = all). **HYPOTHESIS:** the C code filters by the *current realm's* bit; the current
  realm identity presumably comes from the RealmInfo/realmlist the server presents. Verify.

Verbatim Tinker entry (schema reference):
```json
{"Class":"Tinker","Expansion":0,"Flags":8194,"Group":3,"ID":4049,"Icon":"Trade_Engineering",
 "Name":"Conquest of Azeroth Specialization - Tinker (Firearms)","Quality":"Normal",
 "QualityCost":1,"Quality_Random":"Normal","Realms":"4294967295","RequiredIDs":[31113],
 "RequiredLevel":10,"Spells":[92138],"Tab":"Firearms","Type":"Ability"}
```
Probe scripts (scratchpad): `ca_json_probe.py`, `ca_json_distinct.py`.

---

## 5. The blocker chain — what tonight solves

The UI + data are present; the gap is **server-established client state**. Priority order:

1. **`C_Player:IsCustomClass()` → true.** Currently **false** (and `IsDefaultClass()` also false — an
   odd "neither" state). This is the master switch for the CoA UI path. Find which SMSG/field sets it.
2. **Assign a CoA class + spec** to the character (e.g. Tinker) so `GetCategories` /
   `GetTalentsByClass('Tinker', …)` return CoA content.
3. **GameMode/season context** — `C_GameMode:IsGameModeActive(Enum.GameMode.X)`. Enum includes
   `Draft, BuildDraft, WildCard, Felforged, Ironman, Survivalist, Resolute, Nightmare, Crusader`.
   Determine whether Rexxar/CoA is a gamemode bit and set it.
4. **Realm identity / `Realms` bitmask** so the realm filter includes CoA/Rexxar entries.
5. **Per-character CA learned state.** `GetLearnedAE` / `GetLearnedTE` currently throw
   *"Invalid argument type at index 1. Expected string."* (see `Logs/Error.txt`) — the per-character
   CA sync packet is not being sent. Find + send it.
6. **Restore the `IsCustomClass → CoATalents` routing** in `GlobalOverwrites.lua` (or add a `/coa`
   opener), since the current no-op override bypasses it.

---

## 6. Recommended attack plan (ordered)

**Phase A — recon (read-only), do this first; it may shortcut everything:**
- **In-game probe** with `/ca` open (fastest signal): `/run` dump
  `C_CharacterAdvancement.GetCategories(true)`, `GetTalentsByClass("Tinker",0)`,
  `GetMasteriesByClass("Tinker",0)`, `C_Player.IsCustomClass()`. If asking for **"Tinker"**
  already returns data, the JSON is loaded and this is purely a *"which categories to show"*
  gate (→ flip `IsCustomClass`/gamemode). If it returns nothing, the C side hasn't ingested CoA
  content for this realm/gamemode (→ realm/gamemode context problem).
- **Binary recon** (mirror the 0x9BC method): string-search `Ascension.exe` / `Extensions.dll` for
  `IsCustomClass`, `C_GameMode`, `CharacterAdvancementData`, `GetLearnedAE`, and the CA
  opcode/handler registrations to find which SMSG opcodes/fields feed IsCustomClass, gamemode, and
  CA learned-state. Read-only RPM to confirm live.

**Phase B — flip IsCustomClass + assign Tinker:** implement the packet/field in `world_server.py`;
restart via `restart-world-clean.ps1`; reconnect; verify `C_Player:IsCustomClass()==true` via `/run`.

**Phase C — open the CoA UI:** restore the `IsCustomClass→CoATalents` routing (or add `/coa` that
loads `Ascension_CoATalents` and shows `CoATalentFrame`); verify the frame renders.

**Phase D — populate:** iterate realm-bitmask / gamemode / learned-state until the Tinker
Firearms/Invention/Mechanics trees + Talents + Masteries render with icons/spells.

**Phase E — fidelity pass** vs `rexxar-reference/` screenshots.

Work incrementally: one packet/field change → restart world → reconnect → `/reload` → screenshot →
read. Keep client-open time modest; re-discover the client PID each time (it may be relaunched).

---

## 7. Operational runbook  *(verified this session)*

- **Client PID this session:** 34096 (window `clientOrigin≈(1904,58)`, 1280×720). **Re-discover it**
  (`netstat -ano | grep :8085` for the ESTABLISHED peer, or by process name `Ascension`).
- **Drive the client:** scratchpad `wowin.ps1` — actions `shot/click/type/key/hold/info/run`.
  **Reliable input = staged from a CLEAN chat box:** `key ENTER` (open) → `type <cmd>` →
  `key ENTER` (submit). The `run` action (self-contained open+type+submit) is reliable **only when
  no chat box is already open**. The first ~16 typed chars can drop on a focus-settle race — verify
  typed text with a screenshot before submitting anything risky.
- **⚠ MSYS path-mangling trap:** invoking `wowin.ps1` from the Bash tool, a **bare slash arg**
  (`/ca`, `/reload`) gets converted by Git-Bash into a Windows path (arg length jumps, command
  fails silently). **Always prefix** `MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'`. Args containing
  spaces/parens/colons (e.g. `/run Foo:Bar()`) are skipped by MSYS and pass fine.
- **Screenshot:** `wowin.ps1 -Action shot -Out X.png`, then Read the PNG.
- **Open current CA UI:** type `/ca` in-game (persistent across relaunch).
- **Reload UI:** `/reload` (activates `GlobalOverwrites.lua` edits; the 0x9BC gate persists).
- **See Lua errors:** `/console scriptErrors 1` (OFF by default → mid-function errors are invisible),
  and read `Logs/Error.txt`.
- **World server:** `world_server.py` on `127.0.0.1:8085`; log `world_server_log.txt`. Restart with
  elevated `restart-world-clean.ps1` (kills 8085 PIDs, starts one clean). **New-packet insertion
  point:** the post-auth/post-login burst where `SMSG_REALM_INFO` is sent (after
  `SMSG_TUTORIAL_FLAGS`).
- **Read live client state (read-only RPM):** scratchpad `rpm_gate.py`, `rpm_record.py`,
  `rpm_code.py`, `rpm_hook.py`. Runtime↔file map for Extensions.dll:
  `file_VA = runtime_VA - 0x6e480000 + 0x10000000`.
- **Syntax-check Lua before reload:** extract your edited block and
  `C:/AzerothRealm/server-spelldraft/lua52_compiler.exe -p block.lua` (a broken base file breaks the
  whole UI on reload).

---

## 8. Key files & paths

| Path | Role |
|---|---|
| `C:\AzerothRealm\realms\ascension\world_server.py` | local world emulator; add CoA/gamemode/IsCustomClass/CA-state packets here |
| `C:\AzerothRealm\realms\ascension\restart-world-clean.ps1` | elevated clean restart of the world server |
| `C:\AzerothRealm\realms\ascension\world_server_log.txt` | world server log |
| `C:\AzerothRealm\client-ascension\Interface\FrameXML\Util\GlobalOverwrites.lua` | our loose base-UI hooks: LoadAddOn override, `/ca`, keybinds, diagnostics |
| `C:\AzerothRealm\client-ascension\Interface\AddOns\Ascension_CoATalents\` | **the CoA hero-class UI** (target) |
| `C:\AzerothRealm\client-ascension\Interface\AddOns\Ascension_CharacterAdvancement\` | classless CA UI (what `/ca` opens now) |
| `C:\AzerothRealm\client-ascension\Data\Content\CharacterAdvancementData.json` | **all CA data** (classes/tabs/icons/spells/prereqs) |
| `C:\AzerothRealm\client-ascension\Logs\Error.txt` | client Lua/CA errors (the `GetLearnedAE/TE` failures) |
| `…\scratchpad\wowin.ps1` | client input + screenshot harness |
| `…\scratchpad\rpm_*.py`, `ca_json_*.py` | read-only RPM + JSON probes |
| `C:\AzerothRealm\realms\ascension\rexxar-reference\` | real-realm screenshots + `REFERENCE.md` index |

---

## 9. SCOPE / SAFETY — do not cross (standing constraints from the user)

- **LOCAL ONLY.** Do **not** target Project Ascension production infrastructure, external accounts,
  credentials/secrets, or any third-party system. All work is on `C:\AzerothRealm` and our own
  client files.
- **The real launcher/client lives at `C:\Ascension` — a separate tree. Do not modify it.** Logging
  into the real realm uses that tree, not ours (confirmed: the launcher did **not** touch
  `client-ascension`).
- **RPM/Frida is READ-ONLY**, for understanding. **Do NOT patch `Extensions.dll` on disk**
  (reading/disassembly/runtime-read is fine). **Do NOT `WriteProcessMemory`** to flip flags. **Do
  NOT bypass or suspend anti-cheat / anti-tamper** without asking first. **Do NOT** ask for or use
  the real Ascension password.
- **In scope:** editing our own loose client Lua (`GlobalOverwrites.lua`, etc.), `world_server.py`,
  and our auth server.
- If real progress **requires a private signing key, embedded service secret, or other credential
  belonging to Ascension → STOP, switch to clean-room, and ask the user.**
- **AFK authorization (standing):** you may make the recommended choices and run scripts (including
  elevated, without UAC prompts) to move the project forward overnight; iteration and some
  client-crash risk are acceptable. Prefer reversible steps; report faithfully.

---

## 10. Gotchas learned

- `LoadAddOn` is a **no-op override** in `GlobalOverwrites.lua` (returns `true` without loading)
  unless global `ASC_ALLOW_REAL_LOAD=true`, which routes to the real loader
  `ASC_NativeLoadAddOn`. The override **bypasses** the stock `IsCustomClass→CoATalents` routing —
  restore it for CoA.
- **Slash commands must be registered on `PLAYER_LOGIN`** — `GlobalOverwrites.lua` runs before
  `ChatFrame.lua` creates/hard-resets `SlashCmdList`, so a top-level `SlashCmdList[...]=fn` is lost
  (symptom: "Type '/help' for a listing").
- Character is currently **`IsCustomClass=false` AND `IsDefaultClass=false`** (neither). On real
  Ascension a non-custom/non-default char is routed to the **Season9** CA variant — keep this in
  mind when deciding which addon to target.
- The CoA custom classes are the **"Conquest of Azeroth"** hero classes; e.g. Tinker entries are
  named `"Conquest of Azeroth Specialization - Tinker (Firearms/Invention/Mechanics)"`.

---

## 11. Reference & memory

- **Screenshots:** `./rexxar-reference/` (+ `REFERENCE.md`). Real-realm shots may be added by the maintainer
  (Tinker overview + Firearms/Invention/Mechanics/Talents/Masteries + a chosen-path state).
- **Auto-memory** (loaded each session): `ascension-addon-loadability-gate` (gate + `/ca` + full RE
  map), `ascension-world-render`, `ascension-world-handshake`, `ascension-client-auth-protocol`,
  `windows-bash-tool-path-traps`, `ascension-archive-project`.

---

## 12. Verification checklist (definition of done for a Tinker menu)

- [ ] `C_Player:IsCustomClass()` returns **true** (in-game `/run`)
- [ ] Character has a CoA class (Tinker) assigned server-side
- [ ] `/ca` (or `/coa`) loads **`Ascension_CoATalents`** (not plain `Ascension_CharacterAdvancement`)
- [ ] CoA talent frame renders; **Firearms / Invention / Mechanics** trees populate with icons + spells
- [ ] **Talents** and **Masteries** tabs populate
- [ ] `scriptErrors 1` clean; `Logs/Error.txt` free of CA arg-type errors
- [ ] Visual match against `rexxar-reference/` shots
