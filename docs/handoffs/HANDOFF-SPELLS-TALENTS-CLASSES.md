# HANDOFF — Spells, Talent Trees, Custom Classes
**Target: one session, Opus 5. Written 2026-09-01.**

> **Hit an error?** Check `TROUBLESHOOTING.md` at the hub root first — it is the
> symptom-indexed ledger of every failure this hub has hit and the fix that ended
> it. Solve something new, add it there the same day.

**START HERE.** This supersedes `HANDOFF-ARCHIVE-SESSION.md` as the active runbook. That
document remains the reference for everything already solved (boot chain, CoA render
contract, opcode RE notes) — read it only when this one points you at a section.

**§10 IS NOW CLOSED. 10.1 through 10.4 are all DONE and verified live** — action bars,
game modes, spell effects (power / damage / healing / auras) and the Hero Architect Build
Creator. The only item left in §10 is **10.5, character creation as a custom class**, which
is polish rather than capability (`.class` already makes any character any CoA class after
the fact) and is known large. Read §0.1 before opening it.

**One thing is deliberately left OPEN:** a `C stack overflow` inside MPQ'd
`Interface\SharedXML\C_Hook.lua` that raises the login "UI Error" banner. It is cosmetic,
fully characterised, and written up at the end of §0.1 and in `TROUBLESHOOTING.md`.

---

## 0. Definition of done

| Track | Done when |
|---|---|
| **A. Spells** | The character's known CA entries appear in the spellbook and on the action bars, and they cast. |
| **B. Talent trees** | Learning a node in the CoA tree spends essence, the server persists it, and the spell is granted with no relog. |
| **C. Custom classes** | The character presents as one of the 42 CA classes deliberately, with that class's tabs and entry set — not inherited from the vanilla class byte. |

**All three are done — see §0.1 for what was measured and §4 for what Track C left open.**
The original plan read: A is a data join, B needs exactly one unknown opcode, and C is the
open-ended one. That held for A and B. C turned out not to be open-ended at all: it is one
byte in the player's update block.

---

## 0.0 How to work this document — READ BEFORE STARTING

**Work the whole backlog in one go. Do not stop after one fix.** This is the operating mode
the maintainer asked for on 2026-09-01, in his words: none of these *"1 tiny fix per prompt
shenanigans."*

- **§10 is an ordered backlog with a definition of done per item.** Start at the top, work
  down. Finish an item, verify it *live*, then **immediately start the next one**. Do not
  report back and wait for permission to continue.
- **Report at the end**, or when you are genuinely blocked on a decision only the maintainer can make.
  A failing test, an unknown opcode, an undecoded DBC column or a wrong theory is not a
  blocker — it *is* the work. Debug it and carry on.
- **A hard item does not license skipping the easy ones.** If something turns out bigger than
  its entry suggests, timebox it, write down exactly how far you got in §0.1, and move to the
  next item. Finishing four of five and saying which one is unfinished beats stalling on one.
- **Batch the restarts.** Restarting `world_server.py` costs a client relog (§5, ~40s of
  ghost-driving). Group code edits and pay it once per group, not once per edit.
- **Update this file as you go.** Completed items move up into §0.1 with what was *measured*,
  not what was intended. A future session must be able to tell the state of the world from
  this document alone — that is the only reason it exists.
- **Verify live or do not claim it.** Every "DONE" in §0.1 is backed by a packet log line, a
  `dprint` read back out of `LUA.txt`, or a screenshot. Keep that standard.

---

## 0.1 RESULT — sessions of 2026-09-01 and 2026-09-02

**A, B and C are all DONE and verified live**, and so is the whole of §10 except 10.5.
The 2026-09-02 additions are §10.4 (Archetypes / Build Creator) and the login-banner
write-up, both at the end of this section.

### FIRST, THE ONE THAT WILL WASTE YOUR NIGHT: the world port is not free to choose.

If the client draws the world and then dies a few seconds later with **ERROR #132 at a fixed
EIP of `0xCD0CA136` / `0xCD0CA176`**, do not analyse packets — check `archive_ports.py`.
`Extensions.dll+0xA3C950` compares the world endpoint the client connected to against a
**91-entry allow-list of plaintext `host:port` literals** baked into its `.rdata`. Only three
loopback endpoints are on it: **`127.0.0.1:8085`, `:8087`, `:8088`.** On a miss it arms a
kill-switch that was *meant* to be a silent `push 1; call ExitProcess` at `0x00403340` but
never writes the call's 4-byte displacement; because that address is already inline-hooked
(`E9 <rel32> CC CC`), the leftover bytes become the displacement and the next per-frame tick
calls `0x00403347 + 0xCCCC6E2F = 0xCD0CA176`, which is unmapped. The EIP is a fixed constant
across runs and across ASLR bases because a module base is 64 KB aligned, so the low half of
the stolen rel32 never changes — which is exactly why it looks like a corrupt binary and not
a configuration error.

This cost roughly 33 hours across two sessions, twice, because the wire diff between a working
and a crashing run is *empty*: **the port number is not carried in any packet.** A negative
result only excludes what the instrument can measure. `WORLD_PORT` had been moved 8085 → 8095
to free 8085 for the maintainer's own realm; the fix was `8095` → **`8087`**, one line. Verified live:
299 s in world, no crash report, `hookwatch.py` saw one value across 12,983 reads.

Two read-only tools exist for this and neither needs a running client to give the answer:
`tools/allowlist.py` (regex-scans `Extensions.dll` for the literals, then checks the endpoint
the live client actually wrote into BSS at `0x00C79C9E`) and `tools/hookwatch.py` (polls the
patch site through a crash). Full write-up: `TROUBLESHOOTING.md` entry 3.

### Track A — spells: DONE, with one honest limit

Known entries reach the spellbook and the bars, and they cast:

```
<- CMSG_CAST_SPELL (10 B)  ->  SMSG_SPELL_GO (31 B)   CAST 91234  (Brilliance Aura)
<- CMSG_CAST_SPELL (10 B)  ->  SMSG_SPELL_GO (31 B)   CAST 701463 (Mana-forged Barrier)
```

**The limit, stated plainly: nothing resolves the spell.** `SMSG_SPELL_GO` ends the
pending cast, starts the GCD and plays the visual — that is all. No aura is applied, no
health or mana moves, no damage or healing lands, no power is spent. The archive has no
spell-effect engine and this session did not start one. "They cast" in §0 means the cast
completes; it does not mean the spell does what its tooltip says. Building the real thing
(Spell.dbc effect parsing, aura application, power cost, target resolution) is a separate,
much larger piece of work and should get its own handoff.

Casting cannot be tested from `/run` — `CastSpellByID` is protected and a script call is
refused with "A macro script has been blocked from an action only available to the
Blizzard UI." **Test casts with a real key press on an action-bar slot**
(`ghostinput.ps1 -Action key -Text 1`), which the client accepts as a hardware event.

### Track B — talent trees: DONE. The opcode is 0x727.

**`CMSG_CA_KNOWN_ENTRIES` = 0x727 — and it is the client's COMPLETE known-entry set,
not a delta.** Same 21-byte record as the server's 0x726
(`u32 entryId | u32 rank | u32 unk0C | u8 flag | u32 unk18 | u32 unk1C`); `unk18` is a
wall-clock Unix stamp of the click.

The full-set reading is measured, not assumed:

| action | 0x727 body | count |
|---|---|---|
| `LearnID(1189)` from an empty set | 25 B | 1 |
| `LearnID(1300)` on top of it | 46 B | **2 — both entries, not just the new one** |
| `UnlearnID(1189)` | 4 B | **0 — it never names 1189** |

A delta cannot express that unlearn. **The handler must REPLACE the stored set.** Reading
it as a delta is the subtle failure mode: every learn still looks correct and only
unlearns silently do nothing. This was actually written the wrong way first and caught by
the unlearn test — keep that test.

Verified end to end, no relog: essence spends (`GetRemainingAE` 140 → 138), the server
persists to `knownentries.json`, `SMSG_LEARNED_SPELL` + `SMSG_ACTION_BUTTONS` grant the
spell immediately, `UnlearnID` sends `SMSG_REMOVED_SPELL`, and the state survives a relog.

Note `GetLearnedAE()` reported **2** for entry 1189 whose `Cost1` is 1 — stable across a
fresh relog, so it is the client's genuine cost accounting, not a double-count. `Cost1..3`
in `entries.csv` are NOT (AE, TE, level) as assumed; `Cost3` looks like required level.
Do not trust that mapping without measuring.

### Track C — custom classes: DONE. The class IS the character's class byte.

**The earlier conclusion in this file — "REALM-driven, not character-driven" — was wrong,
and everything below supersedes it.** The CoA class is a per-character property this server
already controls: the class byte in **`UNIT_FIELD_BYTES_0`** (descriptor dword 23), the same
byte `UnitClass` reads. Nothing about the realm has to change.

**The RE that says so.** `GetEntriesByClass`'s inner filter (`Extensions.dll` `0x101806a0`)
takes the class as its *second* argument. Its only caller, `0x1017bb39` inside
`ImportPendingBuild` (`0x1017b910`), computes that argument as:

```
0x1017bb13  cmp  ecx, 4              ; TYPEID_PLAYER, else class = 0
0x1017bb1c  mov  eax, [edx+8]        ; the object's descriptor block
0x1017bb1f  mov  eax, [eax+0x5c]     ; dword 23 = UNIT_FIELD_BYTES_0
0x1017bb22  shr  eax, 8              ; race | CLASS | gender | power
```

— exactly the byte the world server writes into the player's update block. The filter hands
it to `MatchesClass` (`0x101c6a40`). The old section's transcription of `MatchesClass` is
correct; only the *source of its argument* was misidentified.

**The live measurement.** `.class tinker` on guid 1, mid-session, no relog:

| | class 10 | class 28 |
|---|---|---|
| `CanLearnID(31113)` — a Tinker node | `false` | `true` |
| `CanLearnID(395)` — a Mage node | `true` | `false` |
| `GetRemainingAE` / `GetRemainingTE` | 140 / 71 | 36 / 35 |

After a relog: `UnitClassID("player")` = **28**, `UnitClass("player")` = **"Tinker"**,
`C_Player:GetClass()` = **"TINKER"**, `CoATalentFrame.class` = **"TINKER"**. The CoA panel
opens on the **Tinker** spec chooser — Demolition / Mechanics / Invention, with Tinker art
and blurbs — and its tree renders headed `TINKER`. `CoAReader`'s own world-entry report
agrees: `Tinker/Class=36  Tinker/Firearms=40  Tinker/Invention=39  Tinker/Mechanics=43`,
totalling 158, which is exactly what `entries.csv` gives for `ClassType == Tinker`.

Throughout all of this the realm is still advertised as **"Area 52 - Free-Pick"** and
`SkillCardsUI` still logs `LOAD db for Area 52 - Free-Pick`. **Realm flavour and character
class are independent.**

**The old negative result could not be reproduced.** The previous attempt set
`characters.json` `class` to 28, relogged, and saw `"Hero"`. Today the same change — made
through `.class`, which writes the same field — is honoured on the next login, and the
mid-session values update is honoured immediately. Treat the old negative as unexplained
rather than as evidence about the mechanism.

**The nuance that will cost you an hour.** A mid-session `UNIT_FIELD_BYTES_0` values update
reaches the CA subsystem *immediately* — `CanLearnID`, the essence budget and the tree all
follow at once — but **not** `UnitClass`, which caches at object-create time. The class
*name*, and any UI keyed off it, needs a relog. Both halves were measured.

**Essence follows the class too.** The old `ESSENCE_DBC_KEY = 10  # measured` note was
measured on a class-10 character. The essence family key *is* the class byte: at level 80,
key 10 is AE 140 / TE 71 and key 28 is AE 36 / TE 35. `essence_for(level, key)` now takes it
and every caller holding a character passes `c["class"]`; the curves are memoised per key.

**The stale-known-set trap — the real cause of the Track B failures.** The old section
blamed the realm for `OPTIMIZE_FOR_TRAVERSAL_FAILED / CA_LEARN_WRONG_CLASS`. The actual rule
is that the client validates a learn by walking the **whole** known set, so a single entry
the current class cannot learn makes **every** `LearnID` fail — and it fails naming the
stale entry, not the one requested. Measured: two Mage entries left on a freshly-flipped
class-28 character turned `LearnID(31113)` into
`false OPTIMIZE_FOR_TRAVERSAL_FAILED CA_LEARN_WRONG_CLASS 1189 1`; clearing them made the
identical call return `true`. `.class` therefore **prunes by default** —
`class_unlearnable()` drops what the new class cannot learn, and `send_known_entries` ->
`sync_spellbook` takes those spells off the bars in the same burst. `.class <name> keep`
opts out and warns that `LearnID` will fail until they go.

**`knownentries.json.tinker-import` is restored and live.** All 36 of its entries are
`ClassType == Tinker`, and on a class-28 character they load clean: `spellbook: +36 spell(s),
-0`, `GetKnownSpellEntries` 24 + `GetKnownTalentEntries` 12 = 36, every node gold in the
tree, AE 0 of 36 remaining, TE 35. That is Tracks A, B and C demonstrated in one shot.

**The new server command:**

```
.class                     which CoA class this character is
.class <name|byte> [keep]  become that class, persisted
.class list [group]        every CoA class and its class byte
```

A bare number is **always** the class byte, never a `ClassTypes` row id — the ranges overlap
(rows 1..46, bytes 1..32), so `.class 28` is Tinker, not row 28 (Starcaller). Names match the
DBC token (`KnightOfXoroth`) or the display name (`Sun Cleric`), case- and
space-insensitively. Rows with no required class — `None`, `ConquestOfAzeroth`,
`RebornGeneral` — are group markers and do not resolve.

Class 10 admits the twelve classic ClassTypes, 5312 of the 10255 entries, and no custom one.
Class 28 admits Tinker and only Tinker, 158 entries. Vanilla bytes behave the same way:
class 3 admits 150.

### 10.2 Game modes — DONE. The empty record set is the CORRECT answer, and here is why.

`CMSG_GAME_MODE_QUERY` (0x62E) is answered with chunk 0 / version 0 / **zero records**, and
that was written off as "a stub". It is not a stub; it is right. Three independent measurements
say so.

**1. The client only ever asks about one mode, and only from one place.** Across a 140 MB
log the query fired exactly **four** times, always for `'BuildDraft'`, and every one of the
four was immediately preceded by the addon action that opens the Hero Architect:

```
>>> CHAT[type=7]: ASC_PATH_TO_ASCENSION  ACTION_OPEN_HERO_ARCHITECT
<- 0x62E (11 B body)   ->  0x62F (23 B body)
```

4 opens, 4 queries, no query from anywhere else. The empty reply never produced a retry, a
stalled panel or a Lua error, and the panel it opens went on to render the whole tree.
(That panel *is* the Hero Architect — `CoATalentFrame.lua:257` sets its own title to
`HERO_ARCHITECT` — so the thing 0x62E gates was already working.)

**2. Nothing the UI can see reads those records.** The entire Lua-visible game-mode surface
is two C bindings, recovered from the registration table at `0x1031f300..0x1031f800`:

| binding | VA | what it reads |
|---|---|---|
| `GetCustomGameMode()` | `0x1031eff0` | `[0x10be4138]`, with bit 0x800 (BuildDraft) masked off unless a per-spec flag is set |
| `IsBuildDraftModeEnabled(spec)` | `0x1031f180` | `[0x10be4138 + 8 + (spec-1)*32] & 1` |

Both read a **static struct at `0x10be4138`** — a mask at +0 and a 20-entry × 32-byte
per-specialisation table at +8 — reached through the lazy singleton getter `0x1031ef10`.
The 0x62F record vector is a different object entirely: `[mgr+0x148]`, 0x138-byte stride,
wiped by chunkIndex 0. A `.text` scan finds exactly **two** references to `0x10be4138`,
both inside that getter, so there is no path from the record vector to the mask.

`C_GameMode` itself is not a C namespace at all — `type(C_GameMode)` is `table`, a
CallbackRegistry mixin (21 keys) wrapping `GetCustomGameMode`. `_G` contains exactly two
names matching "GameMode": `C_GameMode` and `GetCustomGameMode`.

**3. The client's own answers, and the CA panel wants every one of them.**

```
GetCustomGameMode()                                -> 0        (Enum.GameMode.None)
C_GameMode:IsAnyGameModeActive()                   -> false
C_GameMode:GetActiveGameModes()                    -> {} (0 entries)
C_GameMode:IsGameModeActive(Enum.GameMode.BuildDraft) -> false
```

`Enum.GameMode` is a **bitmask**, not an ordinal — `None 0, Random 1, Ironman 2,
Survivalist 4, Draft 8, Resolute 32, WildCard 64, Felforged 128, Nightmare 256,
FreepickRarities 1024, BuildDraft 2048, Crusader 4096` (16 and 512 are unnamed). That is why
`IsGameModeActive("BuildDraft")` throws `bad argument #2 to 'band' (number expected, got
string)` — it takes enum values and ORs them.

Every CA gate reads better with the modes off: `IsGameModeActive(Draft, WildCard)` false is
the full-size, non-compact layout, and `IsHeroTabAvailable` (CharacterAdvancement.lua:1224)
is `C_Player:IsHero() and not IsGameModeActive(BuildDraft)`.

**The corollary matters more than the answer, and it retires an old assumption.** The
Archetypes / hero tab is *not* gated on game modes — that half of the condition is already
satisfied. It is gated on **`C_Player:IsHero()`, which measures `false`** (and
`C_Player:IsDefaultClass()` is `false` too — a Tinker is neither). Filling in game-mode
records would not have opened it. That is now §10.4's actual problem.

> **RESOLVED 2026-09-02.** `IsHero()` is `select(2, UnitClassBase("player")) == "HERO"`,
> i.e. `ChrClasses.dbc` row 10 — so it is the character's **class byte**, set with
> `.class 10`, and it is read **once** in `Collections:SetupTabSystem`, so it only takes
> effect on the next client start. With that done the tab exists and §10.4 landed. Note
> the reading this makes explicit: `IsHero()` is not a realm or game-mode property at all.

**What is NOT proven:** that no *C++* internal reads the record vector — only that nothing
reachable from Lua does. And nobody has traced what *writes* `0x10be4138`; all 171 users go
through the accessor. Whoever wants to genuinely switch a mode on has to find that writer
first.

### 10.1 Action bars — DONE. Slot edits now survive a relog.

`CMSG_SET_ACTION_BUTTON` (0x128) had no handler, so the client's bars were rebuilt from
scratch on every world entry and anything the player dragged was lost. Handled now, and
the layout lives in `actionbars.json` beside the other state files.

**The wire format, measured rather than assumed.** `PickupSpell(9,"spell")` +
`PlaceAction(30)` with Rocket Boots produced

```
raw = 1d 11 a2 07 00      slot 0x1d = 29,  packed 0x0007A211 = 500241
```

so the body is `u8 slot` + `u32 packedAction` where `packed = action | (type << 24)`,
type 0 is a spell, and `packed == 0` clears the slot. **Lua's 1-based action slot N is
wire slot N−1** — that off-by-one is the whole reason a naive implementation looks like
it works and puts everything one button to the left.

**When the client sends them, and the wrong theory that cost time.** They do *not* answer
`SMSG_ACTION_BUTTONS` — a clean restart and relog produced exactly **zero** 0x128 packets.
They arrive after a **spellbook change**, as a normalisation sweep: the client walks from
the end of what we filled up to 143 and sends a clear for each, 133 packets with 11
castable spells. Reading that burst as "the player wiped their bars" is exactly backwards.
A real edit is a *single* packet with a non-zero payload. Per-packet logging for 0x128 is
suppressed for that reason; `bars_note_packet` logs one line per burst, and writes are
debounced 0.25 s so a burst is a couple of file writes rather than 133.

**Autofill is a seed, not a policy.** A character with no saved layout gets the demo
layout — every castable known spell from slot 0 — once, and it is then adopted as theirs.
It is deliberately *not* re-run on spellbook changes: a removal reaches us as a clear, and
refilling the hole would silently undo the drag the player just made. What *is* automatic
is the opposite direction — `sync_spellbook` unbinds any slot whose spell the character no
longer knows, so a `.class` change no longer leaves a bar of red question marks.

**`.bars`** reports the layout, **`.bars auto`** rebuilds the demo layout, **`.bars clear`**
empties it; both push a fresh `SMSG_ACTION_BUTTONS`, which the client honours mid-session.

Verified live, twice across a world-server restart:

```
[18:24:33] SET_ACTION_BUTTON slot 24 <- 0x0007A20C (Deathball)     # PlaceAction(25)
   ... restart + relog ...
S25 -> spell 5 spell 500236      S9 -> spell 5 spell 500236      S26 -> (empty)
[18:31:07] <<< 12 slot(s) bound ... 24  0x0007A20C  type=0  Deathball
[18:31:22] <<< Bars cleared -- 0 slot(s) bound.
[18:31:29] <<< Bars rebuilt from castable known spells -- 11 slot(s) bound.
chk 1 nil 520445                 # HasAction(1)=1, HasAction(25)=nil, slot 1 = 520445
```

Note `GetActionInfo(slot)` on this client returns **four** values —
`type, spellbookIndex, subType, spellId` — not the three of stock 3.3.5a. Read the
*fourth* if you want the spell id, and remember that only the last call in a Lua argument
list expands past its first value.

**Two things landed alongside it**, both of which were making the work slower:

- `world_server_log.txt` had reached **140 MB**, so every `grep` and every tail-the-log
  helper was slow, and `reboot-world.ps1` crashed on it — it compared a **byte** offset
  against a **character** index, and one multi-byte character in 140 MB makes the decoded
  string shorter than the offset (`startIndex cannot be larger than length of string`),
  losing a perfectly good relog. `rotate_log()` now rolls the file over at 64 MB keeping
  one `.1`, and the script reads only the new bytes and treats a shrunk file as a rotation.
- Dot-command replies only ever went to the client's chat frame, which cannot be read from
  outside the process. They are now echoed to the world log as `<<< ` lines, so a command
  test is a `grep`, not a screenshot.

### 10.3(a) Power cost — DONE. A cast now costs something, and the client agrees.

Casting used to be free: `SMSG_SPELL_GO` and nothing else. Now every cast is priced from
`Spell.dbc`, charged, refused when it cannot be paid, and regenerated.

**The cost is two columns added, and reading only the obvious one makes almost every
spell free.** WotLK costs live overwhelmingly in `ManaCostPercentage` (field 204), *of base
mana*, not in the flat `ManaCost` (field 42) — Fireball is `ManaCost 0` + 19%. Measured on
this character's own bar: Rocket Boots `0 + 14%`, Med Pack `0 + 30%`, Deathball `100 + 20%`.
A flat-only reader would have charged 0, 0 and 100 and looked like it worked.

**The pools had to be real first.** The create block was shipping a hardcoded 100/100, which
makes every spell either free or unaffordable and hides any cost bug. Health and power now
come from `max_pools()` — `ARCHIVE_*` constants, policy rather than emulation, because there
is no `player_classlevelstats` here and no row for a Tinker in it if there were. Level 79
gives 14280 HP / 4405 mana, and the client's own `UnitHealthMax` / `UnitManaMax` agree.

**THE TRAP, and it cost most of the session: the client ignores `UNIT_FIELD_POWER1` in a
values update.** Not "values updates do not work mid-session" — that was the first (wrong)
reading, inherited from the Track C note about `UNIT_FIELD_BYTES_0` needing a relog. One
packet, one mask, three fields, measured:

```
.level 79   -> UnitLevel("player")   80 -> 79        field 54, APPLIED
.power 1234 -> UnitHealth("player")  14460 -> 14280  field 24, APPLIED
               UnitMana("player")    4460  -> 4460   field 25, IGNORED
```

Health lands and power does not, in the same mask block. AzerothCore says why —
`Unit::SetPower` (`src/server/game/Entities/Unit/Unit.cpp:12446`) writes the descriptor
**and** unconditionally sends `SMSG_POWER_UPDATE` (**0x480**: packed guid, `u8 powerType`,
`u32 value`). The descriptor write is what other observers read off the unit; the 0x480 is
what moves the local player's own bar. `send_power_update` now sends both, plus both maxima
so a `.level` resizes the bar instead of leaving a full pool reading as partial.

**Verified live, end to end:**

```
.power 1234                  -> B after .power 1234 mana=1410/4405   (1234 + one regen tick)
key '1' (Auto Resuscitation) -> CAST 520445 ... -> SPELL_GO, -1762 power (2643 left)
                             -> E post-cast mana=2995/4405
.power 300 + key '7'         -> CAST 801809 (Nanobot Reconstruction) costs 748, have 300
                                -> CAST_FAILED(NO_POWER)
                             -> UIERR Not enough mana          (the client's own error frame)
```

`SPELL_FAILED_NO_POWER` is **85**, payload-free, and is sent *before* the `SPELL_GO` — sending
the go and then declining to charge would leave the client showing a cast the server does not
believe happened. Regen is a flat 4% of maximum every 5 s, hung off the client's own `CMSG_PING`
rather than a timer thread, so it stops when the client goes quiet.

**Two commands came with it.** `.power [n|max]` / `.health [n|max]` show or set the live pools
(this is how the refusal path is testable without grinding the bar down one cast at a time),
and `.cost <spellId>` prints the cost breakdown and the effect triples.

**Send dot-commands with `SendChatMessage`, not the chat edit box.** `ghostinput.ps1 -Action
slash` opens the box with ENTER, types, and presses ENTER — and it silently stopped delivering
`.`-lines mid-session while `/run` lines through the same path kept working. Nothing was logged
on either side; the command simply never became a `CMSG_MESSAGECHAT`. This always works:

```
ghostinput.ps1 -ProcId <pid> -Action lua -Text 'SendChatMessage(".power max","SAY")'
```

`SendChatMessage` is not protected on this client, so it needs no hardware event — unlike
`CastSpellByID`, which is, and which silently no-ops from `/run`. **Casting still has to be a
real key press on a bar slot** (`-Action key -Text '1'` for Lua slot 1). Two further traps
there: a ground-targeted spell (effect 27, `PERSISTENT_AREA_AURA` — Macro-Gravity Zone, Air
Strike) eats the key press into targeting mode and sends no `CMSG_CAST_SPELL` at all, and a
spell still on cooldown answers `UIERR Spell is not ready yet` client-side. Neither is a
server bug; pick a self-cast aura spell for cost tests.

### 10.3(b) Direct damage and healing — DONE, with the target dummy and one honest substitution.

A cast now moves health. `apply_spell_effects` (`world_server.py:2661`) reads the three
effect columns out of `Spell.dbc`, rolls `basePoints + irand(1, dieSides)`, applies it, and
answers with the log packet the client's combat log actually listens for —
`SMSG_SPELLNONMELEEDAMAGELOG` (**0x250**) for effect 2 and `SMSG_SPELLHEALLOG` (**0x150**)
for effect 10 — followed by the health update. It is called from the `CMSG_CAST_SPELL`
handler at line 4190, after the cost is charged and the `SPELL_GO` is sent.

**`EffectBasePoints` is stored one BELOW the displayed value.** This is a DBC convention, not
a bug to work around: the amount is `basePoints + irand(1, dieSides)`, so a spell that tooltips
"98 to 116" is stored `base=97, die=19`. Reading the column as the answer undercounts every
spell by exactly one and looks like rounding.

**Verified live, end to end, with no command arguments** (2026-09-02, world server restarted
onto the new defaults first):

```
.dummy                       -> Archive Target Dummy, guid 0xF13002E630000001, 200000 hp
TAB                          -> TARGET=Archive Target Dummy hp=200000
key '1' (Scorch 81226)       -> server: 106 damage (199894/200000);  client UnitHealth 199894
key '1' again                -> server: 106 damage (199788/200000);  client UnitHealth 199788
.health 2000 + key '0' (Zap! 680196)
                             -> server: 260 healing to self (2260/14280, 0 overheal)
                             -> client UnitHealth("player") 2000 -> 2260
combat log                   -> CLEU SPELL_CAST_SUCCESS / SPELL_DAMAGE
                                CLEU SPELL_CAST_SUCCESS / SPELL_HEAL
```

Both numbers land inside the rolled range (base 97 + die 19 = 98..116 for Scorch), the client's
own `UnitHealth` deltas match the server's arithmetic exactly, and the events reach
`COMBAT_LOG_EVENT_UNFILTERED` — so the whole path is real, not just the health field.

**THE HONEST LIMIT: the damage spell is Scorch, a Mage entry, not a Tinker one, and it has
to be.** The §10.3 criterion said "a Tinker damage spell". No such spell can be cast on this
client. Bomb Toss (**801005**) is the Tinker's only direct-damage entry, and its `Attributes`
have bit **`0x2` = `SPELL_ATTR0_USES_RANGED_SLOT`** set: the client refuses it *client-side*
with `UIERR Must have a Ranged Weapon equipped` and never sends `CMSG_CAST_SPELL`. There is no
item system in this archive to equip one. A scan of all **10255** CA entries found **631**
entries that do direct damage with that attribute clear and **zero** of them Tinker. So the
substitution is not a shortcut around a hard case — the case does not exist. Scorch (Scorched
Earth, **81226**) was learned onto this Free-Pick character with `.known add 1398`, which is
precisely what a classless realm is for. Re-read this if a future session "fixes" Bomb Toss:
the blocker is a client-side attribute check, and the only real fixes are an item system or a
`Spell.dbc` edit, neither of which is in §10.3's scope.

**Correction to an earlier note in this file:** §10.3 used to say none of this Tinker's bar
spells carries effect 2 or 10. That is false — exactly two do (Bomb Toss, `SCHOOL_DAMAGE`;
Zap!, `HEAL`). The rest put their damage in triggered spells (effect 64) and periodic auras
(effects 6/27), which is §10.3(c)'s problem, not this one.

**`.dummy` takes no arguments now, and the default that matters is the distance.** The dummy
used to spawn 5 yards ahead and **TAB would not target it** — it rendered, the server had it,
and the client would not select it. Measured one variable at a time:

```
.dummy 3019  0 3   -> TAB targets it
.dummy 15476 5 3   -> nothing
.dummy 15476 5 1   -> nothing
```

so it is the **offset**, not the model: display 3019 renders fine and the player's own displayId
does not help. It is not facing either — `GetPlayerFacing()` reads 5.31605 against a stored `o`
of 5.31605. The archive has no terrain height, so a spawn point that is not literally the
caster's own position gets a Z the client will not accept. `ARCHIVE_DUMMY_DISTANCE` is therefore
**`0.0`** — at the caster. Do not "improve" it by pushing the dummy out in front.

**Two client traps that cost real time here:**

- **`TargetUnit()` is protected** on this client and silently no-ops from `/run` — the server's
  own chat reply says so. **TAB (`TARGETNEARESTENEMY`) works**, and is what the probes use.
- **Long `/run` lines silently drop characters.** `ghostinput` types via `WM_CHAR` at 15 ms a
  character; past roughly a hundred characters the tail is simply not there, with no error on
  either side — a probe that never prints its own "armed" marker is this, not a logic bug. Arm
  Lua in several short one-liners instead of one long one.

### 10.3(c) Auras — DONE, both halves, with one honest limit.

A cast now applies a real aura: it shows up in the buff or debuff frame with the right icon,
counts down on its own, ticks on a one-second clock, refreshes in place, can be cancelled by
right-click, and falls off exactly when it should. Buffs on the player and debuffs on the
target dummy both work.

The engine is `world_server.py`, in the block that starts at `_AURAS = {}` — `apply_aura`,
`remove_aura`, `aura_periodic_apply`, `aura_tick`, `free_aura_slot`, `smsg_aura_update`,
`smsg_periodic_aura_log`. `apply_spell_effects` calls it for effect **6**
(`SPELL_EFFECT_APPLY_AURA`), and the `CMSG_CANCEL_AURA` (**0x136**) handler removes it.
`.aura` lists what is active; `.aura clear` drops everything.

**Verified live (2026-09-02).** The buff half, on the player:

```
key '9' (Nanobot Reconstruction 801809)
  client   T0 n=Nanobot Reconstruction  d=60
  client   rem=48.278 -> 28.976 -> 9.611          (counts down by itself)
  server   tick Nanobot Reconstruction: 6 healing (106/14280)   once per second
  client   UnitHealth 190 -> 304 -> 418
  CLEU     SPELL_AURA_APPLIED / SPELL_PERIODIC_HEAL / SPELL_AURA_REFRESH / SPELL_AURA_REMOVED
key '5' (Med Pack, 6 s)  applied 00:36:26, removed 00:36:32, M8 n=nil   (falls off on time)
cast twice               one slot reused, one icon, client fires SPELL_AURA_REFRESH
CancelUnitBuff(...)      server: aura ... off slot 0 (cancelled by the player)
                         client: after-cancel B1=nil
```

The debuff half, on the dummy:

```
.known add 30668 ; .bars set 8 803185 ; .dummy ; TAB ; key '9'
  CLEU   SPELL_CAST_SUCCESS Chains of Malice
         SPELL_AURA_APPLIED Chains of Malice
         SPELL_PERIODIC_DAMAGE x5, one per second
         SPELL_AURA_REMOVED Chains of Malice
  client UnitDebuff("target",1) = Chains of Malice, d=5     (DEBUFF frame, not buff)
  client UnitHealth("target")   200000 -> 199920            (exactly 5 x 16)
  server tick Chains of Malice: 16 damage to the dummy (199984 ... 199920 left)
         aura Chains of Malice off slot 0 (duration elapsed)
```

No crash on either; the client was alive at the end of both runs. If you re-run this and the
dummy reads 200000 again a few seconds later, that is not the aura failing to land —
`ARCHIVE_DUMMY_RESET` is 10.0 s, and the dummy heals to full that long after its last hit.

#### The wire format, as implemented

```
SMSG_AURA_UPDATE (0x496)
    packguid target | u8 slot | u32 spellId          <- spellId 0 = REMOVE, nothing follows
    u8 flags | u8 casterLevel | u8 stacks
    [if !(flags & AFLAG_CASTER)]  packguid caster
    [if   flags & AFLAG_DURATION] u32 maxDuration | u32 remaining
```

Flags: `AFLAG_EFF_INDEX_0/1/2 = 0x01/0x02/0x04`, `AFLAG_CASTER = 0x08`,
`AFLAG_POSITIVE = 0x10`, `AFLAG_DURATION = 0x20`, `AFLAG_ANY_EFFECT_AMOUNT_SENT = 0x40`,
`AFLAG_NEGATIVE = 0x80`. `SMSG_AURA_UPDATE_ALL` is **0x495** and
`SMSG_PERIODICAURALOG` is **0x24E**; the round trip was byte-checked offline first
(18/18 bytes and 29/29 bytes) before anything went near the client.

**ONE aura per spell, not one per effect.** The client's frame is keyed by slot, so a spell
with three aura effects is still one icon; the effect indices ride in the flags byte.

**The client will never drop an aura by itself.** It animates the whole countdown locally
from the single `(maxDuration, remaining)` pair in the apply packet, so the icon looks
correct even if the server forgets it exists. Expiry is *only* what the server says it is:
another `SMSG_AURA_UPDATE` carrying the slot and `spellId = 0`. If an aura sticks forever,
look at `aura_tick`, not at the apply path.

#### The server needed a clock, and the first one was wrong

`aura_tick` runs from the session loop — on every inbound packet *and* on every recv timeout.
That second half is the one that matters, and it is a fix, not a flourish: the first live run
ticked in **bursts of five every five seconds**.

I had measured `CMSG_STANDSTATECHANGE` arriving ~178 times a second and built the tick on
that traffic. The rate was real but the measurement was worthless — it was an artefact of the
state the client happened to be in. A client standing still in the world sends nothing but
`CMSG_PING`, once every 5 s. *"I measured it" is not the same as "I measured it in the state
that matters."*

So the socket is now polled (`conn.settimeout(ARCHIVE_AURA_TICK_MIN)`) and `_recv` calls
`_idle()` on each timeout. Dead-session detection moved with it: it is now
`ARCHIVE_SESSION_TIMEOUT` (120 s) of *no bytes at all*, which is what the old 120 s recv
timeout was trying to express anyway. There is deliberately no timer thread — everything the
tick touches (aura table, unit state, socket) belongs to that one session, so a thread would
need a lock around all three and buy nothing.

#### Two more Spell.dbc columns, measured

- **`DurationIndex` = column 40.** It is an index into **`SpellDuration.dbc`** (866 rows,
  4 fields, 16 bytes each; row = `id, Duration, DurationPerLevel, MaxDuration`), not a
  duration. `Duration` is **signed**: ids 21 and 427 are negative, 3.3.5a's infinity marker,
  and Ascension's own id 2 is `300000010` ms. Both are returned as "no countdown".
- **`EffectAmplitude` = column 98.** The tick period, in ms.

And the useful structural fact behind them: **the low half of this archive's `Spell.dbc` is
the stock 3.3.5a layout.** Columns 40/41/42/49 (`DurationIndex`, `powerType`, `manaCost`,
`StackAmount`) all landed exactly where stock puts them, which is what made it safe to read
column **24** below without measuring it first.

#### The gate that blocked the debuff for an hour

The first DoT tried — Eldritch Devastation (**802727**) — produced `CLEU SPELL_CAST_FAILED`
and **no server-side CAST line at all**: the client refused it before sending anything. The
UI error text was `You can't do that yet`, which is
**`SPELL_FAILED_CASTER_AURASTATE`** — and note that `SPELL_FAILED_TARGET_AURASTATE` has the
*identical* string on this client, so the message alone does not tell you which side failed.

The cause is `Spell.dbc` column **24, `casterAuraSpell` = 680601**: the client will not cast
the spell unless the caster already has that aura. Columns 20..27 are the whole gate block —
`CasterAuraState`, `TargetAuraState`, `CasterAuraStateNot`, `TargetAuraStateNot`,
`casterAuraSpell`, `targetAuraSpell`, `excludeCasterAuraSpell`, `excludeTargetAuraSpell`.
**When picking a spell to test with, require all eight to be zero**, on top of the
`Attributes & 0x2` ranged-slot bit that bit §10.3(b). `scratchpad/dotscan2.py` does exactly
that and found 79 usable periodic-damage entries; Chains of Malice (entry **30668**, spell
**803185**, Knight of Xoroth, 5.0 s, ~16 every 1.0 s) is the one used above.

#### `.bars set` — new, and you will need it

`.bars auto` fills from wire slot 0 in spellbook order, and the stock keybinds only reach
wire slots **0..11** (Lua 1..12, keys `1` through `=`). Chains of Malice autofilled onto wire
slot **12** and was therefore uncastable — and *every* Lua route to move it is protected
(`PickupSpell`, `PlaceAction`, `UseAction`, `ChangeActionBarPage`). So the server got the
missing verb:

```
.bars set <wire-slot> <spellId>      spellId 0 clears the slot
```

**THE HONEST LIMIT: only the periodic aura families do anything mechanically.** Periodic
damage (3), heal (8), leech (53), energize (24) and their neighbours move health and power
for real. Everything else — stat modifiers, stuns, roots, silences, absorbs, speed changes —
is applied, shown with the correct icon and polarity, counted down and removed correctly, and
is otherwise **inert**: there are no stats, no movement authority and no damage pipeline in
this archive for them to modify. That is a scope statement, not a defect. Do not "fix" it by
half-implementing `MOD_STUN` against a server that has nothing to stun.

### 10.4 Archetypes / Build Creator — DONE, end to end, verified live

**Done when** (the criterion, unchanged): *the Archetypes tab lists archetypes and
selecting one applies its build.* It does. The full chain, watched on a running client:

```
class byte 10  ->  C_Player:IsHero() true  ->  Collections.Tabs.HeroArchitect exists
   ->  panel opens  ->  level 80 restores the None/History categories
   ->  "All Builds" query returns 2 records
   ->  the Hero's forced FILTER_CLASS_HERO keeps exactly the class-10 build
   ->  the row renders name / author / icon / role / stat and all 13 entries
   ->  ToggleBuildActive + popup Yes  ->  CMSG_BUILD_ACTIVATE
   ->  13 entries learned  ->  SMSG_BUILD_ACTIVE_BUILD_UPDATE  ->  ACTIVATE_BUILD_OK
   ->  IsKnownSpellID flips false -> true, GetActiveBuildID returns the id,
       IsActiveBuildID true, the button reads "Deactivate Build",
       and the ActiveBuild category resolves to the build.
```

`GetBuild("no-such-build-id")` answers `nil`, so the unknown-build stub is correct too.

**And it survives a relog.** The entries always did (they live in `knownentries.json`),
but the *active* marker did not: 0x632 is the only thing that fills the client's per-spec
table and the client saves it nowhere, so a restart left the character holding every spell
the build granted while the UI showed no active build. `set_active_build()` now records
the id on the character in `characters.json` and `send_ca_block` re-announces it at world
entry, after the known set. Verified with a restart and **zero UI interaction**:
`GetActiveBuildID()` returned the id, `IsActiveBuildID` was true, and opening the panel
showed *Active Build — Free-Pick Firestarter* with a red **Deactivate Build**.

**Four client-side traps did all the damage, and every one of them failed silently.** They
are written up symptom-first in `TROUBLESHOOTING.md` (§ *Character Advancement UI*); the
short form, because each was measured rather than reasoned:

1. **`record+0x60` is the character class byte (`ChrClasses.dbc` id), not the index into
   the client's `FILTER_CLASS_` name table.** Free-Pick/classic content is **10** (Hero),
   Tinker is **28**. Proved with two records differing only in that field, under a Hero:
   `FILTER_CLASS_HERO` kept 10 and dropped 11; `FILTER_CLASS_GENERAL` — index 10 in the
   name table — kept **nothing**, because General has no `ChrClasses` row for the name to
   resolve to. The client resolves the filter *name* to a class byte first.
   `class_type_matches` (the transcribed `MatchesClass`, `0x101c6a40`) agrees: it tests
   `class_byte == ct["required"]`, falling back to `class_byte == 10` for `classic` rows —
   so `ClassTypes.required` **is** the class byte, and `build_filter_class` is just that.
   **Tinker is 28 in both numberings**, which is why the earlier Tinker-only A/B "confirmed"
   the wrong theory. That theory is retired.
2. **The icon must be a bare name.** Five separate consumers prefix `Interface\Icons\`
   themselves; a full path lands in `Logs\MissingFiles.txt` doubled.
3. **`Roles` must never be 0.** It is a bit flag (1 LEADER, 2 TANK, 4 HEALER, 8 DAMAGE).
   0 comes back as `PLAYER_ROLE_NONE`, which is not a key of `Enum.BuildRoles`, and
   `SetBackground` concatenates that nil into a texture path unguarded
   (`BuildView.lua:657`). Because `SetBackground()` runs **before** `SetBuildInfo()`, the
   visible symptom is not an error message — it is a build that renders with **no name, no
   author and no icon**.
4. **The active-build marker is its own packet.** `SMSG_BUILD_ACTIVE_BUILD_UPDATE = 0x632`,
   body `u32 spec, CString buildID, u8, u8` (handler `0x100fdfd0`, element reader
   `0x100fc950`, event literal `0x10b2f1a8`; vector `[mgr+0x1d0..0x1d4]`, stride `0x1C`).
   Without it the build applies and the spells are learned, but the button never becomes
   "Deactivate Build" and the ActiveBuild category stays empty. **Its spec index is 0-based
   while the Lua accessor over the same vector is 1-based:** sending 1 put the id where
   `GetActiveBuild(2)` could see it and left `GetActiveBuild(1)` — the one
   `BuildCreatorUtil.GetActiveBuildID` actually reads, since
   `SpecializationUtil.GetActiveSpecialization()` answers 1 — empty. Send **0**.

**Things that are not bugs but will look like them:**

- **The panel's default category is `BuildDraft` (index 2), not All Builds**, and
  `SelectCategory` short-circuits when `lastQueried == category`. A panel that opens and
  never queries is doing what it was told.
- **`None` (All Builds) and `History` are level-gated**, not permission-gated: they are
  appended only when `C_Player:GetLevel() == GetMaxLevel()` (80 here) or `IsGM()`. The
  archive character was raised 79 -> 80 with `.level 80` for this.
- **`ToggleBuildActive` puts nothing on the wire.** It only raises a `StaticPopup`; the
  accept button is what calls `ActivateBuild`. From a script: `StaticPopup1Button1:Click()`.
- **`IsHero()` is read once**, in `Collections:SetupTabSystem`. `.class 10` takes effect on
  the next client start, not immediately.
- **`load_builds()` re-reads `builds.json` on every query** — edit a build and re-test it
  without restarting the world server.

**Where the layouts are written down:** `world_server.py` — `smsg_build_record`,
`build_filter_class`, `BUILD_CLASS_HERO`, `BUILD_DEFAULT_ICON`, `BUILD_DEFAULT_ROLE`,
`smsg_build_active_build_update`, `ARCHIVE_ACTIVE_SPEC`, each with the measurement that
produced it in the comment above it. `PrimaryStat` is 0 STRENGTH, 1 AGILITY, 2 STAMINA,
3 INTELLECT, 4 SPIRIT.

**Technique worth reusing:** `Interface\FrameXML\Util\BuildCreatorUtil.lua` is MPQ-only, so
`BuildCreatorUtil.GetActiveBuildID` was read by `string.dump()`-ing the live function and
printing it through `dprint` as `string.gsub(B, "[^%w_%.]", ".")`. The string constants
alone answered the question. (Watch the ~95-100 character truncation on `/run` lines typed
through `WM_CHAR`: alias and split.)

### The login "UI Error" banner — one of the two errors fixed, one OPEN

Chasing this is what closed out the session, so both halves are recorded rather than left
for someone to rediscover. The banner is raised by real Lua errors held in
`ERROR_HANDLER_DATABASE.errors.current` — read them from there, **not** from
`Logs\Error.txt`, which only ever held a red herring.

- **FIXED: `MainMenuBar.lua:381: attempt to compare number with nil`.** The archive never
  set the **rest-state byte** — byte 3 of `PLAYER_BYTES_2` (1 rested, **2 normal**, 6 RAF) —
  so `GetRestState()` answered `nil, nil, nil` and `ExhaustionTick`'s
  `PLAYER_ENTERING_WORLD` handler compared it against a number. `player_bytes2` now carries
  `REST_STATE_NORMAL << 24`. Verified: `GetRestState()` -> `2  Normal  1`, error gone.
- **OPEN: `C stack overflow`.** `C_Hook.SendEvent(bucket, "ADDON_LOADED", ...)` recurses
  into itself ~198 frames deep (Lua's C-call ceiling), entirely inside MPQ'd
  `Interface\SharedXML\C_Hook.lua`, via `SecureSetValues -> SetAttribute("event-wipe" /
  "event-update") -> the attribute handler -> SendEvent`. Reproduce on demand: wrap
  `C_Hook.SendEvent` from `/run`, then `LoadAddOn` any on-demand addon. The companion error
  (`CallbackHandler ... chunk has too many syntax levels`) is a *downstream artefact* of the
  same overflow, not a second bug. Ruled out: listener count (there are 2), our `LoadAddOn`
  override, and any registration of ours. `C_Hook.lua` may not be patched, and whether the
  live realm does this too is untestable here. Full write-up in `TROUBLESHOOTING.md`.

### 10.5 Character creation as a custom class — **DONE, end to end, verified live**

**Result (2026-09-02 07:09).** A character was created *through the client's own
character-creation screen* as a custom archetype, and on its first login the client asked the
server for that archetype's build and the server granted it:

```
[07:01:09] w003:    CHAR_CREATE name='Testgamma' race=11 class=10 gender=1 ...
[07:01:09] w003:    *** CHARACTER CREATED guid=3 display=16126 @ map=530 zone=3524 ***
[07:09:27] w004:    BUILD_ACTIVATE 05901096-411d-4810-8e07-19c58128fdc8 (args 1,1)
                    -> applied 'Blade Warden': 4 entry/entries learned, active for spec 0, ACTIVATE_BUILD_OK
```

and in-world, read back out of `LUA.txt`:

```
07:09:27 [[C]:-1] Found build for Testgamma activating 05901096-411d-4810-8e07-19c58128fdc8
07:11:07 [[C]:-1] SPELLS Divine Storm Ghostly Strike Riposte Devastate
```

Those four are exactly the Blade Warden entry set. Nothing was hand-fed: the driver picked
Tank → Melee → Blade Warden in the carousel, the client wrote `archetypeBuildID` into its own
`NewCharacterSetup` blob, and the *client* sent `CMSG_BUILD_ACTIVATE` unprompted at
`PLAYER_LOGIN`.

**How it is driven.** `tools/`-adjacent driver `asc_charcreate4.lua`, installed into
`client-ascension\Interface\GlueXML\AccountLogin.lua` by `charcreate_ctl.py`
(`install` / `config '<json>'` / `status` / `uninstall`). It is **inert unless armed** —
`ASCENSION_ARCHIVE_CHARCREATE = nil` — and must be left that way, because that file is on
the junction into the live install.

Four things about it that are not obvious and each cost a run:

1. **The first `SetGlueScreen("charcreate")` reloads the whole glue Lua environment.**
   Measured twice; `GlueErrorHandler.json` is unchanged across it, so it is client behaviour,
   not a Lua fault. `LUA.txt` and `GlueXML.log` are truncated by that reload, which is why the
   driver keeps its own transcript in `WTF\Custom\ArchiveCharCreateLog.json` and caps itself
   at `maxLoads` bounces.
2. **`GetCVar("realmList")` is useless as an archive gate.** The client stomps it back to the
   official address on that reload and `AccountLogin_OnShow` does not run on the resume path.
   Gate on `ASCENSION_ARCHIVE_REALMLIST`, which `launch-client.ps1` owns.
3. **`GoToIndex(id)` is a silent no-op when no button carries that id.** Always read back with
   `GetCurrentIndex()` and abort on a mismatch, or you create the wrong archetype.
4. **Do not enter the world in the run that created the character.** `NewCharacterSetupUtil`
   loads its blob once per Lua environment, so the world side still holds the pre-create copy.
   Exit, then relaunch.

The authoritative role/category/archetype tree, enumerated live from the client's own DBC
accessors, is in `scratchpad/`-era notes and reproduced here: role 1 Tank = cat 1 Melee
(20, 19, 21, 22, 24, 143), cat 2 Magic (25, 26, 31), cat 3 Hybrid (27, 29, 30, 32, 33, 34);
role 2 Healer = cat 5 Pure (3, 7, 6, 1, 12, 16, 2, 10), cat 6 Combat (13, 14, 15, 17, 18);
role 3 Damage = cat 9 Melee (73, 129, 77, 78, 79, 86, 74, 141), cat 10 Ranged (84, 82, 85,
139, 140), cat 11 Magic (88, 104, 95, 97, 90, 101, 144), cat 12 Hybrid (132, 133, 134, 80,
75, 142, 131, 136).

**Server-side change that went with it.** A first-login `CMSG_BUILD_ACTIVATE` can arrive
while the CA block is still deferred. `world_server.py` now stores the build immediately and
owes the `SMSG_BUILD_ACTIVATE_RESULT` to the CA flush (`ca_pending_ack`), so it can no longer
poison `_SPELLS_SENT` or race the `0x725` container.

---

#### The original investigation, kept for the reasoning


§10.5 was written off as "KNOWN LARGE, probably out of reach" on the assumption that
`C_CharacterCreate` is glue-only. **It is not.** The whole native namespace is registered in
FrameXML too, so the entire character-creation dataset can be read from a running,
logged-in client with `/run` — no glue, no MPQ, no mouse. Measured 2026-09-02:

```
C_CharacterCreate has 33 members in-world, including
  CanCreateClass  CanCreateCoA  CanCreateHero  CanCreateWCR
  GetArchetypes  GetArchetypeInfo  GetArchetypeRoles  GetArchetypeCategories
  GetArchetypeRoleInfo  GetArchetypeCategoryInfo  GetArchetypeSpellDescription
```

**Every gate the creation screen checks is already open on this archive** — measured, not
inferred:

| gate | where it lives | archive answer |
|---|---|---|
| `CanCreateHero()` | Extensions.dll, realm-flavour byte | **true** |
| `CanCreateCoA()` | same | **true** |
| `CanCreateClass(10)` / `(28)` | `0x1018d550`, jump table on classID | **true / true** |
| `GetRealmName() == "Area 52 - Free-Pick"` | half of `CanCreateArchetype` | **true** |
| `C_Config.GetBoolConfig("CONFIG_CHARACTER_CREATION_ARCHETYPES_ENABLED")` | other half | **true** |

So the client will offer **Tinker (28) and every other CoA class** at creation, and
`CharacterCreate_OnShow` will open on `Enum.CharCreateArchetypeBases.UseArchetype` with the
Role → Category → Archetype steps in the navigation bar. (§4.8 of `HANDOFF-ARCHIVE-SESSION.md`
already showed the class pages; this is the archetype half of the same story.) An earlier
session drove that wizard by hand: *Testbeta* — still on the account, guid 2, class 10,
**still level 1** — was created through it with the Hoplite archetype.

**The archetype tree, read out of the client:**

```
role 1 Tank    -> categories 1, 2, 3
role 2 Healer  -> categories 5, 6
role 3 Damage  -> categories 9, 10, 11, 12          56 archetypes across the nine
```

`GetArchetypeInfo(id)` returns **13** values, and the ones that matter are
`[1] buildID` (a UUID string), `[2] a table of the archetype's 3-5 signature spell ids`,
`[3] primary stat token`, `[4] weapon subclasses`, `[5] armor subclasses`, `[6] bare icon
name`, `[10] name`, `[11] short blurb`, `[12] long blurb`, `[13] cinematic path`. All of it
comes from `DBFilesClient/CharacterCreationArchetypes.dbc`, whose columns decode as
`f000 id, f001 category, f002 buildID, f003..f007 spell ids, f008 primary stat,
f015 icon, f019 name, f036 short, f053 long, f155 cinematic` — checked field by field
against the client's own answer for archetype 2 (Dawnkeeper: build
`c483eaf6-a46d-49e4-a55a-ae807d02d279`, spells `{635 Holy Light, 53563 Beacon of Light,
596 Prayer of Healing}`, icon `Ability_Paladin_BeaconofLight`).

#### The archetype's build now exists, and applying it works

`HANDOFF-ARCHIVE-SESSION.md` §4.7 says the first-login call
`C_BuildCreator.ActivateBuild(archetypeBuildID, true, true)` "runs, but emits nothing on the
wire, so nothing is learned". **That is no longer true and should not be repeated.** It was
written before `CMSG_BUILD_ACTIVATE` had a handler. Measured with a real archetype GUID:

```
w001: <- CMSG_BUILD_ACTIVATE (39 B body)
w001:    BUILD_ACTIVATE c483eaf6-... (args 1,1) -- UNKNOWN build; re-sent the current
         13 entry/entries unchanged.
```

It reaches the server every time. The only thing missing was that `builds.json` had never
heard of the 55 GUIDs the creation screen hands out. It has now:

- **54 archetype builds seeded** (`scratchpad/seed_archetype_builds.py`, backup at
  `builds.json.pre-archetypes`). Hoplite was left alone — its 36-entry set was authored with
  `.build save` in an earlier session and is already verified — and *Naturalist* is skipped
  because the DBC gives it no build id at all.
- **The contents are Ascension's, not invented.** Each build is exactly the archetype's own
  signature spells (DBC `f003..f007`) resolved through `CharacterAdvancement.dbc` to CA
  entry ids: 221 of 237 spells map, and the 16 that do not are recorded per build in the
  script's output. What is *not* recoverable is how large Ascension's real archetype builds
  were — that lived on their server — so these are the signature abilities and nothing more.
- Name, bare icon, primary stat and the Roles bit flag all come from the DBC, so §10.4's
  three silent traps (doubled icon path, `Roles == 0`, blank record) are avoided by
  construction.

Verified live, in this order, with the character put back exactly as it was afterwards:

```
ActivateBuild("c483eaf6-...")  ->  applied 'Dawnkeeper': 3 entry/entries learned,
                                   active for spec 0, ACTIVATE_BUILD_OK
IsKnownID(2709 Holy Light)     ->  true
ActivateBuild("c0ffee00-...")  ->  applied 'Free-Pick Firestarter': 13 entries, restored
QueryAllBuilds("None")         ->  server: 56 build(s) in one chunk
                                   client: GetNumBuilds() = 55 after the class filter
```

and the Archetypes panel now draws the whole list — Blade Warden / Path of Strength,
Icebound / Path of Intelligence, Fire Sage / Path of Healing, ... — each with its real icon,
its role badge, `Author: Ascension`, and a working *Choose this Build*.

#### 0x62E is `CMSG_BUILD_QUERY_CATEGORY`, not `CMSG_GAME_MODE_QUERY`

§10.2 concluded that the empty answer to 0x62E was correct. **The answer was right; the
name was wrong**, and the correction matters because the opcode is load-bearing here.
0x62E carries a **BuildCategory name string**: the 11-byte body §10.2 saw was
`"BuildDraft\0"` — the panel's default category (§10.4) — not a game-mode name, and tonight
the same opcode carried `"None"` and came back with 56 build records that the client
rendered as rows. The record vector §10.2 traced to `[mgr+0x148]` is the build list, which
is the same vector §10.4's ledger entry describes. Everything §10.2 measured stands; only
the identification changes, and its conclusion was accidentally right — with no builds
stored, an empty answer *was* the correct answer.

#### What is left: one file the archive is not allowed to edit unattended

The only unfinished step is driving the creation screen itself. It cannot be done from
in-game: `SetGlueScreen`, `SetCharacterClass` and `CharacterCreate_Finish` are glue-side, the
"Create New Character" button is mouse-only (`CharacterSelect_OnKeyDown` binds ESCAPE, ENTER
and the arrow keys, and none of them reach it), and ghost input cannot click — WoW polls the
physical cursor.

That leaves one mechanism: `client-ascension\Interface\GlueXML\AccountLogin.lua`, the loose
glue file the archive already owns for the realmlist redirect. A driver for it is written and
staged at `scratchpad/asc_charcreate.lua` (with `scratchpad/install_charcreate.py` to append
it): a small OnUpdate state machine that goes to charcreate, applies race/sex/class, walks
the three archetype carousels with `GoToIndex`, and either photographs the screen or presses
Create. It is inert three ways over — `ASCENSION_ARCHIVE_CHARCREATE` is `nil` as shipped so
not one statement runs, it refuses unless `realmList` is loopback, and every step is
`pcall`ed.

**It was not installed.** That file is on the junction into the live install, and writing to
it needs the maintainer's say-so, which is exactly the §8 rule. So this is a decision, not a mystery:
say yes and the run is one client restart, or delete the two scratchpad files and the
archetype work above still stands on its own.

### Stand state — sit/stand now round-trips, and a log-eating flood is capped

Two separate things, and only one of them is solved.

**Solved: the sit key now stands the character back up.** `CMSG_STANDSTATECHANGE` (0x101)
went unanswered, so `UNIT_FIELD_BYTES_1` (field **74**, byte 0 = stand state) was never
written. The client animates a sit locally the moment you press the key, so it *looks*
like it worked — but `SitStandOrDescendStart` decides what to send next by reading that
field, not by looking at the animation. Measured: with only `SMSG_STANDSTATE_UPDATE`
(0x29D, one `u8` body) two presses sent `state 1` **twice** and the character stayed
seated; adding a values update for field 74 made the same two presses send `1` then `0`,
and the character sat and stood on screen. **Send both** — the descriptor is the half that
matters. The player create block now carries `UNIT_FIELD_BYTES_1 = 0` as well, so a
character logs in standing instead of inheriting the previous session's pose.

**Not solved: what made the client send it 190 times a second.** The world log had reached
54 MB, **759,299 of its 835,682 lines** a single repeated `CMSG_STANDSTATECHANGE` trace.
It is one packet per *rendered frame* — `GetFramerate()` 176.5 against ~190 lines a second,
character stationary — not the timer an older code comment assumed. A relog cleared it and
it has not returned. It is tempting to write that up as "answering the opcode fixed it", and
that would be wrong: reverting to the unanswered build and relogging produced no flood
either (+7 lines in 10 s), so the relog is the only thing shown to end it. Two other
theories died on the way — the character was not seated (the model was sunk below the
terrain; both poses photograph identically from a close camera) and no movement key was
stuck (speed 0, position unchanged). Left **OPEN** in `TROUBLESHOOTING.md` with the one
datum that would settle it: the 4-byte body value at the time it is flooding.

What *is* in place is damage control: the inbound trace for this opcode is capped at three
lines per session and counted after that, exactly as `CMSG_SET_ACTION_BUTTON` already was,
so a recurrence costs a tally line rather than tens of megabytes.

### Reading client output

`dprint()` does **not** go to chat — it appends to
`C:\AzerothRealm\client-ascension\Logs\LUA.txt`. Tail that file; screenshots of the chat
frame show nothing and will waste time. Also: `ghostinput.ps1 -ProcId` is **mandatory**,
and omitting it makes the script block forever on a PowerShell parameter prompt rather
than failing.

---

## 1. State as of 2026-09-01 — verified today, not remembered

**Was written when nothing was running. As of the end of 2026-09-02 the whole archive
stack is UP and logged in** — shim on 3799, `world_server.py` on 8087, one `Ascension.exe`
in the world on Sunstrider Isle as the level-80 Hero with the Free-Pick Firestarter build
active. the maintainer's own progression realm is up alongside it and was never touched
(`authserver` + `worldserver` on 3724 / 8085 / 7878, running since 2026-09-01 19:40).
If it is all stopped when you arrive, boot with §5; state persists either way.

Already working, verified against a running client:

- Login -> character select -> world entry, and the client *stays* in world.
- The CoA tree renders: 153 populated `class|tab` buckets, 8873 visible entries, 42 classes.
- `SMSG_CA_ACTIVE_SPEC` (0x725), `SMSG_CA_ESSENCE_BUDGET` (0x722) and
  `SMSG_CA_KNOWN_ENTRIES` (0x726) are implemented and verified — including rank, and the
  add/remove diff path in both directions mid-session.
- `CMSG_BUILD_ACTIVATE` (0x5C2) implemented and verified (0 -> 36 entries in one activation).
- `knownentries.json` holds 36 entries for guid 1 — 24 `Ability` + 12 `Talent`, all `Tinker|Class`.

### The measurement that makes Track A easy

Every known CA entry resolves to a real spell — **36/36, zero misses** — and the names are
identical in both DBCs:

```
entry   type    class     tab      spellID   spell name (CA name)
4871    Ability Tinker    Class    704107    Concussive Spanner (Concussive Spanner)
4987    Ability Tinker    Class    707398    Cutting Edge Technology (Cutting Edge Technology)
5103    Talent  Tinker    Class    707832    Modulator (Modulator)
5116    Ability Tinker    Class    505336    Clockwork Ingenuity (Clockwork Ingenuity)
```

The join is entirely local and needs no server contact:

> `knownentries.json` -> `rexxar-reference/ca-dbc-export/entries.csv` (column `SpellID`)
> -> `server-ascension/Data/dbc/Spell.dbc`

That `Spell.dbc` is Ascension's — **209,509 records** against vanilla 3.3.5a's 49,839, with
custom ids running to ~13.9M. `server/Data/dbc/Spell.dbc` is the vanilla control and has
none of them. Never test against that one by accident.

Field offsets, located empirically rather than from a remembered layout: `ID` = field 0,
`Name` = **field 136**, `Rank` = +17, `Description` = +34, `ToolTip` = +51, `DurationIndex`
= field 40 (resolve through `SpellDuration.dbc`), `ProcFlags` = 34, `ProcChance` = 35.

### The measurement that makes Track A necessary

`world_server.py:1081`:

```python
def smsg_initial_spells():
    # u8 talentSpec | u16 spellCount=0 | u16 cooldownCount=0
    return bytes([0]) + struct.pack("<H", 0) + struct.pack("<H", 0)
```

and `smsg_action_buttons()` returns `bytes([0]) + bytes(144 * 4)` — 144 empty slots.

**The character currently knows zero castable spells.** The CoA "known entries" state and
the client's actual spellbook are two independent systems, and only the first is wired.
That is why the tree looks populated while the bars are bare.

---

## 2. Track A — Spells

**Change `smsg_initial_spells()` to send the character's real spell list**, derived from
`knownentries.json` through the join above.

3.3.5a `SMSG_INITIAL_SPELLS` (0x12A) body:

```
u8  talentSpec
u16 spellCount
    spellCount * { u32 spellId ; u16 slotId }        slotId 0 is fine
u16 cooldownCount
    cooldownCount * { u32 spellId; u16 itemId; u16 spellCategory;
                      u32 cooldown; u32 categoryCooldown }
```

Steps:

1. Add a `ca_entry_spells()` helper beside the existing CA code that loads `entries.csv`
   once (10,255 rows, cheap) and maps `entryID -> SpellID`. The row also carries
   `SpellID2..SpellID5`; they are **0 for all 36 current entries**, so start with `SpellID`
   alone and revisit if a multi-spell entry appears.
2. Feed those ids into `smsg_initial_spells()`. Keep the zero-spell path working — a fresh
   character with no known entries must still get a well-formed packet.
3. Populate `smsg_action_buttons()` from the same list so the bars are not empty. Slot
   encoding is `spellId | (ACTION_BUTTON_SPELL << 24)`; 0 means empty.
4. **Verify in-game, not in the log.** The spellbook should list the Tinker abilities by
   name and the bars should carry icons.

   ```
   ghostinput.ps1 -ProcId <pid> -Action lua -Text 'DEFAULT_CHAT_FRAME:AddMessage("tabs="..tostring(GetNumSpellTabs()))'
   ```

   Then actually cast one and watch the world log.

**Expect the granted-vs-known distinction to bite.** `SMSG_INITIAL_SPELLS` at world entry
is the bulk path; granting a spell *mid-session* is a separate opcode (`SMSG_LEARNED_SPELL`)
that Track B will need. Wire the bulk path first and confirm it before touching the
incremental one.

---

## 3. Track B — Talent trees (spending essence)

The tree renders and the client already knows how to ask. What is missing is the
**client -> server "learn this entry"** opcode.

The Lua binding is `LearnID` at **`0x1017d140`** (see `rexxar-reference/ca-lua-bindings.txt`),
alongside `CanLearnID 0x10174c10`, `ShouldConfirmLearnID 0x1017ee70`, `UnlearnID 0x1017fbe0`,
`UnlearnAllSpells 0x1017fba0`, `UnlearnAllTalents 0x1017fbc0`,
`ClearRecentlyLearnedEntries 0x100b2710`.

Every CA-family opcode registered in `Extensions.dll` that we still do **not** implement:

| opcode | dec | handler | site |
|--------|-----|---------|------|
| 0x659 | 1625 | 0x101705e0 | 0x1017225d |
| 0x65b | 1627 | 0x10170dc0 | 0x1017226e |
| 0x6e2 | 1762 | 0x1016fe70 | 0x1017227f |
| 0x728 | 1832 | 0x10170360 | 0x10172290 |
| 0x729 | 1833 | 0x10170b50 | 0x101722a1 |
| 0x72a | 1834 | 0x10170750 | 0x101722b2 |
| 0x72b | 1835 | 0x10170950 | 0x101722c6 |
| 0x72c | 1836 | 0x10170f30 | 0x101722d7 |

Those are the *server->client* handlers. `LearnID` sends a CMSG whose number is not in that
table — find it the way `0x5C2` was found.

**Do the dynamic capture first; it is far cheaper than disassembly.** This is the literal
lesson of §4.11: the `ActivateBuild` opcode sat unrecognised in a capture file the whole
time, while the old handoff claimed the call "emits nothing on the wire."

1. Boot (§5) and get in world.
2. Delete the old `world_unhandled_*.bin` so the new capture is unambiguous.
3. Call the binding directly — no clicking needed, and ghost-clicking is impossible anyway (§6):

   ```
   ghostinput.ps1 -ProcId <pid> -Action lua -Text 'C_CharacterAdvancement.LearnID(5195)'
   ```

   Pick an entry that is **not** already known and **is** affordable. 5195 (Mechanosoldier)
   is already known — take a neighbour from `entries.csv`, or run `.known clear` first.
4. List the new `world_unhandled_*.bin`; the filename names the opcode. Decode the body
   against the entry id you passed — it will almost certainly be `u32 entryID` plus a rank
   or a flag.
5. Implement it: apply through the existing `set_known()`, re-send `0x726`, and grant the
   spell incrementally (see Track A's closing note).
6. Confirm `GetLearnedAE` / `GetLearnedTE` move and the essence total drops.

**If `LearnID` silently no-ops**, check `CanLearnID` first. It gates on essence, on
prerequisites, and on level. Prerequisites are `ConnectedNodes`, exported to `edges.json`,
and they are **directed** — an edge points at the *prerequisite*, always at a lower
`PositionY`. `ARCHIVE_LEVEL` is already 80. Essence comes from `send_essence_budget()` at
`world_server.py:1388`, where the **level-0 row** is the one the client actually reads its
live budget from.

---

## 4. Track C — Custom classes: DONE

The mechanism, the measurements and the `.class` command are in §0.1. In short: the class is
the byte in `UNIT_FIELD_BYTES_0`; `.class` sets it, persists it to `characters.json`,
re-sends the values update, the essence budget and the known-entry set, and prunes what the
new class cannot learn. 42 classes live in `rexxar-reference/ca-dbc-export/classes.json`,
tabs in `tabs.json`, and the required class byte per ClassType is column 2 of
`DBFilesClient_CharacterAdvancementClassTypes.dbc`.

What is **not** done, in the order worth attacking next:

1. **Character creation.** `C_CharacterCreate.GetArchetypes` / `GetArchetypeInfo` live in
   GlueXML, where addons cannot run and the files are inside an MPQ. Choosing the class at
   create time, rather than with a server command afterwards, is a much bigger lift. This
   assessment is unchanged.
2. **`CMSG_GAME_MODE_QUERY` (0x62E) is still a stub** — answered, but with an empty record
   set, at `world_server.py:3172` (`smsg_game_mode_query_response` @1323). Hero classes sit behind the Archetypes tab, which is
   TABLED.
3. **`CMSG_SET_ACTION_BUTTON` (0x128) has no handler.** The client sends one per slot after
   every `SMSG_ACTION_BUTTONS` — 144 at a time, 861 across one session — and they are logged
   and dropped, so a player's own action-bar edits never persist. Irrelevant to the three
   tracks; an obvious small win. The name comes from `ascension-opcodes.txt:243`; the body is
   5 bytes and the captured sample is `01 00 00 00 00`.

---

## 5. Boot runbook

All three **unelevated**, same user. The servers RPM-read the client's session key, so the
client must be unelevated too (`RunAsInvoker`). No UAC needed.

Preflight — the glue must point at the shim, which is what survives the client's
`Config.wtf` rewrite:

```bash
grep -n "ASCENSION_ARCHIVE_REALMLIST" "/c/AzerothRealm/client-ascension/Interface/GlueXML/AccountLogin.lua"
```

It must read `ASCENSION_ARCHIVE_REALMLIST = "127.0.0.1:3799";`

**1) Auth shim** (127.0.0.1:3799), background:

```powershell
cd C:\AzerothRealm\realms\ascension; python shim3799.py TEST TEST
```

**2) World server** (127.0.0.1:8085), background:

```powershell
cd C:\AzerothRealm\realms\ascension; python world_server.py
```

**3) Client — launch directly.** Do NOT use `launch-client.ps1`'s Start-Job / Wait-Process /
finally pattern: its `finally` restores the official realm and blanks the glue about two
seconds after launch. That is the trap that once pointed an entire session at live.

```powershell
$env:__COMPAT_LAYER = 'RunAsInvoker'
Start-Process -FilePath 'C:\AzerothRealm\client-ascension\Ascension.exe' -WorkingDirectory 'C:\AzerothRealm\client-ascension' -NoNewWindow -PassThru
```

**4) Log in** as account `test`, any password — the shim authenticates by reading K, not by
checking the password. Click Login once.

Verify local, not live:

```bash
tail -6 "/c/AzerothRealm/realms/ascension/shim_log.txt"
tail -4 "/c/AzerothRealm/client-ascension/Logs/connection.log"
```

```powershell
Get-NetTCPConnection -OwningProcess <clientpid> -State Established | ? RemotePort -in 3799,8085,3724
```

An established `127.0.0.1:8085` is correct. **`51.210.230.10` means you are on LIVE — stop.**

---

## 6. Driving the client

`ghostinput.ps1` takes a mandatory `-ProcId` and the actions `key`, `char`, `lua`, `luaclick`,
`slash`, `shot` (**`-Out`**, not `-Path`), `info`. Use it, **not `wowin.ps1`** — that one
steals focus and moves the physical mouse, and the maintainer has asked that it never be used while he
is at the machine.

- **You cannot ghost-click at coordinates.** Measured. WoW polls the real cursor, so a posted
  click lands wherever the physical pointer happens to be. Use `-Action lua` or `Frame:Click()`.
- `-Action slash` does not deliver a leading-dot command. Use
  `-Action lua -Text 'SendChatMessage(".known clear","SAY")'` — and **omit the language
  argument**; passing 0 raises `Unknown language` on this character.
- Glue screens are keyboard-navigable: ENTER = Login / Enter World, UP/DOWN = change character.

---

## 7. Traps that will cost you an hour

- **`ASC_IsArchive()` is false on a fresh process's first world entry.** It reads the
  `realmList` CVar, and the client's native restore-to-official fires once — between the
  first login screen and the first world entry. So the `CoAReader` autorun silently skips
  the first login and works from the reconnect onward. Measured both ways. Do not `SetCVar`
  to "fix" it: `Config.wtf` is on the junction and is rewritten on exit.
- **`client-ascension` is a JUNCTION into the live install.** Anything written there touches
  the real account. Gate every auto-running client edit on `ASC_IsArchive()`. Never run the
  launcher repair — it reverts our work.
- **Bash heredocs eat backslashes.** Hit three times in one session: a literal TAB, a real
  newline, and a real NUL byte all ended up inside source files. Use a quoted heredoc and
  assert the paths survived before trusting the file. Separately, backticks inside a
  double-quoted `python -c` are command substitution and will swallow the script — and a
  long document with mixed quoting may simply refuse to parse, in which case write it with
  the file-writing tool instead of fighting the shell.
- **A mid-session class change does not move `UnitClass`.** The CA subsystem picks up a
  `UNIT_FIELD_BYTES_0` values update at once; `UnitClass` caches at object-create and needs a
  relog. If `CanLearnID` has flipped but the class name has not, nothing is broken.
- **`ghostinput.ps1 -Action lua` silently drops an over-long line.** The text goes through the
  chat editbox, so anything past its ~255-character limit produces no output and no error —
  the script's own header says to keep a line SHORT and it means it. A ~330-character `/run`
  vanished without trace. Split the probe instead of wondering why `dprint` never fired.
- **The CoA panel's global is `CoATalentFrame`.** There is no `CharacterAdvancement` global
  and no `Collections.CharacterAdvancement`; `Collections.tabPanels` maps tab id -> the frame
  **name as a string** (`[1] = "CoATalentFrame"`), which indexes without erroring and returns
  nil, so a wrong guess looks like an empty frame rather than a mistake. The live frame is
  also a **newer build** than `rexxar-reference/ui-source/Ascension_CharacterAdvancement`:
  it has `SpecView` / `TreeView` / `ShowTreeView()` / `ShowSpecView()` / `ChangeSpecID()` and
  a `class` string field, and **no** `Content.tabs`. Enumerate the live frame; do not trust
  the reference source's shape. Open with `Collections:GoToTab(Collections.Tabs.CharacterAdvancement)`
  (tab id 1), then `CoATalentFrame:ShowTreeView()` to get past the spec chooser.
- **Do not rename `tools/disx.py` to `dis.py`** — it shadows the stdlib module.
- The client process is named **`Ascension`**, not `Wow.exe`.
- Lua argument-count errors are validated natively, so **`pcall` never sees them**. They land
  in the client's `Logs` directory, and the in-game UI-Error frame drip-feeds a stale backlog
  on a cooldown. Check the file's mtime against the clock before believing what it says.

---

## 8. Scope / safety (still in force, from the maintainer)

- Local environment and provided client files ONLY. Do **not** target Ascension production
  infrastructure, external accounts, credentials, anti-cheat, or any third-party system.
- Do **not** patch `Extensions.dll` on disk. Reading, disassembling and RPM-reading are fine;
  RPM and Frida stay **read-only**. No `WriteProcessMemory` to flip flags.
- Do not ask for the real Ascension password.
- Do not add auto-running or account-mutating code to shared FrameXML without an archive gate.
- Editing our loose client Lua, `world_server.py`, `shim3799.py` and the auth server IS in scope.
- **Elevation is permitted** (the maintainer, 2026-09-01: *"It also has my permission to operate
  elevated."*). Be clear about what that does and does not change: **the boot chain does not
  need it and must not use it.** The entire point of `__COMPAT_LAYER = 'RunAsInvoker'` is to
  run the client *unelevated* so that the unelevated shim and world server can RPM-read its
  session key. An elevated client under unelevated servers breaks that chain outright, and
  elevating all three is a needless change to a working setup. Spend the grant on the one
  command that actually needs it — writing outside the user profile, a service or driver
  level tool, an installer — and leave the realm alone.

Ascension shuts down **2026-09-04**. Nothing in this handoff depends on the live realm — all
three tracks are local data and local RE, and can be finished after the servers go dark.

### Three things that leaked past the archive gate — FOR ADMIN TO DECIDE, not to "fix" unasked

Found while working §10.4. None of them is urgent, all three touch the **live** install
through the `client-ascension` junction, so none was changed unilaterally.

1. **`checkAddonVersion` is now `0` in the live client's `WTF/Config.wtf` (line 32), and we
   put it there.** `ASC_Probe6()` (`GlobalOverwrites.lua:748`) does
   `SetCVar("checkAddonVersion", "0")` as part of a measurement and never restores it. The
   probe is manual-only, but the value persisted. Stock is `1`. Reverting it is one line
   — `/console checkAddonVersion 1` — but it is the maintainer's client, so ask first, and while
   you are there make the probe restore what it changed.
2. **`/ca` is registered with no `ASC_IsArchive()` gate.** The `PLAYER_LOGIN` frame at the
   bottom of `GlobalOverwrites.lua` binds `SlashCmdList["ASCCA"] = ASC_ShowCA`
   unconditionally, so the command exists on the live realm too. It only opens the
   Collections journal, so the blast radius is small — but it is our code running on the
   real account, which is exactly what §8 says not to do.
3. **`ASC_IsArchive()` tests the `realmList` CVar** (`has(addr, "127.0.0.1")`), falling back
   to the old `Ascension-Local` name. The client resets that CVar natively part-way through
   a session, so the gate is trustworthy at FrameXML-load and login time and **suspect
   mid-session**. Any earlier A/B control that gated on it mid-session should be re-read
   with that in mind.

---

## 9. Key files

| Path | What |
|---|---|
| `realms/ascension/world_server.py` | The world server. CA class-types block @1450-1660 (`class_type_matches` @1546, `class_unlearnable` @1604), `smsg_initial_spells` @1868, `send_essence_budget` @2082, CA opcode notes @165-310. |
| `realms/ascension/shim3799.py` | Auth shim. |
| `realms/ascension/knownentries.json` | Per-guid learned CA entries (guid "1" = the 36-row Tinker build, restored and live). |
| `realms/ascension/characters.json` | Per-character record. **`class` is the CoA class** — see §0.1. guid 1 = 28 (Tinker). |
| `rexxar-reference/ca-dbc/DBFilesClient_CharacterAdvancementClassTypes.dbc` | 46 rows. Col 2 = required class byte, 3/4/5 = classic/custom/reborn group. |
| `server-ascension/Data/dbc/ChrClasses.dbc` | 32 rows where vanilla has 10; 12..32 are the CoA classes. Name at field 4. |
| `realms/ascension/builds.json` | Stored builds for `0x5C2` (tabled track). |
| `rexxar-reference/ca-dbc-export/entries.csv` | 10,255 CA entries. `SpellID` is the Track A join key. Read `SCHEMA.md` first. |
| `rexxar-reference/ca-dbc-export/edges.json` | 5,597 **directed** prerequisite edges (edge -> prerequisite). |
| `rexxar-reference/ca-dbc-export/classes.json`, `tabs.json` | The 42 CA classes and their tabs. |
| `rexxar-reference/ca-lua-bindings.txt` | `LearnID`, `CanLearnID`, `UnlearnID`, and friends, with addresses. |
| `rexxar-reference/opcode-handlers.txt` | Opcode -> handler -> registration site. |
| `server-ascension/Data/dbc/Spell.dbc` | Ascension's 209,509-record spell table. **Not** `server/Data/dbc/`. |
| `tools/disx.py`, `annot.py`, `opcmap.py`, `luabind.py`, `findfn.py` | Static RE (capstone). `disx` is importable. |
| `HANDOFF-ARCHIVE-SESSION.md` | Deep reference for everything already solved. §4.12 = the archetype protocol (no longer tabled — see §10.4). |
---

## 10. Backlog — work top to bottom, do not stop between items

Tracks A, B and C are complete (§0.1). This is everything known to be left, ordered so that
the cheap certain wins land before the open-ended one. Read §0.0 before starting.

### 10.1 `CMSG_SET_ACTION_BUTTON` (0x128) — DONE

Handled, persisted to `actionbars.json`, verified across two restarts. Details, the
measured wire format and the burst-timing trap are in §0.1.

### 10.2 `CMSG_BUILD_QUERY_CATEGORY` (0x62E) - DONE, but the *name* was wrong

Filed here originally as `CMSG_GAME_MODE_QUERY`. Everything §0.1 measured stands and the
empty record set really was the correct answer at the time - but the opcode carries a
**BuildCategory name string** (the 11-byte body was `"BuildDraft" + NUL`), and once
`builds.json` had records the very same opcode returned 56 of them and the client rendered
them as rows (§10.5). It was right for the wrong reason. The finding that came out of it
still holds: the Archetypes tab is gated on `C_Player:IsHero()`, not on game modes.

### 10.3 Spell effects — THE BIG ONE. Stage it; do not try to land it whole.

This is Track A's honest limit (§0.1): `SMSG_SPELL_GO` ends the cast, starts the GCD and
plays the visual, and **nothing else happens**. No power spent, no damage, no healing, no
aura. `server-ascension/Data/dbc/Spell.dbc` has 209,509 records and carries the effect
columns; the archive has no engine to read them.

Do it in this order, each stage verified live before the next:

- **(a) Power cost — DONE**, see §0.1. Costs come from `ManaCost` + `ManaCostPercentage`,
  and the client only believes its own power bar if you also send `SMSG_POWER_UPDATE` (0x480).
- **(b) Direct damage and healing — DONE**, see §10.3(b). Damage and healing both move real
  health and both reach the combat log. One honest deviation from the criterion below: the
  damage spell is **Scorch (81226), a Mage entry**, because *no* Tinker damage spell is castable
  on this client — Bomb Toss carries `SPELL_ATTR0_USES_RANGED_SLOT` and zero of the 10255 CA
  entries are Tinker-and-castable. Read §10.3(b) before trying to "fix" that.
- **(c) Auras — DONE**, see §10.3(c). Buffs and debuffs both apply, tick, count down,
  refresh in place, cancel on right-click and fall off on time; `SMSG_AURA_UPDATE` is 0x496 and
  removal is that same packet with `spellId = 0`. The honest limit is that only the *periodic*
  aura families do anything mechanically — stat mods, stuns, roots and absorbs are shown and
  timed correctly but are inert, because this archive has no stats, movement authority or
  damage pipeline for them to touch. Two more `Spell.dbc` columns were measured on the way
  (`DurationIndex` 40, `EffectAmplitude` 98), and column **24 `casterAuraSpell`** is the gate
  that will silently refuse a test spell client-side.

All three stages landed. §10.3 is **DONE**. Anything further here — triggered spells
(effect 64), threat, resistances, crit — is new scope, not the remainder of this item; open a
new backlog entry for it rather than reopening this one.

### 10.4 Archetypes / Build Creator — DONE

The criterion is met and verified live: the Hero Architect lists builds, a build renders in
full, and activating one learns its entries and flips the UI to "Deactivate Build". The four
silent client-side traps that made this hard — the class byte at `record+0x60`, the doubled
icon path, the role-less `SetBackground` crash and the missing `0x632` with its index-base
mismatch — are written up in §0.1 and, symptom-first, in `TROUBLESHOOTING.md`.

Anything further here (publishing builds, the build *editor*, drafts) is new scope. Open a
new entry rather than reopening this one.

### 10.5 Character creation as a custom class — **DONE**

Closed 2026-09-02 with the maintainer's go-ahead to install the driver. A character (`Testgamma`,
guid 3) was created through the client's own creation screen as archetype 19 *Blade Warden*
and learned that archetype's four entries on first login. Full write-up, the four
non-obvious traps and the enumerated archetype tree are in §0.1 under "10.5".

The driver is installed but **disarmed** (`ASCENSION_ARCHIVE_CHARCREATE = nil`) and must
stay that way — `AccountLogin.lua` is on the junction into the live install.

---

