# Known issues

Symptom-first index of failures that look like protocol or server bugs but are
not. Both bridge crashes below are **fixed in this repository**; they are
recorded because the evidence each one leaves behind points at the wrong
component, and because anyone who forked `server/ascension_bridge.py` before
2026-09-09 still has them.

## Why a bridge exception looks like a server bug

`ascension_bridge.py` runs two pumps: client→core on the main thread, core→client
on a daemon thread. **Only the socket reads are wrapped in `try/except`.** Anything
else that raises — including a logging call — unwinds that pump and ends that
direction of traffic for the rest of the session.

Nothing closes the socket, so the client is not disconnected. It simply stops
receiving (or stops being heard). That reads as *"the server never replied"*, and
sends you looking at the core, the DBCs, or the wire format. Check the bridge
first: if a pump thread died, the last thing in the log is the packet it died on
— or, when it died **inside** the log call, that packet is missing entirely.

---

## 1. "Creating character" hangs forever — but the character IS created

**Symptom.** Character creation spins on *Creating character* and never returns.
Cancel, reconnect, and the character is sitting at character-select. The bridge
log shows `CMSG_CHAR_CREATE`, then the new character's `SMSG_TALENTS_INFO` and
its `SMSG_SET_PROFICIENCY` burst, then nothing at all.

**Wrong conclusion.** "The core creates the row but never sends the
`SMSG_CHAR_CREATE` success ack." The packet burst that precedes the silence makes
this very convincing.

**Actual cause.** The core→client pump logged the reply with `opname(opcode)`,
but the helper is `def opname(op, c2s)` — the direction argument is required. The
missing argument raised `TypeError` the instant `SMSG_CHAR_CREATE` arrived. That
log call sits *outside* the `read_s2c` `try/except`, so the pump thread died
**before** forwarding the packet at `send_client`, taking every later S→C packet
with it. The core had already written the character row and had already sent the
ack.

**The misleading part.** The crash happens *inside the log call for
`SMSG_CHAR_CREATE` itself*, so that line never prints. The absence of the line is
the crash — not a missing packet.

**Fix.** Pass the direction: `opname(opcode, False)`.

## 2. Instant disconnect on entering the world, on non-ASCII text

**Symptom.** The session drops the moment anything non-ASCII reaches the log — a
character name, or a line of chat (`describe_chat` logs chat in full).

**Actual cause.** `log()` wrote the log *file* as UTF-8, but printed to stdout
unguarded, and the `try/except` covered only the file write. A Windows console
defaults to the ANSI code page (cp1252), so one non-ASCII byte raises
`UnicodeEncodeError` inside `log()` — on a pump thread.

**Fix.** Reconfigure `stdout`/`stderr` to UTF-8 with `errors="replace"` at import,
plus an ASCII-replace fallback inside `log()`, so a logging call can never take
down a session.

**General rule.** `log()` must never raise. It is called from both pumps.

---

## 3. Character creation rolls back in the database (not a bridge issue)

*First reported by a downstream adopter of this bridge. Recorded here because it
produces the same "soft-lock on creating character" symptom as issue 1 above and
the two are easy to confuse — and because this archive **is** exposed to it, by
a route that a naive check reports as safe.*

Ascension's `Achievement.dbc` / `Achievement_Criteria.dbc` contain IDs far above
65535. AzerothCore binds those as `uint32`, but the stock character-table columns
are 16-bit:

```
character_achievement           PRIMARY KEY (guid, achievement)   achievement smallint unsigned
character_achievement_progress  PRIMARY KEY (guid, criteria)      criteria    smallint unsigned
```

Under non-strict `sql_mode` MySQL **clamps** an oversized id to 65535 instead of
erroring. Two different high IDs therefore become the same row key, collide on
the primary key, and roll the transaction back.

The tell that distinguishes it from issue 1: here the character is **not**
created, so it is absent at character-select. In issue 1 the character exists.

### Measure the right DBC set

Field 0 of a WDBC record is the ID, and records start at byte 20:

```python
import struct
with open("Achievement.dbc", "rb") as f:
    magic, n, fields, recsize, sbs = struct.unpack("<4sIIII", f.read(20))
    data = f.read(n * recsize)
ids = [struct.unpack_from("<I", data, i * recsize)[0] for i in range(n)]
print(len(ids), max(ids), sum(1 for i in ids if i > 65535))
```

**Which file you point that at is the whole question, and the two obvious
choices disagree.** In this archive:

| DBC set | `Achievement.dbc` | ids > 65535 |
|---|---|---|
| the server's `DataDir` (`server/Data/dbc`) | 1,817 rows, max 4,824 | **0** |
| the Ascension set (`server-ascension/Data/dbc`) | 22,603 rows, max 322,523 | **7,408** |

Both numbers are real. The bridge worldserver is deliberately pointed at the
*vanilla* DBCs — that is what the bridge translates onto — so achievements
**earned in-game here** cannot exceed 4,824 and the `CMSG_CHAR_CREATE` path is
genuinely safe. Checking `DataDir` and stopping there reports "not exposed".

That is the trap, and the principle underneath it is worth stating exactly:

> **A DBC bounds the IDs the core writes. It says nothing about IDs arriving
> from outside.**

The column has to hold every ID that will ever be written to it, not just the
ones this server generates. Imported or restored characters carry the IDs of
the service they were captured from — the 322,523 set — and the high ones are
ordinary named rows (70001 `Unlocked Tier 6 Chest Vendor`, 70002 `Unlocked
Tier 6 Leg Vendor`, …), not padding. So measure the DBC set that produced
**the data you intend to store**, which for any import is the source's set and
not your `DataDir`.

### Find the config the server is actually running

Answering "which set is mine" means finding which config the worldserver was
started with — and a config located by convention is not necessarily that one.
Auto-discovery that matches on filename (`worldserver.conf`) and on a `configs/`
or `etc/` directory will not find a config named or placed differently. In this
archive the bridge realm runs `worldserver-bridge.conf` from the realm
directory, which fails both tests; discovery instead finds the unused
`server-ascension/configs/worldserver.conf`, which carries **the same three
DSNs** and a **different `DataDir`**.

That combination is the dangerous one. Every database check passes, so the
config looks confirmed, while every DBC-derived answer is quietly computed
against the wrong tree.

Ask the running process for its own `-c` instead of guessing:

```powershell
Get-CimInstance Win32_Process -Filter "Name='worldserver.exe'" |
    Select-Object ProcessId, CommandLine
```

```sh
tr '\0' ' ' < /proc/<pid>/cmdline
```

And treat a candidate config that agrees on the DSNs but disagrees on `DataDir`
as a hard failure rather than a usable fallback — matching DSNs are what makes
the wrong config convincing.

### Verdict for this archive

`asc_characters` **is** exposed and should be widened. It has not bitten yet
only because `character_achievement` is still empty — it needs a genuinely
progressed imported character.

```sql
ALTER TABLE <characters_db>.character_achievement
    MODIFY `achievement` INT UNSIGNED NOT NULL;
ALTER TABLE <characters_db>.character_achievement_progress
    MODIFY `criteria`    INT UNSIGNED NOT NULL;
```

Confirm the mode you are actually running under first — with
`STRICT_TRANS_TABLES` you would get a real error instead of a silent clamp:

```sql
SELECT @@SESSION.sql_mode;
```

And confirm the current column widths before and after:

```sql
SELECT TABLE_NAME, COLUMN_NAME, COLUMN_TYPE
  FROM information_schema.COLUMNS
 WHERE TABLE_SCHEMA = '<characters_db>'
   AND ((TABLE_NAME = 'character_achievement_progress' AND COLUMN_NAME = 'criteria')
     OR (TABLE_NAME = 'character_achievement'          AND COLUMN_NAME = 'achievement'));
```

After any manual character-table surgery, purge orphaned `character_*` rows —
reused GUIDs collide with leftover sub-table rows.

---

## 4. The general form: non-strict MySQL never tells you it lost your data

Issue 3 is one instance of a class worth stating on its own, because AzerothCore
ships `sql_mode` without `STRICT_TRANS_TABLES`:

- an integer wider than its column is **clamped to the column maximum**
- a string longer than its column is **truncated**

Both succeed. No error, no exception, no log line. You find out later, as a
primary-key collision, a mismatched lookup, or a value that is quietly wrong.

The narrow columns are not exotic — a stock `item_template` alone has dozens of
sub-`INT` columns. Any code path that writes an id it did not itself generate
(client-supplied, imported, or scraped from another realm's data) should check
that the value fits **before** writing, and name the column and the limit when
it does not. `information_schema.COLUMNS` has what you need, with one catch
worth knowing: the unsigned flag appears only in `COLUMN_TYPE`, never in
`DATA_TYPE`, so a range check built on `DATA_TYPE` alone silently gets the
bounds wrong.

Check your mode first — if it comes back with `STRICT_TRANS_TABLES`, none of
this applies and you get a real error instead:

```sql
SELECT @@SESSION.sql_mode;
```

---

## 5. Ascension's DBC string blocks have no leading NUL

**Symptom.** A DBC reader that works perfectly on stock 3.3.5a returns an empty
string for one row per file. Nothing errors.

**Cause.** A WDBC string block conventionally opens with a NUL, so offset 0 is
the empty string and the first real string starts at offset 1. Ascension's
files do not — they put a real string at offset 0 and follow it with a doubled
NUL:

```
stock      AreaTable.dbc   \x00Dun Morogh\x00Longshore...
ascension  AreaTable.dbc   Dun Morogh\x00\x00Longshore...
                           ^ first real string at offset 0
```

Verified from the bytes on all seven files checked — `AreaTable`, `Achievement`,
`Spell`, `BattlemasterList`, `ChrClasses`, `SkillLine`, `ItemDisplayInfo`.

**Fix.** Do not special-case offset 0. Read from the offset to the next NUL and
let offset 0 return a real string. Treat "empty" as a genuine value only when
the byte at that offset actually is NUL.

### Two things this does *not* imply

Both were published here on 2026-09-09 and both are wrong. They are kept
because each is an easy inference from the layout above, and because the second
one will send you chasing the wrong bug.

**It does not mean later offsets are unchanged.** The relocation preserves the
block *length* only when the first string is the same length in both builds,
and Ascension rewrote most of these files:

| file | stock 1st string | Ascension 1st string | 2nd string offset |
|---|---|---|---|
| `AreaTable` | `Dun Morogh` | `Dun Morogh` | 12 / 12 — aligned |
| `BattlemasterList` | `Alterac Valley` | `Alterac Valley` | 16 / 16 — aligned |
| `Achievement` | `Level 10` | `Son of a...` | 10 / **13** |
| `Spell` | `Word of Recall (OLD)` | `UPDATE YOUR CLIENT!` | 22 / **21** |
| `ChrClasses` | `PET` | `Warrior` | 5 / **9** |
| `SkillLine` | `Frost` | `Pet - Pit Lord` | 7 / **16** |
| `ItemDisplayInfo` | `INV_Robe_02` | `Polearm_2H_Bladed_D_03` | 13 / **28** |

Alignment is a property of identical content, not of the writer. The original
claim here was drawn from `AreaTable` and `BattlemasterList` — which are
precisely the two files where Ascension kept stock's first string. **Sampling
two files that happen to open with the same string will fake the general rule.**
Never diff string blocks positionally across builds; resolve every offset.

**It does not produce strings missing their first character.** The natural
guess is that a row still pointing at offset 1 now reads one character short —
`Dun Morogh` as `un Morogh`. Ascension's rows do not do this. Dumped raw, they
store **0** and are self-consistent: `AreaTable` id 1 → offset 0 → `Dun
Morogh`; `ChrClasses` id 1 → offset 0 → `Warrior`.

One-character-short strings come from reading a **numeric column as a string
offset**. A field holding the small constant 1 decodes as the first string
minus its first byte, which looks exactly like a subtly corrupted name. In
`AreaTable` the `un Morogh` that prompted the original claim came from field 0
— the record ID.

> The tell is that the value is identical on every row. A name column never is.

Count distinct values down the column before believing a string field: in
Ascension's `ChrClasses` the real name column has 32 distinct values across 32
rows, while the fields that decode one character short have 2 and 5.

**So the NUL artifact is not what fakes "RENUMBERED" verdicts.** It can only
blank the single row that points at offset 0 — one row per file. A whole audit
column coming back wrong is a misidentified field, and the field layout is
where to look.

**Not affected:** anything reading numeric fields *at a known offset*. The ID
check in issue 3 above reads field 0 as a `uint32` and never touches the string
block, so its results stand regardless.
