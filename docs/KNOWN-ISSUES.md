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

*Reported by a downstream adopter of this bridge; recorded here because it
produces the same "soft-lock on creating character" symptom as issue 1 above, and
the two are easy to confuse. Not reproduced in this archive.*

A CoA-merged `Achievement_Criteria.dbc` contains criteria IDs above 65535.
AzerothCore binds those as `uint32`, but the stock character-table columns are
16-bit, so MySQL clamps the value to 65535 → primary-key collision → the whole
`CMSG_CHAR_CREATE` transaction rolls back.

The tell that distinguishes it from issue 1: here the character is **not**
created, so it is absent at character-select. In issue 1 the character exists.

**Check the DBC before you touch the database** — it is the cheaper test, and it
answers whether you are exposed at all. Field 0 of a WDBC record is the ID:

```python
import struct
with open("Data/dbc/Achievement_Criteria.dbc", "rb") as f:
    magic, n, fields, recsize, sbs = struct.unpack("<4sIIII", f.read(20))
    data = f.read(n * recsize)
ids = [struct.unpack_from("<I", data, i * recsize)[0] for i in range(n)]
print(max(ids), sum(1 for i in ids if i > 65535))
```

The DBC set in this archive reports `13470 0` — max id 13,470 across 7,655
criteria, nothing above the ceiling — so the columns are safe here as they
stand, and the widening below is **not** needed for this archive. It becomes
necessary only if you merge in a CoA achievement set that pushes ids past
65535.

```sql
-- widen if your Achievement_Criteria.dbc carries ids > 65535
ALTER TABLE <characters_db>.character_achievement_progress
    MODIFY `criteria`    INT UNSIGNED NOT NULL;
ALTER TABLE <characters_db>.character_achievement
    MODIFY `achievement` INT UNSIGNED NOT NULL;
```

Check before changing anything:

```sql
SELECT TABLE_NAME, COLUMN_NAME, COLUMN_TYPE
  FROM information_schema.COLUMNS
 WHERE TABLE_SCHEMA = '<characters_db>'
   AND ((TABLE_NAME = 'character_achievement_progress' AND COLUMN_NAME = 'criteria')
     OR (TABLE_NAME = 'character_achievement'          AND COLUMN_NAME = 'achievement'));
```

After any manual character-table surgery, purge orphaned `character_*` rows —
reused GUIDs collide with leftover sub-table rows.
