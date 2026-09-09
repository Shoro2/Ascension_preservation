# Rexxar CA UI — visual reference

Ground-truth screenshots of the **real** Project Ascension Rexxar realm's Character
Advancement / Conquest-of-Azeroth (CoA) hero-class menus, captured for fidelity
comparison while rebuilding these menus against the local archive emulator.

Referenced by: `../HANDOFF-CA-REXXAR.md`.

## How to add shots
1. Drop the `.png`/`.jpg` files into **this folder**
   (`C:\AzerothRealm\realms\ascension\rexxar-reference\`).
2. Tell me (in chat) what each one shows — class, tab, and anything notable.
3. I'll rename them to the convention below and fill in the table.

Suggested filename convention: `NN-class-tab-note.png`
e.g. `01-tinker-overview.png`, `02-tinker-firearms-tree.png`, `03-tinker-masteries.png`.

## Most useful shots (on a Tinker character)
- [ ] CA window full-view — left class list + top tab row
- [ ] Tinker **Firearms** tree (icons + node connections)
- [ ] Tinker **Invention** tree
- [ ] Tinker **Mechanics** tree
- [ ] Tinker **Talents** tab
- [ ] Tinker **Masteries** tab
- [ ] A **chosen-path** state (not the empty "Choose Your Path")
- [ ] Right-side **Spells / Specs** panel populated
- [ ] (bonus) any second custom class for cross-check (Necromancer, Reaper, etc.)

## Catalog
| File | Class | Tab / View | What it shows | Notes |
|------|-------|-----------|---------------|-------|
| live-001-230023.png | REDACTED (CoA, Undead) | Collections → **Vanity** | Collections window chrome; bottom tab row shows **"Character Advancement" greyed-out** | LIVE realm; confirms CA tab is **locked < level 10** on a CoA class |
| live-002…005 | REDACTED | in-world / Collections | leveling progress (23:00–23:07) | LIVE realm; chrome + world, not the CoA tree |
| live-006-230725.png | REDACTED (≈lvl 4) | in-world combat | deployed **mechanical turret** (Tinker ability) vs Samuel Fipps | confirms REDACTED is a CoA class being leveled toward 10 |

**Note:** these six are the *live* leveling journey — useful for frame **chrome** and confirming the
level-10 wall, but **not** the CoA advancement tree (which is gated until 10). The actual tree
**geometry** for all 45 classes is exported to `./ca-export/`; the tree **art** will come from
driving `CoATalentFrame` via the `Ascension_CoAReader` addon (`/coa show <Class>`). A true
CoA-tree capture (Tinker Firearms/Invention/Mechanics, chosen-path state) is still the most useful
thing to add here.
