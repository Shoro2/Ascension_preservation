# Rexxar CA UI — visual reference

Screenshots of the Character Advancement / Conquest-of-Azeroth (CoA) hero-class menus
as rendered by the client against the **local archive emulator**, kept for fidelity
comparison while rebuilding those menus.

Referenced by: `../HANDOFF-CA-REXXAR.md`.

## How to add shots
1. Drop the `.png`/`.jpg` files into **this folder**.
2. Say what each one shows — class, tab, and anything notable.
3. Rename to the convention below and fill in the table.

**Do not add captures taken on the live Project Ascension service.** A live screenshot
carries a real account's character roster — name, level, zone, quest log, bags — and this
is a public repository. `.gitignore` excludes `live-*.png` for that reason. Shots from the
local emulator are fine; that is what everything below is.

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
| arch-001.png | — | login screen | the archive login glue, account `test` | local emulator |
| arch-002.png | — | login screen | "The information you have entered is not valid" dialog | local emulator |
| 2026-09-01-coa-panel-lvl1-locked.png | seed char, Blood Elf | **Character Advancement** | empty tree, "Choose Your Path" with nothing selected | the pre-level-10 state of the panel |
| 2026-09-01-coa-mage-arcane-lvl80.png | seed char, lvl 80 | CA → Mage → **Arcane** | left ability list populated (Conjure Water … Ritual of Refreshment) beside the rank/spend grid | rendered against the local emulator |
| 2026-09-01-coa-mage-frost-lvl80.png | seed char, lvl 80 | CA → Mage → **Frost** | Frostbolt / Frost Armor / Frost Nova … Frostfire Bolt, same grid | rendered against the local emulator |

**Note:** the CA panel is gated until level 10, so the "locked" shot above is the level-1 state
rather than a bug. The tree **geometry** for all 45 classes is exported to `./ca-export/`; the tree
**art** will come from driving `CoATalentFrame` via the `Ascension_CoAReader` addon
(`/coa show <Class>`). A true CoA-tree capture (Tinker Firearms/Invention/Mechanics, chosen-path
state) is still the most useful thing to add here.
