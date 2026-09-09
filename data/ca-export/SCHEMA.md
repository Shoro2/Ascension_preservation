# CharacterAdvancement.dbc — recovered schema

Source: `patch-M.MPQ` → `DBFilesClient\CharacterAdvancement.dbc`
(extracted with `wowunreal\tools\mpqcat.exe`; raw copies in `../ca-dbc/`).

**This is the engine's real CoA dataset.** It has **10255 records**, exactly the
count the live client's `C_CharacterAdvancement.GetAllEntries()` returned. It
supersedes:

- `rexxar-reference\ca-export\` — built from the wrong dataset, do not use.
- `client-ascension\Data\Content\CharacterAdvancementData.json` — a UI-side
  companion file, **not** what the engine loads. (It happens to agree on Name
  and Icon, which is what makes it a useful cross-check — see below.)

## File shape

| header field  | value  | note |
|---------------|--------|------|
| magic         | `WDBC` | plain WotLK DBC, no Ascension container |
| record_count  | 10255  | |
| field_count   | 179    | **loader metadata — not the stride** |
| record_size   | 692    | = 173 dwords; this is the real column count |
| string_block  | 231383 | offset **27** is the canonical empty string |

Trusting `field_count` over `record_size` is the trap here: the two disagree and
only `record_size` describes the bytes on disk. The empty-string quirk is the
second trap — there is a double NUL after `Purify`, so unused string columns all
read as the literal 27, not 0. Offset 0 is `"Ability"`, so a zeroed string column
decodes as `"Ability"` and looks meaningful when it is not.

## How the schema was recovered

Ascension ships no `.dbd`, and neither `Extensions.dll` nor `Ascension.exe`
contains a DBC format string (both were swept for runs of `[nixsfbdlgu]`). The
loader is a template with a per-type `GetFileName()` thunk at `0x101c5d50`
(`mov eax, "DBFilesClient\CharacterAdvancement.dbc"; ret`), so there is no
column list to read. Columns were therefore identified empirically:

1. **String columns** — a column is a string column iff *every* value indexes the
   string block at a string start (offset 0, or preceded by NUL). One value
   landing mid-string disqualifies the column, which kills false positives from
   small-int columns.
2. **FK columns** — `[32]` has range 1..45 against a 46-record ClassTypes table
   and `[33]` has range 0..94 against a 94-record TabTypes table.
3. **Independent confirmation** — resolved entries were checked against
   known-good WotLK spell data:
   - ID 102 → spell **1152** = Purify, Paladin/Holy, icon `Spell_Holy_Purify`
   - ID 306 → spell **22568** = Ferocious Bite, Druid/Feral
   - spell **10** → `Blizzard` / `Spell_Frost_IceStorm` (agrees with the JSON)
   - spell **133** → `Fireball` / `Spell_Fire_FlameBolt`

## Named columns

| col | field | evidence |
|-----|-------|----------|
| 0 | `ID` | unique across all 10255 records |
| 1 | `Type` | `Talent` 6187 / `Ability` 3664 / `TalentAbility` 399 / `None` 5 — matches the `FILTER_TYPE_*` enum in `.rdata` |
| 5 | `SpellID` | nonzero on every record; validated against real spell IDs |
| 6–9 | `SpellID2..5` | rank chain — observed as consecutive IDs (1571657..1571660) |
| 16, 20, 24 | `Quality1..3` | `Normal`/`Poor`/`Uncommon`/`Rare`/`Epic`/`Legendary`/`Artifact` — matches `FILTER_QUALITY_*` |
| 26, 27, 28 | `Cost1..3` | 0..80, correlates loosely with quality; AE/TE essence cost, exact split unproven |
| 32 | `ClassType` | FK → `CharacterAdvancementClassTypes[0]`; `[1]` is the token `GetEntriesByClass` takes |
| 33 | `TabType` | FK → `CharacterAdvancementTabTypes[0]` |
| 47 | `Name` | 6685 distinct; cross-validated |
| 64 | `Icon` | 4472 distinct, `Interface\Icons\` basename; cross-validated |
| 65, 82 | `Description`, `Description2` | populated on only ~100 records |
| 151 | `Anchor` | `TOP` 10241 / `LEFT` 10 / `BOTTOMLEFT` 2 / `TOPLEFT` 2 |
| 152 | `Color` | `TEAL` 10252 / `GREEN` 2 / `ORANGE` 1 |
| 153 | `NodeType` | `SpendSquare` 7409 / `SpendCircle` 2841 / `SpendHex` 5 |
| *byte 0x18E* | `PositionX`,`PositionY`,`SizeX`,`SizeY` | four floats, **not dword-aligned** — see below |

93 further columns are entirely zero or entirely empty and are dropped. The
remaining 58 are emitted verbatim as `col_NNN` under `_raw` — named nothing,
invented nothing.

## The tree geometry is NOT on a dword boundary

`PositionX`, `PositionY`, `SizeX`, `SizeY` are four little-endian **floats at
byte offset `0x18E`** of the record — offset **2 mod 4**. Reading the record as
173 dwords straddles them and produces nonsense like `0x00004280` (the high half
of `64.0f` stranded in a dword's low half). A dword-only sweep for a grid-shaped
column pair finds nothing, which is exactly how this block gets missed.

Read at the right offset they are a clean grid:

| field | offset | range |
|-------|--------|-------|
| `PositionX` | `0x18E` | 0 .. 10 |
| `PositionY` | `0x192` | 0 .. 9 |
| `SizeX` | `0x196` | 64.0 (px) on 2495 entries, 1.0 (grid span) on 991 |
| `SizeY` | `0x19A` | as above |

**3716 entries carry a position**, and within a `(class,tab)` tree ~85% of cells
are distinct — the rest are legitimately stacked multi-rank nodes. Only the
**custom hero-class trees are positioned**: Tinker, Primalist, Guardian, Ranger,
SonOfArugal, WitchDoctor, Barbarian, DemonHunter … Base classes such as
`Mage/Arcane` have no positions at all, because the base ability pool is
*browsed*, not laid out. That asymmetry is a feature of the dataset, not a gap.

Spot-check of `Tinker/Mechanics` straight out of `entries.csv`:

```
(1,2) Sprocket Loaded          (2,1) Mechsuit: Laser Beam
(1,4) Mechsuit: Activate Jets  (2,5) Overload
(1,7) Arclight Adept          (10,0) Build: Mechsuit
```

`entry.Row` / `entry.Column` — read by `Templates\CAGate.lua:297,369` and
`CharacterAdvancement.lua:2030`, and sourced by the engine's entry→Lua builder
from `entry+0x98` / `entry+0x9c`:

```
0x1016cba2  push 0x10b34a50      ; "Column"
0x1016cbb1  mov  ecx,[eax+0x98]  ; entry->Column
0x1016cbcf  push 0x10b34a58      ; "Row"
0x1016cbde  mov  ecx,[eax+0x9c]  ; entry->Row
```

— are the engine's integer view of this same geometry. **Export the floats; do
not invent Row/Column.**

## Entry-ID reference columns (role unproven)

Several dword columns hold values that are 100% valid entry IDs, but sparsely:
`[2]` (314), `[131]` (206), `[132]` (106), `[133]` (86), `[154]` (275), plus
`[134..144]` with single digits each. Only 50–74% of those references stay
inside the referring entry's own `(class,tab)`, so they are prerequisite links
(`RequiredIDs`) rather than the dense in-tree `ConnectedNodes` edge list. The
edge list is not identified — it is likely inside the sub-dword packed region
between `0x188` and `0x25B`, which is not fully mapped. These columns are left
in `_raw` and named nothing.

## Companion tables (also in `../ca-dbc/`)

| file | records | shape |
|------|---------|-------|
| `CharacterAdvancementClassTypes.dbc` | 46 | `[0]`=ID `[1]`=token `[6]`=display |
| `CharacterAdvancementTabTypes.dbc` | 94 | `[0]`=ID `[1]`=token `[2]`=display |
| `CharacterAdvancementCategories.dbc` | 51 | `[0]`=ID `[4]`=icon `[5]`=name `[22]`=description |
| `CharacterAdvancementEssence.dbc` | 5600 | 9 int cols, no strings |
| `ChrSpecs.dbc` / `ChrClassesRoles.dbc` | — | spec + role tables for `C_ClassInfo` |
| `SpellTags.dbc` / `SpellTagTypes.dbc` | — | the browser's tag filter (`patch-S.MPQ`) |

## `edges.json` — the tree's edge graph (NOT from a DBC)

`{ "<entryId>": [entryId, ...] }`, 3517 keys / 5597 edges / max degree 5.

This one is **not** produced by `ca_export.py` and cannot be: `ConnectedNodes`
is not a fixed column anywhere in `CharacterAdvancement.dbc`. The engine parses
it out of the packed region into a heap vector at `entry+0xE8`, so the only way
to read it is to ask a running client. It was dumped by `CoAReader_DoEdges`
(the `edges` step of the `Ascension_CoAReader` autorun) on 2026-09-01 and
parsed out of the addon's SavedVariables.

**The edges are directed and point at PREREQUISITES**, i.e. up the tree toward
row 0. Evidence, all reproducible from these files:

- 0 of 5597 endpoints are reciprocated — it is not an adjacency list.
- every edge lands on a lower `PositionY` (delta −1 x4906, −2 x574, 0 x109,
  −4 x5) and never a higher one;
- all 280 nodes with no `ConnectedNodes` sit at `PositionY = 0`;
- the 109 zero-delta edges are all between row-0 nodes.

Use this rather than the scalar `ParentNode` column when you want the real
graph — nodes can have several parents (5116 has `ParentNode=0` and
`ConnectedNodes=[5998, 6001]`).

Invariants worth relying on: **no edge crosses a Class/Tab boundary** (0 of the
5594 resolvable edges), and max in-degree is 5.

Wart: 3 targets (`6451`, `7181`, `17567`) have no row in `entries.csv`. Drop
them on import rather than failing.

## Regenerating

```
python C:\AzerothRealm\realms\ascension\tools\ca_export.py
```

`edges.json` is the exception — it needs a client run:

```
python C:\AzerothRealm\realms\ascension\tools\edges_import.py
```

That re-parses CoAReaderDB.edges and re-checks every invariant above;
`--check` validates without writing. Re-run the `edges` probe in the client
first if the dataset changed.

`tools\dbcprof.py <file.dbc>` re-runs the column profiler on any of them.

