#!/usr/bin/env python3
r"""Export Ascension's authentic Character-Advancement dataset from the client DBCs.

This supersedes rexxar-reference/ca-export/ (built from the wrong dataset) and
Data\Content\CharacterAdvancementData.json (a UI-side companion file, not what
the engine loads).  The engine's dataset is DBFilesClient\CharacterAdvancement.dbc
inside patch-M.MPQ -- 10255 records, which is exactly the count the live client's
C_CharacterAdvancement.GetAllEntries() returned, so this file IS the entry table.

Schema recovery
---------------
Ascension ships no .dbd and the client has no format string (both binaries were
searched); the loader is a template with a per-type GetFileName() thunk at
0x101c5d50, so the column list was recovered empirically instead:

  * record stride is 692 = 173 dwords.  The header's field_count of 179 is
    loader metadata and is NOT the on-disk stride -- trust record_size.
  * a column is a string column iff every value indexes the string block at a
    string start.  Offset 27 is the canonical empty string (there is a double
    NUL after 'Purify'), which is why whole columns read as 27.
  * ID / Name / Icon / SpellID were then confirmed against known-good facts:
    spell 10 -> 'Blizzard' / 'Spell_Frost_IceStorm', 133 -> 'Fireball' /
    'Spell_Fire_FlameBolt', 2136 -> 'Fire Blast' / 'Spell_Fire_Fireball'.

The tree geometry is NOT on a dword boundary
--------------------------------------------
PositionX / PositionY / SizeX / SizeY are four little-endian floats at byte
offset 0x18E of the record -- offset 2 mod 4.  Reading the record purely as
173 dwords straddles them and yields nonsense like 0x00004280 (the high half of
64.0f sitting in a dword's low half), which is what makes this block easy to
miss.  A dword-only sweep for a grid-shaped column pair finds nothing.

Read correctly they are a clean grid: PositionX 0..10, PositionY 0..9, over
3618 entries, ~85% distinct cells per (class,tab) tree (the rest are stacked
multi-rank nodes).  Only the custom hero-class trees are positioned -- base
classes like Mage/Arcane have none, because those are browsed, not laid out.

entry.Row / entry.Column (read by CAGate.lua and CharacterAdvancement.lua:2030,
sourced by the engine's entry->Lua builder at 0x1016cba2/0x1016cbcf from
entry+0x98 / entry+0x9c) are the engine's own integer view of this same
geometry.  Export the floats; do not invent Row/Column.

    python ca_export.py [outdir]
"""
import csv
import json
import os
import struct
import sys

POSITION_BLOCK = 0x18E   # PositionX, PositionY, SizeX, SizeY -- four LE floats

DBC_DIR = r"C:\AzerothRealm\realms\ascension\rexxar-reference\ca-dbc"
OUT_DIR = r"C:\AzerothRealm\realms\ascension\rexxar-reference\ca-dbc-export"

# column index -> exported field name.  Only columns whose meaning is evidenced
# are named; everything else is emitted as col_NNN so nothing is fabricated.
COLUMNS = {
    0:   ("ID", "int"),
    1:   ("Type", "str"),          # Talent / Ability / TalentAbility / None
    5:   ("SpellID", "int"),       # rank 1; 6..9 are the rest of the rank chain
    6:   ("SpellID2", "int"),
    7:   ("SpellID3", "int"),
    8:   ("SpellID4", "int"),
    9:   ("SpellID5", "int"),
    16:  ("Quality1", "str"),
    20:  ("Quality2", "str"),
    24:  ("Quality3", "str"),
    26:  ("Cost1", "int"),
    27:  ("Cost2", "int"),
    28:  ("Cost3", "int"),
    32:  ("ClassType", "fk_class"),
    33:  ("TabType", "fk_tab"),
    47:  ("Name", "str"),
    64:  ("Icon", "str"),
    65:  ("Description", "str"),
    82:  ("Description2", "str"),
    151: ("Anchor", "str"),        # TOP / LEFT / TOPLEFT / BOTTOMLEFT
    152: ("Color", "str"),         # TEAL / GREEN / ORANGE
    153: ("NodeType", "str"),      # SpendSquare / SpendCircle / SpendHex
}

# columns that are entirely zero or entirely the empty string across all records
# are dropped from the raw passthrough -- they carry nothing.
def load(path):
    d = open(path, "rb").read()
    assert d[:4] == b"WDBC", "%s is not a WDBC" % path
    rc, fc, rs, ss = struct.unpack_from("<IIII", d, 4)
    ncol = rs // 4
    sb = 20 + rc * rs
    blk = d[sb:sb + ss]

    def s(v):
        if v >= ss:
            return None
        e = blk.index(b"\x00", v)
        return blk[v:e].decode("utf-8", "replace")

    recs = [struct.unpack_from("<%dI" % ncol, d, 20 + i * rs) for i in range(rc)]
    raws = [d[20 + i * rs: 20 + (i + 1) * rs] for i in range(rc)]
    return recs, s, ncol, raws


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else OUT_DIR
    os.makedirs(out, exist_ok=True)

    ca, cas, ncol, caraw = load(os.path.join(DBC_DIR, "DBFilesClient_CharacterAdvancement.dbc"))
    cl, cls, _, _ = load(os.path.join(DBC_DIR, "DBFilesClient_CharacterAdvancementClassTypes.dbc"))
    tb, tbs, _, _ = load(os.path.join(DBC_DIR, "DBFilesClient_CharacterAdvancementTabTypes.dbc"))
    cg, cgs, _, _ = load(os.path.join(DBC_DIR, "DBFilesClient_CharacterAdvancementCategories.dbc"))

    # ClassTypes: [0]=id [1]=DBC token (what GetEntriesByClass takes) [6]=display
    classes = {r[0]: {"ID": r[0], "Name": cls(r[1]), "Display": cls(r[6])} for r in cl}
    # TabTypes: [0]=id [1]=DBC token [2]=display
    tabs = {r[0]: {"ID": r[0], "Name": tbs(r[1]), "Display": tbs(r[2])} for r in tb}
    cats = [{"ID": r[0], "SortA": r[1], "SortB": r[2],
             "Icon": cgs(r[4]), "Name": cgs(r[5]), "Description": cgs(r[22])} for r in cg]

    # which raw columns are worth keeping
    dead = set()
    for c in range(ncol):
        vals = set(r[c] for r in ca)
        if vals <= {0} or (len(vals) == 1 and cas(next(iter(vals))) == ""):
            dead.add(c)

    entries = []
    for r, rawrec in zip(ca, caraw):
        e = {}
        for c, (name, kind) in sorted(COLUMNS.items()):
            v = r[c]
            if kind == "str":
                e[name] = cas(v)
            elif kind == "fk_class":
                e[name] = classes.get(v, {}).get("Name")
                e["ClassTypeID"] = v
            elif kind == "fk_tab":
                e[name] = tabs.get(v, {}).get("Name")
                e["TabTypeID"] = v
            else:
                e[name] = v
        # The four floats at byte offset 0x18E are NOT dword-aligned -- see
        # POSITION_BLOCK in the module docstring.  They are the tree geometry.
        px, py, sx, sy = struct.unpack_from("<ffff", rawrec, POSITION_BLOCK)
        e["PositionX"], e["PositionY"] = px, py
        e["SizeX"], e["SizeY"] = sx, sy
        raw = {}
        for c in range(ncol):
            if c in COLUMNS or c in dead:
                continue
            raw["col_%03d" % c] = r[c]
        e["_raw"] = raw
        entries.append(e)

    with open(os.path.join(out, "entries.json"), "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=1, ensure_ascii=False)
    for name, obj in (("classes.json", list(classes.values())),
                      ("tabs.json", list(tabs.values())),
                      ("categories.json", cats)):
        with open(os.path.join(out, name), "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=1, ensure_ascii=False)

    flat = [k for k in entries[0] if k != "_raw"]
    with open(os.path.join(out, "entries.csv"), "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=flat, extrasaction="ignore")
        w.writeheader()
        for e in entries:
            w.writerow(e)

    print("wrote %d entries, %d classes, %d tabs, %d categories -> %s"
          % (len(entries), len(classes), len(tabs), len(cats), out))
    print("named columns: %d, raw passthrough: %d, dropped as empty: %d"
          % (len(COLUMNS), ncol - len(COLUMNS) - len(dead), len(dead)))


if __name__ == "__main__":
    main()
