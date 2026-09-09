"""Apply AzerothCore's own DBC format strings to a dbc directory and report
every file the core would crash on.

Matching field COUNT and record SIZE is not enough - that was the check that
said the Ascension DBCs were fine, and worldserver still died inside
DBCFileLoader::Record::getString on

    ASSERT(stringOffset < file.stringSize)

A file can have exactly the right shape and still hold an integer where the
core's format says 's', which makes the core read that integer as an offset
into the string block and walk off the end.  So the hard check here is the one
the core actually asserts on: every 's' column, in every row, must land inside
the string block.

Two shape mismatches are reported as notes rather than errors, because the
core survives both:

  * fieldCount != strlen(fmt).  AutoProduceData bails, storage.Load() fails -
    and then LoadDBC calls storage.LoadFromDB(dbTable), so the world table
    supplies the data instead.  Every stock gt*.dbc is in this state on a
    healthy server; the numbers come from gtcombatratings_dbc and friends.
    Worth knowing for a foreign client: its gt values are being ignored.
  * recordSize != what the format lays out.  DBCFileLoader never checks it and
    reads every field through fieldsOffset, so it only bites if the core reads
    a field past the point where the two layouts diverge.  Stock
    PowerDisplay.dbc is like this.

Field offsets follow DBCFileLoader::Load exactly: 'b' and 'X' are one byte,
every other format character - 'd' and 'x' included - is four.

Usage:  python check-dbc-fmt.py <dbc-dir> [<dbc-dir> ...]
"""
import os, re, struct, sys

SRC = r"C:\AzerothRealm\src\src"
FMT_H = os.path.join(SRC, "server", "shared", "DataStores", "DBCfmt.h")
STORES = os.path.join(SRC, "server", "game", "DataStores", "DBCStores.cpp")


def load_formats():
    """filename -> (fmt string, world table the core falls back to)."""
    fmts = dict(re.findall(r'char constexpr (\w+)\[\]\s*=\s*"([^"]*)"',
                           open(FMT_H, encoding="utf8", errors="replace").read()))
    src = open(STORES, encoding="utf8", errors="replace").read()
    store_fmt = dict(re.findall(r'DBCStorage\s*<\s*\w+\s*>\s*(\w+)\s*\(\s*(\w+)\s*\)', src))
    out = {}
    for store, fname, table in re.findall(
            r'LOAD_DBC\(\s*(\w+)\s*,\s*"([^"]+)"\s*,\s*(?:"([^"]*)"|nullptr)', src):
        key = store_fmt.get(store)
        if key and key in fmts:
            out[fname] = (fmts[key], table or None)
    return out


def offsets(fmt):
    off, cur = [], 0
    for c in fmt:
        off.append(cur)
        cur += 1 if c in ("b", "X") else 4
    return off, cur


def check(path, fmt, table):
    """-> (errors, notes)"""
    with open(path, "rb") as f:
        blob = f.read()
    if blob[:4] != b"WDBC":
        return ["not a WDBC file"], []
    rc, fc, rs, ss = struct.unpack("<4I", blob[4:20])
    if len(fmt) != fc:
        return [], ["%d fields, format wants %d - file ignored, core reads %s"
                    % (fc, len(fmt), table or "nothing")]
    errs, notes = [], []
    off, want = offsets(fmt)
    if want != rs:
        notes.append("recordSize %d, format lays out %d bytes" % (rs, want))
    recs = blob[20:20 + rc * rs]
    if len(recs) < rc * rs:
        return ["truncated: %d record bytes, expected %d" % (len(recs), rc * rs)], notes
    for i, c in enumerate(fmt):
        if c != "s":
            continue
        nbad, worst = 0, 0
        for r in range(rc):
            v = struct.unpack_from("<I", recs, r * rs + off[i])[0]
            if v >= ss:
                nbad += 1
                worst = max(worst, v)
        if nbad:
            errs.append("column %d ('s'): %d/%d rows point outside the %d-byte "
                        "string block (largest %d)" % (i, nbad, rc, ss, worst))
    return errs, notes


def main(dirs, show_notes=False):
    formats = load_formats()
    print("%d DBC files have a format in the core" % len(formats))
    for d in dirs:
        print("\n=== %s ===" % d)
        missing, clean, broken, noted = [], 0, 0, 0
        for fname in sorted(formats):
            fmt, table = formats[fname]
            p = os.path.join(d, fname)
            if not os.path.isfile(p):
                missing.append(fname)
                continue
            errs, notes = check(p, fmt, table)
            if errs:
                broken += 1
                print("  BROKEN  %s" % fname)
                for x in errs:
                    print("      %s" % x)
            else:
                clean += 1
            if notes:
                noted += 1
                if show_notes:
                    print("  note    %-30s %s" % (fname, "; ".join(notes)))
        print("  -- %d load, %d would crash the core, %d absent, %d with notes"
              % (clean, broken, len(missing), noted))
        if missing:
            print("  absent: %s" % ", ".join(missing))


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if a != "--notes"]
    main(args or [r"C:\AzerothRealm\server-ascension\Data\dbc"],
         "--notes" in sys.argv)
