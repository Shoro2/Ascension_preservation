#!/usr/bin/env python3
"""Profile a WDBC file column-by-column so an unknown Ascension schema can be
recovered without a .dbd.

Ascension's CharacterAdvancement.dbc has 179 in its field_count but a 692-byte
record (= 173 dwords); the field count is loader metadata, not the on-disk
stride, so everything here works off record_size // 4.

A column is called a string column when EVERY value is a valid string-block
offset that starts a string (offset 0, or the preceding byte is NUL).  That test
is strong: a numeric column of small ints fails it as soon as one value lands
mid-string.

    python dbcprof.py <file.dbc> [--col N] [--max-distinct N]
"""
import struct
import sys
from collections import Counter


def load(path):
    d = open(path, "rb").read()
    assert d[:4] == b"WDBC", "not a WDBC"
    rc, fc, rs, ss = struct.unpack_from("<IIII", d, 4)
    base = 20
    sb = base + rc * rs
    return d, rc, fc, rs, ss, base, sb


def main():
    path = sys.argv[1]
    only = None
    maxd = 12
    for i, a in enumerate(sys.argv):
        if a == "--col":
            only = int(sys.argv[i + 1])
        if a == "--max-distinct":
            maxd = int(sys.argv[i + 1])

    d, rc, fc, rs, ss, base, sb = load(path)
    ncol = rs // 4
    print("%s: %d records, %d cols (recsz %d, field_count %d), strblk %d" %
          (path, rc, ncol, rs, fc, ss))

    strblk = d[sb:sb + ss]

    def isstr(v):
        if v >= ss:
            return False
        if v == 0:
            return True
        return strblk[v - 1] == 0

    def gets(v):
        e = strblk.index(b"\x00", v)
        return strblk[v:e].decode("utf-8", "replace")

    cols = [[] for _ in range(ncol)]
    for r in range(rc):
        off = base + r * rs
        vals = struct.unpack_from("<%dI" % ncol, d, off)
        for c in range(ncol):
            cols[c].append(vals[c])

    for c in range(ncol):
        if only is not None and c != only:
            continue
        v = cols[c]
        uniq = set(v)
        nz = sum(1 for x in v if x)
        allstr = all(isstr(x) for x in v)
        # float plausibility: every nonzero value decodes to a sane magnitude
        fl = [struct.unpack("<f", struct.pack("<I", x))[0] for x in v if x]
        isf = bool(fl) and all(1e-6 < abs(f) < 1e9 for f in fl)
        kind = "STR " if allstr else ("flt?" if isf else "int ")
        mn, mx = min(v), max(v)
        head = "  [%3d] +0x%03x %s uniq=%-6d nz=%-6d min=%-10d max=%-12d" % (
            c, c * 4, kind, len(uniq), nz, mn, mx)
        if allstr:
            svals = Counter(gets(x) for x in v)
            top = svals.most_common(maxd)
            head += " | " + ", ".join("%r x%d" % (k, n) for k, n in top)
        elif len(uniq) <= maxd:
            top = Counter(v).most_common(maxd)
            head += " | " + ", ".join("%d x%d" % (k, n) for k, n in top)
        elif isf:
            head += " | f: %g .. %g" % (min(fl), max(fl))
        print(head)


if __name__ == "__main__":
    main()
