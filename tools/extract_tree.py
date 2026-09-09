#!/usr/bin/env python3
"""Pull a whole Interface subtree out of the Ascension MPQ chain by closure.

Ascension's custom archives carry no (listfile), so nothing can enumerate them.
mpqcat.exe resolves an *exact* internal path through the hash table, honouring
the client's own patch precedence -- so the only way to see the tree is to start
from a name we can spell and follow every reference out of it:

    .toc  -> one relative path per non-comment line
    .xml  -> <Script file="..."/> and <Include file="..."/>

    python extract_tree.py "Interface\\FrameXML\\FrameXML.toc" [more roots...]

Read-only with respect to the client: writes only under OUT_ROOT.
"""
import os
import re
import subprocess
import sys

MPQFIND = r"C:\AzerothRealm\wowunreal\tools\mpqfind.exe"
# Precedence, highest first.  Every Ascension UI override lives in patch-B and
# everything else falls through to the stock enUS chain.  Ordering archives by
# name or by path length -- which is what mpqcat does -- silently returns the
# stock 3.3.5 copy of any file Ascension overrides.
CHAIN = ",".join([
    "patch-B.MPQ",
    "patch-enUS-3.MPQ", "patch-enUS-2.MPQ", "patch-enUS.MPQ", "locale-enUS.MPQ",
    "patch-3.MPQ", "patch-2.MPQ", "patch.MPQ",
    "lichking.MPQ", "expansion.MPQ", "common-2.MPQ", "common.MPQ",
])
DATA = os.environ.get("MPQ_DATA", r"C:\AzerothRealm\client-ascension\Data")
OUT_ROOT = os.environ.get(
    "UI_OUT", r"C:\AzerothRealm\realms\ascension\rexxar-reference\ui-tree")

SCRIPT_RE = re.compile(rb'<\s*(?:Script|Include)\b[^>]*\bfile\s*=\s*"([^"]+)"', re.I)


def norm(p):
    """Collapse .. and . the way the client's virtual filesystem does."""
    p = p.replace("/", "\\").strip().strip("\\")
    out = []
    for part in p.split("\\"):
        if part in ("", "."):
            continue
        if part == "..":
            if out:
                out.pop()
            continue
        out.append(part)
    return "\\".join(out)


def fetch(internal, dest):
    if os.path.exists(dest) and os.path.getsize(dest) > 0:
        with open(dest, "rb") as f:
            return f.read()
    d = os.path.dirname(dest)
    if d:
        os.makedirs(d, exist_ok=True)
    r = subprocess.run([MPQFIND, DATA, "--chain", CHAIN, internal, dest],
                       capture_output=True, text=True)
    if r.returncode != 0 or not os.path.exists(dest):
        if os.path.exists(dest):
            os.remove(dest)
        return None
    with open(dest, "rb") as f:
        return f.read()


def walk(roots):
    todo = [norm(r) for r in roots]
    seen = set()
    found, missing = [], []

    while todo:
        rel = todo.pop(0)
        key = rel.lower()
        if key in seen:
            continue
        seen.add(key)

        dest = os.path.join(OUT_ROOT, rel.replace("\\", os.sep))
        data = fetch(rel, dest)
        if data is None:
            missing.append(rel)
            continue
        found.append((rel, len(data)))

        here = os.path.dirname(rel)
        low = rel.lower()
        refs = []
        if low.endswith(".toc"):
            # Several Ascension tocs start with a UTF-8 BOM, which would
            # otherwise hide the leading '#' and turn the "## Interface: 30300"
            # directive into a bogus filename.
            for line in data.decode("utf-8-sig", "replace").splitlines():
                line = line.strip().lstrip("﻿")
                if not line or line.startswith("#"):
                    continue
                refs.append(line)
        elif low.endswith(".xml"):
            for m in SCRIPT_RE.finditer(data):
                refs.append(m.group(1).decode("utf-8", "replace"))

        for ref in refs:
            ref = ref.replace("/", "\\").strip()
            # A ref that names a top-level client directory is absolute; the
            # rest hang off the referring file's own directory.
            if ref.lower().startswith("interface\\"):
                todo.append(norm(ref))
            else:
                todo.append(norm(here + "\\" + ref if here else ref))

    return found, missing


def main():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

    roots = sys.argv[1:] or [r"Interface\FrameXML\FrameXML.toc"]
    os.makedirs(OUT_ROOT, exist_ok=True)
    found, missing = walk(roots)
    total = sum(n for _, n in found)
    print("== %d file(s), %d bytes -> %s" % (len(found), total, OUT_ROOT))
    if missing:
        print("   -- not in MPQ (%d): %s"
              % (len(missing), ", ".join(sorted(missing)[:15])))


if __name__ == "__main__":
    main()
