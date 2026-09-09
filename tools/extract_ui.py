#!/usr/bin/env python3
"""Recursively pull an Ascension FrameXML addon out of the client's MPQ chain.

Ascension's custom patch archives ship with no (listfile), so enumerating tools
see nothing in them.  mpqcat.exe resolves an exact internal path through the MPQ
hash table instead, which still works -- so the trick is to start from a name we
can guess (Interface\\AddOns\\<Name>\\<Name>.toc) and then follow the references:
the TOC lists .xml/.lua files, each .xml lists more via <Script file=.../> and
<Include file=.../>, and so on until the closure is complete.

    python extract_ui.py Ascension_CharacterAdvancement [more addons...]

Read-only: nothing is written back into the client, only into OUT_ROOT.
"""
import os
import re
import subprocess
import sys

MPQCAT = r"C:\AzerothRealm\wowunreal\tools\mpqcat.exe"
DATA = os.environ.get("MPQ_DATA", r"C:\AzerothRealm\client-ascension\Data")
OUT_ROOT = r"C:\AzerothRealm\realms\ascension\rexxar-reference\ui-source"

SCRIPT_RE = re.compile(rb'<\s*(?:Script|Include)\b[^>]*\bfile\s*=\s*"([^"]+)"', re.I)


def norm(p):
    return p.replace("/", "\\").strip()


def fetch(internal, dest):
    """Extract one MPQ path to dest. Returns bytes, or None if absent."""
    if os.path.exists(dest):
        with open(dest, "rb") as f:
            return f.read()
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    r = subprocess.run([MPQCAT, DATA, internal, dest],
                       capture_output=True, text=True)
    if r.returncode != 0 or not os.path.exists(dest):
        if os.path.exists(dest):
            os.remove(dest)
        return None
    with open(dest, "rb") as f:
        return f.read()


def walk(addon):
    base = "Interface\\AddOns\\%s" % addon
    outdir = os.path.join(OUT_ROOT, addon)
    todo = ["%s.toc" % addon]
    seen = set()
    found, missing = [], []

    while todo:
        rel = norm(todo.pop(0))
        key = rel.lower()
        if key in seen:
            continue
        seen.add(key)

        internal = base + "\\" + rel
        dest = os.path.join(outdir, rel.replace("\\", os.sep))
        data = fetch(internal, dest)
        if data is None:
            missing.append(rel)
            continue
        found.append((rel, len(data)))

        low = rel.lower()
        if low.endswith(".toc"):
            for line in data.decode("utf-8", "replace").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                todo.append(line)
        elif low.endswith(".xml"):
            here = os.path.dirname(rel)
            for m in SCRIPT_RE.finditer(data):
                ref = norm(m.group(1).decode("utf-8", "replace"))
                todo.append(os.path.join(here, ref).replace("/", "\\") if here else ref)

    return found, missing


def main():
    # Some of Ascension's own filenames are not representable in the console's
    # default code page (cp1252 here), and the very last thing this tool does is
    # print the file list -- so a full, successful extraction used to end in a
    # UnicodeEncodeError traceback.  Nothing is wrong with the extraction; only
    # the report cannot be spelled.  Ask stdout to replace what it cannot encode.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass                                  # pre-3.7, or a stream we do not own

    addons = sys.argv[1:] or ["Ascension_CharacterAdvancement"]
    os.makedirs(OUT_ROOT, exist_ok=True)
    for addon in addons:
        found, missing = walk(addon)
        total = sum(n for _, n in found)
        print("== %s: %d file(s), %d bytes" % (addon, len(found), total))
        for rel, n in sorted(found):
            print("   %8d  %s" % (n, rel))
        if missing:
            print("   -- not in MPQ (%d): %s" % (len(missing), ", ".join(sorted(missing)[:12])))


if __name__ == "__main__":
    main()
