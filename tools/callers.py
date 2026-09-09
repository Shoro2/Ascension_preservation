#!/usr/bin/env python3
"""Every direct `call` site of a target VA inside Extensions.dll (read-only).

Scans .text for the E8 rel32 encoding and reports each call site, so a global
like a RealmInfo flag getter can be checked for ALL of its readers before the
server starts setting that flag.

    python callers.py 0x102fc630
"""
import struct
import sys
import importlib.util

spec = importlib.util.spec_from_file_location(
    "disx", r"C:\AzerothRealm\realms\ascension\tools\disx.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
D = m.DATA
TLO, THI, _, _ = m.text_range()


def main():
    target = int(sys.argv[1], 16)
    lo_off = m.va2off(TLO)
    hi_off = m.va2off(THI - 1)
    sites = []
    for off in range(lo_off, hi_off):
        if D[off] != 0xE8:
            continue
        rel = struct.unpack_from("<i", D, off + 1)[0]
        va = TLO + (off - lo_off)
        if va + 5 + rel == target:
            sites.append(va)
    print("call 0x%08x -- %d direct site(s)" % (target, len(sites)))
    for va in sites:
        print("  0x%08x" % va)


if __name__ == "__main__":
    main()
