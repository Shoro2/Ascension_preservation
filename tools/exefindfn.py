#!/usr/bin/env python3
"""Locate a Lua C-binding inside Ascension.exe by name (read-only).

Same trick as findfn.py, but pointed at the executable instead of Extensions.dll:
the C_* namespaces are registered with the usual luaL_Reg {const char *name;
lua_CFunction func;} array, so a pointer to the ASCII name sits immediately
before a pointer to the implementation.  Find the string, find every dword that
points at it, and read the dword that follows.

    python exefindfn.py CanCreateHero [bytes-to-disassemble]
    python exefindfn.py --list Archetype        every matching binding, addresses only
"""
import struct
import sys
import importlib.util

spec = importlib.util.spec_from_file_location(
    "exedis", r"C:\AzerothRealm\realms\ascension\tools\exedis.py")
E = importlib.util.module_from_spec(spec)
spec.loader.exec_module(E)
D = E.d


def text_range():
    for nm, sva, vs, rp, rs in E.SECS:
        if nm == ".text":
            return E.BASE + sva, E.BASE + sva + max(vs, rs)
    return 0, 0xFFFFFFFF


TLO, THI = text_range()


def find_string(name):
    """Every VA at which the exact NUL-terminated ASCII `name` appears."""
    needle = name.encode("latin1") + b"\x00"
    out, i = [], 0
    while True:
        i = D.find(needle, i)
        if i < 0:
            return out
        # only accept it as a standalone string, not a tail of a longer one
        if i == 0 or D[i - 1] == 0:
            for nm, sva, vs, rp, rs in E.SECS:
                if rp <= i < rp + rs:
                    out.append(E.BASE + sva + (i - rp))
                    break
        i += 1


def bindings(name):
    """[(nameVA, fnVA)] for luaL_Reg entries whose name field points at `name`."""
    out = []
    for sva in find_string(name):
        ptr = struct.pack("<I", sva)
        i = 0
        while True:
            i = D.find(ptr, i)
            if i < 0:
                break
            fn = struct.unpack_from("<I", D, i + 4)[0]
            if TLO <= fn < THI:
                out.append((sva, fn))
            i += 4
    return out


def main():
    args = sys.argv[1:]
    if args and args[0] == "--list":
        want = args[1]
        seen = {}
        for nm, sva, vs, rp, rs in E.SECS:
            if not nm.startswith(".rdata") and nm != ".data":
                continue
            blob = D[rp:rp + rs]
            off = 0
            while True:
                off = blob.find(want.encode("latin1"), off)
                if off < 0:
                    break
                st = blob.rfind(b"\x00", 0, off) + 1
                en = blob.find(b"\x00", off)
                s = blob[st:en].decode("latin1", "replace")
                if s.isidentifier() and s not in seen:
                    b = bindings(s)
                    if b:
                        seen[s] = b[0][1]
                off = en + 1
        for k in sorted(seen):
            print("  %-34s 0x%08x" % (k, seen[k]))
        return

    name = args[0]
    n = int(args[1], 0) if len(args) > 1 else 0
    b = bindings(name)
    if not b:
        print("no luaL_Reg entry found for %r" % name)
        return
    for sva, fn in b:
        print("%s: name@0x%08x -> fn 0x%08x" % (name, sva, fn))
        if n:
            E.dis(fn, n)


if __name__ == "__main__":
    main()
