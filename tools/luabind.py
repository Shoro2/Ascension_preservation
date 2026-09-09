#!/usr/bin/env python3
"""Recover a C_* Lua namespace's {name, fn} table from Extensions.dll.

Ascension builds the luaL_Reg array on the stack with consecutive
    mov dword ptr [esp+X], <char* name>
    mov dword ptr [esp+X+4], <lua_CFunction>
so sweeping a function for that pair recovers the whole namespace.

    python luabind.py 0x10183e30 0x10185200      dump every pair in a range
    python luabind.py --fn 0x10175d50            which Lua name maps to a fn
Read-only.
"""
import struct, sys, importlib.util
spec = importlib.util.spec_from_file_location("disx", r"C:\AzerothRealm\realms\ascension\tools\disx.py")
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
D = m.DATA
tlo, thi, _, _ = m.text_range()


def cstr(va):
    o = m.va2off(va)
    if o is None:
        return None
    e = D.find(b"\0", o, o + 128)
    if e < 0:
        return None
    try:
        s = D[o:e].decode("ascii")
    except UnicodeDecodeError:
        return None
    return s if s and all(32 <= ord(c) < 127 for c in s) else None


def pairs_in(lo, hi):
    """yield (name, fn) from `mov [esp+X], imm` runs and `push imm` runs."""
    out = []
    o = m.va2off(lo)
    end = m.va2off(hi)
    i = o
    while i < end - 11:
        # c7 84 24 <disp32> <imm32>   mov dword ptr [esp+disp32], imm32
        if D[i] == 0xC7 and D[i + 1] == 0x84 and D[i + 2] == 0x24:
            disp = struct.unpack_from("<I", D, i + 3)[0]
            imm = struct.unpack_from("<I", D, i + 7)[0]
            out.append((disp, imm))
            i += 11
            continue
        # c7 44 24 <disp8> <imm32>
        if D[i] == 0xC7 and D[i + 1] == 0x44 and D[i + 2] == 0x24:
            disp = D[i + 3]
            imm = struct.unpack_from("<I", D, i + 4)[0]
            out.append((disp, imm))
            i += 8
            continue
        i += 1
    slots = dict(out)
    res = []
    for disp, imm in out:
        nm = cstr(imm)
        fn = slots.get(disp + 4)
        if nm and fn and tlo <= fn < thi:
            res.append((nm, fn, disp))
    return res


def main():
    if sys.argv[1] == "--fn":
        want = int(sys.argv[2], 0)
        for lo in (0x10183000, 0x10176000, 0x1017c000):
            pass
        # brute: scan all of .text for the pair form and match fn
        tl, th, rp, rs = m.text_range()
        for nm, fn, disp in pairs_in(tl, th):
            if fn == want:
                print("%s -> 0x%08x" % (nm, fn))
        return
    lo = int(sys.argv[1], 0)
    hi = int(sys.argv[2], 0)
    for nm, fn, disp in pairs_in(lo, hi):
        print("  %-40s 0x%08x   [esp+0x%x]" % (nm, fn, disp))


if __name__ == "__main__":
    main()
