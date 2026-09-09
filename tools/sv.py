import io, lupa
SV = r"C:\AzerothRealm\client-ascension\WTF\Account\TEST\SavedVariables\Ascension_CoAReader.lua"
L = lupa.LuaRuntime(unpack_returned_tuples=True)
L.execute(io.open(SV, "r", encoding="utf-8", errors="replace").read())
db = L.globals().CoAReaderDB

def py(v, depth=0):
    if lupa.lua_type(v) == "table":
        return {py(k): py(v[k], depth+1) for k in v}
    return v

tree = py(db.tree) if db.tree is not None else {}
why  = py(db.why)  if db.why  is not None else {}

print("== tree ==")
print("  realmFlags :", tree.get("realmFlags"))
print("  Tinker/Class entries=%s spells=%s talents=%s" % (
    tree.get("tinkerClass"), tree.get("spells_TinkerClass"), tree.get("talents_TinkerClass")))
print("  counts     :", tree.get("counts"))
for i in (1,2,3):
    s = tree.get("sample%d" % i)
    if s:
        print("  sample%d pos=%s" % (i, tree.get("sample%d_pos" % i)))
        for k in sorted(s, key=str):
            print("      %-26s %s" % (k, s[k]))

print()
print("== why ==")
print("  allCount=%s iterated=%s classTabPairs=%s sweepTried=%s sweepHits=%s" % (
    why.get("allCount"), why.get("iterated"), why.get("hClassTab_n"),
    why.get("sweepTried"), why.get("sweepHitCount")))
print("  gates :", why.get("gates"))
print("  hType :", why.get("hType"))

hits = why.get("sweepHits") or {}
print()
print("== sweepHits: %d buckets ==" % len(hits))
byclass = {}
for k, v in hits.items():
    c, _, t = str(k).partition("|")
    byclass.setdefault(c, []).append((t, v))
for c in sorted(byclass):
    tabs = sorted(byclass[c])
    tot = sum(n for _, n in tabs)
    print("  %-20s %5d entries over %2d tab(s): %s" % (
        c, tot, len(tabs), ", ".join("%s=%s" % t for t in tabs)))

print()
print("== roundtrip ==")
rt = why.get("roundtrip") or {}
for k in sorted(rt, key=str):
    print("  %-22s %s" % (k, rt[k]))
