"""Overlay the harvested Project Ascension data onto asc_world.

Only asc_* is written. The acore_* databases are never opened for write; the
Ascension data comes from the archive under ascension-archive/, harvested from
the live client before the 2026-09-04 shutdown.

Field mappings here were derived by cross-checking against AzerothCore's own
quest_template on the 9,454 quests both sides share, not assumed:
  - the two reward blocks are interleaved (id, count) pairs
  - packet string 1 is LogDescription, string 2 is QuestDescription
See ascension-archive/wdb/wdbquest.py for the derivations.

Usage:  python import-world.py [quests|creatures|trainers|all]
"""
import json, os, subprocess, sys, collections

ARCHIVE = os.environ.get("ASC_ARCHIVE", "ascension-archive")
SCR = os.environ.get("ASC_SCR", os.path.join(os.environ.get("TEMP", "."), "asc-scratch"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ascreds
CNF = ascreds.path()   # root; written to a 0600 temp file, gone at exit
MY = r"C:\AzerothRealm\mysql\bin\mysql.exe"
DB = "asc_world"

QUOTE = chr(39)
BSLASH = chr(92)


def sql(text, db=DB):
    """Run a statement batch through the mysql client via a temp file."""
    f = os.path.join(SCR, "_asc_batch.sql")
    with open(f, "w", encoding="utf8") as fh:
        fh.write("SET NAMES utf8mb4;\nSET SESSION sql_mode='';\n" + text)
    with open(f, "rb") as fh:
        r = subprocess.run([MY, "--defaults-extra-file=" + CNF, db],
                           stdin=fh, capture_output=True)
    if r.returncode:
        raise RuntimeError(r.stderr.decode("utf8", "replace")[:1500])
    return r.stdout.decode("utf8", "replace")


def query(s, db=DB):
    r = subprocess.run([MY, "--defaults-extra-file=" + CNF, "-N", "-B", "-e", s, db],
                       capture_output=True, text=True)
    if r.returncode:
        raise RuntimeError(r.stderr[:800])
    return r.stdout.strip()


def sgn(v, bits=32):
    """The cache stores everything unsigned; several columns are signed."""
    v = int(v)
    return v - (1 << bits) if v >= (1 << (bits - 1)) else v


def esc(s):
    if s is None:
        return QUOTE + QUOTE
    s = str(s)
    s = s.replace(BSLASH, BSLASH + BSLASH)
    s = s.replace(QUOTE, BSLASH + QUOTE)
    s = s.replace(chr(0), "")
    return QUOTE + s + QUOTE


def clamp(v, lo, hi, name, dropped):
    if v < lo or v > hi:
        dropped[name] += 1
        return max(lo, min(hi, v))
    return v


def chunks(seq, n):
    buf = []
    for x in seq:
        buf.append(x)
        if len(buf) >= n:
            yield buf
            buf = []
    if buf:
        yield buf


# ---------------------------------------------------------------- quests
QCOLS = ["ID", "QuestType", "QuestLevel", "MinLevel", "QuestSortID", "QuestInfoID",
         "SuggestedGroupNum", "RequiredFactionId1", "RequiredFactionValue1",
         "RequiredFactionId2", "RequiredFactionValue2", "RewardNextQuest",
         "RewardXPDifficulty", "RewardMoney", "RewardMoneyDifficulty",
         "RewardDisplaySpell", "RewardSpell", "RewardHonor", "RewardKillHonor",
         "StartItem", "Flags", "RewardTitle", "RequiredPlayerKills",
         "RewardTalents", "RewardArenaPoints",
         "RewardItem1", "RewardAmount1", "RewardItem2", "RewardAmount2",
         "RewardItem3", "RewardAmount3", "RewardItem4", "RewardAmount4",
         "RewardChoiceItemID1", "RewardChoiceItemQuantity1",
         "RewardChoiceItemID2", "RewardChoiceItemQuantity2",
         "RewardChoiceItemID3", "RewardChoiceItemQuantity3",
         "RewardChoiceItemID4", "RewardChoiceItemQuantity4",
         "RewardChoiceItemID5", "RewardChoiceItemQuantity5",
         "RewardChoiceItemID6", "RewardChoiceItemQuantity6",
         "RewardFactionID1", "RewardFactionValue1", "RewardFactionOverride1",
         "RewardFactionID2", "RewardFactionValue2", "RewardFactionOverride2",
         "RewardFactionID3", "RewardFactionValue3", "RewardFactionOverride3",
         "RewardFactionID4", "RewardFactionValue4", "RewardFactionOverride4",
         "RewardFactionID5", "RewardFactionValue5", "RewardFactionOverride5",
         "POIContinent", "POIx", "POIy", "POIPriority",
         "LogTitle", "LogDescription", "QuestDescription", "AreaDescription",
         "QuestCompletionLog",
         "RequiredNpcOrGo1", "RequiredNpcOrGo2", "RequiredNpcOrGo3", "RequiredNpcOrGo4",
         "RequiredNpcOrGoCount1", "RequiredNpcOrGoCount2", "RequiredNpcOrGoCount3",
         "RequiredNpcOrGoCount4",
         "RequiredItemId1", "RequiredItemId2", "RequiredItemId3",
         "RequiredItemId4", "RequiredItemId5", "RequiredItemId6",
         "RequiredItemCount1", "RequiredItemCount2", "RequiredItemCount3",
         "RequiredItemCount4", "RequiredItemCount5", "RequiredItemCount6",
         "ObjectiveText1", "ObjectiveText2", "ObjectiveText3", "ObjectiveText4",
         "VerifiedBuild"]


def quest_row(z, dropped):
    g = z.get
    npc = z["objectiveCreatureOrGO"]
    itm = z["objectiveItems"]
    txt = z["objectiveText"]
    v = [int(g("questId")), int(g("method")),
         clamp(sgn(g("level")), -32768, 32767, "QuestLevel", dropped),
         clamp(int(g("minLevel")), 0, 65535, "MinLevel", dropped),
         clamp(sgn(g("zoneOrSort")), -32768, 32767, "QuestSortID", dropped),
         clamp(int(g("type")), 0, 65535, "QuestInfoID", dropped),
         int(g("suggestedPlayers")), int(g("repObjectiveFaction")),
         sgn(g("repObjectiveValue")), int(g("repObjectiveFaction2")),
         sgn(g("repObjectiveValue2")), int(g("nextQuestInChain")),
         int(g("rewXPId")), sgn(g("rewOrReqMoney")), int(g("rewMoneyMaxLevel")),
         int(g("rewSpell")), sgn(g("rewSpellCast")), int(g("rewHonor")),
         float(g("rewHonorMultiplier")), int(g("srcItemId")), int(g("flags")),
         int(g("charTitleId")), int(g("playersSlain")), int(g("bonusTalents")),
         int(g("rewArenaPoints"))]
    for i in range(4):
        v += [int(g("rewItemId%d" % i)), int(g("rewItemCount%d" % i))]
    for i in range(6):
        v += [int(g("rewChoiceItemId%d" % i)), int(g("rewChoiceItemCount%d" % i))]
    for i in range(5):
        v += [int(g("rewRepFaction%d" % i)), sgn(g("rewRepValueId%d" % i)),
              sgn(g("rewRepValue%d" % i))]
    v += [int(g("pointMapId")), float(g("pointX")), float(g("pointY")),
          int(g("pointOpt"))]
    v += [g("title"), g("logDescription"), g("questDescription"),
          g("areaDescription"), g("completionLog")]
    v += [sgn(n["id"]) for n in npc] + [int(n["count"]) for n in npc]
    v += [int(i["id"]) for i in itm] + [int(i["count"]) for i in itm]
    v += [txt[0], txt[1], txt[2], txt[3], 12340]
    return v


def fmt(v):
    if isinstance(v, str):
        return esc(v)
    if isinstance(v, float):
        return repr(round(v, 6))
    return str(int(v))


def do_quests():
    Q = json.load(open(os.path.join(ARCHIVE, "quests", "quests.json"), encoding="utf8"))
    before = int(query("SELECT COUNT(*) FROM quest_template;"))
    dropped = collections.Counter()
    rows = []
    for k in sorted(Q, key=int):
        try:
            rows.append(quest_row(Q[k], dropped))
        except Exception:
            dropped["row_error"] += 1
    head = "REPLACE INTO quest_template (%s) VALUES\n" % ",".join(
        "`%s`" % c for c in QCOLS)
    n = 0
    for batch in chunks(rows, 400):
        body = ",\n".join("(" + ",".join(fmt(x) for x in r) + ")" for r in batch)
        sql(head + body + ";")
        n += len(batch)
        print("   quests %d/%d" % (n, len(rows)), end="\r", flush=True)
    after = int(query("SELECT COUNT(*) FROM quest_template;"))
    print("\n   quest_template %d -> %d  (%d written, +%d new)"
          % (before, after, n, after - before))
    if dropped:
        print("   clamped/failed:", dict(dropped))


# -------------------------------------------------------------- creatures
def do_creatures():
    C = json.load(open(os.path.join(ARCHIVE, "creatures", "creatures.json"),
                       encoding="utf8"))
    if isinstance(C, dict):
        C = list(C.values())
    have = set(int(x) for x in query("SELECT entry FROM creature_template;").split())
    has_model = bool(query("SHOW TABLES LIKE 'creature_template_model';"))
    new, present, models = [], 0, []
    for c in C:
        e = int(c.get("entry", c.get("index", 0)) or 0)
        nm = (c.get("name") or "").strip()
        if not e or not nm:
            continue
        if e in have:
            present += 1
            continue
        new.append((e, nm))
        for i, d in enumerate([d for d in (c.get("displayId") or []) if d][:4]):
            models.append((e, i, int(d)))
    print("   client creatures: %d   new: %d   already in world: %d"
          % (len(C), len(new), present))
    n = 0
    for batch in chunks(new, 500):
        sql("INSERT IGNORE INTO creature_template (entry,name,VerifiedBuild) VALUES "
            + ",".join("(%d,%s,-12340)" % (e, esc(nm)) for e, nm in batch) + ";")
        n += len(batch)
        print("   creature_template +%d/%d" % (n, len(new)), end="\r", flush=True)
    print()
    if has_model and models:
        m = 0
        for batch in chunks(models, 500):
            sql("INSERT IGNORE INTO creature_template_model "
                "(CreatureID,Idx,CreatureDisplayID,DisplayScale,Probability) VALUES "
                + ",".join("(%d,%d,%d,1,1)" % t for t in batch) + ";")
            m += len(batch)
            print("   creature_template_model +%d/%d" % (m, len(models)),
                  end="\r", flush=True)
        print()
    print("   creature_template now:", query("SELECT COUNT(*) FROM creature_template;"))


# --------------------------------------------------------------- trainers
def do_trainers():
    """NPCTrainer.dbc carries no NPC linkage - it is a flat list of trainable
    spells with their skill requirement. So we build one reusable trainer
    TEMPLATE per skill line that a GM can attach to an NPC. Which NPC teaches
    what is server-side data we did not capture.

    Template IDs start at 900000, well clear of the highest creature entry
    (~127,502 after the creature import). They must be positive: npc_trainer.ID
    is `int unsigned` AND part of the primary key, so a negative ID silently
    clamps to 0 under a permissive sql_mode and every template collapses into
    one bucket."""
    T = json.load(open(os.path.join(ARCHIVE, "trainers", "trainers.json"),
                       encoding="utf8"))
    by_skill = collections.defaultdict(list)
    for r in T:
        if r["spell"] <= 0:
            continue
        by_skill[r["reqSkillLine"] or 0].append(r)
    sql("DELETE FROM npc_trainer WHERE ID >= 900000 OR ID = 0;")
    rows, tmpl = [], {}
    ordered = sorted(by_skill.items(), key=lambda kv: -len(kv[1]))
    for i, (skill, items) in enumerate(ordered):
        tid = 900000 + i
        tmpl[tid] = (skill, items[0]["reqSkillName"], len(items))
        for r in items:
            rows.append((tid, r["spell"], 0, skill, r["reqSkillRank"] or 0, 0, 0))
    n = 0
    for batch in chunks(rows, 500):
        sql("INSERT IGNORE INTO npc_trainer (ID,SpellID,MoneyCost,ReqSkillLine,"
            "ReqSkillRank,ReqLevel,ReqSpell) VALUES "
            + ",".join(str(t) for t in batch) + ";")
        n += len(batch)
        print("   npc_trainer +%d/%d" % (n, len(rows)), end="\r", flush=True)
    print("\n   %d trainer templates covering %d spells" % (len(tmpl), len(rows)))
    for tid, (skill, name, cnt) in sorted(tmpl.items(), key=lambda kv: -kv[1][2])[:10]:
        print("      %-8d %-24s %4d spells" % (tid, name or ("skill %d" % skill), cnt))
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "trainer-templates.json")
    json.dump({str(k): {"skillLine": v[0], "skillName": v[1], "spells": v[2]}
               for k, v in tmpl.items()}, open(out, "w"), indent=1)


if __name__ == "__main__":
    what = (sys.argv[1] if len(sys.argv) > 1 else "all").lower()
    if what in ("quests", "all"):
        print("== quests ==")
        do_quests()
    if what in ("creatures", "all"):
        print("== creatures ==")
        do_creatures()
    if what in ("trainers", "all"):
        print("== trainers ==")
        do_trainers()
    print("done")
