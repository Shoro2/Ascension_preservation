"""Minimal WoW 3.3.5a WORLD server for the local Ascension archive (Phase 3b).

Goal: take the client from the world connection (127.0.0.1:8087) all the way to the
CHARACTER-SELECT screen with an empty character list -- proving the full chain
    login (shim :3799)  ->  realm list  ->  world auth  ->  char enum.

The world handshake was cracked in Phase 3 and is STOCK 3.3.5a (see WIRE-SPEC.md 11).
Nothing here is patched into the client. The only "active" thing this does beyond
speaking the documented protocol is a passive ReadProcessMemory of the client's OWN
computed 40-byte world SessionKey (authobj+0x140) -- the same read-only RPM the login
shim already uses -- so the server can verify the digest and drive the header crypt.

Flow (server speaks first):
  1. accept on 8095 (see archive_ports.py -- 8085 belongs to the hub's real realms)
  2. SMSG_AUTH_CHALLENGE  (unencrypted)  body = u32(1) | authSeed(4) | 32 zero seed bytes
  3. recv CMSG_AUTH_SESSION (unencrypted 6-byte header + body); parse Account/seeds/digest
  4. RPM-read the 40-byte world SessionKey at authobj+0x140; verify
         digest == SHA1(Account | 00000000 | clientSeed | serverSeed | SessionKey40)
  5. init ARC4-drop1024 header crypt (fixed AuthCrypt seeds HMAC'd with the SessionKey)
  6. SMSG_AUTH_RESPONSE(AUTH_OK, expansion=WotLK)   -- first ENCRYPTED packet
  7. loop: decrypt each 6-byte client header, read body, answer the small opcodes.
         CMSG_CHAR_ENUM (0x037) -> SMSG_CHAR_ENUM (0x03B) with count=0  == goal reached.

Header crypt: only the packet HEADER is encrypted (WotLK).
  S->C header: size(u16 BE = bodylen+2) | opcode(u16 LE)          (4 bytes)
  C->S header: size(u16 BE = bodylen+4) | opcode(u32 LE)          (6 bytes)
  _serverEncrypt RC4 key = HMAC_SHA1(ServerEncryptionKey, SessionKey40)
  _clientDecrypt RC4 key = HMAC_SHA1(ServerDecryptionKey, SessionKey40)
  both streams drop the first 1024 keystream bytes before use.

Run UNELEVATED, as the same user as the client, which is itself launched unelevated
via __COMPAT_LAYER=RunAsInvoker (a medium-integrity process cannot RPM an elevated
one, and the reverse is not needed).  The login shim on 3799 must ALSO be running
(login + realm list flow through it first).  Usage:
    python world_server.py

Layout.  This file finds what it needs in either of two layouts, and logs every
resolved path at startup (see report_paths) so a wrong layout is visible in the
first twelve lines of the log instead of failing quietly later:
  working realm dir   everything beside this file; reference DBCs under
                      ./rexxar-reference; Ascension's server DBCs two levels up in
                      ../../server-ascension/Data/dbc
  public repo         this file in server/, seed/state JSON in server/data/, the
                      helper modules in ../tools, entries.csv in ../data/ca-export
Overrides: ASC_DATA_DIR (seed/state), ASC_CA_REF (rexxar-reference), ASC_DBC_DIR
(the directory holding Ascension's Spell.dbc + ChrClasses.dbc).
"""
import socket, os, sys, time, hashlib, hmac, struct, json, csv, io, mmap, copy as _copy
import math, random

BASE = os.path.dirname(os.path.abspath(__file__))
import runtime_paths as paths
sys.path.insert(0, BASE)
# The public repo ships chardata / archive_ports / ascension_x25519_m2 under
# ../tools rather than beside this file.  Look there too, after BASE, so neither
# layout needs files copied around before anything starts.
_TOOLS_DIR = os.path.join(os.path.dirname(BASE), "tools")
if os.path.isdir(_TOOLS_DIR) and _TOOLS_DIR not in sys.path:
    sys.path.append(_TOOLS_DIR)
import rpm_readk as R                    # passive RPM plumbing (VM_READ + RPM only)
import chardata                          # per-race display ids / start positions / factions


def _first_existing(*cands):
    """The first candidate path that exists, else the first candidate (so the
    later "cannot read X" log line names the place it was expected)."""
    for p in cands:
        if os.path.exists(p):
            return p
    return cands[0]


LOG = paths.log_file("world_server_log.txt")
# Seed/state files (characters, account data, keybinds, builds, bars).  The public
# repo ships them in ./data; the working realm dir keeps them beside this file.
# A missing seed file does NOT stop the server -- it logs one "unreadable ... not
# seeding" line and carries on with empty keybinds and no characters -- which is
# exactly why the resolved directory is reported at startup.
DATA_DIR = paths.state_dir()
CHARS_PATH = os.path.join(DATA_DIR, "characters.json")

# ---- world-entry burst bisect switch ----------------------------------------
# ERROR #132 cause (3) fires inside the client's per-frame "event 6" broadcast
# while its object manager has no PLAYER object.  Every packet of the world-entry
# burst is a suspect, so each one is skippable by name to bisect which is fatal:
#     set ARCHIVE_BURST_SKIP=spells,acctdata,tutorial,bind,timespeed,motd,create
# Empty (the default) sends the full burst exactly as before.
BURST_SKIP = set(
    s.strip().lower()
    for s in os.environ.get("ARCHIVE_BURST_SKIP", "").split(",")
    if s.strip()
)

def burst_send(part):
    """True when this piece of the world-entry burst should be sent."""
    return part not in BURST_SKIP


# SMSG_REALM_INFO advertises realm_type=2, which tells the client this realm's
# level cap is 80.  Archive characters are created there directly: the CoA panel
# gates its talent half behind "Unlocks at level 10" and gates individual nodes
# on RequiredLevel (Mage's own list runs 1..70), so a level-1 character can only
# ever see the spell column.  Levelling is not something this archive models --
# there are no mobs, no quests and no XP -- so starting at the cap is what makes
# the shipped dataset actually reachable.  This is the level the SERVER reports;
# nothing client-side is patched to ignore the gate.
ARCHIVE_LEVEL = 80

# Which parts of the Character Advancement block to send at world entry.  This
# exists to bisect the in-world crash: the client dies a few seconds after
# entering, and 2026-09-01 19:33 died with SMSG_CA_ESSENCE_BUDGET (0x722) as its
# last received opcode, so the block is the first suspect.  "full" is the real
# behaviour; every other value is a diagnostic.
#   full        0x725 + 5600 x 0x722 + 0x726   (normal)
#   none        nothing at all
#   spec        0x725 only
#   known       0x725 + 0x726, no essence budget
#   budget      0x725 + essence budget, no known entries
ARCHIVE_CA_MODE = os.environ.get("ARCHIVE_CA_MODE", "full").strip().lower()
from archive_ports import HOST, WORLD_PORT as PORT   # 127.0.0.1:8087

# ---- opcodes (3.3.5a, AzerothCore Opcodes.h) --------------------------------
CMSG_CHAR_CREATE                      = 0x036
CMSG_CHAR_ENUM                        = 0x037
CMSG_CHAR_DELETE                      = 0x038
SMSG_CHAR_CREATE                      = 0x03A
SMSG_CHAR_ENUM                        = 0x03B
SMSG_CHAR_DELETE                      = 0x03C
CMSG_PLAYER_LOGIN                     = 0x03D
SMSG_CHARACTER_LOGIN_FAILED           = 0x041
SMSG_LOGIN_SETTIMESPEED               = 0x042
CMSG_LOGOUT_REQUEST                   = 0x04B
SMSG_LOGOUT_RESPONSE                  = 0x04C
SMSG_LOGOUT_COMPLETE                  = 0x04D
CMSG_LOGOUT_CANCEL                    = 0x04E
SMSG_LOGOUT_CANCEL_ACK                = 0x04F
CMSG_NAME_QUERY                       = 0x050
SMSG_NAME_QUERY_RESPONSE              = 0x051
CMSG_ITEM_QUERY_SINGLE                = 0x056
SMSG_ITEM_QUERY_SINGLE_RESPONSE       = 0x058
CMSG_CREATURE_QUERY                   = 0x060
SMSG_CREATURE_QUERY_RESPONSE          = 0x061
CMSG_MESSAGECHAT                      = 0x095
SMSG_MESSAGECHAT                      = 0x096
SMSG_UPDATE_OBJECT                    = 0x0A9
SMSG_DESTROY_OBJECT                   = 0x0AA
SMSG_TUTORIAL_FLAGS                   = 0x0FD
CMSG_STANDSTATECHANGE                 = 0x101
SMSG_STANDSTATE_UPDATE                = 0x29D
SMSG_INITIALIZE_FACTIONS              = 0x122
SMSG_ACTION_BUTTONS                   = 0x129
CMSG_SET_ACTION_BUTTON                = 0x128
SMSG_INITIAL_SPELLS                   = 0x12A
SMSG_LEARNED_SPELL                    = 0x12B
SMSG_SUPERCEDED_SPELL                 = 0x12C
CMSG_CAST_SPELL                       = 0x12E
CMSG_CANCEL_CAST                      = 0x12F
SMSG_CAST_FAILED                      = 0x130
SMSG_SPELL_GO                         = 0x132
SMSG_SPELLHEALLOG                     = 0x150
SMSG_SPELLNONMELEEDAMAGELOG           = 0x250
SMSG_POWER_UPDATE                     = 0x480
CMSG_CANCEL_AURA                      = 0x136
SMSG_PERIODICAURALOG                  = 0x24E
SMSG_AURA_UPDATE_ALL                  = 0x495
SMSG_AURA_UPDATE                      = 0x496
SMSG_BINDPOINTUPDATE                  = 0x155
CMSG_PING                             = 0x1DC
SMSG_PONG                             = 0x1DD
CMSG_QUERY_TIME                       = 0x1CE
SMSG_QUERY_TIME_RESPONSE              = 0x1CF
SMSG_AUTH_CHALLENGE                   = 0x1EC
CMSG_AUTH_SESSION                     = 0x1ED
SMSG_AUTH_RESPONSE                    = 0x1EE
SMSG_COMPRESSED_UPDATE_OBJECT         = 0x1F6
SMSG_REMOVED_SPELL                    = 0x203
SMSG_ACCOUNT_DATA_TIMES               = 0x209
CMSG_REQUEST_ACCOUNT_DATA             = 0x20A
CMSG_UPDATE_ACCOUNT_DATA              = 0x20B
SMSG_UPDATE_ACCOUNT_DATA              = 0x20C
SMSG_LOGIN_VERIFY_WORLD               = 0x236
CMSG_SET_ACTIVE_MOVER                 = 0x26A
SMSG_ADDON_INFO                       = 0x2EF
SMSG_INIT_WORLD_STATES                = 0x2C2
SMSG_MOTD                             = 0x33D
SMSG_REALM_SPLIT                      = 0x38B
CMSG_REALM_SPLIT                      = 0x38C
SMSG_TIME_SYNC_REQ                    = 0x390
CMSG_TIME_SYNC_RESP                   = 0x391
SMSG_FEATURE_SYSTEM_STATUS            = 0x3C9
SMSG_SEND_UNLEARN_SPELLS              = 0x41E
SMSG_CLIENTCACHE_VERSION              = 0x4AB
CMSG_READY_FOR_ACCOUNT_DATA_TIMES     = 0x4FF
SMSG_UPDATE_ACCOUNT_DATA_COMPLETE     = 0x463

# ---- account data (the five WTF *-cache.wtf files live on the SERVER) -------
# ascension-opcodes.txt lists this family one below its wire value (it has
# CMSG_READY_FOR_ACCOUNT_DATA_TIMES at 0x4FE, but the client demonstrably sends
# 0x4FF), so the stock 3.3.5a numbers above are the ones that are real.
NUM_ACCOUNT_DATA_TYPES       = 8
GLOBAL_CACHE_MASK            = 0x15     # types 0,2,4 -- config / bindings / macros
PER_CHARACTER_CACHE_MASK     = 0xEA     # types 1,3,5,6,7
GLOBAL_BINDINGS_CACHE        = 2
PER_CHARACTER_BINDINGS_CACHE = 3
ACCOUNT_DATA_NAMES = ("GLOBAL_CONFIG", "PER_CHAR_CONFIG", "GLOBAL_BINDINGS",
                      "PER_CHAR_BINDINGS", "GLOBAL_MACROS", "PER_CHAR_MACROS",
                      "PER_CHAR_LAYOUT", "PER_CHAR_CHAT")
ACCTDATA_PATH         = os.path.join(DATA_DIR, "accountdata.json")
DEFAULT_BINDINGS_PATH = os.path.join(DATA_DIR, "default-bindings.wtf")
KNOWN_PATH            = os.path.join(DATA_DIR, "knownentries.json")
BUILDS_PATH           = os.path.join(DATA_DIR, "builds.json")
ACTIONBARS_PATH       = os.path.join(DATA_DIR, "actionbars.json")
# The CoA reference set: the Character-Advancement DBCs extracted from the client's
# patch-M.MPQ plus the entries.csv exported from them.  ./rexxar-reference is the
# working layout; the public repo ships entries.csv under ../data/ca-export and
# leaves the DBCs to be extracted from your own client (data/MANIFEST.md).  The DBC
# names are accepted with or without the DBFilesClient_ prefix mpqcat gives them.
CA_REF_DIR            = os.environ.get("ASC_CA_REF") or paths.CONFIG.get("ca_ref_dir") or os.path.join(BASE, "rexxar-reference")
CA_ENTRIES_CSV        = _first_existing(
    os.path.join(CA_REF_DIR, "ca-dbc-export", "entries.csv"),
    os.path.join(os.path.dirname(BASE), "data", "ca-export", "entries.csv"))
CA_CLASSTYPES_DBC     = _first_existing(
    os.path.join(CA_REF_DIR, "ca-dbc", "DBFilesClient_CharacterAdvancementClassTypes.dbc"),
    os.path.join(CA_REF_DIR, "ca-dbc", "CharacterAdvancementClassTypes.dbc"))

# Ascension's OWN spell table -- 209,509 records to vanilla 3.3.5a's 49,839, with the
# custom ids running to ~13.9M.  `server\Data\dbc\Spell.dbc` is the vanilla control
# and holds none of the CA spells, so this path is spelled out in full rather than
# derived from whichever DBC directory happens to be at hand.  In the working layout
# that directory is ../../server-ascension/Data/dbc; anywhere else, set ASC_DBC_DIR
# to wherever you extracted Ascension's Spell.dbc (patch-T.MPQ) and ChrClasses.dbc
# (patch-M.MPQ).  Both are optional: without them the spellbook and the class-name
# table come up empty and say so in the log.
DBC_DIR = os.environ.get("ASC_DBC_DIR") or paths.CONFIG.get("dbc_dir") or os.path.join(
    os.path.dirname(os.path.dirname(BASE)), "server-ascension", "Data", "dbc")
SPELL_DBC = os.path.join(DBC_DIR, "Spell.dbc")
# Ascension's ChrClasses.dbc -- 32 rows where vanilla has 10.  Same directory,
# same reason to spell it out: the vanilla copy has none of the CoA classes.
CHRCLASSES_DBC = os.path.join(DBC_DIR, "ChrClasses.dbc")
DBC_HEADER             = 20             # WDBC magic + four u32 header fields
# Stock 3.3.5a record layout (234 fields / 936 bytes), located empirically and then
# confirmed against the vanilla column order: Name is the 17-column localised block
# (16 locales + a flags dword) at 136, so Rank starts at 153.
SPELL_FIELD_ATTRIBUTES = 4
SPELL_FIELD_NAME       = 136
SPELL_FIELD_RANK       = 153
SPELL_ATTR0_PASSIVE    = 0x00000040     # never castable -- no action-bar slot

# The rest of the columns, anchored on the four 17-wide localised string blocks that
# make the tail unambiguous: Name 136, Rank 153, Description 170, ToolTip 187, so the
# numeric tail starts at 204.  Checked against control records rather than trusted:
#   133 Fireball    Effect0=2 (SCHOOL_DAMAGE) SchoolMask=4 (fire)  DmgClass=1 (magic)
#                   StartRecoveryTime=1500 (the GCD)  SpellFamilyName=3 (mage)
#                   DmgMultiplier[3] = 1.0f 1.0f 1.0f      ManaCostPct=19
#   585 Smite       Effect0=2  SchoolMask=2 (holy)         ManaCostPct=15
#   2050            Effect0=10 (HEAL)                      ManaCostPct=32
# Note this is ASCENSION's Spell.dbc: id 2050 is "Greater Heal" here, not vanilla's
# "Lesser Heal", so names are no guide -- the structural fields are.
SPELL_FIELD_POWER_TYPE   = 41
SPELL_FIELD_MANA_COST    = 42
SPELL_FIELD_MANA_COST_LVL = 43
SPELL_FIELD_MANA_PER_SEC = 44
SPELL_FIELD_EFFECT       = 71           # [3]
SPELL_FIELD_EFFECT_DIE   = 74           # [3]
SPELL_FIELD_EFFECT_BASE  = 80           # [3]
SPELL_FIELD_EFFECT_AURA  = 95           # [3]
SPELL_FIELD_MANA_COST_PCT = 204
SPELL_FIELD_DMG_CLASS    = 213
SPELL_FIELD_SCHOOL_MASK  = 225
SPELL_FIELD_MAX          = SPELL_FIELD_SCHOOL_MASK   # widest column this server reads

SPELL_EFFECT_SCHOOL_DAMAGE = 2
SPELL_EFFECT_APPLY_AURA    = 6
SPELL_EFFECT_HEAL          = 10

# ---- aura columns ------------------------------------------------------------
# BOTH of these were located by MEASUREMENT, not from a remembered layout, because a
# wrong index here does not fail loudly: a bad amplitude makes a HoT tick every 0 ms
# (a busy loop) or never (a buff that quietly does nothing), and a bad duration index
# makes every aura permanent.  The tests, over a 20k-record sample of Spell.dbc:
#
#   DurationIndex  -- the ONLY column (of 0..69) whose every sampled value is either 0
#                     or a live SpellDuration.dbc id, and which is nonzero often.
#                     Exactly one column passed: 40.
#   EffectAmplitude -- the column that is ~0 for every NON-periodic aura effect and a
#                     sane millisecond period for every periodic one.  Column 98 scores
#                     98.0% / 98.5%; its nearest rival (97) scores 8.9%.  The periods it
#                     yields are 1000/3000/2000/10000/500/5000 ms, which is what WotLK
#                     periodic spells actually use.
# Re-run `tools/spellcols.py` if Ascension ever reships Spell.dbc.
SPELL_FIELD_DURATION_INDEX = 40
SPELL_FIELD_STACK_AMOUNT   = 49
SPELL_FIELD_EFFECT_AMPL    = 98         # [3]
SPELL_FIELD_ATTR_EX5       = 9

SPELL_ATTR5_NO_DURATION_DISPLAY = 0x02000000

# AuraFlags -- SpellAuraDefines.h:26.  AFLAG_CASTER means "the caster IS the target",
# and it is what decides whether a caster guid is on the wire at all.
AFLAG_EFF_INDEX_0 = 0x01
AFLAG_EFF_INDEX_1 = 0x02
AFLAG_EFF_INDEX_2 = 0x04
AFLAG_CASTER      = 0x08
AFLAG_POSITIVE    = 0x10
AFLAG_DURATION    = 0x20
AFLAG_NEGATIVE    = 0x80

# The aura types this server RESOLVES.  Everything else is shown in the buff frame with
# a real duration and is otherwise inert -- see apply_aura's docstring for why that is
# the honest stopping point rather than a shortcut.
SPELL_AURA_PERIODIC_DAMAGE         = 3
SPELL_AURA_PERIODIC_HEAL           = 8
SPELL_AURA_OBS_MOD_HEALTH          = 20
SPELL_AURA_OBS_MOD_POWER           = 21
SPELL_AURA_PERIODIC_ENERGIZE       = 24
SPELL_AURA_PERIODIC_LEECH          = 53
SPELL_AURA_PERIODIC_MANA_LEECH     = 64
SPELL_AURA_PERIODIC_DAMAGE_PERCENT = 89

AURA_PERIODIC_HARM = (SPELL_AURA_PERIODIC_DAMAGE, SPELL_AURA_PERIODIC_LEECH,
                      SPELL_AURA_PERIODIC_DAMAGE_PERCENT)
AURA_PERIODIC_HELP = (SPELL_AURA_PERIODIC_HEAL, SPELL_AURA_OBS_MOD_HEALTH)
AURA_PERIODIC_POWER = (SPELL_AURA_PERIODIC_ENERGIZE, SPELL_AURA_OBS_MOD_POWER)

# Positivity decides which half of the frame the icon lands in.  Real 3.3.5a runs
# SpellInfo::IsPositiveEffect, several hundred lines of special cases; this archive
# needs only "does the icon go in the buff bar or the debuff bar", so it asks the one
# question that actually answers that: does the aura obviously do the target harm.
AURA_TYPES_NEGATIVE = frozenset((
    SPELL_AURA_PERIODIC_DAMAGE, SPELL_AURA_PERIODIC_LEECH,
    SPELL_AURA_PERIODIC_MANA_LEECH, SPELL_AURA_PERIODIC_DAMAGE_PERCENT,
    5,      # MOD_CONFUSE
    7,      # MOD_FEAR
    12,     # MOD_STUN
    25,     # MOD_PACIFY
    26,     # MOD_ROOT
    27,     # MOD_SILENCE
    33,     # MOD_DECREASE_SPEED
))

# MAX_AURAS is 255 client-side (SpellAuraDefines.h:21), but the 3.3.5a UI only draws 32
# buffs and 16 debuffs, so a slot past that is a slot nobody can see.  56 is the real
# server's own visible-aura working set and is far more than this archive will ever use.
ARCHIVE_MAX_AURA_SLOTS = 56

# How often aura_tick is allowed to do real work.  It is called on EVERY inbound packet
# and the client sends ~178 a second (CMSG_STANDSTATECHANGE alone), so without this the
# tick would run 178 times a second to do nothing 177 of them.  0.1 s keeps a 1000 ms
# HoT accurate to a tenth of a tick.
ARCHIVE_AURA_TICK_MIN = 0.10

# How long the world socket may go completely silent before the session is declared
# dead.  This used to be expressed as a 120 s recv timeout, which conflated "quiet for
# a moment" with "gone" -- and that conflation is what forced auras to be clocked off
# client traffic.  The recv timeout is now ARCHIVE_AURA_TICK_MIN and this is the real
# deadline, so a quiet client is still closed at exactly the same point it always was.
ARCHIVE_SESSION_TIMEOUT = 120.0

# WotLK costs are overwhelmingly a PERCENTAGE of base mana rather than a flat number --
# Fireball is "19% of base mana", ManaCost 0 -- so both columns have to be read and
# added.  See power_cost().
POWER_MANA, POWER_RAGE, POWER_FOCUS, POWER_ENERGY = 0, 1, 2, 3

# Pool sizes are ARCHIVE POLICY, not emulation.  Real 3.3.5a reads them from the
# player_classlevelstats SQL table, which has no row for a Tinker and which this
# archive does not have a database for at all.  These land a level 80 on ~14.5k health
# and ~4.5k mana, which is the right order of magnitude for the era and, more to the
# point, makes a 780-mana Deathball visibly move the bar.
ARCHIVE_POOL_BASE        = 60
ARCHIVE_HEALTH_PER_LEVEL = 180
ARCHIVE_MANA_PER_LEVEL   = 55
ARCHIVE_FIXED_POWER      = 100          # rage / focus / energy are 0..100, not a pool
ARCHIVE_REGEN_PCT        = 0.04         # of max power, per regen tick
ARCHIVE_REGEN_INTERVAL   = 5.0          # s -- rides the client's own 5 s ping

# ---- the target dummy --------------------------------------------------------
# Damage needs something to damage.  There is no creature table here and no map,
# so ".dummy" spawns one object out of nothing, AT THE CASTER'S OWN FEET.
# Display 3019 is Creature\Object\WoodenDummy.mdx -- found by scanning ASCENSION's
# own CreatureModelData.dbc for a dummy model and joining it back through
# CreatureDisplayInfo.dbc, rather than trusting a remembered id from a wiki.
# Faction 14 (Monster) is what makes TAB / TargetNearestEnemy pick it up.
#
# DISTANCE 0 IS THE FIX FOR "the dummy spawns but TAB will not target it", and it
# is not arbitrary.  Measured 2026-09-02, one variable at a time:
#
#     .dummy 3019  0 3   -> TAB targets it
#     .dummy 15476 5 3   -> nothing
#     .dummy 15476 5 1   -> nothing
#
# so it is the OFFSET, not the model -- 3019 renders fine, and swapping in the
# player's own displayId does not help.  It is not facing either: the client's
# GetPlayerFacing() reads 5.31605 against a stored o of 5.31605, so five yards
# "in front" really is in front.  The cause is that this archive has no map, no
# ADT and no vmaps, so an offset spawn can only inherit the CASTER's z -- which
# is the ground height where the CASTER stands, not where the dummy lands.  Five
# yards away that is above or below the real terrain, and the client will not
# select a unit it cannot see.  The caster's own position is the one placement
# whose z is known good.  `.dummy <display> <dist> <scale>` overrides all three,
# which is how the above was measured.
ARCHIVE_DUMMY_ENTRY    = 190000
ARCHIVE_DUMMY_DISPLAY  = 3019
ARCHIVE_DUMMY_NAME     = "Archive Target Dummy"
ARCHIVE_DUMMY_SUBNAME  = "Hits it back"
ARCHIVE_DUMMY_FACTION  = 14             # FactionTemplate.dbc: Monster
ARCHIVE_DUMMY_HEALTH   = 200000
ARCHIVE_DUMMY_LEVEL    = 80
ARCHIVE_DUMMY_RESET    = 10.0           # s of not being hit before it heals up
ARCHIVE_DUMMY_DISTANCE = 0.0            # AT the caster -- see the note above
MAX_CREATURE_QUEST_ITEMS = 6            # QueryHandler.cpp writes six either way
_SPELL_DBC   = None                     # (file, mmap, recs, recsize, strblock) | False
_SPELL_CACHE = {}                       # spellId -> info dict | None (misses cached too)
_SPELLS_SENT = {}                       # guid -> the spell-id set the client was last sent

# ---- action bars ------------------------------------------------------------
MAX_ACTION_BUTTONS       = 144          # Player.h:261, "checked in 3.2.0"
ACTION_BUTTON_SPELL      = 0x00
ACTION_BUTTON_ACTION_MAX = 0x00FFFFFF   # the packed action field is 24 bits wide
ACTION_BUTTONS_CLEAR     = 2            # state 2 wipes the bars and carries no slots

# ---- casting -----------------------------------------------------------------
CAST_FLAG_UNKNOWN_9      = 0x00000100   # Spell.h:64 -- the flag SendSpellGo starts from
TARGET_FLAG_NONE         = 0x00000000
SPELL_FAILED_NOT_KNOWN   = 63           # SharedDefines.h:1000; carries no extra payload
SPELL_FAILED_NO_POWER    = 85           # SharedDefines.h:1022; also payload-free

# ---- Ascension CUSTOM opcodes (Extensions.dll extended dispatch table) -------
# Registered in Extensions.dll's opcode->handler map (0x10be3564) via the same API
# as stock opcodes; the client dispatches them through a shared FNV-1a thunk
# (0x102cfe00) that routes by opcode id. 0x9BC = server->client realm-info record;
# its handler RealmInfo::Deserialize (0x102fc6c0) fills the RealmInfo singleton and,
# critically, sets RealmInfo[+0x48] -- the flag the addon-loadability hook checks
# before it will load any LoadOnDemand custom-UI addon. See ascension memory
# "ascension-addon-loadability-gate".
SMSG_REALM_INFO                       = 0x9BC

# 0x58D = server->client "here is the realm's whole config table".  Handler
# 0x10196c90, registered at 0x10198222 (`push 0 / push 0x10196c90 / push 0x58D`).
# NOTE the opcode-name list in ascension-opcodes.txt is MISALIGNED at high
# opcodes -- it calls 0x5B0 "SMSG_UPDATE_CONFIGS", but 0x5B0's handler actually
# fires TRIAL_DEACTIVATE_RESULT.  0x58D is the one that touches the config
# singleton, found by looking for the FNV-1a constant plus a call to the config
# manager (0x101982d0) inside a registered handler.
#
# The handler snapshots and CLEARS all six config maps, then refills them from
# the packet, so one packet carries the entire table.  Wire format, verified
# instruction by instruction:
#
#     for each of 4 sections:
#         u32 count
#         count x { u32 keyLen; keyLen raw bytes (NO nul); <value> }
#
#     section 1 -> map +0x00  value u32   (C_Config.GetIntConfig)
#     section 2 -> map +0x20  value u8    (C_Config.GetBoolConfig)
#     section 3 -> map +0x40  value f32   (C_Config.GetFloatConfig)
#     section 4 -> map +0x60  value f32
#
# Sections 5 and 6 (maps +0x80/+0xa0) are guarded at 0x10197a5e by
#     if (size - rpos < 8) goto epilogue
# so a packet that stops after section 4 unwinds cleanly through the normal exit
# path -- which is why this archive sends exactly four sections.
# Keys are hashed FNV-1a (seed 0x811c9dc5, prime 0x1000193) over the raw bytes
# with no case folding, so they must match the Lua string exactly.
SMSG_UPDATE_CONFIGS                   = 0x58D

# 0x725 = server->client "character-advancement active specialization".  Handler
# 0x10171d90, registered at 0x10172238.  Body is exactly two u32:
#     u32 activeSpecIndex  -> CAContainer[+0x14]   (GetActiveSpecID returns this+1)
#     u32 specSlotCount    -> CAContainer[+0x18]   (upper bound for loadout lookups)
# The handler ALSO does the one-time bootstrap of the client's whole CA state:
# on the first 0x725 of a session ([CASingleton+0x00] still null) it builds the
# per-GUID container from the local player GUID and then calls 0x10173d00, which
# allocates the 0x278-byte pending-build object and stores it at CASingleton+0x24.
#
# That allocation is not optional.  CharacterAdvancement's per-entry visibility
# filter (0x101c6bd0, called from inside GetEntriesByClass) does, for every entry
# whose flags(+0x124) have bit 19 set:
#       state = [CASingleton+0x24]          ; 0x101722e0 -> 0x1016fdc0
#       hit   = state->find(entry->id)      ; 0x10152920: mov edx,[ecx+0x24] ...
#       if (!hit) return HIDDEN
# With no 0x725 ever sent, state is NULL and that `mov edx,[ecx+0x24]` faults on
# 0x00000024 -- the ERROR #132 the client threw the moment realm-flavour bytes
# made any bit-19 entry reachable.  Sending 0x725 once at world entry is what the
# live realm does, and it both fixes the crash and makes the trees enumerable.
SMSG_CA_ACTIVE_SPEC                   = 0x725

# CMSG_BUILD_ACTIVATE (0x5C2) -- what C_BuildCreator.ActivateBuild(buildID, true, true)
# ACTUALLY puts on the wire.  The old handoff recorded that this call "emits nothing";
# that was wrong.  It emits, and the archive had already captured it as an unknown
# opcode (world_unhandled_w003_5C2.bin, 39 bytes) without recognising it.
#
# The binding is C_BuildCreator.ActivateBuild -> 0x10101740 (name string 0x10b2e6d0,
# bound in the table written at 0x1010df63).  Reading it straight through:
#   0x101017bf  call 0x10309e50   -- a validation on arg 1; if it returns 0 the whole
#                                    function bails at 0x101017c9 and returns false
#                                    WITHOUT sending.  That is the only silent path.
#   0x101017df  call 0x84f9f0     -- lua_tolstring(arg 1): the build ID is a STRING
#   0x101018a0  push 0x5c2        -- packet constructor; this is the opcode
#   0x101018bb  0x10087390 / 0x100b97a0   -- append the id as a CString
#   0x101018d7  [0x10bc90dc](&b, 1) x2    -- append the two booleans, one byte each
#   0x1010190d  send
# So the body is:
#     CString buildID   -- a 36-char UUID, e.g. "1ef4bae3-780c-444c-833f-ecf46149de94"
#     u8      arg2      -- the first `true`
#     u8      arg3      -- the second `true`
# 36 + 1 + 1 + 1 = 39, exactly the captured length.
#
# The archive answers it the way an activated build is actually observable: a build IS
# a set of learned entries, so applying one means applying its entry list and
# re-sending SMSG_CA_KNOWN_ENTRIES (0x726).  Contents live in builds.json -- Ascension
# stores builds server-side and that store did not survive, so the archive keeps its
# own, populated with ".build save <id>" from the current .known set.  An unknown id
# is reported, never guessed at.
CMSG_BUILD_ACTIVATE                   = 0x5C2

# ---- Build Creator / Archetypes (0x62E..0x631) -------------------------------
#
# THESE WERE MISNAMED AS THE GAME-MODE QUERY UNTIL 2026-09-02.  They are the Build
# Creator list/detail pair, and the rename is backed by four measurements:
#
#   * C_BuildCreator.QueryAllBuilds("Featured") puts 9 bytes on the wire as 0x62E,
#     "Leveling" 9, and 0 -> 2.  Always len(arg)+1, always right after the Lua call.
#   * C_BuildCreator.QueryBuild("abc-123") sends 0x630 with exactly b"abc-123" + NUL.
#   * The string "BUILD_CREATOR_CATEGORY_RESULT" is referenced from 0x100ff999, inside
#     0x62F handler 0x100ff530; "BUILD_CREATOR_BUILD_RESULT" from 0x100ff485, inside
#     0x631 handler 0x100ff200.
#   * All four register from one block, 0x1010124a..0x1010130b.
#
# The old note was not careless -- it saw four 0x62E queries for "BuildDraft" after the
# Hero Architect opened, and "BuildDraft" is BOTH a game-mode name AND
# Enum.BuildCategory.BuildDraft.  Nothing could break that tie without driving
# QueryAllBuilds by hand.  The rest of that analysis stands: game-mode state really does
# live in the static struct at 0x10be4138, nothing Lua-visible reads the 0x62F record
# vector as a game mode, and the Archetypes tab is gated on C_Player:IsHero().
#
# 0x62F body, per handler 0x100ff530:
#     CString category      -- echoed back; the client keys its pending request on it
#     u32     chunkIndex    -- 0 wipes the existing record vector first (0x100ff5fb:
#                              walk [mgr+0x148]..[mgr+0x14c] in 0x138-byte strides,
#                              destruct each, reset end=begin)
#     u32     chunkCount    -- NOT a version.  0x100ff8bb does `dec eax` on it and
#                              compares with chunkIndex: BUILD_CREATOR_CATEGORY_RESULT
#                              fires ONLY on the last chunk, i.e. chunkIndex==count-1.
#     u32     recordCount   -- records in THIS chunk; 0 skips the record loop
#     recordCount x build record (0x138 bytes each, deserializer 0x100f9330)
#
# So the honest empty answer is (0, 1, 0) -- one chunk, no builds -- and NOT (0, 0, 0),
# which is what this file used to send.  (0, 0, 0) left the client comparing -1 with 0,
# so the event never fired, the panel never left its loading state, and nothing was
# logged on either side.
CMSG_BUILD_QUERY_CATEGORY             = 0x62E
SMSG_BUILD_CATEGORY_RESULT            = 0x62F
CMSG_BUILD_QUERY                      = 0x630
SMSG_BUILD_RESULT                     = 0x631

# SMSG_BUILD_ACTIVATE_RESULT (0x5C3) -- the reply CMSG_BUILD_ACTIVATE never had.
# It registers at site 0x1010124a, one slot below the rest of the Build Creator
# family, and handler 0x100fde70 reads ONE CString and nothing else before firing
#     FireEvent("BUILD_CREATOR_ACTIVATE_RESULT", "%s", status)      -- 0x100fdf23
# Without it BuildCreatorMixin:BUILD_CREATOR_ACTIVATE_RESULT never runs, so
# HideLoading() is never called: the build applies server-side and the panel spins
# on its loading spinner forever.  The addon compares the status against exactly one
# value, "ACTIVATE_BUILD_OK" (BuildCreator.lua:758); every other status is rendered
# as `_G[result] or result`, so an unknown key falls back to its own text and the
# status doubles as a global-string lookup.
SMSG_BUILD_ACTIVATE_RESULT            = 0x5C3

# SMSG_BUILD_ACTIVE_BUILD_UPDATE (0x632) -- "this build is now the active one for
# spec N".  Without it the build applies but the UI never learns it is active:
# BuildCreatorUtil.GetActiveBuildID reads C_BuildCreator.GetActiveBuild(specID),
# which is fed only by this packet, so the Activate button never becomes Deactivate
# and the ActiveBuild category stays empty.  Handler 0x100fdfd0; element reader
# 0x100fc950.  Body: u32 spec, CString buildID, u8, u8.
SMSG_BUILD_ACTIVE_BUILD_UPDATE        = 0x632

# The spec slot to mark.  This is a RAW VECTOR INDEX, and it is 0-based, while the
# Lua accessor over the same vector is 1-based: sending 1 put the id where
# C_BuildCreator.GetActiveBuild(2) could see it, and left GetActiveBuild(1) -- the
# one BuildCreatorUtil.GetActiveBuildID actually reads, because
# SpecializationUtil.GetActiveSpecialization() answers 1 -- still empty.  So the
# character's first (and, on the archive, only) specialization is index 0.
ARCHIVE_ACTIVE_SPEC = 0

# SMSG_CA_ESSENCE_BUDGET (0x722, handler 0x101dd510) -- the real source of the essence
# numbers the Character Advancement panel prints.  Ascension's own FrameXML does
#     -- GetItemCount hackfix for Character Advancement. Requires proper fix later
#     function GetItemCount(...)
#         if itemID == ItemData.ABILITY_ESSENCE then
#             return C_CharacterAdvancement.GetRemainingAE() or 0
#         elseif itemID == ItemData.TALENT_ESSENCE then ... GetRemainingTE() ...
#         return _GetItemCount(...)
#     end
# (Interface\FrameXML\Util\GlobalOverwrites.lua:447), so a *numeric* GetItemCount for
# either essence id never reaches the bags at all -- essence is not really a bag item.
# GetRemainingAE (0x1017aa10) -> CAState::RemainingAE (0x10153a90) is
#     max(0, TotalAE(state) - SpentAE(state))
# and TotalAE (0x10153190) / ExpectedAE (0x101530b0) both scan the record store at
# 0x10bdfc78 (maxIdx) / 0x10bdfc7c (minIdx) / 0x10bdfc8c (rows), which THIS opcode
# fills.  One 36-byte record per packet, nine u32s, in this exact order (derived from
# the reader's sequential ByteBuffer reads and the row writes at 0x101dd5b5, and
# cross-checked against the 0x24-byte malloc on the insert path at 0x101dd5f0):
#     u32 id             -- row[+0x00], the store index
#     u32 level          -- row[+0x04], matched against the queried level
#     u32 key            -- row[+0x08], must equal state[+0x14]
#     u32 flagA          -- row[+0x0C], (!=0) must equal state[+0x18]
#     u32 flagB          -- row[+0x10], (!=0) must equal state[+0x19]
#     u32 flagC          -- row[+0x14], (!=0) must equal state[+0x1a]
#     u32 flagD          -- row[+0x18], (!=0) must equal (state[+0x2c] != 0)
#     u32 abilityEssence -- row[+0x1c], returned by ExpectedAE / TotalAE
#     u32 talentEssence  -- row[+0x20], returned by ExpectedTE / TotalTE (0x10153331)
#
# WHERE THAT "state" COMES FROM, and why it is not the empty struct it was assumed to
# be.  GetRemainingAE calls a getter (0x1016f390) that does NOT return a CA state
# directly: it looks the local player's CA *record* up in a static manager
# (0x10bde440, returned by 0x101722e0), then returns that record's ACTIVE SPEC:
#     record[+0x08 .. +0x0c]  vector<CAState*>          (0x10149480 indexes it)
#     record[+0x14]           active spec index         (0x10149470)
#     record[+0x18]           spec-count limit
#     -> state = record.specs[record.activeIndex], or the static empty state at
#        0x10bde8a8 when there is no such spec.
# Read live out of the running client (read-only RPM), the active state holds
#     key(+0x14) = 10, flagA/B/C(+0x18,+0x19,+0x1a) = 0/0/0, (+0x2c) = 0 -> flagD 0,
#     level(+0x30) = 80  -- the character's REAL level, not 0
# so the row this client reads its budget from is level 80 / key 10 / all flags clear,
# which is CharacterAdvancementEssence.dbc row id 80: AE 140, TE 71.
#
# Two things follow, and both were wrong here before:
#   * key 10 is a real family; key 0 does not exist anywhere in the DBC (its key
#     column runs 1..32), so archive rows sent with key 0 can never match; and
#   * the client LOADS that DBC itself at startup -- the store already holds all 5600
#     rows at their own ids before a single packet arrives.  Synthetic rows numbered
#     level*16+combo therefore land on ids 0..1375, which is not empty space: it
#     overwrites 1344 real rows, INCLUDING the whole key-10 family at ids 1..80.  The
#     archive was deleting the very numbers it was trying to supply, which is why the
#     panel reported 0 essence and ".essence 500" changed nothing.
# So this server now replays the client's own DBC verbatim -- same ids, levels, keys
# and flags -- which repairs any earlier damage, matches whatever the CA state asks
# for without having to know it, and carries Ascension's real curve.
SMSG_CA_ESSENCE_BUDGET                = 0x722

# 0x726 = server->client "these are the character-advancement entries you know".
# Handler 0x10171260, registered at 0x10172249 -- the entry right after 0x725 in the
# same CA registration block (0x1017222c..0x101722d7), which holds the whole CA
# opcode family: 0x659, 0x65b, 0x6e2, 0x725, 0x726, 0x728..0x72c.
#
# The body is a length-prefixed vector, read by 0x10166760 straight off the
# ByteBuffer.  Element stride in memory is 0x20, but only 21 bytes of each are on
# the wire -- the sequential reads at 0x101668b0..0x10166900 fill exactly the fields
# the element constructor (0x10150020) zero-initialises, and nothing else:
#     u32 entryId    -> rec[+0x04]   the CharacterAdvancement.dbc entry ID; the map key
#     u32 rank       -> rec[+0x08]   copied to store[+0x0C] at 0x10171523
#     u32 unk0C      -> rec[+0x0C]
#     u8  flag       -> rec[+0x10]   diffed against the old state GetFlag (0x10155640)
#     u32 unk18      -> rec[+0x18]
#     u32 unk1C      -> rec[+0x1C]
# rec[+0x00] is set by the constructor and never read from the wire; rec[+0x14] is
# pure padding after the byte.  So: u32 count, then count * 21 bytes.
#
# The handler does not merely store the vector -- it DIFFS it against the state the
# client already holds and fires one Lua event per change:
#     ASCENSION_KNOWN_ENTRY_UPDATED  ("%u%u" of id, rank)  entry added or re-ranked
#     ASCENSION_ENTRY_UPDATED        ("%u"   of id)
#     ASCENSION_KNOWN_ENTRY_REMOVED  ("%u"   of id)        entry no longer in the set
#     ASCENSION_KNOWN_ENTRIES_UPDATED                      once, after the whole diff
# so re-sending the FULL set is the supported way to change it; the client works out
# the deltas itself.  This is what C_CharacterAdvancement.IsKnownID and
# GetTalentRankByID answer from -- 0x10a31720 / 0x10a31bb0 walk the resident
# 0x2C-stride store, matching id at +0x00 and returning rank from +0x0C -- and so it
# is what makes a node in the tree draw as learned instead of greyed out.
#
# ORDERING MATTERS.  At 0x10171376 the handler looks up the per-GUID CA container and,
# if it is missing, allocates the pending build (0x10173d00) and returns without
# applying anything.  0x725 is what builds that container at world entry, so 0x726
# has to follow it -- which is also the order the live realm uses.
SMSG_CA_KNOWN_ENTRIES                 = 0x726

# CMSG_CA_KNOWN_ENTRIES (0x727) -- the client half of a learn OR an unlearn.  It is
# the mirror of the server's 0x726 in both shape and MEANING: the client uploads its
# COMPLETE known-entry set, not the entries that just changed.
#
# MEASURED, not guessed.  On a character with an empty known set,
# C_CharacterAdvancement.LearnID(1189) emitted one 25-byte 0x727 (count = 1) and
# returned `true, nil, nil, nil, nil`.  UnlearnID(1189) then emitted a 4-byte 0x727
# with count = 0 -- it did not name 1189 anywhere.  A delta could not express that
# removal, so the payload is the whole set and the handler must REPLACE.
#
# Reading it as a delta is the subtle failure: every learn still looks right, and
# only unlearns silently do nothing, leaving the server holding entries the client
# has already dropped.
#
#     u32 count, then `count` records of the SAME 21 bytes as SMSG_CA_KNOWN_ENTRIES:
#         u32 entryId | u32 rank | u32 unk0C | u8 flag | u32 unk18 | u32 unk1C
#
# The one captured record was 1189, rank 1, unk0C 1, flag 0, unk18 0x6A974E8F,
# unk1C 0.  unk18 is wall-clock Unix seconds at the moment of the click (it matched
# the capture time), so it is a "learned at" stamp rather than anything the server
# has to interpret; unk0C was 1 here where the server's own 0x726 sends 0, and one
# sample is not enough to name it, so both are logged and otherwise ignored.
#
# LearnID is NOT a single-node operation.  It first walks a path to the requested
# node and learns everything on the way, which is why it can fail with
# OPTIMIZE_FOR_TRAVERSAL_FAILED naming a DIFFERENT entry than the one asked for --
# the failure the archive hit for a long time, because the imported known set was a
# Tinker build while this realm hands out class 10 (Hero), and every Tinker node on
# the path fails CALearnWrongClassHook.  A batch of several records is therefore
# normal and the handler must apply all of them, not just the first.
#
# The client applies the learn locally BEFORE sending, so no reply is required for
# the UI to update.  Re-sending 0x726 is still the right answer: it is what makes
# the server the authority, and it drags the spellbook along (send_known_entries ->
# sync_spellbook), which is what grants the spell with no relog.
CMSG_CA_KNOWN_ENTRIES_UPLOAD          = 0x727

AUTH_OK = 0x0C
EXPANSION_WOTLK = 2

# ResponseCodes (SharedDefines.h) -- verified against the on-disk AzerothCore source
CHAR_CREATE_SUCCESS   = 0x2F
CHAR_CREATE_ERROR     = 0x30
CHAR_CREATE_NAME_IN_USE = 0x32
CHAR_DELETE_SUCCESS   = 0x47
CHAR_DELETE_FAILED    = 0x48
CHAR_LOGIN_FAILED     = 0x51

# update-object constants (wire-ref.md, extracted from AzerothCore 3.3.5a)
UPDATETYPE_VALUES = 0
UPDATETYPE_CREATE_OBJECT = 2
UPDATETYPE_CREATE_OBJECT2 = 3
TYPEID_ITEM = 1
TYPEID_UNIT = 3
TYPEID_PLAYER = 4
UPDATEFLAG_SELF, UPDATEFLAG_LOWGUID = 0x01, 0x10
UPDATEFLAG_LIVING, UPDATEFLAG_STATIONARY = 0x20, 0x40
TYPEMASK_ITEM = 0x03                    # OBJECT|ITEM = 1|2
TYPEMASK_UNIT = 0x09                    # OBJECT|UNIT = 1|8
TYPEMASK_PLAYER = 0x19                  # OBJECT|UNIT|PLAYER = 1|8|16
UNIT_END = 148                          # m_valuesCount for a Creature -> 5 mask blocks
PLAYER_END = 1326                       # m_valuesCount for a Player -> 42 mask blocks
ITEM_END = 64                           # m_valuesCount for an Item  -> 2 mask blocks

# UpdateFields.h indices, read off C:\AzerothRealm\src (OBJECT_END=6, UNIT_END=148)
OBJECT_FIELD_GUID, OBJECT_FIELD_TYPE, OBJECT_FIELD_ENTRY, OBJECT_FIELD_SCALE_X = 0, 2, 3, 4
ITEM_FIELD_OWNER, ITEM_FIELD_CONTAINED, ITEM_FIELD_CREATOR = 6, 8, 10
ITEM_FIELD_STACK_COUNT, ITEM_FIELD_FLAGS = 14, 21
ITEM_FIELD_DURABILITY, ITEM_FIELD_MAXDURABILITY = 60, 61
UNIT_FIELD_FACTIONTEMPLATE = 55
UNIT_FIELD_FLAGS = 59                   # OBJECT_END + 0x35
UNIT_FIELD_DISPLAYID, UNIT_FIELD_NATIVEDISPLAYID = 67, 68
UNIT_FIELD_BOUNDINGRADIUS, UNIT_FIELD_COMBATREACH = 65, 66
UNIT_FIELD_BASEATTACKTIME = 62          # [2]
UNIT_DYNAMIC_FLAGS = 79
UNIT_NPC_FLAGS = 82
UNIT_FIELD_BASE_MANA, UNIT_FIELD_BASE_HEALTH = 120, 121
PLAYER_FLAGS = 150
PLAYER_FIELD_PACK_SLOT_1 = 370          # backpack slot 0; 16 slots, 2 dwords each
REST_STATE_NORMAL = 2                   # PLAYER_BYTES_2 byte3; 1 = rested, 2 = normal
# UNIT_FIELD_BYTES_1 byte0 is the stand state (1 SIT, 2..6 chairs, 8 KNEEL); bytes
# 1..3 are pet talent points, vis flags and anim tier, all 0 for a player.
UNIT_FIELD_BYTES_1 = 74
STAND_STATE_STAND = 0
PLAYER_FLAGS_GM = 0x00000008

# HighGuid::Item = 0x4000 in the top word; items carry no entry in the guid.
HIGHGUID_ITEM = 0x4000 << 48
# HighGuid::Unit = 0xF130, and a creature guid DOES carry its entry:
#     ObjectGuid.h:135  counter | (entry << 24) | (high << 48)
# which is why the client can ask CMSG_CREATURE_QUERY for an entry it has only
# ever seen inside a guid.
HIGHGUID_UNIT = 0xF130 << 48

# ---- ability / talent essence ------------------------------------------------
# Ascension's character-advancement UI reads these as bag items:
#     CharacterAdvancement.lua:1266  GetItemCount(ItemData.ABILITY_ESSENCE)
#     CharacterAdvancement.lua:1267  GetItemCount(ItemData.TALENT_ESSENCE)
# and the two entry ids come from that shipped UI source...
#
# ...but the bag is not where the CoA panel looks.  Ascension's own shipped
# Interface\FrameXML\Util\GlobalOverwrites.lua (line 447) overrides the
# global GetItemCount and short-circuits exactly these two entries to
# C_CharacterAdvancement.GetRemainingAE() / GetRemainingTE(), which read a
# client-side record store that only SMSG_CA_ESSENCE_BUDGET (0x722) fills.  The
# archive hands out matching bag stacks anyway so the item half of the UI (bags,
# tooltips, /script GetItemCount) agrees with the panel.
ITEM_ABILITY_ESSENCE = 383080
ITEM_TALENT_ESSENCE  = 383081

# Essence budget table (SMSG_CA_ESSENCE_BUDGET).  TotalAE looks up the row for the
# character's CURRENT level, so these are CUMULATIVE totals, not per-level grants --
# RemainingAE = total - alreadySpent, which is why spending in the panel decrements
# correctly on its own.  The curve is Ascension's own rather than something invented
# here: the live server streams this opcode straight out of
# CharacterAdvancementEssence.dbc, and the archive replays the copy that ships in
# the client's own MPQs.  See load_essence_rows() / essence_curve().
ESSENCE_DBC = _first_existing(
    os.path.join(CA_REF_DIR, "ca-dbc", "DBFilesClient_CharacterAdvancementEssence.dbc"),
    os.path.join(CA_REF_DIR, "ca-dbc", "CharacterAdvancementEssence.dbc"))
ESSENCE_DBC_KEY = 10                    # measured: the archive client's state[+0x14]
ESSENCE_OVERRIDE = None                 # (ae, te) from ".essence <n>"; None = real curve

# ".essprobe" support.  The essence family a client reads is a property of its CA
# state, not of this server, and getting it wrong is silent -- every number just reads
# 0.  This probe sends one row per (key, flagCombo) with the pair ENCODED into the
# essence value, so a single GetExpectedAE read names the family that matched.  It
# writes only ids >= ESSPROBE_ID_BASE, well clear of the DBC's own 1..6366, because
# the store is pre-loaded and a reused id destroys a real row.
# Answer for this archive client, measured 2026-09-01: key 10, all flags clear.
ESSPROBE_ID_BASE  = 20000               # far above the DBC's max id (6366): no clobber
ESSPROBE_KEYS     = range(0, 64)        # the DBC uses 1..32; the slack is deliberate


def essprobe_encode(key, combo):
    """AE for the probe row.  +1 keeps a match from looking like "no match at all"."""
    return key * 16 + combo + 1


def essprobe_decode(ae):
    """Inverse of essprobe_encode -> (key, combo), or None if this is not a probe hit."""
    if not ae:
        return None
    v = ae - 1
    return (v // 16, v % 16)

# GM level.  This is not AzerothCore -- there is no account/security table and no
# command handler in the core sense -- so "GM level 3" here means two things:
#   1. PLAYER_FLAGS_GM is set on the player, which is what the CLIENT keys off (GM
#      chat tag, .gm-style UI affordances, and it stops treating the player as a
#      normal unit for a few checks).
#   2. the dot-command handler below is enabled, giving the archive-useful subset.
# Set to 0 to get a plain player back.
ARCHIVE_GM_LEVEL = 3

CHAT_MSG_SYSTEM = 0x00                  # SharedDefines.h ChatMsg
CHAT_MSG_WHISPER = 0x07
LANG_UNIVERSAL  = 0
LANG_ADDON      = 0xFFFFFFFF            # the marker that makes the client route a
                                        # chat packet to CHAT_MSG_ADDON instead of
                                        # printing it in a chat frame
UNIT_FIELD_LEVEL = 54
# race | class | gender | power, one byte each.  The class byte in here is what
# UnitClass reads AND what the CoA entry filter tests -- see the CA class-types
# note below.
UNIT_FIELD_BYTES_0 = 23

# Minimal ItemTemplates for the two essences.  The CA panel draws its own hardcoded
# icon (CharacterAdvancementTemplates.xml:71 SetIcon "inv_custom_abilityessence"), so
# DisplayInfoID only matters for the bag slot; name/quality/stack drive everything the
# panel and the tooltip actually show.  Class 15/SubClass 0 = Miscellaneous/Junk.
ITEM_TEMPLATES = {
    ITEM_ABILITY_ESSENCE: {
        "name": "Ability Essence", "quality": 4, "stackable": 1000000,
        "description": "Spent to learn abilities in the Character Advancement panel.",
    },
    ITEM_TALENT_ESSENCE: {
        "name": "Talent Essence", "quality": 4, "stackable": 1000000,
        "description": "Spent to learn talents in the Character Advancement panel.",
    },
}

OPNAME = {
    0x036: "CMSG_CHAR_CREATE", 0x037: "CMSG_CHAR_ENUM", 0x038: "CMSG_CHAR_DELETE",
    0x03A: "SMSG_CHAR_CREATE", 0x03B: "SMSG_CHAR_ENUM", 0x03C: "SMSG_CHAR_DELETE",
    0x03D: "CMSG_PLAYER_LOGIN", 0x041: "SMSG_CHARACTER_LOGIN_FAILED",
    0x042: "SMSG_LOGIN_SETTIMESPEED", 0x050: "CMSG_NAME_QUERY",
    0x051: "SMSG_NAME_QUERY_RESPONSE", 0x0A9: "SMSG_UPDATE_OBJECT",
    0x095: "CMSG_MESSAGECHAT",
    0x0FD: "SMSG_TUTORIAL_FLAGS", 0x101: "CMSG_STANDSTATECHANGE",
    0x29D: "SMSG_STANDSTATE_UPDATE",
    0x122: "SMSG_INITIALIZE_FACTIONS", 0x129: "SMSG_ACTION_BUTTONS",
    0x128: "CMSG_SET_ACTION_BUTTON",
    0x12A: "SMSG_INITIAL_SPELLS", 0x12B: "SMSG_LEARNED_SPELL",
    0x12C: "SMSG_SUPERCEDED_SPELL", 0x12E: "CMSG_CAST_SPELL",
    0x12F: "CMSG_CANCEL_CAST", 0x130: "SMSG_CAST_FAILED",
    0x132: "SMSG_SPELL_GO", 0x480: "SMSG_POWER_UPDATE",
    0x150: "SMSG_SPELLHEALLOG", 0x250: "SMSG_SPELLNONMELEEDAMAGELOG",
    0x136: "CMSG_CANCEL_AURA", 0x24E: "SMSG_PERIODICAURALOG",
    0x495: "SMSG_AURA_UPDATE_ALL", 0x496: "SMSG_AURA_UPDATE",
    0x060: "CMSG_CREATURE_QUERY", 0x061: "SMSG_CREATURE_QUERY_RESPONSE",
    0x0AA: "SMSG_DESTROY_OBJECT",
    0x203: "SMSG_REMOVED_SPELL", 0x155: "SMSG_BINDPOINTUPDATE",
    0x1CE: "CMSG_QUERY_TIME", 0x1CF: "SMSG_QUERY_TIME_RESPONSE",
    0x1DC: "CMSG_PING", 0x1DD: "SMSG_PONG", 0x1EC: "SMSG_AUTH_CHALLENGE",
    0x1ED: "CMSG_AUTH_SESSION", 0x1EE: "SMSG_AUTH_RESPONSE",
    0x1F6: "SMSG_COMPRESSED_UPDATE_OBJECT",
    0x04B: "CMSG_LOGOUT_REQUEST", 0x04C: "SMSG_LOGOUT_RESPONSE",
    0x04D: "SMSG_LOGOUT_COMPLETE", 0x04E: "CMSG_LOGOUT_CANCEL",
    0x04F: "SMSG_LOGOUT_CANCEL_ACK",
    0x209: "SMSG_ACCOUNT_DATA_TIMES", 0x20A: "CMSG_REQUEST_ACCOUNT_DATA",
    0x20B: "CMSG_UPDATE_ACCOUNT_DATA", 0x20C: "SMSG_UPDATE_ACCOUNT_DATA",
    0x463: "SMSG_UPDATE_ACCOUNT_DATA_COMPLETE",
    0x236: "SMSG_LOGIN_VERIFY_WORLD", 0x26A: "CMSG_SET_ACTIVE_MOVER",
    0x2EF: "SMSG_ADDON_INFO", 0x2C2: "SMSG_INIT_WORLD_STATES", 0x33D: "SMSG_MOTD",
    0x38B: "SMSG_REALM_SPLIT", 0x38C: "CMSG_REALM_SPLIT",
    0x390: "SMSG_TIME_SYNC_REQ", 0x391: "CMSG_TIME_SYNC_RESP",
    0x3C9: "SMSG_FEATURE_SYSTEM_STATUS", 0x41E: "SMSG_SEND_UNLEARN_SPELLS",
    0x4AB: "SMSG_CLIENTCACHE_VERSION", 0x4FF: "CMSG_READY_FOR_ACCOUNT_DATA_TIMES",
    0x58D: "SMSG_UPDATE_CONFIGS",
    0x9BC: "SMSG_REALM_INFO",
    0x725: "SMSG_CA_ACTIVE_SPEC", 0x726: "SMSG_CA_KNOWN_ENTRIES",
    0x727: "CMSG_CA_KNOWN_ENTRIES(upload)",
    0x5C2: "CMSG_BUILD_ACTIVATE", 0x5C3: "SMSG_BUILD_ACTIVATE_RESULT",
    0x632: "SMSG_BUILD_ACTIVE_BUILD_UPDATE",
}

# ---- world header crypt constants (AuthCrypt.cpp) ---------------------------
SERVER_ENC_SEED = bytes.fromhex("cc98ae04e897eaca12ddc09342915357")   # S->C
SERVER_DEC_SEED = bytes.fromhex("c2b3723cc6aed9b5343c53ee2f4367ce")   # C->S

# fixed, logged challenge seed so every run is reproducible and digest math checkable
AUTH_SEED = bytes.fromhex("11223344")        # authSeed / serverSeed (raw 4 bytes)
CHALLENGE_TAIL = bytes(32)                    # two 16-byte "encryption seeds" (client ignores)

WORLD_KEY_OFFSET = 0x140                      # authobj+0x140 = 40-byte world SessionKey
WORLD_KEY_LEN = 40

# ---- addon-info reply constants (WorldSession.cpp SendAddonsInfo) ------------
STANDARD_ADDON_CRC = 0x4C1C776D
MAX_ACCOUNT_TUTORIAL_VALUES = 8
ADDON_PUBKEY = bytes.fromhex(
    "c35b5084b93e32428cd0c748fa0e5d545aa30e14ba9e0db95d8beeb684934575"
    "ff31fe2f643f3d6d07d9449b408559344e10e1e74369ef7c16fcb4ed1b9528a8"
    "2376513157302b790850101c4a1a2cc88b8f052d223ddb5a247a0f1350378f5a"
    "cc9e04440e8701d4a315941634c6c2c3fb49fee1f9da8c503cbe2cbb57ed46b9"
    "ad8bc6df0ed60fbe80b38b1e77cfad22cfb74bcffbf06b11452d7a8118f2927e"
    "98565d5e69720a0d030a85a2859ccbfb566e8f44bb8f0222686397bc85baa8f7"
    "b540683c77866f4bd788ca8ad7ce36f0456ed564790f17fc64dd106ff3f5e0a6"
    "c3fb1b8c29ef8ee534cbd12ace79c39a0d36ea01e0aa912054f072d81ec789d2")
assert len(ADDON_PUBKEY) == 256, len(ADDON_PUBKEY)


LOG_MAX_BYTES = 64 * 1024 * 1024        # one previous run is kept as .1


def rotate_log():
    """Roll world_server_log.txt over once at startup if it has grown past the cap.

    This log is verbose by design -- every packet in both directions -- and one long
    session reached 140 MB, at which point every `grep` over it and every tail-the-log
    helper became slow enough to change how the work was done.  Rotating keeps exactly
    two files: the current run and the one before it."""
    try:
        if os.path.exists(LOG) and os.path.getsize(LOG) > LOG_MAX_BYTES:
            os.replace(LOG, LOG + ".1")
    except Exception:
        pass                                # a locked log is not worth failing boot over


def log(msg):
    line = "[%s] %s" % (time.strftime("%H:%M:%S"), msg)
    print(line, flush=True)
    try:
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


# ---- RC4 (ARC4) with running state ------------------------------------------
class RC4:
    def __init__(self, key):
        S = list(range(256)); j = 0
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) & 0xFF
            S[i], S[j] = S[j], S[i]
        self.S = S; self.i = 0; self.j = 0

    def crypt(self, data):
        S = self.S; i = self.i; j = self.j; out = bytearray(len(data))
        for n, b in enumerate(data):
            i = (i + 1) & 0xFF
            j = (j + S[i]) & 0xFF
            S[i], S[j] = S[j], S[i]
            out[n] = b ^ S[(S[i] + S[j]) & 0xFF]
        self.i = i; self.j = j
        return bytes(out)


def make_crypt(session_key40):
    enc = RC4(hmac.new(SERVER_ENC_SEED, session_key40, hashlib.sha1).digest())
    dec = RC4(hmac.new(SERVER_DEC_SEED, session_key40, hashlib.sha1).digest())
    enc.crypt(bytes(1024))            # drop 1024
    dec.crypt(bytes(1024))            # drop 1024
    return enc, dec


# ---- passive RPM: read the 40-byte world SessionKey -------------------------
def read_world_key():
    """Return (pid, objptr, key40, key32) for the live client, else None."""
    for pid in R.find_pids():
        base = R.module_base(pid)
        if not base:
            continue
        h = R._open(pid)
        if not h:
            continue
        try:
            raw = R._read(h, base + R.STATIC_OBJ_SLOT_RVA, 4)
            if not raw:
                continue
            objptr = int.from_bytes(raw, "little")
            if not objptr:
                continue
            key40 = R._read(h, objptr + WORLD_KEY_OFFSET, WORLD_KEY_LEN)
            key32 = R._read(h, objptr + R.K_OFFSET_IN_OBJ, 32)
            if key40:
                return (pid, objptr, key40, key32)
        finally:
            R.k32.CloseHandle(h)
    return None


# ---- packet framing ---------------------------------------------------------
def build_challenge():
    body = struct.pack("<I", 1) + AUTH_SEED + CHALLENGE_TAIL        # 4 + 4 + 32 = 40
    size = 2 + len(body)                                            # opcode(2) + body
    return struct.pack(">H", size) + struct.pack("<H", SMSG_AUTH_CHALLENGE) + body


def recv_exact(conn, n):
    buf = b""
    while len(buf) < n:
        try:
            b = conn.recv(n - len(buf))
        except (socket.timeout, OSError):
            return None
        if not b:
            return None
        buf += b
    return buf


def frame_pkt(enc, opcode, body):
    """The exact bytes send_pkt would put on the socket, without sending them.

    Split out of send_pkt so a burst can be framed once and written once.  enc is a
    stream cipher, so framing N packets in order and writing the concatenation is
    byte-identical to N separate sends -- TCP was going to coalesce them anyway."""
    size = len(body) + 2                                            # opcode(2) + body
    if size > 0x7FFF:
        hdr = bytes([0x80 | ((size >> 16) & 0xFF), (size >> 8) & 0xFF, size & 0xFF,
                     opcode & 0xFF, (opcode >> 8) & 0xFF])
    else:
        hdr = bytes([(size >> 8) & 0xFF, size & 0xFF, opcode & 0xFF, (opcode >> 8) & 0xFF])
    if enc is not None:
        hdr = enc.crypt(hdr)
    return hdr + body


# Sends get their OWN deadline, separate from the receive poll.
#
# handle_client() polls the session socket with conn.settimeout(ARCHIVE_AURA_TICK_MIN)
# (0.1 s) so the idle clock can run between packets.  A Python socket timeout is not
# receive-only: it binds sendall() too, and sendall() applies it to the WHOLE write.
# The client stops draining its socket for whole seconds right after world entry
# (map load, then 36 addons initialising and chattering on their channels), so a
# write that lands in that window sits in a full send buffer, 100 ms pass, sendall()
# raises, and the session dies as
#
#     w001: <- CMSG_QUERY_TIME                  (0 B body)
#     w001: handler error TimeoutError('timed out')
#
# a few seconds into the world: the last inbound opcode is logged, there is no
# outbound line after it (send_pkt logs AFTER the write), and the client sits on
# a dead socket.  Any write can trip it -- the one that did was the 12-byte
# SMSG_QUERY_TIME_RESPONSE, not the 224 KB essence burst that had just gone out.
# Whether it trips at all depends on how long that machine's client stalls, which
# is why one install never saw it and another hit it on every login.
#
# Fix: every write goes through sock_sendall(), which raises the timeout to
# ARCHIVE_SEND_TIMEOUT for the duration of the write and puts the poll timeout
# back afterwards.  A client that cannot accept a packet within 30 s is gone, and
# then the session SHOULD die.
ARCHIVE_SEND_TIMEOUT = 30.0


def sock_sendall(conn, buf):
    """conn.sendall(buf) with the send deadline, restoring the poll timeout after."""
    prev = conn.gettimeout()
    if prev is None or prev >= ARCHIVE_SEND_TIMEOUT:
        conn.sendall(buf)
        return
    conn.settimeout(ARCHIVE_SEND_TIMEOUT)
    try:
        conn.sendall(buf)
    finally:
        conn.settimeout(prev)


def send_pkt(conn, enc, opcode, body):
    """Send an S->C packet: header + plaintext body.
    enc is an RC4 state to encrypt the header, or None for a PLAINTEXT header.
    This Ascension client keeps world headers UNENCRYPTED through char-select
    (proven by raw capture: it sends plaintext CMSG_PING), so enc is normally None."""
    sock_sendall(conn, frame_pkt(enc, opcode, body))
    log("        -> %-28s (%d B body%s)"
        % (OPNAME.get(opcode, "0x%03X" % opcode), len(body), "" if enc is None else ", ENC"))


def send_batch(conn, enc, pkts, label):
    """Write a whole run of packets as ONE sendall, and log ONE line for it.

    The essence table is 5600 packets.  As 5600 sendall calls with 5600 log lines it
    was both the slowest thing this server does and the reason world_server_log.txt
    reached 8.8 MB in an evening -- a real login was 5600 lines of "-> 0x722 (36 B
    body)" with the interesting packets buried between them."""
    if not pkts:
        return 0
    buf = b"".join(frame_pkt(enc, opc, body) for opc, body in pkts)
    sock_sendall(conn, buf)
    log("        -> %-28s (%d packets, %d B, one write)" % (label, len(pkts), len(buf)))
    return len(pkts)


# ---- CMSG_AUTH_SESSION parse (unencrypted header) ---------------------------
def parse_auth_session(body):
    f = {}
    p = 0
    def u32():
        nonlocal p; v = struct.unpack_from("<I", body, p)[0]; p += 4; return v
    def u64():
        nonlocal p; v = struct.unpack_from("<Q", body, p)[0]; p += 8; return v
    f["build"] = u32()
    f["loginServerID"] = u32()
    z = body.index(b"\x00", p); f["account"] = body[p:z]; p = z + 1
    f["loginServerType"] = u32()
    f["localChallenge"] = body[p:p + 4]; p += 4          # clientSeed (raw 4 bytes)
    f["regionID"] = u32()
    f["battlegroupID"] = u32()
    f["realmID"] = u32()
    f["dosResponse"] = u64()
    f["digest"] = body[p:p + 20]; p += 20
    f["addon_raw"] = body[p:]
    f["addon_len"] = len(f["addon_raw"])
    return f


def verify_digest(f, key40):
    h = hashlib.sha1()
    h.update(f["account"])
    h.update(b"\x00\x00\x00\x00")
    h.update(f["localChallenge"])       # clientSeed
    h.update(AUTH_SEED)                  # serverSeed
    h.update(key40)
    return h.digest() == f["digest"]


# ---- SMSG builders ----------------------------------------------------------
# RealmInfo flag cluster (+0x40..+0x47).  Each byte is one realm "flavour"
# boolean.  Mapping proved by disassembling Extensions.dll: the C_Realm Lua
# bindings are one-line getters over these bytes --
#     +0x40 -> 0x102fc660 -> C_Realm.IsLive
#     +0x41 -> 0x102fc6b0 -> C_Realm.IsSeasonal
#     +0x42 -> 0x102fc650 -> C_Realm.IsLeague
#     +0x43 -> 0x102fc670 -> C_Realm.IsPTR
#     +0x44 -> 0x102fc640 -> C_Realm.IsDevelopment
#     +0x46 -> 0x102fc630 -> no Lua binding; the CoA realm-kind bit (see below)
#     +0x47 -> 0x102fc6a0 -> no Lua binding; the Wildcard realm-kind bit
#   C_Realm.IsProduction = 0x102fc680 = (+0x40 || +0x41 || +0x42)
#
# This is NOT cosmetic.  CharacterAdvancement::IsEntryVisible (0x101c6cc0) --
# the per-entry filter inside GetEntriesByClass (0x10177050) -- ends with:
#     if (entry[+0x128] && IsLive)     return true;   // available on live
#     if (entry[+0x129] && IsSeasonal) return true;
#     if (entry[+0x12a] && IsLeague)   return true;
#     if (entry[+0x12b] && IsPTR)      return true;
#     if (!entry[+0x12c])              return false;
#     return IsDevelopment;
# so with every flavour byte zero NO entry is ever visible, GetEntriesByClass
# returns an empty vector for all 161 class/tab pairs, and TalentTreeBaseMixin:
# BuildTree() (which iterates exactly that call) draws nothing.  Sending the
# realm's true flavour is what makes the CA / CoA trees populate.
# +0x46 and +0x47 are not flavour trivia -- they decide what KIND of character the
# creation screen makes, and they are mutually exclusive with "Hero":
#     C_CharacterCreate.CanCreateCoA()  (0x1018d6c0) = [+0x46] || [+0x44]
#     C_CharacterCreate.CanCreateWCR()  (0x1018d760) = [+0x47] || [+0x44]
#     C_CharacterCreate.CanCreateHero() (0x1018d710) = !([+0x46] || [+0x47])
# so +0x46 says "this is a Character-of-Ascension realm", +0x47 is its Wildcard
# counterpart, and IsDevelopment (+0x44) unlocks CoA and WCR creation without
# taking Hero away -- which is exactly how a dev realm should behave.
#
# The same pair is read by the character-advancement record filter at 0x101c6810
# and 0x101c6d21, which collapses them into one "is this a plain Hero realm" bool
#     dl = IsDevelopment || !([+0x46] || [+0x47])
# and compares it against each record's own flag, so the realm kind also selects
# which advancement records the client treats as available.
#
# GlueXML/CharacterCreate.lua (the 101 KB custom copy in patch-B.MPQ) settles
# which kind this archive has to claim -- lines 12-13 and CharacterCreate_OnShow:
#
#     function C_CharacterCreate.CanCreateArchetype()
#         return GetRealmName() == "Area 52 - Free-Pick"
#            and C_Config.GetBoolConfig("CONFIG_CHARACTER_CREATION_ARCHETYPES_ENABLED")
#     end
#
#     if C_CharacterCreate.CanCreateHero() then
#         SetSelectedClass(HERO_CLASS_ID); SetCharacterClass(HERO_CLASS_ID)
#         if C_CharacterCreate.CanCreateArchetype() then
#             CharCreateArchetypeFrame:GoToIndex(Enum.CharCreateArchetypeBases.UseArchetype)
#         else
#             CharCreateArchetypeFrame:GoToIndex(Enum.CharCreateArchetypeBases.Freepick)
#         end
#     end
#
# The archetype wizard (Role -> Subrole -> Archetype) is therefore the FREE-PICK
# path: it only runs when CanCreateHero() is true, i.e. when +0x46 and +0x47 are
# BOTH zero.  "Hero" (class 10) is not a mis-classification to escape -- it is
# the class every Free-Pick character has, and the archetype is an extra creation
# step that seeds its starting abilities, not a different class.
#
# That looks like a straight either/or -- Free-Pick + archetypes, or the fixed
# COA_CLASS_ORDER list, never both -- until you read the top of
# CharacterCreate_RefreshClassButtons (line 1462), which has a fourth branch:
#
#     CharCreateSwapClassesButton:SetShown(
#         C_Realm.IsDevelopment() and isCoA and (isClassicClass or canCreateHero))
#
#     if isCoA and isClassicClass then
#         local _, _, classIndex = GetSelectedClass()
#         if classIndex == Enum.Class.HERO            then ShowFreepickClasses(self)
#         elseif classIndex >= Enum.Class.CustomStart then ShowCoAClasses(self)
#         else                                             ShowRegularClasses(self)
#         end
#     elseif isCoA then ... elseif isClassicClass then ... elseif canCreateHero then ...
#
# and CharacterCreate_SwapClasses() (line 1783) cycles FREEPICK -> REGULAR ->
# COA -> FREEPICK.  IsDevelopment (+0x44) satisfies the CoA and Wildcard tests on
# its own WITHOUT setting +0x46/+0x47, so a development realm gets all three at
# once: isCoA, isClassicClass and canCreateHero are all true, the swap button
# appears, and creation opens on the Free-Pick/archetype panel (because
# CharacterCreate_OnShow force-selects HERO_CLASS_ID whenever CanCreateHero())
# with the 21 CoA classes and the 10 classic classes one click away.
#
# The same byte also widens the advancement-record filter -- dl = IsDevelopment ||
# !([+0x46] || [+0x47]) is true again, so records that a CoA-only realm hides
# (Tinker and the other late CoA releases) come back -- and it is simply the
# truthful description of this realm: a single-player development copy.  So the
# archive advertises LIVE + IsDevelopment, and answers the other two archetype
# gates directly: the realm is named "Area 52 - Free-Pick" in the realmlist
# (shim3799.py), and CONFIG_CHARACTER_CREATION_ARCHETYPES_ENABLED arrives in
# SMSG_UPDATE_CONFIGS (0x58D) during the post-auth burst.
# The realm's own name is a gate too: CanCreateArchetype() compares GetRealmName()
# (Ascension.exe 0x00510e00 -> the "realmName" CVar, "Last realm connected to")
# against the literal "Area 52 - Free-Pick".  That CVar is written from the realm
# LIST, so shim3799.py has to advertise this exact string; RealmInfo's own copy is
# set to match so nothing in the UI disagrees about which realm this is.
ARCHIVE_REALM_NAME = "Area 52 - Free-Pick"

#                     +0x40 +0x41 +0x42 +0x43 +0x44 +0x45 +0x46 +0x47
#                      Live                     Dev         CoA   WCR
REALM_FLAVOUR_LIVE = (1, 0, 0, 0, 0, 0, 0, 0)     # a normal production Hero realm
REALM_FLAVOUR_COA  = (1, 0, 0, 0, 0, 0, 1, 0)     # production + CoA character creation
REALM_FLAVOUR_WCR  = (1, 0, 0, 0, 0, 0, 0, 1)     # production + Wildcard creation
REALM_FLAVOUR_DEV  = (1, 0, 0, 0, 1, 0, 0, 0)     # production + development unlocks
ARCHIVE_REALM_FLAVOUR = REALM_FLAVOUR_DEV


def smsg_realm_info(realm_name=ARCHIVE_REALM_NAME, realm_type=2, gate=1,
                    valid_tag=11, flags=None,
                    field18=0, trailing=0):
    """SMSG_REALM_INFO (0x9BC) body, byte-exact for RealmInfo::Deserialize
    (Extensions.dll 0x102fc6c0). Field -> RealmInfo offset map verified by disasm:
        u32 valid_tag  -> +0x04  (==11 sets +0x49 'valid' marker)
        u32 realm_type -> +0x08  (0/1/2 -> level cap 60/70/80)
        f32 x3         -> +0x0c/+0x10/+0x14
        u32 field18    -> +0x18  (stored as bool)
        f32 x2         -> +0x1c/+0x20
        u32 (0)        -> +0x24
        u8  x8 flags   -> +0x40..+0x47  (realm-flavour cluster; see above)
        cstr realm     -> +0x28  (realm name std::string)
        cstr (empty)   -> +0x4c  (second std::string)
        u8  gate       -> +0x48  *** addon-loadability GATE; nonzero = OPEN ***
        u32 trailing   -> +0x64  (optional tail; we always include it)
    """
    flags = ARCHIVE_REALM_FLAVOUR if flags is None else flags
    body  = struct.pack("<I", valid_tag)
    body += struct.pack("<I", realm_type)
    body += struct.pack("<fff", 0.0, 0.0, 0.0)
    body += struct.pack("<I", field18)
    body += struct.pack("<ff", 0.0, 0.0)
    body += struct.pack("<I", 0)
    body += bytes(flags[:8]).ljust(8, b"\x00")
    body += realm_name.encode("utf-8") + b"\x00"
    body += b"\x00"
    body += bytes([gate & 0xFF])
    body += struct.pack("<I", trailing)
    return body


# ---- SMSG_UPDATE_CONFIGS ----------------------------------------------------
# Ascension's realm config table, as the live server would push it at login.
# Only keys the archive has actually verified belong here: the handler CLEARS
# every map before refilling, so anything omitted reads back nil -- which is the
# same thing the client sees today, and therefore the safe default.  Turning on a
# feature whose packets this archive does not serve would be worse than leaving
# it off, so the table grows one verified key at a time.
ARCHIVE_CONFIG_INT = {}                  # map +0x00, C_Config.GetIntConfig
ARCHIVE_CONFIG_BOOL = {
    # GlueXML/CharacterCreate.lua:13 -- the second half of CanCreateArchetype().
    # With this true and the realm named "Area 52 - Free-Pick", character
    # creation opens on Enum.CharCreateArchetypeBases.UseArchetype and the
    # Role -> Subrole -> Archetype steps join CHAR_CREATE_STEPS_EXTEND.
    "CONFIG_CHARACTER_CREATION_ARCHETYPES_ENABLED": True,
}
ARCHIVE_CONFIG_FLOAT = {}                # map +0x40, C_Config.GetFloatConfig
ARCHIVE_CONFIG_FLOAT2 = {}               # map +0x60, second float map


def _config_section(entries, pack_value):
    """One config section: u32 count, then count x {u32 keyLen, key, value}.

    The key is written raw and UNTERMINATED -- the handler mallocs keyLen bytes,
    memcpys them, and advances rpos by exactly keyLen (0x1019783d..0x1019785b),
    so a trailing NUL would land inside the key and change its FNV hash."""
    out = struct.pack("<I", len(entries))
    for key, value in entries.items():
        kb = key.encode("utf-8")
        out += struct.pack("<I", len(kb)) + kb + pack_value(value)
    return out


def smsg_update_configs(ints=None, bools=None, floats=None, floats2=None):
    """SMSG_UPDATE_CONFIGS (0x58D) body -- four sections, then stop.

    Stopping after section 4 is deliberate and legal: 0x10197a5e checks
    `size - rpos >= 8` before section 5 and falls through to the epilogue when
    the packet is exhausted, so the client destroys its map snapshots and
    returns normally instead of reading past the end."""
    body = _config_section(ARCHIVE_CONFIG_INT if ints is None else ints,
                           lambda v: struct.pack("<I", int(v) & 0xFFFFFFFF))
    body += _config_section(ARCHIVE_CONFIG_BOOL if bools is None else bools,
                            lambda v: bytes([1 if v else 0]))
    body += _config_section(ARCHIVE_CONFIG_FLOAT if floats is None else floats,
                            lambda v: struct.pack("<f", float(v)))
    body += _config_section(ARCHIVE_CONFIG_FLOAT2 if floats2 is None else floats2,
                            lambda v: struct.pack("<f", float(v)))
    return body


def smsg_ca_active_spec(active_index=0, spec_slots=1):
    """SMSG_CA_ACTIVE_SPEC (0x725) body -- two u32, read in this order by
    0x10171e23..0x10171e3b.  Also fires the Lua event
    ASCENSION_CA_SPECIALIZATION_ACTIVE_ID_CHANGED with (active_index + 1)."""
    return struct.pack("<II", active_index, spec_slots)


def smsg_ca_known_entries(records):
    """SMSG_CA_KNOWN_ENTRIES (0x726) body -- u32 count, then 21 bytes per record in
    the order 0x101668b0..0x10166900 reads them.  See the opcode note up top.

    `records` is a sequence of (entryId, rank, unk0C, flag, unk18, unk1C); the
    helper below fills the four unknowns with the constructor default of 0, which
    is what a plainly-known entry looks like."""
    out = struct.pack("<I", len(records))
    for entry_id, rank, unk0c, flag, unk18, unk1c in records:
        out += struct.pack("<IIIBII", entry_id & 0xFFFFFFFF, rank & 0xFFFFFFFF,
                           unk0c & 0xFFFFFFFF, flag & 0xFF,
                           unk18 & 0xFFFFFFFF, unk1c & 0xFFFFFFFF)
    return out


def parse_cmsg_ca_known_entries(body):
    """CMSG_CA_KNOWN_ENTRIES (0x727) -> [(entryId, rank, unk0c, flag, unk18, unk1c)].

    Same 21-byte record as smsg_ca_known_entries writes.  A short or ragged tail is
    truncated rather than raising: a half-read packet should cost the records it
    could not parse, not the connection."""
    if len(body) < 4:
        return []
    count = struct.unpack_from("<I", body, 0)[0]
    out, off = [], 4
    for _ in range(min(count, (len(body) - 4) // 21)):
        entry_id, rank, unk0c = struct.unpack_from("<III", body, off)
        flag = body[off + 12]
        unk18, unk1c = struct.unpack_from("<II", body, off + 13)
        out.append((entry_id, rank, unk0c, flag, unk18, unk1c))
        off += 21
    return out


def smsg_char_enum_empty():
    return bytes([0])                    # uint8 count = 0 (no characters)

def smsg_realm_split(unk_bytes):
    return unk_bytes + struct.pack("<I", 0) + b"01/01/01\x00"

def smsg_pong(ping_bytes):
    return ping_bytes                    # echo the ping sequence (u32)

def smsg_account_data_times(mask, times):
    """u32 gametime | u8 1 | u32 mask | u32 time  (one per set bit, ascending).

    AzerothCore sends this twice per session: GLOBAL_CACHE_MASK from
    HandleReadyForAccountDataTimes (char-select) and PER_CHARACTER_CACHE_MASK
    from HandlePlayerLogin.  For each advertised type the client compares our
    timestamp against its own WTF cache file and asks for anything newer.

    We used to send mask=0 here.  That is a well-formed packet and the client
    accepts it happily -- it simply means "the server has no account data", so
    the client asks for nothing and comes up with an empty binding set: no
    movement keys, no ESC menu, no action bars.  Advertising the real mask is
    what makes a fresh character playable, and it is exactly what the live
    realm does."""
    out = struct.pack("<I", int(time.time())) + bytes([1]) + struct.pack("<I", mask)
    for t in times:
        out += struct.pack("<I", t)
    return out

def smsg_update_account_data(guid, atype, tstamp, raw):
    """u64 guid | u32 type | u32 time | u32 uncompressed-len | zlib(raw).

    Mirrors WorldSession::HandleRequestAccountData.  `raw` is the literal text
    of the matching *-cache.wtf file; the client writes it back out verbatim."""
    import zlib
    return (struct.pack("<Q", guid) + struct.pack("<III", atype, tstamp, len(raw))
            + (zlib.compress(raw, 9) if raw else b""))

def smsg_clientcache_version(v=0):
    return struct.pack("<I", v)

def smsg_tutorial_flags():
    return struct.pack("<I", 0) * MAX_ACCOUNT_TUTORIAL_VALUES        # 8 * u32(0) = 32 zero bytes

def build_addon_info(addon_raw):
    """Reproduce WorldSession::SendAddonsInfo for the client's addon list.
    Blob: u32 uncompressedSize | zlib( u32 count | {cstr name,u8 enabled,u32 crc,u32 unk}* | u32 time )."""
    import zlib
    out = bytearray()
    naddon = 0
    if len(addon_raw) >= 4:
        try:
            raw = zlib.decompress(addon_raw[4:])
            q = 0
            count = struct.unpack_from("<I", raw, q)[0]; q += 4
            for _ in range(count):
                z = raw.index(b"\x00", q); q = z + 1                 # cstr name (value unused in reply)
                enabled = raw[q]; q += 1
                crc = struct.unpack_from("<I", raw, q)[0]; q += 4
                q += 4                                               # unk1
                out += bytes([2])                                    # State = 2
                out += bytes([1])                                    # UsePublicKeyOrCRC = true
                usepk = 1 if crc != STANDARD_ADDON_CRC else 0
                out += bytes([usepk])
                if usepk:
                    out += ADDON_PUBKEY                              # 256 bytes
                out += struct.pack("<I", 0)                          # unk
                out += bytes([0])                                    # unk3 = 0
                naddon += 1
        except Exception as e:
            log("        addon-info parse failed (%r) -> sending empty list" % e)
            out = bytearray()
            naddon = 0
    out += struct.pack("<I", 0)                                      # banned addon count = 0
    return bytes(out), naddon


# ---- character persistence (characters.json) --------------------------------
# db = { account_str: [ char_dict, ... ] }.  Single-player archive: a tiny flat
# JSON store is plenty and keeps the created character across restarts.
def load_chars():
    try:
        with open(CHARS_PATH, "r", encoding="utf-8") as fp:
            return json.load(fp)
    except Exception:
        return {}

def save_chars(db):
    try:
        tmp = CHARS_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fp:
            json.dump(db, fp, indent=2)
        os.replace(tmp, CHARS_PATH)
    except Exception as e:
        log("        !! save_chars failed: %r" % e)

# ---- account-data persistence (accountdata.json) ----------------------------
# { "global": { account: { type: {time,data} } },
#   "chars":  { guid:    { type: {time,data} } } }
# Global types (config/bindings/macros) are shared by every character on the
# account; the rest are per character.  Types are stringified because JSON
# object keys are strings.
def load_acctdata():
    try:
        with open(ACCTDATA_PATH, "r", encoding="utf-8") as fp:
            db = json.load(fp)
    except Exception:
        db = {}
    db.setdefault("global", {})
    db.setdefault("chars", {})
    return db

def save_acctdata(db):
    try:
        tmp = ACCTDATA_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fp:
            json.dump(db, fp, indent=2)
        os.replace(tmp, ACCTDATA_PATH)
    except Exception as e:
        log("        !! save_acctdata failed: %r" % e)

def _acct_bucket(db, account, guid, atype):
    if GLOBAL_CACHE_MASK & (1 << atype):
        return db["global"].setdefault(str(account), {})
    return db["chars"].setdefault(str(guid), {})

def acctdata_get(account, guid, atype):
    rec = _acct_bucket(load_acctdata(), account, guid, atype).get(str(atype))
    if not rec:
        return 0, b""
    return int(rec.get("time", 0)), rec.get("data", "").encode("utf-8")

def acctdata_set(account, guid, atype, tstamp, data):
    db = load_acctdata()
    _acct_bucket(db, account, guid, atype)[str(atype)] = {"time": int(tstamp),
                                                          "data": data}
    save_acctdata(db)

def acctdata_times(account, guid, mask):
    db = load_acctdata()
    out = []
    for i in range(NUM_ACCOUNT_DATA_TYPES):
        if mask & (1 << i):
            rec = _acct_bucket(db, account, guid, i).get(str(i))
            out.append(int(rec.get("time", 0)) if rec else 0)
    return out

def acctdata_seed_bindings(account, guid):
    """Hand a never-before-seen account/character the archive's default keymap.

    The live realm has years of saved bindings for a returning player; a fresh
    archive account has none, and an unbound WoW client cannot move, open the
    ESC menu or press an action button -- it is not playable at all.  So the
    first time we are asked for an account's (or a character's) binding cache we
    fill it from realms/ascension/default-bindings.wtf, a byte copy of the
    "Name" character's own profile.

    Seeded once and only once per key: as soon as the player rebinds anything
    the client uploads CMSG_UPDATE_ACCOUNT_DATA and that stored value wins
    forever after.  Delete the entry from accountdata.json to re-seed."""
    try:
        with open(DEFAULT_BINDINGS_PATH, "r", encoding="utf-8") as fp:
            text = fp.read()
    except Exception as e:
        log("        !! default-bindings.wtf unreadable (%r) -- not seeding" % e)
        return []
    db, seeded = load_acctdata(), []
    for atype in (GLOBAL_BINDINGS_CACHE, PER_CHARACTER_BINDINGS_CACHE):
        if atype == PER_CHARACTER_BINDINGS_CACHE and not guid:
            continue
        bucket = _acct_bucket(db, account, guid, atype)
        if str(atype) not in bucket:
            bucket[str(atype)] = {"time": int(time.time()), "data": text}
            seeded.append(ACCOUNT_DATA_NAMES[atype])
    if seeded:
        save_acctdata(db)
        log("        seeded default keymap (%d B) for %s"
            % (len(text), ", ".join(seeded)))
    return seeded

def next_guid(db):
    hi = 0
    for chars in db.values():
        for c in chars:
            hi = max(hi, int(c["guid"]))
    return hi + 1


# ---- wire helpers -----------------------------------------------------------
def u32le(v):  return struct.pack("<I", v & 0xFFFFFFFF)
def f32le(v):  return struct.pack("<f", v)
def mstime():  return int(time.time() * 1000) & 0xFFFFFFFF

def pack_guid(guid):
    """3.3.5 packed GUID: 1 mask byte (bit i set = byte i nonzero) then nonzero bytes LSB->MSB."""
    mask = 0
    parts = bytearray()
    for i in range(8):
        b = (guid >> (8 * i)) & 0xFF
        if b:
            mask |= (1 << i)
            parts.append(b)
    return bytes([mask]) + bytes(parts)

def packed_calendar_time():
    """SMSG_LOGIN_SETTIMESPEED packed time (ByteBuffer::AppendPackedTime layout)."""
    lt = time.localtime()
    wow_wday = (lt.tm_wday + 1) % 7                       # C/WoW: 0=Sunday; Python: 0=Monday
    return (((lt.tm_year - 2000) & 0x1F) << 24) | ((lt.tm_mon - 1) << 20) \
        | ((lt.tm_mday - 1) << 14) | (wow_wday << 11) | (lt.tm_hour << 6) | lt.tm_min

def build_values_block(fields, field_count=None):
    """fields: {fieldIndex: 4-byte value}. Returns u8 blockCount, mask u32*, then
    the set values in ascending field-index order (UpdateMask wire form).
    field_count sizes the mask to the object's full m_valuesCount (as the real
    server does: updateMask.SetCount(m_valuesCount)); defaults to just covering
    the highest set field."""
    need = (max(fields) // 32) + 1
    nblocks = max(need, (field_count + 31) // 32) if field_count else need
    mask = [0] * nblocks
    for idx in fields:
        mask[idx // 32] |= (1 << (idx % 32))
    out = bytearray([nblocks])
    for m in mask:
        out += struct.pack("<I", m)
    for idx in sorted(fields):
        out += fields[idx]
    return bytes(out)


# ---- character-flow SMSG builders -------------------------------------------
def smsg_char_create(result):
    return bytes([result])

def smsg_char_delete(result):
    return bytes([result])

def smsg_char_enum(chars):
    out = bytearray([len(chars)])
    for c in chars:
        out += struct.pack("<Q", int(c["guid"]))
        out += c["name"].encode("utf-8") + b"\x00"
        out += bytes([c["race"] & 0xFF, c["class"] & 0xFF, c["gender"] & 0xFF,
                      c["skin"] & 0xFF, c["face"] & 0xFF, c["hairStyle"] & 0xFF,
                      c["hairColor"] & 0xFF, c["facialHair"] & 0xFF, c["level"] & 0xFF])
        out += struct.pack("<I", c["zone"])
        out += struct.pack("<I", c["map"])
        out += struct.pack("<fff", c["x"], c["y"], c["z"])
        out += struct.pack("<I", 0)                        # guildId
        out += struct.pack("<I", 0)                        # charFlags
        out += struct.pack("<I", 0)                        # customizationFlag
        out += bytes([0])                                  # firstLogin (0 = no intro cinematic)
        out += struct.pack("<I", 0)                        # petDisplayId
        out += struct.pack("<I", 0)                        # petLevel
        out += struct.pack("<I", 0)                        # petFamily
        for _ in range(23):                                # INVENTORY_SLOT_BAG_END = 23
            out += struct.pack("<I", 0)                    #   displayId
            out += bytes([0])                              #   inventoryType
            out += struct.pack("<I", 0)                    #   enchant aura id
    return bytes(out)

def smsg_login_verify_world(c):
    return struct.pack("<I", c["map"]) + struct.pack("<ffff", c["x"], c["y"], c["z"], c["o"])

def smsg_login_settimespeed():
    return struct.pack("<I", packed_calendar_time()) + struct.pack("<f", 0.01666667) + struct.pack("<I", 0)

def smsg_send_unlearn_spells():
    return struct.pack("<I", 0)                            # count = 0

def smsg_time_sync_req(counter=0):
    return struct.pack("<I", counter)

def smsg_bindpoint_update(c):
    return struct.pack("<fff", c["x"], c["y"], c["z"]) + struct.pack("<I", c["map"]) + struct.pack("<I", c["zone"])

def smsg_motd(*lines):
    out = struct.pack("<I", len(lines))
    for ln in lines:
        out += ln.encode("utf-8") + b"\x00"
    return out

def smsg_name_query_response(c):
    out = bytearray()
    out += pack_guid(int(c["guid"]))
    out += bytes([0])                                      # name is known
    out += c["name"].encode("utf-8") + b"\x00"
    out += bytes([0])                                      # cross-realm name (empty)
    out += bytes([c["race"] & 0xFF, c["gender"] & 0xFF, c["class"] & 0xFF])
    out += bytes([0])                                      # declined names present = 0
    return bytes(out)

def smsg_query_time_response():
    return struct.pack("<I", int(time.time())) + struct.pack("<I", 0)


def smsg_system_message(text):
    """SMSG_MESSAGECHAT carrying one CHAT_MSG_SYSTEM line -- the default branch of
    ChatHandler::BuildChatPacket with no GM tag and no channel name, so sender and
    target guids are both zero.  This is how the dot-commands answer."""
    b = text.encode("utf-8")
    out = bytearray()
    out += bytes([CHAT_MSG_SYSTEM])
    out += struct.pack("<I", LANG_UNIVERSAL)
    out += struct.pack("<Q", 0)                    # senderGuid
    out += struct.pack("<I", 0)                    # "2.1.0" unk dword
    out += struct.pack("<Q", 0)                    # targetGuid
    out += struct.pack("<I", len(b) + 1)
    out += b + b"\x00"
    out += bytes([0])                              # chatTag = CHAT_TAG_NONE
    return bytes(out)


def smsg_addon_whisper(guid, text):
    """SMSG_MESSAGECHAT carrying one addon message back to the player who sent it.

    Ascension's UI uses SendAddonMessage(prefix, msg, "WHISPER", <self>) as a decoupled
    event bus between its own addons -- opening the Collections "Archetypes" tab fires
    ASC_PATH_TO_ASCENSION / ACTION_OPEN_HERO_ARCHITECT that way.  That is not a local
    call: the client hands the message to the server and only fires CHAT_MSG_ADDON when
    the server hands it back, so an emulator that swallows addon whispers leaves every
    listener waiting forever.

    Player::Whisper (Player.cpp:9669) is the exact behaviour being copied:
        ChatHandler::BuildChatPacket(data, CHAT_MSG_WHISPER, language, this, this, text);
        target->SendDirectMessage(&data);
        if (isAddonMessage) return;          // no CHAT_MSG_WHISPER_INFORM echo
    -- note "this, this": the packet names the SENDER as both sender and target, and
    only the receiving session gets it.  CHAT_MSG_WHISPER takes BuildChatPacket's
    default branch (Chat.cpp:430), so there is no sender-name and no channel field:
    just the two guids, then the message.  `text` is the raw "PREFIX\tMESSAGE" the
    client sent, which is how 3.3.5 puts an addon message on the wire."""
    b = text.encode("utf-8")
    out = bytearray()
    out += bytes([CHAT_MSG_WHISPER])
    out += struct.pack("<I", LANG_ADDON)
    out += struct.pack("<Q", guid)                 # senderGuid
    out += struct.pack("<I", 0)                    # "2.1.0" unk dword
    out += struct.pack("<Q", guid)                 # targetGuid (Whisper passes `this`)
    out += struct.pack("<I", len(b) + 1)
    out += b + b"\x00"
    out += bytes([0])                              # chatTag = CHAT_TAG_NONE
    return bytes(out)


def build_values_update(guid, fields, field_count):
    """SMSG_UPDATE_OBJECT body with a single UPDATETYPE_VALUES block -- used to change
    fields on an object the client already has (a stack count, a level) without
    re-creating it."""
    blk = bytearray()
    blk += bytes([UPDATETYPE_VALUES])
    blk += pack_guid(guid)
    blk += build_values_block(fields, field_count)
    return struct.pack("<I", 1) + bytes(blk)


def smsg_build_category_result(category, records=(), chunk=0, chunks=1):
    """Answer to CMSG_BUILD_QUERY_CATEGORY.

    `records` is a sequence of already-serialised build records.  The defaults are the
    empty answer -- chunk 0 of 1, no builds.  chunks MUST be at least 1: the client only
    raises BUILD_CREATOR_CATEGORY_RESULT when chunkIndex == chunks-1, so a 0 there is
    swallowed in silence.  See the opcode note up top."""
    body = category.encode("utf-8") + b"\x00"
    body += struct.pack("<III", chunk, max(1, chunks), len(records))
    for r in records:
        body += r
    return body


# The BuildCategory enum, read straight out of the client's own name table at
# 0x10b1c288 (an array of {const char *, size_t}).  Enum.BuildCategory in Lua also
# carries Featured, MyBuilds, ActiveBuild and History, but none of those four ever
# reach the wire: BuildCreator.lua:184..195 rewrites Featured and MyBuilds to None
# plus a local filter, History reads a bookmark list, and ActiveBuild jumps straight
# to QueryBuild.  These fourteen are the whole wire vocabulary.
BUILD_CATEGORY_IDS = {
    "None": 0,                  "Leveling": 1,
    "Level60PvE": 2,            "Level60PvP": 3,
    "Level60PvPvE": 4,          "Level70PvE": 5,
    "Level70PvP": 6,            "Level70PvPvE": 7,
    "BuildDraft": 8,            "Archived": 9,
    "BuildDraftEndGamePvE": 10, "BuildDraftEndGamePvP": 11,
    "Broken": 12,               "Max": 13,
}

# A BARE icon name, no path: every consumer prefixes "Interface\\Icons\\"
# itself (BuildView.lua:70 and :223, BuildViewSection.lua:124,
# BuildListItem.lua:52, CategoryListItem.lua:45), so a full path here comes
# back as a doubled Interface\\Icons\\Interface\\Icons\\... miss, which the
# client records in Logs\\MissingFiles.txt and draws as an empty circle.
BUILD_DEFAULT_ICON = "INV_Misc_QuestionMark"

# PLAYER_ROLE_DAMAGE.  Roles is a bit flag -- 1 LEADER, 2 TANK, 4 HEALER,
# 8 DAMAGE -- measured by round-tripping values through GetBuild().Roles.
# 0 comes back as PLAYER_ROLE_NONE, which is NOT a key of Enum.BuildRoles, and
# BuildViewMixin:SetBackground concatenates that nil into a texture path
# unguarded (BuildView.lua:657).  Because SetBackground runs BEFORE
# SetBuildInfo, a role-less record renders with no name, author or icon and
# raises an interface error.  Never send 0.
BUILD_DEFAULT_ROLE = 8


def _bstr(s):
    """A build record field: NUL-terminated UTF-8, never length-prefixed."""
    return ("" if s is None else str(s)).encode("utf-8", "replace") + b"\x00"


def smsg_build_spell(spell_id, level=1, comment="", flags=0):
    """One entry of a build record's Spells vector.

    0x28 bytes in the client's struct.  Element deserialiser 0x100f6180 reads, in
    this order, and C_BuildCreator.GetBuild() hands every one of them back to Lua
    under these names:

        0x00 u32     Spell      -- a REAL spell id.  BuildSpell.lua:19 feeds it to
                                   GetSpellInfo and C_CharacterAdvancement
                                   .IsKnownSpellID, so a CA entry id here draws a
                                   blank row.  ca_entry_spell() is the converter.
        0x04 u32     Level      -- the character level the build takes it at, not a
                                   rank (BuildSpell.lua:435 PlaceHeldSpellAtLevel).
        0x08 u8 x 4  IsCoreAbility / IsOptimalAbility / IsSynergisticAbility /
                     IsEmpoweringAbility -- four badges on the row.  All four names
                     are confirmed; which byte is which is NOT, because every one of
                     them was sent as 0.  Measure before using them.
        0x0c u32     Flags
        0x10 CString Comment    -- shows as a notes icon on the row.

    An entry learned past rank 1 is a different spell, and the Build Creator record
    has nowhere to say so, hence the rank goes in Comment rather than being lost."""
    return struct.pack("<II4BI",
                       int(spell_id) & 0xFFFFFFFF,
                       int(level) & 0xFFFFFFFF,
                       0, 0, 0, 0,
                       int(flags) & 0xFFFFFFFF) + _bstr(comment)


def build_spell_rows(build):
    """A stored build's entries as (spellId, level, comment) triples.

    Entries whose spell cannot be resolved are dropped, exactly as ca_known_spells
    drops them -- handing the client an id Spell.dbc does not have is what leaves a
    row blank instead of erroring."""
    out = []
    for r in build_rows(build):
        sid, _row = ca_entry_spell(r["id"], r["rank"])
        if not sid:
            continue
        out.append((sid, 1, "" if r["rank"] <= 1 else "Rank %d" % r["rank"]))
    return out


BUILD_CLASS_HERO = 10          # ChrClasses.dbc row 10, name "Hero", token "HERO"


def build_filter_class(class_type_id):
    """A CA entry's ClassTypeID -> the number a build record carries at +0x60.

    That number is the character class byte, and ClassTypes.required already IS the
    class byte -- class_type_matches (the client's own MatchesClass) tests
    `class_byte == ct["required"]` and falls back to `class_byte == 10` for a row
    flagged classic.  So every classic row answers 10 (Hero / Free-Pick, the only
    character that can learn classic entries a la carte) and a custom class answers
    its own byte, Tinker 28 and so on.  Rows with no required byte -- None,
    ConquestOfAzeroth, RebornGeneral -- are group markers and get no vote.
    """
    try:
        ctid = int(class_type_id)
    except (TypeError, ValueError):
        return None
    for ct in CLASS_TYPES:
        if int(ct["id"]) != ctid:
            continue
        req = int(ct["required"])
        if req:
            return req
        return BUILD_CLASS_HERO if ct["classic"] else None
    return None

def build_class_of(build, fallback=None):
    """The class a stored build belongs to, in the record's +0x60 numbering.

    Voted from the build's own entries through build_filter_class, so a Tinker build
    reads 28 and a build of classic entries reads HERO.  builds.json may pin it with
    an explicit "class".  With nothing to vote on it falls back to HERO rather than
    to the querying character's class byte: the two numberings differ, and the only
    character that can see this panel at all is a Hero."""
    if "class" in (build or {}):
        return int(build["class"]) & 0xFFFFFFFF
    votes = {}
    idx = ca_entry_index()
    for r in build_rows(build):
        row = idx.get(r["id"])
        if not row:
            continue
        c = build_filter_class(row.get("ClassTypeID"))
        if c is None:
            continue
        votes[c] = votes.get(c, 0) + 1
    if not votes:
        return (BUILD_CLASS_HERO if fallback is None else int(fallback)) & 0xFFFFFFFF
    return max(sorted(votes), key=lambda c: votes[c])


def smsg_build_record(bid, build, category=0, author="", clas=None):
    """One 0x138-byte build record, in wire order.

    Recovered from deserialiser 0x100f9330 -- wire order IS struct order, and every
    one of the 0x138 bytes is accounted for:

        0x000 CString ID                0x018 CString LevelingID
        0x030 CString EndGameIDPVE      0x048 CString EndGameIDPVP
        0x060 u32     (unnamed)         0x064 CString AuthorName
        0x07c CString Name              0x094 CString Subtext
        0x0ac CString Description       0x0c4 CString Icon
        0x0dc u32     Upvotes           0x0e0 u64     CreatedTime
        0x0e8 u64     UpdatedTime       0x0f0 u32     Category
        0x0f4 u32     Roles             0x0f8 u32     PrimaryStat
        0x0fc vector  Spells            0x108 vector  RandomEnchants
        0x114 vector  WeaponTypes       0x120 vector  ArmorTypes
        0x12c u8      NeedsRepairs      0x130 u32     Flags
        0x134 u32     DifficultyRating

    Every vector is a u32 count followed by that many elements, so a count of 0 is
    always safe.  Only Spells is populated here; the archive has no enchant, weapon
    or armour data to put in the other three.

    The u32 at 0x60 is the record's CLASS.  It has no name because the client never
    surfaces it to Lua -- GetBuild() returns 40-odd fields and none of them is a
    class -- but it is what the class filter reads, measured both ways: a record sent
    with 28 (Tinker) survived UpdateFilter{FILTER_CLASS_TINKER} and was dropped by
    both FILTER_CLASS_MAGE and FILTER_CLASS_HERO.  That matters because
    BuildCreator.lua:295 adds a FILTER_CLASS_<CLASS> filter on every refresh, so a
    record with the wrong number here is invisible while looking perfectly healthy on
    the wire.  The numbering is the CHARACTER CLASS BYTE (ChrClasses.dbc id), which
    is NOT the index into the client's FILTER_CLASS_ name table at 0x10b210b8:
    measured under a Hero with two records differing only in this field,
    FILTER_CLASS_HERO kept 10 and dropped 11, and FILTER_CLASS_GENERAL -- index 10
    in that table -- kept nothing, because General has no ChrClasses row for the
    name to resolve to.  Tinker is 28 either way, which is why a Tinker-only test
    cannot tell the two numberings apart.  See build_filter_class.

    An EMPTY Spells vector is not "a build with no spells" -- 0x100ff3e5 reads it as
    DELETE THIS BUILD and erases the cached record.  Never send one by accident."""
    rows = build_spell_rows(build)
    now = int(time.time())
    out = b""
    out += _bstr(bid)
    out += _bstr(build.get("levelingId", ""))
    out += _bstr(build.get("endGameIdPvE", ""))
    out += _bstr(build.get("endGameIdPvP", ""))
    out += struct.pack("<I", build_class_of(build, clas))
    out += _bstr(build.get("author", author))
    out += _bstr(build.get("name", bid))
    out += _bstr(build.get("subtext", ""))
    out += _bstr(build.get("description", ""))
    out += _bstr(build.get("icon", BUILD_DEFAULT_ICON))
    out += struct.pack("<I", int(build.get("upvotes", 0)) & 0xFFFFFFFF)
    out += struct.pack("<QQ", int(build.get("created", now)), int(build.get("updated", now)))
    out += struct.pack("<III",
                       int(build.get("category", category)) & 0xFFFFFFFF,
                       int(build.get("roles", BUILD_DEFAULT_ROLE)) & 0xFFFFFFFF,
                       int(build.get("primaryStat", 0)) & 0xFFFFFFFF)
    out += struct.pack("<I", len(rows))
    for sid, lvl, comment in rows:
        out += smsg_build_spell(sid, lvl, comment)
    out += struct.pack("<III", 0, 0, 0)          # RandomEnchants, WeaponTypes, ArmorTypes
    out += struct.pack("<BII", 0,
                       int(build.get("flags", 0)) & 0xFFFFFFFF,
                       int(build.get("difficulty", 0)) & 0xFFFFFFFF)
    return out


def build_records_for(cat, author="", clas=None):
    """Every stored build the archive is willing to show under `cat`.

    A build with no entries is skipped rather than sent empty, because an empty
    Spells vector is the client delete-this-build encoding (see smsg_build_record).
    "None" is the catch-all that the Featured and MyBuilds tabs both resolve to, so
    it lists everything."""
    want = BUILD_CATEGORY_IDS.get(cat)
    out = []
    for bid, b in sorted(load_builds().items()):
        if not build_spell_rows(b):
            continue
        if want not in (None, 0) and int(b.get("category", 0)) != want:
            continue
        out.append(smsg_build_record(bid, b, category=want or 0,
                                     author=author, clas=clas))
    return out


def smsg_build_result(result, record):
    """Answer to CMSG_BUILD_QUERY: a status CString, then exactly one build record.

    Handler 0x100ff200 reads both unconditionally and then fires
    BUILD_CREATOR_BUILD_RESULT with the arg descriptor "%s%s" -- status first,
    record.ID second.  So the buildID the addon sees comes from the RECORD, not from
    what it asked for, and on failure BuildCreator.lua:744 renders
    `_G[result] or result`, which makes the status double as a global-string key."""
    return _bstr(result) + record


def smsg_build_active_build_update(spec, build_id, flag_a=0, flag_b=0):
    """Mark build_id as the active build of specialization `spec`.

    Handler 0x100fdfd0 reads the u32 index, then hands the rest to the element
    reader 0x100fc950, which takes a CString and two single bytes -- the element is
    0x18 of std::string plus those two, padded to the 0x1C stride the handler
    indexes with.  Sending an EMPTY build id is how a spec goes back to having no
    active build, because that is what string.isNilOrEmpty tests for in
    BuildCreatorUtil.GetActiveBuildID.
    """
    return (struct.pack("<I", int(spec) & 0xFFFFFFFF) + _bstr(build_id)
            + bytes([flag_a & 0xFF, flag_b & 0xFF]))


def smsg_build_activate_result(status):
    """Answer to CMSG_BUILD_ACTIVATE -- one status CString, no record.

    "ACTIVATE_BUILD_OK" is the only value the addon treats as success.  The archive
    also sends "ACTIVATE_BUILD_UNKNOWN_BUILD", which has no global string, so the
    error box shows that text verbatim -- which is the honest thing for it to say."""
    return _bstr(status)


def load_essence_rows(path=None):
    """Ascension's essence table, read out of its own client DBC.

    DBFilesClient_CharacterAdvancementEssence.dbc is a stock WDBC -- 20-byte header
    (magic, recordCount, fieldCount, recordSize, stringBlockSize) then fixed-size
    records.  This build ships 5600 records of 9 u32 fields:
        [0] id  [1] level  [2] key  [3..6] four match flags  [7] AE  [8] TE
    which is field-for-field the record SMSG_CA_ESSENCE_BUDGET puts on the wire,
    because that opcode is the server streaming this very table row by row.

    The table holds one 80-row family per (key, flag-combination): 70 families over
    keys 1..32, levels 1..80.  Rows are returned VERBATIM and in file order, ids and
    all -- see send_essence_budget for why the ids matter.

    Returns a list of 9-tuples, or [] if the DBC is missing -- the archive still
    boots, it just has no essence to hand out, which the WORLD-ENTRY log makes
    obvious."""
    path = ESSENCE_DBC if path is None else path
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except (IOError, OSError) as e:
        log("essence: cannot read %s (%s) -- no table loaded" % (path, e))
        return []
    if len(raw) < 20 or raw[:4] != b"WDBC":
        log("essence: %s is not a WDBC file -- no table loaded" % path)
        return []
    nrec, nfield, recsz, _strsz = struct.unpack_from("<4I", raw, 4)
    if nfield < 9 or recsz < 36 or 20 + nrec * recsz > len(raw):
        log("essence: unexpected DBC shape (%d recs, %d fields, %d bytes/rec)"
            % (nrec, nfield, recsz))
        return []
    return [struct.unpack_from("<9I", raw, 20 + i * recsz) for i in range(nrec)]


ESSENCE_ROWS = load_essence_rows()


_ESSENCE_CURVES = {}


def essence_curve(key=None):
    """{level: (ae, te)} for one (key, all-flags-clear) family of ESSENCE_ROWS.

    Only the archive's own bookkeeping uses this -- the bag stacks, ".info" and the
    ".essence" report.  What the CoA panel reads is the record store, which
    send_essence_budget fills from ESSENCE_ROWS directly.  ESSENCE_DBC_KEY is 10
    because that is the key the archive client's CA state actually holds; at level 80
    that family is AE 140 / TE 71."""
    key = ESSENCE_DBC_KEY if key is None else key
    if key not in _ESSENCE_CURVES:
        _ESSENCE_CURVES[key] = dict(
            (r[1], (r[7], r[8])) for r in ESSENCE_ROWS
            if r[2] == key and not (r[3] or r[4] or r[5] or r[6]))
    return _ESSENCE_CURVES[key]


ESSENCE_CURVE = essence_curve()


def essence_for(level, key=None):
    """The (ability, talent) totals a character of this level is entitled to.
    ".essence <n>" installs a flat override for testing; otherwise this is
    Ascension's own curve, clamped to the range the DBC actually defines.

    `key` is the essence FAMILY -- the character's class byte.  The families are
    not interchangeable: at level 80 key 10 (Free-Pick "Hero") is AE 140 / TE 71
    while key 28 (Tinker) is 36 / 35.  Callers that have a character pass its
    class; the default stays ESSENCE_DBC_KEY so a caller without one is unchanged.
    Which family the CLIENT actually reads is its own choice -- ".essprobe" is
    the diagnostic that measures it."""
    if ESSENCE_OVERRIDE is not None:
        return ESSENCE_OVERRIDE
    curve = essence_curve(key)
    if not curve:
        return (0, 0)
    if level in curve:
        return curve[level]
    lo, hi = min(curve), max(curve)
    return curve[hi if level > hi else lo]


def smsg_ca_essence_budget(row_id, level, ability, talent, combo=0, key=None):
    """One SMSG_CA_ESSENCE_BUDGET record (36 bytes, nine u32s).

    `combo` packs the four match flags the handler stores at row[+0x0C..+0x18]:
    bit 0 -> flagA, bit 1 -> flagB, bit 2 -> flagC, bit 3 -> flagD.  The reader
    only ever tests them for non-zero, so 1 and 0 are the only values worth
    sending.  See the SMSG_CA_ESSENCE_BUDGET note up top for the derivation."""
    return struct.pack("<9I",
                       row_id,
                       level,
                       ESSENCE_DBC_KEY if key is None else key,
                       (combo >> 0) & 1,
                       (combo >> 1) & 1,
                       (combo >> 2) & 1,
                       (combo >> 3) & 1,
                       ability,
                       talent)


# ---- CA class types (CharacterAdvancementClassTypes.dbc) ---------------------
# WHAT DECIDES A CHARACTER'S CoA CLASS.  It is the class byte in
# UNIT_FIELD_BYTES_0 -- the same byte UnitClass reads -- and nothing else: not the
# realm flavour, not SMSG_CA_ACTIVE_SPEC, not the char-enum record.  Read off the
# client rather than assumed:
#
#   GetEntriesByClass's inner filter (Extensions.dll 0x101806a0) takes the class as
#   its SECOND argument, and its only caller (0x1017bb39) computes that argument as
#       0x1017bb13  cmp  ecx, 4                ; TYPEID_PLAYER, else class = 0
#       0x1017bb1c  mov  eax, [edx+8]          ; the object's descriptor block
#       0x1017bb1f  mov  eax, [eax+0x5c]       ; dword 23 = UNIT_FIELD_BYTES_0
#       0x1017bb22  shr  eax, 8                ; race | CLASS | gender | power
#   which is exactly the byte this server writes into the player's update block.
#
#   The filter hands it to MatchesClass (0x101c6a40), which decides per entry using
#   the ClassTypes row that entry's ClassType column points at:
#       ct = ClassTypes[entry.ClassType]
#       if   ct.required : return arg == ct.required    -- one specific class
#       elif ct.classic  : return arg == 10             -- any Free-Pick "Hero"
#       elif ct.custom   : return 12 <= arg <= 32       -- any CoA custom class
#       else             : return false
#
# So class 10 admits the twelve classic ClassTypes -- 5312 of the 10255 entries --
# and no custom one, while class 28 admits Tinker and only Tinker (158 entries).
# Setting the character's class byte is therefore the whole of "be a Tinker": the
# tabs, the learnable set and the essence family all follow it, with no client
# patch and nothing changed about the realm.
#
# Columns of the 46-record DBC (23 dwords per record):
#     [0] ID   [1] Name -- the token GetEntriesByClass takes, and the one
#                          entries.csv stores in its ClassType column
#     [2] required class byte   [3] classic group   [4] custom group
#     [5] reborn group          [6] display name
CLASS_TYPE_NAME     = 1
CLASS_TYPE_REQUIRED = 2
CLASS_TYPE_CLASSIC  = 3
CLASS_TYPE_CUSTOM   = 4
CLASS_TYPE_REBORN   = 5
CLASS_TYPE_DISPLAY  = 6

# Vanilla 3.3.5a ChrClasses.dbc has 10 rows; Ascension's has 32, and 12..32 are the
# CoA classes.  Only used to print the name the client is about to report from
# UnitClass, so a missing file costs nothing but the label.
CHRCLASS_FIELD_NAME  = 4
CHRCLASS_FIELD_TOKEN = 55


def _dbc_table(path, min_cols):
    """(rows, string-block) for a stock WDBC, or (None, None) with a logged reason.

    Rows come back as tuples of recordSize/4 dwords -- record_size, never
    field_count, is what describes the bytes on disk."""
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except (IOError, OSError) as e:
        log("class: cannot read %s (%s)" % (path, e))
        return None, None
    if len(raw) < DBC_HEADER or raw[:4] != b"WDBC":
        log("class: %s is not a WDBC file" % path)
        return None, None
    nrec, _nfield, recsz, _strsz = struct.unpack_from("<4I", raw, 4)
    ncol = recsz // 4
    if ncol < min_cols or DBC_HEADER + nrec * recsz > len(raw):
        log("class: unexpected shape in %s (%d recs, %d bytes/rec)"
            % (os.path.basename(path), nrec, recsz))
        return None, None
    rows = [struct.unpack_from("<%dI" % ncol, raw, DBC_HEADER + i * recsz)
            for i in range(nrec)]
    return rows, raw[DBC_HEADER + nrec * recsz:]


def _sblk_string(sblk, off):
    """One string-block entry, read at face value.

    Offset 0 is NOT special-cased to "empty" here.  Most DBCs open their string
    block with a NUL so offset 0 reads empty on its own, but ClassTypes opens
    with the literal "None" -- and row 1 IS None, the group marker MatchesClass
    sends down its arg == 10 branch.  Calling 0 empty silently dropped that row,
    and with it the six ClassType "None" entries a Free-Pick character can
    learn: 5306 instead of 5312."""
    if not sblk or off < 0 or off >= len(sblk):
        return ""
    z = sblk.find(b"\x00", off)
    return sblk[off:z if z >= 0 else len(sblk)].decode("utf-8", "replace")


def load_class_types(path=None):
    """[{id, name, display, required, classic, custom, reborn}] in DBC order, or []
    when the file is missing -- the server still boots, ".class" just says so."""
    rows, sblk = _dbc_table(CA_CLASSTYPES_DBC if path is None else path,
                            CLASS_TYPE_DISPLAY + 1)
    if rows is None:
        return []
    return [{"id":       r[0],
             "name":     _sblk_string(sblk, r[CLASS_TYPE_NAME]),
             "display":  _sblk_string(sblk, r[CLASS_TYPE_DISPLAY]),
             "required": r[CLASS_TYPE_REQUIRED],
             "classic":  r[CLASS_TYPE_CLASSIC],
             "custom":   r[CLASS_TYPE_CUSTOM],
             "reborn":   r[CLASS_TYPE_REBORN]} for r in rows]


def load_chrclasses(path=None):
    """{class byte: display name} from Ascension's own ChrClasses.dbc."""
    rows, sblk = _dbc_table(CHRCLASSES_DBC if path is None else path,
                            CHRCLASS_FIELD_TOKEN + 1)
    if rows is None:
        return {}
    return dict((r[0], _sblk_string(sblk, r[CHRCLASS_FIELD_NAME])
                 or _sblk_string(sblk, r[CHRCLASS_FIELD_TOKEN])) for r in rows)


CLASS_TYPES = load_class_types()
CHRCLASSES = load_chrclasses()


def class_type_matches(ct, class_byte):
    """MatchesClass (0x101c6a40) transcribed.  class_byte is the character's
    UNIT_FIELD_BYTES_0 class -- the only input the client's own filter has."""
    if ct["required"]:
        return class_byte == ct["required"]
    if ct["classic"]:
        return class_byte == 10
    if ct["custom"]:
        return 0 <= (class_byte - 12) <= 20      # the unsigned (arg - 0xC) <= 0x14
    return False


def class_group(ct):
    return ("classic" if ct["classic"] else
            "custom" if ct["custom"] else
            "reborn" if ct["reborn"] else "-")


def resolve_class_byte(token):
    """A .class argument -> (class_byte, matching ClassTypes row or None).

    A bare number is ALWAYS the class byte, never a ClassTypes row id: the two
    ranges overlap (rows 1..46, bytes 1..32) and the byte is what goes on the wire,
    so ".class 28" is Tinker rather than row 28 (Starcaller).  Names match either
    the DBC token (KnightOfXoroth) or the display name (Sun Cleric), case- and
    space-insensitively.  Rows with no required class -- None, ConquestOfAzeroth,
    RebornGeneral -- are group markers, not classes, and do not resolve."""
    t = (token or "").strip().lower()
    if not t:
        return None, None
    if t.isdigit():
        n = int(t)
        return (n, None) if 0 < n <= 0xFF else (None, None)
    flat = t.replace(" ", "").replace("_", "").replace("-", "")
    for ct in CLASS_TYPES:
        if not ct["required"]:
            continue
        if flat in (ct["name"].lower(), ct["display"].lower().replace(" ", "")):
            return ct["required"], ct
    return None, None


def class_entry_counts(class_byte):
    """(total, {ClassType name: count}) admitted by one class byte, computed the way
    the client computes it.  This is the size of the tree the CoA panel should
    offer that character."""
    idx = ca_entry_index()
    if not idx:
        return 0, {}
    ok = set(ct["name"] for ct in CLASS_TYPES if class_type_matches(ct, class_byte))
    per = {}
    for row in idx.values():
        nm = row.get("ClassType") or ""
        if nm in ok:
            per[nm] = per.get(nm, 0) + 1
    return sum(per.values()), per


def class_unlearnable(guid, class_byte):
    """This character's known entries that `class_byte` cannot learn.

    Leaving them behind is not cosmetic.  The client validates a learn by walking
    the WHOLE known set, so a single foreign entry makes every LearnID fail --
    and it fails naming the stale entry, not the one you asked for.  Measured on
    a character flipped 10 -> 28 with two Mage entries still known:
        LearnID(31113) -> false OPTIMIZE_FOR_TRAVERSAL_FAILED
                          CA_LEARN_WRONG_CLASS 1189 1
    where 1189 is the stale Mage entry and 31113 the Tinker one being learned.
    Clearing the two made the same call return true."""
    idx = ca_entry_index()
    if not idx:
        return []
    ok = set(ct["name"] for ct in CLASS_TYPES if class_type_matches(ct, class_byte))
    return [r for r in known_for(guid)
            if (idx.get(r["id"], {}).get("ClassType") or "") not in ok]


def class_report(c):
    """What .class prints -- the byte, what the client should say about it, and the
    entry set it admits."""
    byte = int(c["class"]) & 0xFF
    total, per = class_entry_counts(byte)
    plays = [ct for ct in CLASS_TYPES if class_type_matches(ct, byte)]
    ae, te = essence_for(c["level"], byte)
    lines = [
        "Class byte %d -- ChrClasses says %r; UnitClass should agree."
        % (byte, CHRCLASSES.get(byte, "(no row)")),
        "Admits %d CA entr%s from %d class type(s): %s"
        % (total, "y" if total == 1 else "ies", len(plays),
           ", ".join(sorted(ct["name"] for ct in plays)) or "(none)"),
    ]
    if per:
        top = sorted(per.items(), key=lambda kv: (-kv[1], kv[0]))[:6]
        lines.append("  " + ", ".join("%s %d" % (k, v) for k, v in top)
                     + (", ..." if len(per) > len(top) else ""))
    lines.append("Essence family key %d at level %d: AE %d / TE %d "
                 "(.essprobe to confirm which family the client reads)."
                 % (byte, c["level"], ae, te))
    return lines


# ---- known CA entries (knownentries.json) -----------------------------------
# { guid: [ {id, rank}, ... ] } -- the set of CharacterAdvancement entries this
# character has learned, replayed to the client as SMSG_CA_KNOWN_ENTRIES at world
# entry.  Guids are stringified because JSON object keys are strings.
#
# On the live realm this set grows as the player spends essence; the archive has no
# spend path (CMSG for "learn entry" is not implemented), so it is edited with the
# ".known" command instead.  That is the archive's stand-in for the archetype build
# that never applies -- see ARCHIVE_NEW_CHAR_LEVEL, where the client's own
# C_BuildCreator.ActivateBuild is documented as emitting nothing on the wire.
KNOWN_UNKNOWN_FIELDS = (0, 0, 0, 0)     # rec +0x0C, +0x10 flag, +0x18, +0x1C

def load_known():
    try:
        with open(KNOWN_PATH, "r", encoding="utf-8") as fp:
            return json.load(fp)
    except Exception:
        return {}

def save_known(db):
    try:
        tmp = KNOWN_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fp:
            json.dump(db, fp, indent=2)
        os.replace(tmp, KNOWN_PATH)
    except Exception as e:
        log("        !! save_known failed: %r" % e)

def known_for(guid):
    """This character's learned entries as a list of {id, rank}, id-sorted."""
    rows = load_known().get(str(int(guid)), [])
    out = []
    for r in rows:
        try:
            out.append({"id": int(r["id"]), "rank": int(r.get("rank", 1))})
        except (KeyError, TypeError, ValueError):
            continue
    out.sort(key=lambda r: r["id"])
    return out

def set_active_build(guid, build_id):
    """Remember which build a character has active, so world entry can re-announce it.

    SMSG_BUILD_ACTIVE_BUILD_UPDATE is the only thing that fills the client's per-spec
    active-build table, and the client does not persist it: without this the spells
    stayed learned across a relog but GetActiveBuildID() came back empty, the button
    reverted to "Activate Build" and the ActiveBuild category emptied out.  Stored on
    the character record rather than beside the known set because it is per character,
    not per entry.
    """
    db = load_chars()
    hit = False
    for chars in db.values():
        for row in chars:
            try:
                if int(row.get("guid", -1)) != int(guid):
                    continue
            except (TypeError, ValueError):
                continue
            hit = True
            if build_id:
                row["activeBuild"] = str(build_id)
            else:
                row.pop("activeBuild", None)
    if hit:
        save_chars(db)


def set_known(guid, rows):
    db = load_known()
    key = str(int(guid))
    if rows:
        db[key] = [{"id": r["id"], "rank": r["rank"]} for r in rows]
    else:
        db.pop(key, None)
    save_known(db)


_CA_INDEX = None

def ca_entry_index():
    """Lazy {id: row} over the decoded CharacterAdvancement.dbc export.

    entries.csv is the same 10255-row dataset as entries.json but an eighth of the
    size, and the only columns ".known" needs are ID / Name / ClassType / TabType /
    Type.  Loaded on first use so a server that never runs the command never pays
    for it.  See rexxar-reference\\ca-dbc-export\\SCHEMA.md."""
    global _CA_INDEX
    if _CA_INDEX is None:
        idx = {}
        try:
            with io.open(CA_ENTRIES_CSV, "r", encoding="utf-8", newline="") as fp:
                for row in csv.DictReader(fp):
                    try:
                        idx[int(row["ID"])] = row
                    except (KeyError, TypeError, ValueError):
                        continue
            log("known: CA entry index loaded (%d entries)" % len(idx))
        except Exception as e:
            log("known: cannot read %s (%r) -- .known class is unavailable"
                % (CA_ENTRIES_CSV, e))
        _CA_INDEX = idx
    return _CA_INDEX


# ---- CA entries -> real castable spells --------------------------------------
# The CoA "known entries" state (0x726) and the client's actual spellbook are two
# independent systems.  Wiring the first one is what makes the tree render; this is
# what makes the character able to cast.  The join is entirely local:
#
#   knownentries.json -> entries.csv (SpellID) -> server-ascension\Data\dbc\Spell.dbc
#
# It resolves for every entry this character knows, and the names agree in both DBCs.

def spell_dbc():
    """Ascension's Spell.dbc, mapped read-only and lazily.

    209,509 records against vanilla 3.3.5a's 49,839, with custom ids running to
    ~13.9M.  `server\\Data\\dbc\\Spell.dbc` is the VANILLA control and contains none
    of the CA spells -- opening that one by accident makes every custom entry look
    missing, so the path is spelled out rather than derived from a shared DBC dir.

    The record layout is stock 3.3.5a (234 fields / 936 bytes per record), which is
    why the field indices below are the WotLK ones.  Ids are strictly ascending and
    unique across all 209,509 records (verified), so lookups are a binary search over
    the mapping and the server never reads the 209 MB into memory.

    Returns (file, mmap, recordCount, recordSize, stringBlockOffset) or None."""
    global _SPELL_DBC
    if _SPELL_DBC is None:
        try:
            fp = open(SPELL_DBC, "rb")
            mm = mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ)
            magic, nrec, nfld, recsz, sblk = struct.unpack_from("<4siiii", mm, 0)
            if magic != b"WDBC":
                raise ValueError("not a WDBC file (magic %r)" % magic)
            if recsz < (SPELL_FIELD_MAX + 1) * 4:
                raise ValueError("record is %d bytes -- too short for field %d"
                                 % (recsz, SPELL_FIELD_RANK))
            _SPELL_DBC = (fp, mm, nrec, recsz, DBC_HEADER + nrec * recsz)
            log("spells: Spell.dbc mapped (%d records, %d bytes/record)" % (nrec, recsz))
        except Exception as e:
            log("spells: cannot read %s (%r) -- no spells can be granted"
                % (SPELL_DBC, e))
            _SPELL_DBC = False
    return _SPELL_DBC or None


def _dbc_string(mm, stroff, off):
    """One string-block entry.  Offset 0 is the block's own leading NUL in every
    DBC we read here, so it means "empty" rather than "the first string"."""
    if off <= 0:
        return ""
    z = mm.find(b"\x00", stroff + off)
    if z < 0:
        return ""
    return mm[stroff + off:z].decode("utf-8", "replace")


_DURATION_DBC = {}                      # SpellDuration.dbc id -> base duration in ms
_DURATION_LOADED = [False]


def spell_duration_ms(info):
    """How long one application of `info` lasts, in milliseconds.

    0 means "no duration" -- a passive, or an aura the client should show with no
    timer.  A NEGATIVE base duration is 3.3.5a's infinity marker and is returned as 0
    for the same reason: an aura with no expiry and no countdown.

    Spell.dbc does not carry the number; it carries a DurationIndex into
    SpellDuration.dbc, whose row is (id, Duration, DurationPerLevel, MaxDuration).
    Only the base is read: DurationPerLevel is a vanilla-era scaling that WotLK spells
    do not use, and this archive has no aura-scaling model to spend it on."""
    if not _DURATION_LOADED[0]:
        _DURATION_LOADED[0] = True
        path = os.path.join(os.path.dirname(SPELL_DBC), "SpellDuration.dbc")
        rows, _sblk = _dbc_table(path, 4)
        if rows is None:
            log("auras: no SpellDuration.dbc -- every aura will be durationless")
        else:
            for r in rows:
                # Duration is SIGNED: id 21 and 427 are -1, the infinity marker.
                d = r[1] if r[1] < 0x80000000 else r[1] - 0x100000000
                _DURATION_DBC[r[0]] = d
            log("auras: SpellDuration.dbc mapped (%d durations)" % len(_DURATION_DBC))
    if not info:
        return 0
    idx = int(info.get("durationIndex", 0))
    if idx <= 0:
        return 0
    d = _DURATION_DBC.get(idx, 0)
    # 300000010 ms is Ascension's own "effectively forever" row (id 2); treat anything
    # past a day the same way a negative does -- shown, but with no countdown.
    if d < 0 or d > 86400000:
        return 0
    return int(d)


def spell_info(spell_id):
    """{id, attributes, name, rank} for one spell, or None if Ascension's Spell.dbc
    has no such record.  Results are cached; a miss is cached too."""
    spell_id = int(spell_id)
    if spell_id in _SPELL_CACHE:
        return _SPELL_CACHE[spell_id]
    out = None
    d = spell_dbc()
    if d:
        _fp, mm, nrec, recsz, stroff = d
        lo, hi = 0, nrec - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            base = DBC_HEADER + mid * recsz
            v = struct.unpack_from("<I", mm, base)[0]
            if v < spell_id:
                lo = mid + 1
            elif v > spell_id:
                hi = mid - 1
            else:
                def u(idx):
                    return struct.unpack_from("<I", mm, base + idx * 4)[0]

                def i32(idx):
                    return struct.unpack_from("<i", mm, base + idx * 4)[0]

                out = {
                    "id":         spell_id,
                    "attributes": u(SPELL_FIELD_ATTRIBUTES),
                    "name":       _dbc_string(mm, stroff, u(SPELL_FIELD_NAME)),
                    "rank":       _dbc_string(mm, stroff, u(SPELL_FIELD_RANK)),
                    "powerType":  i32(SPELL_FIELD_POWER_TYPE),
                    "manaCost":   u(SPELL_FIELD_MANA_COST),
                    "manaCostPct": u(SPELL_FIELD_MANA_COST_PCT),
                    "manaCostPerLevel": u(SPELL_FIELD_MANA_COST_LVL),
                    "schoolMask": u(SPELL_FIELD_SCHOOL_MASK),
                    "dmgClass":   u(SPELL_FIELD_DMG_CLASS),
                    # EffectBasePoints is SIGNED and stored one BELOW the value the
                    # client shows, which is why a "no effect" column reads as -1
                    # rather than 0.  Kept raw here; power costs do not use it, and
                    # stage (b) needs the raw pair (base, dieSides) anyway.
                    "attributesEx5": u(SPELL_FIELD_ATTR_EX5),
                    "durationIndex": i32(SPELL_FIELD_DURATION_INDEX),
                    "stackAmount": u(SPELL_FIELD_STACK_AMOUNT),
                    "effects":    [{"effect":    u(SPELL_FIELD_EFFECT + n),
                                    "basePoints": i32(SPELL_FIELD_EFFECT_BASE + n),
                                    "dieSides":  i32(SPELL_FIELD_EFFECT_DIE + n),
                                    "aura":      u(SPELL_FIELD_EFFECT_AURA + n),
                                    # milliseconds between periodic ticks; 0 for every
                                    # non-periodic aura, which is exactly what makes
                                    # "is this aura periodic" a one-column question.
                                    "amplitude": i32(SPELL_FIELD_EFFECT_AMPL + n)}
                                   for n in range(3)],
                }
                break
    _SPELL_CACHE[spell_id] = out
    return out


def ca_entry_spell(entry_id, rank=1):
    """The spell a learned CA entry grants at `rank`, as (spellId, entryRow).

    entries.csv carries SpellID plus SpellID2..SpellID5, and those extras are a RANK
    CHAIN rather than extra spells -- 705781/705782 are Refined Gunpowder "Rank 1"
    and "Rank 2" in Spell.dbc, and 704111/707833 are Explosive Personality's two
    ranks.  So the granted spell is the chain entry at the learned rank, which for
    rank 1 (every row in knownentries.json today) is plain SpellID.  2379 of the
    10255 entries carry a chain and 3 of this character's 36 do, so the rank index
    matters as soon as anything is learned past rank 1.
    An out-of-range rank clamps to the last link rather than dropping the spell."""
    row = ca_entry_index().get(int(entry_id))
    if not row:
        return 0, None
    chain = []
    for col in ("SpellID", "SpellID2", "SpellID3", "SpellID4", "SpellID5"):
        try:
            sid = int(row.get(col) or 0)
        except (TypeError, ValueError):
            sid = 0
        if sid:
            chain.append(sid)
    if not chain:
        return 0, row
    return chain[min(max(int(rank), 1), len(chain)) - 1], row


def ca_known_spells(guid):
    """This character's learned CA entries resolved to spells, entry-id ordered.

    [{entry, rank, spell, name, passive}, ...].  `passive` is SPELL_ATTR0_PASSIVE
    straight off Ascension's Spell.dbc: 25 of this character's 36 entries are passive
    talent effects, and those must never take an action-bar slot.  A spell that is not
    in Spell.dbc is dropped and logged -- handing the client an id it cannot resolve is
    what leaves a spellbook page blank instead of erroring."""
    out, seen = [], set()
    for r in known_for(guid):
        sid, row = ca_entry_spell(r["id"], r["rank"])
        if not sid:
            log("spells: CA entry %d has no SpellID -- skipped" % r["id"])
            continue
        if sid in seen:                     # two entries can share a spell; grant once
            continue
        info = spell_info(sid)
        if info is None:
            log("spells: CA entry %d -> spell %d is not in Spell.dbc -- skipped"
                % (r["id"], sid))
            continue
        seen.add(sid)
        out.append({"entry":   r["id"],
                    "rank":    r["rank"],
                    "spell":   sid,
                    "name":    info["name"] or (row or {}).get("Name") or "",
                    "passive": bool(info["attributes"] & SPELL_ATTR0_PASSIVE)})
    return out


def smsg_initial_spells(c):
    """SMSG_INITIAL_SPELLS (0x12A) -- the bulk "here is your spellbook" packet.

        u8  talentSpec
        u16 spellCount ; spellCount * { u32 spellId ; u16 unused }
        u16 cooldownCount ; cooldownCount * { u32 spellId; u16 itemId;
                                              u16 category; u32 cd; u32 categoryCd }

    The u16 after each id is not a slot -- AzerothCore writes a literal 0 there and
    comments as much (Player.cpp:2811).  Passives are included: they belong in the
    client's spell store even though SPELL_ATTR0_DO_NOT_DISPLAY keeps them off the
    spellbook page.  A character with no known entries still gets a well-formed
    zero-count packet, which is the state a freshly created character is in."""
    spells = ca_known_spells(c["guid"])
    out = bytearray([0])                                   # talentSpec
    out += struct.pack("<H", len(spells))
    for s in spells:
        out += struct.pack("<IH", s["spell"], 0)
    out += struct.pack("<H", 0)                            # cooldownCount
    return bytes(out)


def smsg_learned_spell(spell_id):
    """SMSG_LEARNED_SPELL (0x12B) -- grant one spell mid-session, no relog.
    u32 spellId | u16 0, exactly as Player::SendLearnPacket writes it."""
    return struct.pack("<IH", int(spell_id), 0)


def smsg_removed_spell(spell_id):
    """SMSG_REMOVED_SPELL (0x203) -- u32 spellId.  Ascension's own opcode table
    calls this 0x202, but that table runs one low from somewhere in 0x1EF..0x1FC
    onward (it also puts SMSG_ACCOUNT_DATA_TIMES at 0x208, where 0x209 is the value
    that demonstrably works), so the stock 3.3.5a number is the real one."""
    return struct.pack("<I", int(spell_id))


# ---- action bars (CMSG_SET_ACTION_BUTTON 0x128 / actionbars.json) ------------
# THE WIRE FORMAT, MEASURED -- not assumed from AzerothCore.  Body is 5 bytes,
# `u8 slot` then `u32 packedAction` where packed = action | (type << 24):
#
#     PlaceAction(30) with Rocket Boots on the cursor  ->  raw 1d 11 a2 07 00
#                                                          slot 0x1d = 29
#                                                          packed 0x0007A211 = 500241
#
# so Lua's 1-based action slot N is wire slot N-1, and type 0 is a spell.  A packed
# value of 0 clears the slot.
#
# WHAT THE CLIENT ACTUALLY SENDS, and why the first reading of it was wrong: these do
# NOT arrive in response to SMSG_ACTION_BUTTONS.  They arrive after any SPELLBOOK
# CHANGE, as a normalisation sweep -- the client walks every slot from the end of what
# we filled up to 143 and sends a clear for each.  With 11 castable spells that is 133
# packets, all `packed=0`, starting at slot 11.  Reading that burst as "the player
# wiped their bars" would be exactly backwards; it is the client agreeing that the tail
# is empty.  A real edit shows up as a single packet with a non-zero packed value.
_BARS = None                    # {guid:int -> {slot:int -> packed:int}}
_BARS_DIRTY = False
_BARS_LAST_FLUSH = 0.0
BARS_FLUSH_INTERVAL = 0.25      # s -- coalesces a 133-packet burst into a couple of writes


def load_bars():
    """The whole file, as {guid:int -> {slot:int -> packed:int}}.  JSON keys are always
    strings, so both levels are converted back to ints once, here, rather than at every
    use site."""
    global _BARS
    if _BARS is None:
        out = {}
        try:
            with io.open(ACTIONBARS_PATH, "r", encoding="utf-8") as fp:
                raw = json.load(fp)
            for g, slots in raw.items():
                out[int(g)] = dict((int(s), int(v)) for s, v in slots.items() if int(v))
        except Exception:
            out = {}
        _BARS = out
    return _BARS


def save_bars(force=False):
    """Write the layout out, at most once per BARS_FLUSH_INTERVAL unless forced.

    The rate limit exists because a normalisation burst is ~133 packets inside one
    second and each one would otherwise rewrite the file.  `force=True` is used at
    session end so nothing is lost to the debounce."""
    global _BARS_DIRTY, _BARS_LAST_FLUSH
    import time
    if not _BARS_DIRTY:
        return
    now = time.monotonic()
    if not force and now - _BARS_LAST_FLUSH < BARS_FLUSH_INTERVAL:
        return
    try:
        tmp = ACTIONBARS_PATH + ".tmp"
        with io.open(tmp, "w", encoding="utf-8") as fp:
            json.dump(dict((str(g), dict((str(s), v) for s, v in sorted(slots.items())))
                           for g, slots in sorted(load_bars().items()) if slots),
                      fp, indent=2)
        os.replace(tmp, ACTIONBARS_PATH)
        _BARS_DIRTY = False
        _BARS_LAST_FLUSH = now
    except Exception as e:
        log("        !! save_bars failed: %r" % e)


def bars_for(guid):
    """This character's saved layout, or {} if they have never had one."""
    return load_bars().get(int(guid), {})


def bars_set(guid, slot, packed):
    """Apply one CMSG_SET_ACTION_BUTTON.  Returns True if anything actually changed --
    most of a normalisation burst clears slots that are already clear, and skipping
    those keeps the file from being rewritten for nothing."""
    global _BARS_DIRTY
    slots = load_bars().setdefault(int(guid), {})
    old = slots.get(int(slot), 0)
    if packed:
        if old == packed:
            return False
        slots[int(slot)] = int(packed)
    else:
        if not old:
            return False
        del slots[int(slot)]
    _BARS_DIRTY = True
    return True


def bars_autofill(c):
    """Lay every castable known spell out from slot 0 -- the archive's demo layout.

    Only used when a character has NO saved layout at all, and by ".bars auto".  It is
    deliberately NOT run on every spellbook change: doing that would silently re-add a
    spell the player had just dragged off their bar, since the client tells us about a
    removal as a clear and we would immediately fill the hole back in."""
    out = {}
    n = 0
    for s in ca_known_spells(c["guid"]):
        if s["passive"] or n >= MAX_ACTION_BUTTONS:
            continue
        if s["spell"] > ACTION_BUTTON_ACTION_MAX:
            log("spells: %s (%d) exceeds the 24-bit action field -- no button"
                % (s["name"], s["spell"]))
            continue
        out[n] = s["spell"] | (ACTION_BUTTON_SPELL << 24)
        n += 1
    return out


_AB_BURST = {}                  # cid -> [count, last_monotonic, changed]
AB_BURST_GAP = 2.0


def bars_note_packet(cid, guid, body):
    """Record one packet and return a log line when a burst is worth reporting.

    Per-packet logging is suppressed for this opcode: 133 identical lines buried
    everything else in the file.  One line per burst says the same thing."""
    import time
    if len(body) != 5:
        return "SET_ACTION_BUTTON unexpected body %d B: %s" % (len(body), body.hex())
    slot = body[0]
    packed = struct.unpack_from("<I", body, 1)[0]
    changed = bars_set(guid, slot, packed)
    save_bars()

    now = time.monotonic()
    st = _AB_BURST.get(cid)
    if st is None or now - st[1] > AB_BURST_GAP:
        st = [0, now, 0]
        _AB_BURST[cid] = st
    st[0] += 1
    st[1] = now
    st[2] += 1 if changed else 0

    if st[0] == 1 and packed:
        # A lone non-zero packet is a real player edit -- always worth a line.
        info = spell_info(packed & ACTION_BUTTON_ACTION_MAX) if (packed >> 24) == 0 else None
        return ("SET_ACTION_BUTTON slot %d <- 0x%08X%s"
                % (slot, packed,
                   " (%s)" % info["name"] if info and info.get("name") else ""))
    if st[0] == MAX_ACTION_BUTTONS or (st[0] % 64 == 0):
        return ("SET_ACTION_BUTTON burst: %d packet(s) so far, %d changed the layout"
                % (st[0], st[2]))
    return None


def smsg_action_buttons(c, state=1):
    """SMSG_ACTION_BUTTONS (0x129): u8 state, then MAX_ACTION_BUTTONS u32 slots of
    `action | (type << 24)`, 0 for empty.

    state 1 is what AzerothCore sends for any packet carrying button data --
    SendInitialActionButtons() is literally SendActionButtons(1) -- because state 0
    "had some difficulties" (Player.cpp:5730).  state 2 clears the bars and writes no
    slot data at all.

    Only CASTABLE spells get a button: a passive on a bar draws a dead slot.  The
    action field is 24 bits, so an id at or above 0x1000000 cannot be bound this way;
    no CA spell comes close (the dataset's largest is 2,315,425) but the guard keeps a
    future one from silently landing on the wrong button."""
    out = bytearray([state & 0xFF])
    if state == ACTION_BUTTONS_CLEAR:
        return bytes(out)
    layout = bars_for(c["guid"])
    if not layout:
        # First time this character has ever been sent bars: lay the demo layout out
        # and adopt it, so the very next edit is a diff against something real.
        layout = bars_autofill(c)
        if layout:
            load_bars()[int(c["guid"])] = dict(layout)
            globals()["_BARS_DIRTY"] = True
            save_bars(force=True)
            log("        bars: seeded %d slot(s) for guid %s (no saved layout)"
                % (len(layout), c["guid"]))
    slots = [0] * MAX_ACTION_BUTTONS
    for slot, packed in layout.items():
        if 0 <= slot < MAX_ACTION_BUTTONS:
            slots[slot] = packed
    for v in slots:
        out += struct.pack("<I", v)
    return bytes(out)


def send_spellbook(conn, eo, send_pkt, c):
    """Push this character's whole spellbook and bars -- the world-entry bulk path.
    Returns (totalSpells, castableSpells)."""
    spells = ca_known_spells(c["guid"])
    send_pkt(conn, eo, SMSG_INITIAL_SPELLS, smsg_initial_spells(c))
    send_pkt(conn, eo, SMSG_SEND_UNLEARN_SPELLS, smsg_send_unlearn_spells())
    send_pkt(conn, eo, SMSG_ACTION_BUTTONS, smsg_action_buttons(c))
    _SPELLS_SENT[int(c["guid"])] = set(s["spell"] for s in spells)
    return len(spells), sum(1 for s in spells if not s["passive"])


def sync_spellbook(conn, eo, send_pkt, c):
    """Bring the client's spellbook in line with the current known-entry set, without
    a relog.  Returns (learnedCount, removedCount).

    SMSG_INITIAL_SPELLS is the bulk path and is only honoured at world entry, so a
    mid-session change has to go out as the incremental pair -- SMSG_LEARNED_SPELL per
    addition, SMSG_REMOVED_SPELL per removal -- diffed against what this guid was last
    sent.  3.3.5a has no per-slot action-button opcode, so the bars are re-sent whole
    whenever anything moved at all."""
    guid = int(c["guid"])
    now = set(s["spell"] for s in ca_known_spells(guid))
    was = _SPELLS_SENT.get(guid, set())
    learned, removed = now - was, was - now
    for sid in sorted(learned):
        send_pkt(conn, eo, SMSG_LEARNED_SPELL, smsg_learned_spell(sid))
    for sid in sorted(removed):
        send_pkt(conn, eo, SMSG_REMOVED_SPELL, smsg_removed_spell(sid))
    if removed:
        # A button pointing at a spell the character no longer knows draws as a red
        # question mark and cannot be cast, and after a '.class' change that would be
        # most of the bar.  Unbind those slots before the bars go back out; the player's
        # OTHER slots are left exactly as they were, which is the whole point of saving
        # them in the first place.
        stale = [s for s, p in bars_for(guid).items()
                 if (p >> 24) == ACTION_BUTTON_SPELL
                 and (p & ACTION_BUTTON_ACTION_MAX) in removed]
        for s in stale:
            bars_set(guid, s, 0)
        if stale:
            save_bars(force=True)
            log("        bars: unbound %d slot(s) whose spell was unlearned" % len(stale))
    if learned or removed:
        send_pkt(conn, eo, SMSG_ACTION_BUTTONS, smsg_action_buttons(c))
    _SPELLS_SENT[guid] = now
    return len(learned), len(removed)


# ---- power, health and what a spell costs ------------------------------------
# Track A stopped at SMSG_SPELL_GO: the cast ended, the GCD started, the visual
# played, and nothing else happened.  This is the first thing that actually happens --
# a spell costs power, and a cast you cannot pay for is refused.
UNIT_FIELD_HEALTH    = 24
UNIT_FIELD_POWER1    = 25               # +powerType
UNIT_FIELD_MAXHEALTH = 32
UNIT_FIELD_MAXPOWER1 = 33               # +powerType

_UNIT_STATE = {}                        # guid -> {"hp", "power"}; per-session, not saved


def max_pools(c):
    """(maxHealth, maxPower) for a character.  See the ARCHIVE_* note: policy, not
    emulation -- there is no player_classlevelstats here, and no row for a Tinker in it
    if there were."""
    lvl = max(1, int(c["level"]))
    hp = ARCHIVE_POOL_BASE + ARCHIVE_HEALTH_PER_LEVEL * lvl
    ptype = chardata.power_for(int(c["class"])) & 0xFF
    if ptype != POWER_MANA:
        return hp, ARCHIVE_FIXED_POWER     # rage / focus / energy are a fixed 0..100
    return hp, ARCHIVE_POOL_BASE + ARCHIVE_MANA_PER_LEVEL * lvl


def unit_state(c):
    """This character's live health and power, seeded full on first use.

    Deliberately in memory only.  Logging in at full is what every WoW server does
    anyway, and persisting it would mean a file write on every regen tick to store
    something nobody would notice was missing."""
    guid = int(c["guid"])
    st = _UNIT_STATE.get(guid)
    hp, mp = max_pools(c)
    if st is None:
        st = _UNIT_STATE[guid] = {"hp": hp, "power": mp}
    # ".level" resizes the pools underneath us; clamp rather than leave a bar reading
    # over 100%.
    st["hp"] = min(st["hp"], hp)
    st["power"] = min(st["power"], mp)
    return st


def power_cost(info, c):
    """What one cast of `info` costs, in the caster's own power type.

    Two columns, added: a flat `ManaCost` and a `ManaCostPercentage` of BASE mana.
    The percentage is the one that matters in WotLK -- Fireball is ManaCost 0 and
    "19% of base mana" -- and reading only the flat column makes almost every spell
    look free.  Base mana here is the character's full pool, since the archive has no
    separate notion of an unbuffed base.

    A spell whose power type is not the caster's costs nothing: charging a mana user
    for a rage spell would be worse than charging nothing."""
    if not info:
        return 0
    ptype = chardata.power_for(int(c["class"])) & 0xFF
    if int(info.get("powerType", 0)) != ptype:
        return 0
    _hp, maxp = max_pools(c)
    cost = int(info.get("manaCost", 0))
    cost += int(info.get("manaCostPct", 0)) * maxp // 100
    return max(0, cost)


def smsg_power_update(guid, power, value):
    """SMSG_POWER_UPDATE (0x480) -- packed guid, u8 powerType, u32 value.

    Straight out of Unit::SetPower.  Do not be tempted to drop the values update and
    send only this: 0x480 moves the number, the descriptor is what every OTHER client
    reads off the unit, and the real server sends both."""
    return pack_guid(int(guid)) + bytes([power & 0xFF]) + struct.pack("<I", int(value))


def send_power_update(conn, eo, send_pkt, c):
    """Push health, power and both maxima to the client.

    TWO packets, and the second one is not optional.  A values update carrying
    UNIT_FIELD_HEALTH and UNIT_FIELD_POWER1 in the same mask lands the health and
    silently drops the power -- measured, see this patch's header.  SMSG_POWER_UPDATE
    is what the client actually believes about its own bar.

    The maxima ride along because ".level" resizes the pools underneath the client:
    without them the bar keeps the old maximum and a full pool reads as partial."""
    st = unit_state(c)
    maxhp, maxp = max_pools(c)
    ptype = chardata.power_for(int(c["class"])) & 0xFF
    send_pkt(conn, eo, SMSG_UPDATE_OBJECT,
             build_values_update(int(c["guid"]),
                                 {UNIT_FIELD_HEALTH: u32le(st["hp"]),
                                  UNIT_FIELD_MAXHEALTH: u32le(maxhp),
                                  UNIT_FIELD_POWER1 + ptype: u32le(st["power"]),
                                  UNIT_FIELD_MAXPOWER1 + ptype: u32le(maxp)},
                                 PLAYER_END))
    send_pkt(conn, eo, SMSG_POWER_UPDATE,
             smsg_power_update(int(c["guid"]), ptype, st["power"]))


def regen_tick(conn, eo, send_pkt, c):
    """Give a slice of power back; returns True only when something changed.

    Without this a caster drains to zero once and stays there, which looks exactly
    like a broken cost calculation.  A flat percentage of maximum: the real formula is
    spirit and the five-second rule, and this archive has neither spirit nor combat
    state to hang them on."""
    st = unit_state(c)
    _hp, maxp = max_pools(c)
    if st["power"] >= maxp:
        return False
    st["power"] = min(maxp, st["power"] + max(1, int(maxp * ARCHIVE_REGEN_PCT)))
    send_power_update(conn, eo, send_pkt, c)
    return True


# ---- target dummies ----------------------------------------------------------
# A damage spell needs something to point at, and this archive has no creature table,
# no map and no grid.  So the dummy is built by hand: one CREATE_OBJECT block for a
# TYPEID_UNIT, a CMSG_CREATURE_QUERY answer so it has a name, and a health number the
# server keeps.  That is the whole of it -- it does not move, does not fight back and
# does not path.
#
# IT ALSO DOES NOT DIE, and that is deliberate rather than a shortcut: a WoW training
# dummy does not die either.  Death would mean a corpse, a loot window, a respawn timer
# and SMSG_ATTACKERSTATEUPDATE, none of which exist here, and none of which are needed
# to show that a damage number left the server and moved a health bar.
_DUMMIES = {}                   # guid -> {"hp", "maxhp", "x", "y", "z", "o", "hit"}
_DUMMY_SEQ = [0]


def dummy_guid(counter):
    """ObjectGuid.h:135 -- counter | (entry << 24) | (HighGuid::Unit << 48)."""
    return int(counter) | (ARCHIVE_DUMMY_ENTRY << 24) | HIGHGUID_UNIT


def build_dummy_create_block(guid, d):
    """One UPDATETYPE_CREATE_OBJECT block for a stationary creature.

    Flags are LIVING|STATIONARY (0x60): the same pair the player create block uses
    minus SELF, so the movement half is byte-identical to the one already proven to
    work -- and STATIONARY sits in the LIVING else-branch, so it emits nothing.
    Dropping LIVING and sending STATIONARY alone would be a DIFFERENT movement block,
    which is exactly the kind of change that produces a silent no-render."""
    blk = bytearray()
    blk += bytes([UPDATETYPE_CREATE_OBJECT])
    blk += pack_guid(guid)
    blk += bytes([TYPEID_UNIT])

    blk += struct.pack("<H", UPDATEFLAG_LIVING | UPDATEFLAG_STATIONARY)
    blk += struct.pack("<I", 0)                            # movementFlags
    blk += struct.pack("<H", 0)                            # movementFlags2
    blk += struct.pack("<I", mstime())                     # timestamp
    blk += struct.pack("<ffff", d["x"], d["y"], d["z"], d["o"])
    blk += struct.pack("<I", 0)                            # fallTime
    for spd in (2.5, 7.0, 4.5, 4.722222, 2.5, 7.0, 4.5, 3.141594, 3.14):
        blk += struct.pack("<f", spd)

    fields = {
        OBJECT_FIELD_GUID:      u32le(guid & 0xFFFFFFFF),
        OBJECT_FIELD_GUID + 1:  u32le((guid >> 32) & 0xFFFFFFFF),
        OBJECT_FIELD_TYPE:      u32le(TYPEMASK_UNIT),
        OBJECT_FIELD_ENTRY:     u32le(ARCHIVE_DUMMY_ENTRY),
        OBJECT_FIELD_SCALE_X:   f32le(d.get("scale", 1.0)),
        UNIT_FIELD_BYTES_0:     u32le(1 << 8),             # race 0, class 1, mana user
        UNIT_FIELD_HEALTH:      u32le(d["hp"]),
        UNIT_FIELD_MAXHEALTH:   u32le(d["maxhp"]),
        UNIT_FIELD_LEVEL:       u32le(ARCHIVE_DUMMY_LEVEL),
        UNIT_FIELD_FACTIONTEMPLATE: u32le(ARCHIVE_DUMMY_FACTION),
        UNIT_FIELD_FLAGS:       u32le(0),                  # selectable, attackable
        UNIT_FIELD_BASEATTACKTIME:     u32le(2000),
        UNIT_FIELD_BASEATTACKTIME + 1: u32le(2000),
        UNIT_FIELD_BOUNDINGRADIUS: f32le(0.9),
        UNIT_FIELD_COMBATREACH:    f32le(1.5),
        UNIT_FIELD_DISPLAYID:       u32le(d.get("display", ARCHIVE_DUMMY_DISPLAY)),
        UNIT_FIELD_NATIVEDISPLAYID: u32le(d.get("display", ARCHIVE_DUMMY_DISPLAY)),
        UNIT_DYNAMIC_FLAGS:     u32le(0),
        UNIT_NPC_FLAGS:         u32le(0),
        UNIT_FIELD_BASE_HEALTH: u32le(d["maxhp"]),
    }
    blk += build_values_block(fields, UNIT_END)
    return struct.pack("<I", 1) + bytes(blk)


def smsg_creature_query_response(entry):
    """SMSG_CREATURE_QUERY_RESPONSE, field for field out of
    WorldSession::HandleCreatureQueryOpcode (QueryHandler.cpp:112).

    Only the archive's own dummy entry is known; anything else gets the not-found
    form, which is a single u32 with the top bit set -- silence would leave the
    client showing "Unknown" forever and re-asking."""
    if int(entry) != ARCHIVE_DUMMY_ENTRY:
        return struct.pack("<I", (int(entry) | 0x80000000) & 0xFFFFFFFF)
    out = bytearray()
    out += struct.pack("<I", ARCHIVE_DUMMY_ENTRY)
    out += ARCHIVE_DUMMY_NAME.encode("utf-8") + b"\x00"
    out += b"\x00" * 3                                      # name2, name3, name4
    out += ARCHIVE_DUMMY_SUBNAME.encode("utf-8") + b"\x00"  # SubName (the <title>)
    out += b"\x00"                                          # IconName
    out += struct.pack("<I", 0)                             # type_flags
    out += struct.pack("<I", 7)                             # type: Humanoid
    out += struct.pack("<I", 0)                             # family
    out += struct.pack("<I", 0)                             # rank: normal
    out += struct.pack("<II", 0, 0)                         # KillCredit[2]
    out += struct.pack("<4I", ARCHIVE_DUMMY_DISPLAY, 0, 0, 0)
    out += struct.pack("<ff", 1.0, 1.0)                     # ModHealth, ModMana
    out += bytes([0])                                       # RacialLeader
    out += struct.pack("<%dI" % MAX_CREATURE_QUEST_ITEMS,
                       *([0] * MAX_CREATURE_QUEST_ITEMS))
    out += struct.pack("<I", 0)                             # movementId
    return bytes(out)


def spawn_dummy(conn, eo, send_pkt, c, display=None, dist=None, scale=1.0):
    """Put one dummy in front of the caster and tell the client about it."""
    _DUMMY_SEQ[0] += 1
    guid = dummy_guid(_DUMMY_SEQ[0])
    # display/dist/scale are overridable on purpose.  "The client created the object
    # but nothing appeared" has two very different causes -- a model that will not load
    # and a position nobody is looking at -- and the only way to tell them apart is to
    # re-spawn with a model known to render, at a distance of zero.
    o = float(c["o"])
    r = ARCHIVE_DUMMY_DISTANCE if dist is None else float(dist)
    d = {"hp": ARCHIVE_DUMMY_HEALTH, "maxhp": ARCHIVE_DUMMY_HEALTH,
         "x": float(c["x"]) + r * math.cos(o),
         "y": float(c["y"]) + r * math.sin(o),
         "z": float(c["z"]), "o": (o + math.pi) % (2 * math.pi),
         "display": int(display) if display else ARCHIVE_DUMMY_DISPLAY,
         "scale": float(scale),
         "hit": 0.0}
    _DUMMIES[guid] = d
    send_pkt(conn, eo, SMSG_UPDATE_OBJECT, build_dummy_create_block(guid, d))
    return guid, d


def despawn_dummies(conn, eo, send_pkt):
    """Destroy every dummy this session spawned.  onDeath=0: no death animation for
    something that was never alive."""
    n = 0
    for guid in list(_DUMMIES):
        send_pkt(conn, eo, SMSG_DESTROY_OBJECT, struct.pack("<Q", guid) + bytes([0]))
        del _DUMMIES[guid]
        n += 1
    return n


def send_dummy_health(conn, eo, send_pkt, guid, d):
    """A values update on the dummy.  UNIT_END, not PLAYER_END -- a creature's
    m_valuesCount is 148, and sizing the mask to 1326 would describe fields the
    client's creature object does not have."""
    send_pkt(conn, eo, SMSG_UPDATE_OBJECT,
             build_values_update(guid, {UNIT_FIELD_HEALTH: u32le(d["hp"])}, UNIT_END))


def dummy_tick(conn, eo, send_pkt):
    """Heal every dummy back to full once it has been left alone.  Without this the
    first character to log in grinds the dummy to nothing and every later test reads
    as "the damage stopped working"."""
    now = time.monotonic()
    for guid, d in _DUMMIES.items():
        if d["hp"] < d["maxhp"] and (now - d["hit"]) >= ARCHIVE_DUMMY_RESET:
            d["hp"] = d["maxhp"]
            send_dummy_health(conn, eo, send_pkt, guid, d)


# ---- spell effects: damage and healing ---------------------------------------
def parse_spell_targets(blob):
    """SpellCastTargets::Read, far enough to learn what the cast was aimed at.

    Returns (mask, objectGuid).  Only the first packed guid is decoded: every other
    field in the block is either a location or an item, and neither can be the victim
    of a damage effect."""
    if len(blob) < 4:
        return 0, 0
    mask = struct.unpack_from("<I", blob, 0)[0]
    PACKED_FIRST = (0x0002 | 0x00010000 | 0x00000800 | 0x00000200 | 0x00008000)
    if not (mask & PACKED_FIRST):
        return mask, 0
    pos = 4
    if pos >= len(blob):
        return mask, 0
    bits = blob[pos]
    pos += 1
    guid = 0
    for i in range(8):
        if bits & (1 << i):
            if pos >= len(blob):
                return mask, 0
            guid |= blob[pos] << (8 * i)
            pos += 1
    return mask, guid


def effect_amount(e):
    """SpellEffectInfo::CalcValue, minus everything this archive cannot know.

    `basePoints + irand(1, dieSides)`, with dieSides 0 meaning no roll.  The DBC
    stores BasePoints one BELOW the displayed value, which is why the die-1 case adds
    exactly 1 and why an unused effect column reads -1 rather than 0.  Spell power,
    coefficients, crit, resistance and level scaling are all absent -- there are no
    stats here to scale by, and inventing a multiplier would make the number a lie
    rather than an approximation."""
    die = int(e["dieSides"])
    base = int(e["basePoints"])
    if die == 0:
        return base
    return base + (random.randint(1, die) if die >= 1 else random.randint(die, 1))


def smsg_spell_damage_log(target_guid, caster_guid, spell_id, damage,
                          overkill, school_mask):
    """SMSG_SPELLNONMELEEDAMAGELOG -- Unit::SendSpellNonMeleeDamageLog, Unit.cpp:6740.
    physicalLog 0 keeps the combat-log line in the "suffers N damage from <spell>"
    form, which is what a spell should read as."""
    out = bytearray()
    out += pack_guid(int(target_guid))
    out += pack_guid(int(caster_guid))
    out += struct.pack("<I", int(spell_id))
    out += struct.pack("<I", int(damage))
    out += struct.pack("<I", int(overkill))
    out += bytes([int(school_mask) & 0xFF])
    out += struct.pack("<I", 0)                            # absorbed
    out += struct.pack("<I", 0)                            # resisted
    out += bytes([0])                                      # physicalLog
    out += bytes([0])                                      # unused
    out += struct.pack("<I", 0)                            # blocked
    out += struct.pack("<I", 0)                            # HitInfo
    out += bytes([0])                                      # no extended data
    return bytes(out)


def smsg_spell_heal_log(target_guid, caster_guid, spell_id, heal, overheal):
    """SMSG_SPELLHEALLOG -- Unit::SendHealSpellLog, Unit.cpp:8389."""
    out = bytearray()
    out += pack_guid(int(target_guid))
    out += pack_guid(int(caster_guid))
    out += struct.pack("<I", int(spell_id))
    out += struct.pack("<I", int(heal))
    out += struct.pack("<I", int(overheal))
    out += struct.pack("<I", 0)                            # absorbed
    out += bytes([0])                                      # not a crit
    out += bytes([0])                                      # unused
    return bytes(out)


# ---- auras -------------------------------------------------------------------
# An aura is the first thing in this archive with a LIFETIME.  Damage and healing are
# events: the packet goes out and the server is done.  An aura has to be remembered,
# counted down, ticked, and then explicitly taken away again -- and each of those four
# has its own way of looking like "auras do not work".
#
# What the client does for free, and what it will not:
#
#   * The COUNTDOWN is free.  SMSG_AURA_UPDATE carries (maxDuration, remaining) once,
#     at application, and the client animates the sweep itself.  Do not re-send an
#     update every second to "keep it ticking" -- that restarts the animation and the
#     icon visibly stutters.
#   * The REMOVAL is not free.  The client's timer reaching zero greys the icon; it
#     does NOT delete it.  The aura stays in the frame until the server sends the same
#     slot back with spellId 0.  A server that forgets this looks like it works right
#     up until the buff never falls off.
#
# What this server resolves, and what it only shows.  Periodic health and power auras
# (3/8/20/21/24/53/64/89) tick for real: they move health, they send
# SMSG_PERIODICAURALOG, and they land in the combat log.  Every OTHER aura type is
# applied, displayed, counted down and removed correctly, and has no mechanical effect.
# That is a deliberate stopping point rather than an unfinished one: SPELL_AURA_MOD_STAT
# and its neighbours modify stats this archive does not compute, on a character sheet
# fed by constants (see max_pools), so "implementing" them would mean inventing a stat
# system in order to move a number nothing reads.  Kinetic Shield shows and expires; it
# does not absorb, because there is nothing here to absorb.
_AURAS = {}                             # target guid -> {slot: aura dict}
_AURA_LAST_TICK = [0.0]


def smsg_aura_update(target_guid, aura):
    """SMSG_AURA_UPDATE (0x496) -- AuraApplication::BuildUpdatePacket, SpellAuras.cpp:187.

        packguid target
        u8  slot
        u32 spellId                      <- 0 here means REMOVE, and nothing follows
        u8  flags ; u8 casterLevel ; u8 stacks
        [if !(flags & AFLAG_CASTER)]  packguid caster
        [if   flags & AFLAG_DURATION] u32 maxDuration ; u32 remaining

    Both tails are driven by the flags byte, so wrong flags do not produce a
    wrong-looking buff -- they produce a short read and a client that silently
    discards the packet.
    """
    out = bytearray()
    out += pack_guid(int(target_guid))
    out += bytes([aura["slot"] & 0xFF])
    if aura.get("removing"):
        out += struct.pack("<I", 0)
        return bytes(out)
    flags = int(aura["flags"])
    out += struct.pack("<I", int(aura["spell"]))
    out += bytes([flags & 0xFF, int(aura["level"]) & 0xFF,
                  max(1, int(aura["stacks"])) & 0xFF])
    if not (flags & AFLAG_CASTER):
        out += pack_guid(int(aura["caster"]))
    if flags & AFLAG_DURATION:
        out += struct.pack("<I", int(aura["maxdur_ms"]))
        out += struct.pack("<I", int(aura_remaining_ms(aura)))
    return bytes(out)


def smsg_periodic_aura_log(target_guid, caster_guid, spell_id, aura_type, amount,
                           overflow, school_mask):
    """SMSG_PERIODICAURALOG (0x24E) -- Unit::SendPeriodicAuraLog, Unit.cpp.

    The tail is switched on the AURA TYPE, not on the spell, and the shapes are
    different lengths -- a heal carries no school and no resist.  Sending the damage
    shape for a heal is a silent mis-parse, not an error.
    """
    out = bytearray()
    out += pack_guid(int(target_guid))
    out += pack_guid(int(caster_guid))
    out += struct.pack("<I", int(spell_id))
    out += struct.pack("<I", 1)                            # count: one effect logged
    out += struct.pack("<I", int(aura_type))
    if aura_type in AURA_PERIODIC_HARM:
        out += struct.pack("<I", int(amount))              # damage
        out += struct.pack("<I", int(overflow))            # overkill
        out += struct.pack("<I", int(school_mask))
        out += struct.pack("<I", 0)                        # absorbed
        out += struct.pack("<I", 0)                        # resisted
        out += bytes([0])                                  # not a critical tick
    elif aura_type in AURA_PERIODIC_HELP:
        out += struct.pack("<I", int(amount))              # healing
        out += struct.pack("<I", int(overflow))            # overheal
        out += struct.pack("<I", 0)                        # absorbed
        out += bytes([0])                                  # not a critical tick
    elif aura_type in AURA_PERIODIC_POWER:
        out += struct.pack("<I", 0)                        # power type: mana
        out += struct.pack("<I", int(amount))
    else:
        return b""
    return bytes(out)


def aura_remaining_ms(aura):
    """Milliseconds left, or the full duration for an aura that never expires."""
    if aura.get("expires") is None:
        return int(aura["maxdur_ms"])
    return max(0, int((aura["expires"] - time.monotonic()) * 1000.0))


def aura_positive(info, aura_types, self_cast):
    """AFLAG_POSITIVE or AFLAG_NEGATIVE -- which half of the frame the icon lands in.

    Real 3.3.5a runs SpellInfo::IsPositiveEffect, several hundred lines of special
    cases, because it uses the answer for immunity, dispel and AI decisions too.
    Nothing here does any of that, so this asks only the question that decides the
    display: does the aura obviously harm whoever is holding it.  A self-cast is a buff
    unless its type is explicitly harmful -- a self-applied DoT is a real thing and
    should read as one.
    """
    if any(t in AURA_TYPES_NEGATIVE for t in aura_types):
        return AFLAG_NEGATIVE
    return AFLAG_POSITIVE


def free_aura_slot(target_guid, spell_id, caster_guid):
    """The slot this application belongs in.

    A recast of the same spell by the same caster REUSES its slot -- that is what makes
    it a refresh instead of a second icon, and it is what the real server does
    (AuraApplication's constructor looks for an existing application first).  Otherwise
    the lowest free slot, so the frame fills left to right.
    """
    held = _AURAS.setdefault(int(target_guid), {})
    for slot, a in held.items():
        if int(a["spell"]) == int(spell_id) and int(a["caster"]) == int(caster_guid):
            return slot
    for slot in range(ARCHIVE_MAX_AURA_SLOTS):
        if slot not in held:
            return slot
    return None


def apply_aura(conn, eo, send_pkt, c, info, target_guid):
    """Apply every SPELL_EFFECT_APPLY_AURA effect of one cast as a single aura.

    ONE aura, not one per effect: the client's frame is keyed by slot, and a spell with
    three aura effects is still one icon.  The effect indices ride in the flags byte
    (AFLAG_EFF_INDEX_0..2), which is how the client knows how many it covers.

    The periodic amount is rolled ONCE, here, and every tick reuses it.  That is what
    retail does -- a HoT does not re-roll each second -- and it also means the tick
    lines add up to something a human can check against the tooltip.
    """
    if not info:
        return []
    caster = int(c["guid"])
    tgt = int(target_guid) if target_guid else caster
    # An aura with no target is a self-cast; that IS what the client does with a
    # friendly spell and an empty target frame, and Nanobot Reconstruction is exactly
    # this case.
    if tgt not in _DUMMIES and tgt != caster:
        tgt = caster
    now = time.monotonic()

    eff_mask, aura_types, ticks = 0, [], []
    for n, e in enumerate(info["effects"]):
        if int(e["effect"]) != SPELL_EFFECT_APPLY_AURA:
            continue
        atype = int(e["aura"])
        eff_mask |= (1 << n)
        aura_types.append(atype)
        period = int(e.get("amplitude", 0))
        if period > 0 and atype in (AURA_PERIODIC_HARM + AURA_PERIODIC_HELP
                                    + AURA_PERIODIC_POWER):
            amount = max(0, effect_amount(e))
            if amount:
                ticks.append({"index": n, "aura": atype, "amount": amount,
                              "period": period / 1000.0,
                              "next": now + period / 1000.0})
    if not eff_mask:
        return []

    dur_ms = spell_duration_ms(info)
    flags = eff_mask
    if tgt == caster:
        flags |= AFLAG_CASTER
    flags |= aura_positive(info, aura_types, tgt == caster)
    # SPELL_ATTR5_NO_DURATION_DISPLAY is the spell saying "draw me with no timer".
    # Honour it: overriding it puts a countdown on icons meant to look permanent, a
    # cosmetic bug nobody would ever trace back to here.
    if dur_ms > 0 and not (int(info.get("attributesEx5", 0))
                           & SPELL_ATTR5_NO_DURATION_DISPLAY):
        flags |= AFLAG_DURATION

    slot = free_aura_slot(tgt, info["id"], caster)
    if slot is None:
        return ["no free aura slot (%d in use)" % ARCHIVE_MAX_AURA_SLOTS]
    prev = _AURAS[tgt].get(slot)
    stacks = 1
    if prev is not None and int(prev["spell"]) == int(info["id"]):
        maxstack = int(info.get("stackAmount", 0))
        stacks = min(maxstack, int(prev["stacks"]) + 1) if maxstack else 1

    aura = {"spell": int(info["id"]), "name": info.get("name") or "?", "slot": slot,
            "caster": caster, "target": tgt, "flags": flags,
            "level": max(1, int(c["level"])), "stacks": stacks,
            "maxdur_ms": dur_ms, "school": int(info.get("schoolMask", 0)),
            "expires": (now + dur_ms / 1000.0) if (flags & AFLAG_DURATION) else None,
            "ticks": ticks}
    _AURAS[tgt][slot] = aura
    send_pkt(conn, eo, SMSG_AURA_UPDATE, smsg_aura_update(tgt, aura))

    return ["aura %s (type%s %s) on %s, slot %d, %s%s"
            % (aura["name"], "" if len(aura_types) == 1 else "s",
               "+".join(str(t) for t in aura_types),
               "self" if tgt == caster else "the dummy", slot,
               ("%.1fs" % (dur_ms / 1000.0)) if dur_ms else "no duration",
               (", %s every %.1fs"
                % ("/".join(str(t["amount"]) for t in ticks), ticks[0]["period"]))
               if ticks else "")]


def remove_aura(conn, eo, send_pkt, target_guid, slot, why="expired"):
    """Take one aura off, on the wire as well as in memory.

    The wire half is the one that matters and the one that is easy to skip: the
    client's own timer hitting zero only GREYS the icon.  Until this packet arrives the
    buff is still in the frame, still returned by UnitAura, and a re-application looks
    like it stacked.
    """
    held = _AURAS.get(int(target_guid), {})
    aura = held.pop(int(slot), None)
    if aura is None:
        return None
    aura["removing"] = True
    send_pkt(conn, eo, SMSG_AURA_UPDATE, smsg_aura_update(target_guid, aura))
    return "aura %s off slot %d (%s)" % (aura["name"], slot, why)


def aura_periodic_apply(conn, eo, send_pkt, c, aura, tick):
    """One periodic tick: move the number, log it, push the new health.

    Returns a short log line, or None when the tick had nothing to do.
    """
    caster, tgt = int(aura["caster"]), int(aura["target"])
    amount = int(tick["amount"])
    atype = int(tick["aura"])
    dummy = _DUMMIES.get(tgt)

    if atype in AURA_PERIODIC_HELP:
        if dummy is not None:
            healed = min(amount, dummy["maxhp"] - dummy["hp"])
            dummy["hp"] += healed
            send_pkt(conn, eo, SMSG_PERIODICAURALOG,
                     smsg_periodic_aura_log(tgt, caster, aura["spell"], atype,
                                            amount, amount - healed, aura["school"]))
            send_dummy_health(conn, eo, send_pkt, tgt, dummy)
            return "tick %s: %d healing to the dummy" % (aura["name"], amount)
        st = unit_state(c)
        maxhp = max_pools(c)[0]
        healed = min(amount, maxhp - st["hp"])
        st["hp"] += healed
        send_pkt(conn, eo, SMSG_PERIODICAURALOG,
                 smsg_periodic_aura_log(tgt, caster, aura["spell"], atype,
                                        amount, amount - healed, aura["school"]))
        send_power_update(conn, eo, send_pkt, c)
        return "tick %s: %d healing (%d/%d)" % (aura["name"], amount, st["hp"], maxhp)

    if atype in AURA_PERIODIC_HARM:
        if dummy is not None:
            over = max(0, amount - dummy["hp"])
            dummy["hp"] = max(0, dummy["hp"] - amount)
            dummy["hit"] = time.monotonic()
            send_pkt(conn, eo, SMSG_PERIODICAURALOG,
                     smsg_periodic_aura_log(tgt, caster, aura["spell"], atype,
                                            amount, over, aura["school"]))
            send_dummy_health(conn, eo, send_pkt, tgt, dummy)
            return ("tick %s: %d damage to the dummy (%d left)"
                    % (aura["name"], amount, dummy["hp"]))
        st = unit_state(c)
        over = max(0, amount - st["hp"])
        st["hp"] = max(0, st["hp"] - amount)
        send_pkt(conn, eo, SMSG_PERIODICAURALOG,
                 smsg_periodic_aura_log(tgt, caster, aura["spell"], atype,
                                        amount, over, aura["school"]))
        send_power_update(conn, eo, send_pkt, c)
        return "tick %s: %d damage to self (%d left)" % (aura["name"], amount, st["hp"])

    if atype in AURA_PERIODIC_POWER:
        st = unit_state(c)
        maxp = max_pools(c)[1]
        gained = min(amount, maxp - st["power"])
        st["power"] += gained
        send_pkt(conn, eo, SMSG_PERIODICAURALOG,
                 smsg_periodic_aura_log(tgt, caster, aura["spell"], atype,
                                        amount, 0, aura["school"]))
        send_power_update(conn, eo, send_pkt, c)
        return "tick %s: %d power (%d/%d)" % (aura["name"], gained, st["power"], maxp)
    return None


def aura_tick(conn, eo, send_pkt, c):
    """Advance every aura on this character and on the dummies.

    CALLED FROM THE SESSION LOOP -- both on every inbound packet and, more importantly,
    on every recv timeout (_idle), which is what actually paces it.  There is no timer
    thread in this server on purpose (see the time-sync note).

    An earlier version clocked this off client traffic instead, on a measurement that
    CMSG_STANDSTATECHANGE arrives ~178 times a second.  It does -- but only while the
    client is in the state that generates it.  A client standing still sends nothing
    but CMSG_PING every 5 s, so ticks arrived in bursts of five.  The socket timeout is
    ARCHIVE_AURA_TICK_MIN and this rate limit keeps the fast path cheap when packets
    DO flood in; a tenth of a second of error on a 1 s HoT is invisible.

    Returns the log lines for whatever actually happened, so a quiet tick costs one
    subtraction and an empty list.
    """
    now = time.monotonic()
    if (now - _AURA_LAST_TICK[0]) < ARCHIVE_AURA_TICK_MIN:
        return []
    _AURA_LAST_TICK[0] = now
    lines = []
    for tgt in list(_AURAS.keys()):
        for slot, aura in list(_AURAS.get(tgt, {}).items()):
            for tick in aura["ticks"]:
                # A catch-up loop, not a single "is it due" test.  The clock here is
                # the client's packet flow, so a stall -- a loading screen, a stutter,
                # a breakpoint -- would otherwise silently swallow ticks.
                while tick["next"] <= now:
                    if aura["expires"] is not None and tick["next"] > aura["expires"]:
                        break
                    line = aura_periodic_apply(conn, eo, send_pkt, c, aura, tick)
                    if line:
                        lines.append(line)
                    tick["next"] += tick["period"]
            if aura["expires"] is not None and now >= aura["expires"]:
                line = remove_aura(conn, eo, send_pkt, tgt, slot, "duration elapsed")
                if line:
                    lines.append(line)
    return lines


def apply_spell_effects(conn, eo, send_pkt, c, info, target_guid):
    """Resolve the direct-damage and direct-heal effects of one cast.

    Returns a list of short strings for the log, empty when the spell has neither --
    which is the common case.  Of this Tinker's fourteen bar spells exactly TWO carry
    a direct effect: Bomb Toss (801005, SCHOOL_DAMAGE) and Zap! (680196, HEAL).  All
    the rest put their damage in triggered spells (effect 64) and periodic auras
    (effect 6/27), so a spellbook full of abilities that do nothing visible here is
    the honest state of (b), not a bug in it.

    AND BOMB TOSS CANNOT BE CAST HERE.  Its Attributes have bit 0x2 set
    (SPELL_ATTR0_USES_RANGED_SLOT), so the client refuses it client-side with "Must
    have a Ranged Weapon equipped" and never sends CMSG_CAST_SPELL -- there is no
    item system in this archive to equip one.  A scan of all 10255 CA entries found
    ZERO Tinker entries with a direct-damage effect and that attribute clear, so the
    damage path is not testable with a Tinker spell at all.  It was verified instead
    with Scorch (Scorched Earth) 81226, a Mage entry learned onto this Free-Pick
    character -- which is exactly what a classless realm is for.  See the handoff.

    A damage effect with no valid target hits nothing rather than falling back to the
    caster: "cast at nobody" and "cast at yourself" are different events and the
    combat log should not confuse them."""
    if not info:
        return []
    caster = int(c["guid"])
    out = []
    aura_done = [False]
    dummy = _DUMMIES.get(int(target_guid))

    for e in info["effects"]:
        eff = int(e["effect"])

        if eff == SPELL_EFFECT_SCHOOL_DAMAGE:
            amount = max(0, effect_amount(e))
            if not amount:
                continue
            if dummy is not None:
                overkill = max(0, amount - dummy["hp"])
                dummy["hp"] = max(0, dummy["hp"] - amount)
                dummy["hit"] = time.monotonic()
                send_pkt(conn, eo, SMSG_SPELLNONMELEEDAMAGELOG,
                         smsg_spell_damage_log(target_guid, caster, info["id"],
                                               amount, overkill, info["schoolMask"]))
                send_dummy_health(conn, eo, send_pkt, int(target_guid), dummy)
                out.append("%d damage to the dummy (%d/%d left)"
                           % (amount, dummy["hp"], dummy["maxhp"]))
            elif int(target_guid) == caster:
                st = unit_state(c)
                overkill = max(0, amount - st["hp"])
                st["hp"] = max(0, st["hp"] - amount)
                send_pkt(conn, eo, SMSG_SPELLNONMELEEDAMAGELOG,
                         smsg_spell_damage_log(caster, caster, info["id"],
                                               amount, overkill, info["schoolMask"]))
                send_power_update(conn, eo, send_pkt, c)
                out.append("%d damage to self (%d hp left)" % (amount, st["hp"]))
            else:
                out.append("%d damage with no target -- dropped" % amount)

        elif eff == SPELL_EFFECT_APPLY_AURA:
            # Handled once for the whole spell rather than once per effect -- a spell
            # with three aura effects is still one icon in one slot -- so the loop only
            # needs to notice that there IS one.
            if not aura_done[0]:
                aura_done[0] = True
                out += apply_aura(conn, eo, send_pkt, c, info, target_guid)

        elif eff == SPELL_EFFECT_HEAL:
            amount = max(0, effect_amount(e))
            if not amount:
                continue
            if dummy is not None:
                healed = min(amount, dummy["maxhp"] - dummy["hp"])
                dummy["hp"] += healed
                send_pkt(conn, eo, SMSG_SPELLHEALLOG,
                         smsg_spell_heal_log(target_guid, caster, info["id"],
                                             amount, amount - healed))
                send_dummy_health(conn, eo, send_pkt, int(target_guid), dummy)
                out.append("%d healing to the dummy (%d overheal)"
                           % (amount, amount - healed))
            else:
                # A heal with no target is a heal on yourself -- that IS what the
                # client does with a friendly spell and an empty target frame.
                st = unit_state(c)
                maxhp = max_pools(c)[0]
                healed = min(amount, maxhp - st["hp"])
                st["hp"] += healed
                send_pkt(conn, eo, SMSG_SPELLHEALLOG,
                         smsg_spell_heal_log(caster, caster, info["id"],
                                             amount, amount - healed))
                send_power_update(conn, eo, send_pkt, c)
                out.append("%d healing to self (%d/%d, %d overheal)"
                           % (amount, st["hp"], maxhp, amount - healed))

    return out


# ---- casting -----------------------------------------------------------------
# The archive has no spell system: nothing resolves effects, applies auras or spends
# power.  What it does have to do is CLOSE the cast, because the client treats a cast
# it has announced as pending until the server answers.  With no answer the button
# stays locked and every later cast of that spell is refused client-side, which reads
# as "the spell does not work" when the real story is a missing reply.

def parse_cmsg_cast_spell(body):
    """CMSG_CAST_SPELL (0x12E): u8 castCount | u32 spellId | u8 castFlags | targets.
    The SpellCastTargets tail is kept as opaque bytes -- see smsg_spell_go.
    Returns (castCount, spellId, castFlags, targetsBlob)."""
    if len(body) < 6:
        return 0, 0, 0, b""
    return body[0], struct.unpack_from("<I", body, 1)[0], body[5], bytes(body[6:])


def smsg_spell_go(c, cast_count, spell_id, targets, hit_guid=None):
    """SMSG_SPELL_GO (0x132) -- "the cast happened".  This is what ends the pending
    cast, starts the global cooldown and plays the visual.

        packguid castItem (the caster itself when no item is involved)
        packguid caster
        u8  castCount ; u32 spellId ; u32 castFlags ; u32 timestampMs
        u8  hitCount  ; hitCount  * u64 targetGuid    <- FULL guids here, not packed
        u8  missCount ; missCount * (u64 guid, u8 missCondition, [u8 reflectResult])
        <SpellCastTargets>
        [castFlags & CAST_FLAG_POWER_LEFT_SELF] u32 powerRemaining

    One hit and no misses.  The hit is whatever the cast was actually aimed at, and
    it matters: the hit list is where the client puts the impact visual, so reporting
    the caster for a spell thrown at a dummy plays the explosion on the player.  It
    falls back to the caster when the cast named nobody, which is what a self-buff is.

    The SpellCastTargets block is the client's own bytes echoed back.  That is exact
    rather than lazy: SpellCastTargets::Read and ::Write are byte-for-byte identical
    for every mask this server can see -- an empty mask writes only the u32 and stops,
    and TARGET_FLAG_UNIT / SOURCE_LOCATION / DEST_LOCATION are a packed guid (plus
    three floats) on both sides.  CAST_FLAG_POWER_LEFT_SELF is never set, so no power
    field follows.  CAST_FLAG_UNKNOWN_9 is the flag AzerothCore always starts from."""
    guid = int(c["guid"])
    pg = pack_guid(guid)
    out = bytearray()
    out += pg                                              # castItem == caster
    out += pg                                              # caster
    out += bytes([cast_count & 0xFF])
    out += struct.pack("<I", int(spell_id))
    out += struct.pack("<I", CAST_FLAG_UNKNOWN_9)
    out += struct.pack("<I", int(time.time() * 1000) & 0xFFFFFFFF)
    out += bytes([1]) + struct.pack("<Q", int(hit_guid) if hit_guid else guid)
    out += bytes([0])                                      # no misses
    out += targets if targets else struct.pack("<I", TARGET_FLAG_NONE)
    return bytes(out)


def smsg_cast_failed(cast_count, spell_id, result=SPELL_FAILED_NOT_KNOWN):
    """SMSG_CAST_FAILED (0x130): u8 castCount | u32 spellId | u8 result.
    SPELL_FAILED_NOT_KNOWN is deliberate -- it is not one of the results that carries
    an extra payload, so this stays three fields wide whatever went wrong."""
    return bytes([cast_count & 0xFF]) + struct.pack("<I", int(spell_id)) + bytes([result & 0xFF])


# ---------------------------------------------------------------------------
# Build store.  A "build" here is only what the archive can honestly hold: a name
# and the entry list activating it should learn.  Ascension kept the real ones
# server-side, so there is nothing to import -- ".build save <id>" snapshots the
# current .known set under a build id, which is what makes a later 0x5C2 for that
# id do something instead of reporting an unknown build.
def load_builds():
    try:
        with open(BUILDS_PATH, "r", encoding="utf-8") as fp:
            return json.load(fp)
    except Exception:
        return {}

def save_builds(db):
    try:
        tmp = BUILDS_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fp:
            json.dump(db, fp, indent=2)
        os.replace(tmp, BUILDS_PATH)
    except Exception as e:
        log("        !! save_builds failed: %r" % e)

def build_rows(build):
    """A stored build's entry list, in the {id, rank} shape set_known wants."""
    out = []
    for r in (build or {}).get("entries", []):
        try:
            out.append({"id": int(r["id"]), "rank": int(r.get("rank", 1))})
        except (KeyError, TypeError, ValueError):
            continue
    out.sort(key=lambda r: r["id"])
    return out


def send_known_entries(conn, eo, send_pkt, c):
    """Replay this character's learned CA entries.  Always sent, even when empty:
    a zero-count 0x726 is the well-formed "you know nothing", it drives the same
    ASCENSION_KNOWN_ENTRIES_UPDATED refresh, and re-sending the full set is how the
    client is told about removals as well as additions.  Returns the record count."""
    rows = known_for(c["guid"])
    send_pkt(conn, eo, SMSG_CA_KNOWN_ENTRIES,
             smsg_ca_known_entries([(r["id"], r["rank"]) + KNOWN_UNKNOWN_FIELDS
                                    for r in rows]))
    # The CoA tree and the spellbook are separate systems, so the entries the panel
    # now shows as known have to be granted as real spells too.  At world entry
    # send_spellbook has already primed the cache and this diff is empty.
    learned, removed = sync_spellbook(conn, eo, send_pkt, c)
    if learned or removed:
        log("        spellbook: +%d spell(s), -%d" % (learned, removed))
    return len(rows)


def send_essence_budget(conn, eo, send_pkt, c):
    """Fill the client's essence record store -- one packet per DBC row, verbatim.

    The store is keyed by row id, and the client has ALREADY loaded all 5600 rows of
    CharacterAdvancementEssence.dbc into it before this server says anything.  So an
    id here is not a free slot to allocate: reusing one overwrites a real row.  Every
    record therefore goes out with its own id, level, key and flags, which

      * repairs the store no matter what an earlier session wrote into it,
      * matches whatever (level, key, flags) the character's CA state happens to hold
        without this server needing to know it -- see the SMSG_CA_ESSENCE_BUDGET note
        up top for how that state is reached and what it holds here, and
      * carries Ascension's real numbers rather than an invented curve.

    ".essence <n>" substitutes the AE/TE pair on every row on the way out, so the
    override lands on the family the client reads whichever one that is.  Nothing else
    about a row is ever altered.  Returns the number of records sent."""
    pkts = []
    for (rid, level, key, f0, f1, f2, f3, ability, talent) in ESSENCE_ROWS:
        if ESSENCE_OVERRIDE is not None:
            ability, talent = ESSENCE_OVERRIDE
        combo = (1 if f0 else 0) | ((1 if f1 else 0) << 1)               | ((1 if f2 else 0) << 2) | ((1 if f3 else 0) << 3)
        pkts.append((SMSG_CA_ESSENCE_BUDGET,
                     smsg_ca_essence_budget(rid, level, ability, talent, combo, key)))
    return send_batch(conn, eo, pkts, "SMSG_CA_ESSENCE_BUDGET")


def smsg_item_query_single_response(entry):
    """SMSG_ITEM_QUERY_SINGLE_RESPONSE, field-for-field in the order AzerothCore's
    WorldSession::HandleItemQuerySingleOpcode writes it (ItemHandler.cpp).  The client
    has to have this: Cache\\WDB\\enUS\\itemcache.wdb here is 32 bytes -- a bare header
    with no records -- so nothing is cached and every entry is asked for on sight.
    Unknown entries get the stock `entry | 0x80000000` "no such item" reply."""
    t = ITEM_TEMPLATES.get(entry)
    if not t:
        return struct.pack("<I", entry | 0x80000000)

    o = bytearray()
    o += struct.pack("<I", entry)
    o += struct.pack("<I", 15)                     # Class = Miscellaneous
    o += struct.pack("<I", 0)                      # SubClass = Junk
    o += struct.pack("<i", -1)                     # SoundOverrideSubclass
    o += t["name"].encode("utf-8") + b"\x00"       # Name1
    o += b"\x00\x00\x00"                           # Name2..4: blizz sends empty
    o += struct.pack("<I", 0)                      # DisplayInfoID (panel draws its own icon)
    o += struct.pack("<I", t["quality"])
    o += struct.pack("<I", 0)                      # Flags
    o += struct.pack("<I", 0)                      # Flags2
    o += struct.pack("<I", 0)                      # BuyPrice
    o += struct.pack("<I", 0)                      # SellPrice
    o += struct.pack("<I", 0)                      # InventoryType = NON_EQUIP
    o += struct.pack("<i", -1)                     # AllowableClass = all
    o += struct.pack("<i", -1)                     # AllowableRace  = all
    o += struct.pack("<I", 1)                      # ItemLevel
    o += struct.pack("<I", 0)                      # RequiredLevel
    o += struct.pack("<I", 0)                      # RequiredSkill
    o += struct.pack("<I", 0)                      # RequiredSkillRank
    o += struct.pack("<I", 0)                      # RequiredSpell
    o += struct.pack("<I", 0)                      # RequiredHonorRank
    o += struct.pack("<I", 0)                      # RequiredCityRank
    o += struct.pack("<I", 0)                      # RequiredReputationFaction
    o += struct.pack("<I", 0)                      # RequiredReputationRank
    o += struct.pack("<i", 0)                      # MaxCount (0 = no unique limit)
    o += struct.pack("<i", t["stackable"])
    o += struct.pack("<I", 0)                      # ContainerSlots
    o += struct.pack("<I", 0)                      # StatsCount -> no stat pairs follow
    o += struct.pack("<I", 0)                      # ScalingStatDistribution
    o += struct.pack("<I", 0)                      # ScalingStatValue
    for _ in range(2):                             # MAX_ITEM_PROTO_DAMAGES
        o += struct.pack("<ffI", 0.0, 0.0, 0)      #   DamageMin, DamageMax, DamageType
    for _ in range(7):                             # Armor + 6 resistances
        o += struct.pack("<I", 0)
    o += struct.pack("<I", 0)                      # Delay
    o += struct.pack("<I", 0)                      # AmmoType
    o += struct.pack("<f", 0.0)                    # RangedModRange
    for _ in range(5):                             # MAX_ITEM_PROTO_SPELLS, all empty
        o += struct.pack("<IIIiIi", 0, 0, 0, -1, 0, -1)
    o += struct.pack("<I", 0)                      # Bonding = NO_BIND
    o += t["description"].encode("utf-8") + b"\x00"
    o += struct.pack("<I", 0)                      # PageText
    o += struct.pack("<I", 0)                      # LanguageID
    o += struct.pack("<I", 0)                      # PageMaterial
    o += struct.pack("<I", 0)                      # StartQuest
    o += struct.pack("<I", 0)                      # LockID
    o += struct.pack("<i", 0)                      # Material
    o += struct.pack("<I", 0)                      # Sheath
    o += struct.pack("<I", 0)                      # RandomProperty
    o += struct.pack("<I", 0)                      # RandomSuffix
    o += struct.pack("<I", 0)                      # Block
    o += struct.pack("<I", 0)                      # ItemSet
    o += struct.pack("<I", 0)                      # MaxDurability
    o += struct.pack("<I", 0)                      # Area
    o += struct.pack("<I", 0)                      # Map
    o += struct.pack("<I", 0)                      # BagFamily
    o += struct.pack("<I", 0)                      # TotemCategory
    for _ in range(3):                             # MAX_ITEM_PROTO_SOCKETS
        o += struct.pack("<II", 0, 0)              #   Color, Content
    o += struct.pack("<I", 0)                      # socketBonus
    o += struct.pack("<I", 0)                      # GemProperties
    o += struct.pack("<i", -1)                     # RequiredDisenchantSkill
    o += struct.pack("<f", 0.0)                    # ArmorDamageModifier
    o += struct.pack("<I", 0)                      # Duration (0 = permanent)
    o += struct.pack("<i", 0)                      # ItemLimitCategory
    o += struct.pack("<I", 0)                      # HolidayId
    return bytes(o)


def build_item_create_block(item_guid, owner_guid, entry, count):
    """One CREATE_OBJECT block for a bag item.  Item::Item() sets
    m_updateFlag = UPDATEFLAG_LOWGUID (0x0010) and nothing else, so the movement
    block is just the u16 flags followed by the u32 guid counter -- no position,
    no speeds (Object::BuildMovementUpdate, the UPDATEFLAG_LOWGUID switch)."""
    blk = bytearray()
    # Object::BuildCreateUpdateBlockForPlayer only promotes to CREATE_OBJECT2
    # inside "if (flags & UPDATEFLAG_STATIONARY_POSITION)", which an Item never
    # has -- so items are always plain UPDATETYPE_CREATE_OBJECT (2).
    blk += bytes([UPDATETYPE_CREATE_OBJECT])
    blk += pack_guid(item_guid)
    blk += bytes([TYPEID_ITEM])
    blk += struct.pack("<H", UPDATEFLAG_LOWGUID)
    blk += struct.pack("<I", item_guid & 0xFFFFFFFF)       # GetGUID().GetCounter()

    fields = {
        OBJECT_FIELD_GUID:      u32le(item_guid & 0xFFFFFFFF),
        OBJECT_FIELD_GUID + 1:  u32le((item_guid >> 32) & 0xFFFFFFFF),
        OBJECT_FIELD_TYPE:      u32le(TYPEMASK_ITEM),
        OBJECT_FIELD_ENTRY:     u32le(entry),
        OBJECT_FIELD_SCALE_X:   f32le(1.0),
        ITEM_FIELD_OWNER:       u32le(owner_guid & 0xFFFFFFFF),
        ITEM_FIELD_OWNER + 1:   u32le((owner_guid >> 32) & 0xFFFFFFFF),
        ITEM_FIELD_CONTAINED:   u32le(owner_guid & 0xFFFFFFFF),
        ITEM_FIELD_CONTAINED + 1: u32le((owner_guid >> 32) & 0xFFFFFFFF),
        ITEM_FIELD_STACK_COUNT: u32le(count),
        ITEM_FIELD_FLAGS:       u32le(0),
        ITEM_FIELD_DURABILITY:    u32le(0),
        ITEM_FIELD_MAXDURABILITY: u32le(0),
    }
    blk += build_values_block(fields, ITEM_END)
    return bytes(blk)


def archive_inventory(c):
    """The bag contents this archive hands every character: one stack of each essence.
    Returns [(backpackSlot, itemGuid, entry, count)] -- item guids are derived from the
    character guid so they stay stable across relogs."""
    owner = int(c["guid"])
    ae, te = essence_for(c["level"], c["class"])
    out = []
    for slot, (entry, count) in enumerate(((ITEM_ABILITY_ESSENCE, ae),
                                           (ITEM_TALENT_ESSENCE,  te))):
        if count <= 0:
            continue
        out.append((slot, HIGHGUID_ITEM | (owner * 16 + slot + 1), entry, count))
    return out


def build_player_create_object(c):
    """SMSG_UPDATE_OBJECT body: one CREATE_OBJECT2 block for the client's own player.
    Layout per wire-ref.md (AzerothCore 3.3.5a: BOUNDINGRADIUS/COMBATREACH precede
    DISPLAYID/NATIVEDISPLAYID in this fork)."""
    guid = int(c["guid"])
    flags = UPDATEFLAG_SELF | UPDATEFLAG_LIVING | UPDATEFLAG_STATIONARY   # 0x0061

    blk = bytearray()
    blk += bytes([UPDATETYPE_CREATE_OBJECT2])
    blk += pack_guid(guid)
    blk += bytes([TYPEID_PLAYER])

    # --- movement block (UPDATEFLAG_LIVING) ---
    blk += struct.pack("<H", flags)
    blk += struct.pack("<I", 0)                            # movementFlags
    blk += struct.pack("<H", 0)                            # movementFlags2
    blk += struct.pack("<I", mstime())                     # timestamp
    blk += struct.pack("<ffff", c["x"], c["y"], c["z"], c["o"])
    blk += struct.pack("<I", 0)                            # fallTime
    for spd in (2.5, 7.0, 4.5, 4.722222, 2.5, 7.0, 4.5, 3.141594, 3.14):   # 9 speeds, wire order
        blk += struct.pack("<f", spd)
    # flags 0x0061: SELF has no payload, LIVING done, STATIONARY sits in the LIVING
    # else-branch so it emits nothing; no other trailing blocks -> movement ends here.

    # --- values block ---
    race, clas, gender = c["race"] & 0xFF, c["class"] & 0xFF, c["gender"] & 0xFF
    power = chardata.power_for(clas) & 0xFF
    bytes0 = race | (clas << 8) | (gender << 16) | (power << 24)
    player_bytes = (c["skin"] & 0xFF) | ((c["face"] & 0xFF) << 8) \
        | ((c["hairStyle"] & 0xFF) << 16) | ((c["hairColor"] & 0xFF) << 24)
    # byte0 facial hair, byte2 bank bag slots, byte3 REST STATE.  The rest-state
    # byte is not optional: the client's GetRestState() reads it and answers nil,
    # nil, nil when it is 0, and MainMenuBar's ExhaustionTick handler compares that
    # nil against a number on PLAYER_ENTERING_WORLD -- "MainMenuBar.lua:381: attempt
    # to compare number with nil", which is what raises the login "UI Error" banner.
    # 1 = rested, 2 = normal (TrinityCore REST_STATE_NOT_RAF_LINKED), 6 = RAF.
    player_bytes2 = (c["facialHair"] & 0xFF) | (REST_STATE_NORMAL << 24)
    display = int(c["displayId"])
    faction = chardata.RACE_FACTION.get(race, 35)
    fields = {
        0:   u32le(guid & 0xFFFFFFFF),        # OBJECT_FIELD_GUID (low)
        1:   u32le((guid >> 32) & 0xFFFFFFFF),# OBJECT_FIELD_GUID (high) = 0 for players
        2:   u32le(TYPEMASK_PLAYER),          # OBJECT_FIELD_TYPE
        4:   f32le(1.0),                      # OBJECT_FIELD_SCALE_X
        UNIT_FIELD_BYTES_0: u32le(bytes0),    # race|class|gender|power
        24:  u32le(unit_state(c)["hp"]),      # UNIT_FIELD_HEALTH
        32:  u32le(max_pools(c)[0]),          # UNIT_FIELD_MAXHEALTH
        54:  u32le(c["level"] & 0xFFFFFFFF),  # UNIT_FIELD_LEVEL
        55:  u32le(faction),                  # UNIT_FIELD_FACTIONTEMPLATE
        65:  f32le(0.306),                    # UNIT_FIELD_BOUNDINGRADIUS
        66:  f32le(1.5),                      # UNIT_FIELD_COMBATREACH
        67:  u32le(display),                  # UNIT_FIELD_DISPLAYID
        68:  u32le(display),                  # UNIT_FIELD_NATIVEDISPLAYID
        UNIT_FIELD_BYTES_1: u32le(STAND_STATE_STAND),   # byte0 stand state
                                              # A character logs in STANDING.  Without this the
                                              # client keeps whatever pose it had
                                              # and asks to change it every frame.
        153:  u32le(player_bytes),            # PLAYER_BYTES  (skin|face|hair|haircolor)
        154:  u32le(player_bytes2),           # PLAYER_BYTES_2 (facial hair)
        155:  u32le(gender),                  # PLAYER_BYTES_3 (byte0 gender)
        634:  u32le(0),                       # PLAYER_XP
        635:  u32le(400),                     # PLAYER_NEXT_LEVEL_XP
        1230: u32le(0xFFFFFFFF),              # PLAYER_FIELD_WATCHED_FACTION_INDEX = -1
    }
    # The pool has to be real before a cost can mean anything -- 100/100 made every
    # spell either free or unaffordable.
    fields[25 + power] = u32le(unit_state(c)["power"])   # UNIT_FIELD_POWERx
    fields[33 + power] = u32le(max_pools(c)[1])          # UNIT_FIELD_MAXPOWERx
    if ARCHIVE_GM_LEVEL > 0:
        fields[PLAYER_FLAGS] = u32le(PLAYER_FLAGS_GM)

    # Backpack slot pointers.  PLAYER_FIELD_PACK_SLOT_1 is a 16-entry array of u64
    # guids (2 dwords each); the client resolves each to an item object it has already
    # been sent, which is why the item blocks are emitted ahead of the player below.
    inv = archive_inventory(c)
    for slot, item_guid, _entry, _count in inv:
        fields[PLAYER_FIELD_PACK_SLOT_1 + slot * 2] = u32le(item_guid & 0xFFFFFFFF)
        fields[PLAYER_FIELD_PACK_SLOT_1 + slot * 2 + 1] = u32le((item_guid >> 32) & 0xFFFFFFFF)

    blk += build_values_block(fields, PLAYER_END)

    # Order matches Player::BuildCreateUpdateBlockForPlayer: contained items first,
    # then the player itself.
    items = b"".join(build_item_create_block(g, guid, e, n) for _s, g, e, n in inv)
    return struct.pack("<I", 1 + len(inv)) + items + bytes(blk)


# ---- dot-commands -----------------------------------------------------------
# This is not AzerothCore: there is no ChatHandler, no command table and no security
# levels.  ARCHIVE_GM_LEVEL just gates this handler, which implements the handful of
# commands that are actually useful for reading the archive.  Everything here talks to
# the client through ordinary update packets, so nothing is faked client-side.
COMMAND_HELP = [
    "Archive commands (this is not AzerothCore -- only these exist):",
    "  .help                      this list",
    "  .info                      character / archive state",
    "  .essence <n>               override BOTH essence budgets with n",
    "  .essence ability|talent <n>  override one budget",
    "  .essence reset             back to Ascension's own per-level curve",
    "  .essprobe [level]          diagnostic: which essence (key,flags) family matches",
    "  .level <n>                 set character level (1-80), persisted",
    "  .bars                      show the saved action-bar layout",
    "  .bars auto|clear           refill it from castable spells, or empty it",
    "  .bars set <slot> <spell>   bind one wire slot 0..11 (= keys 1..=) by hand",
    "  .power [n|max]             show or set current power; .health does health",
    "  .cost <spellId>            what that spell costs and what it does",
    "  .dummy [remove]            spawn a target dummy in front of you, or clear",
    "  .aura                      list active auras and their remaining time",
    "  .aura clear                strip every aura, on you and on the dummies",
    "  .class                     which CoA class this character is",
    "  .class <name|byte> [keep]  become that class, persisted; keep = do not",
    "                             drop known entries the new class cannot learn",
    "  .class list [group]        every CoA class and its class byte",
    "  .known                     list learned CA entries",
    "  .known add <id> [rank]     learn one entry by CharacterAdvancement.dbc ID",
    "  .known remove <id>         forget one entry",
    "  .known class <Class> [Tab]  learn a whole class (or one tab of it)",
    "  .known clear               forget everything",
    "  .build                     list stored builds",
    "  .build save <id> [name]    record the current .known set as build <id>",
    "  .build apply <id>          activate a stored build now",
    "  .build forget <id>         delete a stored build",
]


def run_command(c, cmdline, conn, eo, send_pkt):
    """Run one dot-command. Returns the lines to echo back as CHAT_MSG_SYSTEM."""
    global ESSENCE_OVERRIDE
    parts = cmdline.split()
    if not parts:
        return COMMAND_HELP
    cmd, args = parts[0].lower(), parts[1:]

    if cmd in ("help", "commands"):
        return COMMAND_HELP

    if cmd == "info":
        return [
            "Archive: %s (guid %d), level %d, map %d, gmLevel %d"
            % (c["name"], c["guid"], c["level"], c["map"], ARCHIVE_GM_LEVEL),
            "Ability Essence %d / Talent Essence %d -- %s"
            % (essence_for(c["level"], c["class"]) + (
                "manual override" if ESSENCE_OVERRIDE is not None
                else "Ascension curve (key %d, %d levels)"
                     % (ESSENCE_DBC_KEY, len(ESSENCE_CURVE)),)),
        ]

    if cmd == "essence":
        which, amount = "both", None
        if len(args) == 1:
            amount = args[0]
        elif len(args) >= 2:
            which, amount = args[0].lower(), args[1]
        usage = ["usage: .essence <n> | .essence ability|talent <n> | .essence reset"]
        ae, te = essence_for(c["level"], c["class"])
        if which == "both" and str(amount).lower() in ("reset", "curve", "default"):
            ESSENCE_OVERRIDE = None
        else:
            try:
                n = max(0, min(int(amount), 1000000))
            except (TypeError, ValueError):
                return usage
            if which.startswith("a"):
                ESSENCE_OVERRIDE = (n, te)
            elif which.startswith("t"):
                ESSENCE_OVERRIDE = (ae, n)
            elif which == "both":
                ESSENCE_OVERRIDE = (n, n)
            else:
                return usage
        # The panel reads the CA record store (GetRemainingAE/TE), so resend that;
        # the bag stacks are cosmetic but kept in step so the tooltips agree.
        send_essence_budget(conn, eo, send_pkt, c)
        for _slot, item_guid, entry, count in archive_inventory(c):
            send_pkt(conn, eo, SMSG_UPDATE_OBJECT,
                     build_values_update(item_guid,
                                         {ITEM_FIELD_STACK_COUNT: u32le(count)}, ITEM_END))
        return ["Essence now: Ability %d, Talent %d (%s). Reopen the panel to refresh."
                % (essence_for(c["level"], c["class"]) + (
                    "override" if ESSENCE_OVERRIDE is not None else "Ascension curve",))]

    if cmd == "essprobe":
        # Diagnostic, not gameplay: it writes only ids >= ESSPROBE_ID_BASE, so the
        # client's real DBC rows are left alone and the probe can be repeated.
        try:
            level = max(0, min(int(args[0]), 85)) if args else c["level"]
        except ValueError:
            return ["usage: .essprobe [level]"]
        n = 0
        for key in ESSPROBE_KEYS:
            for combo in range(16):
                send_pkt(conn, eo, SMSG_CA_ESSENCE_BUDGET,
                         smsg_ca_essence_budget(
                             ESSPROBE_ID_BASE + key * 16 + combo, level,
                             essprobe_encode(key, combo), key + 1, combo, key))
                n += 1
        log("        essprobe: %d row(s) at level %d, keys %d..%d"
            % (n, level, min(ESSPROBE_KEYS), max(ESSPROBE_KEYS)))
        return [
            "Sent %d probe rows at level %d (ids %d+)." % (n, level, ESSPROBE_ID_BASE),
            "Now run:  /run print(C_CharacterAdvancement.GetExpectedAE(%d))" % level,
            "0 = nothing matched.  Otherwise key=(v-1)/16, flagCombo=(v-1)%16.",
        ]

    if cmd == "level":
        try:
            lvl = max(1, min(int(args[0]), 80))
        except (IndexError, ValueError):
            return ["usage: .level <1-80>"]
        c["level"] = lvl
        db = load_chars()
        for chars in db.values():
            for row in chars:
                if int(row["guid"]) == int(c["guid"]):
                    row["level"] = lvl
        save_chars(db)
        send_pkt(conn, eo, SMSG_UPDATE_OBJECT,
                 build_values_update(int(c["guid"]),
                                     {UNIT_FIELD_LEVEL: u32le(lvl)}, PLAYER_END))
        # The essence budget is a function of level, so it has to follow the level.
        send_essence_budget(conn, eo, send_pkt, c)
        for _slot, item_guid, entry, count in archive_inventory(c):
            send_pkt(conn, eo, SMSG_UPDATE_OBJECT,
                     build_values_update(item_guid,
                                         {ITEM_FIELD_STACK_COUNT: u32le(count)}, ITEM_END))
        return ["Level set to %d (persisted). The CA talent half unlocks at 10." % lvl,
                "Essence now: Ability %d, Talent %d." % essence_for(lvl, c["class"])]

    if cmd == "build":
        # The server half of C_BuildCreator.ActivateBuild -- see CMSG_BUILD_ACTIVATE.
        usage = [
            "usage: .build | .build save <id> [name] | .build apply <id>",
            "       .build forget <id>",
            "<id> is the build UUID the client sends, e.g. from the world log's",
            "BUILD_ACTIVATE line.",
        ]
        db = load_builds()
        sub_ = args[0].lower() if args else "list"

        if sub_ in ("list", "show"):
            if not db:
                return ["No stored builds. Activate one in the client, copy the id",
                        "from the world log, then '.build save <id> <name>'."]
            out = ["%d stored build(s):" % len(db)]
            for bid in sorted(db):
                b = db[bid]
                out.append("  %s  %-24s %d entry/entries"
                           % (bid, b.get("name", "<unnamed>"), len(build_rows(b))))
            return out

        if len(args) < 2:
            return usage
        bid = args[1]

        if sub_ == "save":
            rows = known_for(c["guid"])
            if not rows:
                return ["Nothing to save: this character has no learned entries.",
                        "'.known class <Class> [Tab]' first."]
            db[bid] = {"name": " ".join(args[2:]) or bid,
                       "entries": [{"id": r["id"], "rank": r["rank"]} for r in rows]}
            save_builds(db)
            return ["Saved build %s (%r) with %d entry/entries."
                    % (bid, db[bid]["name"], len(rows)),
                    "The client's next ActivateBuild for that id will apply it."]

        if sub_ == "forget":
            if db.pop(bid, None) is None:
                return ["No stored build %s." % bid]
            save_builds(db)
            return ["Deleted build %s." % bid]

        if sub_ == "apply":
            b = db.get(bid)
            if b is None:
                return ["No stored build %s. '.build' lists them." % bid]
            rows = build_rows(b)
            set_known(c["guid"], rows)
            n = send_known_entries(conn, eo, send_pkt, c)
            return ["Applied build %r: %d entry/entries learned." % (b.get("name", bid), n)]

        return usage

    if cmd in ("power", "mana", "hp", "health"):
        usage = ["usage: .power [n|max] | .health [n|max]",
                 "       .power <spellId>  is NOT a thing -- use .cost <spellId>"]
        st = unit_state(c)
        maxhp, maxp = max_pools(c)
        key, cap = ("hp", maxhp) if cmd in ("hp", "health") else ("power", maxp)
        if args:
            want = args[0].lower()
            if want in ("max", "full"):
                st[key] = cap
            else:
                try:
                    st[key] = max(0, min(cap, int(want)))
                except ValueError:
                    return usage
            send_power_update(conn, eo, send_pkt, c)
        ptype = chardata.power_for(int(c["class"])) & 0xFF
        return ["Health %d/%d, power %d/%d (type %d, field %d) at level %d."
                % (st["hp"], maxhp, st["power"], maxp, ptype,
                   UNIT_FIELD_POWER1 + ptype, c["level"])]

    if cmd == "cost":
        if not args:
            return ["usage: .cost <spellId>"]
        try:
            sid = int(args[0])
        except ValueError:
            return ["usage: .cost <spellId>"]
        info = spell_info(sid)
        if not info:
            return ["Spell %d is not in Ascension's Spell.dbc." % sid]
        st = unit_state(c)
        return ["%d %r: ManaCost %d + %d%% of base -> costs %d, you have %d."
                % (sid, info["name"], info["manaCost"], info["manaCostPct"],
                   power_cost(info, c), st["power"]),
                "  powerType %d, school 0x%X, effects %s"
                % (info["powerType"], info["schoolMask"],
                   ", ".join("%d(base %d, die %d)"
                             % (e["effect"], e["basePoints"], e["dieSides"])
                             for e in info["effects"] if e["effect"]) or "none")]

    if cmd in ("aura", "auras"):
        guid = int(c["guid"])
        what = args[0].lower() if args else "list"
        if what in ("clear", "remove", "off"):
            n = 0
            for tgt in list(_AURAS.keys()):
                for slot in list(_AURAS.get(tgt, {}).keys()):
                    if remove_aura(conn, eo, send_pkt, tgt, slot, "cleared by .aura"):
                        n += 1
            return ["Removed %d aura(s)." % n]
        lines = []
        for tgt, held in sorted(_AURAS.items()):
            who = "you" if tgt == guid else ("dummy 0x%X" % tgt)
            for slot, a in sorted(held.items()):
                rem = aura_remaining_ms(a)
                lines.append(
                    "  [%2d] %-30s on %-12s %s%s"
                    % (slot, a["name"][:30], who,
                       ("%.1f/%.1fs" % (rem / 1000.0, a["maxdur_ms"] / 1000.0))
                       if a["expires"] is not None else "no timer",
                       (", %s every %.1fs"
                        % ("/".join(str(t["amount"]) for t in a["ticks"]),
                           a["ticks"][0]["period"])) if a["ticks"] else ""))
        return (["Active auras:"] + lines) if lines else ["No auras are active."]

    if cmd == "dummy":
        which = args[0].lower() if args else ""
        if which in ("remove", "clear", "off"):
            return ["Removed %d dummy/dummies." % despawn_dummies(conn, eo, send_pkt)]
        rest = args[1:] if which in ("add", "spawn") else args
        if which and which not in ("add", "spawn") and not which[0].isdigit():
            return ["usage: .dummy [displayId [distance [scale]]] | .dummy remove"]
        try:
            display = int(rest[0]) if len(rest) > 0 else None
            dist = float(rest[1]) if len(rest) > 1 else None
            scale = float(rest[2]) if len(rest) > 2 else 1.0
        except ValueError:
            return ["usage: .dummy [displayId [distance [scale]]] | .dummy remove"]
        guid, d = spawn_dummy(conn, eo, send_pkt, c, display, dist, scale)
        return ["%s at (%.1f, %.1f, %.1f), guid 0x%X, %d hp, display %d, scale %.1f."
                % (ARCHIVE_DUMMY_NAME, d["x"], d["y"], d["z"], guid, d["maxhp"],
                   d["display"], d["scale"]),
                "Press TAB to target it -- TargetUnit() is protected and does",
                "nothing from /run, but the TAB binding works.  A dummy spawned",
                "away from you (dist > 0) usually cannot be targeted at all:",
                "there is no terrain height here, so it lands off the ground."]

    if cmd == "bars":
        # The read/repair half of the 0x128 work: the client can only tell us about
        # slots it can see, so a layout that got into a bad state is otherwise only
        # fixable by hand-editing actionbars.json.
        usage = ["usage: .bars | .bars auto | .bars clear",
                 "       .bars set <wire-slot> <spellId>   (spellId 0 clears it)"]
        guid = int(c["guid"])
        which = args[0].lower() if args else ""

        if which == "set":
            # Autofill fills from slot 0 in spellbook order, which regularly parks a
            # spell past wire slot 11 -- and 11 is the last one the stock keybinds can
            # reach.  Every Lua route to a different slot is protected, so this is the
            # only way to put a specific spell under a specific key.
            if len(args) != 3:
                return ["'.bars set' needs a slot and a spell id."] + usage
            try:
                slot, sid = int(args[1]), int(args[2])
            except ValueError:
                return ["Both the slot and the spell id must be numbers."] + usage
            if not (0 <= slot < MAX_ACTION_BUTTONS):
                return ["Wire slot must be 0..%d (Lua slot N is wire N-1)."
                        % (MAX_ACTION_BUTTONS - 1)]
            if sid and sid > ACTION_BUTTON_ACTION_MAX:
                return ["Spell %d does not fit the 24-bit action field." % sid]
            info = spell_info(sid) if sid else None
            if sid and not info:
                return ["Spell.dbc has no spell %d." % sid]
            bars_set(guid, slot, (sid | (ACTION_BUTTON_SPELL << 24)) if sid else 0)
            save_bars(force=True)
            send_pkt(conn, eo, SMSG_ACTION_BUTTONS, smsg_action_buttons(c))
            if not sid:
                return ["Wire slot %d cleared (Lua slot %d)." % (slot, slot + 1)]
            return ["Wire slot %d = %s (%d). That is Lua slot %d%s."
                    % (slot, info["name"] or "?", sid, slot + 1,
                       ", key %s" % ("1234567890-="[slot],) if slot < 12 else
                       " -- no default keybind reaches it")]

        if which in ("auto", "clear"):
            layout = bars_autofill(c) if which == "auto" else {}
            load_bars()[guid] = dict(layout)
            globals()["_BARS_DIRTY"] = True
            save_bars(force=True)
            send_pkt(conn, eo, SMSG_ACTION_BUTTONS, smsg_action_buttons(c))
            return ["Bars %s -- %d slot(s) bound."
                    % ("rebuilt from castable known spells" if which == "auto"
                       else "cleared", len(layout))]
        if which:
            return ["Unknown .bars subcommand %r." % which] + usage

        layout = bars_for(guid)
        if not layout:
            return ["No saved layout. The next SMSG_ACTION_BUTTONS will seed one,",
                    "or '.bars auto' does it now."]
        lines = ["%d slot(s) bound. Wire slots are 0-based -- Lua's slot N is wire N-1:"
                 % len(layout)]
        for slot in sorted(layout):
            if len(lines) > 24:
                lines.append("  ... and %d more" % (len(layout) - 24))
                break
            packed = layout[slot]
            atype, action = packed >> 24, packed & ACTION_BUTTON_ACTION_MAX
            info = spell_info(action) if atype == ACTION_BUTTON_SPELL else None
            lines.append("  %3d  0x%08X  type=%d  %s"
                         % (slot, packed, atype,
                            (info or {}).get("name") or "action %d" % action))
        return lines

    if cmd == "class":
        usage = ["usage: .class | .class <name|byte> | .class list [classic|custom|reborn]"]
        if not CLASS_TYPES:
            return ["CharacterAdvancementClassTypes.dbc is unavailable "
                    "-- see the server log."]

        if args and args[0].lower() == "list":
            want_group = args[1].lower() if len(args) > 1 else None
            lines = ["CoA classes -- byte is what goes in UNIT_FIELD_BYTES_0:"]
            for ct in CLASS_TYPES:
                g = class_group(ct)
                if not ct["required"] or (want_group and g != want_group):
                    continue
                lines.append("  %-3d %-18s %-24s %s"
                             % (ct["required"], ct["name"], ct["display"], g))
            if len(lines) == 1:
                return ["No class types in group %r." % want_group] + usage
            return lines

        if not args:
            return class_report(c)

        # Trailing "keep" leaves the known set alone.  The default is to prune,
        # because the alternative is a character that silently cannot learn
        # anything at all -- see class_unlearnable.
        keep = args[-1].lower() == "keep"
        if keep:
            args = args[:-1]
        if not args:
            return ["usage: .class <name|byte> [keep]"]

        want = " ".join(args)
        byte, _ct = resolve_class_byte(want)
        if byte is None:
            return ["No class %r -- .class list shows every name and byte." % want]
        old = int(c["class"]) & 0xFF
        if byte == old:
            return class_report(c)

        c["class"] = byte
        db = load_chars()
        for chars in db.values():
            for row in chars:
                if int(row["guid"]) == int(c["guid"]):
                    row["class"] = byte
        save_chars(db)

        dropped = class_unlearnable(c["guid"], byte)
        if dropped and not keep:
            gone = set(r["id"] for r in dropped)
            set_known(c["guid"],
                      [r for r in known_for(c["guid"]) if r["id"] not in gone])

        # UNIT_FIELD_BYTES_0 is the entire mechanism -- see the CA class-types note.
        # The power slot rides in the same dword, so it is recomputed alongside.
        power = chardata.power_for(byte) & 0xFF
        bytes0 = (int(c["race"]) & 0xFF) | (byte << 8) \
            | ((int(c["gender"]) & 0xFF) << 16) | (power << 24)
        send_pkt(conn, eo, SMSG_UPDATE_OBJECT,
                 build_values_update(int(c["guid"]),
                                     {UNIT_FIELD_BYTES_0: u32le(bytes0)}, PLAYER_END))
        # The essence family is selected by the CA state, and the tree redraws off
        # the known-entry refresh, so both are re-sent rather than left until a
        # relog.  Bag stacks follow essence_for, which is keyed on the class too.
        send_essence_budget(conn, eo, send_pkt, c)
        for _slot, item_guid, entry, count in archive_inventory(c):
            send_pkt(conn, eo, SMSG_UPDATE_OBJECT,
                     build_values_update(item_guid,
                                         {ITEM_FIELD_STACK_COUNT: u32le(count)}, ITEM_END))
        send_known_entries(conn, eo, send_pkt, c)
        note = []
        if dropped:
            plural = "y" if len(dropped) == 1 else "ies"
            note = ["%s %d known entr%s this class cannot learn%s"
                    % (("Kept" if keep else "Dropped"), len(dropped), plural,
                       " -- LearnID will fail until they go." if keep else ".")]
        return ["Class %d -> %d." % (old, byte)] + class_report(c) + note

    if cmd == "known":
        usage = [
            "usage: .known | .known add <id> [rank] | .known remove <id>",
            "       .known class <ClassType> [TabType] | .known clear",
        ]
        rows = known_for(c["guid"])
        sub = args[0].lower() if args else "list"

        if sub in ("list", "show"):
            if not rows:
                return ["No learned CA entries. '.known class Tinker' learns one."]
            idx = ca_entry_index()
            out = ["%d learned CA entry/entries:" % len(rows)]
            for r in rows[:20]:
                e = idx.get(r["id"])
                out.append("  %d  rank %d  %s" % (
                    r["id"], r["rank"],
                    "%s (%s/%s)" % (e["Name"], e["ClassType"], e["TabType"])
                    if e else "<not in the DBC export>"))
            if len(rows) > 20:
                out.append("  ... and %d more (see knownentries.json)" % (len(rows) - 20))
            return out

        if sub == "clear":
            set_known(c["guid"], [])
            send_known_entries(conn, eo, send_pkt, c)
            return ["Forgot %d entry/entries. The client diffs the new set itself."
                    % len(rows)]

        if sub in ("add", "learn"):
            try:
                entry_id = int(args[1])
                rank = int(args[2]) if len(args) > 2 else 1
            except (IndexError, ValueError):
                return usage
            e = ca_entry_index().get(entry_id)
            rows = [r for r in rows if r["id"] != entry_id]
            rows.append({"id": entry_id, "rank": rank})
            rows.sort(key=lambda r: r["id"])
            set_known(c["guid"], rows)
            send_known_entries(conn, eo, send_pkt, c)
            return ["Learned %d (%s) at rank %d -- %d total."
                    % (entry_id,
                       "%s, %s/%s" % (e["Name"], e["ClassType"], e["TabType"])
                       if e else "not in the DBC export, sent anyway",
                       rank, len(rows))]

        if sub in ("remove", "forget"):
            try:
                entry_id = int(args[1])
            except (IndexError, ValueError):
                return usage
            kept = [r for r in rows if r["id"] != entry_id]
            if len(kept) == len(rows):
                return ["%d was not learned." % entry_id]
            set_known(c["guid"], kept)
            send_known_entries(conn, eo, send_pkt, c)
            return ["Forgot %d -- %d left." % (entry_id, len(kept))]

        if sub == "class":
            if len(args) < 2:
                return usage
            want_class = args[1].lower()
            want_tab = args[2].lower() if len(args) > 2 else None
            idx = ca_entry_index()
            if not idx:
                return ["The CA entry index is unavailable -- see the server log."]
            picked = [e for e in idx.values()
                      if (e.get("ClassType") or "").lower() == want_class
                      and (want_tab is None
                           or (e.get("TabType") or "").lower() == want_tab)]
            if not picked:
                names = sorted({e.get("ClassType") or "" for e in idx.values()})
                return ["No entries for class %r%s." % (
                            args[1], " tab %r" % args[2] if want_tab else ""),
                        "Known classes: " + ", ".join(n for n in names if n)]
            have = {r["id"]: r for r in rows}
            for e in picked:
                have[int(e["ID"])] = {"id": int(e["ID"]), "rank": 1}
            rows = sorted(have.values(), key=lambda r: r["id"])
            set_known(c["guid"], rows)
            send_known_entries(conn, eo, send_pkt, c)
            tabs = sorted({e.get("TabType") or "?" for e in picked})
            return ["Learned %d %s entry/entries (%s) -- %d total."
                    % (len(picked), picked[0].get("ClassType") or args[1],
                       ", ".join(tabs[:6]) + (" ..." if len(tabs) > 6 else ""),
                       len(rows)),
                    "Reopen the Character Advancement panel to see them."]

        return usage

    return ["Unknown command '.%s' -- try .help" % cmd]


# ---- CMSG_CHAR_CREATE parse (defensive: classless clients may add trailing bytes) ---
def parse_char_create(body):
    z = body.index(b"\x00")
    name = body[:z].decode("utf-8", "replace")
    tail = body[z + 1:]
    v = list(tail[:9]) + [0] * max(0, 9 - len(tail))       # pad if the client sent fewer
    keys = ("race", "class", "gender", "skin", "face", "hairStyle", "hairColor", "facialHair", "outfitId")
    d = dict(zip(keys, v))
    d["name"] = name
    d["extra"] = tail[9:]                                   # any Ascension-specific trailing bytes
    return d

# A freshly created character starts at 1, not at ARCHIVE_LEVEL, and that is
# load-bearing rather than flavour.  The archetype chosen during creation is
# never sent to the server -- CMSG_CHAR_CREATE stays byte-for-byte stock 3.3.5
# (verified: a 7-character name gives a 17 B body, no trailing fields).  Instead
# SharedXML/Util/NewCharacterSetupUtil.lua wraps CreateCharacter, stores
# archetypeBuildID in a client-side WTF blob keyed by GetRealmName() and the
# character name, and applies it on the character's FIRST login:
#
#     local buildID = NewCharacterSetupUtil.GetCharacterData(playerName, "archetypeBuildID")
#     if buildID ~= nil then
#         if UnitLevel("player") == 1 then          -- for not to mess up anything
#             C_BuildCreator.ActivateBuild(buildID, true, true)
#         end
#         NewCharacterSetupUtil.SetCharacterData(playerName, "archetypeBuildID", nil)
#     end
#
# -- and it clears the pending value either way.  Handing the client a level-80
# character therefore throws the archetype away on the one login that could have
# used it.  Levelling up afterwards (.level 80) is free; starting above 1 is not.
ARCHIVE_NEW_CHAR_LEVEL = 1


def make_character(db, cc):
    """Build a persistable character dict from a parsed CMSG_CHAR_CREATE."""
    race, gender, clas = cc["race"], cc["gender"], cc["class"]
    disp = chardata.display_for(race, gender)
    mp, x, y, z, o, zone = chardata.start_for(race)
    return {
        "guid": next_guid(db), "name": cc["name"].strip() or "Archivist",
        "race": race, "class": clas, "gender": gender,
        "skin": cc["skin"], "face": cc["face"], "hairStyle": cc["hairStyle"],
        "hairColor": cc["hairColor"], "facialHair": cc["facialHair"],
        "level": ARCHIVE_NEW_CHAR_LEVEL, "map": mp, "zone": zone, "x": x, "y": y, "z": z, "o": o,
        "displayId": disp,
    }


# ---- one client session -----------------------------------------------------
def handle_client(conn, cid):
    conn.settimeout(30.0)
    log("-" * 70)
    log("w%03d: connection -> SMSG_AUTH_CHALLENGE (authSeed=%s)" % (cid, AUTH_SEED.hex()))
    conn.sendall(build_challenge())

    # --- unencrypted CMSG_AUTH_SESSION ---
    hdr = recv_exact(conn, 6)
    if not hdr:
        log("w%03d: no auth-session header (client sent nothing)." % cid); return
    size = struct.unpack(">H", hdr[:2])[0]
    opcode = struct.unpack("<I", hdr[2:6])[0]
    if opcode != CMSG_AUTH_SESSION:
        log("w%03d: FIRST opcode 0x%03X != CMSG_AUTH_SESSION -- non-stock opening. hdr=%s"
            % (cid, opcode, hdr.hex())); return
    body = recv_exact(conn, size - 4)
    if body is None:
        log("w%03d: short auth-session body." % cid); return
    try:
        open(os.path.join(BASE, "world_authsession_w%03d.bin" % cid), "wb").write(hdr + body)
    except Exception:
        pass
    f = parse_auth_session(body)
    log("w%03d: CMSG_AUTH_SESSION build=%d account=%r realmID=%d clientSeed=%s addon=%dB"
        % (cid, f["build"], f["account"], f["realmID"], f["localChallenge"].hex(), f["addon_len"]))

    # --- passive RPM: 40-byte world SessionKey (BEST-EFFORT) ---
    # The world channel is PLAINTEXT for this client, so the session key is only
    # needed to (a) verify the client's digest for our own confidence and (b) arm
    # the adaptive crypt-fallback in case the client ever flips to encrypted
    # headers. Neither is required to drive a plaintext session, so if the RPM read
    # is unavailable (e.g. the server is running non-elevated) we degrade to
    # plaintext-only instead of bailing.
    enc = dec = None
    wk = read_world_key()
    if wk:
        pid, objptr, key40, key32 = wk
        log("w%03d: RPM pid=%d objptr=0x%x  world SessionKey(obj+0x140,40B)=%s"
            % (cid, pid, objptr, key40.hex()))
        if verify_digest(f, key40):
            log("w%03d: *** DIGEST OK -- SessionKey verified ***" % cid)
        else:
            log("w%03d: !! digest MISMATCH -- key40/account/seed layout differs; proceeding plaintext." % cid)
            if key32:
                log("w%03d:    (for reference K32 obj+0x120=%s)" % (cid, key32.hex()))
        enc, dec = make_crypt(key40)         # arm the crypt-fallback (unused unless client flips)
    else:
        log("w%03d: RPM read unavailable (non-elevated?). Proceeding PLAINTEXT-only; "
            "digest unverified, no crypt fallback (fine for this confirmed-plaintext client)." % cid)

    # --- PLAINTEXT world headers (this client does NOT encrypt world headers;
    #     raw capture proved it sends a plaintext CMSG_PING). ---
    send_pkt(conn, None, SMSG_AUTH_RESPONSE,
             bytes([AUTH_OK]) + struct.pack("<I", 0) + bytes([0]) +
             struct.pack("<I", 0) + bytes([EXPANSION_WOTLK]))
    log("w%03d: AUTH_OK sent PLAINTEXT (expansion=WotLK)." % cid)

    # proactive post-auth burst -- matches AC InitializeSessionCallback order.
    # The client's glue advances to character-select after this sequence.
    addon_body, naddon = build_addon_info(f["addon_raw"])
    send_pkt(conn, None, SMSG_ADDON_INFO, addon_body)
    log("w%03d: (addon-info for %d addons)" % (cid, naddon))
    send_pkt(conn, None, SMSG_CLIENTCACHE_VERSION, smsg_clientcache_version(0))
    send_pkt(conn, None, SMSG_TUTORIAL_FLAGS, smsg_tutorial_flags())
    # Ascension custom: populate the client's RealmInfo singleton so the addon-
    # loadability gate opens (RealmInfo[+0x48]!=0). Without this, Extensions.dll's
    # loader hook (0x312630) treats every LoadOnDemand custom-UI addon as
    # non-loadable (loadable=nil,reason=nil) and the whole custom UI stays dark.
    # RealmInfo is a process-global singleton, so sending once here -- before any
    # addon/UI evaluation -- holds for the entire session.
    send_pkt(conn, None, SMSG_REALM_INFO, smsg_realm_info())
    _fl = ARCHIVE_REALM_FLAVOUR
    log("w%03d: realm flavour bytes +0x40..+0x47 = %s -> Live=%d Dev=%d "
        "CanCreateCoA=%d CanCreateWCR=%d CanCreateHero=%d"
        % (cid, tuple(_fl), 1 if _fl[0] else 0, 1 if _fl[4] else 0,
           1 if (_fl[6] or _fl[4]) else 0,
           1 if (_fl[7] or _fl[4]) else 0,
           0 if (_fl[6] or _fl[7]) else 1))
    log("w%03d: sent SMSG_REALM_INFO (0x9BC) as %r -> RealmInfo+0x48=1 (addon gate "
        "OPEN), flavour=%r (IsLive=1 -> CA entries visible)."
        % (cid, ARCHIVE_REALM_NAME, ARCHIVE_REALM_FLAVOUR))
    # The realm config table.  Sent here, at the glue stage, because the gate it
    # opens is read by CharacterCreate_OnShow -- long before any character enters
    # the world.  The config manager is a process-global singleton, so one send
    # covers the glue Lua state and the in-game one both.
    send_pkt(conn, None, SMSG_UPDATE_CONFIGS, smsg_update_configs())
    log("w%03d: sent SMSG_UPDATE_CONFIGS (0x58D): %d int / %d bool / %d float / %d float2"
        % (cid, len(ARCHIVE_CONFIG_INT), len(ARCHIVE_CONFIG_BOOL),
           len(ARCHIVE_CONFIG_FLOAT), len(ARCHIVE_CONFIG_FLOAT2)))
    for _k, _v in sorted(ARCHIVE_CONFIG_BOOL.items()):
        log("w%03d:    bool %s = %s" % (cid, _k, _v))
    log("w%03d: post-auth burst sent PLAINTEXT. Serving opcodes..." % cid)

    # --- RAW CAPTURE of the client's first C->S bytes (crypt-sync forensics) ---
    # Peek the first chunk raw (ciphertext) BEFORE any framing so we can analyse the
    # keystream alignment offline. Also decrypt a COPY of the first 24 bytes with a
    # CLONE of dec so the real dec position stays knowable.
    conn.settimeout(120.0)
    first = None
    try:
        first = conn.recv(4096)
    except (socket.timeout, OSError) as e:
        log("w%03d: no C->S bytes within 120s (%r)." % (cid, e)); return
    if not first:
        log("w%03d: client closed before sending C->S data." % cid); return
    rawpath = os.path.join(BASE, "world_raw_cin_w%03d.bin" % cid)
    try:
        open(rawpath, "wb").write(first)
    except Exception:
        pass
    log("w%03d: RAW C->S first %d bytes (ciphertext): %s" % (cid, min(len(first), 32), first[:32].hex()))
    if dec is not None:
        dec_first24 = _copy.deepcopy(dec).crypt(first[:24])
        log("w%03d: dec(first 24) headers-as-decrypted:  %s" % (cid, dec_first24.hex()))
    log("w%03d:   -> saved full raw (%d B) to %s" % (cid, len(first), os.path.basename(rawpath)))
    # feed the captured bytes back into the normal framing loop
    pending = first

    # --- character store for this account -------------------------------------
    account = f["account"].decode("utf-8", "replace")
    db = load_chars()
    db.setdefault(account, [])
    log("w%03d: account=%r has %d stored character(s)." % (cid, account, len(db[account])))
    captured_ops = set()                       # first-seen unhandled C->S opcodes -> dumped once
    acked_ops = {}                             # no-op acks -> logged once, then counted
    traced_ops = {}                            # inbound trace lines emitted per opcode
    stand_state = [STAND_STATE_STAND]          # last state CONFIRMED to the client
    stand_last = [0.0]

    def find_char(guid):
        for c in db[account]:
            if int(c["guid"]) == guid:
                return c
        return None

    def dump_packet(tag, opc, cbody):
        path = os.path.join(BASE, "world_%s_w%03d_%03X.bin" % (tag, cid, opc))
        try:
            open(path, "wb").write(cbody)
            log("w%03d:    [captured %s 0x%03X -> %s]" % (cid, tag, opc, os.path.basename(path)))
        except Exception:
            pass

    # --- post-auth loop -------------------------------------------------------
    # Headers arrive PLAINTEXT on this client. We parse plaintext-first and only
    # fall back to RC4 decryption if a plaintext header is implausible AND the
    # decrypted view is plausible (i.e. the client flipped to crypt after a clean
    # AUTH_OK). `crypt_in` latches that transition; sends then mirror it.
    crypt_in = False
    # --- periodic time-sync state (server conformance) --------------------------
    # AzerothCore/TrinityCore send SMSG_TIME_SYNC_REQ every ~10s while in world; the
    # client replies CMSG_TIME_SYNC_RESP and treats a long drought as a dead session,
    # tearing down its world thread ~30s in (3 missed intervals). We only sent seq 0
    # at PLAYER_LOGIN, so the client dropped at +31s. Re-send every 10s by piggybacking
    # on the client's own 5s CMSG_PING (a proven-reliable event) -- no recv-loop timeout
    # surgery, so a genuinely silent client still closes via the normal recv path
    # instead of wedging this single-threaded server.
    in_world = False
    ts_counter = 1                         # seq 0 already sent in the login burst
    ts_last = 0.0                          # monotonic time of last time-sync send
    regen_last = 0.0                       # monotonic time of last power regen tick
    cur_char = None                        # character this session is playing (set at login)

    # The CA block -- 0x725 SMSG_CA_ACTIVE_SPEC, then 5600 x 0x722
    # SMSG_CA_ESSENCE_BUDGET, then 0x726 SMSG_CA_KNOWN_ENTRIES -- is NOT part of the
    # login burst any more.  Two reasons, and the second one is a client crash:
    #
    #   * Those handlers key their container off the LOCAL PLAYER GUID, and during
    #     the loading screen the client has no player object to key on: our
    #     SMSG_UPDATE_OBJECT is queued, not applied, until the map has loaded.  Sent
    #     with the burst it was arriving before the thing it fills into existed.
    #   * ~200 KB in 5600 packets is by far the largest thing this server does while
    #     the client is at its most fragile.  The client dispatches a frame handler
    #     out of VehiclePassenger_C.cpp that reads the active player with no NULL
    #     check (Ascension.exe 0x00749EEB: ObjectGet(guid, TYPEMASK_PLAYER) -> NULL,
    #     "referenced memory at 0x00000F60"), so every extra second on the loading
    #     bar is another chance for it to fire first and take the client down with
    #     ERROR #132.  Keeping this flood out of that window shortens it.
    #
    # CMSG_SET_ACTIVE_MOVER is the client stating that the player object now exists
    # and the loading screen is done -- precisely the precondition both handlers
    # want, and it never arrives in a session that crashes on the way in.
    ca_pending = None                      # character still owed its CA block
    ca_pending_at = 0.0                    # monotonic time it was deferred
    ca_pending_ack = None                  # build id whose ACTIVATE_RESULT is owed

    def flush_ca(why):
        """Send the deferred CA block now.  Order still matters: 0x725 builds the
        per-GUID container that 0x726 bails out without."""
        nonlocal ca_pending, ca_pending_ack
        c2, ca_pending = ca_pending, None
        if ARCHIVE_CA_MODE == "none":
            log("w%03d: === CA block SKIPPED (%s; ARCHIVE_CA_MODE=none) ==="
                % (cid, why))
            return
        send_pkt(conn, eo, SMSG_CA_ACTIVE_SPEC, smsg_ca_active_spec(0, 1))
        ess = (send_essence_budget(conn, eo, send_pkt, c2)
               if ARCHIVE_CA_MODE in ("full", "budget") else 0)
        kn = (send_known_entries(conn, eo, send_pkt, c2)
              if ARCHIVE_CA_MODE in ("full", "known") else 0)
        # ... and which of those entries came from a build.  After the known set, so
        # the client is marking a state it already has.
        active_build = str(c2.get("activeBuild") or "")
        if active_build:
            send_pkt(conn, eo, SMSG_BUILD_ACTIVE_BUILD_UPDATE,
                     smsg_build_active_build_update(ARCHIVE_ACTIVE_SPEC, active_build))
            log("w%03d:     active build re-announced for spec %d: %s"
                % (cid, ARCHIVE_ACTIVE_SPEC, active_build))
        # An activation that arrived during the loading screen was recorded but not
        # answered (see CMSG_BUILD_ACTIVATE).  Its ack goes out here, after the
        # state it acknowledges, for the same reason the live path acks last.
        if ca_pending_ack is not None:
            send_pkt(conn, eo, SMSG_BUILD_ACTIVATE_RESULT,
                     smsg_build_activate_result("ACTIVATE_BUILD_OK"))
            log("w%03d:     deferred BUILD_ACTIVATE %s acknowledged"
                % (cid, ca_pending_ack))
            ca_pending_ack = None
        log("w%03d: === CA block sent (%s, mode=%s): %d essence record(s): AE %d / "
            "TE %d at level %d, %d known CA entry/entries ==="
            % ((cid, why, ARCHIVE_CA_MODE, ess) + essence_for(c2["level"], c2["class"])
               + (c2["level"], kn)))

    last_rx = [time.monotonic()]

    def _idle():
        """Run on every recv timeout -- i.e. whenever the client has nothing to say.

        This is the server's clock.  It is deliberately NOT a thread: everything it
        touches (the aura table, the unit state, the socket) belongs to this session,
        and a thread would need a lock around all three to buy nothing.
        """
        if in_world and cur_char is not None:
            _eo = enc if crypt_in else None
            for _line in aura_tick(conn, _eo, send_pkt, cur_char):
                log("w%03d:    %s" % (cid, _line))

    def _recv(n):
        """Read exactly n bytes, running the idle clock while waiting.

        The partial read lives in `pending`, so a timeout in the MIDDLE of a frame is
        safe: the bytes already taken stay taken and the next pass continues from
        there.  Returning None still means the session is over, but it now means
        "closed, errored, or silent for ARCHIVE_SESSION_TIMEOUT" rather than "silent
        for one timeout period".
        """
        nonlocal pending
        while len(pending) < n:
            try:
                b = conn.recv(n - len(pending))
            except socket.timeout:
                _idle()
                if (time.monotonic() - last_rx[0]) > ARCHIVE_SESSION_TIMEOUT:
                    log("w%03d: no client traffic for %.0fs -- closing."
                        % (cid, ARCHIVE_SESSION_TIMEOUT))
                    return None
                continue
            except OSError:
                return None
            if not b:
                return None
            last_rx[0] = time.monotonic()
            pending += b
        out, pending = pending[:n], pending[n:]
        return out

    def plausible(hdr6):
        # C->S header = size(2 BE) + opcode(4 LE). Stock 3.3.5 CMSG opcodes stop
        # around 0x4FF, but Ascension adds CUSTOM opcodes above that (0x53B, 0x6A3,
        # ...) sent by its addon suite. Bound the opcode at 0x1000 so those frame
        # cleanly and fall through to the catch-all handler instead of being
        # misread as garbage and dropping the connection. The size window
        # (4..0x2800) plus the requirement that the opcode's high 16 bits are zero
        # still discriminates a real header from an encrypted/garbage one.
        sz = struct.unpack(">H", hdr6[:2])[0]
        op = struct.unpack("<I", hdr6[2:6])[0]
        return (4 <= sz <= 0x2800) and (0 < op < 0x1000)

    # From here on the socket is polled, not blocked on: see _recv/_idle.  The long
    # timeout above still guards the FIRST C->S bytes, where there is nothing to tick.
    conn.settimeout(ARCHIVE_AURA_TICK_MIN)

    while True:
        eh = _recv(6)
        if not eh:
            if acked_ops:
                log("w%03d:    no-op acks this session: %s" % (cid, ", ".join(
                    "%s x%d" % (OPNAME.get(o, "0x%03X" % o), n)
                    for o, n in sorted(acked_ops.items()))))
            save_bars(force=True)          # beat the debounce on the way out
            log("w%03d: client closed the connection." % cid); return
        if not crypt_in:
            if plausible(eh):
                chdr = eh                                    # plaintext header
            elif dec is not None:
                probe = _copy.deepcopy(dec).crypt(eh)        # test-decrypt without advancing dec
                if plausible(probe):
                    crypt_in = True
                    chdr = dec.crypt(eh)                      # commit: advance real dec
                    log("w%03d: >>> client switched to ENCRYPTED headers; mirroring on send." % cid)
                else:
                    log("w%03d: unframable header %s (plain-op=0x%X, dec-op=0x%X); dropping conn."
                        % (cid, eh.hex(), struct.unpack("<I", eh[2:6])[0],
                           struct.unpack("<I", probe[2:6])[0])); return
            else:
                log("w%03d: implausible plaintext header %s and no key for crypt fallback; dropping conn."
                    % (cid, eh.hex())); return
        else:
            chdr = dec.crypt(eh)
        csize = struct.unpack(">H", chdr[:2])[0]
        copc = struct.unpack("<I", chdr[2:6])[0]
        cbody = _recv(csize - 4) if csize >= 4 else b""
        if cbody is None:
            log("w%03d: short body for 0x%03X (len=%d)." % (cid, copc, csize - 4)); return
        name = OPNAME.get(copc, "0x%03X" % copc)
        traced_ops[copc] = traced_ops.get(copc, 0) + 1
        # Two opcodes arrive faster than this file can be read.  CMSG_SET_ACTION_BUTTON
        # comes in 133-packet bursts and bars_note_packet logs the burst instead.
        # CMSG_STANDSTATECHANGE arrives once per rendered FRAME -- measured at 176 fps
        # against ~190 packets a second, and it was 759,299 lines of one 835,682-line
        # log, 91% of the file.  Trace the first three and then count them; the tally
        # is printed when the session ends.
        if copc != CMSG_SET_ACTION_BUTTON and (copc != CMSG_STANDSTATECHANGE
                                               or traced_ops[copc] <= 3):
            log("w%03d: <- %-32s (%d B body)" % (cid, name, len(cbody)))
        eo = enc if crypt_in else None                       # send in whatever mode the client is in

        # Auras advance on the CLIENT'S OWN PACKET FLOW, deliberately.  This server is
        # single-threaded by design (see the time-sync note), so there is no timer to
        # hang a tick on -- but the client sends ~178 packets a second while it is in
        # world, which is a better clock than a 5 s ping and costs nothing when nothing
        # is due.  aura_tick rate-limits itself; do not add one here.
        if in_world and cur_char is not None:
            for _line in aura_tick(conn, eo, send_pkt, cur_char):
                log("w%03d:    %s" % (cid, _line))

        if copc == CMSG_CHAR_ENUM:
            send_pkt(conn, eo, SMSG_CHAR_ENUM, smsg_char_enum(db[account]))
            log("w%03d: === CHAR-SELECT: sent SMSG_CHAR_ENUM with %d character(s) ===" % (cid, len(db[account])))

        elif copc == CMSG_CHAR_CREATE:
            dump_packet("charcreate", copc, cbody)         # always keep the raw classless bytes
            try:
                cc = parse_char_create(cbody)
            except Exception as e:
                log("w%03d:    char-create parse error %r -> CHAR_CREATE_ERROR" % (cid, e))
                send_pkt(conn, eo, SMSG_CHAR_CREATE, smsg_char_create(CHAR_CREATE_ERROR)); continue
            log("w%03d:    CHAR_CREATE name=%r race=%d class=%d gender=%d (skin=%d face=%d hair=%d/%d facial=%d) extra=%dB"
                % (cid, cc["name"], cc["race"], cc["class"], cc["gender"], cc["skin"], cc["face"],
                   cc["hairStyle"], cc["hairColor"], cc["facialHair"], len(cc["extra"])))
            if any(c["name"].lower() == cc["name"].strip().lower() for c in db[account]):
                send_pkt(conn, eo, SMSG_CHAR_CREATE, smsg_char_create(CHAR_CREATE_NAME_IN_USE))
                log("w%03d:    name in use -> CHAR_CREATE_NAME_IN_USE" % cid)
            else:
                newc = make_character(db, cc)              # classless: accept ANY class byte, never validate
                db[account].append(newc); save_chars(db)
                send_pkt(conn, eo, SMSG_CHAR_CREATE, smsg_char_create(CHAR_CREATE_SUCCESS))
                log("w%03d:    *** CHARACTER CREATED guid=%d display=%d @ map=%d zone=%d ***"
                    % (cid, newc["guid"], newc["displayId"], newc["map"], newc["zone"]))

        elif copc == CMSG_CHAR_DELETE:
            guid = struct.unpack_from("<Q", cbody, 0)[0] if len(cbody) >= 8 else 0
            victim = find_char(guid)
            if victim:
                db[account].remove(victim); save_chars(db)
                send_pkt(conn, eo, SMSG_CHAR_DELETE, smsg_char_delete(CHAR_DELETE_SUCCESS))
                log("w%03d:    deleted guid=%d (%r)" % (cid, guid, victim["name"]))
            else:
                send_pkt(conn, eo, SMSG_CHAR_DELETE, smsg_char_delete(CHAR_DELETE_FAILED))

        elif copc == CMSG_PLAYER_LOGIN:
            guid = struct.unpack_from("<Q", cbody, 0)[0] if len(cbody) >= 8 else 0
            c = find_char(guid)
            if not c:
                send_pkt(conn, eo, SMSG_CHARACTER_LOGIN_FAILED, bytes([CHAR_LOGIN_FAILED]))
                log("w%03d:    PLAYER_LOGIN for unknown guid=%d -> LOGIN_FAILED" % (cid, guid)); continue
            log("w%03d: === PLAYER_LOGIN guid=%d (%r) -> entering world map=%d ===" % (cid, guid, c["name"], c["map"]))
            # world-entry burst (order follows AC SendInitialPacketsBeforeAddToMap -> AddToMap)
            # The client forgets every object it has ever been sent when it leaves the
            # world, so a dummy remembered across a relog is a guid only the server
            # believes in -- and damage aimed at it would vanish.
            _DUMMIES.clear()
            send_pkt(conn, eo, SMSG_LOGIN_VERIFY_WORLD, smsg_login_verify_world(c))
            spell_rows = castable_rows = 0
            if burst_send("acctdata"):
                acctdata_seed_bindings(account, int(c["guid"]))
                _adt = acctdata_times(account, int(c["guid"]), PER_CHARACTER_CACHE_MASK)
                send_pkt(conn, eo, SMSG_ACCOUNT_DATA_TIMES,
                         smsg_account_data_times(PER_CHARACTER_CACHE_MASK, _adt))
                log("w%03d:    -> ACCOUNT_DATA_TIMES per-character mask=0x%02X times=%r"
                    % (cid, PER_CHARACTER_CACHE_MASK, _adt))
            if burst_send("tutorial"):
                send_pkt(conn, eo, SMSG_TUTORIAL_FLAGS, smsg_tutorial_flags())
            if burst_send("spells"):
                spell_rows, castable_rows = send_spellbook(conn, eo, send_pkt, c)
            if burst_send("bind"):
                send_pkt(conn, eo, SMSG_BINDPOINTUPDATE, smsg_bindpoint_update(c))
            if burst_send("timespeed"):
                send_pkt(conn, eo, SMSG_LOGIN_SETTIMESPEED, smsg_login_settimespeed())
            if burst_send("create"):
                send_pkt(conn, eo, SMSG_UPDATE_OBJECT, build_player_create_object(c))
            if burst_send("timesync"):
                send_pkt(conn, eo, SMSG_TIME_SYNC_REQ, smsg_time_sync_req(0))
            if burst_send("motd"):
                send_pkt(conn, eo, SMSG_MOTD, smsg_motd("Local Ascension archive -- welcome, %s." % c["name"]))
            # Everything CA-shaped now waits for the client to say it is really in
            # the world -- see the ca_pending note at the top of this session.
            ca_pending, ca_pending_at = (c, time.monotonic()) if burst_send("ca") else (None, 0.0)
            log("w%03d: === WORLD-ENTRY burst sent (self-create display=%d, %d bag item(s), "
                "gm=%d, %d spell(s), %d castable, %d bar slot(s) bound; CA block "
                "deferred to SET_ACTIVE_MOVER)%s ==="
                % (cid, c["displayId"], len(archive_inventory(c)), ARCHIVE_GM_LEVEL,
                   spell_rows, castable_rows, len(bars_for(c["guid"])),
                   ("  SKIPPED: " + ",".join(sorted(BURST_SKIP))) if BURST_SKIP else ""))
            in_world = True
            cur_char = c
            ts_last = time.monotonic()     # login sent seq 0; next time-sync due in ~10s

        elif copc == CMSG_LOGOUT_REQUEST:
            # u32 reason (0 = ok) | u8 instant.  AzerothCore only sets instant
            # when the player is resting, a GM, or already dead; here there is
            # nothing to wait out, so the archive always logs out immediately.
            # SMSG_LOGOUT_COMPLETE is what actually returns the client to
            # character select -- the response alone just unlocks the button.
            send_pkt(conn, eo, SMSG_LOGOUT_RESPONSE, struct.pack("<IB", 0, 1))
            send_pkt(conn, eo, SMSG_LOGOUT_COMPLETE, b"")
            log("w%03d: === LOGOUT %r -> back to character select ==="
                % (cid, cur_char["name"] if cur_char else "?"))
            in_world = False
            cur_char = None
            ca_pending = None      # a logout mid-loading owes the next login, not this one

        elif copc == CMSG_LOGOUT_CANCEL:
            # Only reachable if we ever stop answering "instant" above.
            send_pkt(conn, eo, SMSG_LOGOUT_CANCEL_ACK, b"")
            log("w%03d:    LOGOUT_CANCEL -> ack" % cid)

        elif copc == CMSG_NAME_QUERY:
            guid = struct.unpack_from("<Q", cbody, 0)[0] if len(cbody) >= 8 else 0
            c = find_char(guid)
            if c:
                send_pkt(conn, eo, SMSG_NAME_QUERY_RESPONSE, smsg_name_query_response(c))
            else:
                log("w%03d:    NAME_QUERY for unknown guid=%d -- ignored" % (cid, guid))

        elif copc == CMSG_QUERY_TIME:
            send_pkt(conn, eo, SMSG_QUERY_TIME_RESPONSE, smsg_query_time_response())

        elif copc == CMSG_REALM_SPLIT:
            send_pkt(conn, eo, SMSG_REALM_SPLIT, smsg_realm_split(cbody[:4] if len(cbody) >= 4 else b"\x00\x00\x00\x00"))
        elif copc == CMSG_PING:
            send_pkt(conn, eo, SMSG_PONG, smsg_pong(cbody[:4] if len(cbody) >= 4 else b"\x00\x00\x00\x00"))
            # Keep the world session alive: re-send a time-sync every ~10s, piggybacked
            # on the client's own 5s ping (lands roughly every other ping). Gated on
            # in_world so it never fires at char-select, and driven only by client
            # traffic so a silent client still closes via the normal recv path.
            if in_world and (time.monotonic() - ts_last) >= 10.0:
                send_pkt(conn, eo, SMSG_TIME_SYNC_REQ, smsg_time_sync_req(ts_counter))
                log("w%03d:    -> SMSG_TIME_SYNC_REQ (seq=%d, periodic keepalive)" % (cid, ts_counter))
                ts_counter += 1
                ts_last = time.monotonic()
            # Power regen rides the same client-driven tick, for the same reason: no
            # timer thread, and it stops the moment the client goes quiet.
            if in_world and cur_char is not None \
                    and (time.monotonic() - regen_last) >= ARCHIVE_REGEN_INTERVAL:
                regen_last = time.monotonic()
                regen_tick(conn, eo, send_pkt, cur_char)
                dummy_tick(conn, eo, send_pkt)
            # Safety net.  If SET_ACTIVE_MOVER never arrives -- an addon swallowing
            # it, or some other way into the world -- the CA panel would sit empty
            # forever, which is a far worse failure than sending it late.  Ten
            # seconds is well past any healthy loading screen.
            if ca_pending is not None and (time.monotonic() - ca_pending_at) >= 10.0:
                flush_ca("fallback -- no SET_ACTIVE_MOVER after 10 s")
        elif copc == CMSG_READY_FOR_ACCOUNT_DATA_TIMES:
            acctdata_seed_bindings(account, 0)
            _adt = acctdata_times(account, 0, GLOBAL_CACHE_MASK)
            send_pkt(conn, eo, SMSG_ACCOUNT_DATA_TIMES,
                     smsg_account_data_times(GLOBAL_CACHE_MASK, _adt))
            log("w%03d:    -> ACCOUNT_DATA_TIMES global mask=0x%02X times=%r"
                % (cid, GLOBAL_CACHE_MASK, _adt))

        elif copc == CMSG_MESSAGECHAT:
            # Diagnostic readback channel: the loose FrameXML probe SAYs its world-entry
            # state here so we can read it server-side without on-screen transcription.
            try:
                mtype = struct.unpack_from("<I", cbody, 0)[0]
                lang  = struct.unpack_from("<I", cbody, 4)[0]
                rest  = cbody[8:]
                target = ""
                if mtype in (CHAT_MSG_WHISPER, 0x11):   # WHISPER / CHANNEL prefix a CString
                    nul = rest.find(b"\x00")
                    if nul >= 0:
                        target = rest[:nul].decode("utf-8", "replace")
                        rest = rest[nul + 1:]
                nul = rest.find(b"\x00")
                msg = (rest[:nul] if nul >= 0 else rest).decode("utf-8", "replace")
                log("w%03d:    >>> CHAT[type=%d lang=%d%s]: %s"
                    % (cid, mtype, lang, (" to %r" % target) if target else "", msg))
                if msg.startswith(".") and ARCHIVE_GM_LEVEL > 0 and cur_char:
                    # Echo the reply into the world log too.  It only ever went to the
                    # client's chat frame, which cannot be read back from outside the
                    # process -- so every command test meant a screenshot.  Now the log
                    # is the transcript.
                    for line in run_command(cur_char, msg[1:], conn, eo, send_pkt):
                        send_pkt(conn, eo, SMSG_MESSAGECHAT, smsg_system_message(line))
                        log("w%03d:    <<< %s" % (cid, line))
                elif lang == LANG_ADDON and mtype == CHAT_MSG_WHISPER and cur_char:
                    # Addon message whispered at a player.  There is exactly one player
                    # in this archive, so "online" means "is this character"; anyone
                    # else is offline and the core would drop the whisper.  Delivering
                    # it is what makes Ascension's own addon-to-addon signalling work.
                    if target.lower() == str(cur_char["name"]).lower():
                        send_pkt(conn, eo, SMSG_MESSAGECHAT,
                                 smsg_addon_whisper(int(cur_char["guid"]), msg))
                        log("w%03d:    ADDON whisper delivered back to %s"
                            % (cid, cur_char["name"]))
                    else:
                        log("w%03d:    ADDON whisper to %r -- not online, dropped"
                            % (cid, target))
            except Exception as e:
                log("w%03d:    CMSG_MESSAGECHAT parse error %r (body=%s)" % (cid, e, cbody[:48].hex()))

        elif copc == CMSG_ITEM_QUERY_SINGLE:
            entry = struct.unpack_from("<I", cbody, 0)[0] if len(cbody) >= 4 else 0
            known = entry in ITEM_TEMPLATES
            send_pkt(conn, eo, SMSG_ITEM_QUERY_SINGLE_RESPONSE, smsg_item_query_single_response(entry))
            log("w%03d:    ITEM_QUERY_SINGLE entry=%d -> %s" % (cid, entry, "template" if known else "unknown"))

        elif copc == CMSG_CA_KNOWN_ENTRIES_UPLOAD:
            recs = parse_cmsg_ca_known_entries(cbody)
            if not cur_char:
                log("w%03d:    CA known-entry upload (%d record(s)) before world "
                    "entry -- ignored" % (cid, len(recs)))
                continue
            idx = ca_entry_index()
            was = set(r["id"] for r in known_for(cur_char["guid"]))
            # The client is the authority on its own tree here, so this REPLACES the
            # stored set.  Duplicate ids keep the highest rank rather than the last
            # one seen, so a re-ordered packet cannot quietly downgrade a node.
            best = {}
            for entry_id, rank, unk0c, flag, unk18, unk1c in recs:
                cur = best.get(entry_id)
                if cur is None or rank > cur["rank"]:
                    best[entry_id] = {"id": entry_id, "rank": rank}
            rows = sorted(best.values(), key=lambda r: r["id"])
            now = set(best)
            set_known(cur_char["guid"], rows)
            n = send_known_entries(conn, eo, send_pkt, cur_char)

            def _name(eid):
                e = idx.get(eid) if idx else None
                return ("%s, %s/%s" % (e["Name"], e["ClassType"], e["TabType"])
                        if e else "not in the DBC export")
            for eid in sorted(now - was):
                log("w%03d:    CA_LEARN   %d rank %d -- %s"
                    % (cid, eid, best[eid]["rank"], _name(eid)))
            for eid in sorted(was - now):
                log("w%03d:    CA_UNLEARN %d -- %s" % (cid, eid, _name(eid)))
            if not (now - was) and not (was - now):
                log("w%03d:    CA known-entry upload -- no change (%d entry/entries)"
                    % (cid, n))
            log("w%03d:    CA known-entry upload: %d in, +%d/-%d -> %d known, "
                "persisted" % (cid, len(recs), len(now - was), len(was - now), n))

        elif copc == CMSG_BUILD_ACTIVATE:
            # C_BuildCreator.ActivateBuild(buildID, true, true) -- see the note up top.
            nul = cbody.find(b"\x00")
            build_id = (cbody[:nul] if nul >= 0 else cbody).decode("utf-8", "replace")
            tail = cbody[nul + 1:] if nul >= 0 else b""
            a2 = tail[0] if len(tail) > 0 else 0
            a3 = tail[1] if len(tail) > 1 else 0
            if not cur_char:
                log("w%03d:    BUILD_ACTIVATE %s before world entry -- ignored"
                    % (cid, build_id))
                continue
            build = load_builds().get(build_id)
            if ca_pending is not None:
                # The client is still on the loading screen.  This is the ordinary
                # case for a brand-new character: NewCharacterSetupUtil replays the
                # archetype's build on PLAYER_LOGIN
                # (NewCharacterSetupUtil.lua:140-150), which fires well before
                # CMSG_SET_ACTIVE_MOVER -- and that is exactly the window the CA
                # block is deferred out of.  Answering now would push 0x726, the
                # learned spells and the action bars into it, ahead of the 0x725
                # that builds the container they fill, and send_known_entries'
                # sync_spellbook would additionally mark every spell as already sent
                # so the real flush would have nothing left to deliver.
                #
                # So: record the activation, drop the spellbook watermark so the
                # flush re-diffs from scratch, and let flush_ca deliver the state
                # and the ack in the right order.  The client is not waiting on
                # anything in the meantime -- its own UI for this is not loaded yet.
                if build is None:
                    send_pkt(conn, eo, SMSG_BUILD_ACTIVATE_RESULT,
                             smsg_build_activate_result("ACTIVATE_BUILD_UNKNOWN_BUILD"))
                    log("w%03d:    BUILD_ACTIVATE %s during loading -- UNKNOWN build"
                        % (cid, build_id))
                    continue
                rows = build_rows(build)
                set_known(cur_char["guid"], rows)
                cur_char["activeBuild"] = build_id
                set_active_build(cur_char["guid"], build_id)
                _SPELLS_SENT.pop(int(cur_char["guid"]), None)
                ca_pending_ack = build_id
                log("w%03d:    BUILD_ACTIVATE %s (args %d,%d) -> stored %r: "
                    "%d entry/entries, deferred to the CA flush"
                    % (cid, build_id, a2, a3, build.get("name", build_id), len(rows)))
                continue
            if build is None:
                # Honest answer: the archive has no copy of this build.  Re-send the
                # set the character already has so the client's pending activation
                # resolves against real state instead of hanging on it.
                n = send_known_entries(conn, eo, send_pkt, cur_char)
                send_pkt(conn, eo, SMSG_BUILD_ACTIVATE_RESULT,
                         smsg_build_activate_result("ACTIVATE_BUILD_UNKNOWN_BUILD"))
                log("w%03d:    BUILD_ACTIVATE %s (args %d,%d) -- UNKNOWN build; "
                    "re-sent the current %d entry/entries unchanged. "
                    "'.build save %s' records this id."
                    % (cid, build_id, a2, a3, n, build_id))
            else:
                rows = build_rows(build)
                set_known(cur_char["guid"], rows)
                n = send_known_entries(conn, eo, send_pkt, cur_char)
                # The known set moves first, then the active-build marker, then the
                # ack LAST: the addon re-reads state inside
                # BUILD_CREATOR_ACTIVATE_RESULT -- UpdateControlButtons asks
                # IsActiveBuildID to decide whether the button says Activate or
                # Deactivate -- so the ack must not arrive before the state it is
                # acknowledging.
                send_pkt(conn, eo, SMSG_BUILD_ACTIVE_BUILD_UPDATE,
                         smsg_build_active_build_update(ARCHIVE_ACTIVE_SPEC,
                                                        build_id))
                cur_char["activeBuild"] = build_id
                set_active_build(cur_char["guid"], build_id)
                send_pkt(conn, eo, SMSG_BUILD_ACTIVATE_RESULT,
                         smsg_build_activate_result("ACTIVATE_BUILD_OK"))
                log("w%03d:    BUILD_ACTIVATE %s (args %d,%d) -> applied %r: "
                    "%d entry/entries learned, active for spec %d, "
                    "ACTIVATE_BUILD_OK"
                    % (cid, build_id, a2, a3, build.get("name", build_id), n,
                       ARCHIVE_ACTIVE_SPEC))

        elif copc == CMSG_BUILD_QUERY_CATEGORY:
            nul = cbody.find(b"\x00")
            cat = (cbody[:nul] if nul >= 0 else cbody).decode("utf-8", "replace")
            _author = str(cur_char["name"]) if cur_char else ""
            recs = build_records_for(cat, author=_author)
            send_pkt(conn, eo, SMSG_BUILD_CATEGORY_RESULT,
                     smsg_build_category_result(cat, recs))
            log("w%03d:    BUILD_QUERY_CATEGORY %r -> %d build(s) (chunk 0 of 1)"
                % (cid, cat, len(recs)))

        elif copc == CMSG_BUILD_QUERY:
            nul = cbody.find(b"\x00")
            bid = (cbody[:nul] if nul >= 0 else cbody).decode("utf-8", "replace")
            _author = str(cur_char["name"]) if cur_char else ""
            b = load_builds().get(bid)
            if b is not None and build_spell_rows(b):
                rec = smsg_build_record(bid, b, author=_author)
                send_pkt(conn, eo, SMSG_BUILD_RESULT,
                         smsg_build_result("VIEW_BUILD_OK", rec))
                log("w%03d:    BUILD_QUERY %s -> %r, %d spell(s)"
                    % (cid, bid, b.get("name", bid), len(build_spell_rows(b))))
            else:
                # The archive does not have this build.  0x100ff200 deserialises a
                # record whatever the status says, and then caches it -- read the walk
                # at 0x100ff356 carefully, because the obvious reading is wrong: the
                # empty-Spells "erase" branch at 0x100ff3e5 is only reached for an ID
                # the client ALREADY has.  An ID it does not have is push_back-ed at
                # 0x100ff3b4 whatever is in it, so answering with the id that was
                # asked for leaves a stub behind and a later GetBuild(id) returns a
                # table instead of nil.  Answer with an EMPTY id instead: nothing is
                # cached under a real build id, a second unknown query finds that same
                # empty id and erases it, and the one row it can leave in the raw
                # vector carries class 0 -- which the Hero Architect's forced
                # FILTER_CLASS_HERO drops, and that panel is the only way in.
                rec = smsg_build_record("", {"class": 0}, author=_author)
                send_pkt(conn, eo, SMSG_BUILD_RESULT,
                         smsg_build_result("VIEW_BUILD_UNKNOWN", rec))
                log("w%03d:    BUILD_QUERY %s -> UNKNOWN, empty record "
                    "(.build save records it)" % (cid, bid))

        elif copc == CMSG_REQUEST_ACCOUNT_DATA:
            atype = struct.unpack_from("<I", cbody, 0)[0] if len(cbody) >= 4 else 0xFF
            if atype >= NUM_ACCOUNT_DATA_TYPES:
                log("w%03d:    REQUEST_ACCOUNT_DATA bogus type=%d -- ignored" % (cid, atype))
                continue
            _g = int(cur_char["guid"]) if cur_char else 0
            _t, _raw = acctdata_get(account, _g, atype)
            send_pkt(conn, eo, SMSG_UPDATE_ACCOUNT_DATA,
                     smsg_update_account_data(_g, atype, _t, _raw))
            log("w%03d:    REQUEST_ACCOUNT_DATA type=%d (%s) -> %d B, time=%d"
                % (cid, atype, ACCOUNT_DATA_NAMES[atype], len(_raw), _t))

        elif copc == CMSG_UPDATE_ACCOUNT_DATA:
            # The client uploads a cache file whenever the player changes it
            # (rebinding a key, moving a frame, editing a macro).  Store it: the
            # seeded default must never overwrite the player's own edits.
            if len(cbody) < 12:
                log("w%03d:    UPDATE_ACCOUNT_DATA short (%d B) -- ignored" % (cid, len(cbody)))
                continue
            atype, tstamp, rawlen = struct.unpack_from("<III", cbody, 0)
            if atype >= NUM_ACCOUNT_DATA_TYPES:
                log("w%03d:    UPDATE_ACCOUNT_DATA bogus type=%d -- ignored" % (cid, atype))
                continue
            _g = int(cur_char["guid"]) if cur_char else 0
            text = ""
            if rawlen:
                import zlib
                try:
                    dec = zlib.decompress(cbody[12:])
                except Exception as e:
                    log("w%03d:    UPDATE_ACCOUNT_DATA type=%d inflate failed: %r" % (cid, atype, e))
                    continue
                nul = dec.find(b"\x00")                 # AC reads it as a C string
                text = (dec[:nul] if nul >= 0 else dec).decode("utf-8", "replace")
            acctdata_set(account, _g, atype, tstamp, text)
            send_pkt(conn, eo, SMSG_UPDATE_ACCOUNT_DATA_COMPLETE, struct.pack("<II", atype, 0))
            log("w%03d:    UPDATE_ACCOUNT_DATA type=%d (%s) <- %d B stored"
                % (cid, atype, ACCOUNT_DATA_NAMES[atype], len(text)))

        elif copc == CMSG_CAST_SPELL:
            cast_count, spell_id, cast_flags, targets = parse_cmsg_cast_spell(cbody)
            if not in_world or cur_char is None:
                continue
            known = set(s["spell"] for s in ca_known_spells(cur_char["guid"]))
            info = spell_info(spell_id)
            tmask, tguid = parse_spell_targets(targets)
            if spell_id in known:
                cost = power_cost(info, cur_char)
                st = unit_state(cur_char)
                if cost > st["power"]:
                    # Refuse BEFORE the SPELL_GO.  Sending the go and then declining to
                    # charge for it would leave the client showing a cast the server
                    # does not believe happened.
                    send_pkt(conn, eo, SMSG_CAST_FAILED,
                             smsg_cast_failed(cast_count, spell_id, SPELL_FAILED_NO_POWER))
                    log("w%03d:    CAST %d (%s) costs %d, have %d "
                        "-> CAST_FAILED(NO_POWER)"
                        % (cid, spell_id, (info or {}).get("name") or "?",
                           cost, st["power"]))
                    continue
                st["power"] -= cost
                send_pkt(conn, eo, SMSG_SPELL_GO,
                         smsg_spell_go(cur_char, cast_count, spell_id, targets, tguid))
                if cost:
                    send_power_update(conn, eo, send_pkt, cur_char)
                # Effects come AFTER the go: the client wants the cast to have
                # happened before it is told what it did.
                hits = apply_spell_effects(conn, eo, send_pkt, cur_char, info, tguid)
                log("w%03d:    CAST %d (%s) flags=0x%02X targets=0x%04X/%d -> SPELL_GO%s%s"
                    % (cid, spell_id, (info or {}).get("name") or "?", cast_flags,
                       tmask, tguid & 0xFFFFFFFF,
                       (", -%d power (%d left)" % (cost, st["power"])) if cost
                       else ", free",
                       ("; " + "; ".join(hits)) if hits else ""))
            else:
                # Refusing beats staying silent: an unanswered cast leaves the client
                # holding a pending spell and quietly refusing every later press.
                send_pkt(conn, eo, SMSG_CAST_FAILED,
                         smsg_cast_failed(cast_count, spell_id))
                log("w%03d:    CAST %d (%s) is not in this character's spell set "
                    "-> CAST_FAILED(NOT_KNOWN)"
                    % (cid, spell_id, (info or {}).get("name") or "unknown spell"))

        elif copc == CMSG_CREATURE_QUERY:
            # u32 entry then a FULL (unpacked) u64 guid -- QueryHandler.cpp:91 reads
            # the guid with the plain operator, not ReadAsPacked.
            entry = struct.unpack_from("<I", cbody, 0)[0] if len(cbody) >= 4 else 0
            send_pkt(conn, eo, SMSG_CREATURE_QUERY_RESPONSE,
                     smsg_creature_query_response(entry))
            log("w%03d:    CREATURE_QUERY entry=%d -> %s"
                % (cid, entry,
                   "the archive dummy" if entry == ARCHIVE_DUMMY_ENTRY
                   else "not found (top bit set)"))

        elif copc == CMSG_SET_ACTION_BUTTON:
            _line = bars_note_packet(cid, int(cur_char["guid"]) if cur_char else 0,
                                     cbody)
            if _line:
                log("w%03d:    %s" % (cid, _line))

        elif copc == CMSG_CANCEL_AURA:
            # u32 spellId -- SpellHandler.cpp:HandleCancelAuraOpcode.  This is what a
            # right-click on a buff icon sends, and answering it is what makes the icon
            # actually go away: the client does not remove it on its own.
            sid = struct.unpack_from("<I", cbody, 0)[0] if len(cbody) >= 4 else 0
            gone = []
            if cur_char is not None:
                held = _AURAS.get(int(cur_char["guid"]), {})
                for _slot, _a in list(held.items()):
                    if int(_a["spell"]) == sid:
                        _line = remove_aura(conn, eo, send_pkt,
                                            int(cur_char["guid"]), _slot,
                                            "cancelled by the player")
                        if _line:
                            gone.append(_line)
            log("w%03d:    CANCEL_AURA %d -> %s"
                % (cid, sid, "; ".join(gone) if gone else "not held, nothing to do"))

        elif copc == CMSG_CANCEL_CAST:
            # Nothing is ever mid-cast here, so there is nothing to stop and no reply
            # is due; the client has already dropped its own cast bar.
            log("w%03d:    CANCEL_CAST -- nothing in flight, ignored" % cid)

        elif copc == CMSG_STANDSTATECHANGE:
            # THE CLIENT IS NOT ON A TIMER -- it asks once per frame, and it asks
            # forever because nothing ever answered.  A stand state is only real when
            # the server confirms it with SMSG_STANDSTATE_UPDATE (u8 state); until then
            # the client's request is outstanding and it re-sends.  Reply on a change,
            # and at most once a second otherwise, so that a client that keeps asking
            # cannot turn this into an outbound flood as well.
            _st = (struct.unpack("<I", cbody[:4])[0] & 0xFF) if len(cbody) >= 4 else 0
            acked_ops[copc] = acked_ops.get(copc, 0) + 1
            _now = time.monotonic()
            if _st != stand_state[0] or (_now - stand_last[0]) >= 1.0:
                _changed = _st != stand_state[0]
                stand_state[0], stand_last[0] = _st, _now
                # BOTH packets, and the descriptor is the one that matters.  0x29D
                # alone is not enough: measured, the client plays the sit animation
                # locally but leaves UNIT_FIELD_BYTES_1 at 0, so the sit key sends
                # SIT a second time instead of STAND.  SitStandOrDescendStart reads
                # the field, not the animation.
                if cur_char is not None:
                    send_pkt(conn, eo, SMSG_UPDATE_OBJECT,
                             build_values_update(int(cur_char["guid"]),
                                                 {UNIT_FIELD_BYTES_1: u32le(_st)},
                                                 PLAYER_END))
                send_pkt(conn, eo, SMSG_STANDSTATE_UPDATE, bytes([_st]))
                if _changed or acked_ops[copc] <= 3:
                    log("w%03d:    STANDSTATECHANGE -> %d, confirmed with "
                        "SMSG_STANDSTATE_UPDATE" % (cid, _st))

        elif copc in (CMSG_SET_ACTIVE_MOVER, CMSG_TIME_SYNC_RESP):
            if copc == CMSG_SET_ACTIVE_MOVER and ca_pending is not None:
                flush_ca("SET_ACTIVE_MOVER -- client has its player object")
            # These need no reply: SET_ACTIVE_MOVER is the client claiming its own
            # player object, and time-sync answers our own 10 s keepalive.  (Stand
            # state used to be filed here too, on the assumption that the client was
            # re-asserting it on a timer.  It was not -- see CMSG_STANDSTATECHANGE
            # above; it was asking for an answer it never got.)  Logging each one
            # buried everything else in the file, so say it once per opcode per
            # session and keep the tally after that; it is dumped at session end.
            acked_ops[copc] = acked_ops.get(copc, 0) + 1
            if acked_ops[copc] == 1:
                log("w%03d:    (%s -- acknowledged, no reply needed; "
                    "further ones are counted, not logged)" % (cid, name))

        else:
            if copc not in captured_ops:                   # capture unknown C->S once for later study
                captured_ops.add(copc)
                dump_packet("unhandled", copc, cbody)
            log("w%03d:    (no handler for %s -- logged, ignored)" % (cid, name))


def report_paths():
    """Every file this server reads, where it resolved to, and whether it is there.

    Printed once at startup because the failure mode for a wrong layout is quiet:
    a missing seed file is one "unreadable ... not seeding" line, a missing
    reference DBC is an empty table, and the session then LOOKS healthy right up
    to the keybinds being blank or the CoA panel having nothing to draw."""
    rows = [("seed/state dir",          DATA_DIR),
            ("characters",              CHARS_PATH),
            ("account data",            ACCTDATA_PATH),
            ("default bindings",        DEFAULT_BINDINGS_PATH),
            ("known entries",           KNOWN_PATH),
            ("builds",                  BUILDS_PATH),
            ("action bars",             ACTIONBARS_PATH),
            ("CA entries.csv",          CA_ENTRIES_CSV),
            ("CA class-types DBC",      CA_CLASSTYPES_DBC),
            ("CA essence DBC",          ESSENCE_DBC),
            ("Ascension Spell.dbc",     SPELL_DBC),
            ("Ascension ChrClasses.dbc", CHRCLASSES_DBC)]
    missing = 0
    for label, p in rows:
        ok = os.path.exists(p)
        missing += not ok
        log("  %-26s %s  %s" % (label, "ok     " if ok else "MISSING", p))
    if missing:
        log("  %d path(s) MISSING -- see the layout note at the top of this file; "
            "ASC_DATA_DIR / ASC_CA_REF / ASC_DBC_DIR override the defaults." % missing)


def main():
    rotate_log()                            # before the first log() call of this run
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((HOST, PORT))
    except OSError as e:
        log("BIND FAILED on %d: %r (free the port / stop the probe first)" % (PORT, e)); return
    srv.listen(8)
    log("=" * 70)
    log("MINIMAL WORLD SERVER on %s:%d   log-> %s" % (HOST, PORT, LOG))
    log("Shim on 3799 must also be running. Log in, pick a realm, click 'Select Realm'.")
    report_paths()
    cid = 0
    while True:
        conn, addr = srv.accept()
        cid += 1
        try:
            handle_client(conn, cid)
        except Exception as e:
            log("w%03d: handler error %r" % (cid, e))
        finally:
            try:
                conn.close()
            except OSError:
                pass


if __name__ == "__main__":
    main()
