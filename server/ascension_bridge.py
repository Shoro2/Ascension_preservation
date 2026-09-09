#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ascension_bridge.py -- put the Ascension client into the REAL AzerothCore world.

Why this exists
===============
`world_server.py` is a hand-written Python world server.  It was the right tool for
reverse-engineering the client's protocol, and it now does spells, auras, action
bars, the whole Character Advancement stack and character creation.  What it does
not have, and never will without reimplementing a game server, is a *world*: the
155 000 creature spawns, 6 100 gossip menus, 41 600 vendor rows, 17 900 trainer
rows and 18 600 quests that make NPCs behave "just like the main game".

All of that already exists on this machine.  `server-ascension\\worldserver.exe` is
stock AzerothCore running against Ascension's own DBCs and the `asc_*` databases,
and it boots clean.  It was never played only because the Ascension client cannot
log into it: the client speaks a custom auth protocol and, on the world channel,
sends **plaintext headers** and a handful of opcodes AzerothCore has never heard of.

This bridge is the translation layer.

    Ascension client  <--plaintext, custom opcodes-->  BRIDGE  <--RC4, stock-->  AzerothCore

Client side
-----------
* Plaintext headers in both directions; see TROUBLESHOOTING and world_server.py.
* The listen port is NOT free to choose.  Extensions.dll checks the endpoint the
  client connected to against a hard-coded allow-list, and a miss arms a buggy
  kill-switch that crashes the client a few seconds after the world draws.  The
  only loopback entries are 8085, 8087 and 8088.  See archive_ports.py.

AzerothCore side
----------------
* We authenticate as an ordinary client: read `SMSG_AUTH_CHALLENGE`, answer
  `CMSG_AUTH_SESSION` with a digest over a session key **we choose** and write into
  `asc_auth.account.session_key` first.  The client's own key is never needed --
  the two halves of the connection are separately authenticated.
* Three fields have to be rewritten or AzerothCore drops the socket: the build
  (client sends 12344, core accepts 12340), the realm id (client sends 11, this
  core is realm 1) and the digest (recomputed for the core's own seed).
* After `AUTH_OK` the core encrypts every header with ARC4-drop1024 keyed by
  HMAC-SHA1 over the session key.  We hold both stream states and re-frame every
  packet: strip the core's crypt going out to the client, add it going in.

Opcode policy
-------------
Stock 3.3.5a opcodes stop at `NUM_MSG_TYPES = 0x521`.  Every Ascension addition --
0x58D configs, 0x5C2 build activate, 0x62E/0x630 build queries, 0x722/0x725/0x726
Character Advancement, 0x727 known-entry upload, 0x9BC realm info -- is above that.
So the rule is simply: **an opcode >= 0x521 never crosses the bridge.**  Client-side
customs are answered here or dropped; the core never sees a packet it cannot parse.

    python ascension_bridge.py            # listen 8088, upstream 127.0.0.1:8086

Read-only with respect to the client.  Touches `asc_auth.account` only.
"""
import hashlib
import hmac
import os
import socket
import struct
import sys
import threading
import time

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)

# world_server.py is the canonical source for the crypt, the realm-flavour bytes
# and every Ascension-custom packet builder; importing keeps the two from drifting.
# It has no module-level side effects -- everything lives behind __main__.
from world_server import (RC4, SERVER_ENC_SEED, SERVER_DEC_SEED, smsg_realm_info,
                          REALM_FLAVOUR_WCR, SMSG_TUTORIAL_FLAGS)

# ---- configuration ----------------------------------------------------------
LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = int(os.environ.get("ASC_BRIDGE_PORT", "8088"))   # 8085/8087/8088 ONLY
AC_HOST = os.environ.get("ASC_AC_HOST", "127.0.0.1")
AC_PORT = int(os.environ.get("ASC_AC_PORT", "8086"))
AC_REALM_ID = int(os.environ.get("ASC_AC_REALM_ID", "1"))
AC_BUILD = int(os.environ.get("ASC_AC_BUILD", "12340"))

LOG_PATH = os.path.join(BASE, "bridge_log.txt")
LOG_MAX_BYTES = 32 * 1024 * 1024

CLIENT_AUTH_SEED = bytes.fromhex("11223344")   # what WE challenge the client with
CHALLENGE_TAIL = bytes(32)

# The realm-flavour bytes decide which character-creation UI the client puts up,
# and only one of them produces characters AzerothCore can actually build.
#
#   DEV / LIVE  -> CanCreateHero()  -> class is forced to HERO_CLASS_ID (10),
#                  the classless "Free-Pick" hero.  Class 10 has no
#                  `playercreateinfo` row, so the core answers CHAR_CREATE_FAILED.
#   COA         -> CanCreateCoA()   -> the custom classes, ids 12..32.  Worse.
#   WCR         -> CanCreateWCR()   -> CharacterCreate_ShowRegularClasses(), the
#                  11 stock WotLK classes (CharacterCreate.lua:1676).
#
# So the bridge advertises WCR, and deliberately does NOT send SMSG_UPDATE_CONFIGS:
# CanCreateArchetype() (CharacterCreate.lua:12) is realm-name AND config, and with
# the config absent the archetype steps stay out of the flow.
BRIDGE_REALM_FLAVOUR = REALM_FLAVOUR_WCR

SMSG_AUTH_CHALLENGE = 0x1EC
CMSG_AUTH_SESSION = 0x1ED
SMSG_AUTH_RESPONSE = 0x1EE
CMSG_CHAR_CREATE = 0x036
SMSG_REALM_INFO = 0x9BC

SMSG_MESSAGECHAT = 0x096
SMSG_LOGIN_VERIFY_WORLD = 0x236

# ARCHIVE IDENTIFICATION.  The client's realmList CVar is restored to the live
# address by native code before the player is in world (measured 2026-09-02:
# GetCVar("realmList") -> 51.210.230.10 on a session established to
# 127.0.0.1:8088), so GlobalOverwrites.lua's ASC_IsArchive() cannot tell where
# it is running once the world is loaded.  Since that file is shared with the
# LIVE install through the client-ascension junction, guessing is not an option
# -- so the archive announces itself and live simply never does.  One system
# chat line, a few seconds after SMSG_LOGIN_VERIFY_WORLD.
ARCHIVE_TOKEN = "ASCARCHIVE-LOCAL-REALM"
ARCHIVE_HELLO = ("Ascension archive realm (%s).  /asctal opens the talent tree."
                 % ARCHIVE_TOKEN)
ARCHIVE_HELLO_DELAY = float(os.environ.get("ASC_HELLO_DELAY", "6"))

# BISECTING A CLIENT CRASH.  Set ASC_DROP_OPCODES to a space/comma separated
# list of server->client opcodes ("0x4C0 0x12A") and the bridge will log them
# and then NOT forward them.  This exists because the client started dying at
# 0x6E7A5BCE inside Extensions.dll on the very millisecond of CMSG_PLAYER_LOGIN,
# with an identical stack every time, once the character had seven talents
# instead of three -- and the only way to find out which login packet does it is
# to take them away one at a time.
SMSG_SET_FLAT_SPELL_MODIFIER = 0x266
SMSG_SET_PCT_SPELL_MODIFIER = 0x267

DROP_OPCODES = frozenset(
    int(x, 0) for x in
    os.environ.get("ASC_DROP_OPCODES", "").replace(",", " ").split())

# The login spell-mod resend (0x266/0x267) is the PROVEN carrier of the
# 0x6E7A5BCE crash: with talents held at {11069, 11070}, forwarding it crashed
# 3/3 and dropping it logged in 2/2, while dropping an unrelated opcode still
# crashed.  ASC_SPELLMOD_MODE reshapes the stream so the exact trigger can be
# isolated without touching the talent set:
#   firstop  only the first effect index per (opcode, op) is forwarded
#   eff0     every packet rewritten to effect index 0
#   uniq     exact duplicate (op, eff, val) triples suppressed
#   one      only the very first spell-mod packet of the login
SPELLMOD_MODE = os.environ.get("ASC_SPELLMOD_MODE", "").strip().lower()
SPELLMOD_BODY_BYTES = 16


CHAT_MSG_SYSTEM = 0x00
LANG_UNIVERSAL = 0


def smsg_system_chat(text):
    """SMSG_MESSAGECHAT the way the 3.3.5 client parses a default-path message:
    uint8 type, uint32 language, uint64 sender, uint32 flags, uint64 receiver,
    uint32 len (NUL included), the text, uint8 chatTag.  Checked against a real
    packet rather than assumed: a 7-character SAY logged 38 bytes, and
    1+4+8+4+8+4+8+1 is exactly 38."""
    msg = text.encode("utf-8") + b"\x00"
    return (struct.pack("<BIQIQI", CHAT_MSG_SYSTEM, LANG_UNIVERSAL, 0, 0, 0, len(msg))
            + msg + b"\x00")


FIRST_CUSTOM_OPCODE = 0x521          # NUM_MSG_TYPES; at or above this is Ascension's

# AzerothCore's playable classes in 3.3.5a.  Ascension's classless realms send a
# Character-Advancement class byte (10 = Tinker, up to 32) that has no
# `playercreateinfo` row, so the core would refuse the creation outright.
AC_VALID_CLASSES = {1, 2, 3, 4, 5, 6, 7, 8, 9, 11}
AC_FALLBACK_CLASS = int(os.environ.get("ASC_FALLBACK_CLASS", "1"))   # Warrior

# Set ASC_BRIDGE_TRACE=1 to log every opcode in both directions.  Off, only the
# packets below are named -- enough to tell "the client never asked" apart from
# "the core never answered", which is the question that actually comes up.
TRACE = os.environ.get("ASC_BRIDGE_TRACE", "") not in ("", "0")

CMSG_PING = 0x1DC
CMSG_MESSAGECHAT = 0x095

# Opcode names are DIRECTION-SPECIFIC: 0x12A is SMSG_INITIAL_SPELLS going out
# and nothing at all coming in, and an earlier single flat table mislabelled it
# (and 0x12B, 0x17B, 0x17F, 0x12E ...) which made the world log actively
# misleading.  Two tables now, both transcribed from the core's own header,
# src/server/game/Server/Protocol/Opcodes.h -- if you add one, copy the value
# from there, do not guess it.
CNAMES = {                                  # client -> core
    0x036: "CMSG_CHAR_CREATE",       0x037: "CMSG_CHAR_ENUM",
    0x038: "CMSG_CHAR_DELETE",       0x03D: "CMSG_PLAYER_LOGIN",
    0x05C: "CMSG_QUEST_QUERY",       0x095: "CMSG_MESSAGECHAT",
    0x108: "CMSG_AUTOSTORE_LOOT_ITEM",
    0x12E: "CMSG_CAST_SPELL",        0x141: "CMSG_ATTACKSWING",
    0x142: "CMSG_ATTACKSTOP",        0x15D: "CMSG_LOOT",
    0x15E: "CMSG_LOOT_MONEY",        0x15F: "CMSG_LOOT_RELEASE",
    0x17B: "CMSG_GOSSIP_HELLO",      0x17C: "CMSG_GOSSIP_SELECT_OPTION",
    0x182: "CMSG_QUESTGIVER_STATUS_QUERY",
    0x184: "CMSG_QUESTGIVER_HELLO",  0x186: "CMSG_QUESTGIVER_QUERY_QUEST",
    0x189: "CMSG_QUESTGIVER_ACCEPT_QUEST",
    0x18A: "CMSG_QUESTGIVER_COMPLETE_QUEST",
    0x18C: "CMSG_QUESTGIVER_REQUEST_REWARD",
    0x18E: "CMSG_QUESTGIVER_CHOOSE_REWARD",
    0x19E: "CMSG_LIST_INVENTORY",    0x1B0: "CMSG_TRAINER_LIST",
    0x213: "CMSG_UNLEARN_TALENTS",   0x251: "CMSG_LEARN_TALENT",
    0x2E7: "CMSG_WARDEN_DATA",
}
SNAMES = {                                  # core -> client
    0x03A: "SMSG_CHAR_CREATE",       0x03B: "SMSG_CHAR_ENUM",
    0x03C: "SMSG_CHAR_DELETE",       0x03E: "SMSG_NEW_WORLD",
    0x03F: "SMSG_TRANSFER_PENDING",  0x041: "SMSG_CHARACTER_LOGIN_FAILED",
    0x05D: "SMSG_QUEST_QUERY_RESPONSE",
    0x096: "SMSG_MESSAGECHAT",       0x0A9: "SMSG_UPDATE_OBJECT",
    0x0FD: "SMSG_TUTORIAL_FLAGS",    0x127: "SMSG_SET_PROFICIENCY",
    0x129: "SMSG_ACTION_BUTTONS",    0x12A: "SMSG_INITIAL_SPELLS",
    0x12B: "SMSG_LEARNED_SPELL",     0x12C: "SMSG_SUPERCEDED_SPELL",
    0x130: "SMSG_CAST_FAILED",       0x131: "SMSG_SPELL_START",
    0x132: "SMSG_SPELL_GO",          0x143: "SMSG_ATTACKSTART",
    0x144: "SMSG_ATTACKSTOP",        0x145: "SMSG_ATTACKSWING_NOTINRANGE",
    0x146: "SMSG_ATTACKSWING_BADFACING",
    0x148: "SMSG_ATTACKSWING_DEADTARGET",
    0x149: "SMSG_ATTACKSWING_CANT_ATTACK",
    0x160: "SMSG_LOOT_RESPONSE",     0x161: "SMSG_LOOT_RELEASE_RESPONSE",
    0x17D: "SMSG_GOSSIP_MESSAGE",    0x17E: "SMSG_GOSSIP_COMPLETE",
    0x183: "SMSG_QUESTGIVER_STATUS", 0x185: "SMSG_QUESTGIVER_QUEST_LIST",
    0x188: "SMSG_QUESTGIVER_QUEST_DETAILS",
    0x18B: "SMSG_QUESTGIVER_REQUEST_ITEMS",
    0x18D: "SMSG_QUESTGIVER_OFFER_REWARD",
    0x18F: "SMSG_QUESTGIVER_QUEST_INVALID",
    0x191: "SMSG_QUESTGIVER_QUEST_COMPLETE",
    0x192: "SMSG_QUESTGIVER_QUEST_FAILED",
    0x19F: "SMSG_LIST_INVENTORY",    0x1B1: "SMSG_TRAINER_LIST",
    0x1D0: "SMSG_LOG_XPGAIN",        0x1D4: "SMSG_LEVELUP_INFO",
    0x1EE: "SMSG_AUTH_RESPONSE",     0x1F6: "SMSG_COMPRESSED_UPDATE_OBJECT",
    0x224: "SMSG_GOSSIP_POI",        0x236: "SMSG_LOGIN_VERIFY_WORLD",
    0x24C: "SMSG_SPELLLOGEXECUTE",   0x24E: "SMSG_PERIODICAURALOG",
    0x250: "SMSG_SPELLNONMELEEDAMAGELOG",
    0x2E6: "SMSG_WARDEN_DATA",       0x418: "SMSG_QUESTGIVER_STATUS_MULTIPLE",
    0x4C0: "SMSG_TALENTS_INFO",      0x9BC: "SMSG_REALM_INFO",
}


# Named, but far too frequent in the world to log every time -- object updates
# and the movement/status chatter arrive by the hundred per second.  TRACE
# still shows them.
NOISY = {0x0A9, 0x1F6, 0x182, 0x183, 0x418, 0x24C, 0x24E, 0x250}


def opname(op, c2s):
    t = CNAMES if c2s else SNAMES
    return t.get(op, "0x%03X" % op)


# NOTE: these are the ASCENSION client's chat-type numbers, not AzerothCore's --
# a plain SendChatMessage("x") arrives as type 1, not 0.  The number is printed
# alongside the name so a wrong guess here is visible instead of misleading.
CHAT_TYPES = {1: "SAY", 2: "PARTY", 3: "RAID", 4: "GUILD", 6: "OFFICER",
              7: "YELL", 8: "WHISPER", 0x0F: "EMOTE", 0x12: "CHANNEL"}


def describe_chat(body):
    """CMSG_MESSAGECHAT: uint32 type, uint32 language, then one or two cstrings
    depending on the type.  Logged in full because it is the ONLY cheap textual
    read-back channel out of the running client -- Logs/WoWChatLog.txt does not
    flush while the client is up and dprint() does not reach Logs/LUA.txt in the
    world, so an in-game probe reports by saying its answer:
        /run SendChatMessage("ASCPROBE hp="..UnitHealth("player"))
    and the answer lands in this file a fraction of a second later."""
    if len(body) < 8:
        return "short (%d B)" % len(body)
    typ, lang = struct.unpack("<II", body[:8])
    parts = [p.decode("utf-8", "replace") for p in body[8:].split(b"\x00") if p]
    return "%s(%d): %s" % (CHAT_TYPES.get(typ, "type"), typ, " | ".join(parts))


CMSG_LEARN_TALENT = 0x251
SMSG_CAST_FAILED = 0x130
SMSG_TRAINER_LIST = 0x1B1
# Ascension is a classless realm and its client THROWS AWAY every service in a
# CLASS trainer list.  Measured, not guessed: the core sends 6 services, all
# state=0 (green) -- see describe_trainer_list below -- the window opens, the
# greeting out of that same packet is displayed by GetTrainerGreetingText(),
# and GetNumTrainerServices() still answers 0 with available/unavailable/used
# all filtered in.  Change nothing but the uint32 trainer type from 0 (CLASS)
# to 2 (TRADESKILL) and the identical list renders: 7 rows, every spell green,
# and Train sends CMSG_TRAINER_BUY_SPELL as usual.  The header reads "Recipes"
# instead of the class name, which is the whole price.
#
# Only type 0 is touched -- profession trainers are already 2, and mount (1)
# and pet (3) trainers render fine as themselves.
# ASC_TRAINER_TYPE overrides the replacement value; ASC_TRAINER_TYPE=0 turns
# the rewrite off and shows the core's real behaviour again.
TRAINER_TYPE_OVERRIDE = int(os.environ.get("ASC_TRAINER_TYPE", "2"))


def describe_trainer_list(body):
    """SMSG_TRAINER_LIST: uint64 guid, uint32 type, uint32 count,
    then count * 38-byte records, then the greeting as a cstring."""
    if len(body) < 16:
        return "short (%d B)" % len(body)
    guid, ttype, count = struct.unpack_from("<QII", body, 0)
    out = ["guid=0x%X type=%d count=%d" % (guid, ttype, count)]
    off = 16
    for i in range(min(count, 12)):
        if off + 38 > len(body):
            out.append("  #%d TRUNCATED" % i)
            break
        spell, state, cost = struct.unpack_from("<IBI", body, off)
        req_level = body[off + 17]
        out.append("  #%d spell=%d state=%d cost=%d reqLevel=%d"
                   % (i, spell, state, cost, req_level))
        off += 38
    tail = body[off:].split(b"\x00")[0]
    out.append("  greeting=%r" % tail.decode("utf-8", "replace"))
    return "\n".join(out)



def describe_learn_talent(body):
    """CMSG_LEARN_TALENT: uint32 talentId, uint32 requestedRank.  The id comes
    out of the CLIENT's Talent.dbc; the core looks it up in its own.  When the
    two DBC sets disagree the learn is refused with no error text anywhere, so
    the id is the only way to tell 'the client asked for the wrong talent' apart
    from 'the core would not grant it'."""
    if len(body) < 8:
        return "short (%d B)" % len(body)
    tid, rank = struct.unpack("<II", body[:8])
    return "talentId=%d rank=%d" % (tid, rank)


def describe_cast_failed(body):
    """SMSG_CAST_FAILED: uint8 castCount, uint32 spellId, uint8 result."""
    if len(body) < 6:
        return "short (%d B)" % len(body)
    cnt = body[0]
    spell = struct.unpack("<I", body[1:5])[0]
    res = body[5]
    return "spell=%d result=0x%02X count=%d" % (spell, res, cnt)


def worth_logging(op, c2s):
    t = CNAMES if c2s else SNAMES
    return TRACE or (op in t and op not in NOISY)


# ResponseCodes, src/server/shared/SharedDefines.h:3622.  SMSG_CHAR_CREATE and
# SMSG_CHARACTER_LOGIN_FAILED are a single byte out of this enum, and that byte
# is the difference between "the client never asked" and "the core said no, for
# this reason" -- so it always gets spelled out, never logged as a length.
RESPONSE_CODES = {
    0x2E: "CHAR_CREATE_IN_PROGRESS",   0x2F: "CHAR_CREATE_SUCCESS",
    0x30: "CHAR_CREATE_ERROR",         0x31: "CHAR_CREATE_FAILED",
    0x32: "CHAR_CREATE_NAME_IN_USE",   0x33: "CHAR_CREATE_DISABLED",
    0x34: "CHAR_CREATE_PVP_TEAMS_VIOLATION",
    0x35: "CHAR_CREATE_SERVER_LIMIT",  0x36: "CHAR_CREATE_ACCOUNT_LIMIT",
    0x37: "CHAR_CREATE_SERVER_QUEUE",  0x38: "CHAR_CREATE_ONLY_EXISTING",
    0x39: "CHAR_CREATE_EXPANSION",     0x3A: "CHAR_CREATE_EXPANSION_CLASS",
    0x3B: "CHAR_CREATE_LEVEL_REQUIREMENT",
    0x3C: "CHAR_CREATE_UNIQUE_CLASS_LIMIT",
    0x3D: "CHAR_CREATE_CHARACTER_IN_GUILD",
    0x3E: "CHAR_CREATE_RESTRICTED_RACECLASS",
    0x3F: "CHAR_CREATE_CHARACTER_CHOOSE_RACE",
    0x4C: "CHAR_LOGIN_IN_PROGRESS",    0x4D: "CHAR_LOGIN_SUCCESS",
    0x4E: "CHAR_LOGIN_NO_WORLD",       0x4F: "CHAR_LOGIN_DUPLICATE_CHARACTER",
    0x50: "CHAR_LOGIN_NO_INSTANCES",   0x51: "CHAR_LOGIN_FAILED",
    0x52: "CHAR_LOGIN_DISABLED",       0x53: "CHAR_LOGIN_NO_CHARACTER",
}
SMSG_CHAR_CREATE = 0x03A
SMSG_CHARACTER_LOGIN_FAILED = 0x041


def describe_char_create(body):
    """CMSG_CHAR_CREATE: cstring name, then race, class, gender, skin, face,
    hairStyle, hairColour, facialHair, outfitId -- one byte each."""
    try:
        z = body.index(b"\x00")
    except ValueError:
        return "unparsable (%d B)" % len(body)
    t = body[z + 1:]
    if len(t) < 9:
        return "name=%r short tail (%d B)" % (body[:z], len(t))
    return ("name=%s race=%d class=%d gender=%d skin=%d face=%d hair=%d/%d "
            "facial=%d outfit=%d"
            % ((body[:z].decode("ascii", "replace"),) + tuple(t[:9])))

_log_lock = threading.Lock()


def log(msg):
    line = "[%s] %s" % (time.strftime("%H:%M:%S"), msg)
    with _log_lock:
        print(line, flush=True)
        try:
            with open(LOG_PATH, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception:
            pass


def rotate_log():
    try:
        if os.path.exists(LOG_PATH) and os.path.getsize(LOG_PATH) > LOG_MAX_BYTES:
            os.replace(LOG_PATH, LOG_PATH + ".1")
    except Exception:
        pass


# ---- ARC4-drop1024, as AuthCrypt uses it ------------------------------------
def make_crypt(session_key40):
    """Return (s2c, c2s) stream states for talking to the core AS A CLIENT.

    The seed names are from the CORE's point of view -- it ENCRYPTS what it
    sends and DECRYPTS what it receives -- so our roles are the mirror image:
    s2c decrypts headers the core sent us, c2s encrypts headers we send it."""
    s2c = RC4(hmac.new(SERVER_ENC_SEED, session_key40, hashlib.sha1).digest())
    c2s = RC4(hmac.new(SERVER_DEC_SEED, session_key40, hashlib.sha1).digest())
    s2c.crypt(bytes(1024))
    c2s.crypt(bytes(1024))
    return s2c, c2s


# ---- socket helpers ---------------------------------------------------------
def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except (socket.timeout, OSError):
            return None
        if not chunk:
            return None
        buf += chunk
    return buf


def frame_s2c(opcode, body, enc=None):
    """Server->client: uint16 BE size (opcode+body) + uint16 LE opcode."""
    size = len(body) + 2
    if size > 0x7FFF:
        hdr = bytes([0x80 | ((size >> 16) & 0xFF), (size >> 8) & 0xFF, size & 0xFF,
                     opcode & 0xFF, (opcode >> 8) & 0xFF])
    else:
        hdr = bytes([(size >> 8) & 0xFF, size & 0xFF, opcode & 0xFF, (opcode >> 8) & 0xFF])
    if enc is not None:
        hdr = enc.crypt(hdr)
    return hdr + body


def frame_c2s(opcode, body, enc=None):
    """Client->server: uint16 BE size (opcode+body) + uint32 LE opcode."""
    size = len(body) + 4
    hdr = struct.pack(">H", size) + struct.pack("<I", opcode)
    if enc is not None:
        hdr = enc.crypt(hdr)
    return hdr + body


def read_c2s(sock, dec=None):
    """Read one client->server packet. Returns (opcode, body) or None."""
    hdr = recv_exact(sock, 6)
    if hdr is None:
        return None
    if dec is not None:
        hdr = dec.crypt(hdr)
    size = struct.unpack(">H", hdr[:2])[0]
    opcode = struct.unpack("<I", hdr[2:6])[0]
    blen = size - 4
    if blen < 0 or blen > 0x10000:
        raise ValueError("implausible C->S header: size=%d opcode=0x%X" % (size, opcode))
    body = recv_exact(sock, blen) if blen else b""
    if body is None:
        return None
    return opcode, body


def read_s2c(sock, dec=None):
    """Read one server->client packet. The size field is 2 or 3 bytes; the flag
    lives in the top bit of the FIRST byte, so it has to be decrypted alone before
    we know how many more bytes belong to this header."""
    b0 = recv_exact(sock, 1)
    if b0 is None:
        return None
    if dec is not None:
        b0 = dec.crypt(b0)
    if b0[0] & 0x80:
        rest = recv_exact(sock, 4)
        if rest is None:
            return None
        if dec is not None:
            rest = dec.crypt(rest)
        size = ((b0[0] & 0x7F) << 16) | (rest[0] << 8) | rest[1]
        opcode = rest[2] | (rest[3] << 8)
    else:
        rest = recv_exact(sock, 3)
        if rest is None:
            return None
        if dec is not None:
            rest = dec.crypt(rest)
        size = (b0[0] << 8) | rest[0]
        opcode = rest[1] | (rest[2] << 8)
    blen = size - 2
    if blen < 0 or blen > 0x800000:
        raise ValueError("implausible S->C header: size=%d opcode=0x%X" % (size, opcode))
    body = recv_exact(sock, blen) if blen else b""
    if body is None:
        return None
    return opcode, body


# ---- CMSG_AUTH_SESSION ------------------------------------------------------
def parse_auth_session(body):
    f = {}
    p = 0

    def u32():
        nonlocal p
        v = struct.unpack_from("<I", body, p)[0]
        p += 4
        return v

    f["build"] = u32()
    f["loginServerID"] = u32()
    z = body.index(b"\x00", p)
    f["account"] = body[p:z]
    p = z + 1
    f["loginServerType"] = u32()
    f["clientSeed"] = body[p:p + 4]
    p += 4
    f["regionID"] = u32()
    f["battlegroupID"] = u32()
    f["realmID"] = u32()
    f["dosResponse"] = body[p:p + 8]
    p += 8
    f["digest"] = body[p:p + 20]
    p += 20
    f["addon_raw"] = body[p:]
    return f


def build_auth_session(f, build, realm_id, digest):
    out = struct.pack("<I", build)
    out += struct.pack("<I", f["loginServerID"])
    out += f["account"] + b"\x00"
    out += struct.pack("<I", f["loginServerType"])
    out += f["clientSeed"]
    out += struct.pack("<I", f["regionID"])
    out += struct.pack("<I", f["battlegroupID"])
    out += struct.pack("<I", realm_id)
    out += f["dosResponse"]
    out += digest
    out += f["addon_raw"]
    return out


def auth_digest(account, client_seed, server_seed, key40):
    h = hashlib.sha1()
    h.update(account)
    h.update(b"\x00\x00\x00\x00")
    h.update(client_seed)
    h.update(server_seed)
    h.update(key40)
    return h.digest()


# ---- the one thing we write: asc_auth.account.session_key --------------------
_DB_CFG = None


def db_config():
    """Read the core's own LoginDatabaseInfo rather than keeping a second copy of
    the credentials here."""
    global _DB_CFG
    if _DB_CFG is not None:
        return _DB_CFG
    conf = os.path.join(os.path.dirname(os.path.dirname(BASE)),
                        "server-ascension", "configs", "worldserver.conf")
    with open(conf, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.startswith("LoginDatabaseInfo"):
                val = line.split("=", 1)[1].strip().strip('"')
                host, port, user, pw, dbname = val.split(";")
                _DB_CFG = dict(host=host, port=int(port), user=user,
                               password=pw, database=dbname)
                return _DB_CFG
    raise RuntimeError("no LoginDatabaseInfo in %s" % conf)


def stage_session_key(account, key40):
    """Create the account if it is new, then hand the core the key we will sign with.

    `salt`/`verifier` stay zeroed: they are the SRP6 material the *auth* server
    uses, and nothing in the world handshake reads them.  This account exists only
    so the core has somewhere to keep a session key."""
    import pymysql
    cfg = db_config()
    conn = pymysql.connect(charset="utf8mb4", autocommit=True, **cfg)
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM account WHERE username = %s", (account,))
            row = cur.fetchone()
            if row is None:
                cur.execute(
                    "INSERT INTO account (username, salt, verifier, session_key,"
                    " email, reg_mail, expansion, last_ip, os)"
                    " VALUES (%s, %s, %s, %s, '', '', 2, '127.0.0.1', 'Win')",
                    (account, bytes(32), bytes(32), key40))
                cur.execute("SELECT id FROM account WHERE username = %s", (account,))
                row = cur.fetchone()
                log("    created asc_auth account %r (id %s)" % (account, row[0]))
            # `os` is not cosmetic: with Warden enabled the core rejects the
            # session outright (AUTH_REJECT, "invalid client OS ()") if the
            # column is anything but 'Win' or 'OSX', and the rejection arrives
            # AFTER the crypt is armed, so it reads as a crypt bug if you only
            # look at the wire.
            cur.execute("UPDATE account SET session_key = %s, os = 'Win',"
                        " locked = 0, online = 0 WHERE id = %s",
                        (key40, row[0]))
            return int(row[0])
    finally:
        conn.close()


# ---- one bridged session ----------------------------------------------------
class Session(object):
    def __init__(self, client, cid, addr):
        self.client = client
        self.cid = cid
        self.addr = addr
        self.core = None
        self.s2c = None          # decrypts headers the core sends us
        self.c2s = None          # encrypts headers we send the core
        self.alive = True
        self.account = b"?"
        self.customs_sent = False
        self.reason = None

    def log(self, msg):
        log("b%03d: %s" % (self.cid, msg))

    # -- handshake ------------------------------------------------------------
    def run(self):
        try:
            self.handshake()
        except Exception as e:
            self.log("!! handshake failed: %r" % (e,))
            self.close()
            return
        t = threading.Thread(target=self.pump_core_to_client, daemon=True)
        t.start()
        try:
            self.pump_client_to_core()
        finally:
            self.close(self.reason)

    def handshake(self):
        # 1. challenge the client exactly as world_server.py does
        body = struct.pack("<I", 1) + CLIENT_AUTH_SEED + CHALLENGE_TAIL
        self.client.sendall(frame_s2c(SMSG_AUTH_CHALLENGE, body))

        pkt = read_c2s(self.client)
        if pkt is None:
            raise RuntimeError("client closed before CMSG_AUTH_SESSION")
        opcode, abody = pkt
        if opcode != CMSG_AUTH_SESSION:
            raise RuntimeError("expected CMSG_AUTH_SESSION, got 0x%X" % opcode)
        f = parse_auth_session(abody)
        self.account = f["account"]
        self.log("CMSG_AUTH_SESSION build=%d account=%r realmID=%d addon=%dB"
                 % (f["build"], f["account"], f["realmID"], len(f["addon_raw"])))

        # 2. choose a session key and give it to the core BEFORE we connect
        key40 = os.urandom(40)
        acct_id = stage_session_key(f["account"].decode("utf-8", "replace"), key40)
        self.log("staged session key for asc_auth account id %d" % acct_id)

        # 3. authenticate to the core as a client
        self.core = socket.create_connection((AC_HOST, AC_PORT), timeout=30)
        self.core.settimeout(None)
        pkt = read_s2c(self.core)
        if pkt is None:
            raise RuntimeError("core closed before SMSG_AUTH_CHALLENGE")
        opcode, cbody = pkt
        if opcode != SMSG_AUTH_CHALLENGE:
            raise RuntimeError("core sent 0x%X, not SMSG_AUTH_CHALLENGE" % opcode)
        server_seed = cbody[4:8]
        self.log("core seed %s" % server_seed.hex())

        digest = auth_digest(f["account"], f["clientSeed"], server_seed, key40)
        out = build_auth_session(f, AC_BUILD, AC_REALM_ID, digest)
        self.core.sendall(frame_c2s(CMSG_AUTH_SESSION, out))
        self.log("-> core CMSG_AUTH_SESSION (build %d -> %d, realm %d -> %d)"
                 % (f["build"], AC_BUILD, f["realmID"], AC_REALM_ID))

        # 4. from here the core's headers are encrypted
        self.s2c, self.c2s = make_crypt(key40)

        # Forward whatever the core sends until its verdict arrives, so a refusal
        # is named in the log instead of showing up later as a silent hang.
        for _ in range(8):
            pkt = read_s2c(self.core, self.s2c)
            if pkt is None:
                raise RuntimeError("core closed instead of answering the auth session")
            opcode, rbody = pkt
            self.client.sendall(frame_s2c(opcode, rbody))
            if opcode == SMSG_AUTH_RESPONSE:
                res = rbody[0] if rbody else 0xFF
                self.log("core AuthResult 0x%02X (%s)"
                         % (res, "AUTH_OK" if res == 0x0C else "REFUSED"))
                if res != 0x0C:
                    raise RuntimeError("core refused the session")
                return
            self.log("<- core 0x%03X (%d B) before the auth response" % (opcode, len(rbody)))
        raise RuntimeError("core never sent SMSG_AUTH_RESPONSE")

    # -- pumps ----------------------------------------------------------------
    def pump_client_to_core(self):
        while self.alive:
            try:
                pkt = read_c2s(self.client)
            except ValueError as e:
                self.log("!! client stream: %s" % e)
                break
            except OSError as e:
                self.log("!! client socket: %r" % (e,))
                break
            if pkt is None:
                self.reason = self.reason or "client hung up (EOF)"
                break
            opcode, body = pkt
            if opcode == CMSG_CHAR_CREATE:
                self.log("   C->S CMSG_CHAR_CREATE %s" % describe_char_create(body))
            elif opcode == CMSG_LEARN_TALENT:
                self.log("   C->S CMSG_LEARN_TALENT %s" % describe_learn_talent(body))
            elif opcode == CMSG_MESSAGECHAT:
                self.log("   C->S chat %s" % describe_chat(body))
            elif worth_logging(opcode, True) and opcode != CMSG_PING:
                self.log("   C->S %s (%d B)" % (opname(opcode, True), len(body)))
            if opcode >= FIRST_CUSTOM_OPCODE:
                self.handle_custom(opcode, body)
                continue
            if opcode == CMSG_CHAR_CREATE:
                body = self.fix_char_create(body)
            try:
                self.core.sendall(frame_c2s(opcode, body, self.c2s))
            except OSError:
                break

    spellmod_seen = None

    def pump_core_to_client(self):
        self.spellmod_seen = {}
        while self.alive:
            try:
                pkt = read_s2c(self.core, self.s2c)
            except ValueError as e:
                self.log("!! core stream: %s" % e)
                break
            except OSError as e:
                self.log("!! core socket: %r" % (e,))
                break
            if pkt is None:
                self.reason = self.reason or ("core hung up (EOF) -- look for a "
                                              "kick reason in logs-bridge/Server.log")
                break
            opcode, body = pkt
            if opcode in (SMSG_CHAR_CREATE, SMSG_CHARACTER_LOGIN_FAILED) and body:
                self.log("   S->C %s -> %s"
                         % (opname(opcode),
                            RESPONSE_CODES.get(body[0], "0x%02X" % body[0])))
            elif opcode == SMSG_CAST_FAILED:
                self.log("   S->C SMSG_CAST_FAILED %s" % describe_cast_failed(body))
            elif opcode == SMSG_TRAINER_LIST:
                self.log("   S->C SMSG_TRAINER_LIST\n%s" % describe_trainer_list(body))
                if (TRAINER_TYPE_OVERRIDE and len(body) >= 12
                        and struct.unpack_from("<I", body, 8)[0] == 0):
                    body = (body[:8]
                            + struct.pack("<I", TRAINER_TYPE_OVERRIDE)
                            + body[12:])
                    self.log("   .. CLASS trainer list re-typed %d so the "
                             "classless client will render it"
                             % TRAINER_TYPE_OVERRIDE)
            elif opcode in (SMSG_SET_FLAT_SPELL_MODIFIER,
                            SMSG_SET_PCT_SPELL_MODIFIER) and len(body) >= 6:
                # The login spell-mod resend (CharacterHandler.cpp, "Xinef: we
                # need to resend all spell mods") is the only login packet whose
                # CONTENT varies with the talent set once 0x4C0 and 0x12A are
                # ruled out.  Log (effect index, op, value) so a crashing login
                # can be compared with a passing one bucket by bucket.
                eff, op = body[0], body[1]
                val = struct.unpack_from("<i", body, 2)[0]
                self.log("   S->C %s eff=%d op=%d val=%d"
                         % (opname(opcode, False), eff, op, val))
            elif worth_logging(opcode, False):
                self.log("   S->C %s (%d B)" % (opname(opcode, False), len(body)))
            # The Ascension client reads a 10-byte spell-mod body where stock
            # 3.3.5a sends 6.  Un-padded, every one of these overran its buffer
            # and the login died at Extensions.dll+0x324BCE.  See
            # TROUBLESHOOTING.md, "ERROR #132 ... on the millisecond of
            # CMSG_PLAYER_LOGIN".  Verified live: 6 and 8 bytes crash, 10
            # through 32 do not.
            if (opcode in (SMSG_SET_FLAT_SPELL_MODIFIER,
                           SMSG_SET_PCT_SPELL_MODIFIER)
                    and len(body) < SPELLMOD_BODY_BYTES
                    and SPELLMOD_MODE != "raw"):
                body = body + bytes(SPELLMOD_BODY_BYTES - len(body))
            if SPELLMOD_MODE and opcode in (SMSG_SET_FLAT_SPELL_MODIFIER,
                                            SMSG_SET_PCT_SPELL_MODIFIER)                     and len(body) >= 6:
                eff, op = body[0], body[1]
                val = struct.unpack_from("<i", body, 2)[0]
                seen = self.spellmod_seen
                drop = False
                if SPELLMOD_MODE == "firstop":
                    owner = seen.setdefault((opcode, op), eff)
                    drop = owner != eff
                elif SPELLMOD_MODE == "eff0":
                    body = bytes([0]) + body[1:]
                elif SPELLMOD_MODE == "uniq":
                    drop = (opcode, op, eff, val) in seen
                    seen[(opcode, op, eff, val)] = True
                elif SPELLMOD_MODE.startswith("pad"):
                    body = body + bytes(int(SPELLMOD_MODE[3:]))
                elif SPELLMOD_MODE.startswith("op"):
                    # Rewrite the SpellModOp byte, leaving effect index and
                    # value alone.  ASC_SPELLMOD_MODE=op7 -> every packet op 7.
                    body = body[:1] + bytes([int(SPELLMOD_MODE[2:])]) + body[2:]
                elif SPELLMOD_MODE == "one" or SPELLMOD_MODE.startswith("n"):
                    limit = 1 if SPELLMOD_MODE == "one" else int(
                        SPELLMOD_MODE[1:])
                    n = seen.get("n", 0)
                    drop = n >= limit
                    seen["n"] = n + 1
                if drop:
                    self.log("   .. SPELLMOD %s eff=%d op=%d val=%d withheld "
                             "[mode=%s]" % (opname(opcode, False), eff, op,
                                            val, SPELLMOD_MODE))
                    continue
            if opcode in DROP_OPCODES:
                self.log("   .. DROPPED %s (%d B) [ASC_DROP_OPCODES]"
                         % (opname(opcode, False), len(body)))
                continue
            try:
                self.client.sendall(frame_s2c(opcode, body))
            except OSError:
                break
            if opcode == SMSG_TUTORIAL_FLAGS and not self.customs_sent:
                self.send_customs()
            # EVERY world entry, not just the first.  One TCP session can enter
            # the world more than once (logout -> character select -> Enter
            # World), and each entry reloads FrameXML, which resets
            # ASC_ARCHIVE_SEEN back to false.  A once-per-socket hello left the
            # archive gate shut for every re-entry.
            if opcode == SMSG_LOGIN_VERIFY_WORLD:
                threading.Timer(ARCHIVE_HELLO_DELAY,
                                self.send_archive_hello).start()
        self.close(self.reason)

    def send_archive_hello(self):
        """Tell the client, in a way only this bridge can, that it is on the
        archive.  Delayed past world entry because the chat frame has to exist
        to raise CHAT_MSG_SYSTEM, and that is what GlobalOverwrites.lua listens
        for to set ASC_ARCHIVE_SEEN."""
        try:
            self.client.sendall(
                frame_s2c(SMSG_MESSAGECHAT, smsg_system_chat(ARCHIVE_HELLO)))
        except OSError:
            return
        self.log("-> client archive hello (%s)" % ARCHIVE_TOKEN)

    def send_customs(self):
        """Ascension-only packets the core cannot know about, in world_server.py's
        proven order: they go out after SMSG_TUTORIAL_FLAGS, at the glue stage,
        because the gate they open is read while the character screens are being
        built -- long before anyone enters the world."""
        self.customs_sent = True
        # RealmInfo is a process-global singleton in the client, so one send holds
        # for the whole session. +0x48 nonzero is the addon-loadability gate:
        # without it every LoadOnDemand Ascension addon reports loadable=nil and
        # the custom UI stays dark.
        self.client.sendall(frame_s2c(
            SMSG_REALM_INFO, smsg_realm_info(flags=BRIDGE_REALM_FLAVOUR)))
        self.log("-> client SMSG_REALM_INFO flavour=%r (addon gate open, stock "
                 "class creation)" % (tuple(BRIDGE_REALM_FLAVOUR),))

    # -- translation ----------------------------------------------------------
    def handle_custom(self, opcode, body):
        """Ascension's own opcodes never reach the core. Answer what we can, and
        say plainly what we dropped -- a silent drop here looks exactly like a
        protocol bug three hours later."""
        self.log("   custom 0x%03X (%d B) not forwarded" % (opcode, len(body)))

    def fix_char_create(self, body):
        """The classless realm sends a Character-Advancement class byte, which has
        no `playercreateinfo` row, so the core would answer CHAR_CREATE_FAILED.
        Substitute a class the core can actually build."""
        try:
            z = body.index(b"\x00")
        except ValueError:
            return body
        tail = bytearray(body[z + 1:])
        if len(tail) < 2:
            return body
        clas = tail[1]
        if clas in AC_VALID_CLASSES:
            return body
        tail[1] = AC_FALLBACK_CLASS
        self.log("   CHAR_CREATE class %d has no playercreateinfo row -> %d"
                 % (clas, AC_FALLBACK_CLASS))
        return body[:z + 1] + bytes(tail)

    def close(self, reason=None):
        if not self.alive:
            return
        self.alive = False
        if reason:
            self.log("closing: %s" % reason)
        for s in (self.client, self.core):
            try:
                if s:
                    s.close()
            except Exception:
                pass
        self.log("session closed")


def main():
    rotate_log()
    log("=" * 78)
    log("ascension_bridge: client %s:%d  ->  AzerothCore %s:%d (realm %d, build %d)"
        % (LISTEN_HOST, LISTEN_PORT, AC_HOST, AC_PORT, AC_REALM_ID, AC_BUILD))
    if LISTEN_PORT not in (8085, 8087, 8088):
        log("!! port %d is NOT on the client's endpoint allow-list -- the client "
            "will crash a few seconds after the world draws. See archive_ports.py."
            % LISTEN_PORT)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((LISTEN_HOST, LISTEN_PORT))
    srv.listen(4)
    log("listening.")
    cid = 0
    while True:
        conn, addr = srv.accept()
        cid += 1
        log("b%03d: connection from %s:%d" % (cid, addr[0], addr[1]))
        threading.Thread(target=Session(conn, cid, addr).run, daemon=True).start()


if __name__ == "__main__":
    main()
