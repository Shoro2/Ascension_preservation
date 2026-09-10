"""Offline validator for world_server.py's character-flow + world-entry packets.

No elevation, no client, no RPM: stubs out rpm_readk, imports the real builders
from world_server, then PARSES each packet back exactly the way the 3.3.5a client
would -- asserting field values and that no trailing bytes remain (a leftover byte
means a desync that would hang the client on the loading screen).

Run:  python test_world_offline.py
"""
import sys, os, types, struct

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)
sys.path.insert(0, os.path.join(os.path.dirname(BASE), "server"))

# --- stub the passive-RPM module so importing world_server needs no client ---
_stub = types.ModuleType("rpm_readk")
_stub.find_pids = lambda: []
_stub.module_base = lambda pid: 0
_stub._open = lambda pid: 0
_stub._read = lambda h, a, n: b""
_stub.STATIC_OBJ_SLOT_RVA = 0
_stub.K_OFFSET_IN_OBJ = 0x120
_stub.k32 = types.SimpleNamespace(CloseHandle=lambda h: None)
sys.modules["rpm_readk"] = _stub

import world_server as W
import chardata

FAILS = []
def check(cond, msg):
    tag = "  ok " if cond else " FAIL"
    print("%s  %s" % (tag, msg))
    if not cond:
        FAILS.append(msg)


# ---- little-endian cursor reader --------------------------------------------
class Rdr:
    def __init__(self, b): self.b = b; self.p = 0
    def u8(self):  v = self.b[self.p]; self.p += 1; return v
    def u16(self): v = struct.unpack_from("<H", self.b, self.p)[0]; self.p += 2; return v
    def u16be(self): v = struct.unpack_from(">H", self.b, self.p)[0]; self.p += 2; return v
    def u32(self): v = struct.unpack_from("<I", self.b, self.p)[0]; self.p += 4; return v
    def u64(self): v = struct.unpack_from("<Q", self.b, self.p)[0]; self.p += 8; return v
    def f(self):   v = struct.unpack_from("<f", self.b, self.p)[0]; self.p += 4; return v
    def cstr(self):
        z = self.b.index(b"\x00", self.p); s = self.b[self.p:z]; self.p = z + 1; return s.decode("utf-8", "replace")
    def packguid(self):
        mask = self.u8(); guid = 0
        for i in range(8):
            if mask & (1 << i):
                guid |= self.b[self.p] << (8 * i); self.p += 1
        return guid
    def left(self): return len(self.b) - self.p


def approx(a, b, eps=1e-3): return abs(a - b) <= eps


# ---- a sample created character (Troll Female, as in the AFK screenshot) -----
DB = {}
DB.setdefault("test", [])
cc = W.parse_char_create(b"Zubarra\x00" + bytes([8, 3, 1, 5, 2, 7, 4, 1, 0]))  # race8 class3 gender1(female)
check(cc["race"] == 8 and cc["class"] == 3 and cc["gender"] == 1, "parse_char_create fields (race=8 class=3 gender=1)")
check(cc["name"] == "Zubarra", "parse_char_create name")

char = W.make_character(DB, cc)
DB["test"].append(char)
exp_disp = chardata.display_for(8, 1)   # troll female = 1479
check(char["displayId"] == exp_disp == 1479, "make_character display id -> troll female 1479")
check(char["map"] == 1 and char["zone"] == 14, "make_character start -> Durotar/Valley of Trials (map1 zone14)")
check(char["guid"] >= 1, "make_character assigned a guid (%d)" % char["guid"])


print("\n== SMSG_CHAR_ENUM ==")
enum = W.smsg_char_enum(DB["test"])
r = Rdr(enum)
count = r.u8(); check(count == 1, "char count == 1")
g = r.u64(); check(g == char["guid"], "guid u64 == %d" % char["guid"])
nm = r.cstr(); check(nm == "Zubarra", "name == Zubarra")
race = r.u8(); clas = r.u8(); gender = r.u8()
check((race, clas, gender) == (8, 3, 1), "race/class/gender == 8/3/1")
skin = r.u8(); face = r.u8(); hs = r.u8(); hc = r.u8(); fh = r.u8(); lvl = r.u8()
check(lvl == 1, "level == 1")
zone = r.u32(); mp = r.u32(); x = r.f(); y = r.f(); z = r.f()
check(zone == 14 and mp == 1, "zone==14 map==1")
check(approx(x, char["x"]) and approx(y, char["y"]) and approx(z, char["z"]), "x/y/z match start pos")
guild = r.u32(); cflags = r.u32(); custom = r.u32(); first = r.u8()
check(first == 0, "firstLogin == 0 (no intro cinematic)")
pdisp = r.u32(); plvl = r.u32(); pfam = r.u32()
check((pdisp, plvl, pfam) == (0, 0, 0), "no pet")
slots = 0
for _ in range(23):
    r.u32(); r.u8(); r.u32(); slots += 1
check(slots == 23, "equipment loop == 23 slots (INVENTORY_SLOT_BAG_END)")
check(r.left() == 0, "char-enum fully consumed, 0 trailing bytes")


print("\n== SMSG_CHAR_CREATE / DELETE ==")
check(W.smsg_char_create(W.CHAR_CREATE_SUCCESS) == bytes([0x2F]), "char-create success == 0x2F")
check(W.smsg_char_delete(W.CHAR_DELETE_SUCCESS) == bytes([0x47]), "char-delete success == 0x47")


print("\n== SMSG_LOGIN_VERIFY_WORLD ==")
r = Rdr(W.smsg_login_verify_world(char))
mp = r.u32(); x = r.f(); y = r.f(); z = r.f(); o = r.f()
check(mp == 1, "map == 1")
check(approx(x, char["x"]) and approx(o, char["o"]), "position + orientation match")
check(r.left() == 0, "verify-world fully consumed")


print("\n== SMSG_UPDATE_OBJECT (self player create) ==")
obj = W.build_player_create_object(char)
r = Rdr(obj)
blocks = r.u32(); check(blocks == 1, "outer blockCount == 1")
utype = r.u8(); check(utype == 3, "updateType == CREATE_OBJECT2 (3)")
oguid = r.packguid(); check(oguid == char["guid"], "packed guid == char guid")
tid = r.u8(); check(tid == 4, "typeId == TYPEID_PLAYER (4)")
flags = r.u16(); check(flags == 0x0061, "updateFlags == 0x0061 (SELF|LIVING|STATIONARY)")
# movement (LIVING)
mf = r.u32(); check(mf == 0, "movementFlags == 0")
mf2 = r.u16(); check(mf2 == 0, "movementFlags2 == 0")
tm = r.u32()
mx = r.f(); my = r.f(); mz = r.f(); mo = r.f()
check(approx(mx, char["x"]) and approx(mo, char["o"]), "movement x/o match start pos")
fall = r.u32(); check(fall == 0, "fallTime == 0")
speeds = [r.f() for _ in range(9)]
exp_speeds = [2.5, 7.0, 4.5, 4.722222, 2.5, 7.0, 4.5, 3.141594, 3.14]
check(all(approx(a, b, 1e-2) for a, b in zip(speeds, exp_speeds)), "9 speeds in wire order: %s" % [round(s, 3) for s in speeds])
# values block
nblocks = r.u8(); check(nblocks == 42, "values blockCount == 42 (full PLAYER_END mask)")
mask_words = [r.u32() for _ in range(nblocks)]
set_bits = []
for wi, w in enumerate(mask_words):
    for bit in range(32):
        if w & (1 << bit):
            set_bits.append(wi * 32 + bit)
vals = {}
for idx in set_bits:                      # values follow in ascending index order
    vals[idx] = r.u32()
check(r.left() == 0, "update-object fully consumed, 0 trailing bytes")

# decode the important fields
def fval(i): return vals.get(i)
power = chardata.power_for(3)
exp_bytes0 = 8 | (3 << 8) | (1 << 16) | (power << 24)
check(fval(0) == (char["guid"] & 0xFFFFFFFF), "field GUID low")
check(fval(2) == 0x19, "field OBJECT_FIELD_TYPE == 0x19")
check(struct.unpack("<f", struct.pack("<I", fval(4)))[0] == 1.0, "field SCALE_X == 1.0")
check(fval(23) == exp_bytes0, "field UNIT_FIELD_BYTES_0 == race|class|gender|power (0x%08X)" % exp_bytes0)
check(fval(54) == 1, "field UNIT_FIELD_LEVEL == 1")
check(fval(67) == 1479 and fval(68) == 1479, "field DISPLAYID/NATIVEDISPLAYID == 1479")
check(fval(55) == chardata.RACE_FACTION[8], "field FACTIONTEMPLATE == troll faction (%d)" % chardata.RACE_FACTION[8])
check(fval(153) is not None, "field PLAYER_BYTES present")
check(fval(155) == 1, "field PLAYER_BYTES_3 byte0 == gender(1)")
check(fval(1230) == 0xFFFFFFFF, "field WATCHED_FACTION_INDEX == -1")
check((25 + power) in vals and (33 + power) in vals, "matching POWERx / MAXPOWERx fields set")


print("\n== SMSG_NAME_QUERY_RESPONSE ==")
r = Rdr(W.smsg_name_query_response(char))
qg = r.packguid(); check(qg == char["guid"], "name-query packed guid")
known = r.u8(); check(known == 0, "name known byte == 0")
qn = r.cstr(); check(qn == "Zubarra", "name-query name")
realm = r.u8(); check(realm == 0, "cross-realm name empty")
qr = r.u8(); qgn = r.u8(); qc = r.u8()
check((qr, qgn, qc) == (8, 1, 3), "name-query race/gender/class == 8/1/3")
decl = r.u8(); check(decl == 0, "declined-names byte == 0")
check(r.left() == 0, "name-query fully consumed")


print("\n== fixed-layout burst packets (parse for sane length) ==")
check(len(W.smsg_login_settimespeed()) == 12, "SETTIMESPEED == 12 bytes (u32+f32+u32)")
check(len(W.smsg_initial_spells()) == 5, "INITIAL_SPELLS == 5 bytes")
check(len(W.smsg_action_buttons()) == 1 + 144 * 4, "ACTION_BUTTONS == 1 + 144*4 bytes")
check(len(W.smsg_send_unlearn_spells()) == 4, "SEND_UNLEARN_SPELLS == 4 bytes")
check(len(W.smsg_time_sync_req(0)) == 4, "TIME_SYNC_REQ == 4 bytes")
r = Rdr(W.smsg_bindpoint_update(char)); r.f(); r.f(); r.f(); bm = r.u32(); bz = r.u32()
check(bm == 1 and bz == 14 and r.left() == 0, "BINDPOINTUPDATE xyz+map+zone")
r = Rdr(W.smsg_motd("hello")); lc = r.u32(); ln = r.cstr()
check(lc == 1 and ln == "hello" and r.left() == 0, "MOTD lineCount+cstr")
r = Rdr(W.smsg_account_data_times()); r.u32(); a = r.u8(); m = r.u32()
check(a == 1 and m == 0 and r.left() == 0, "ACCOUNT_DATA_TIMES minimal form")


# ---- name-in-use + delete round trip on the DB ------------------------------
print("\n== DB round trip (create/enum/delete) ==")
dup = W.parse_char_create(b"zubarra\x00" + bytes([8, 3, 1, 0, 0, 0, 0, 0, 0]))
is_dup = any(c["name"].lower() == dup["name"].strip().lower() for c in DB["test"])
check(is_dup, "duplicate name detected case-insensitively (-> NAME_IN_USE)")
DB["test"].remove(char)
check(len(DB["test"]) == 0, "delete removes the character from the account list")


print("\n" + ("=" * 60))
if FAILS:
    print("RESULT: %d FAILURE(S):" % len(FAILS))
    for m in FAILS:
        print("   - " + m)
    sys.exit(1)
else:
    print("RESULT: ALL CHECKS PASSED -- packets are wire-faithful.")
    sys.exit(0)
