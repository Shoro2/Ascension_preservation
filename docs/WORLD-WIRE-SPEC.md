# Ascension World/Extension Protocol — Reverse-Engineering Spec

Target: lawfully-owned Project Ascension client (build 12344), `client-ascension\Extensions.dll`
(12.6 MB, 32-bit, image base `0x10000000`). All findings are from **read-only** static
disassembly (capstone/pefile) + observing our own local `world_server.py`. No Extensions.dll
patching. Companion files in this dir:
- `ascension-opcodes.txt` — full opcode→name map (0x1..0x80B, 2001 entries).
- `ascension-handler-map.txt` — 349 SMSG receive-handler registrations (opcode→handler VA).

## 1. Opcode numbering — SOLVED and verified

Extensions.dll holds a contiguous opcode **name-pointer table** at file-offset `0x2C4003`
(anchor = opcode `0x3B` = SMSG_CHAR_ENUM). Entry stride = **6 bytes**: `{u32 name_ptr(VA),
u16 0xB8C3}`. The `0xB8C3` const holds unbroken for opcodes **0x1 .. 0x80B** (`0x80B` = `MAX`).

Formula: `entry_off = 0x2C4003 + (opcode - 0x3B) * 6`; reverse it (scan all entries, match by
name) to get name→opcode with zero guessing.

**Verified against stock 3.3.5a wire numbers at 12 points spanning the whole range:**
`0x3B` SMSG_CHAR_ENUM, `0x3D` CMSG_PLAYER_LOGIN, `0x66` CONTACT_LIST, `0x95` MESSAGECHAT,
`0xC9` MOVE_FALL_LAND, `0xFE` TUTORIAL_FLAG, `0x104` TEXT_EMOTE, `0x12A` INITIAL_SPELLS,
`0x1CC` PLAYED_TIME, `0x1F4` ZONEUPDATE, `0x2CD` MOVE_TIME_SKIPPED, `0x500`
QUERY_QUESTS_COMPLETED_RESPONSE (top of stock enum). Stock ends ~`0x500`; **everything
≥ 0x501 is custom Ascension** and appended in-order.

> CORRECTION vs earlier sessions: `CMSG_EXTENSION_INITIALIZED` is **0x58A**, NOT 0x53B
> (0x53B = CMSG_AUTO_QUEST_SHOW_COMPLETE). The old "name table unreliable above 0x1ED"
> verdict was wrong — it came from a bad indexing hypothesis (dense-from-0 + offset K).
> The anchor formula above is correct across the entire enum.
>
> WARNING: custom-opcode name **prefixes are not reliable for direction**. The client sends
> several `SMSG_`-named opcodes as request stubs (observed: it sent 0x561, 0x5A1, 0x6FD,
> 0x741, 0x745, 0x777). Trust the number, not the SMSG/CMSG prefix.

## 2. Establishment / Character-Advancement opcodes (server→client unless noted)

| Opcode | Name | Receive handler (VA) |
|--------|------|----------------------|
| 0x57F | CMSG_CHARACTER_ADVANCEMENT_LOADOUT_ACTIVATE_REQUEST (c→s) | — |
| 0x584 | SMSG_MISC_PLAYER_DATA_PAYLOAD | (generic-payload path) |
| 0x586 | SMSG_CHARACTER_ADVANCEMENT_LOADOUT_ACTIVE_PAYLOAD | (not in 0x102C4590 registrar) |
| 0x587 | SMSG_CHARACTER_ADVANCEMENT_LOADOUT_OWNED_PAYLOAD | 0x102720B0 |
| 0x58A | CMSG_EXTENSION_INITIALIZED (c→s ack) | 0x101197C0 (parses a C-string) |
| 0x594 | SMSG_PATCH_MYSTIC_ENCHANT | generic DBC-patch |
| 0x65D | SMSG_PATCH_CHARACTER_ADVANCEMENT | 0x102A36F0 |
| 0x669 | CMSG_CHARACTER_ADVANCEMENT_LOCK_ENTRY (c→s) | 0x10A4FD70 |
| 0x66B | CMSG_CHARACTER_ADVANCEMENT_UNLOCK_ENTRY (c→s) | 0x1031AD50 |
| 0x6B5 | SMSG_PATCH_CHARACTER_ADVANCEMENT_CATEGORIES | generic DBC-patch |
| 0x775 | SMSG_PATCH_CHR_CLASSES | generic DBC-patch |
| 0x782 | SMSG_PATCH_SKILL_RACE_CLASS_INFO | generic DBC-patch |
| 0x808 | SMSG_PATCH_CHARACTER_CREATION_CLASS_DETAILS | generic DBC-patch |
| 0x80A | SMSG_PATCH_CHR_CLASSES_ROLES | generic DBC-patch |

## 3. Packet build/send API (client side — CDataStore vtable @ 0x10bc90xx)

From the 0x586 / 0x775 send sites, the client builds outgoing packets like:
```
call [0x10bc90bc]          ; CDataStore ctor/init (writes vtbl 0x10b1b384, sets cap=0xF SSO)
push <opcode>
call [0x10bc90cc]          ; SetOpcode(opcode)
push 4 ; push &val ; call [0x10bc90dc]   ; Write(src, size)   -- per field
call [0x10bc90fc]          ; Finalize()
mov esi,[0x10bc91ec] ; call [0x10bc91f0]  ; get connection singleton
push &store ; mov ecx,eax ; call esi      ; connection->Send(store)
```
`[0x10bc90dc]` = `CDataStore::Write(void* src, int nbytes)`. Strings use std::string SSO
(inline buffer if len ≤ 15, else heap ptr; a length field precedes the bytes).

## 4. Known payload formats

- **0x586 SMSG_CHARACTER_ADVANCEMENT_LOADOUT_ACTIVE_PAYLOAD** (from client send @0x10274528):
  `{ u32 field1; if field1 != 0: byte[field1] blob }` — a length-prefixed serialized loadout
  blob (std::string). field1 = blob length. Blob internal format = still opaque (serialized
  CA build entries; the CharacterAdvancement entry schema is `ClassType, Spells, RequiredLevel,
  Quality, QualityCost, Description, Comment` per strings @0xB274FC).
- **0x58A CMSG_EXTENSION_INITIALIZED** handler (0x101197C0) parses a **C-string** from the
  packet (strlen loop + std::string assign @0x10086e30). Payload ≈ a version/extension id string.
- **SMSG_PATCH_\*** family: NOT individually registered — one generic DBC-patch dispatcher
  keyed by opcode→DBC. Payload = DBC-row patch. The client already has all these DBCs locally
  (custom `ChrClasses.dbc`, `CharacterAdvancement.dbc`, `CharacterAdvancementClassTypes.dbc`
  inside `patch-C*.MPQ`; plus `Data\Content\CharacterAdvancementData.json`, 7.8 MB). So the
  PATCH stream is likely deltas/overrides, **not** required to teach the client the classes exist.

## 5. The gate (why the custom UI is dark) — current model

All 36 LoadOnDemand addons report `loadable=nil, reason=nil` (incl. Blizzard .pub-signed).
Native lockout keyed on class-type: `IsCustomClass()==false AND IsDefaultClass()==false`.
`IsCustomClass`/`IsDefaultClass` strings are **absent** from Extensions.dll → those Lua
natives live in **WoW.exe**, not Extensions.dll. The underlying machinery in Extensions.dll:
enum `CharacterAdvancementClassType` (RTTI @0xBCDA09), `CharacterAdvancementClassTypes.dbc`.

Model: the gate is a per-character **established class-type / extensions-initialized** state,
not a signature check and not a missing-definition problem. The client, at world entry, fires
an extension request burst and **waits**; our minimal server never answers, so the class-type
never establishes, `IsCustomClass` stays false, and every LoD addon stays locked. The client
only emits `CMSG_EXTENSION_INITIALIZED (0x58A)` **after** establishment completes (we have
never observed it send 0x58A — consistent with never completing establishment).

## 6. Observed client→server burst at world entry (session w001, unhandled dumps)

Custom opcodes the client actually sent post-login (numbers reliable, names indicative only):
`0x53B, 0x561, 0x5A1, 0x667, 0x6A3, 0x6FD, 0x741, 0x745, 0x777`. It did **not** send 0x58A.

## 7. Next steps (protocol reconstruction)

1. Disassemble the generic DBC-patch dispatcher + `SMSG_PATCH_CHR_CLASSES` path to get the
   PATCH row format (find the routine that all PATCH_* opcodes route through).
2. Disassemble handler 0x102720B0 (LOADOUT_OWNED) and the 0x586 receive path to learn what
   marks the character custom-class (most likely gate trigger).
3. Consider WoW.exe disasm for `IsCustomClass` to find the exact flag + its setter (cross-ref
   to the Extensions.dll code that sets it → the definitive establishment packet).
4. Empirical (authorized, crash-risk): from `world_server.py`, at PLAYER_LOGIN send minimal
   establishment SMSGs (start safest: 0x586 with field1=0), relog, read `IsCustomClass()` via
   `/run`. Iterate payloads. Start empty/minimal to avoid client crashes.
