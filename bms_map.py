#!/usr/bin/env python3
"""Pure mapping between a Bind My Soul checkpoint and AzerothCore's schema.

No database, no I/O -- every function here is a total function over checkpoint
data, so the whole mapping layer is testable without a server.

Schema facts this module encodes, each verified against the named file in the
AzerothCore source tree:

  Item.h:167          EnchantmentSlot: PERM=0, SOCK=2..4, PRISMATIC=6, MAX=12
                      -> item_instance.enchantments is 36 space-separated ints
                         (12 slots x id/duration/charges)
  Player.h:681        EQUIPMENT_SLOT_END=19, INVENTORY_SLOT_BAG_START=19,
                      INVENTORY_SLOT_ITEM_START=23, INVENTORY_SLOT_ITEM_END=39
  Player.h:587        AT_LOGIN_RENAME=0x01, AT_LOGIN_CUSTOMIZE=0x08

The checkpoint's own conventions (confirmed against a real capture):

  * equipment slotId is the client's INVSLOT_* value, 1..19; the database slot
    is slotId - 1.
  * sexId is UnitSex(): 2 = male, 3 = female; database gender is 0 = male.
  * itemString has NO "item:" prefix -- it is "6096:0:0:0:0:0:0:0:20".
  * A nil field is absent from the JSON entirely. An unenchanted item has no
    "enchantId" key at all, so every read must tolerate a missing key.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "AT_LOGIN_CUSTOMIZE",
    "AT_LOGIN_RENAME",
    "ItemFields",
    "MappingError",
    "UnmappedValue",
    "allocate_name",
    "class_id",
    "enchantments_blob",
    "equipped_db_slot",
    "gender_id",
    "money_parts",
    "parse_item_fields",
    "race_id",
    "split_bag_placement",
]

# -- AzerothCore constants -------------------------------------------------

EQUIPMENT_SLOT_END = 19
INVENTORY_SLOT_BAG_START = 19
INVENTORY_SLOT_BAG_END = 23
INVENTORY_SLOT_ITEM_START = 23
INVENTORY_SLOT_ITEM_END = 39
KEYRING_SLOT_START = 86
KEYRING_SLOT_END = 118

# The client's container indices, as the addon records them in bagId.
BACKPACK_CONTAINER = 0
KEYRING_CONTAINER = -2

MAX_ENCHANTMENT_SLOT = 12
PERM_ENCHANTMENT_SLOT = 0
SOCK_ENCHANTMENT_SLOT = 2
PRISMATIC_ENCHANTMENT_SLOT = 6

AT_LOGIN_RENAME = 0x01
AT_LOGIN_CUSTOMIZE = 0x08

MAX_CHARACTER_NAME = 12  # WoW hard limit; suffixes must fit inside it


class MappingError(Exception):
    """A checkpoint value cannot be represented in the target schema."""


@dataclass
class UnmappedValue:
    """Something the importer could not translate, for the conflict report."""

    category: str
    value: str
    reason: str

    def __str__(self) -> str:
        return f"{self.category}: {self.value} -- {self.reason}"


# -- identity --------------------------------------------------------------
#
# UnitRace's second return is the English race name; UnitClass's second return
# is the uppercase class token. Both come straight from the client.

RACE_IDS = {
    "Human": 1,
    "Orc": 2,
    "Dwarf": 3,
    "NightElf": 4,
    "Scourge": 5,      # Undead: the client's token is "Scourge"
    "Undead": 5,
    "Tauren": 6,
    "Gnome": 7,
    "Troll": 8,
    "Goblin": 9,
    "BloodElf": 10,
    "Draenei": 11,
}

CLASS_IDS = {
    "WARRIOR": 1,
    "PALADIN": 2,
    "HUNTER": 3,
    "ROGUE": 4,
    "PRIEST": 5,
    "DEATHKNIGHT": 6,
    "SHAMAN": 7,
    "MAGE": 8,
    "WARLOCK": 9,
    "DRUID": 11,
}

# Ascension ships custom classes as a UNIT_FIELD_BYTES_0 class byte with no
# stock equivalent (Tinker = 28). A stock AzerothCore target cannot represent
# them, and silently importing one as a Mage would produce a broken character.
CUSTOM_CLASS_TOKENS = {"HERO", "TINKER", "ADVENTURER"}


def race_id(race_token: Any) -> int:
    token = str(race_token or "").strip()
    if token in RACE_IDS:
        return RACE_IDS[token]
    folded = {k.lower(): v for k, v in RACE_IDS.items()}
    if token.lower() in folded:
        return folded[token.lower()]
    raise MappingError(f"Unknown race token {token!r}.")


def class_id(class_token: Any) -> int:
    token = str(class_token or "").strip().upper()
    if token in CLASS_IDS:
        return CLASS_IDS[token]
    if token in CUSTOM_CLASS_TOKENS:
        raise MappingError(
            f"{token} is an Ascension custom class with no stock AzerothCore "
            "equivalent; this character cannot be imported onto this realm."
        )
    raise MappingError(f"Unknown class token {token!r}.")


def gender_id(sex_id: Any) -> int:
    """UnitSex(): 1 neutral, 2 male, 3 female -> database gender 0 male, 1 female."""
    value = sex_id if isinstance(sex_id, int) and not isinstance(sex_id, bool) else None
    if value in (2, 3):
        return value - 2
    raise MappingError(f"Cannot map sexId {sex_id!r} to a database gender.")


def allocate_name(desired: str, taken: set[str]) -> tuple[str, bool]:
    """Return a free character name, appending a counter when needed.

    Comparison is case-insensitive because WoW names are. The result is capped
    at 12 characters, so the base name is trimmed to make room for the counter
    rather than producing a name the server would reject.

    Returns (name, was_renamed). When was_renamed is True the caller should set
    AT_LOGIN_RENAME so the player is prompted to choose a real name.
    """
    base = str(desired or "").strip()
    if not base:
        raise MappingError("The checkpoint has no character name.")
    lowered = {str(n).strip().lower() for n in taken}
    if base.lower() not in lowered:
        return base[:MAX_CHARACTER_NAME], False
    for counter in range(2, 1000):
        suffix = str(counter)
        stem = base[: MAX_CHARACTER_NAME - len(suffix)]
        candidate = f"{stem}{suffix}"
        if candidate.lower() not in lowered:
            return candidate, True
    raise MappingError(f"Could not find a free name based on {base!r}.")


# -- items -----------------------------------------------------------------

_ITEM_LINK_RE = re.compile(r"\|Hitem:([-0-9:]+)\|h")


@dataclass
class ItemFields:
    """The numeric fields of a 3.3.5a item link."""

    item_id: int
    enchant_id: int = 0
    gems: list[int] = field(default_factory=lambda: [0, 0, 0, 0])
    suffix_id: int = 0
    unique_id: int = 0
    link_level: int = 0


def _int(value: Any, default: int = 0) -> int:
    try:
        parsed = int(str(value).strip())
    except (TypeError, ValueError):
        return default
    return parsed


def parse_item_fields(record: dict[str, Any]) -> ItemFields:
    """Read one checkpoint item record into its numeric link fields.

    Prefers itemString / itemLinkFields (already split by the addon) and falls
    back to re-parsing itemLink. Tolerates every field being absent, because
    the addon drops nil values before encoding.
    """
    parts: list[str] = []
    fields_value = record.get("itemLinkFields")
    if isinstance(fields_value, list) and fields_value:
        parts = [str(p) for p in fields_value]
    if not parts:
        item_string = record.get("itemString")
        if isinstance(item_string, str) and item_string:
            parts = item_string.replace("item:", "", 1).split(":")
    if not parts:
        link = record.get("itemLink")
        if isinstance(link, str):
            match = _ITEM_LINK_RE.search(link)
            if match:
                parts = match.group(1).split(":")

    def at(index: int) -> int:
        return _int(parts[index]) if index < len(parts) else 0

    item_id = at(0) or _int(record.get("itemId"))
    if item_id <= 0:
        raise MappingError(f"Item record has no usable item id: {record.get('name')!r}")

    gems = [at(2), at(3), at(4), at(5)]
    # gemIds is the addon's own parse; trust it when the link fields are absent.
    if not any(gems):
        observed = record.get("gemIds")
        if isinstance(observed, list):
            gems = [_int(g) for g in observed[:4]] + [0] * max(0, 4 - len(observed))

    return ItemFields(
        item_id=item_id,
        enchant_id=at(1) or _int(record.get("enchantId")),
        gems=gems,
        suffix_id=at(6),
        unique_id=at(7),
        link_level=at(8),
    )


def enchantments_blob(fields: ItemFields) -> str:
    """Build item_instance.enchantments: 12 slots x (id, duration, charges)."""
    slots = [[0, 0, 0] for _ in range(MAX_ENCHANTMENT_SLOT)]
    if fields.enchant_id:
        slots[PERM_ENCHANTMENT_SLOT][0] = fields.enchant_id
    for offset, gem in enumerate(fields.gems[:3]):
        if gem:
            slots[SOCK_ENCHANTMENT_SLOT + offset][0] = gem
    if len(fields.gems) > 3 and fields.gems[3]:
        slots[PRISMATIC_ENCHANTMENT_SLOT][0] = fields.gems[3]
    return " ".join(str(value) for slot in slots for value in slot)


# -- inventory placement ---------------------------------------------------

def equipped_db_slot(client_slot_id: Any) -> int:
    """INVSLOT_* (1..19) -> character_inventory.slot (0..18)."""
    value = _int(client_slot_id, -1)
    if not 1 <= value <= EQUIPMENT_SLOT_END:
        raise MappingError(f"Equipment slotId {client_slot_id!r} is out of range 1..19.")
    return value - 1


def split_bag_placement(record: dict[str, Any]) -> tuple[int, int]:
    """Map a bag item to (container_bag_index, database slot).

    Returns the *client* container index (0 = backpack, 1..4 = equipped bags),
    not the container's item guid. The caller substitutes the real guid once
    the container item rows exist, because character_inventory.bag holds the
    container's item_instance guid rather than a bag number.

    Backpack items occupy database slots 23..38 and keyring items 86..117;
    both live directly on the character, so bag is 0 for them. Items inside an
    equipped bag are slot-indexed from 0 within that bag.

    Note that the addon scans containers -2, 0 and 1..4 (Core.lua:1260) but
    scans equipment only for slots 1..19 (Core.lua:1070), so the equipped bag
    *containers* themselves are never captured. The importer therefore has no
    container guid to hang bags 1..4 on and must relocate those items.
    """
    bag_id = _int(record.get("bagId"), -99)
    bag_slot = _int(record.get("bagSlot"), -1)
    if bag_slot < 1:
        raise MappingError(f"Bag item has no usable bagSlot: {record.get('name')!r}")
    if bag_id == BACKPACK_CONTAINER:
        slot = INVENTORY_SLOT_ITEM_START + (bag_slot - 1)
        if slot >= INVENTORY_SLOT_ITEM_END:
            raise MappingError(f"Backpack slot {bag_slot} is beyond the 16-slot backpack.")
        return 0, slot
    if bag_id == KEYRING_CONTAINER:
        slot = KEYRING_SLOT_START + (bag_slot - 1)
        if slot >= KEYRING_SLOT_END:
            raise MappingError(f"Keyring slot {bag_slot} is beyond the 32-slot keyring.")
        return 0, slot
    if 1 <= bag_id <= 4:
        return bag_id, bag_slot - 1
    raise MappingError(f"Unsupported bagId {bag_id!r}.")


def equipped_bag_db_slot(bag_id: int) -> int:
    """Equipped bag container 1..4 -> character_inventory.slot 19..22."""
    value = _int(bag_id, -1)
    if not 1 <= value <= 4:
        raise MappingError(f"Bag container index {bag_id!r} is out of range 1..4.")
    return INVENTORY_SLOT_BAG_START + (value - 1)


# -- misc ------------------------------------------------------------------

def money_parts(copper: Any) -> tuple[int, int, int]:
    value = _int(copper, 0)
    value = max(0, value)
    gold, rest = divmod(value, 10_000)
    silver, bronze = divmod(rest, 100)
    return gold, silver, bronze


def at_login_flags(renamed: bool, customize: bool = True) -> int:
    """Flags to set on characters.at_login.

    Rename is prompted only when the name actually had to change. Customize is
    on by default because the client never exposes skin/face/hair/hairColor/
    facialStyle after login, so those five fields are always guesses -- the
    customization screen is the graceful way to let the player fix them.
    """
    flags = 0
    if renamed:
        flags |= AT_LOGIN_RENAME
    if customize:
        flags |= AT_LOGIN_CUSTOMIZE
    return flags
