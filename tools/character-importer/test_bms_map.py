#!/usr/bin/env python3
"""Tests for the checkpoint -> AzerothCore mapping layer.

Run:  python test_bms_map.py
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from bms_map import (  # noqa: E402
    AT_LOGIN_CUSTOMIZE,
    AT_LOGIN_RENAME,
    MappingError,
    allocate_name,
    at_login_flags,
    class_id,
    enchantments_blob,
    equipped_bag_db_slot,
    equipped_db_slot,
    gender_id,
    money_parts,
    parse_item_fields,
    race_id,
    split_bag_placement,
)


class IdentityTests(unittest.TestCase):
    def test_races(self):
        self.assertEqual(race_id("Human"), 1)
        self.assertEqual(race_id("BloodElf"), 10)
        self.assertEqual(race_id("Scourge"), 5)   # the client's Undead token
        self.assertEqual(race_id("Undead"), 5)
        self.assertEqual(race_id("nightelf"), 4)  # case-insensitive fallback

    def test_classes(self):
        self.assertEqual(class_id("MAGE"), 8)
        self.assertEqual(class_id("mage"), 8)
        self.assertEqual(class_id("DRUID"), 11)   # 10 is unused in 3.3.5a
        self.assertEqual(class_id("DEATHKNIGHT"), 6)

    def test_custom_class_is_refused_with_a_reason(self):
        """A classless/Tinker character must fail loudly, not import as a Mage."""
        with self.assertRaisesRegex(MappingError, "custom class"):
            class_id("HERO")
        with self.assertRaisesRegex(MappingError, "custom class"):
            class_id("TINKER")

    def test_unknown_identity_raises(self):
        with self.assertRaises(MappingError):
            race_id("Vulpera")
        with self.assertRaises(MappingError):
            class_id("MONK")

    def test_gender(self):
        self.assertEqual(gender_id(2), 0)  # male
        self.assertEqual(gender_id(3), 1)  # female
        for bad in (None, 1, 0, True, "2"):
            with self.assertRaises(MappingError):
                gender_id(bad)


class NameAllocationTests(unittest.TestCase):
    def test_free_name_is_kept(self):
        self.assertEqual(allocate_name("Probethree", set()), ("Probethree", False))

    def test_collision_appends_counter_and_flags_rename(self):
        name, renamed = allocate_name("Probethree", {"Probethree"})
        self.assertEqual(name, "Probethree2")
        self.assertTrue(renamed)

    def test_collision_is_case_insensitive(self):
        name, renamed = allocate_name("Probethree", {"PROBETHREE"})
        self.assertEqual(name, "Probethree2")
        self.assertTrue(renamed)

    def test_counter_walks_past_taken_suffixes(self):
        taken = {"Reeks", "Reeks2", "Reeks3"}
        self.assertEqual(allocate_name("Reeks", taken), ("Reeks4", True))

    def test_long_name_is_trimmed_to_fit_the_12_char_limit(self):
        """A suffix must not push the name past what the server accepts."""
        name, renamed = allocate_name("Abcdefghijkl", {"Abcdefghijkl"})
        self.assertEqual(len(name), 12)
        self.assertEqual(name, "Abcdefghijk2")
        self.assertTrue(renamed)

    def test_blank_name_raises(self):
        with self.assertRaises(MappingError):
            allocate_name("   ", set())

    def test_at_login_flags(self):
        self.assertEqual(at_login_flags(renamed=True), AT_LOGIN_RENAME | AT_LOGIN_CUSTOMIZE)
        self.assertEqual(at_login_flags(renamed=False), AT_LOGIN_CUSTOMIZE)
        self.assertEqual(at_login_flags(renamed=False, customize=False), 0)


class ItemFieldTests(unittest.TestCase):
    def test_parses_addon_split_fields(self):
        """The real capture's shape: itemLinkFields, no 'item:' prefix."""
        fields = parse_item_fields(
            {
                "itemId": 6096,
                "itemString": "6096:0:0:0:0:0:0:0:20",
                "itemLinkFields": ["6096", "0", "0", "0", "0", "0", "0", "0", "20"],
            }
        )
        self.assertEqual(fields.item_id, 6096)
        self.assertEqual(fields.enchant_id, 0)
        self.assertEqual(fields.gems, [0, 0, 0, 0])
        self.assertEqual(fields.link_level, 20)

    def test_parses_enchanted_and_gemmed_item(self):
        fields = parse_item_fields(
            {"itemString": "49623:3789:3418:3419:0:0:0:1153415552:80"}
        )
        self.assertEqual(fields.item_id, 49623)
        self.assertEqual(fields.enchant_id, 3789)
        self.assertEqual(fields.gems, [3418, 3419, 0, 0])
        self.assertEqual(fields.unique_id, 1153415552)

    def test_falls_back_to_reparsing_the_link(self):
        fields = parse_item_fields(
            {"itemLink": "|cffa335ee|Hitem:49623:3789:3418:0:0:0:-42:0:80|h[X]|h|r"}
        )
        self.assertEqual(fields.item_id, 49623)
        self.assertEqual(fields.enchant_id, 3789)
        self.assertEqual(fields.suffix_id, -42)

    def test_missing_enchant_key_is_zero_not_a_crash(self):
        """Absent key means nil: the addon drops nil before encoding."""
        fields = parse_item_fields({"itemId": 6096, "itemString": "6096"})
        self.assertEqual(fields.item_id, 6096)
        self.assertEqual(fields.enchant_id, 0)

    def test_gem_ids_used_when_link_fields_absent(self):
        fields = parse_item_fields({"itemId": 100, "gemIds": [41285, 40133]})
        self.assertEqual(fields.gems, [41285, 40133, 0, 0])

    def test_unusable_record_raises(self):
        with self.assertRaises(MappingError):
            parse_item_fields({"name": "Mystery"})


class EnchantmentBlobTests(unittest.TestCase):
    def test_blob_is_36_ints(self):
        blob = enchantments_blob(parse_item_fields({"itemString": "6096"}))
        self.assertEqual(len(blob.split(" ")), 36)
        self.assertEqual(set(blob.split(" ")), {"0"})

    def test_perm_enchant_lands_in_slot_zero(self):
        blob = enchantments_blob(parse_item_fields({"itemString": "1:3789"}))
        values = blob.split(" ")
        self.assertEqual(values[0], "3789")          # PERM_ENCHANTMENT_SLOT id
        self.assertEqual(values[1:3], ["0", "0"])    # duration, charges

    def test_gems_land_in_socket_slots_2_3_4(self):
        blob = enchantments_blob(parse_item_fields({"itemString": "1:0:11:22:33:0"}))
        values = blob.split(" ")
        SOCK = 2 * 3
        self.assertEqual(values[SOCK], "11")
        self.assertEqual(values[SOCK + 3], "22")
        self.assertEqual(values[SOCK + 6], "33")

    def test_fourth_gem_is_the_prismatic_slot(self):
        blob = enchantments_blob(parse_item_fields({"itemString": "1:0:0:0:0:99"}))
        values = blob.split(" ")
        self.assertEqual(values[6 * 3], "99")  # PRISMATIC_ENCHANTMENT_SLOT


class InventoryPlacementTests(unittest.TestCase):
    def test_equipped_slot_is_client_slot_minus_one(self):
        self.assertEqual(equipped_db_slot(1), 0)    # Head
        self.assertEqual(equipped_db_slot(16), 15)  # Main Hand
        self.assertEqual(equipped_db_slot(19), 18)  # Tabard

    def test_equipped_slot_bounds(self):
        for bad in (0, 20, -1, None, "x"):
            with self.assertRaises(MappingError):
                equipped_db_slot(bad)

    def test_backpack_maps_to_slots_23_to_38(self):
        self.assertEqual(split_bag_placement({"bagId": 0, "bagSlot": 1}), (0, 23))
        self.assertEqual(split_bag_placement({"bagId": 0, "bagSlot": 16}), (0, 38))

    def test_backpack_overflow_raises(self):
        with self.assertRaises(MappingError):
            split_bag_placement({"bagId": 0, "bagSlot": 17})

    def test_keyring_maps_to_slots_86_to_117(self):
        """The addon scans container -2 (Core.lua:1260); it is not a real bag."""
        self.assertEqual(split_bag_placement({"bagId": -2, "bagSlot": 1}), (0, 86))
        self.assertEqual(split_bag_placement({"bagId": -2, "bagSlot": 32}), (0, 117))
        with self.assertRaises(MappingError):
            split_bag_placement({"bagId": -2, "bagSlot": 33})

    def test_equipped_bag_contents_are_zero_indexed(self):
        self.assertEqual(split_bag_placement({"bagId": 2, "bagSlot": 1}), (2, 0))
        self.assertEqual(split_bag_placement({"bagId": 4, "bagSlot": 20}), (4, 19))

    def test_bag_containers_occupy_slots_19_to_22(self):
        self.assertEqual(equipped_bag_db_slot(1), 19)
        self.assertEqual(equipped_bag_db_slot(4), 22)
        with self.assertRaises(MappingError):
            equipped_bag_db_slot(5)

    def test_unsupported_bag_raises(self):
        with self.assertRaises(MappingError):
            split_bag_placement({"bagId": 9, "bagSlot": 1})
        with self.assertRaises(MappingError):
            split_bag_placement({"bagId": 0})


class MoneyTests(unittest.TestCase):
    def test_split(self):
        self.assertEqual(money_parts(4516), (0, 45, 16))
        self.assertEqual(money_parts(12_345_678), (1234, 56, 78))
        self.assertEqual(money_parts(0), (0, 0, 0))
        self.assertEqual(money_parts(None), (0, 0, 0))
        self.assertEqual(money_parts(-5), (0, 0, 0))


# Point this at your own WTF/Account/<NAME>/SavedVariables/BindMySoul.lua to
# check the mapping against a real capture. None is committed: it is a record of
# somebody's character.
REAL_CAPTURE = os.environ.get("BMS_TEST_CAPTURE", "")


@unittest.skipUnless(os.path.isfile(REAL_CAPTURE),
                     "set $BMS_TEST_CAPTURE to a BindMySoul.lua to run these")
class RealCaptureMappingTests(unittest.TestCase):
    """Every item in a real checkpoint must map without an exception."""

    @classmethod
    def setUpClass(cls):
        from bms_parse import extract_checkpoint_codes, load_savedvariables, parse_checkpoint

        db = load_savedvariables(REAL_CAPTURE)
        cls.checkpoint = parse_checkpoint(extract_checkpoint_codes(db)[0])

    def test_identity_maps(self):
        char = self.checkpoint.character
        self.assertIsInstance(race_id(char["raceToken"]), int)
        self.assertIsInstance(class_id(char["classToken"]), int)
        self.assertIn(gender_id(char["sexId"]), (0, 1))

    def test_every_equipped_item_maps(self):
        for item in self.checkpoint.character.get("equipment", []):
            fields = parse_item_fields(item)
            self.assertGreater(fields.item_id, 0)
            self.assertEqual(len(enchantments_blob(fields).split(" ")), 36)
            self.assertIn(equipped_db_slot(item["slotId"]), range(0, 19))

    def test_every_bag_item_maps(self):
        for item in self.checkpoint.character.get("bags", []):
            fields = parse_item_fields(item)
            self.assertGreater(fields.item_id, 0)
            bag, slot = split_bag_placement(item)
            self.assertIn(bag, range(0, 5))
            self.assertGreaterEqual(slot, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
