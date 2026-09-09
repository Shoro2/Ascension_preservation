#!/usr/bin/env python3
"""Tests for importer logic that needs no database.

Run:  python test_bms_import.py
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from bms_import import (  # noqa: E402
    EQUIPMENT_CACHE_MAX,
    EQUIPMENT_CACHE_SIZE,
    Plan,
    _captured_durability,
    _durability,
    _equipment_cache,
    equipment_cache_width,
    resolve_settings,
)


class FakeConn:
    """Answers exactly the one SELECT equipment_cache_width() issues."""

    def __init__(self, caches):
        self.caches = caches

    def cursor(self, *_args, **_kwargs):
        return FakeCursor(self.caches)


class FakeCursor:
    def __init__(self, caches):
        self.caches = caches

    def execute(self, *_args, **_kwargs):
        return None

    def fetchall(self):
        return [{"equipmentCache": c} for c in self.caches]

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False


def width_of(caches):
    args = argparse.Namespace(characters_db="chars")
    return equipment_cache_width(FakeConn(caches), args)


def plan_with(items):
    """items: (inventory slot, item entry, perm enchant id)."""
    plan = Plan(guid=7)
    for index, (slot, entry, enchant) in enumerate(items, start=100):
        blob = [0] * 36
        blob[0] = enchant
        plan.add("item_instance", {
            "guid": index,
            "itemEntry": entry,
            "owner_guid": plan.guid,
            "enchantments": " ".join(str(v) for v in blob),
        })
        plan.add("character_inventory", {
            "guid": plan.guid, "bag": 0, "slot": slot, "item": index,
        })
    return plan


class EquipmentCacheTests(unittest.TestCase):
    """characters.equipmentCache is what the character-select screen renders.

    An empty cache shows a fully equipped character as naked in the list, which
    is exactly the bug this function was written to fix.
    """

    def test_shape_is_always_38_values(self):
        for plan in (Plan(guid=1), plan_with([(0, 100, 0)])):
            self.assertEqual(len(_equipment_cache(plan).split()), EQUIPMENT_CACHE_SIZE)

    def test_a_character_with_nothing_equipped_is_all_zeros(self):
        self.assertEqual(set(_equipment_cache(Plan(guid=1)).split()), {"0"})

    def test_entry_lands_at_slot_times_two(self):
        values = _equipment_cache(plan_with([(3, 6096, 0), (15, 35, 0)])).split()
        self.assertEqual(values[3 * 2], "6096")
        self.assertEqual(values[15 * 2], "35")
        self.assertEqual(values[0], "0")

    def test_permanent_enchant_lands_beside_its_item(self):
        values = _equipment_cache(plan_with([(16, 49623, 3789)])).split()
        self.assertEqual(values[16 * 2], "49623")
        self.assertEqual(values[16 * 2 + 1], "3789")

    def test_backpack_and_bank_items_are_excluded(self):
        """Only slots below EQUIPMENT_SLOT_END are visible on the login screen."""
        values = _equipment_cache(
            plan_with([(0, 111, 0), (23, 2070, 0), (38, 159, 0), (86, 5, 0)])).split()
        self.assertEqual(values[0], "111")
        self.assertEqual([v for v in values if v != "0"], ["111"])

    def test_an_inventory_row_with_no_item_instance_is_skipped(self):
        """A dangling reference must not crash the build, nor invent an entry."""
        plan = plan_with([(3, 6096, 0)])
        plan.add("character_inventory", {"guid": 7, "bag": 0, "slot": 4, "item": 999})
        values = _equipment_cache(plan).split()
        self.assertEqual(values[3 * 2], "6096")
        self.assertEqual(values[4 * 2], "0")

    def test_an_item_with_no_enchantment_blob_is_tolerated(self):
        plan = Plan(guid=7)
        plan.add("item_instance", {"guid": 1, "itemEntry": 42, "enchantments": ""})
        plan.add("character_inventory", {"guid": 7, "bag": 0, "slot": 2, "item": 1})
        values = _equipment_cache(plan).split()
        self.assertEqual(values[2 * 2], "42")
        self.assertEqual(values[2 * 2 + 1], "0")

    def test_it_matches_the_real_capture_that_exposed_the_bug(self):
        """Probethree's five equipped items, as committed to the live realm."""
        real = [(3, 6096, 0), (4, 56, 0), (6, 1395, 0), (7, 55, 0), (15, 35, 0)]
        values = _equipment_cache(plan_with(real)).split()
        self.assertEqual(
            [(i // 2, values[i]) for i in range(0, len(values), 2) if values[i] != "0"],
            [(3, "6096"), (4, "56"), (6, "1395"), (7, "55"), (15, "35")])


class CacheWidthTests(unittest.TestCase):
    """The cache width is a property of the target fork, not a constant.

    Stock is 19 slots (38 values); the Ascension realm this was built against
    writes 23 slots (46). The core reads the blob as fixed-size pairs, so a
    short cache is read out of alignment.
    """

    STOCK = " ".join(["0"] * 38)
    FORK = " ".join(["0"] * 46)

    def test_a_stock_realm_reports_38(self):
        self.assertEqual(width_of([self.STOCK, self.STOCK]), 38)

    def test_a_wider_fork_is_detected(self):
        self.assertEqual(width_of([self.FORK, self.FORK, self.FORK]), 46)

    def test_an_empty_realm_falls_back_to_stock(self):
        self.assertEqual(width_of([]), EQUIPMENT_CACHE_SIZE)

    def test_our_own_short_row_does_not_win_a_tie(self):
        """The bug wrote 38 onto a 46-slot realm; a tie must not preserve it."""
        self.assertEqual(width_of([self.STOCK, self.FORK]), 46)

    def test_the_majority_wins_outright(self):
        self.assertEqual(width_of([self.STOCK, self.STOCK, self.STOCK, self.FORK]), 38)

    def test_junk_rows_are_ignored(self):
        for junk in ("", "   ", None, "0 0 0", " ".join(["0"] * 39),
                     " ".join(["0"] * (EQUIPMENT_CACHE_MAX + 2))):
            self.assertEqual(width_of([junk, self.FORK]), 46)

    def test_all_junk_falls_back_rather_than_crashing(self):
        self.assertEqual(width_of(["", "0 0 0", None]), EQUIPMENT_CACHE_SIZE)

    def test_the_blob_is_built_at_the_detected_width(self):
        values = _equipment_cache(plan_with([(4, 56, 0)]), 46)
        self.assertEqual(len(values.split()), 46)
        self.assertEqual(values.split()[4 * 2], "56")

    def test_bag_slots_never_enter_a_wider_cache(self):
        """Slots 19-22 are bag slots on a stock core; width must not admit them."""
        values = _equipment_cache(plan_with([(15, 35, 0), (19, 4498, 0)]), 46).split()
        self.assertEqual(values[15 * 2], "35")
        self.assertEqual([v for v in values if v != "0"], ["35"])


class ResolveSettingsTests(unittest.TestCase):
    """Flag beats environment beats server config beats stock default.

    This decides which realm gets written to, so the ordering is not cosmetic.
    """

    SECRET = "config-side-password"
    CONF = """
LoginDatabaseInfo     = "10.0.0.1;3307;cfguser;{secret};cfg_auth"
WorldDatabaseInfo     = "10.0.0.1;3307;cfguser;{secret};cfg_world"
CharacterDatabaseInfo = "10.0.0.1;3307;cfguser;{secret};cfg_characters"
DataDir = "{data}"
"""

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="bms-resolve-")
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        os.makedirs(os.path.join(self.root, "Data", "dbc"))
        self.conf = os.path.join(self.root, "worldserver.conf")
        with open(self.conf, "w", encoding="utf-8") as handle:
            handle.write(self.CONF.format(
                secret=self.SECRET,
                data=os.path.join(self.root, "Data").replace("\\", "/")))
        for variable in ("BMS_DB_HOST", "BMS_DB_PORT", "BMS_DB_USER", "BMS_AUTH_DB",
                         "BMS_CHARACTERS_DB", "BMS_WORLD_DB", "BMS_DBC_DIR",
                         "BMS_DB_PASSWORD", "BMS_SERVER_CONFIG"):
            os.environ.pop(variable, None)

    def args(self, **overrides):
        base = dict(config=self.conf, no_config=False, host=None, port=None,
                    user=None, password=None, password_env="BMS_DB_PASSWORD",
                    auth_db=None, characters_db=None, world_db=None, dbc_dir=None)
        base.update(overrides)
        return argparse.Namespace(**base)

    def origins(self, rows):
        return {name: origin for name, _value, origin in rows}

    def test_a_config_supplies_everything(self):
        args = self.args()
        rows = resolve_settings(args)
        self.assertEqual(args.host, "10.0.0.1")
        self.assertEqual(args.port, 3307)
        self.assertEqual(args.user, "cfguser")
        self.assertEqual(args.characters_db, "cfg_characters")
        self.assertEqual(args.world_db, "cfg_world")
        self.assertEqual(args.auth_db, "cfg_auth")
        self.assertTrue(args.dbc_dir.endswith("dbc"))
        self.assertEqual(set(self.origins(rows).values()), {"config"})

    def test_the_password_comes_from_the_config_when_nothing_else_has_one(self):
        """This is what removes the last required environment variable."""
        args = self.args()
        resolve_settings(args)
        self.assertEqual(args.password, self.SECRET)
        self.assertEqual(args.password_origin, "config")

    def test_an_explicit_flag_beats_the_config(self):
        args = self.args(characters_db="mine", host="192.168.0.5")
        rows = self.origins(resolve_settings(args))
        self.assertEqual(args.characters_db, "mine")
        self.assertEqual(args.host, "192.168.0.5")
        self.assertEqual(rows["characters_db"], "--characters-db")
        self.assertEqual(rows["world_db"], "config")

    def test_the_environment_beats_the_config(self):
        os.environ["BMS_CHARACTERS_DB"] = "env_characters"
        self.addCleanup(os.environ.pop, "BMS_CHARACTERS_DB", None)
        args = self.args()
        rows = self.origins(resolve_settings(args))
        self.assertEqual(args.characters_db, "env_characters")
        self.assertEqual(rows["characters_db"], "$BMS_CHARACTERS_DB")

    def test_an_environment_password_beats_the_config(self):
        os.environ["BMS_DB_PASSWORD"] = "from-env"
        self.addCleanup(os.environ.pop, "BMS_DB_PASSWORD", None)
        args = self.args()
        resolve_settings(args)
        self.assertIsNone(args.password, "connect() reads the variable itself")
        self.assertEqual(args.password_origin, "$BMS_DB_PASSWORD")

    def test_an_explicit_password_beats_everything(self):
        os.environ["BMS_DB_PASSWORD"] = "from-env"
        self.addCleanup(os.environ.pop, "BMS_DB_PASSWORD", None)
        args = self.args(password="from-flag")
        resolve_settings(args)
        self.assertEqual(args.password, "from-flag")
        self.assertEqual(args.password_origin, "--password")

    def test_no_config_falls_back_to_stock_defaults(self):
        args = self.args(config=None, no_config=True)
        rows = self.origins(resolve_settings(args))
        self.assertEqual(args.characters_db, "acore_characters")
        self.assertEqual(args.host, "127.0.0.1")
        self.assertEqual(args.port, 3306)
        self.assertEqual(rows["characters_db"], "default")
        self.assertIsNone(args.config_path)
        self.assertEqual(args.password_origin, "not set")

    def test_a_port_from_the_environment_is_still_an_integer(self):
        os.environ["BMS_DB_PORT"] = "3399"
        self.addCleanup(os.environ.pop, "BMS_DB_PORT", None)
        args = self.args(config=None, no_config=True)
        resolve_settings(args)
        self.assertEqual(args.port, 3399)
        self.assertIsInstance(args.port, int)

    def test_more_than_one_config_is_refused_rather_than_guessed(self):
        """Importing into the wrong realm is worse than asking."""
        for name in ("realm-a", "realm-b"):
            configs = os.path.join(self.root, name, "configs")
            os.makedirs(configs)
            shutil.copy(self.conf, os.path.join(configs, "worldserver.conf"))
        args = self.args(config=None)
        with self.assertRaises(Exception) as caught:
            resolve_settings(args, start=self.root)
        message = str(caught.exception)
        self.assertIn("realm-a", message)
        self.assertIn("realm-b", message)
        self.assertIn("--config", message)

    def test_the_reported_rows_never_carry_the_password(self):
        rows = resolve_settings(self.args())
        self.assertNotIn(self.SECRET, "\n".join("%s %s %s" % r for r in rows))


class DurabilityTests(unittest.TestCase):
    """The addon nests durability; reading a flat key imported everything broken."""

    ROBE = {"name": "Apprentice's Robe", "durability": {"current": 35, "maximum": 35}}
    WORN = {"name": "Bent Staff", "durability": {"current": 7, "maximum": 25}}
    SHIRT = {"name": "Apprentice's Shirt"}          # no durability key at all

    def test_captured_current_is_used(self):
        self.assertEqual(_durability(self.WORN, 25), 7)

    def test_a_full_item_stays_full(self):
        self.assertEqual(_durability(self.ROBE, 35), 35)

    def test_an_uncaptured_item_defaults_to_full_not_broken(self):
        """0 would mean broken gear, which is the one state we know it was not in."""
        self.assertEqual(_durability(self.SHIRT, 55), 55)

    def test_an_item_with_no_durability_stays_zero(self):
        """Shirts and food have MaxDurability 0, so the clamp lands on 0 naturally."""
        self.assertEqual(_durability(self.SHIRT, 0), 0)
        self.assertEqual(_durability({"name": "Hearthstone"}, 0), 0)

    def test_capture_is_clamped_to_the_target_template(self):
        """A fork with a lower MaxDurability must not receive an over-value."""
        self.assertEqual(_durability({"durability": {"current": 999}}, 25), 25)

    def test_the_old_flat_key_is_not_honoured(self):
        """durabilityCurrent never existed; treating it as data would mask the bug."""
        self.assertEqual(_durability({"durabilityCurrent": 12}, 40), 40)

    def test_junk_values_fall_back_rather_than_crash(self):
        for junk in ({"durability": "35"}, {"durability": {"current": "x"}},
                     {"durability": {"current": None}}, {"durability": []}):
            self.assertEqual(_durability(junk, 30), 30)

    def test_negative_capture_is_floored(self):
        self.assertEqual(_durability({"durability": {"current": -5}}, 30), 0)

    def test_captured_durability_reads_both_fields(self):
        self.assertEqual(_captured_durability(self.WORN, "current"), 7)
        self.assertEqual(_captured_durability(self.WORN, "maximum"), 25)
        self.assertIsNone(_captured_durability(self.SHIRT, "current"))

    def test_the_real_capture_that_exposed_the_bug(self):
        """Probethree's five equipped items, with the templates the realm holds."""
        real = [({"durability": {"current": 35, "maximum": 35}}, 35, 35),   # Robe
                ({"durability": {"current": 25, "maximum": 25}}, 25, 25),   # Pants
                ({"durability": {"current": 25, "maximum": 25}}, 25, 25),   # Bent Staff
                ({}, 0, 0),                                                   # Shirt
                ({}, 30, 30)]                                                 # Boots
        for record, template_max, expected in real:
            self.assertEqual(_durability(record, template_max), expected)


if __name__ == "__main__":
    unittest.main(verbosity=2)
