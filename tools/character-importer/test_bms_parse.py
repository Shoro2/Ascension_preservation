#!/usr/bin/env python3
"""Round-trip tests for bms_parse.

No real BindMySoul.lua exists yet, so these build fixtures the same way the
addon and the WoW client would: JSON encoded with the addon's deterministic
rules (sorted keys, compact separators, only control characters escaped),
wrapped in the BMSP envelope, then written into a SavedVariables file using
the client's own string escaping.

Run:  python test_bms_parse.py
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from bms_parse import (  # noqa: E402
    BmsError,
    capability_map,
    extract_checkpoint_codes,
    load_savedvariables,
    parse_checkpoint,
    parse_lua,
    percent_decode,
    summarize,
)

# An Ascension item link: pipe-delimited, with a bracketed name. This is the
# shape most likely to break a naive line- or pipe-based reader.
ITEM_LINK = (
    "|cffa335ee|Hitem:49623:3789:3418:3418:0:0:0:1153415552:80:0"
    "|h[Shadowmourne]|h|r"
)


def addon_json(value) -> str:
    """Match Protocol.jsonEncode: sorted keys, no spaces, non-ASCII kept raw."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def lua_quote(value: str) -> str:
    """Escape a string the way the WoW client writes SavedVariables."""
    out = []
    for char in value:
        if char == "\\":
            out.append("\\\\")
        elif char == '"':
            out.append('\\"')
        elif char == "\n":
            out.append("\\n")
        elif char == "\r":
            out.append("\\r")
        elif char == "\t":
            out.append("\\t")
        elif ord(char) < 32:
            out.append(f"\\{ord(char)}")
        else:
            out.append(char)
    return '"' + "".join(out) + '"'


def make_checkpoint(
    name: str = "Reeks",
    realm: str = "Rexxar - Conquest of Azeroth",
    sealed_at: int = 1_757_000_000,
    sequence: int = 7,
    percentage: int = 84,
) -> dict:
    return {
        "schema": "bind-my-soul/preservation-checkpoint",
        "version": 2,
        "standard": "bms-character-v2",
        "addonVersion": "1.3.5",
        "sealedAt": sealed_at,
        "localSequence": sequence,
        "integrity": {
            "serialization": "deterministic-json-v1",
            "hashAlgorithm": "sha256",
            "sealStatus": "pending-companion-hash",
            "evidenceLevel": "client-observed",
        },
        "character": {
            "key": "rexxar-conquest-of-azeroth:0x0000000000ABCDEF",
            "name": name,
            "realmName": realm,
            "realmSlug": "rexxar-conquest-of-azeroth",
            "guid": "0x0000000000ABCDEF",
            "className": "Tinker",
            "classToken": "HERO",
            "raceName": "Blood Elf",
            "faction": "Horde",
            "level": 80,
            "money": 12_345_678,
            "gameMode": {
                "id": "conquest-of-azeroth",
                "label": "Conquest of Azeroth",
                "source": "C_CharacterAdvancement active specialization plus UnitClass",
                "activeSpecializationId": 28,
            },
            "equipment": [
                {
                    "location": "equipped",
                    "slotId": 16,
                    "slotName": "Main Hand",
                    "itemId": 49623,
                    "itemLink": ITEM_LINK,
                    "itemString": "item:49623:3789:3418:3418:0:0:0:1153415552:80:0",
                    "name": "Shadowmourne",
                    "quality": 4,
                    "itemLevel": 284,
                    "enchantId": 3789,
                    "gemIds": [3418, 3418],
                    "tooltipLines": [
                        "Shadowmourne",
                        "Binds when picked up",
                        'Chance on hit: "Soul" fragment  \\ backslash + quote test',
                    ],
                }
            ],
            "bags": [],
            "knownSpellIds": [133, 116, 30451],
            "knownMysticSpellIds": [],
            "appliedMysticSpellIds": [],
            "currencies": [],
            "skills": [],
            "reputations": [
                {
                    "rowIndex": 1,
                    "identityStatus": "name-and-row-index-no-client-faction-id",
                    "name": "Argent Crusade",
                    "standingId": 7,
                    "value": 20999,
                }
            ],
            "quests": {"active": [], "completedIds": [8342, 9001], "historyAvailable": True},
            "titles": {"known": []},
            "actionBars": {
                "schema": "bind-my-soul/action-bar-layout",
                "version": 1,
                "slotCount": 120,
                "occupied": [
                    {"slot": 1, "actionType": "spell", "actionId": 133, "spellId": 133}
                ],
                "captureComplete": True,
            },
            "achievements": {"completed": [], "inProgress": []},
            "professionRecipes": {"catalogs": []},
            # The addon builds this with table.insert, so it serialises as an
            # ARRAY of records carrying their own "key" -- not as an object.
            # Confirmed against a real capture (Core.lua:228).
            "capabilities": [
                {
                    "key": "equipment",
                    "available": True,
                    "sourceApi": "GetInventoryItemLink",
                    "note": "1 item(s); 0 missing structured stats.",
                },
                {
                    "key": "mysticCollection",
                    "available": False,
                    "sourceApi": "C_MysticEnchant.QueryEnchants",
                    "note": "Mystic collection API is unavailable.",
                },
                {
                    "key": "advancement",
                    "available": False,
                    "sourceApi": "C_CharacterAdvancement",
                    "note": "The realm-specific advancement API is unavailable.",
                },
            ],
        },
        "sharedStorage": {"realmSlug": "rexxar-conquest-of-azeroth", "vaults": []},
        "coverage": {
            "standard": "bms-character-v2",
            "percentage": percentage,
            "completed": 11,
            "total": 13,
            "complete": False,
            "domains": [
                {"id": "identity", "label": "Character identity", "status": "fresh",
                 "required": True},
                {"id": "mystics", "label": "Mystic collection", "status": "unavailable",
                 "required": True},
                {"id": "mail", "label": "Mailbox", "status": "missing", "required": False},
            ],
        },
    }


def envelope(checkpoint: dict) -> str:
    return f"BMSP2|g={checkpoint['sealedAt']}|j=" + addon_json(checkpoint)


def legacy_envelope(checkpoint: dict) -> str:
    """A BMSP1 code: percent-encoded payload, v1 schema and standard."""
    legacy = json.loads(json.dumps(checkpoint))
    legacy["version"] = 1
    legacy["standard"] = "bms-character-v1"
    legacy["coverage"]["standard"] = "bms-character-v1"
    payload = addon_json(legacy)
    encoded = "".join(
        char if (char.isalnum() and char.isascii()) or char in "-_." else
        "".join(f"%{byte:02X}" for byte in char.encode("utf-8"))
        for char in payload
    )
    return f"BMSP1|g={legacy['sealedAt']}|d=" + encoded


def savedvariables(latest: str, history: list[str] | None = None) -> str:
    """Write a SavedVariables file shaped like the client's own output."""
    history = history or []
    lines = [
        "\nBindMySoulDB = {",
        '\t["schema"] = 6,',
        '\t["version"] = "1.3.5",',
        '\t["checkpointExport"] = ' + lua_quote(latest) + ",",
    ]
    if history:
        lines.append(
            '\t["checkpointQueueExport"] = ' + lua_quote("\n".join(history)) + ","
        )
    lines += [
        '\t["settings"] = {',
        '\t\t["window"] = {',
        '\t\t\t["width"] = 760,',
        '\t\t\t["height"] = 680,',
        '\t\t\t["point"] = "CENTER",',
        "\t\t},",
        "\t},",
        '\t["checkpointHistory"] = {',
        "\t\t{",
        '\t\t\t["sealedAt"] = 1757000000,',
        '\t\t\t["characterName"] = "Reeks",',
        '\t\t\t["percentage"] = 84,',
        '\t\t\t["complete"] = false,',
        "\t\t},",
        "\t},",
        '\t["characters"] = {',
        "\t},",
        "}\n",
    ]
    return "\n".join(lines)


class LuaParserTests(unittest.TestCase):
    def test_scalars_and_nesting(self):
        parsed = parse_lua(
            'A = {\n'
            '  ["s"] = "text",\n'
            '  ["n"] = -12.5,\n'
            '  ["hex"] = 0x1F,\n'
            '  ["exp"] = 1e3,\n'
            '  ["t"] = true,\n'
            '  ["f"] = false,\n'
            '  ["z"] = nil,\n'
            '  ["nested"] = { ["deep"] = { ["deeper"] = 1 } },\n'
            '}\n'
        )
        a = parsed["A"]
        self.assertEqual(a["s"], "text")
        self.assertEqual(a["n"], -12.5)
        self.assertEqual(a["hex"], 31)
        self.assertEqual(a["exp"], 1000.0)
        self.assertIs(a["t"], True)
        self.assertIs(a["f"], False)
        self.assertIsNone(a["z"])
        self.assertEqual(a["nested"]["deep"]["deeper"], 1)

    def test_string_escapes(self):
        parsed = parse_lua(
            'A = { ["v"] = "quote:\\" back:\\\\ nl:\\n tab:\\t dec:\\65 pipe:| brace:} " }'
        )
        self.assertEqual(parsed["A"]["v"], 'quote:" back:\\ nl:\n tab:\t dec:A pipe:| brace:} ')

    def test_arrayify_and_mixed_keys(self):
        parsed = parse_lua('A = { [1] = "x", [2] = "y", [3] = "z" }\nB = { [2] = "gap" }\n')
        self.assertEqual(parsed["A"], ["x", "y", "z"])
        self.assertEqual(parsed["B"], {2: "gap"})

    def test_positional_and_comments(self):
        parsed = parse_lua('-- leading comment\nA = { "one", "two" } -- trailing\n')
        self.assertEqual(parsed["A"], ["one", "two"])

    def test_rejects_garbage(self):
        with self.assertRaises(BmsError):
            parse_lua("A = {")


class EnvelopeTests(unittest.TestCase):
    def test_round_trip(self):
        source = make_checkpoint()
        parsed = parse_checkpoint(envelope(source))
        self.assertEqual(parsed.prefix, "BMSP2")
        self.assertEqual(parsed.version, 2)
        self.assertEqual(parsed.sealed_at, source["sealedAt"])
        self.assertEqual(parsed.data, source)
        self.assertEqual(parsed.name, "Reeks")
        self.assertEqual(parsed.character["equipment"][0]["itemLink"], ITEM_LINK)

    def test_legacy_bmsp1(self):
        parsed = parse_checkpoint(legacy_envelope(make_checkpoint()))
        self.assertEqual(parsed.prefix, "BMSP1")
        self.assertEqual(parsed.version, 1)
        self.assertEqual(parsed.coverage["standard"], "bms-character-v1")

    def test_bmsp2_rejects_legacy_encoding(self):
        code = envelope(make_checkpoint()).replace("|j=", "|d=", 1)
        with self.assertRaisesRegex(BmsError, "cannot use encoding"):
            parse_checkpoint(code)

    def test_envelope_timestamp_must_match_payload(self):
        source = make_checkpoint()
        code = f"BMSP2|g={source['sealedAt'] + 1}|j=" + addon_json(source)
        with self.assertRaisesRegex(BmsError, "does not match"):
            parse_checkpoint(code)

    def test_schema_and_identity_and_coverage_checks(self):
        bad_schema = make_checkpoint()
        bad_schema["schema"] = "something-else"
        with self.assertRaisesRegex(BmsError, "schema is not supported"):
            parse_checkpoint(envelope(bad_schema))

        blank_name = make_checkpoint()
        blank_name["character"]["name"] = "   "
        with self.assertRaisesRegex(BmsError, "identity is incomplete"):
            parse_checkpoint(envelope(blank_name))

        bad_coverage = make_checkpoint()
        bad_coverage["coverage"]["standard"] = "bms-character-v1"
        with self.assertRaisesRegex(BmsError, "coverage record is incomplete"):
            parse_checkpoint(envelope(bad_coverage))

    def test_not_a_checkpoint(self):
        for junk in ("", "hello", "BMSP2|g=abc|j={}", "BMSP9|g=1|j={}"):
            with self.assertRaises(BmsError):
                parse_checkpoint(junk)

    def test_percent_decode_matches_addon_strictness(self):
        self.assertEqual(percent_decode("a%20b"), "a b")
        with self.assertRaises(BmsError):
            percent_decode("100%")


class SavedVariablesTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="bms-test-")

    def _write(self, text: str, name: str = "BindMySoul.lua") -> str:
        path = os.path.join(self.dir, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
        return path

    def test_extracts_latest_and_history_in_order(self):
        latest = envelope(make_checkpoint(sealed_at=1_757_000_300, sequence=9))
        older = [
            envelope(make_checkpoint(sealed_at=1_757_000_200, sequence=8)),
            envelope(make_checkpoint(sealed_at=1_757_000_100, sequence=7)),
        ]
        path = self._write(savedvariables(latest, older))
        db = load_savedvariables(path)

        self.assertEqual(db["schema"], 6)
        self.assertEqual(db["checkpointHistory"][0]["characterName"], "Reeks")
        self.assertIs(db["checkpointHistory"][0]["complete"], False)

        codes = extract_checkpoint_codes(db)
        self.assertEqual(len(codes), 3)
        sealed = [parse_checkpoint(code).sealed_at for code in codes]
        self.assertEqual(sealed, [1_757_000_300, 1_757_000_200, 1_757_000_100])

    def test_deduplicates_repeated_codes(self):
        code = envelope(make_checkpoint())
        db = load_savedvariables(self._write(savedvariables(code, [code, code])))
        self.assertEqual(len(extract_checkpoint_codes(db)), 1)

    def test_reads_legacy_checkpoint_queue_table(self):
        latest = envelope(make_checkpoint(sealed_at=1_757_000_300))
        old = envelope(make_checkpoint(sealed_at=1_757_000_100))
        text = (
            "\nBindMySoulDB = {\n"
            '\t["checkpointExport"] = ' + lua_quote(latest) + ",\n"
            '\t["checkpointQueue"] = {\n'
            "\t\t[1] = " + lua_quote(old) + ",\n"
            "\t},\n"
            "}\n"
        )
        db = load_savedvariables(self._write(text))
        self.assertEqual(len(extract_checkpoint_codes(db)), 2)

    def test_unicode_character_name_survives(self):
        code = envelope(make_checkpoint(name="Sylvänas", realm="Rexxar - Conquête"))
        db = load_savedvariables(self._write(savedvariables(code)))
        parsed = parse_checkpoint(extract_checkpoint_codes(db)[0])
        self.assertEqual(parsed.name, "Sylvänas")
        self.assertEqual(parsed.realm, "Rexxar - Conquête")

    def test_item_link_survives_both_escape_layers(self):
        code = envelope(make_checkpoint())
        db = load_savedvariables(self._write(savedvariables(code)))
        parsed = parse_checkpoint(extract_checkpoint_codes(db)[0])
        item = parsed.character["equipment"][0]
        self.assertEqual(item["itemLink"], ITEM_LINK)
        self.assertIn("\\ backslash + quote test", item["tooltipLines"][2])
        self.assertEqual(item["gemIds"], [3418, 3418])

    def test_missing_global_is_reported(self):
        path = self._write('SomeOtherDB = { ["a"] = 1 }\n')
        with self.assertRaisesRegex(BmsError, "expected BindMySoulDB"):
            load_savedvariables(path)

    def test_empty_database_yields_no_codes(self):
        db = load_savedvariables(self._write("BindMySoulDB = {}\n"))
        self.assertEqual(extract_checkpoint_codes(db), [])

    def test_summary_renders(self):
        parsed = parse_checkpoint(envelope(make_checkpoint()))
        text = summarize(parsed)
        self.assertIn("Reeks", text)
        self.assertIn("Conquest of Azeroth", text)
        self.assertIn("1,234g 56s 78c", text)
        self.assertIn("84%", text)
        # Unavailable Ascension APIs must be surfaced, not silently dropped.
        self.assertIn("mysticCollection", text)
        self.assertIn("advancement", text)
        self.assertIn("Mystic collection API is unavailable.", text)


class CapabilityTests(unittest.TestCase):
    def test_array_form_is_keyed(self):
        """The real, shipped form: an array of records carrying their own key."""
        char = {
            "capabilities": [
                {"key": "titles", "available": True, "note": "190 known titles observed."},
                {"key": "mysticCollection", "available": False, "note": "unavailable"},
            ]
        }
        mapped = capability_map(char)
        self.assertEqual(set(mapped), {"titles", "mysticCollection"})
        self.assertIs(mapped["titles"]["available"], True)
        self.assertIs(mapped["mysticCollection"]["available"], False)

    def test_object_form_still_accepted(self):
        mapped = capability_map({"capabilities": {"titles": {"available": True}}})
        self.assertEqual(mapped["titles"]["key"], "titles")
        self.assertIs(mapped["titles"]["available"], True)

    def test_missing_or_junk_is_empty(self):
        self.assertEqual(capability_map({}), {})
        self.assertEqual(capability_map({"capabilities": "nonsense"}), {})
        self.assertEqual(capability_map({"capabilities": [{"available": True}]}), {})

    def test_explicit_counts_win_over_bounded_arrays(self):
        """achievements.completedCount is authoritative over a truncated array."""
        source = make_checkpoint()
        source["character"]["achievements"] = {
            "completed": [1, 2],
            "completedCount": 91,
            "inProgress": [],
        }
        text = summarize(parse_checkpoint(envelope(source)))
        self.assertIn("achievements done      91", text)


# Point this at your own WTF/Account/<NAME>/SavedVariables/BindMySoul.lua to
# run the parser against a real capture. None is committed: it is a record of
# somebody's character.
REAL_CAPTURE = os.environ.get("BMS_TEST_CAPTURE", "")


@unittest.skipUnless(os.path.isfile(REAL_CAPTURE),
                     "set $BMS_TEST_CAPTURE to a BindMySoul.lua to run these")
class RealCaptureTests(unittest.TestCase):
    """Regression guard against an actual addon-produced file."""

    @classmethod
    def setUpClass(cls):
        db = load_savedvariables(REAL_CAPTURE)
        cls.codes = extract_checkpoint_codes(db)
        cls.checkpoint = parse_checkpoint(cls.codes[0])

    def test_parses_and_validates(self):
        self.assertTrue(self.codes)
        self.assertEqual(self.checkpoint.prefix, "BMSP2")
        self.assertTrue(self.checkpoint.name)
        self.assertTrue(self.checkpoint.realm)

    def test_capabilities_are_readable(self):
        caps = self.checkpoint.capabilities
        self.assertTrue(caps, "real capture must expose capability records")
        self.assertIn("equipment", caps)

    def test_item_links_round_trip(self):
        for item in self.checkpoint.character.get("equipment", []):
            link = item.get("itemLink", "")
            if link:
                self.assertTrue(link.startswith("|c"), link[:40])
                self.assertIn("|Hitem:", link)
                self.assertTrue(link.endswith("|h|r"), link[-20:])

    def test_summary_does_not_crash(self):
        self.assertIn(self.checkpoint.name, summarize(self.checkpoint))


if __name__ == "__main__":
    unittest.main(verbosity=2)
