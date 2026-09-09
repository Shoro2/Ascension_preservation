"""Tests for the WDBC reader.

Fixtures are built in memory rather than read from a real DBC: the point of
these is the byte-level contract, and a real DBC would make the suite depend on
which server happens to be installed.
"""

import os
import struct
import tempfile
import unittest

import bms_dbc
from bms_dbc import DBC, DbcError, dbc_header


def write_dbc(path, rows, strings, fields=None):
    """A minimal well-formed WDBC.

    `rows` is a list of int tuples, `strings` the raw string block exactly as
    the caller wants it laid out -- including whether it starts with a NUL,
    which is the whole subject of several tests below.
    """
    fields = fields if fields is not None else (len(rows[0]) if rows else 1)
    record_size = fields * 4
    head = struct.pack("<4sIIII", b"WDBC", len(rows), fields, record_size, len(strings))
    body = b"".join(struct.pack("<%di" % fields, *row) for row in rows)
    with open(path, "wb") as handle:
        handle.write(head + body + strings)
    return path


class DbcFixtureMixin:
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(self._clean)

    def _clean(self):
        for name in os.listdir(self.dir):
            os.unlink(os.path.join(self.dir, name))
        os.rmdir(self.dir)

    def build(self, name, rows, strings, fields=None):
        return write_dbc(os.path.join(self.dir, name), rows, strings, fields)


class StringBlockTests(DbcFixtureMixin, unittest.TestCase):
    def test_offset_zero_returns_the_string_that_is_there(self):
        """Ascension's blocks start with a real string, and a row points at it.

        This is the bug this test exists for: treating offset 0 as "no string"
        drops that row's name, and the importer reports the lookup as an
        unresolved skip rather than as an error.
        """
        strings = b"Fire\x00Frost\x00"
        path = self.build("TalentTab.dbc", [(0,), (5,)], strings)
        dbc = DBC(path)
        self.assertEqual(dbc.s(0, 0), "Fire")
        self.assertEqual(dbc.s(1, 0), "Frost")

    def test_rows_sharing_a_name_share_one_offset(self):
        """String blocks deduplicate, so "one row per file" is not the rule.

        Every row whose name equals the block's first string reads at offset 0.
        Measured on Ascension's Achievement.dbc: ids 3 and 5610 are both
        "Son of a...", and both were blanked by the old special case.
        """
        strings = b"Son of a...\x00Level 10\x00"
        path = self.build("Achievement.dbc", [(0,), (12,), (0,)], strings)
        dbc = DBC(path)
        self.assertEqual(
            [dbc.s(row, 0) for row in range(3)],
            ["Son of a...", "Level 10", "Son of a..."],
        )

    def test_stock_layout_still_reads_offset_zero_as_empty(self):
        """The fix must not change stock behaviour.

        Stock 3.3.5a puts a lone NUL first, so offset 0 is genuinely the empty
        string there -- and it stays empty for the ordinary reason (the byte at
        offset 0 is a terminator), not because of a special case.
        """
        strings = b"\x00PLAYER, Human\x00"
        path = self.build("Faction.dbc", [(0,), (1,)], strings)
        dbc = DBC(path)
        self.assertEqual(dbc.s(0, 0), "")
        self.assertEqual(dbc.s(1, 0), "PLAYER, Human")

    def test_offset_past_the_block_is_empty_not_an_exception(self):
        path = self.build("Faction.dbc", [(9999,)], b"\x00Hi\x00")
        self.assertEqual(DBC(path).s(0, 0), "")

    def test_negative_offset_is_empty(self):
        path = self.build("Faction.dbc", [(-4,)], b"\x00Hi\x00")
        self.assertEqual(DBC(path).s(0, 0), "")

    def test_unterminated_final_string_reads_to_the_end(self):
        path = self.build("Faction.dbc", [(1,)], b"\x00Trailing")
        self.assertEqual(DBC(path).s(0, 0), "Trailing")

    def test_utf8_is_decoded_and_bad_bytes_do_not_raise(self):
        path = self.build("Faction.dbc", [(1,), (7,)], b"\x00Caf\xc3\xa9\x00\xff\xfe\x00")
        dbc = DBC(path)
        self.assertEqual(dbc.s(0, 0), "Café")
        self.assertTrue(dbc.s(1, 0))  # replaced, not an exception


class HeaderTests(DbcFixtureMixin, unittest.TestCase):
    def test_header_reports_counts_without_reading_the_body(self):
        path = self.build("Talent.dbc", [(1, 2), (3, 4), (5, 6)], b"\x00")
        self.assertEqual(dbc_header(path), (3, 2))

    def test_header_of_a_non_dbc_is_none(self):
        path = os.path.join(self.dir, "notes.txt")
        with open(path, "wb") as handle:
            handle.write(b"this is not a DBC at all, really")
        self.assertIsNone(dbc_header(path))

    def test_header_of_a_missing_file_is_none(self):
        self.assertIsNone(dbc_header(os.path.join(self.dir, "absent.dbc")))

    def test_header_of_a_truncated_file_is_none(self):
        path = os.path.join(self.dir, "short.dbc")
        with open(path, "wb") as handle:
            handle.write(b"WDBC\x01")
        self.assertIsNone(dbc_header(path))


class RecordTests(DbcFixtureMixin, unittest.TestCase):
    def test_fields_are_read_by_row_and_column(self):
        path = self.build("Talent.dbc", [(10, 11, 12), (20, 21, 22)], b"\x00")
        dbc = DBC(path)
        self.assertEqual(dbc.i(1, 2), 22)
        self.assertEqual(len(dbc), 2)

    def test_u_reads_a_high_id_as_unsigned(self):
        """Ascension ids run past 2^31, and struct 'i' would make them negative."""
        path = self.build("Achievement.dbc", [(-1,)], b"\x00")
        self.assertEqual(DBC(path).u(0, 0), 0xFFFFFFFF)

    def test_a_non_wdbc_file_is_refused(self):
        path = os.path.join(self.dir, "fake.dbc")
        with open(path, "wb") as handle:
            handle.write(b"XXXX" + b"\x00" * 32)
        with self.assertRaises(DbcError):
            DBC(path)

    def test_a_narrower_layout_is_refused(self):
        """Removed columns mean every offset below is wrong; a wider file is fine."""
        path = self.build("Talent.dbc", [(1, 2)], b"\x00", fields=2)
        dbc = DBC(path)
        with self.assertRaises(DbcError):
            dbc._expect_fields(bms_dbc.TALENT_FIELDS)

    def test_a_wider_layout_is_allowed_and_recorded(self):
        wide = bms_dbc.TALENT_FIELDS + 3
        path = self.build("Talent.dbc", [tuple(range(wide))], b"\x00", fields=wide)
        dbc = DBC(path)
        dbc._expect_fields(bms_dbc.TALENT_FIELDS)
        self.assertTrue(dbc.widened)


if __name__ == "__main__":
    unittest.main()
