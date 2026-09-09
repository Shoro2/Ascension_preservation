#!/usr/bin/env python3
"""Tests for reading an AzerothCore server config.

Run:  python test_bms_config.py
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from bms_config import (  # noqa: E402
    CHARACTERS_KEY,
    LOGIN_KEY,
    MAX_CONFIG_BYTES,
    WORLD_KEY,
    ConfigError,
    DatabaseInfo,
    candidates,
    find_config,
    load,
    parse_dsn,
    read_config,
    read_pairs,
)

SECRET = "hunter2-s3cret"

WORLDSERVER = """
# AzerothCore worldserver configuration
[worldserver]

LoginDatabaseInfo     = "127.0.0.1;3306;acore;{secret};acore_auth"
WorldDatabaseInfo     = "127.0.0.1;3306;acore;{secret};acore_world"
CharacterDatabaseInfo = "127.0.0.1;3306;acore;{secret};acore_characters"

DataDir = "."
"""


class Fixture(unittest.TestCase):
    """A throwaway server tree: <root>/configs/worldserver.conf.

    No data directory is created here on purpose -- DataDir resolution depends
    on which layout exists, so each test builds the one it means to exercise.
    """

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="bms-config-")
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        self.configs = os.path.join(self.root, "configs")
        os.makedirs(self.configs)

    def write(self, text, name="worldserver.conf"):
        path = os.path.join(self.configs, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
        return path

    def standard(self):
        return self.write(WORLDSERVER.format(secret=SECRET))


class DsnTests(unittest.TestCase):
    """The DSN is positional and semicolon-separated, as the core parses it."""

    def test_a_normal_dsn(self):
        info = parse_dsn("127.0.0.1;3306;acore;pw;acore_world")
        self.assertEqual((info.host, info.port, info.user, info.database),
                         ("127.0.0.1", 3306, "acore", "acore_world"))
        self.assertEqual(info.password, "pw")

    def test_the_fifth_field_is_the_schema_name(self):
        """This is how asc_world is discovered without anyone being asked."""
        self.assertEqual(parse_dsn("h;3306;u;p;asc_world").database, "asc_world")

    def test_an_empty_password_is_allowed(self):
        self.assertEqual(parse_dsn("h;3306;u;;db").password, "")

    def test_surrounding_whitespace_is_trimmed(self):
        info = parse_dsn(" h ; 3306 ; u ; p ; db ")
        self.assertEqual((info.host, info.port, info.database), ("h", 3306, "db"))

    def test_too_few_fields_is_refused(self):
        with self.assertRaises(ConfigError):
            parse_dsn("127.0.0.1;3306;acore;pw")

    def test_too_many_fields_is_refused(self):
        """A password containing ';' is unrepresentable on a real server too."""
        with self.assertRaises(ConfigError):
            parse_dsn("h;3306;u;pass;word;db")

    def test_a_non_numeric_port_is_refused(self):
        with self.assertRaises(ConfigError):
            parse_dsn("h;threethousand;u;p;db")

    def test_a_port_out_of_range_is_refused(self):
        for port in ("0", "65536", "-1"):
            with self.assertRaises(ConfigError):
                parse_dsn("h;%s;u;p;db" % port)

    def test_an_empty_host_or_database_is_refused(self):
        with self.assertRaises(ConfigError):
            parse_dsn(";3306;u;p;db")
        with self.assertRaises(ConfigError):
            parse_dsn("h;3306;u;p;")

    def test_the_error_names_the_key_that_was_wrong(self):
        with self.assertRaises(ConfigError) as caught:
            parse_dsn("nonsense", WORLD_KEY)
        self.assertIn(WORLD_KEY, str(caught.exception))


class SecrecyTests(unittest.TestCase):
    """A parsed password must not be able to reach a log line by accident."""

    def setUp(self):
        self.info = parse_dsn("127.0.0.1;3306;acore;%s;acore_world" % SECRET)

    def test_repr_hides_it(self):
        self.assertNotIn(SECRET, repr(self.info))

    def test_str_and_format_hide_it(self):
        self.assertNotIn(SECRET, str(self.info))
        self.assertNotIn(SECRET, "{}".format(self.info))
        self.assertNotIn(SECRET, f"{self.info}")

    def test_being_inside_a_container_still_hides_it(self):
        """A traceback prints locals, so a list or dict of these must be safe too."""
        self.assertNotIn(SECRET, repr([self.info]))
        self.assertNotIn(SECRET, repr({"world": self.info}))

    def test_redacted_says_enough_to_be_useful(self):
        shown = self.info.redacted()
        self.assertNotIn(SECRET, shown)
        for part in ("acore", "127.0.0.1", "3306", "acore_world"):
            self.assertIn(part, shown)

    def test_the_value_is_still_reachable_on_purpose(self):
        """Hiding it from repr must not stop the importer from connecting."""
        self.assertEqual(self.info.password, SECRET)


class PairTests(Fixture):
    def test_comments_and_blanks_are_ignored(self):
        path = self.write("# comment\n; also a comment\n[section]\n\nA = 1\n")
        self.assertEqual(read_pairs(path), {"A": "1"})

    def test_quotes_are_stripped(self):
        path = self.write('A = "quoted"\nB = \'single\'\nC = bare\n')
        self.assertEqual(read_pairs(path), {"A": "quoted", "B": "single", "C": "bare"})

    def test_a_mismatched_quote_is_left_alone(self):
        self.assertEqual(read_pairs(self.write('A = "half\n'))["A"], '"half')

    def test_the_last_assignment_wins(self):
        """That is what makes a .conf override a .conf.dist."""
        self.assertEqual(read_pairs(self.write("A = 1\nA = 2\n"))["A"], "2")

    def test_lines_without_an_equals_are_skipped(self):
        self.assertEqual(read_pairs(self.write("junk line\nA = 1\n")), {"A": "1"})

    def test_a_value_containing_equals_survives(self):
        self.assertEqual(read_pairs(self.write("A = a=b=c\n"))["A"], "a=b=c")

    def test_a_missing_file_is_a_config_error(self):
        with self.assertRaises(ConfigError):
            read_pairs(os.path.join(self.root, "nope.conf"))

    def test_an_absurdly_large_file_is_refused(self):
        path = os.path.join(self.configs, "big.conf")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("A = 1\n")
            handle.truncate(MAX_CONFIG_BYTES + 1)
        with self.assertRaises(ConfigError):
            read_pairs(path)


class ReadConfigTests(Fixture):
    def test_all_three_dsns_are_read(self):
        config = read_config(self.standard())
        self.assertEqual(config.login.database, "acore_auth")
        self.assertEqual(config.world.database, "acore_world")
        self.assertEqual(config.characters.database, "acore_characters")
        self.assertEqual(config.missing(), [])

    def test_a_relative_datadir_resolves_beside_configs(self):
        """DataDir "." means the server root, which is the parent of configs/."""
        os.makedirs(os.path.join(self.root, "dbc"))
        config = read_config(self.standard())
        self.assertEqual(os.path.normcase(config.data_dir),
                         os.path.normcase(self.root))
        self.assertTrue(os.path.isdir(config.dbc_dir))

    def test_a_relative_datadir_is_resolved_by_finding_the_dbc(self):
        """`DataDir "."` is layout-dependent, so the dbc directory decides."""
        os.makedirs(os.path.join(self.configs, "Data", "dbc"))
        text = WORLDSERVER.format(secret=SECRET).replace(
            'DataDir = "."', 'DataDir = "Data"')
        config = read_config(self.write(text))
        self.assertEqual(os.path.normcase(config.data_dir),
                         os.path.normcase(os.path.join(self.configs, "Data")))
        self.assertTrue(os.path.isdir(config.dbc_dir))

    def test_an_unresolvable_relative_datadir_still_reports_something(self):
        """No dbc anywhere: report the likeliest path rather than None."""
        text = WORLDSERVER.format(secret=SECRET).replace(
            'DataDir = "."', 'DataDir = "nowhere"')
        config = read_config(self.write(text))
        self.assertEqual(os.path.normcase(config.data_dir),
                         os.path.normcase(os.path.join(self.root, "nowhere")))

    def test_an_absolute_datadir_is_taken_as_given(self):
        text = WORLDSERVER.format(secret=SECRET).replace(
            'DataDir = "."', 'DataDir = "%s"' % self.root.replace("\\", "/"))
        config = read_config(self.write(text))
        self.assertEqual(os.path.normcase(os.path.normpath(config.data_dir)),
                         os.path.normcase(self.root))

    def test_dbc_is_datadir_plus_dbc(self):
        config = read_config(self.standard())
        self.assertEqual(os.path.basename(config.dbc_dir), "dbc")

    def test_missing_keys_are_named_not_guessed(self):
        config = read_config(self.write('WorldDatabaseInfo = "h;3306;u;p;w"\n'))
        self.assertIn(LOGIN_KEY, config.missing())
        self.assertIn(CHARACTERS_KEY, config.missing())
        self.assertIsNone(config.dbc_dir)

    def test_login_falls_back_to_a_sibling_authserver_conf(self):
        """A split deployment keeps LoginDatabaseInfo only in authserver.conf."""
        text = WORLDSERVER.format(secret=SECRET)
        text = "\n".join(l for l in text.splitlines() if not l.startswith(LOGIN_KEY))
        self.write('LoginDatabaseInfo = "10.0.0.9;3307;au;pw;other_auth"\n',
                   name="authserver.conf")
        config = read_config(self.write(text))
        self.assertEqual(config.login.database, "other_auth")
        self.assertEqual(config.login.port, 3307)
        self.assertEqual(config.missing(), [])

    def test_a_broken_dsn_reports_rather_than_half_loading(self):
        text = WORLDSERVER.format(secret=SECRET).replace(
            '"127.0.0.1;3306;acore;%s;acore_world"' % SECRET, '"garbage"')
        with self.assertRaises(ConfigError):
            read_config(self.write(text))

    def test_a_missing_config_file_is_reported_clearly(self):
        with self.assertRaises(ConfigError) as caught:
            read_config(os.path.join(self.root, "absent.conf"))
        self.assertIn("absent.conf", str(caught.exception))

    def test_describe_never_prints_the_password(self):
        rendered = "\n".join(read_config(self.standard()).describe())
        self.assertNotIn(SECRET, rendered)
        self.assertIn("acore_characters", rendered)


class DiscoveryTests(Fixture):
    def test_it_finds_a_config_under_the_server_root(self):
        self.standard()
        self.assertEqual(os.path.normcase(find_config(self.root) or ""),
                         os.path.normcase(os.path.join(self.configs,
                                                       "worldserver.conf")))

    def test_it_finds_one_from_a_subdirectory(self):
        """Running from tools/bindmysoul must still locate the server config."""
        self.standard()
        deep = os.path.join(self.root, "tools", "bindmysoul")
        os.makedirs(deep)
        self.assertTrue(find_config(deep))

    def test_a_real_conf_is_preferred_over_a_dist(self):
        self.write("A = 1\n", name="worldserver.conf.dist")
        self.standard()
        self.assertTrue((find_config(self.root) or "").endswith("worldserver.conf"))

    def test_a_dist_is_used_when_nothing_else_exists(self):
        self.write(WORLDSERVER.format(secret=SECRET), name="worldserver.conf.dist")
        self.assertTrue((find_config(self.root) or "").endswith(".dist"))

    def test_the_environment_override_is_tried_first(self):
        target = self.write(WORLDSERVER.format(secret=SECRET), name="elsewhere.conf")
        os.environ["BMS_SERVER_CONFIG"] = target
        self.addCleanup(os.environ.pop, "BMS_SERVER_CONFIG", None)
        self.assertEqual(os.path.normcase(candidates(self.root)[0]),
                         os.path.normcase(target))
        self.assertEqual(os.path.normcase(find_config(self.root) or ""),
                         os.path.normcase(target))

    def test_nothing_found_returns_none_rather_than_raising(self):
        empty = tempfile.mkdtemp(prefix="bms-empty-")
        self.addCleanup(shutil.rmtree, empty, ignore_errors=True)
        os.environ.pop("BMS_SERVER_CONFIG", None)
        found = find_config(empty)
        self.assertTrue(found is None or os.path.isfile(found))

    def test_candidates_are_unique_and_absolute(self):
        paths = candidates(self.root)
        self.assertEqual(len(paths), len(set(paths)))
        self.assertTrue(all(os.path.isabs(p) for p in paths))

    def test_load_prefers_an_explicit_path(self):
        self.assertEqual(load(self.standard()).world.database, "acore_world")

    def test_load_explains_itself_when_there_is_nothing_to_find(self):
        empty = tempfile.mkdtemp(prefix="bms-empty-")
        self.addCleanup(shutil.rmtree, empty, ignore_errors=True)
        os.environ.pop("BMS_SERVER_CONFIG", None)
        try:
            load(start=empty)
        except ConfigError as exc:
            self.assertIn("--config", str(exc))


class RealServerTests(unittest.TestCase):
    """Against a real server config, when one is available.

    Point $BMS_TEST_SERVER_CONFIG at your own worldserver.conf to run these;
    otherwise they skip, so the suite stays green on a machine with no realm.
    """

    def setUp(self):
        self.conf = os.environ.get("BMS_TEST_SERVER_CONFIG") or ""
        if not os.path.isfile(self.conf):
            self.skipTest("set $BMS_TEST_SERVER_CONFIG to a worldserver.conf to run these")
        self.CONF = self.conf

    def test_the_live_config_yields_everything_the_importer_needs(self):
        """Assert the shape, not the names: every realm names its schemas
        differently, which is the whole reason for reading them from here."""
        config = read_config(self.CONF)
        self.assertEqual(config.missing(), [])
        for info in (config.login, config.world, config.characters):
            self.assertTrue(info.database)
            self.assertTrue(info.host)
            self.assertTrue(1 <= info.port <= 65535)
        self.assertNotEqual(config.world.database, config.characters.database)

    def test_the_dbc_directory_it_reports_actually_exists(self):
        self.assertTrue(os.path.isdir(read_config(self.CONF).dbc_dir))

    def test_the_live_password_is_not_printable(self):
        config = read_config(self.CONF)
        secret = config.world.password
        if not secret:
            self.skipTest("this config has no password to leak")
        for text in (repr(config), str(config.world), "\n".join(config.describe())):
            self.assertNotIn(secret, text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
