#!/usr/bin/env python3
"""Read an AzerothCore server config so the importer can configure itself.

Everything the importer needs -- three database DSNs and the DBC directory --
is already written down in the operator's own `worldserver.conf`. Reading it
turns seven required flags into none, and means nobody has to retype a password
that their server already knows.

    LoginDatabaseInfo     = "127.0.0.1;3306;user;password;acore_auth"
    WorldDatabaseInfo     = "127.0.0.1;3306;user;password;acore_world"
    CharacterDatabaseInfo = "127.0.0.1;3306;user;password;acore_characters"
    DataDir               = "."

The DSN is semicolon-separated in that fixed order, which is how the core's own
`DatabaseWorkerPool` parses it, so the fifth field is the schema name -- that is
where `acore_auth` vs `asc_auth` comes from without anyone being asked.

SECURITY: a password read from a config lives in memory and nowhere else.
`DatabaseInfo` refuses to put it in repr() or str(), so it cannot reach a log
line, a traceback, or a crash report by accident; `redacted()` is the only
rendering intended for display. Nothing in this module writes to disk.
"""

from __future__ import annotations

import os
import shlex
import subprocess
from dataclasses import dataclass, field

MAX_CONFIG_BYTES = 4 * 1024 * 1024   # a server conf is ~40 KB; this is a sanity bound
DSN_FIELDS = 5                       # host;port;user;password;database

PROCESS_TIMEOUT = 20                 # a process listing that hangs must not hang us
CONFIG_FLAGS = ("-c", "-config", "--config")

WORLD_KEY = "WorldDatabaseInfo"
LOGIN_KEY = "LoginDatabaseInfo"
CHARACTERS_KEY = "CharacterDatabaseInfo"
DATA_DIR_KEY = "DataDir"

CONFIG_NAMES = ("worldserver.conf", "worldserver.conf.dist")
LOGIN_CONFIG_NAMES = ("authserver.conf", "authserver.conf.dist")

WALK_LEVELS = 5          # how far up from the start directory to look
SUBDIR_SCAN_LEVELS = 4   # how many of those levels also look one directory down
SUBDIR_SCAN_LIMIT = 60   # subdirectories examined per level

# Where a server config usually sits, relative to somewhere the user might run us.
RELATIVE_HINTS = (
    ".",
    "configs",
    "etc",
    os.path.join("..", "configs"),
    os.path.join("..", "etc"),
    os.path.join("..", "..", "configs"),
    os.path.join("..", "..", "etc"),
)

# Absolute locations worth a look on a stock install.
ABSOLUTE_HINTS = (
    "/etc/azerothcore",
    "/azerothcore/env/dist/etc",
    "/azerothcore/etc",
    "/opt/azerothcore/etc",
    os.path.join(os.path.expanduser("~"), "azerothcore", "env", "dist", "etc"),
)


class ConfigError(Exception):
    """The config could not be read, or does not say what the importer needs."""


@dataclass
class DatabaseInfo:
    """One `*DatabaseInfo` DSN.

    The password is deliberately unprintable: see the module docstring.
    """

    host: str
    port: int
    user: str
    password: str = field(repr=False)
    database: str

    def redacted(self) -> str:
        return "%s@%s:%s/%s" % (self.user, self.host, self.port, self.database)

    def __repr__(self) -> str:
        return "DatabaseInfo(%s, password=<hidden>)" % self.redacted()

    __str__ = __repr__


@dataclass
class ServerConfig:
    """What a server config told us. Any field may be None if it was absent."""

    path: str
    login: DatabaseInfo | None = None
    world: DatabaseInfo | None = None
    characters: DatabaseInfo | None = None
    data_dir: str | None = None

    @property
    def dbc_dir(self) -> str | None:
        """The DBC directory, which the core keeps at DataDir/dbc."""
        if not self.data_dir:
            return None
        return os.path.join(self.data_dir, "dbc")

    def missing(self) -> list[str]:
        """Which of the things the importer needs this config did not supply."""
        absent = []
        for key, value in ((LOGIN_KEY, self.login), (WORLD_KEY, self.world),
                           (CHARACTERS_KEY, self.characters)):
            if value is None:
                absent.append(key)
        if not self.data_dir:
            absent.append(DATA_DIR_KEY)
        return absent

    def describe(self) -> list[str]:
        """Display lines. Never includes a password -- see redacted()."""
        lines = ["config  %s" % self.path]
        for label, info in (("auth", self.login), ("characters", self.characters),
                            ("world", self.world)):
            lines.append("  %-11s %s" % (label, info.redacted() if info else "not set"))
        lines.append("  %-11s %s" % ("dbc", self.dbc_dir or "not set"))
        return lines


def parse_dsn(value: str, key: str = "DSN") -> DatabaseInfo:
    """Parse `host;port;user;password;database`.

    The core splits on `;` positionally, so a password containing `;` is not
    representable in this format on a real server either -- rejecting it here
    matches what the server itself would do rather than inventing a rule.
    """
    parts = value.split(";")
    if len(parts) != DSN_FIELDS:
        raise ConfigError(
            "%s should be host;port;user;password;database (%d fields), got %d."
            % (key, DSN_FIELDS, len(parts)))
    host, port, user, password, database = (p.strip() for p in parts)
    if not host:
        raise ConfigError("%s has an empty host." % key)
    if not database:
        raise ConfigError("%s has an empty database name." % key)
    try:
        port_number = int(port)
    except ValueError:
        raise ConfigError("%s has a non-numeric port %r." % (key, port)) from None
    if not 1 <= port_number <= 65535:
        raise ConfigError("%s has a port outside 1-65535 (%d)." % (key, port_number))
    return DatabaseInfo(host=host, port=port_number, user=user,
                        password=password, database=database)


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def read_pairs(path: str) -> dict[str, str]:
    """Read `Key = value` lines out of a server config.

    The core's own reader takes the LAST assignment of a key, which is what
    makes the `.conf` override the `.conf.dist`, so do the same.
    """
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        raise ConfigError("Cannot read %s: %s" % (path, exc)) from None
    if size > MAX_CONFIG_BYTES:
        raise ConfigError("%s is %d bytes, which is too large to be a server config."
                          % (path, size))
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            text = handle.read()
    except OSError as exc:
        raise ConfigError("Cannot read %s: %s" % (path, exc)) from None

    pairs: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped[0] in "#;[":
            continue
        key, sep, value = stripped.partition("=")
        if not sep:
            continue
        pairs[key.strip()] = _unquote(value)
    return pairs


def read_config(path: str) -> ServerConfig:
    """Read one server config, falling back to a sibling authserver.conf.

    A worldserver.conf normally carries all three DSNs, but a split deployment
    can leave LoginDatabaseInfo only in authserver.conf, so look there before
    reporting it missing.
    """
    if not os.path.isfile(path):
        raise ConfigError("No such config file: %s" % path)
    pairs = read_pairs(path)

    config = ServerConfig(path=os.path.abspath(path))
    for key, attribute in ((LOGIN_KEY, "login"), (WORLD_KEY, "world"),
                           (CHARACTERS_KEY, "characters")):
        raw = pairs.get(key)
        if raw:
            setattr(config, attribute, parse_dsn(raw, key))

    if config.login is None:
        for name in LOGIN_CONFIG_NAMES:
            sibling = os.path.join(os.path.dirname(config.path), name)
            if os.path.isfile(sibling):
                raw = read_pairs(sibling).get(LOGIN_KEY)
                if raw:
                    config.login = parse_dsn(raw, LOGIN_KEY)
                    break

    config.data_dir = _resolve_data_dir(pairs.get(DATA_DIR_KEY), config.path)
    return config


def _resolve_data_dir(data_dir: str | None, config_path: str) -> str | None:
    """Turn the config's DataDir into a real directory.

    A relative DataDir -- and the stock value is `"."` -- is relative to the
    server's working directory, which is not something a config file records.
    Different layouts put it in different places (`bin/` beside `etc/`, or the
    server root above `configs/`), so rather than pick one and be wrong half the
    time, try each and keep the one that actually contains a `dbc` directory.
    """
    if not data_dir:
        return None
    if os.path.isabs(data_dir):
        return os.path.normpath(data_dir)

    config_dir = os.path.dirname(config_path)
    bases = (
        os.path.dirname(config_dir),   # <root>/configs/worldserver.conf -> <root>
        config_dir,                    # DataDir written relative to the config
        os.getcwd(),                   # run from the server's working directory
    )
    resolved = [os.path.normpath(os.path.join(base, data_dir)) for base in bases]
    for candidate in resolved:
        if os.path.isdir(os.path.join(candidate, "dbc")):
            return candidate
    return resolved[0]


def _subdirectories(path: str) -> list[str]:
    """Immediate subdirectory names, bounded so a huge tree cannot stall us."""
    try:
        with os.scandir(path) as entries:
            names = sorted(entry.name for entry in entries
                           if entry.is_dir() and not entry.name.startswith("."))
    except OSError:
        return []
    return names[:SUBDIR_SCAN_LIMIT]


def candidates(start: str | None = None) -> list[str]:
    """Every path worth trying, in the order they should be tried."""
    found: list[str] = []

    def add(path: str) -> None:
        full = os.path.abspath(path)
        if full not in found:
            found.append(full)

    override = os.environ.get("BMS_SERVER_CONFIG")
    if override:
        add(override)

    base = os.path.abspath(start or os.getcwd())
    # Walk up from where we are: a tool run out of tools/bindmysoul is two
    # directories below the server root on a normal install.
    walk = base
    for depth in range(WALK_LEVELS):
        for hint in RELATIVE_HINTS:
            for name in CONFIG_NAMES:
                add(os.path.join(walk, hint, name))
        # Also look one level down. A machine that hosts two realms keeps them
        # in sibling directories (server/ and server-ascension/), which no
        # amount of walking upwards will reach.
        if depth < SUBDIR_SCAN_LEVELS:
            for sub in _subdirectories(walk):
                for hint in ("configs", "etc"):
                    for name in CONFIG_NAMES:
                        add(os.path.join(walk, sub, hint, name))
        parent = os.path.dirname(walk)
        if parent == walk:
            break
        walk = parent

    for hint in ABSOLUTE_HINTS:
        for name in CONFIG_NAMES:
            add(os.path.join(hint, name))
    return found


def find_all_configs(start: str | None = None) -> list[str]:
    """Every server config that actually exists, best first.

    Deduplicated by directory: a `.conf` and its `.conf.dist` in the same place
    are one server, not two, and the real file wins.
    """
    seen: dict[str, str] = {}
    for path in candidates(start):
        if not os.path.isfile(path):
            continue
        key = os.path.normcase(os.path.dirname(path))
        if key not in seen:
            seen[key] = path
    return list(seen.values())


def find_config(start: str | None = None) -> str | None:
    """The first server config we can actually find, or None."""
    found = find_all_configs(start)
    return found[0] if found else None


# -- asking the running server itself --------------------------------------
#
# Discovery above works by name and by convention, and that is a guess. A
# worldserver that is actually running holds its own config open and names it on
# its command line, so when the two disagree the process is right. This matters
# more than it sounds: a config from the realm next door usually has the same
# database settings but a different DataDir, so the import writes to the correct
# schema while resolving talents and spells against the wrong DBCs -- which
# looks like a clean run and quietly drops what it could not resolve.

def _command_output(argv: list[str]) -> str:
    """Run a process listing, or return "" if it is unavailable, slow or noisy."""
    try:
        done = subprocess.run(argv, capture_output=True, text=True,
                              timeout=PROCESS_TIMEOUT)
    except Exception:
        return ""
    return done.stdout or ""


def worldserver_command_lines() -> list[str]:
    """The full command line of every worldserver running on this machine."""
    lines: list[str] = []
    if os.name == "nt":
        # wmic is the fast path and is present on Windows 10; the CIM query is
        # the replacement on builds where wmic has been removed.
        text = _command_output(["wmic", "process", "where",
                                "name='worldserver.exe'", "get", "CommandLine",
                                "/format:list"])
        for line in text.splitlines():
            key, sep, value = line.partition("=")
            if sep and key.strip() == "CommandLine" and value.strip():
                lines.append(value.strip())
        if not lines:
            text = _command_output(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                 "Get-CimInstance Win32_Process -Filter \"Name='worldserver.exe'\" "
                 "| ForEach-Object { $_.CommandLine }"])
            lines.extend(line.strip() for line in text.splitlines() if line.strip())
    else:
        text = _command_output(["ps", "-eo", "args="])
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            # Match on the executable only. A grep over the whole line would
            # match any process that merely mentions a worldserver path.
            first = stripped.split(None, 1)[0]
            if os.path.basename(first).startswith("worldserver"):
                lines.append(stripped)
    return lines


def config_from_command_line(command_line: str) -> str | None:
    """The path given to `-c` / `--config`, or None if there was not one.

    Split with posix=False because a Windows command line is full of
    backslashes, and posix mode would eat them as escapes.
    """
    try:
        tokens = [_unquote(t) for t in shlex.split(command_line, posix=False)]
    except ValueError:
        return None
    for index, token in enumerate(tokens):
        flag, sep, joined = token.partition("=")
        if flag not in CONFIG_FLAGS:
            continue
        value = joined if sep else (tokens[index + 1] if index + 1 < len(tokens) else "")
        if value:
            return value
    return None


def running_servers() -> list[tuple[str, ServerConfig | None]]:
    """Every running worldserver as (command line, its config or None).

    Best effort throughout: a machine where the process listing is unavailable,
    or a server started with a relative config path we cannot resolve, yields
    nothing rather than an error. The unparsed ones are kept in the list with a
    None config on purpose -- a caller deciding whether a realm is safe to write
    to needs to know that a server is running even when we cannot say which.
    """
    servers: list[tuple[str, ServerConfig | None]] = []
    seen: set[str] = set()
    for line in worldserver_command_lines():
        config = None
        path = config_from_command_line(line)
        if path:
            path = os.path.abspath(path)
            key = os.path.normcase(path)
            if key in seen:
                continue
            seen.add(key)
            if os.path.isfile(path):
                try:
                    config = read_config(path)
                except ConfigError:
                    config = None
        servers.append((line, config))
    return servers


def running_server_configs() -> list[ServerConfig]:
    """Just the configs, for callers that only care about the readable ones."""
    return [config for _line, config in running_servers() if config is not None]


def serves_database(config: ServerConfig, database: str) -> bool:
    """Is this config's realm the one that owns `database`?

    Compared on the schema name alone. Several realms sharing one MySQL are
    told apart by schema (`acore_characters` vs `asc_characters`), while the
    host is written a different way in every config that reaches it.
    """
    if config.characters is None or not database:
        return False
    return config.characters.database.lower() == database.lower()


def load(path: str | None = None, start: str | None = None) -> ServerConfig:
    """Read the named config, or go looking for one."""
    if path:
        return read_config(path)
    discovered = find_config(start)
    if not discovered:
        raise ConfigError(
            "No worldserver.conf found. Pass --config /path/to/worldserver.conf, "
            "set $BMS_SERVER_CONFIG, or supply the database flags by hand.")
    return read_config(discovered)
