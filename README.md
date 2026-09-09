# Bind My Soul — offline character importer

Rebuild a [Bind My Soul](https://bindmysoul.com) character on your own
AzerothCore server.

Bind My Soul is an in-game addon that captures a character to a signed
checkpoint. This tool reads the `.bmsr.zip` the website gives you, verifies it,
and recreates that character in your realm's database — gear, spells, talents,
skills, reputations, action bars and all.

It runs entirely offline. Nothing is uploaded, and no network call is made.

---

## Quick start

```bash
python bms_import.py mycharacter.bmsr.zip --account MYACCOUNT
```

That is the whole command. The importer finds your `worldserver.conf`, reads
the database host, port, user, password, the three schema names and the DBC
directory out of it, and shows you what it would do. **Nothing is written
without `--apply`.**

When it looks right, stop the realm and run it again:

```bash
python bms_import.py mycharacter.bmsr.zip --account MYACCOUNT --apply
```

Start the realm, log in, and the character is there. The client will prompt you
to rename and to pick an appearance.

### If it cannot find your config

On a machine hosting more than one realm it will refuse to guess:

```
error: Found 3 server configs and will not guess between them:
  /azerothcore/realm-a/etc/worldserver.conf
  /azerothcore/realm-b/etc/worldserver.conf
Pass --config with the one you mean.
```

So point it at the right one:

```bash
python bms_import.py mycharacter.bmsr.zip --account MYACCOUNT \
    --config /azerothcore/etc/worldserver.conf
```

---

## Requirements

- Python 3.9 or newer — CI covers 3.9, 3.11 and 3.13 on Linux and Windows
- [PyMySQL](https://pypi.org/project/PyMySQL/) — `pip install -r requirements.txt`

Everything else is the Python standard library. There is nothing to build, and
PyMySQL is pure Python, so no compiler and no MySQL client library are needed.

---

## What it restores

| Restored | Notes |
| --- | --- |
| Character record | race, class, level, money, played time, position |
| Equipment and bags | including per-item durability and enchantments |
| Spells | filtered against the target's `Spell.dbc` |
| Talents | resolved by name through `Talent.dbc` / `TalentTab.dbc` |
| Skills | resolved by name through `SkillLine.dbc` |
| Reputations | resolved by name through `Faction.dbc` |
| Action bars | spells and macros |
| Quests | active and completed |
| Homebind | the recorded bind zone |

## What it does not restore, and why

These are reported every run, so nothing is silently dropped.

| Skipped | Why |
| --- | --- |
| Titles | the addon's scan is broken — `IsTitleKnown` returns `0` for unknown, and `0` is truthy in Lua, so every title reads as known |
| Glyphs | only a socket index and type are captured, with no glyph name or spell id to resolve |
| Achievement criteria | counters are account-wide and client-side; importing them would credit progress the character may not own |
| Mounts and companions | stored per-account server-side, and the checkpoint carries no ids |
| Profession recipes | captured only for profession windows the player happened to have open |
| Currencies | no currency ids are captured |
| Mail, bank and guild bank | not captured |
| Appearance | the 3.3.5a client never exposes skin/face/hair after login, so the character is created with a default look and `AT_LOGIN_CUSTOMIZE`, which walks the player through the barber shop on first login |

Two more deliberate choices:

- **Active quest objectives start at zero.** The client only exposes objectives
  as display strings like `3/8 Kobolds slain`. Parsing those back into counter
  columns would be guessing which objective is which, so the quest is restored
  and the counters are not.
- **The character spawns at the race/class starting point.** A checkpoint
  records the bind *zone name*, never coordinates.

---

## Safety

The importer is built to be hard to misuse.

- **Dry run by default.** `--apply` is the only thing that writes.
- **It never overwrites.** A new character is always created. If the name is
  taken it appends a number and sets the rename flag, so you are prompted to
  choose a new name at login. Your existing characters are never touched.
- **It refuses to write to a running realm.** The worldserver caches character
  data in memory and would overwrite rows inserted underneath it. Stop the realm
  first. (`--allow-online` exists, but you almost certainly do not want it.)
- **It will not guess between realms.** See above.
- **Bundle integrity is checked before anything else.** Eight offline checks per
  character: package digest, checkpoint digest and length, and that the digest is
  listed in the roster, the signed export receipt, the package manifest and the
  hash receipt. A bundle that fails is refused unless you pass
  `--allow-unverified`.
- **Passwords are never written down.** A password read from your config lives
  in memory only. It is excluded from `repr()`, so it cannot reach a log line or
  a traceback by accident, and nothing here writes it to disk.

### Rehearsing against a live database

`--rehearse` runs every `INSERT` against the real schema inside a transaction
and then rolls it back. It proves the writes are valid — right columns, right
types, no constraint violations — without keeping them, and it is safe while the
realm is up.

```bash
python bms_import.py mycharacter.bmsr.zip --account MYACCOUNT --rehearse
```

### Items your server does not have

If the checkpoint references an item your `item_template` lacks, the item is
skipped and reported. `--synthesize` instead creates placeholder
`item_template` rows so the character keeps the item — useful when importing
from a custom server onto a stock one, but the placeholders are approximations.

---

## Input formats

Three shapes are accepted, and detected automatically:

1. **`.bmsr.zip`** — what bindmysoul.com hands you. This is the expected input.
2. **`BindMySoul.lua`** — the addon's own SavedVariables file, straight from
   your WoW directory.
3. **A text file containing a `BMSP...` code** — for lifting a code out by hand.

A bundle can hold several characters. `--list` shows them; `--index N` picks
one.

```bash
python bms_import.py mybundle.bmsr.zip --list
```

---

## Configuration

Settings are resolved in this order, first one wins:

1. A command-line flag
2. An environment variable
3. Your `worldserver.conf`
4. The stock AzerothCore default

| Flag | Environment | Default |
| --- | --- | --- |
| `--host` | `BMS_DB_HOST` | `127.0.0.1` |
| `--port` | `BMS_DB_PORT` | `3306` |
| `--user` | `BMS_DB_USER` | `root` |
| `--password` | `BMS_DB_PASSWORD` | from the config |
| `--auth-db` | `BMS_AUTH_DB` | `acore_auth` |
| `--characters-db` | `BMS_CHARACTERS_DB` | `acore_characters` |
| `--world-db` | `BMS_WORLD_DB` | `acore_world` |
| `--dbc-dir` | `BMS_DBC_DIR` | `DataDir/dbc` from the config |
| `--config` | `BMS_SERVER_CONFIG` | discovered |

Prefer the environment variable over `--password`: a command line is visible to
other processes on the machine.

`--no-config` disables config discovery entirely if you would rather be
explicit.

Every run prints where each setting came from:

```
CONFIG  /azerothcore/etc/worldserver.conf
  host           127.0.0.1                     config
  characters_db  acore_characters              config
  dbc_dir        /azerothcore/data/dbc         config
  password       <hidden>                      config
```

---

## Forks and custom servers

The importer measures the target rather than assuming a stock core:

- **`equipmentCache` width is read from your realm's existing characters.** A
  stock core has 19 equipment slots (38 values); forks add more. The core reads
  that column as fixed-size pairs, so writing the wrong width leaves the
  character-select screen reading it out of alignment — which shows a fully
  equipped character as naked.
- **Item durability is clamped to your `item_template`.** An item whose
  durability was not captured is created at your server's maximum rather than
  at zero, so imported gear does not arrive broken.
- **Schema fit is checked before writing.** Every planned row is compared
  against the actual columns of the target tables, so a fork that renamed or
  dropped a column is reported instead of crashing mid-insert.

---

## Troubleshooting

**`No password. Set $BMS_DB_PASSWORD or pass --password.`**
No config was found and no password was given. Pass `--config`, or set the
environment variable.

**`No playercreateinfo row for race N class C.`**
The target world database has no starting position for that race/class
combination — usually a custom class that does not exist on your server.

**`error: N integrity check(s) failed`**
The bundle's contents are not what bindmysoul.com signed: it was edited,
truncated, or damaged in transit. Re-download it.

**Character looks naked on the character-selection screen**
That screen renders from `characters.equipmentCache` alone. Log in once and the
server rewrites it. If it persists, your realm's cache width was misdetected —
open an issue with the output of the run.

---

## Development

```bash
python -m unittest discover -p "test_*.py"
```

171 tests, no database and no realm required — the suites that can use a live
one skip themselves when it is absent. To run those too, point
`$BMS_TEST_SERVER_CONFIG` at a real `worldserver.conf`.

| Module | Job |
| --- | --- |
| `bms_bundle.py` | read and verify the `.bmsr.zip` |
| `bms_parse.py` | decode the `BMSP` checkpoint envelope |
| `bms_map.py` | map addon tokens to core ids |
| `bms_dbc.py` | read the server's DBC files |
| `bms_config.py` | read `worldserver.conf` |
| `bms_import.py` | plan and apply the import |

### A note on the signature

Every offline check in the bundle is verified. The ed25519 signature itself is
**not** — checking it requires fetching the service's public key over the
network, and this tool does not make network calls. The integrity chain still
binds the checkpoint you are importing to the digests the service signed; what
is unverified is that the signature over those digests is genuine.

---

## License

MIT — see [LICENSE](LICENSE).

Not affiliated with Bind My Soul, Ascension, or Blizzard Entertainment. This
tool reads a file the service gives you and writes to a database you own.

---

## Untrusted input

A checkpoint is a file someone hands you. It is treated as hostile: the
SavedVariables reader parses rather than executes (it is never `exec`'d), and
the bundle reader enforces limits on member count, compressed and uncompressed
size, and path shape, so a zip bomb or a path-traversal entry cannot get through.
