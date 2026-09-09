r"""Seed asc_characters with the static rows the shipped SQL files carry.

clone-base.py deliberately cloned acore_characters with --no-data, so no
player, guild, mail or bot-name row from the reference realm could leak into
this realm.  That was right, and it also dropped the handful of tables the
base and module SQL populate as fixed content.  The first one missing is not
survivable:

    ASSERT(result, "active_arena_season can't be empty")
                              ArenaSeasonMgr.cpp line 112

Rows come from the source tree's own .sql files, never from acore_characters,
so nothing from the reference realm can arrive here by the back door.  Only
the INSERT statements are taken: the schema already matches the current core,
and DROP/CREATE from a base file would roll individual tables back to their
pre-update shape.

Only tables that are empty right now are touched, so a second run is a no-op
and nothing the running server has since written is overwritten.
Updates.EnableDatabases is 0 for this realm, so `updates`/`updates_include`
bookkeeping is not seeded - the schema came from an already-updated database
and base-level rows there would misdescribe it.

Usage:  python seed-characters.py [--dry-run]
"""
import os, re, subprocess, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ascreds

SRC = r"C:\AzerothRealm\src"
DB = "asc_characters"
MYSQL = r"C:\AzerothRealm\mysql\bin\mysql.exe"
if not os.path.isfile(MYSQL):
    MYSQL = "mysql"

SEED_FILES = [
    os.path.join(SRC, "data", "sql", "base", "db_characters"),
    os.path.join(SRC, "modules", "mod-playerbots", "data", "sql", "characters", "base"),
    os.path.join(SRC, "modules", "mod-ollama-chat", "data", "sql", "characters", "base"),
    # mail_server_template arrived as an update, not in the base set
    os.path.join(SRC, "data", "sql", "updates", "db_characters", "2026_07_21_00.sql"),
]
SKIP = {"updates", "updates_include"}

INSERT = re.compile(rb"^\s*INSERT(?:\s+IGNORE)?\s+INTO\s+`?([A-Za-z0-9_]+)`?", re.I)


def statements(path):
    """-> [(table, sql-bytes)] for every INSERT in one .sql file."""
    out, cur, table = [], None, None
    for line in open(path, "rb").read().split(b"\n"):
        if cur is None:
            m = INSERT.match(line)
            if not m:
                continue
            table, cur = m.group(1).decode(), [line]
        else:
            cur.append(line)
        if line.rstrip().endswith(b";"):
            out.append((table, b"\n".join(cur)))
            cur, table = None, None
    return out


def sql_files():
    for p in SEED_FILES:
        if os.path.isfile(p):
            yield p
        elif os.path.isdir(p):
            for f in sorted(os.listdir(p)):
                if f.lower().endswith(".sql"):
                    yield os.path.join(p, f)


def mysql(cnf, sql=None, stdin=None):
    cmd = [MYSQL, "--defaults-extra-file=" + cnf, "--default-character-set=utf8mb4"]
    if sql:
        cmd += ["--batch", "--skip-column-names", "-e", sql]
    cmd.append(DB)
    p = subprocess.run(cmd, capture_output=True, stdin=stdin)
    if p.returncode:
        raise RuntimeError(p.stderr.decode("utf8", "replace")[:500])
    return [l.rstrip("\r") for l in p.stdout.decode("utf8", "replace").split("\n") if l.strip()]


def main(argv):
    dry = "--dry-run" in argv
    cnf = ascreds.path()
    have = {}
    for row in mysql(cnf, "SELECT table_name FROM information_schema.tables "
                          "WHERE table_schema='%s';" % DB):
        have[row] = int(mysql(cnf, "SELECT COUNT(*) FROM `%s`;" % row)[0])

    by_table = {}
    for path in sql_files():
        for table, sql in statements(path):
            if table in SKIP or table not in have:
                continue
            by_table.setdefault(table, []).append((os.path.basename(path), sql))

    payload, plan = [], []
    for table in sorted(by_table):
        n = sum(len(s) for _, s in by_table[table])
        if have[table]:
            plan.append("  %-38s skipped, already holds %d row(s)" % (table, have[table]))
            continue
        plan.append("  %-38s %d statement(s), %.1f KB from %s"
                    % (table, len(by_table[table]), n / 1024.0,
                       ", ".join(sorted({f for f, _ in by_table[table]}))))
        payload += [s for _, s in by_table[table]]
    print("\n".join(plan) or "  nothing to seed")
    if dry or not payload:
        return

    blob = b"SET NAMES utf8mb4;\n" + b"\n".join(payload) + b"\n"
    tmp = os.path.join(os.environ.get("TEMP", "."), "asc-seed-characters.sql")
    with open(tmp, "wb") as f:
        f.write(blob)
    try:
        with open(tmp, "rb") as f:
            mysql(cnf, stdin=f)
    finally:
        os.remove(tmp)
    # Verify rather than trust the exit code: on the first run one statement
    # in the batch left its table empty while mysql still returned 0, so a
    # silent partial seed is a failure mode this tool has actually had.
    print("\nafter:")
    short = []
    for table in sorted(by_table):
        n = int(mysql(cnf, "SELECT COUNT(*) FROM `%s`;" % table)[0])
        if not have[table] and not n:
            short.append(table)
        print("  %-38s %d row(s)%s"
              % (table, n, "   <-- STILL EMPTY" if not n else ""))
    if short:
        print("\n%d table(s) did not take their rows: %s"
              % (len(short), ", ".join(short)))
        sys.exit(1)


if __name__ == "__main__":
    main(sys.argv[1:])
