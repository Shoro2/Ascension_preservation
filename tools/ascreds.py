r"""Materialise a throwaway MySQL defaults-file for the importers.

The passwords live in exactly one place - C:\AzerothRealm\credentials.txt,
the same file control/realms.py reads - so no script here holds one, and none
of them ever put one on a command line where a process list would show it.

The file is written to the OS temp dir with 0600, and removed at interpreter
exit; a crash leaves at most one short-lived file behind.

    CNF = ascreds.path()            # root, for cross-database work
    CNF = ascreds.path("ascore")    # the realm's own restricted user
"""
import atexit, os, re, tempfile

CREDS = r"C:\AzerothRealm\credentials.txt"

# Label in credentials.txt that carries each user's password.
LABELS = {
    "root": "MySQL root password",
    "ascore": "Ascension MySQL password",
}

_made = {}


def password(user):
    label = LABELS.get(user)
    if not label:
        raise KeyError("no credentials.txt label known for MySQL user %r" % user)
    with open(CREDS, encoding="utf-8-sig", errors="replace") as f:
        m = re.search(re.escape(label) + r":\s*(.+)", f.read())
    if not m:
        raise KeyError("%r not found in %s" % (label, CREDS))
    return m.group(1).strip()


def path(user="root", host="127.0.0.1", port="3306"):
    if user in _made:
        return _made[user]
    fd, p = tempfile.mkstemp(prefix="asc-%s-" % user, suffix=".cnf")
    with os.fdopen(fd, "w", encoding="utf8") as f:
        f.write("[client]\nhost=%s\nport=%s\nuser=%s\npassword=%s\n"
                % (host, port, user, password(user)))
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass
    _made[user] = p
    atexit.register(_drop, p)
    return p


def _drop(p):
    try:
        os.remove(p)
    except OSError:
        pass
