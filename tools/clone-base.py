"""Clone the vanilla AzerothCore databases into the asc_* schemas.

Source databases are opened READ-ONLY (mysqldump only). Nothing here writes to
acore_*; that is the hard constraint from HANDOFF-REALM-PROFILES.md.
"""
import os, subprocess, sys, time

SCR  = os.environ.get("ASC_SCR", os.path.join(os.environ.get("TEMP", "."), "asc-scratch"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ascreds
CNF  = ascreds.path()   # root; written to a 0600 temp file, gone at exit
BIN  = r"C:\AzerothRealm\mysql\bin"
DUMP = os.path.join(BIN, "mysqldump.exe")
MY   = os.path.join(BIN, "mysql.exe")

# (source, target, data?) - characters/playerbots get schema only, world/auth get data
JOBS = [
    ("acore_world",      "asc_world",      True),
    ("acore_auth",       "asc_auth",       True),
    ("acore_characters", "asc_characters", False),
    ("acore_playerbots", "asc_playerbots", False),
]

def run(cmd, **kw):
    r = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if r.returncode:
        sys.stderr.write("FAIL %s\n%s\n" % (cmd[:3], r.stderr[:600]))
    return r

for src, dst, with_data in JOBS:
    t0 = time.time()
    out = os.path.join(SCR, dst + ".sql")
    args = [DUMP, "--defaults-extra-file=" + CNF, "--single-transaction",
            "--no-tablespaces", "--routines", "--events", "--set-gtid-purged=OFF"]
    if not with_data:
        args.append("--no-data")
    args.append(src)
    with open(out, "wb") as fh:
        r = subprocess.run(args, stdout=fh, stderr=subprocess.PIPE)
    if r.returncode:
        print("DUMP FAIL %s: %s" % (src, r.stderr.decode()[:400])); continue
    size = os.path.getsize(out)
    with open(out, "rb") as fh:
        r = subprocess.run([MY, "--defaults-extra-file=" + CNF, dst], stdin=fh,
                           capture_output=True)
    ok = "ok" if r.returncode == 0 else "RESTORE FAIL: " + r.stderr.decode()[:300]
    print("%-16s -> %-16s %9.1f MB  %5.0fs  %s"
          % (src, dst, size / 1048576, time.time() - t0, ok), flush=True)
    try: os.remove(out)
    except OSError: pass

print("clone-base done", flush=True)
