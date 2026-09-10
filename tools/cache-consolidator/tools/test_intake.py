"""Prove intake never reports an archive "cached" that it has not extracted.

extract_all() names each extract directory after the archive's FILENAME and
decides "already done" by asking whether that directory exists and is
non-empty. That is a name test standing in for an identity test, and it lost a
submission: two different files were both called Account.zip -- one freshly
dropped in _inbox/, one already filed under _inbox/archive/ -- so the second
mapped onto the first's directory, was reported `cached`, and its contents
never entered the ledger. No error. Exit 0. "all stages OK".

It is the same shape as the vendor rows the worldserver silently refused: a step
that reports success while the consumer quietly declines the work. The only
check that catches it is asking what the CONSUMER did, so that is what this
tests -- not that extract_all() returned, but that the payload came out.

    python test_intake.py
"""
import os, shutil, sys, tempfile, zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import intake

NEW, OLD = "-- the new drop\n", "-- already filed\n"


def fixture(tmp, both=True):
    """An inbox holding one or two archives that share a filename."""
    root = os.path.join(tmp, "inbox")
    sub = os.path.join(root, "archive")
    os.makedirs(sub)
    with zipfile.ZipFile(os.path.join(root, "Account.zip"), "w") as z:
        z.writestr("SavedVariables/new.lua", NEW)
    if both:
        with zipfile.ZipFile(os.path.join(sub, "Account.zip"), "w") as z:
            z.writestr("SavedVariables/old.lua", OLD)
    intake.EXTRACT = os.path.join(tmp, "extracted")
    intake.SCAN_ROOTS = [root]
    intake.QUARANTINE = os.path.join(tmp, "quarantine")
    return root


def payloads():
    """Every extracted file, markers excluded."""
    out = set()
    for _dp, _d, fs in os.walk(intake.EXTRACT):
        out |= {f for f in fs if f not in (intake.SRCMARK, intake.SRCHASH)}
    return out


def dirs():
    return sorted(os.listdir(intake.EXTRACT))


def case_same_name():
    """Two different archives with one filename: both must come out."""
    tmp = tempfile.mkdtemp(prefix="intake-samename-")
    try:
        fixture(tmp)
        got = intake.extract_all()
        have = payloads()
        return [
            ("the freshly dropped archive is extracted", "new.lua" in have),
            ("the already-filed archive is extracted", "old.lua" in have),
            ("they land in separate directories", len(dirs()) == 2),
            ("neither is reported cached",
             all(how == "ok" for _fn, how in got)),
        ]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def case_rerun():
    """Running again must extract nothing and create nothing."""
    tmp = tempfile.mkdtemp(prefix="intake-rerun-")
    try:
        fixture(tmp)
        intake.extract_all()
        before = dirs()
        got = intake.extract_all()
        return [
            ("a second run re-extracts nothing",
             all(how == "cached" for _fn, how in got)),
            ("a second run adds no directories", dirs() == before),
        ]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def case_legacy_marker():
    """A directory predating the hash marker is grandfathered, not re-extracted.

    Disowning unmarked directories would re-extract the whole historical archive
    set into hash-suffixed twins on the next run, which is a far worse outcome
    than the narrow name-comparison it falls back to.
    """
    tmp = tempfile.mkdtemp(prefix="intake-legacy-")
    try:
        fixture(tmp, both=False)
        intake.extract_all()
        os.remove(os.path.join(intake.EXTRACT, "Account", intake.SRCHASH))
        got = intake.extract_all()
        return [
            ("a name-only marker is still honoured",
             all(how == "cached" for _fn, how in got)),
            ("a name-only marker produces no twin", len(dirs()) == 1),
        ]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def case_changed_content():
    """A file re-uploaded with new content under the same name is re-extracted."""
    tmp = tempfile.mkdtemp(prefix="intake-changed-")
    try:
        root = fixture(tmp, both=False)
        intake.extract_all()
        with zipfile.ZipFile(os.path.join(root, "Account.zip"), "w") as z:
            z.writestr("SavedVariables/second.lua", "-- revised\n")
        got = intake.extract_all()
        return [
            ("the revised archive is extracted",
             "second.lua" in payloads()),
            ("the first extraction is kept too", "new.lua" in payloads()),
            ("it is not reported cached",
             all(how == "ok" for _fn, how in got)),
        ]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    bad = n = 0
    for case in (case_same_name, case_rerun, case_legacy_marker,
                 case_changed_content):
        print("%s:" % case.__name__)
        for label, ok in case():
            n += 1
            bad += not ok
            print("  %s  %s" % ("ok  " if ok else "FAIL", label))
    print("\n%d/%d %s" % (n - bad, n,
                          "- intake reports cached only when it means it"
                          if not bad else "- %d BROKEN, submissions can be "
                          "silently skipped" % bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
