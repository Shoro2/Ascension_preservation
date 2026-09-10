#!/usr/bin/env python3
"""Tests for the .bmsr.zip bundle reader.

Bundles are built in memory so the tamper cases are exact: one byte changes and
the matching check must flip to FAIL while the others stay OK.

Run:  python test_bms_bundle.py
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import sys
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from bms_bundle import (  # noqa: E402
    BundleError,
    is_bundle,
    read_bundle,
    render_bundle,
)

CODE = 'BMSP2|g=1788937107|j={"schema":"bind-my-soul/preservation-checkpoint",' \
       '"version":2,"character":{"name":"Probethree"}}'


def sha(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def build_package(code: str = CODE) -> bytes:
    """One character package, self-consistent."""
    checkpoint = code.encode("utf-8")
    digest = sha(checkpoint)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("checkpoint.bmsp", checkpoint)
        archive.writestr("restoration-verification-manifest.json", json.dumps({
            "schema": "bind-my-soul/restoration-package-manifest",
            "version": 1,
            "checkpointPath": "checkpoint.bmsp",
            "checkpointSha256": digest,
        }))
        archive.writestr("service-hash-receipt.json", json.dumps({
            "schema": "bind-my-soul/checkpoint-hash-proof",
            "sha256": digest,
            "byteLength": len(checkpoint),
        }))
    return buffer.getvalue()


def build_bundle(path: str, *, code: str = CODE, package: bytes | None = None,
                 mutate_manifest=None, package_path: str = "packages/001-probe-aaaa.zip",
                 omit_package: bool = False, omit_receipt: bool = False) -> str:
    package = build_package(code) if package is None else package
    checkpoint = code.encode("utf-8")
    digest = sha(checkpoint)
    manifest = {
        "schema": "bind-my-soul/restoration-share-manifest",
        "version": 2,
        "format": "BMSR2",
        "contractVersion": "1",
        "createdAt": "2026-09-09T07:37:15.934Z",
        "accountUsername": "tester",
        "entries": [{
            "packagePath": package_path,
            "packageSha256": sha(package),
            "checkpointSha256": digest,
            "checkpointByteLength": len(checkpoint),
            "checkpointVersion": 2,
            "standard": "bms-character-v2",
            "sealedAt": "2026-09-09T06:58:27.000Z",
            "localSequence": 2,
            "characterKey": "area-52:0x1",
            "characterName": "Probethree",
            "realmSlug": "area-52",
            "realmName": "Area 52 - Free-Pick",
            "coveragePercentage": 75,
            "coverageComplete": False,
        }],
        "roster": {
            "snapshotAt": "2026-09-09T07:22:14.916Z",
            "scope": "all-account-latest",
            "characterCount": 1,
            "checkpointSha256s": [digest],
        },
        "partIndex": 1,
    }
    if mutate_manifest is not None:
        mutate_manifest(manifest)
    manifest_bytes = json.dumps(manifest, indent=2).encode("utf-8")
    receipt = {
        "receiptSchema": "bind-my-soul/restoration-export-receipt",
        "receiptVersion": 2,
        "format": "BMSR2",
        "service": "bindmysoul.com",
        "manifestSha256": "0" * 64,
        "checkpointSha256s": [d for e in manifest["entries"]
                              for d in [e.get("checkpointSha256")]],
        "trustLevel": "account-authorized-export",
        "signatureAlgorithm": "ed25519",
        "signatureKeyId": "bms-ed25519-test",
    }
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("restoration-share-manifest.json", manifest_bytes)
        if not omit_receipt:
            archive.writestr("service-export-receipt.json", json.dumps(receipt, indent=2))
            archive.writestr("BUNDLE-FINGERPRINT.txt", "BMSR2\n%s\n" % receipt["manifestSha256"])
        if not omit_package and manifest["entries"]:
            archive.writestr(manifest["entries"][0]["packagePath"], package)
    return path


class BundleFixture(unittest.TestCase):
    def setUp(self):
        import tempfile

        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)

    def path(self, name: str = "b.bmsr.zip") -> str:
        return os.path.join(self._dir.name, name)

    def checks(self, bundle) -> dict[str, bool]:
        return {check.label: check.ok for check in bundle.all_checks}


class HappyPathTests(BundleFixture):
    def test_a_well_formed_bundle_verifies(self):
        bundle = read_bundle(build_bundle(self.path()))
        self.assertTrue(bundle.verified, bundle.failures)
        self.assertEqual(bundle.codes, [CODE])
        self.assertEqual(bundle.entries[0].character_name, "Probethree")
        self.assertEqual(bundle.entries[0].realm_name, "Area 52 - Free-Pick")
        self.assertEqual(bundle.account_username, "tester")

    def test_every_content_check_passes(self):
        bundle = read_bundle(build_bundle(self.path()))
        for label in ("package digest", "checkpoint digest", "checkpoint length",
                      "digest in the roster", "digest in the signed receipt",
                      "package manifest agrees", "hash receipt agrees"):
            self.assertTrue(self.checks(bundle)[label], label)

    def test_manifest_fingerprint_is_reported_but_never_enforced(self):
        """It is not sha256 of the manifest file; a bundle must not fail over it."""
        bundle = read_bundle(build_bundle(self.path()))
        note = next(c for c in bundle.checks if c.label == "manifest fingerprint")
        self.assertFalse(note.fatal)
        self.assertTrue(bundle.verified)

    def test_is_bundle_discriminates(self):
        self.assertTrue(is_bundle(build_bundle(self.path())))
        plain = self.path("plain.txt")
        with open(plain, "w", encoding="utf-8") as handle:
            handle.write(CODE)
        self.assertFalse(is_bundle(plain))
        self.assertFalse(is_bundle(self.path("missing.zip")))

    def test_render_mentions_the_unchecked_signature(self):
        text = render_bundle(read_bundle(build_bundle(self.path())))
        self.assertIn("ed25519", text)
        self.assertIn("Probethree", text)


class TamperTests(BundleFixture):
    """A changed byte must surface as a failed check, not a silent import."""

    def test_edited_checkpoint_fails_the_digest(self):
        package = build_package(CODE.replace("Probethree", "Probefaked"))
        path = build_bundle(self.path(), package=package)   # manifest still hashes the original
        bundle = read_bundle(path)
        self.assertFalse(bundle.verified)
        self.assertFalse(self.checks(bundle)["checkpoint digest"])
        self.assertTrue(self.checks(bundle)["package digest"])

    def test_repacked_package_fails_the_package_digest(self):
        path = build_bundle(self.path())
        with zipfile.ZipFile(path) as archive:
            members = {name: archive.read(name) for name in archive.namelist()}
        members["packages/001-probe-aaaa.zip"] = build_package(CODE) + b"\x00"
        with zipfile.ZipFile(path, "w") as archive:
            for name, blob in members.items():
                archive.writestr(name, blob)
        bundle = read_bundle(path)
        self.assertFalse(bundle.verified)
        self.assertFalse(self.checks(bundle)["package digest"])

    def test_a_digest_missing_from_the_signed_receipt_fails(self):
        """Swapping in another character's checkpoint breaks the signed binding."""
        other = CODE.replace("Probethree", "Somebodyelse")

        # The manifest and package are self-consistent for the swapped-in character;
        # only the signed receipt still names the original, which is the whole point.
        path = build_bundle(self.path(), code=other, package=build_package(other))
        with zipfile.ZipFile(path) as archive:
            members = {name: archive.read(name) for name in archive.namelist()}
        receipt = json.loads(members["service-export-receipt.json"])
        receipt["checkpointSha256s"] = [sha(CODE.encode("utf-8"))]
        members["service-export-receipt.json"] = json.dumps(receipt).encode("utf-8")
        with zipfile.ZipFile(path, "w") as archive:
            for name, blob in members.items():
                archive.writestr(name, blob)
        bundle = read_bundle(path)
        self.assertFalse(bundle.verified)
        self.assertFalse(self.checks(bundle)["digest in the signed receipt"])
        self.assertTrue(self.checks(bundle)["checkpoint digest"])

    def test_truncated_checkpoint_fails_the_length(self):
        short = CODE[:-10]
        path = build_bundle(self.path(), code=short)
        with zipfile.ZipFile(path) as archive:
            members = {name: archive.read(name) for name in archive.namelist()}
        manifest = json.loads(members["restoration-share-manifest.json"])
        manifest["entries"][0]["checkpointByteLength"] = len(CODE)
        members["restoration-share-manifest.json"] = json.dumps(manifest).encode("utf-8")
        with zipfile.ZipFile(path, "w") as archive:
            for name, blob in members.items():
                archive.writestr(name, blob)
        bundle = read_bundle(path)
        self.assertFalse(self.checks(bundle)["checkpoint length"])

    def test_missing_receipt_is_fatal(self):
        bundle = read_bundle(build_bundle(self.path(), omit_receipt=True))
        self.assertFalse(bundle.verified)
        self.assertFalse(self.checks(bundle)["export receipt present"])

    def test_roster_count_disagreement_is_reported(self):
        def bump(manifest):
            manifest["roster"]["characterCount"] = 4

        bundle = read_bundle(build_bundle(self.path(), mutate_manifest=bump))
        self.assertFalse(self.checks(bundle)["entry count"])


class HostileInputTests(BundleFixture):
    """The bundle is an upload. Reading one must not be able to hurt the host."""

    def test_package_path_escaping_the_zip_is_refused(self):
        for evil in ("../../../etc/passwd.zip", "packages/../../x.zip",
                     "C:/Windows/System32/x.zip", "packages/sub/dir.zip"):
            path = build_bundle(self.path("evil.zip"), package_path=evil, omit_package=True)
            with self.assertRaises(BundleError) as caught:
                read_bundle(path)
            self.assertIn("packages/", str(caught.exception))

    def test_a_missing_package_is_refused(self):
        path = build_bundle(self.path(), omit_package=True)
        with self.assertRaisesRegex(BundleError, "has no packages/"):
            read_bundle(path)

    def test_a_zip_bomb_is_refused_before_it_expands(self):
        path = self.path("bomb.zip")
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("restoration-share-manifest.json", "{}")
            archive.writestr("big.bin", b"\x00" * (33 * 1024 * 1024))
        with self.assertRaisesRegex(BundleError, "ceiling"):
            read_bundle(path)

    def test_too_many_members_is_refused(self):
        path = self.path("many.zip")
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("restoration-share-manifest.json", "{}")
            for index in range(600):
                archive.writestr("f%d" % index, b"x")
        with self.assertRaisesRegex(BundleError, "ceiling"):
            read_bundle(path)

    def test_a_non_bmsp_payload_is_refused(self):
        path = build_bundle(self.path(), code="print('hello')")
        with self.assertRaisesRegex(BundleError, "BMSP envelope"):
            read_bundle(path)

    def test_a_plain_zip_is_refused_with_a_reason(self):
        path = self.path("plain.zip")
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("readme.txt", "nothing to see")
        with self.assertRaisesRegex(BundleError, "not a Bind My Soul restoration bundle"):
            read_bundle(path)

    def test_an_unknown_format_is_refused_rather_than_guessed(self):
        def future(manifest):
            manifest["format"] = "BMSR9"

        with self.assertRaisesRegex(BundleError, "not supported"):
            read_bundle(build_bundle(self.path(), mutate_manifest=future))

    def test_an_empty_entry_list_is_refused(self):
        def empty(manifest):
            manifest["entries"] = []

        with self.assertRaisesRegex(BundleError, "no character entries"):
            read_bundle(build_bundle(self.path(), mutate_manifest=empty))

    def test_a_corrupt_zip_is_refused(self):
        path = self.path("corrupt.zip")
        with open(path, "wb") as handle:
            handle.write(b"PK\x03\x04 not really a zip")
        self.assertFalse(is_bundle(path))
        with self.assertRaises(BundleError):
            read_bundle(path)


class MultiCharacterTests(BundleFixture):
    def test_two_characters_are_both_read_and_both_verified(self):
        second = CODE.replace("Probethree", "Secondchar")
        path = self.path("two.zip")
        pkg_a, pkg_b = build_package(CODE), build_package(second)
        entries = []
        for order, (code, pkg) in enumerate(((CODE, pkg_a), (second, pkg_b)), start=1):
            blob = code.encode("utf-8")
            entries.append({
                "packagePath": "packages/%03d-c.zip" % order,
                "packageSha256": sha(pkg),
                "checkpointSha256": sha(blob),
                "checkpointByteLength": len(blob),
                "characterName": "Probethree" if order == 1 else "Secondchar",
                "realmName": "Area 52 - Free-Pick",
            })
        digests = [e["checkpointSha256"] for e in entries]
        manifest = {
            "schema": "bind-my-soul/restoration-share-manifest",
            "version": 2, "format": "BMSR2", "accountUsername": "tester",
            "createdAt": "2026-09-09T07:37:15.934Z", "partIndex": 1,
            "entries": entries,
            "roster": {"characterCount": 2, "checkpointSha256s": digests},
        }
        receipt = {"service": "bindmysoul.com", "manifestSha256": "0" * 64,
                   "checkpointSha256s": digests, "signatureKeyId": "k"}
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("restoration-share-manifest.json", json.dumps(manifest, indent=2))
            archive.writestr("service-export-receipt.json", json.dumps(receipt))
            archive.writestr("BUNDLE-FINGERPRINT.txt", "BMSR2\n%s\n" % ("0" * 64))
            archive.writestr("packages/001-c.zip", pkg_a)
            archive.writestr("packages/002-c.zip", pkg_b)
        bundle = read_bundle(path)
        self.assertTrue(bundle.verified, bundle.failures)
        self.assertEqual([e.character_name for e in bundle.entries],
                         ["Probethree", "Secondchar"])
        self.assertEqual(bundle.codes, [CODE, second])


# Point this at a .bmsr.zip you downloaded to exercise the reader against a
# real, unmodified service bundle. None is committed: a bundle names the account
# that exported it, and the characters inside it belong to somebody.
REAL_BUNDLE = os.environ.get("BMS_TEST_BUNDLE", "")


@unittest.skipUnless(os.path.isfile(REAL_BUNDLE),
                     "set $BMS_TEST_BUNDLE to a .bmsr.zip to run these")
class RealDownloadTests(unittest.TestCase):
    """The bundle bindmysoul.com actually served, unmodified."""

    @classmethod
    def setUpClass(cls):
        cls.bundle = read_bundle(REAL_BUNDLE)

    def test_it_verifies(self):
        self.assertTrue(self.bundle.verified, self.bundle.failures)

    def test_it_carries_one_parseable_checkpoint(self):
        from bms_parse import parse_checkpoint

        self.assertEqual(len(self.bundle.entries), 1)
        checkpoint = parse_checkpoint(self.bundle.codes[0])
        self.assertEqual(checkpoint.character.get("name"), "Probethree")
        self.assertEqual(checkpoint.character.get("level"), 20)

    def test_the_index_matches_the_checkpoint_inside(self):
        from bms_parse import parse_checkpoint

        entry = self.bundle.entries[0]
        checkpoint = parse_checkpoint(entry.code)
        self.assertEqual(entry.character_name, checkpoint.character.get("name"))
        self.assertEqual(entry.realm_name, checkpoint.character.get("realmName"))

    def test_the_declared_fingerprint_is_not_the_manifest_digest(self):
        """Pins the finding: don't let a future change start enforcing it."""
        with zipfile.ZipFile(REAL_BUNDLE) as archive:
            raw = archive.read("restoration-share-manifest.json")
        self.assertNotEqual(sha(raw), self.bundle.receipt.get("manifestSha256"))
        for variant in (json.dumps(json.loads(raw), separators=(",", ":")),
                        json.dumps(json.loads(raw), separators=(",", ":"), sort_keys=True),
                        json.dumps(json.loads(raw), indent=2),
                        json.dumps(json.loads(raw), indent=2) + "\n"):
            self.assertNotEqual(sha(variant.encode("utf-8")),
                                self.bundle.receipt.get("manifestSha256"))

    def test_copy_is_untouched(self):
        """Reading must never rewrite the download."""
        before = os.stat(REAL_BUNDLE)
        read_bundle(REAL_BUNDLE)
        after = os.stat(REAL_BUNDLE)
        self.assertEqual((before.st_size, before.st_mtime), (after.st_size, after.st_mtime))


if __name__ == "__main__":
    unittest.main(verbosity=2)
