#!/usr/bin/env python3
"""Read a Bind My Soul restoration bundle -- the .bmsr.zip the website hands out.

This is what a user actually downloads, so it is the importer's real front door.
The SavedVariables path stays supported for people who lift the code straight
out of their own client.

Layout of a BMSR2 bundle (verified against a real download):

    restoration-share-manifest.json     the index: one entry per character
    service-export-receipt.json         ed25519-signed, names every checkpoint hash
    BUNDLE-FINGERPRINT.txt              "BMSR2\\n<manifestSha256>\\n"
    packages/001-<name>-<hash12>.zip
        checkpoint.bmsp                     the BMSP2|g=...|j=... envelope
        restoration-verification-manifest.json
        service-hash-receipt.json           ed25519-signed, per checkpoint

What verifies offline, and does so completely:

    sha256(packages/NNN-....zip)  == manifest.entries[i].packageSha256
    sha256(checkpoint.bmsp)       == manifest.entries[i].checkpointSha256
    len(checkpoint.bmsp)          == manifest.entries[i].checkpointByteLength
    that same digest appears in   manifest.roster.checkpointSha256s
                                  service-export-receipt.checkpointSha256s
                                  restoration-verification-manifest.checkpointSha256
                                  service-hash-receipt.sha256

The signed export receipt names the checkpoint digest directly, so the content
chain is bound to the signature without going through the manifest at all.

What does NOT verify offline: receipt.manifestSha256 (and the identical value in
BUNDLE-FINGERPRINT.txt). It is not sha256 of the manifest file in any
serialisation -- raw bytes, compact, sorted, re-indented, with or without the
trailing newline, minus any one/two/three keys, and with createdAt swapped for
the receipt's own exportedAt were all tried and none match. The receipt is
stamped 16 ms *before* the manifest's createdAt, so the service signed a payload
it composed internally and the exporter re-stamped the manifest on the way into
the zip. Treat that field as a service-side label, and say so rather than
pretending the bundle failed.

Verifying the ed25519 signatures needs the service public key from
https://bindmysoul.com/checkpoint-receipt-public-key.txt -- a network fetch, so
it is deliberately not done here.

The bundle is untrusted upload input: nothing is extracted to disk, member names
are matched exactly or validated against a strict pattern, and both member count
and uncompressed size are capped.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import zipfile
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "BundleError",
    "Bundle",
    "BundleEntry",
    "BundleCheck",
    "MANIFEST_NAME",
    "is_bundle",
    "read_bundle",
]

MANIFEST_NAME = "restoration-share-manifest.json"
RECEIPT_NAME = "service-export-receipt.json"
FINGERPRINT_NAME = "BUNDLE-FINGERPRINT.txt"
INNER_CHECKPOINT = "checkpoint.bmsp"
INNER_MANIFEST = "restoration-verification-manifest.json"
INNER_RECEIPT = "service-hash-receipt.json"

MANIFEST_SCHEMA = "bind-my-soul/restoration-share-manifest"
SUPPORTED_FORMATS = ("BMSR2",)

# Zip-bomb and traversal guards. A real bundle is a few tens of KB per
# character; these ceilings are three orders of magnitude clear of that.
MAX_MEMBERS = 512
MAX_TOTAL_UNCOMPRESSED = 256 * 1024 * 1024
MAX_MEMBER_UNCOMPRESSED = 32 * 1024 * 1024
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_CHECKPOINT_BYTES = 4_000_000
PACKAGE_PATH_RE = re.compile(r"^packages/[A-Za-z0-9][A-Za-z0-9._-]{0,120}\.zip$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class BundleError(Exception):
    """The bundle is not a bundle, or is structurally broken."""


@dataclass
class BundleCheck:
    """One integrity statement, and whether it held."""

    ok: bool
    label: str
    detail: str = ""
    fatal: bool = True

    @property
    def status(self) -> str:
        if self.ok:
            return "OK"
        return "FAIL" if self.fatal else "NOTE"


@dataclass
class BundleEntry:
    """One character's package inside the bundle."""

    index: int
    package_path: str
    code: str = field(repr=False, default="")
    checkpoint_sha256: str = ""
    package_sha256: str = ""
    byte_length: int = 0
    character_name: str = ""
    character_key: str = ""
    realm_name: str = ""
    realm_slug: str = ""
    coverage_percentage: Any = None
    coverage_complete: bool = False
    sealed_at: str = ""
    local_sequence: Any = None
    standard: str = ""
    checkpoint_version: Any = None
    checks: list[BundleCheck] = field(default_factory=list)

    @property
    def verified(self) -> bool:
        return all(check.ok for check in self.checks if check.fatal)

    @property
    def label(self) -> str:
        return "%s @ %s" % (self.character_name or "?", self.realm_name or "?")


@dataclass
class Bundle:
    """A parsed .bmsr.zip."""

    path: str
    format: str
    manifest: dict[str, Any]
    receipt: dict[str, Any]
    fingerprint: str
    account_username: str
    created_at: str
    part_index: Any
    entries: list[BundleEntry]
    checks: list[BundleCheck]

    @property
    def verified(self) -> bool:
        bundle_ok = all(check.ok for check in self.checks if check.fatal)
        return bundle_ok and all(entry.verified for entry in self.entries)

    @property
    def codes(self) -> list[str]:
        return [entry.code for entry in self.entries]

    @property
    def all_checks(self) -> list[BundleCheck]:
        out = list(self.checks)
        for entry in self.entries:
            out.extend(entry.checks)
        return out

    @property
    def failures(self) -> list[BundleCheck]:
        return [check for check in self.all_checks if not check.ok and check.fatal]


# --------------------------------------------------------------------------
# reading
# --------------------------------------------------------------------------

def is_bundle(path: str) -> bool:
    """True when path is a zip carrying a restoration share manifest.

    Cheap and non-throwing: used to pick a loader, not to validate.
    """
    if not os.path.isfile(path):
        return False
    try:
        with zipfile.ZipFile(path) as archive:
            return MANIFEST_NAME in archive.namelist()
    except (zipfile.BadZipFile, OSError):
        return False


def _guard_archive(archive: zipfile.ZipFile, what: str) -> None:
    infos = archive.infolist()
    if len(infos) > MAX_MEMBERS:
        raise BundleError("%s holds %d members; the ceiling is %d."
                          % (what, len(infos), MAX_MEMBERS))
    total = 0
    for info in infos:
        if info.is_dir():
            continue
        if info.file_size > MAX_MEMBER_UNCOMPRESSED:
            raise BundleError("%s: member %r expands to %d bytes; the ceiling is %d."
                              % (what, info.filename, info.file_size, MAX_MEMBER_UNCOMPRESSED))
        total += info.file_size
    if total > MAX_TOTAL_UNCOMPRESSED:
        raise BundleError("%s expands to %d bytes; the ceiling is %d."
                          % (what, total, MAX_TOTAL_UNCOMPRESSED))


def _read_member(archive: zipfile.ZipFile, name: str, what: str) -> bytes:
    try:
        return archive.read(name)
    except KeyError:
        raise BundleError("%s has no %s." % (what, name)) from None


def _read_json(archive: zipfile.ZipFile, name: str, what: str) -> dict[str, Any]:
    raw = _read_member(archive, name, what)
    if len(raw) > MAX_JSON_BYTES:
        raise BundleError("%s: %s is %d bytes; the ceiling is %d."
                          % (what, name, len(raw), MAX_JSON_BYTES))
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise BundleError("%s: %s is not readable JSON (%s)." % (what, name, exc)) from None
    if not isinstance(value, dict):
        raise BundleError("%s: %s is not a JSON object." % (what, name))
    return value


def _digest(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def _compare(checks: list[BundleCheck], label: str, actual: str, expected: Any,
             fatal: bool = True) -> None:
    """Record a digest comparison, naming both sides when they differ."""
    if not isinstance(expected, str) or not SHA256_RE.match(expected.lower()):
        checks.append(BundleCheck(False, label, "the bundle declares no usable sha256", fatal))
        return
    expected = expected.lower()
    if actual == expected:
        checks.append(BundleCheck(True, label, actual[:16] + "...", fatal))
    else:
        checks.append(BundleCheck(
            False, label, "computed %s, bundle says %s" % (actual[:16], expected[:16]), fatal))


def _member_present(checks: list[BundleCheck], label: str, digest: str, pool: Any,
                    where: str) -> None:
    values = pool if isinstance(pool, list) else []
    lowered = {v.lower() for v in values if isinstance(v, str)}
    if digest in lowered:
        checks.append(BundleCheck(True, label, "listed in %s" % where))
    else:
        checks.append(BundleCheck(
            False, label, "%s does not list %s (it lists %d digest(s))"
            % (where, digest[:16] + "...", len(lowered))))


def read_bundle(path: str) -> Bundle:
    """Parse and verify a .bmsr.zip. Raises BundleError only on structural breakage.

    Integrity results are reported through Bundle.checks / BundleEntry.checks so
    the caller can print them and decide; a digest mismatch is data, not an
    exception.
    """
    if not os.path.isfile(path):
        raise BundleError("No such file: %s" % path)

    try:
        archive = zipfile.ZipFile(path)
    except zipfile.BadZipFile as exc:
        raise BundleError("%s is not a readable zip (%s)." % (path, exc)) from None

    with archive:
        _guard_archive(archive, os.path.basename(path))
        names = set(archive.namelist())
        if MANIFEST_NAME not in names:
            raise BundleError(
                "%s has no %s, so it is not a Bind My Soul restoration bundle."
                % (os.path.basename(path), MANIFEST_NAME))

        manifest_raw = _read_member(archive, MANIFEST_NAME, "bundle")
        manifest = _read_json(archive, MANIFEST_NAME, "bundle")
        receipt = _read_json(archive, RECEIPT_NAME, "bundle") if RECEIPT_NAME in names else {}
        fingerprint = ""
        if FINGERPRINT_NAME in names:
            fingerprint = _read_member(archive, FINGERPRINT_NAME, "bundle").decode(
                "utf-8", "replace")

        checks: list[BundleCheck] = []

        schema = manifest.get("schema")
        if schema != MANIFEST_SCHEMA:
            raise BundleError("Unexpected manifest schema %r (want %r)."
                              % (schema, MANIFEST_SCHEMA))
        fmt = str(manifest.get("format") or "")
        if fmt not in SUPPORTED_FORMATS:
            raise BundleError(
                "Bundle format %r is not supported; this importer reads %s."
                % (fmt, ", ".join(SUPPORTED_FORMATS)))

        entries_raw = manifest.get("entries")
        if not isinstance(entries_raw, list) or not entries_raw:
            raise BundleError("The manifest lists no character entries.")

        roster = manifest.get("roster") if isinstance(manifest.get("roster"), dict) else {}
        roster_digests = roster.get("checkpointSha256s")
        receipt_digests = receipt.get("checkpointSha256s")

        # -- bundle-level checks ------------------------------------------
        if receipt:
            checks.append(BundleCheck(
                True, "export receipt present",
                "%s, %s, key %s" % (receipt.get("service") or "?",
                                    receipt.get("trustLevel") or "?",
                                    receipt.get("signatureKeyId") or "?"),
                fatal=False))
        else:
            checks.append(BundleCheck(
                False, "export receipt present",
                "no %s -- the bundle carries no service signature" % RECEIPT_NAME))

        declared = str(receipt.get("manifestSha256") or "").lower()
        fingerprint_lines = [line.strip() for line in fingerprint.splitlines() if line.strip()]
        if fingerprint_lines:
            if fingerprint_lines[0] != fmt:
                checks.append(BundleCheck(
                    False, "fingerprint format tag",
                    "%s says %r, the manifest says %r"
                    % (FINGERPRINT_NAME, fingerprint_lines[0], fmt)))
            stamped = fingerprint_lines[-1].lower()
            if declared and stamped != declared:
                checks.append(BundleCheck(
                    False, "fingerprint agrees with the receipt",
                    "%s says %s, the receipt says %s"
                    % (FINGERPRINT_NAME, stamped[:16] + "...", declared[:16] + "...")))
            else:
                checks.append(BundleCheck(
                    True, "fingerprint agrees with the receipt", stamped[:16] + "...",
                    fatal=False))

        # Recorded, never enforced: see the module docstring.
        checks.append(BundleCheck(
            True, "manifest fingerprint",
            "declared %s -- a service-side label, not sha256 of the manifest file, "
            "so it is not checkable offline (computed %s)"
            % (declared[:16] + "..." if declared else "nothing",
               _digest(manifest_raw)[:16] + "..."),
            fatal=False))

        if roster_digests is not None and not isinstance(roster_digests, list):
            checks.append(BundleCheck(False, "roster digest list", "roster.checkpointSha256s "
                                                                  "is not a list"))
        declared_count = roster.get("characterCount")
        if isinstance(declared_count, int) and declared_count != len(entries_raw):
            checks.append(BundleCheck(
                False, "entry count",
                "the roster claims %d character(s), the manifest lists %d"
                % (declared_count, len(entries_raw))))

        part = manifest.get("partIndex")
        parts = manifest.get("partCount")
        if isinstance(parts, int) and parts > 1:
            checks.append(BundleCheck(
                True, "multi-part export",
                "this is part %s of %s; the other parts hold characters this one does not"
                % (part, parts), fatal=False))

        # -- per-entry checks ---------------------------------------------
        entries: list[BundleEntry] = []
        for index, raw_entry in enumerate(entries_raw):
            if not isinstance(raw_entry, dict):
                raise BundleError("Manifest entry %d is not an object." % index)
            package_path = str(raw_entry.get("packagePath") or "")
            entry = BundleEntry(
                index=index,
                package_path=package_path,
                checkpoint_sha256=str(raw_entry.get("checkpointSha256") or "").lower(),
                package_sha256=str(raw_entry.get("packageSha256") or "").lower(),
                byte_length=int(raw_entry.get("checkpointByteLength") or 0),
                character_name=str(raw_entry.get("characterName") or ""),
                character_key=str(raw_entry.get("characterKey") or ""),
                realm_name=str(raw_entry.get("realmName") or ""),
                realm_slug=str(raw_entry.get("realmSlug") or ""),
                coverage_percentage=raw_entry.get("coveragePercentage"),
                coverage_complete=bool(raw_entry.get("coverageComplete")),
                sealed_at=str(raw_entry.get("sealedAt") or ""),
                local_sequence=raw_entry.get("localSequence"),
                standard=str(raw_entry.get("standard") or ""),
                checkpoint_version=raw_entry.get("checkpointVersion"),
            )
            who = entry.label

            if not PACKAGE_PATH_RE.match(package_path):
                raise BundleError(
                    "Manifest entry %d names package path %r, which is not a plain "
                    "packages/<file>.zip. Refusing to read it." % (index, package_path))
            if package_path not in names:
                raise BundleError("The bundle has no %s, which entry %d (%s) needs."
                                  % (package_path, index, who))

            package_bytes = _read_member(archive, package_path, "bundle")
            _compare(entry.checks, "package digest", _digest(package_bytes),
                     entry.package_sha256)

            try:
                inner = zipfile.ZipFile(io.BytesIO(package_bytes))
            except zipfile.BadZipFile as exc:
                raise BundleError("%s is not a readable zip (%s)." % (package_path, exc)) from None

            with inner:
                _guard_archive(inner, package_path)
                inner_names = set(inner.namelist())
                if INNER_CHECKPOINT not in inner_names:
                    raise BundleError("%s has no %s." % (package_path, INNER_CHECKPOINT))
                checkpoint_bytes = inner.read(INNER_CHECKPOINT)
                if len(checkpoint_bytes) > MAX_CHECKPOINT_BYTES:
                    raise BundleError(
                        "%s: %s is %d bytes; the ceiling is %d."
                        % (package_path, INNER_CHECKPOINT, len(checkpoint_bytes),
                           MAX_CHECKPOINT_BYTES))

                digest = _digest(checkpoint_bytes)
                _compare(entry.checks, "checkpoint digest", digest, entry.checkpoint_sha256)

                if entry.byte_length:
                    if len(checkpoint_bytes) == entry.byte_length:
                        entry.checks.append(BundleCheck(
                            True, "checkpoint length", "%d bytes" % entry.byte_length))
                    else:
                        entry.checks.append(BundleCheck(
                            False, "checkpoint length",
                            "the file is %d bytes, the manifest says %d"
                            % (len(checkpoint_bytes), entry.byte_length)))

                _member_present(entry.checks, "digest in the roster", digest, roster_digests,
                                "manifest.roster")
                if receipt:
                    _member_present(entry.checks, "digest in the signed receipt", digest,
                                    receipt_digests, RECEIPT_NAME)

                if INNER_MANIFEST in inner_names:
                    inner_manifest = _read_json(inner, INNER_MANIFEST, package_path)
                    _compare(entry.checks, "package manifest agrees", digest,
                             str(inner_manifest.get("checkpointSha256") or "").lower())
                if INNER_RECEIPT in inner_names:
                    inner_receipt = _read_json(inner, INNER_RECEIPT, package_path)
                    _compare(entry.checks, "hash receipt agrees", digest,
                             str(inner_receipt.get("sha256") or "").lower())
                    claimed = inner_receipt.get("byteLength")
                    if isinstance(claimed, int) and claimed != len(checkpoint_bytes):
                        entry.checks.append(BundleCheck(
                            False, "hash receipt length",
                            "the receipt says %d bytes, the file is %d"
                            % (claimed, len(checkpoint_bytes))))

            try:
                entry.code = checkpoint_bytes.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise BundleError("%s: %s is not UTF-8 (%s)."
                                  % (package_path, INNER_CHECKPOINT, exc)) from None
            if not entry.code.lstrip().startswith("BMSP"):
                raise BundleError(
                    "%s: %s does not start with a BMSP envelope."
                    % (package_path, INNER_CHECKPOINT))

            entries.append(entry)

        return Bundle(
            path=path,
            format=fmt,
            manifest=manifest,
            receipt=receipt,
            fingerprint=fingerprint,
            account_username=str(manifest.get("accountUsername") or ""),
            created_at=str(manifest.get("createdAt") or ""),
            part_index=manifest.get("partIndex"),
            entries=entries,
            checks=checks,
        )


def render_bundle(bundle: Bundle) -> str:
    """A human-readable integrity report."""
    lines: list[str] = []
    lines.append("BUNDLE  %s" % os.path.basename(bundle.path))
    lines.append("  format %s   account %s   exported %s%s"
                 % (bundle.format, bundle.account_username or "?", bundle.created_at or "?",
                    "   part %s" % bundle.part_index if bundle.part_index not in (None, 1) else ""))
    lines.append("")
    for check in bundle.checks:
        lines.append("  [%-4s] %-34s %s" % (check.status, check.label, check.detail))
    for entry in bundle.entries:
        lines.append("")
        lines.append("  [%d] %s   coverage %s%%%s"
                     % (entry.index, entry.label, entry.coverage_percentage,
                        "" if entry.coverage_complete else " (incomplete)"))
        lines.append("      package %s" % entry.package_path)
        lines.append("      sealed  %s   sequence %s   standard %s"
                     % (entry.sealed_at or "?", entry.local_sequence, entry.standard or "?"))
        for check in entry.checks:
            lines.append("      [%-4s] %-30s %s" % (check.status, check.label, check.detail))
    lines.append("")
    if bundle.verified:
        lines.append("  Integrity: every offline check passed. The ed25519 signature itself is "
                     "NOT checked (that needs the service public key over the network).")
    else:
        lines.append("  Integrity: %d check(s) FAILED. This bundle does not match what the "
                     "service signed." % len(bundle.failures))
    return "\n".join(lines)


if __name__ == "__main__":  # pragma: no cover - manual use
    import sys

    if len(sys.argv) != 2:
        print("usage: python bms_bundle.py <bundle.bmsr.zip>", file=sys.stderr)
        raise SystemExit(2)
    try:
        print(render_bundle(read_bundle(sys.argv[1])))
    except BundleError as error:
        print("error: %s" % error, file=sys.stderr)
        raise SystemExit(2)
