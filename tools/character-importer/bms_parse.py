#!/usr/bin/env python3
"""Read Bind My Soul preservation checkpoints out of a WoW SavedVariables file.

The addon writes its checkpoints as plain strings inside BindMySoulDB:

    BindMySoulDB.checkpointExport       -- latest checkpoint code
    BindMySoulDB.checkpointQueueExport  -- up to 4 older codes, newline joined

Each code is the envelope produced by Protocol.SerializeCheckpoint:

    BMSP2|g=<unix seconds>|j=<deterministic JSON>
    BMSP1|g=<unix seconds>|d=<percent-encoded JSON>   (legacy)

There is no compression, no encryption and -- despite what the addon's own
integrity block says -- no hash. `integrity.sealStatus` is the literal string
"pending-companion-hash"; the addon never computes a digest. Treat a checkpoint
as trusted-source data, not as tamper-evident.

Validation here mirrors Protocol.ParseCheckpoint (Protocol.lua:460) exactly, so
a payload this module accepts is one the addon would also accept.

Usage:
    python bms_parse.py <BindMySoul.lua | WTF account dir | code file> --summary
    python bms_parse.py <path> --list
    python bms_parse.py <path> --index 0 --json out.json
    python bms_parse.py <path> --out-dir ./checkpoints
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import bms_bundle  # noqa: E402

__all__ = [
    "BmsError",
    "Checkpoint",
    "capability_map",
    "parse_lua",
    "load_savedvariables",
    "extract_checkpoint_codes",
    "parse_checkpoint",
    "percent_decode",
    "summarize",
]

CHECKPOINT_SCHEMA = "bind-my-soul/preservation-checkpoint"
MAX_CHECKPOINT_BYTES = 4_000_000

# prefix -> (version, coverage standard, permitted envelope encodings)
_PREFIXES = {
    "BMSP2": (2, "bms-character-v2", ("j",)),
    "BMSP1": (1, "bms-character-v1", ("d",)),
}

_ENVELOPE_RE = re.compile(r"^(BMSP\d+)\|g=(\d+)\|([dj])=(.+)$", re.DOTALL)


class BmsError(Exception):
    """A checkpoint or SavedVariables file could not be read."""


# --------------------------------------------------------------------------
# Lua SavedVariables parser
# --------------------------------------------------------------------------
#
# SavedVariables is a restricted Lua subset: a sequence of `NAME = <value>`
# assignments where values are nil/booleans/numbers/strings/tables. We parse it
# directly rather than shelling out to a Lua interpreter, because the file is
# untrusted input and executing it would be a code-execution primitive.

_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_NUMBER_RE = re.compile(
    r"-?(?:0[xX][0-9a-fA-F]+|(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?)"
)
_LONG_OPEN_RE = re.compile(r"\[(=*)\[")

_SIMPLE_ESCAPES = {
    "a": "\a",
    "b": "\b",
    "f": "\f",
    "n": "\n",
    "r": "\r",
    "t": "\t",
    "v": "\v",
    "\\": "\\",
    '"': '"',
    "'": "'",
    "\n": "\n",
}


class _LuaParser:
    def __init__(self, text: str) -> None:
        self.s = text
        self.i = 0
        self.n = len(text)

    # -- helpers ----------------------------------------------------------
    def _fail(self, message: str) -> "BmsError":
        line = self.s.count("\n", 0, self.i) + 1
        return BmsError(f"{message} (line {line}, byte {self.i})")

    def _skip(self) -> None:
        s, n = self.s, self.n
        while self.i < n:
            ch = s[self.i]
            if ch in " \t\r\n":
                self.i += 1
                continue
            if ch == "-" and s.startswith("--", self.i):
                self.i += 2
                long_open = _LONG_OPEN_RE.match(s, self.i)
                if long_open:
                    self._long_bracket(long_open)
                    continue
                nl = s.find("\n", self.i)
                self.i = n if nl < 0 else nl + 1
                continue
            return

    def _long_bracket(self, match: re.Match) -> str:
        """Consume a [[...]] / [==[...]==] literal, returning its contents."""
        close = "]" + match.group(1) + "]"
        start = match.end()
        if start < self.n and self.s[start] == "\n":  # Lua drops a leading newline
            start += 1
        end = self.s.find(close, start)
        if end < 0:
            raise self._fail("Unterminated long bracket")
        self.i = end + len(close)
        return self.s[start:end]

    # -- scalars ----------------------------------------------------------
    def _string(self) -> str:
        quote = self.s[self.i]
        self.i += 1
        out: list[str] = []
        s, n = self.s, self.n
        while True:
            if self.i >= n:
                raise self._fail("Unterminated string")
            # Fast path: copy up to the next quote or backslash in one slice.
            nxt = self.i
            while nxt < n and s[nxt] != quote and s[nxt] != "\\":
                nxt += 1
            if nxt > self.i:
                out.append(s[self.i : nxt])
                self.i = nxt
            if self.i >= n:
                raise self._fail("Unterminated string")
            if s[self.i] == quote:
                self.i += 1
                return "".join(out)
            # Escape sequence.
            self.i += 1
            if self.i >= n:
                raise self._fail("Truncated escape sequence")
            esc = s[self.i]
            if esc in _SIMPLE_ESCAPES:
                out.append(_SIMPLE_ESCAPES[esc])
                self.i += 1
            elif esc.isdigit():
                digits = ""
                while self.i < n and len(digits) < 3 and s[self.i].isdigit():
                    digits += s[self.i]
                    self.i += 1
                code = int(digits)
                if code > 255:
                    raise self._fail(f"Decimal escape \\{digits} out of range")
                out.append(chr(code))
            elif esc in "xX":  # Lua 5.2+, tolerated
                hex_digits = s[self.i + 1 : self.i + 3]
                if len(hex_digits) != 2 or not re.fullmatch(r"[0-9a-fA-F]{2}", hex_digits):
                    raise self._fail("Invalid hex escape")
                out.append(chr(int(hex_digits, 16)))
                self.i += 3
            else:
                # Unknown escape: keep the character, matching lenient readers.
                out.append(esc)
                self.i += 1

    def _number(self) -> float | int:
        match = _NUMBER_RE.match(self.s, self.i)
        if not match:
            raise self._fail("Invalid number")
        self.i = match.end()
        text = match.group(0)
        negative = text.startswith("-")
        body = text[1:] if negative else text
        if body[:2].lower() == "0x":
            value: float | int = int(body, 16)
        elif any(c in body for c in ".eE"):
            value = float(body)
        else:
            value = int(body)
        return -value if negative else value

    # -- composites -------------------------------------------------------
    def _table(self, arrayify: bool) -> Any:
        self.i += 1  # consume '{'
        items: dict[Any, Any] = {}
        positional = 1
        while True:
            self._skip()
            if self.i >= self.n:
                raise self._fail("Unterminated table")
            ch = self.s[self.i]
            if ch == "}":
                self.i += 1
                break
            if ch in ",;":
                self.i += 1
                continue
            if ch == "[":
                long_open = _LONG_OPEN_RE.match(self.s, self.i)
                if long_open:  # a bare long-string element, not a key
                    items[positional] = self._long_bracket(long_open)
                    positional += 1
                    continue
                self.i += 1
                key = self._value(arrayify)
                self._skip()
                if self.i >= self.n or self.s[self.i] != "]":
                    raise self._fail("Expected ']' after table key")
                self.i += 1
                self._skip()
                if self.i >= self.n or self.s[self.i] != "=":
                    raise self._fail("Expected '=' after table key")
                self.i += 1
                items[key] = self._value(arrayify)
                continue
            name_match = _NAME_RE.match(self.s, self.i)
            if name_match:
                after = name_match.end()
                probe = after
                while probe < self.n and self.s[probe] in " \t\r\n":
                    probe += 1
                # `name = value` is a keyed entry; anything else is positional
                # (e.g. the bare keyword `true`).
                if probe < self.n and self.s[probe] == "=" and self.s[probe : probe + 2] != "==":
                    self.i = probe + 1
                    items[name_match.group(0)] = self._value(arrayify)
                    continue
            items[positional] = self._value(arrayify)
            positional += 1

        if arrayify and items and all(
            isinstance(k, int) and not isinstance(k, bool) for k in items
        ):
            keys = sorted(items)
            if keys == list(range(1, len(keys) + 1)):
                return [items[k] for k in keys]
        return items

    def _value(self, arrayify: bool) -> Any:
        self._skip()
        if self.i >= self.n:
            raise self._fail("Expected a value")
        ch = self.s[self.i]
        if ch in "\"'":
            return self._string()
        if ch == "{":
            return self._table(arrayify)
        if ch == "[":
            long_open = _LONG_OPEN_RE.match(self.s, self.i)
            if long_open:
                return self._long_bracket(long_open)
            raise self._fail("Unexpected '['")
        if ch == "-" and not self.s.startswith("--", self.i):
            return self._number()
        if ch.isdigit() or ch == ".":
            return self._number()
        name_match = _NAME_RE.match(self.s, self.i)
        if name_match:
            word = name_match.group(0)
            if word in ("true", "false", "nil", "inf", "nan"):
                self.i = name_match.end()
                return {
                    "true": True,
                    "false": False,
                    "nil": None,
                    "inf": float("inf"),
                    "nan": float("nan"),
                }[word]
        raise self._fail("Unexpected token")

    def parse_chunk(self, arrayify: bool) -> dict[str, Any]:
        globals_: dict[str, Any] = {}
        while True:
            self._skip()
            if self.i >= self.n:
                return globals_
            if self.s[self.i] == ";":
                self.i += 1
                continue
            name_match = _NAME_RE.match(self.s, self.i)
            if not name_match:
                raise self._fail("Expected a global assignment")
            name = name_match.group(0)
            self.i = name_match.end()
            if name == "local":  # tolerate `local X = ...`
                continue
            self._skip()
            if self.i >= self.n or self.s[self.i] != "=":
                raise self._fail(f"Expected '=' after {name!r}")
            self.i += 1
            globals_[name] = self._value(arrayify)


def parse_lua(text: str, arrayify: bool = True) -> dict[str, Any]:
    """Parse a SavedVariables chunk into a dict of its global assignments.

    With `arrayify`, tables whose keys are exactly 1..n become Python lists,
    which is what the addon's own array tables (checkpointHistory, domains,
    equipment, ...) mean.
    """
    return _LuaParser(text).parse_chunk(arrayify)


def _read_text(path: str) -> str:
    with open(path, "rb") as handle:
        raw = handle.read()
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]
    for encoding in ("utf-8", "cp1252", "latin-1"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode("latin-1", errors="replace")


def load_savedvariables(path: str, variable: str = "BindMySoulDB") -> dict[str, Any]:
    """Load one SavedVariables global out of `path`."""
    globals_ = parse_lua(_read_text(path))
    if variable not in globals_:
        found = ", ".join(sorted(globals_)) or "nothing"
        raise BmsError(f"{path} defines {found}; expected {variable}.")
    db = globals_[variable]
    if not isinstance(db, dict):
        raise BmsError(f"{variable} in {path} is not a table.")
    return db


# --------------------------------------------------------------------------
# Checkpoint envelope
# --------------------------------------------------------------------------

_PERCENT_PAIR_RE = re.compile(r"%([0-9a-fA-F]{2})")


def percent_decode(value: str) -> str:
    """Mirror Protocol.Decode, including its strict leftover-'%' rejection."""
    if "%" in _PERCENT_PAIR_RE.sub("", value):
        raise BmsError("Invalid percent encoding.")
    return _PERCENT_PAIR_RE.sub(lambda m: chr(int(m.group(1), 16)), value)


@dataclass
class Checkpoint:
    """One validated checkpoint."""

    prefix: str
    version: int
    sealed_at: int
    data: dict[str, Any]
    code: str = field(repr=False, default="")

    @property
    def character(self) -> dict[str, Any]:
        return self.data.get("character") or {}

    @property
    def coverage(self) -> dict[str, Any]:
        return self.data.get("coverage") or {}

    @property
    def name(self) -> str:
        return str(self.character.get("name") or "?")

    @property
    def realm(self) -> str:
        return str(self.character.get("realmName") or "?")

    @property
    def bytes(self) -> int:
        return len(self.code.encode("utf-8"))

    @property
    def capabilities(self) -> dict[str, dict[str, Any]]:
        """Capability records keyed by name. See capability_map()."""
        return capability_map(self.character)


def capability_map(character: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Normalise character.capabilities into a name -> record mapping.

    The addon builds this with table.insert (Core.lua:228), so it serialises as
    a JSON *array* of {key, available, sourceApi, note} records, not as an
    object. Older/legacy payloads used a keyed object, so accept both.
    """
    raw = character.get("capabilities")
    result: dict[str, dict[str, Any]] = {}
    if isinstance(raw, list):
        for record in raw:
            if isinstance(record, dict) and record.get("key"):
                result[str(record["key"])] = record
    elif isinstance(raw, dict):
        for key, record in raw.items():
            if isinstance(record, dict):
                result[str(key)] = {"key": str(key), **record}
    return result


def parse_checkpoint(code: str) -> Checkpoint:
    """Decode and validate one BMSP envelope.

    Applies exactly the checks Protocol.ParseCheckpoint applies, in the same
    order, so acceptance here matches the addon's own reader.
    """
    code = code.strip()
    if len(code) > MAX_CHECKPOINT_BYTES:
        raise BmsError("The character checkpoint is too large.")

    match = _ENVELOPE_RE.match(code)
    if not match:
        raise BmsError("That is not a Bind My Soul preservation checkpoint.")
    prefix, generated_at, encoding, encoded = match.groups()
    if prefix not in _PREFIXES:
        raise BmsError(f"Unsupported checkpoint prefix {prefix!r}.")

    version, standard, allowed_encodings = _PREFIXES[prefix]
    if encoding not in allowed_encodings:
        raise BmsError(f"{prefix} checkpoints cannot use encoding {encoding!r}.")

    envelope_timestamp = int(generated_at)
    if not 1 <= envelope_timestamp <= 9_999_999_999:
        raise BmsError("The checkpoint timestamp is invalid.")

    payload = percent_decode(encoded) if encoding == "d" else encoded
    try:
        data = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise BmsError(f"The checkpoint JSON is malformed: {exc}") from exc

    if not isinstance(data, dict):
        raise BmsError("The checkpoint schema is not supported.")
    if data.get("schema") != CHECKPOINT_SCHEMA or data.get("version") != version:
        raise BmsError("The checkpoint schema is not supported.")

    sealed_at = data.get("sealedAt")
    if not isinstance(sealed_at, int) or isinstance(sealed_at, bool):
        raise BmsError("The checkpoint timestamp is invalid.")
    if sealed_at != envelope_timestamp:
        raise BmsError("The checkpoint envelope timestamp does not match its payload.")

    character = data.get("character")
    if (
        not isinstance(character, dict)
        or not str(character.get("name") or "").strip()
        or not str(character.get("realmName") or "").strip()
    ):
        raise BmsError("The checkpoint character identity is incomplete.")

    coverage = data.get("coverage")
    if (
        not isinstance(coverage, dict)
        or coverage.get("standard") != standard
        or not isinstance(coverage.get("domains"), list)
    ):
        raise BmsError("The checkpoint coverage record is incomplete.")

    return Checkpoint(
        prefix=prefix,
        version=version,
        sealed_at=sealed_at,
        data=data,
        code=code,
    )


def extract_checkpoint_codes(db: dict[str, Any]) -> list[str]:
    """Return every checkpoint code in a BindMySoulDB, latest first.

    Reads checkpointExport (latest), then checkpointQueueExport (newline
    joined history), then the legacy checkpointQueue table that older addon
    releases wrote, de-duplicating while preserving order.
    """
    codes: list[str] = []
    seen: set[str] = set()

    def add(value: Any) -> None:
        if not isinstance(value, str):
            return
        candidate = value.strip()
        if candidate.startswith(("BMSP1|", "BMSP2|")) and candidate not in seen:
            seen.add(candidate)
            codes.append(candidate)

    add(db.get("checkpointExport"))
    queue_export = db.get("checkpointQueueExport")
    if isinstance(queue_export, str):
        for line in queue_export.splitlines():
            add(line)
    legacy = db.get("checkpointQueue")
    if isinstance(legacy, list):
        for value in legacy:
            add(value)
    elif isinstance(legacy, dict):
        for _, value in sorted(legacy.items(), key=lambda kv: str(kv[0])):
            add(value)
    return codes


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------

_COUNTED_SECTIONS = [
    ("equipment", "equipment"),
    ("bags", "bags"),
    ("knownSpellIds", "known spells"),
    ("knownMysticSpellIds", "known mystics"),
    ("appliedMysticSpellIds", "applied mystics"),
    ("currencies", "currencies"),
    ("skills", "skills"),
    ("reputations", "reputations"),
    ("titles", "titles"),
    ("glyphs", "glyphs"),
]


def _count(value: Any) -> int | None:
    if isinstance(value, list):
        return len(value)
    if isinstance(value, dict):
        # The addon writes explicit *Count fields alongside the arrays and they
        # are authoritative: a deep achievement scan can report a count while
        # the array itself is bounded.
        for key in ("completedCount", "occupiedCount", "knownCount"):
            if isinstance(value.get(key), int) and not isinstance(value[key], bool):
                return value[key]
        for key in ("known", "occupied", "completed", "items", "catalogs", "active"):
            inner = value.get(key)
            if isinstance(inner, list):
                return len(inner)
    return None


def _money(copper: Any) -> str:
    if not isinstance(copper, int) or isinstance(copper, bool):
        return "unknown"
    gold, rest = divmod(copper, 10_000)
    silver, bronze = divmod(rest, 100)
    return f"{gold:,}g {silver}s {bronze}c"


def summarize(checkpoint: Checkpoint) -> str:
    import datetime as _dt

    char = checkpoint.character
    coverage = checkpoint.coverage
    data = checkpoint.data
    sealed = _dt.datetime.fromtimestamp(checkpoint.sealed_at).strftime("%Y-%m-%d %H:%M:%S")
    mode = char.get("gameMode") or {}
    integrity = data.get("integrity") or {}

    lines: list[str] = []
    lines.append(f"{char.get('name')} - {char.get('realmName')}")
    lines.append("=" * max(24, len(lines[0])))
    lines.append(
        f"  level {char.get('level')} {char.get('raceName')} {char.get('className')}"
        f" ({char.get('faction')})"
    )
    lines.append(f"  mode        {mode.get('label')} [{mode.get('id')}]")
    lines.append(f"  guid        {char.get('guid')}")
    lines.append(f"  money       {_money(char.get('money'))}")
    lines.append(f"  sealed      {sealed}  (seq {data.get('localSequence')})")
    lines.append(
        f"  envelope    {checkpoint.prefix} v{checkpoint.version},"
        f" {checkpoint.bytes:,} bytes, addon {data.get('addonVersion')}"
    )
    lines.append(
        f"  integrity   {integrity.get('sealStatus')}"
        f" / {integrity.get('evidenceLevel')} (no digest is written by the addon)"
    )

    percentage = coverage.get("percentage")
    lines.append(
        f"  coverage    {percentage}% - {coverage.get('completed')}"
        f"/{coverage.get('total')} required sources current"
    )

    lines.append("")
    lines.append("  Contents")
    for key, label in _COUNTED_SECTIONS:
        count = _count(char.get(key))
        if count is not None:
            lines.append(f"    {label:<22} {count}")
    for key, label in (
        ("actionBars", "action slots"),
        ("achievements", "achievements done"),
        ("quests", "quests active"),
        ("characterBank", "character bank"),
        ("mail", "mail"),
        ("professionRecipes", "profession catalogs"),
    ):
        count = _count(char.get(key))
        if count is not None:
            lines.append(f"    {label:<22} {count}")
    completed_quests = (char.get("quests") or {}).get("completedIds")
    if isinstance(completed_quests, list):
        lines.append(f"    {'quests completed':<22} {len(completed_quests)}")
    vaults = (data.get("sharedStorage") or {}).get("vaults")
    if isinstance(vaults, (list, dict)):
        lines.append(f"    {'shared vaults':<22} {len(vaults)}")

    domains = coverage.get("domains") or []
    if domains:
        lines.append("")
        lines.append("  Readiness domains")
        for domain in domains:
            if not isinstance(domain, dict):
                continue
            status = str(domain.get("status", "?"))
            flag = {"fresh": "ok", "stale": "STALE", "missing": "MISSING",
                    "unavailable": "N/A"}.get(status, status)
            optional = "" if domain.get("required", True) else "  (optional)"
            lines.append(f"    {flag:<8} {str(domain.get('label', domain.get('id'))):<34}{optional}")

    capabilities = capability_map(char)
    if capabilities:
        missing = sorted(k for k, r in capabilities.items() if not r.get("available"))
        available = sorted(k for k, r in capabilities.items() if r.get("available"))
        lines.append("")
        lines.append(
            f"  Capabilities  {len(available)} available, {len(missing)} unavailable"
        )
        if missing:
            lines.append("  Unavailable (server or client did not expose these)")
            for key in missing:
                note = str(capabilities[key].get("note") or "")
                lines.append(f"    {key:<24} {note}")
        # Ascension-only surfaces decide how much of a character is restorable,
        # so always state them explicitly rather than only when they fail.
        lines.append("  Realm-specific surfaces")
        for key in ("advancement", "mysticCollection", "appliedMystics", "equipmentAppearance"):
            record = capabilities.get(key)
            if record:
                flag = "ok " if record.get("available") else "N/A"
                lines.append(f"    {flag} {key:<22} {str(record.get('note') or '')[:70]}")

    return "\n".join(lines)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def resolve_input(path: str) -> str:
    """Accept a SavedVariables file, a WTF account dir, or a raw code file."""
    if os.path.isfile(path):
        return path
    if os.path.isdir(path):
        direct = os.path.join(path, "SavedVariables", "BindMySoul.lua")
        if os.path.isfile(direct):
            return direct
        matches: list[str] = []
        for root, _dirs, files in os.walk(path):
            for name in files:
                if name.lower() == "bindmysoul.lua":
                    matches.append(os.path.join(root, name))
        if len(matches) == 1:
            return matches[0]
        if not matches:
            raise BmsError(f"No BindMySoul.lua found under {path}.")
        listing = "\n  ".join(sorted(matches))
        raise BmsError(f"Several BindMySoul.lua files found; name one:\n  {listing}")
    raise BmsError(f"{path} does not exist.")


def load_codes(path: str) -> list[str]:
    resolved = resolve_input(path)
    if bms_bundle.is_bundle(resolved):
        try:
            return bms_bundle.read_bundle(resolved).codes
        except bms_bundle.BundleError as exc:
            raise BmsError(str(exc)) from None
    text = _read_text(resolved)
    stripped = text.lstrip()
    if stripped.startswith(("BMSP1|", "BMSP2|")):
        return [line for line in (l.strip() for l in text.splitlines()) if line]
    db = load_savedvariables(resolved)
    return extract_checkpoint_codes(db)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Read Bind My Soul checkpoints from a SavedVariables file.",
    )
    parser.add_argument(
        "path",
        help="BindMySoul.lua, a WTF account directory, or a file of raw BMSP codes",
    )
    parser.add_argument("--list", action="store_true", help="list checkpoints and exit")
    parser.add_argument("--index", type=int, default=0, help="which checkpoint (0 = latest)")
    parser.add_argument("--summary", action="store_true", help="print a readable summary")
    parser.add_argument("--json", metavar="FILE", help="write the checkpoint JSON here ('-' for stdout)")
    parser.add_argument("--raw", metavar="FILE", help="write the raw BMSP code here ('-' for stdout)")
    parser.add_argument("--out-dir", metavar="DIR", help="write every checkpoint as JSON into DIR")
    parser.add_argument("--indent", type=int, default=2, help="JSON indent (0 for compact)")
    args = parser.parse_args(argv)

    try:
        codes = load_codes(args.path)
    except BmsError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if not codes:
        print("error: no checkpoints found. Has /bms save been run and the UI reloaded?",
              file=sys.stderr)
        return 1

    indent = args.indent if args.indent > 0 else None

    if args.list or args.out_dir:
        written = 0
        for index, code in enumerate(codes):
            try:
                checkpoint = parse_checkpoint(code)
            except BmsError as exc:
                print(f"[{index}] INVALID: {exc}", file=sys.stderr)
                continue
            import datetime as _dt

            sealed = _dt.datetime.fromtimestamp(checkpoint.sealed_at)
            label = "latest" if index == 0 else f"history {index}"
            print(
                f"[{index}] {label:<10} {checkpoint.name} - {checkpoint.realm:<24}"
                f" {sealed:%Y-%m-%d %H:%M}  {checkpoint.coverage.get('percentage')}%"
                f"  {checkpoint.bytes:,} bytes"
            )
            if args.out_dir:
                os.makedirs(args.out_dir, exist_ok=True)
                safe_realm = re.sub(r"[^A-Za-z0-9._-]+", "-", checkpoint.realm)
                safe_name = re.sub(r"[^A-Za-z0-9._-]+", "-", checkpoint.name)
                out_path = os.path.join(
                    args.out_dir,
                    f"{safe_realm}-{safe_name}-{checkpoint.sealed_at}.json",
                )
                with open(out_path, "w", encoding="utf-8") as handle:
                    json.dump(checkpoint.data, handle, indent=indent, ensure_ascii=False)
                written += 1
                print(f"     -> {out_path}")
        if args.out_dir:
            print(f"\nwrote {written} checkpoint(s) to {args.out_dir}")
        return 0

    if not -len(codes) <= args.index < len(codes):
        print(f"error: --index {args.index} out of range (0..{len(codes) - 1})", file=sys.stderr)
        return 2

    try:
        checkpoint = parse_checkpoint(codes[args.index])
    except BmsError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.raw:
        if args.raw == "-":
            print(checkpoint.code)
        else:
            with open(args.raw, "w", encoding="utf-8") as handle:
                handle.write(checkpoint.code)
            print(f"wrote {checkpoint.bytes:,} bytes to {args.raw}", file=sys.stderr)

    if args.json:
        payload = json.dumps(checkpoint.data, indent=indent, ensure_ascii=False)
        if args.json == "-":
            print(payload)
        else:
            with open(args.json, "w", encoding="utf-8") as handle:
                handle.write(payload)
            print(f"wrote {args.json}", file=sys.stderr)

    if args.summary or not (args.json or args.raw):
        print(summarize(checkpoint))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
