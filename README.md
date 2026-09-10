# Ascension Preservation — Conquest of Azeroth (local server archive)

A preservation archive of **Project Ascension**'s classless custom WoW 3.3.5a
experience — focused on the **Conquest of Azeroth (CoA) custom-class /
Character-Advancement** system — rebuilt so the **original Ascension executable can
log into a local realm using the reviewed AuthGate proxy**.

Project Ascension's live service shut down **2026-09-04**. This repository is the
post-shutdown record of *how the client works* and a working local re-host of the
login → world → Character-Advancement path.

> **What this is:** original reverse-engineering, protocol documentation, and a
> reviewed AuthGate authentication proxy plus a Python world bridge/server
> stack that speaks Ascension's wire protocol to the original client.
>
> **What this is NOT:** it does **not** contain the Ascension/Blizzard client,
> its DBCs, MPQs, art, or bulk content. You bring those from your own legally
> obtained client. See [`NOTICE.md`](NOTICE.md) and
> [`data/MANIFEST.md`](data/MANIFEST.md).

---

## Default local authentication: AuthGate

The maintained original-client path now uses [AscensionAuthGate](contrib/AscensionAuthGate/README.md), adapted from **FirstOni's** code, with real per-account SRP password validation and a verified server proof. The local bridge remains on 8088; the separate auth shim on 3799 is no longer needed for this path. The original-client character was tested successfully after migration. [Read the scoped security review](contrib/AscensionAuthGate/SECURITY-REVIEW.md) before installing.

The source, build/tests and guarded original-client installer are included; game binaries, captured keys, private histories and prebuilt DLLs are not. Both CoA and Free-Pick metadata are supported. Older shim-based runbooks below remain historical/alternative documentation, and the shim remains in the repository for deliberate legacy use.

## Start here

1. **[Current AuthGate guide](docs/HOW-THE-REDIRECT-WORKS.md)** — the default
   architecture, ports, original-client setup, launch sequence and verification.
2. **[AuthGate package](contrib/AscensionAuthGate/README.md)** — source, build/test
   commands, guarded installer and launcher, with credit to FirstOni.
3. **[Fresh-machine data and core setup](docs/handoffs/HANDOFF-FRESH-INSTALL.md)**
   — required client-supplied assets, repository layout, maps and database setup.
   Its historical shim/standalone-world login instructions are superseded by
   the current AuthGate guide.
4. **[Spells, talents and classes](docs/handoffs/HANDOFF-SPELLS-TALENTS-CLASSES.md)**
   and **[known issues](docs/KNOWN-ISSUES.md)** — gameplay progress and troubleshooting.
5. **[Earlier archive research](docs/handoffs/HANDOFF-ARCHIVE-SESSION.md)** —
   historical discoveries and the former boot sequence, retained for reference.

## What works

- The original `Ascension.exe` launches unelevated with the reviewed **AuthGate**
  proxy. The genuine extension is preserved as `Extensions_orig.dll`.
- An existing local account's **correct password is required**. AuthGate validates
  it with the realm's authserver on `127.0.0.1:3724` and verifies the server proof.
- The client owns its custom-auth listener on `127.0.0.1:3725`, then enters the
  world through the bridge on `127.0.0.1:8088` and AzerothCore on `8086`.
- The original-client character reached the world with the legacy shim stopped;
  the user confirmed flawless gameplay. CoA and Free-Pick retain distinct realm
  metadata and the configured profile's character database.
- The reviewed AuthGate package passed 59 isolated checks and two real local
  credential checks. See its [security review](contrib/AscensionAuthGate/SECURITY-REVIEW.md)
  for the evidence and scope. The proprietary client's own external networking
  is a separate boundary; AuthGate is not a firewall for it.

The gameplay handoffs document Character Advancement, account-data exchange,
and remaining content limitations. Historical standalone-world results are
identified separately from the current bridge route.

## Repository layout

```
docs/            Protocol specs and narrative write-ups (our RE work)
  HOW-THE-REDIRECT-WORKS.md     ← how the redirect + in-game entry works
  WIRE-SPEC.md                  custom auth wire research (historically captured on 3799)
  WORLD-WIRE-SPEC.md            world protocol research (standalone route on 8087)
  ASCENSION-NOTES.md            master notes: client layout, redirect, DB rebuild
  KNOWN-ISSUES.md               symptom-first: hangs/disconnects and their real causes
  protocol/                     opcode + handler maps
  handoffs/                     session handoffs (boot runbook, CoA deep-dives)

server/          The runnable local stack
  shim3799.py                   LEGACY permissive auth shim (3799); not a default dependency
  world_server.py               alternative standalone world server (8087)
  ascension_bridge.py           bridge (port 8088) onto an AzerothCore worldserver (8086)
  rpm_readk.py                  reads the session key from client memory
  *.ps1                         legacy/server helpers; current client launcher is in AuthGate
  worldserver-bridge.conf       AzerothCore worldserver config (DB password REDACTED)
  data/                         server seed/state we generated (builds, chars, keybinds…)
  rexxar-reference/ca-dbc/      NOT shipped: put the CharacterAdvancement*.dbc you extract
                                from patch-M.MPQ here (or set ASC_CA_REF)

data/            CoA CONTENT derived from the client (schema + exports)
  ca-export/                    Character-Advancement tree export (classes, tabs, edges…)
  sanitized-for-core.json       changelog of the DBC enum clamps sanitize-for-core.py
                                applied for the STANDALONE worldserver profile (not world content)
  MANIFEST.md                   proprietary files you must supply from your own client

tools/           Reverse-engineering + analysis toolkit (~60 scripts). Also holds the
                 modules the servers import (archive_ports, ascension_x25519_m2, chardata);
                 the servers find it via ../tools, do not copy them.
reference/       Curated screenshots + Lua/opcode reference text
  ascension_opcodes.json        opcode id → name, 2058 entries (this client)
  ascension_custom_opcodes.json 754-entry subset, 749 of them above stock's 0x500 ceiling
area-52/         Area-52 "Free-Pick" realm-flavour specifics (see its README)
contrib/         Tools contributed by others, adapted (see each README)
  AscensionAuthGate/             FirstOni-derived reviewed local auth proxy + tests
  AscensionRedirect/            WinDivert packet redirect + Frida auth-send probe
  mpqtools/                     mpqcat / mpqfind sources (StormLib) used by tools/extract_*.py
```

## Requirements

- Windows, Python 3.x, and Visual Studio C++ x86 build tools to build AuthGate.
  Its PE verification script also requires Python `pefile`; see the package guide.
- A legally obtained Project Ascension 3.3.5a client (see `data/MANIFEST.md` for
  the exact files the server reads/needs). Paths in the scripts assume a layout
  like `C:\AzerothRealm\client-ascension\…`; adjust to yours.
- For the default bridge route: a MySQL/MariaDB instance, an AzerothCore
  authserver with an existing local account, and an AzerothCore 3.3.5a worldserver. The bridge speaks stock build 12340 to the core,
  so upstream `azerothcore-wotlk` `master` with no modules is enough; the
  maintainer's own core is a locally built mod-playerbots fork, which is not
  required. Maps/vmaps/mmaps come from a **clean stock 3.3.5a client**, never from
  Ascension's MPQ chain. Details in `docs/handoffs/HANDOFF-FRESH-INSTALL.md` §6.
- The recovered game **data** (items, creatures, quests, texts) and the tools
  that put it into a client or a world database live in the sister repository
  [hertigservices/ascension-cache-consolidator](https://github.com/hertigservices/ascension-cache-consolidator):
  `tools/install.py` for the client, `tools/import_world.py` for the AzerothCore
  world DB, `docs/USING-THE-DATA.md` for how it shows up in game. This repository
  is about running the Ascension *client* against a server you control; that one
  is about the content, and works with a stock 3.3.5a client too.

## Privacy / secrets note

This package was scrubbed before publishing: the maintainer's account
email/passwords and the real DB password were removed, and raw live-login packet
captures (`e0-captures/`, `live-*.bin`) and server logs are **excluded**. The
default AuthGate path requires an existing local account and its correct
password. Raw key logging and diagnostic rollback are disabled. The former
shim's permissive login is a legacy behavior, not an AuthGate setup instruction.
Do not commit credentials, runtime histories or raw packet/key captures.

## Credits

**FirstOni** contributed the original AscensionAuthGate design and implementation. The reviewed local adaptation, security hardening and tests are documented in [its attribution notice](contrib/AscensionAuthGate/THIRD-PARTY-NOTICE.md).

Reverse-engineering, documentation, and the local server stack were developed
iteratively with **Claude Code**. Preservation project — not affiliated with or
endorsed by Project Ascension or Blizzard Entertainment.
