# Ascension Preservation — Conquest of Azeroth (local server archive)

A preservation archive of **Project Ascension**'s classless custom WoW 3.3.5a
experience — focused on the **Conquest of Azeroth (CoA) custom-class /
Character-Advancement** system — rebuilt so the **unmodified Ascension client can
log into a fully local server and play offline**.

Project Ascension's live service shut down **2026-09-04**. This repository is the
post-shutdown record of *how the client works* and a working local re-host of the
login → world → Character-Advancement path.

> **What this is:** original reverse-engineering, protocol documentation, and a
> small Python server stack (auth shim + world server) that speaks enough of
> Ascension's wire protocol to satisfy the real client.
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

1. **[`docs/HOW-THE-REDIRECT-WORKS.md`](docs/HOW-THE-REDIRECT-WORKS.md)** — the
   detailed writeup of **how the client is redirected to a local server and gets
   in-game**. Read this first; it is the heart of the project.
2. **[`docs/handoffs/HANDOFF-ARCHIVE-SESSION.md`](docs/handoffs/HANDOFF-ARCHIVE-SESSION.md)**
   — full boot runbook + everything already solved.
3. **[`docs/handoffs/HANDOFF-SPELLS-TALENTS-CLASSES.md`](docs/handoffs/HANDOFF-SPELLS-TALENTS-CLASSES.md)**
   — the current frontier: CoA spells, talent trees, custom classes.
4. **[`docs/KNOWN-ISSUES.md`](docs/KNOWN-ISSUES.md)** — symptom-first list of
   failures that look like server or protocol bugs but are not. Check it before
   diagnosing a hang or a silent disconnect.
5. **[`docs/handoffs/HANDOFF-FRESH-INSTALL.md`](docs/handoffs/HANDOFF-FRESH-INSTALL.md)**
   — **setting this up on another machine.** Written for a person (or their AI
   assistant) standing the stack up from this repository: the +5 s in-world
   disconnect and its fix, the repository-layout gotchas, which files you must
   extract from your own client, and the AzerothCore build / map / DB answers.

## What works

- The **unmodified `Ascension.exe`** logs into a local stack (auth shim on
  `127.0.0.1:3799`, world server on `127.0.0.1:8087`), unelevated, no UAC, no
  binary patching, no network-crypto defeat.
- Client reaches **character-select**, **enters and stays in the world**
  (Sunstrider Isle), and touches the live service for nothing but CDN pings.
- The **Conquest-of-Azeroth / Character-Advancement panel renders** — 153
  populated class|tab buckets, 8873 entries, 42 classes — plus archetypes and
  working character creation into custom classes.
- 3.3.5a account-data exchange (keybinds, action bars) served from the server.

See the handoffs for the precise state and the open items.

## Repository layout

```
docs/            Protocol specs and narrative write-ups (our RE work)
  HOW-THE-REDIRECT-WORKS.md     ← how the redirect + in-game entry works
  WIRE-SPEC.md                  auth (3799) handshake, byte-level
  WORLD-WIRE-SPEC.md            world (8087) handshake
  ASCENSION-NOTES.md            master notes: client layout, redirect, DB rebuild
  KNOWN-ISSUES.md               symptom-first: hangs/disconnects and their real causes
  protocol/                     opcode + handler maps
  handoffs/                     session handoffs (boot runbook, CoA deep-dives)

server/          The runnable local stack
  shim3799.py                   permissive auth shim (port 3799)
  world_server.py               world server (port 8087)
  ascension_bridge.py           bridge (port 8088) onto an AzerothCore worldserver (8086)
  rpm_readk.py                  reads the session key from client memory
  *.ps1                         launch / restart helpers
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

- Windows, Python 3.x.
- A legally obtained Project Ascension 3.3.5a client (see `data/MANIFEST.md` for
  the exact files the server reads/needs). Paths in the scripts assume a layout
  like `C:\AzerothRealm\client-ascension\…`; adjust to yours.
- For the AzerothCore-backed world-DB route: a MySQL/MariaDB instance and an
  AzerothCore 3.3.5a worldserver. The bridge speaks stock build 12340 to the core,
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
legacy shim accepts account `test` / any password; the default AuthGate path requires an existing local account and its correct password. If you regenerate content from a
live capture, do not commit captures containing real credentials.

## Credits

**FirstOni** contributed the original AscensionAuthGate design and implementation. The reviewed local adaptation, security hardening and tests are documented in [its attribution notice](contrib/AscensionAuthGate/THIRD-PARTY-NOTICE.md).

Reverse-engineering, documentation, and the local server stack were developed
iteratively with **Claude Code**. Preservation project — not affiliated with or
endorsed by Project Ascension or Blizzard Entertainment.
