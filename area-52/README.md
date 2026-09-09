# Area 52 — Free-Pick (realm-flavour specifics)

The project's focus is **Conquest of Azeroth (CoA)** — the custom-class /
Character-Advancement system. This subfolder isolates the bits that are specific
to the **"Area 52 - Free-Pick"** realm flavour, so they don't clutter the CoA
material.

## Why the emulator advertises "Area 52 - Free-Pick"

There is a coupling worth understanding before you change any realm strings.
Several **client-side gates** for custom-class creation read the **realm name**
directly. Measured: `CanCreateArchetype` (and roughly half its sibling checks)
returns true when `GetRealmName() == "Area 52 - Free-Pick"`. So the local
emulator advertises exactly that realm name/meta to unlock CoA **archetype
creation** in the client's own FrameXML — it is not that we are emulating the
Area-52 season's content; we are borrowing its realm identity because that
identity is what opens the creation path.

## Where the coupling lives (do not "fix" unasked)

These constants are baked into the server code (they cannot be moved into this
folder without breaking the gate); they are listed here so the coupling is
discoverable:

- `server/shim3799.py`
  - `ARCHIVE_REALM_NAME = "Area 52 - Free-Pick"`
  - `ARCHIVE_REALM_META = "Area 52 - Free-Pick!1!0!Area52!true!1!6!13977862"`
- `server/world_server.py`
  - `ARCHIVE_REALM_NAME = "Area 52 - Free-Pick"` and the realm-flavour bytes
    (`IsLive` / `IsProduction`) sent in the realm-info packet.

`docs/WIRE-SPEC.md` §"realm list" shows where `Area 52 - Free-Pick!…` sits on the
wire; `docs/handoffs/HANDOFF-SPELLS-TALENTS-CLASSES.md` documents the
`GetRealmName()`-based creation gates in detail.

## What is (and isn't) here

There were **no standalone Area-52 asset files** in the sweep to relocate — Area
52 is a realm *identity* used by the emulator, not a separate content bundle. Drop
any Area-52-season-specific assets you gather (season UI like
`Ascension_CharacterAdvancementSeason9`, season screenshots, season-only data)
**into this folder** to keep them out of the CoA line.
