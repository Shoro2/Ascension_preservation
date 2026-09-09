# Data manifest — the full local sweep, and what to bring from your own client

This repository is **public** and deliberately **does not** ship the Ascension
client or anything you already get from it. The other developers on this project
already have the client, so bundling ~10 GB of copyrighted MPQ archives here would
be redundant, against GitHub's file-size limits, and a copyright problem.

This manifest is the bridge: it inventories **everything in the local sweep** —
what ships here, and what you must supply or regenerate from your own legally
obtained client — so no knowledge is lost even where the bytes are not shipped.

---

## A. Ships in this repo (our original work + safe derived data)

| Path | What |
|---|---|
| `docs/` | Protocol specs, the redirect write-up, master notes, session handoffs |
| `server/` | The runnable local stack (auth shim, world server, bridge, launch scripts) |
| `server/data/` | Server **seed/state we generated** (keybinds, action bars, characters, builds, trainer templates) |
| `tools/` | ~60 reverse-engineering + analysis scripts |
| `data/ca-export/` | Character-Advancement **structure** export (schema, classes, tabs, categories, edges, entries) |
| `data/sanitized-for-core.json` | Changelog of the enum clamps `tools/sanitize-for-core.py` applied to Ascension's DBCs for the **standalone** worldserver profile (11,730 changes). Not world content; `import-world.py` does not read it |
| `reference/` | Curated screenshots we captured, Lua/opcode reference text, raw world-opcode samples |

> The `data/` and `server/data/` JSON are **derived from the client's own data**.
> They are included because every collaborator already owns the client and they
> make the stack runnable out of the box. They can be regenerated (§C). If a
> stricter public-copyright reading is preferred, delete `data/ca-export/`,
> `data/sanitized-for-core.json`, and the content-bearing files in `server/data/`
> and regenerate locally.

---

## B. NOT shipped — bring from your own client (you already have these)

### B1. The Ascension client MPQ chain — `mpqB/` (7.9 GB, 37 archives)

The client's game-data archives. Copyrighted; obtain from your own install.

```
base-enUS.MPQ        27.8 MB     patch-CG.MPQ        231.9 MB
locale-enUS.MPQ     194.8 MB     patch-CH.MPQ        134.2 MB
patch-4.MPQ           0.1 MB     patch-CHA.MPQ      1460.5 MB
patch-5.MPQ           0.1 MB     patch-CI.MPQ         59.2 MB
patch-A.MPQ        1971.0 MB     patch-CJ.MPQ         11.3 MB
patch-B.MPQ           6.8 MB     patch-CK.MPQ        117.7 MB
patch-C.MPQ           0.1 MB     patch-CL.MPQ         98.1 MB
patch-CA.MPQ        217.1 MB     patch-CM.MPQ        291.4 MB
patch-CB.MPQ        272.9 MB     patch-CN.MPQ        180.0 MB
patch-CC.MPQ        183.8 MB     patch-CO.MPQ         61.3 MB
patch-CD.MPQ        460.9 MB     patch-CP.MPQ        142.6 MB
patch-CE.MPQ         89.0 MB     patch-CQ.MPQ          1.8 MB
patch-CF.MPQ        226.6 MB     patch-CR.MPQ        187.1 MB
                                 patch-CS.MPQ        453.9 MB
patch-CT.MPQ        201.5 MB     patch-CU.MPQ          3.1 MB
patch-CV.MPQ        175.7 MB     patch-CW.MPQ        180.5 MB
patch-CX.MPQ          9.9 MB     patch-CY.MPQ         19.8 MB
patch-CZ.MPQ         38.4 MB     patch-CZZ.MPQ         0.1 MB
patch-enUS-2.MPQ    215.1 MB     patch-enUS-3.MPQ     95.7 MB
```
`mpqchain/` (≈2 GB) is a second working copy of the same chain. `patch-CA…CZZ`
are Ascension's custom content patches; the CA/CoA engine dataset lives in one of
these as a DBC (not as loose JSON — see the "Ascension archive" notes in
`docs/ASCENSION-NOTES.md`).

### B2. Extracted DBCs — `server-ascension/Data/dbc/` (≈245 files, part of a 713 MB server tree)

245 DBCs extracted from the client's MPQs, used to build the local world DB.
Regenerate by extracting from your own MPQ chain (any MPQ tool / the scripts in
`tools/`, sources for ours in `contrib/mpqtools/`). Key ones the CoA work depends
on: `CharacterCreationArchetypes.dbc`, the Character-Advancement dataset DBC, and
the standard 3.3.5a set.

**The Python world server reads four of these directly** and boots without them
(it says so in its resolved-path report) but then has no essence / class table:

| File | Archive | Default location (override) |
|---|---|---|
| `DBFilesClient\CharacterAdvancementEssence.dbc` | `patch-M.MPQ` | `server/rexxar-reference/ca-dbc/` (`ASC_CA_REF`) |
| `DBFilesClient\CharacterAdvancementClassTypes.dbc` | `patch-M.MPQ` | `server/rexxar-reference/ca-dbc/` (`ASC_CA_REF`) |
| `DBFilesClient\ChrClasses.dbc` | `patch-M.MPQ` | `../../server-ascension/Data/dbc/` (`ASC_DBC_DIR`) |
| `DBFilesClient\Spell.dbc` | `patch-T.MPQ` | `../../server-ascension/Data/dbc/` (`ASC_DBC_DIR`) |

The CA files may keep their extracted name or carry the `DBFilesClient_` prefix;
both are accepted. `tools/ca_export.py` wants all seven
`CharacterAdvancement*` / `CharacterCreationArchetype*` DBCs in the same `ca-dbc/`.

### B3. Loose client content — `client-ascension\Data\Content\*.json`

Ascension ships much custom data as loose JSON inside the client (e.g.
`CharacterAdvancementData.json`, `WildcardSkillCardData.json` (~49 k skill cards),
`SpellRankData.json` (~13 k)). These are read straight from your client install;
they are not shipped here.

### B4. The client itself — `client-ascension/`

A **junction into the live 43 GB install** on the sweep machine. Never copied.

---

## C. How to regenerate the shipped derived data from your own client

| Shipped file | Regenerate with |
|---|---|
| `data/ca-export/*` (CA tree structure) | `tools/ca_export.py`, `tools/extract_tree.py`, `tools/edges_import.py` |
| `data/sanitized-for-core.json` | `tools/sanitize-for-core.py` |
| `server/data/trainer-templates.json`, `knownentries.json` | `tools/import-world.py`, `tools/seed-characters.py` |
| DBC set (§B2) | extract from your MPQ chain, then `tools/fix-dbc.py`, `tools/check-dbc-fmt.py` |

---

## D. Excluded for privacy — do NOT redistribute

These are in the sweep but were **withheld** because they contain the sweep
machine's own live-login material (the account field XOR the public pad `K`
recovers a real account; the password tail is present):

- `e0-captures/` — `s0NN_c00_hello.bin` (hello with account/password), `_c01_proof.bin` (SRP proof)
- `wire-analysis/hello_*.bin` — 641-byte custom hello captures
- `live-server-challenge-response.bin`, `live-server-proof-response.bin`
- All `*.log` (auth-proxy, world, shim logs)

The **findings** from these captures are fully written up, credential-free, in
`docs/WIRE-SPEC.md` and `docs/WORLD-WIRE-SPEC.md`. If you regenerate captures from
your own client, they will contain **your** credentials — keep them out of any
public repo.
