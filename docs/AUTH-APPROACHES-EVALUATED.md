# Auth approaches evaluated — the shim, FirstOni's AuthGate, and what we took

This project makes an unmodified Project Ascension 3.3.5a client log into a local server.
Several people have solved the auth step different ways. This records the options, why this
repo uses the shim, the one idea we lifted from FirstOni's *AscensionAuthGate*, and which
approach fits which kind of user — because "easiest to run" depends on who is running it.

All of it is preservation tooling for a **lawfully-owned** client against **your own** local
server. None of it is for use against live Ascension servers.

---

## The three families

**1. Redirect + server-side shim (this repo).**
A loose `Interface\GlueXML\AccountLogin.lua` forces the `realmList` CVar so the client dials
`127.0.0.1` (no driver, no admin, no NAT — see `HOW-THE-REDIRECT-WORKS.md` §2). A Python
**shim** (`server/shim3799.py`) answers Ascension's custom login and hands back a realm list;
`server/world_server.py` (or the bridge) carries the world protocol. The shim needs the
client's per-session key **K** to build the proof `M2 = HMAC-SHA256(K,"OK")`, and it reads K
from the client with `ReadProcessMemory`.

**2. Un-hook the custom auth (Donny's `ascfix_srp`).**
Reverse the inline hooks Ascension's `Extensions.dll` installs, so the client speaks **stock
SRP6** to a stock authserver. Elegant, but fragile on this build: the proof verifier
(`M2 = HMAC-SHA256(K,"OK")`) is not one of the hooks a portable un-hooker reliably restores,
and it appears to be applied dynamically at handshake. Recorded as a road tested, not the one
this repo ships.

**3. In-client DLL that plays the auth itself (FirstOni's AuthGate).**
Replace `Extensions.dll` with a proxy that chain-loads the real one, then answer the custom
login **in-process**: read K from memory (no cross-process call), return the `M2` proof, serve
a realm list, and add a genuine SRP6 **password gate** against a stock authserver. Reaches
character select. World gameplay still needs the same world-protocol handling as (1).

---

## Why this repo stays on the shim (family 1)

- **Build-agnostic redirect.** The loose-Lua lever has no hard-coded offsets; it works across
  client builds. AuthGate's in-process hooks are pinned to one build's RVAs and silently no-op
  on a mismatch.
- **Non-destructive.** The shim never changes a client file. AuthGate renames and replaces
  `Extensions.dll` on disk, which is riskier (anti-tamper) and unsafe on a client install that
  is a junction/symlink to another realm.
- **The world side is the same work either way.** AuthGate "reaches character select"; a
  populated world still needs the world-protocol layer this repo already has. So AuthGate would
  replace only the *auth* half, not the stack.

## What we took from AuthGate: the in-process K read

The shim's one privileged step is the `ReadProcessMemory` of K, which forces it to run at the
**same integrity level as the client** (`HOW-THE-REDIRECT-WORKS.md` §3/§5 — the error-740
elevation dance). AuthGate showed the clean fix: read K from **inside** the client, where no
`OpenProcess`/RPM and no integrity match are needed.

`contrib/InProcessKeyOracle/` lifts exactly that: a tiny `kexport.dll` (loaded by a file-drop
`dinput8` proxy) reads K via the **same pointer chain** `rpm_readk.py` uses — `Extensions base
+ 0xbdbc04 → obj → +0x120`, independently confirmed identical to AuthGate's constants — and
serves it on a loopback oracle. `shim3799.py` prefers the oracle, then RPM, then variant-guess,
so it is a pure upgrade when present and a no-op when not. Credit: FirstOni.

We did **not** adopt the rest of AuthGate (the on-disk DLL swap, the password gate wired to a
particular DB, the hard-coded world endpoint), for the reasons above.

---

## Which approach fits which user

The real barrier for most people is **not** the auth step — it is standing up the server
(build, databases, DBC set). No client-side auth trick removes that; a prebuilt server release
plus an installer does. With that said, for the client half:

| | Redirect + shim (+ oracle) | FirstOni's AuthGate |
|---|---|---|
| Client files changed | none (loose Lua; optional `dinput8`+`kexport` drop) | rename + replace `Extensions.dll` |
| Works across client builds | yes (Lua lever) | no — pinned to one build's offsets |
| Password check | permissive by default | real per-account SRP6 |
| Extra process to run | yes (the Python shim) | no (folded into the DLL) |
| Reads K without elevation | yes, **with** the oracle add-on | yes (in-process by design) |
| World / gameplay | handled here | still needs the same world layer |

**For someone without a coding agent**, neither is turnkey today, and for opposite reasons:
the shim needs a Python process launched correctly; AuthGate needs a binary that matches the
client build and a server whose DB/endpoint match what the DLL was compiled for. AuthGate's
single-drop, no-extra-process, real-password shape is genuinely nicer **for the exact client
build it was compiled against** — which makes it a strong basis for a *"keep your real
Ascension client"* preservation download, an audience this repo's server-first path does not
otherwise serve.

The turnkey answer for that audience is an **installer**, not a different auth hack: ship a
prebuilt server + a script that turns a client into a configured copy, keep the build-agnostic
Lua redirect, and include the in-process oracle so the auth step needs no elevation. That
combination gets closest to "download, run, play" without a coding agent in the loop.
