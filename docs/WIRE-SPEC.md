# Ascension client ↔ authserver — wire specification (local archive)

**Purpose.** A fixed, factual baseline of the Ascension login wire protocol as *observed*,
before any variable is changed. Everything here is derived from captured bytes and connection
logs, not from prose in any tool. Every field carries a status label:

- **[confirmed]** — directly read from captured bytes / logs, reproducible.
- **[inferred]** — a reading consistent with the bytes but not yet proven by an experiment.
- **[unknown]** — role not established; deliberately left unlabeled as to purpose.

Field roles such as "nonce", "public key", "MAC", "hash", "ephemeral" are **intentionally not
used** for any region until a controlled experiment establishes that role. Where the vanilla
3.3.5a layout would put such a field, that is noted as *position only*, not identity.

---

## Provenance & trust

**Evidence used (all local, all the user's own captures):**

| Artifact | What it is |
|---|---|
| `auth-proxy.log` (= `auth-proxy-local-analysis.log`) | client ↔ **stock AzerothCore** (3724); 6 Ascension hellos, server closes on each |
| `auth-proxy-account-1.log` | first-session prefix of the above (no new data; account was **not** varied) |
| `auth-proxy-live.log` | client ↔ **real Ascension** (51.210.230.10); the one **full successful** handshake |
| `live-server-challenge-response.bin` (119 B) | server 0x00 response from the successful login |
| `live-server-proof-response.bin` (44 B) | server 0x01 response from the successful login |
| `live-realmlist-raw.bin` (2306 B) | server 0x10 response from the successful login |
| `replay-auth.log` | result of replaying the two server responses back to the client |
| `wire-analysis/*.bin` | every message extracted to raw bytes by `wire-analysis/parse_captures.py` |

**Reproducible:** `python wire-analysis/parse_captures.py` re-extracts every message from the
logs and recomputes the constant/variable maps; `python wire-analysis/verify.py` re-decodes the
crypto messages and re-checks the invariants below.

**Trust note (why this document exists).** The sibling tools carry prose conclusions in their
comments. Those are treated here as **unverified hypotheses, not evidence.** In particular:

- `trace-handshake.py` states the handshake is libsodium **X25519 + HMAC-SHA256** with the KDF
  hidden in a `.vm_sec` VM. **The wire does not support this.** The server challenge carries the
  *canonical* WoW SRP6 modulus and g=7 (§4). The X25519 claim comes from static DLL analysis in a
  comment and **must not be carried forward as fact.** It may be true of some code path in
  `Extensions.dll`, but nothing observed on the wire requires it.
- `replay-auth.py`'s note ("client rejected our M2 → check the Extensions.dll M2 path") records a
  correct *observation* (§2) but steers toward an exotic cause; a **plain SRP6 handshake also
  rejects a replay**, so that steer is unproven.

No sign of adversarially planted or AI-directed misdirection was found; the one wrong claim reads
as honest over-interpretation. Regardless, this spec records **only** byte/log-derived facts so a
reader need not trust any narration — including this one: re-run the two scripts.

---

## 1. Transport / framing

- **[confirmed]** Raw TCP, no TLS. The proxy reads cleartext opcodes in both directions; there is
  no SNI/handshake wrapper. Client dials `127.0.0.1:<port>`; `<port>` is arbitrary (the harness
  chose 3799 — see the launcher notes; the client's own default is the standard auth port 3724).
- **[confirmed]** Byte 0 of every message is an opcode. Observed opcodes: `0x00`, `0x01`, `0x10`
  — the vanilla 3.3.5a auth opcodes (LOGON_CHALLENGE, LOGON_PROOF, REALM_LIST).
- **[confirmed]** Framing is per-opcode, vanilla-style:
  - `0x00` (both directions): `cmd(1) | b1(1) | size(2, uint16 LE) | body[size]`.
  - `0x01`: fixed-length body, no size field (75 B client, 44 B server).
  - `0x10` client: fixed 5 B; `0x10` server: `cmd(1) | size(2, uint16 LE) | payload[size]`.

---

## 2. State machine

**[confirmed]** Successful login (from `auth-proxy-live.log`):

```
CONNECT
  C → 0x00  (645 B)          client hello / challenge
  S → 0x00  (119 B, result=0x00 SUCCESS)
  C → 0x01  (75 B)           client proof
  S → 0x01  (44 B, err=0x00 SUCCESS)
  C → 0x10  (5 B)            realm-list request
  S → 0x10  (2306 B)         realm list
  (C → 0x10 / S → 0x10)*     realm-list refresh loop, ~1 Hz while on realm screen
```

Note: the live capture's 1452 B + 854 B pair (messages 5/6) is a single 2306 B `0x10` response
split across two TCP segments (1452+854 = 2306), **not** a distinct message. **[confirmed]**

**[confirmed]** Against **stock AzerothCore** (`auth-proxy.log`): `C → 0x00 (632 B)` then the
**server closes** with no reply. A stock 39 B `0x00` from a vanilla client on the same port/server
gets a normal 119 B SUCCESS (connection 1). ⇒ the rejection is specific to the oversized `0x00`
body, not the port, server, or account.

**[confirmed]** Against the **replay server** (`replay-auth.log`): `C → 0x00`, `S →` recorded
119 B, `C → 0x01`, `S →` recorded 44 B, then the **client closes without sending 0x10**. ⇒ the
client validates something session-bound in the proof step; a straight replay is refused.
**[inferred]** This is consistent with any fresh-per-session challenge-response (including plain
SRP6) and does **not**, on its own, imply custom cryptography.

---

## 3. Message `0x00` request — client hello  *(the only structural deviation from vanilla)*

Body length observed: **631 / 632 / 641** across sessions (vanilla body = 35). Offsets below are
**packet-relative** (byte 0 = opcode; the 4-byte header is included). Canonical example =
`wire-analysis/hello_L_c1_645.bin` (the successful live login, 645 B total):

| Offset | Len | Example bytes | Region | Status / notes |
|---|---|---|---|---|
| `0x000` | 1 | `00` | opcode | **[confirmed]** LOGON_CHALLENGE |
| `0x001` | 1 | `08` | header b1 | **[confirmed]** value; vanilla calls this "error"/protocol. Role **[unknown]** |
| `0x002` | 2 | `81 02` | body size | **[confirmed]** uint16 LE = 641 |
| `0x004` | 4 | `fc f4 f4 e6` | marker | **[confirmed]** constant in **all** captures. Vanilla position = gamename `"WoW\0"`; value is not "WoW". Role **[unknown]** |
| `0x008` | 16 | `d32529a8…ae8185bb2439` | **window V1** | **[confirmed]** varies every launch. Role **[unknown]** |
| `0x018` | 285 | `ad7d3670…` | **static block S1** | **[confirmed]** byte-identical across **all** captures (every size/session) |
| `0x135` | 20 | `51d31886…544efa74` | **ACCOUNT field — CRACKED** | **[confirmed — known-plaintext]** = `account_name` (ASCII, case-preserved, NUL-padded to 20) **XOR fixed pad K** where `K = 28a668efc006e2b5ab81c32acb0842b237219774`. Recovers `the account login (redacted)`, `anothername`, `newusername1` exactly. A static wire-obfuscation pad — **no hash, no key derivation, no secret**; reversible with one XOR. |
| `0x145` | 240 | … | **static block S2** | **[confirmed]** constant within a size group |
| `0x235` | 60 | `27cd07fc…607e66e5` | **window V3** | **[confirmed]** varies every launch. Role **[unknown]** |
| `0x271` | 1 | `20` | **PASSWORD byte** | **[confirmed — E1]** single byte; `0x20` for E0 pw and both E2 usernames, but `0x37`/`0x3a` for the two E1 passwords ⇒ **password-derived**. (Not part of a 4-byte field; the next 3 bytes are a constant tag.) |
| `0x272` | 3 | `d7 ac b6` | tag | **[confirmed]** constant 3-byte anchor in every capture, immediately before the tail. |
| `0x275` | var | tail | **PASSWORD tail — partially cracked** | **[confirmed — known-plaintext]** = `password` (ASCII, verbatim) **XOR a per-connection keystream**; length = password length exactly (`a 7-char password`→7 B, `a 10-char password`→10 B). Keystream is **per-connection** (0 shared bytes between two connections) and did **not** match V1/V3 head/tail, sha1/md5/rc4 of V1/V3/ACC/K/challenge, concatenations, or any literal slice (xor/add/sub/reversed). Source **[unknown]** — must derive from a per-connection nonce (for the server to recover the password) or, worst case, a shared key. **Not on the critical path for a permissive local shim** (which need not verify the password). |

> **Caveat — ignore the proxy's field names.** `auth-proxy.py` prints "gamename / version / build /
> account name length 129 / 482 extra bytes" for this message. Those are **artifacts of forcing the
> vanilla 35-byte layout onto a 641-byte body** and are **not** real fields. Do not treat "account
> name length = 129" as a length; it is byte `0x1D` of block S1 seen through the wrong lens.

**Variable-window summary — updated by the E0 control (8 sessions, identical creds, fixed
challenge; run 1 = 3 same-process connections, runs 2–6 = separate processes):**

| Window | Offset | Len | Variability class (E0) |
|---|---|---|---|
| V1 | `0x008` | 16 | **per-connection** — fresh on every Login click, incl. within one process |
| V3 | `0x235` | 60 | **per-connection** — same |
| tail | `0x275` | 16 (this run) | **per-connection** — same |
| ~~V2~~ | `0x135` | 16 | **static** — identical across all 8 sessions (reclassified out of the variable set) |
| S1 | `0x018` | 285 | static (global constant) |
| S2 | `0x145` | 240 | static |

**E0 headline:** exactly **92 of 645** hello bytes vary, in **three windows only** — V1 (16 B),
V3 (60 B), tail (16 B) — and **all three are per-connection**: they regenerate on *every* connection,
including the three back-to-back Login clicks inside a single client process. **There is no
per-process-only hello window** (the class the old V2 note imagined does not exist). The other
**553 bytes are a static skeleton**, and that skeleton is **byte-identical between the E0 harness
captures and the one live production login** (`compare-live-vs-e0.py`): only V1/V3/tail differ
live-vs-local ⇒ the skeleton is **client-constant, not server- or session-driven**. Whether it is
*credential*-driven is still open (E1/E2 — the E0 vs live creds may not have matched). **[inferred]**
S1 (285 B) is stable client identity/attestation material; content **[unknown]**.

---

## 4. Message `0x00` response — server challenge (119 B)

Decode of `live-server-challenge-response.bin` as a vanilla SRP6 challenge — **every field parses**:

| Offset | Len | Field (vanilla) | Value / status |
|---|---|---|---|
| 0 | 1 | cmd | `00` **[confirmed]** |
| 1 | 1 | error | `00` **[confirmed]** |
| 2 | 1 | result | `00` = SUCCESS **[confirmed]** |
| 3 | 32 | B | `01ce9edf…ba3be13c` **[confirmed]** present; changes per session **[inferred]** |
| 35 | 1 | g_len | `01` **[confirmed]** |
| 36 | 1 | g | `07` **[confirmed]** = 7 (canonical WoW g) |
| 37 | 1 | N_len | `20` = 32 **[confirmed]** |
| 38 | 32 | N | wire `b79b3e2a…5e644b89`; reversed = `894b645e…2a3e9bb7` **[confirmed] = the canonical WoW SRP6 modulus** (identical to `check-login.py` and to stock AzerothCore) |
| 70 | 32 | salt | `9078563412 8967452391 7856…` **[confirmed] a patterned placeholder, not random** |
| 102 | 16 | version_challenge | `baa31e99…69cdd2f1` **[confirmed]** present; role **[unknown]** |
| 118 | 1 | security_flags | `00` **[confirmed]** |

**[confirmed]** The server side is standard SRP6 *framing* with canonical WoW parameters. **[unknown]**
whether the placeholder salt is used by the client or ignored.

---

## 5. Message `0x01` request — client proof (75 B)

Decode of `wire-analysis/live_CLIENT_msg2_75.bin` against the vanilla proof layout:

| Offset | Len | Field (vanilla) | Value / status |
|---|---|---|---|
| 0 | 1 | cmd | `01` **[confirmed]** |
| 1 | 32 | A | `0400…000004000…` — **[confirmed] degenerate**: 2 distinct byte values, 29 zeros. Cannot be a real SRP6 `A = g^a mod N`. |
| 33 | 20 | M1 | `0400…0400…` — **[confirmed] degenerate**: 2 distinct values, 18 zeros |
| 53 | 20 | (vanilla crc_hash) | `cec0e4df5aa4a527a207369f558f542c2773430a` — **[confirmed] full entropy** (19/20 distinct, 0 zeros) |
| 73 | 1 | number_of_keys | `00` **[confirmed]** |
| 74 | 1 | security_flags | `00` **[confirmed]** |

**[inferred]** The client reuses the 75-byte vanilla envelope but **relocates the meaningful proof
material to the final 20-byte slot** (`crc_hash`, `[53:73]`); the standard `A`/`M1` fields carry no
proof-of-knowledge. **[confirmed]** that slot is **not a verbatim copy** of any hello window
(V1/V3/tail). The derivation is **[unknown]**.

**E0 findings on the proof (8 sessions):**
- **[confirmed] Variability class = per-process, NOT per-connection.** The three back-to-back Login
  clicks in run 1 (s001–s003) produced a **byte-identical** proof (`sha 6fede981…`) **even though
  their hellos differed** (V1/V3/tail regenerated each click). Separate launches (s004–s008) each
  produced a **distinct** proof. So the proof is stable across connections within a process and
  changes when the process restarts.
- **[confirmed] The proof is independent of V1 / V3 / tail.** Those windows changed across s001→s003
  while the proof stayed identical ⇒ they are **not inputs** to the proof. This **refutes H1**.
- **[confirmed] `A` and `M1` are never real SRP6 values.** In the LIVE (successful) proof they are a
  fixed placeholder pattern `04 00 00 00 …` (three `0x00000004`s in `A`, two in `M1`). In E0 they are
  instead **apparent uninitialised memory**, taking one of ~3 modes across the 6 launches: all-zero
  (s001/s006/s008), an ascending 32-bit table `6e1b0100 f7210100 …` that reads like stale pointers/
  offsets (s004/s007), and a third pattern (s005). The E0 proofs **never** show the `04 00` pattern.
  **[inferred]** the client fills `A`/`M1` with a deliberate constant only on the *validated-challenge*
  success path; against the replayed E0 challenge it takes an error/short path and leaves those buffers
  stale — yet **still emits a real 20-byte `crc_hash`** every time. This is a strong sign the standard
  SRP6 `M1` check is **not** what authenticates, and is consistent with stock AzerothCore dropping the
  socket (its `M1` verify cannot pass on `04 00…`/garbage).
- **[confirmed] The `crc_hash` slot carries per-process entropy** — non-zero and distinct every
  launch, identical within a process. **[confirmed — E1/E2] It is credential-INDEPENDENT:** across
  s009–s012 (two different passwords, two different usernames) the `crc_hash` was **byte-identical**
  (`2ac15ea7…`) — because those four were connections of one process (see below). So `crc_hash` is a
  **per-process token, not a proof of the password**. Authentication rides on the hello's account/
  password fields (§3), not on this slot.

**E1/E2 result — the credentials are BOTH carried in the hello, obfuscated:**
- **Account** → 20-byte field at **`0x135`** (§3). Changes only when the username changes. Derived/
  obfuscated (no ASCII). Cross-username diff is **byte-local, not avalanche** (user#1 vs user#2 differ
  in only a few positions) ⇒ a **simple reversible transform**, not a keyed cryptographic hash.
- **Password** → byte **`0x271`** + variable-length **tail** at `0x275`, whose **length equals the
  password length**; tail content is per-connection ⇒ length-preserving keystream-style obfuscation.
- **Neither field shows any sign of an embedded server secret** — both are functions of the user's own
  credentials. The transform is the remaining unknown; because it is byte-local it is very likely
  crackable from a few known-plaintext logins (pending the plaintext strings). **Feasibility gate:
  still no stop-trigger; evidence now points toward clean-room-buildable.**
- **Note:** s009–s012 shared one `crc_hash` ⇒ they were four Login clicks in **one** client process
  (fields changed between clicks), not four relaunches. That is a clean within-process credential test;
  confirm with the user.

---

## 6. Message `0x01` response — server proof (44 B)

Decode of `live-server-proof-response.bin`:

| Offset | Len | Field (vanilla) | Value / status |
|---|---|---|---|
| 0 | 1 | cmd | `01` **[confirmed]** |
| 1 | 1 | error | `00` = SUCCESS **[confirmed]** |
| 2 | 20 | (vanilla M2) | `927b6f3a0bff844257f8041fcfbd3424886da17b` — **[confirmed]** full entropy; role **[inferred]** server proof |
| 22 | 22 | trailing | `5b24214870874877631148e500008000000000000100` — **[confirmed]** bytes; longer than vanilla's ~10 B account/survey/flags tail; sub-structure **[unknown]** |

**[confirmed]** (from `replay-auth.log`) The client rejects this response when it is replayed from a
different session ⇒ the client checks it against its own session state. Which inputs feed that check
is **[unknown]** (§9).

---

## 7. Realm-list exchange (`0x10`)

- **[confirmed]** Client request = 5 B: `10` + 4 bytes (`live_CLIENT_msg3_5.bin`). Vanilla layout is
  `cmd(1) + uint32(0)`.
- **[confirmed]** Server response = `10 | size(2, uint16 LE) | payload`. Payload contains realm
  records with ASCII `IP:port` address strings; `replay-auth.py` locates **21** such addresses with
  a plain `(\d{1,3}\.){3}\d{1,3}:\d{1,5}` regex and rewrites them, and the client accepts the
  rewritten list ⇒ **[inferred]** the realm-list body is the **standard** 3.3.5a format (no custom
  transform on this message).
- **[confirmed]** The client polls this ~1×/second while on the realm screen (55+ identical
  round-trips in the live capture).

**[confirmed — decoded from `live-realmlist-raw.bin`, 2306 B] The realm-list body is standard
3.3.5a framing carrying a TWO-BLOCK categorized set: `numRealms = 42 = 21 connectable + 21
metadata twins`.**

- **Block A (records 0–20) — connectable realms.** Standard per-realm record:
  `icon(1) | lock(1) | flags(1) | name(cstr) | "ip:port"(cstr) | population(f32) | numChars(1) |
  category(1) | realmID(1) | [if flags&0x04: major,minor,bugfix(3) + build(u16)]`. Category byte
  observed = 8/15/26/1. `flags`: 0x02=OFFLINE, 0x04=SPECIFY_BUILD (→3.3.5.13000), 0x10/0x60=NEW/
  RECOMMENDED. These are the entries that actually dial a world server.
- **Block B (records 21–41) — metadata twins, all `category = 27`, empty address.** The *name*
  field is a `!`-delimited metadata string, one per Block-A realm, same order:
  `RealmName!expansionID!gamemodeID!image!unlocked!page!index!descriptionSpell`
  e.g. `Area 52 - Free-Pick!1!0!Area52!true!1!6!13977862`,
  `Vol'jin - Conquest of Azeroth!0!11!Voljin!true!1!4!13977864`. **`page`** buckets the realm:
  **page 1 = the visible playable realms** (Area52 Free-Pick, the Conquest-of-Azeroth realms,
  Bronzebeard, Dawnrise…); page 4/50 = the hidden "dev" bucket. `image` = the gamemode art asset;
  `unlocked` gates selectability. RealmList.lua reads these via `GetRealmInfo(cat27, idx)` and
  joins them to Block A by name.

**Why a hand-built single realm never displays:** with no category-27 metadata twin, the client
has no `page`/`gamemode`/`unlocked` for it, so it falls to the hidden dev page and the main realm
screen is blank. **Fix (`shim3799.build_realmlist`): replay the whole 42-record capture, rewrite
only the 21 non-empty addresses to `127.0.0.1:8085`, clear lock + offline bits.** The genuine
Ascension list then renders and every entry dials the local world. (No Ascension data leaves the
box — the user's own capture, addresses localized; a realm list is not a credential.)

**[inferred]** Post-authentication, the protocol is stock. All custom behaviour is confined to the
`0x00` request (§3), the relocated proof material (§5–6), and the categorized realm-list layout above.

---

## 8. Cross-capture invariants (confirmed)

1. Server `N` and `g` equal the canonical WoW SRP6 values and equal what stock AzerothCore emits.
2. Marker `fc f4 f4 e6` at `0x004` is constant in every hello.
3. Block S1 (`0x018`, 285 B) is byte-identical across all captures (all sizes and all sessions).
4. **[E0]** Exactly three hello windows vary — V1 (`0x08`, 16 B), V3 (`0x235`, 60 B), tail (`0x275`,
   16 B) — and **all three are per-connection** (regenerate on every Login click, incl. within one
   process). The other 553 B are static.
5. **[E0 — corrects the old V2 claim]** `0x135` (16 B) is **byte-identical across all 8 sessions**
   (6 processes + 3 connections). It is static skeleton, not a variable window. **No per-process-only
   hello window exists.**
6. **[E0]** The 553 B static skeleton is byte-identical between the local harness login and the one
   live production login (only V1/V3/tail differ) ⇒ skeleton is client-constant, not server-driven.
7. **[E0]** The `0x01` proof is **per-process** (identical across a process's connections, distinct
   across processes) and **independent of V1/V3/tail** ⇒ those windows do not feed the proof (refutes
   H1). `A`/`M1` are placeholder (`04 00…` live) or uninitialised (E0); only `crc_hash[53:73]` carries
   per-session entropy.
8. The proof's real 20-byte slot is not a verbatim copy of any hello region (either direction).
9. A recorded challenge+proof replayed to the client is rejected before the realm-list step.
10. Stock AzerothCore closes the socket on the oversized `0x00`; a vanilla 39 B `0x00` succeeds.

---

## 9. Unresolved hypotheses (NOT established — do not treat as fact)

- **H1** ~~V1 / V3 / tail carry fresh per-session client material *used by* the proof.~~ **REFUTED by
  E0.** The proof is byte-identical across three same-process connections whose V1/V3/tail all differed,
  so those windows are **not** proof inputs. They vary per *connection*; the proof varies per *process*.
  Their role is something else (obfuscation/padding the server tolerates, or an input to a step that is
  not the proof). *(New sub-question H1′: the proof's per-process entropy comes from a startup ephemeral
  — is it seeded from the credentials, from a client file, or from an RNG? → E1/E2.)*
- **H2** The session secret is **password-derived** (SRP6-verifier style). Supported circumstantially
  by the canonical N/g/salt/B/M2 on the wire; **unproven**.
- **H3** Authentication uses an **installation credential** (a value in the user's own client files)
  rather than, or in addition to, the password. Consistent with the globally-constant S1 block;
  **unproven**.
- **H4** A **static embedded secret / server private key** is required. *This is the only branch that
  would trigger the stop-condition.* **No evidence for it yet** — and password- or install-
  independence alone would **not** establish it (could be post-derivation, deliberate randomization,
  or H3). It is confirmed only by evidence pointing specifically at a service/private secret.
- **H5** The underlying primitive is SRP6-with-repurposed-fields vs. a libsodium construction
  (the `trace-handshake.py` claim). The wire is consistent with canonical SRP6 parameters; the KDF
  that produces the proof slot and M2 is **unobserved**. **Open.**
- **H6** Roles of the placeholder salt and degenerate `A`/`M1` — decoys, ignored inputs, or inputs to
  a modified hash. **Unknown.**

---

## 10. Experiment hooks (one variable at a time; compare against a control distribution)

Each experiment uses a **local deterministic responder** that serves a **fixed** 119 B challenge
every run (so the server side is not a moving variable). Reaching a valid M2 is **not** required —
capturing the client's `0x00` and `0x01` is enough.

- **E0 — control distribution. ✅ DONE (8 sessions: 3 connections in run 1 + 5 more runs).**
  Result: hello varies only in V1/V3/tail, all **per-connection**; V2 reclassified **static**; the
  proof is **per-process** and **independent of V1/V3/tail**; only `crc_hash[53:73]` carries per-session
  entropy; skeleton matches the live login byte-for-byte. Tooling: `analyze-e0.py`,
  `compare-live-vs-e0.py`; raw in `e0-captures/`. **This retargets E1–E3:** the only outputs worth
  watching are **(a) `crc_hash` = proof[53:73]** and **(b) the 553 B static skeleton** (esp. S1/S2).
  V1/V3/tail are noise; do not chase them.
- **E1 — password.** Same username + fixed served challenge; change **only the password** across a few
  launches. Compare against E0. Decisive question: **does `crc_hash` (or any skeleton byte) become a
  function of the password?** If yes → material is credential-derived → a local server that holds the
  account's own verifier can reproduce it → **clean-room feasible, no embedded secret** (H2). If
  `crc_hash` still just varies per-launch with no password dependence, that narrows toward H1′/H3 (not
  yet H4). *Because the proof is per-process, one launch per password is enough; take 2 launches per
  password to separate password-effect from per-launch ephemeral noise.*
- **E2 — username.** Change **only the username**; find the account field. Watch the skeleton (S1/S2)
  and `crc_hash`. Locating where the username lands tells the shim how to parse the account.
- **E3 — challenge perturbation.** Vary only the served `B` / salt; see which client outputs depend on
  the server challenge. Since the proof was stable under a *constant* replayed challenge, E3 isolates
  whether `crc_hash`/M2-validation actually binds `B` → tells the shim which challenge fields matter.

> **Feasibility-gate status after E0:** unchanged — **no stop-condition trigger**. Nothing yet points
> at an embedded Ascension secret. The auth material has narrowed to a single 20-byte per-process value
> (`crc_hash`) plus a client-constant skeleton; E1 decides whether that value is credential-derived
> (clean-room-buildable) or not. No DLL tracing, no secret extraction is needed to run E1–E3.

Only if E1–E3 converge on "a fixed secret not derivable from the user's own password or client
files" does the DLL-level trace become warranted — and that is the point to pause and prefer a
clean-room / community implementation over extracting anything from the protected binary.

---

## Appendix — file inventory

```
wire-analysis/
  parse_captures.py     # log → per-message .bin + constant/variable maps
  verify.py             # crypto-message decode + invariant checks
  hello_{A,L}_c*_*.bin  # 7 client 0x00 hellos (3×636, 2×635, 2×645) + 1 vanilla 39 B control
  live_CLIENT_msg*.bin  # client side of the successful live handshake
  live_SERVER_msg*.bin  # server side of the successful live handshake
```

Regenerate: `python wire-analysis/parse_captures.py && python wire-analysis/verify.py`.

---

## M2 phase — the permissive shim (`shim3799.py`)

E0/E1/E2 established that both credentials ride in the hello (account CRACKED, password
obfuscated), the proof's `A`/`M1` are garbage, and `crc_hash` is a credential-independent
per-process token. The one remaining gate is the **server proof M2**: can a local server
compute an M2 the client accepts, using only the user's own password + on-wire values
(clean-room) rather than an Ascension secret?

**`shim3799.py`** answers this empirically. It is a full WoW 3.3.5 SRP6 *server* on
127.0.0.1:3799 that (1) frames the 645 B hello by its length field, (2) decodes the
account via pad `K`, (3) sends a standard 119 B challenge (canonical N, g=7, k=3; fixed
server salt; live `version_challenge` reused), (4) accepts the placeholder proof without
verifying M1, (5) sends a 44 B proof response (`01 00` + M2 + the 22 B live tail), then
**watches for the client's next move**: a `0x10` realm-list request ⇒ **M2 ACCEPTED**;
socket close ⇒ **rejected**. No Ascension secret, no DLL patch; uses a LOCAL test identity
whose password the operator types. Validated end-to-end by `scratchpad/selftest_shim.py`
(loopback of a real captured hello+proof; account decode + all variants exercised).

**Decisive new observation:** in the E0/E1 captures the proof carries **`A` = all-zeros
and `M1` = all-zeros** (live production used the `04 00…` placeholder). Either way the
client sends **no real ephemeral `A`**. Textbook SRP (`S = (A·v^u)^b`) therefore cannot be
the scheme. The secret-free agreement that works with **no client ephemeral** is the
**a=0 case of SRP**: the client computes `S = (B − k·v)^(u·x) = g^(b·u·x) = v^(u·b)`, and
the server computes the same `v^(u·b)` from its own `b` and the password-derived verifier
`v`. `K = SHA1_interleave(S)`, `M2 = SHA1(A ‖ M1 ‖ K)` (stock client-side check). This
(variant 0), its no-`u` sibling `S = v^b` (variant 1), and textbook SRP as a control
(variant 2) are the leading hypotheses; `compute_M2()` holds 8 variants and the shim
**auto-advances one per connection**, so each Login click tests the next and logs which.

**Gate status: still NO stop-trigger.** Every candidate M2 is built from the user's own
password-derived verifier + public challenge values — no embedded secret. If the search
exhausts and the client accepts none, the next step is community/clean-room reference, not
binary secret extraction.

---

## 11. World handshake (`127.0.0.1:8085`) — CRACKED, and it is STOCK 3.3.5a

**[confirmed — `world_probe.py`, digest reproduced byte-for-byte]** After the realm list, selecting
a realm makes the client dial the realm's world address and wait (server-speaks-first). We sent the
exact AzerothCore `SMSG_AUTH_CHALLENGE` (`uint32(1) | authSeed(4) | 32 random`, body 40, wire
`size(BE) | opcode 0x01EC(LE) | body`) and captured the client's `CMSG_AUTH_SESSION` (opcode
`0x01ED`). Field order + digest formula match stock AzerothCore `WorldSocket.cpp` exactly:

```
Digest = SHA1( Account | 00 00 00 00 | clientSeed(4) | serverSeed(4) | SessionKey )
```

**Observed (realm Rexxar picked):** `build = 12344 (0x3038)` (note: 12344, not 12340),
`account = "test"` sent **lowercase, not uppercased**, `realmID = 23` (the picked realm's id from
our list), `clientSeed = eb121886`, digest `a56800e5…6ed6`. A known-plaintext window search over the
client auth object reproduced the digest with `account as-sent`, seed order `client,server`.

**[confirmed] The world SessionKey is a SEPARATE 40-byte value, NOT the 32-byte login K.**

| Object slot | Bytes | Value (this session) | Used for |
|---|---|---|---|
| `authobj+0x120` | 32 | `1227fb33…2fd062` | LOGIN proof `M2 = HMAC-SHA256(K,"OK")` |
| `authobj+0x140` (= K+32) | **40** | `f8a805e5…3e7369` | **WORLD digest / crypt (stock 3.3.5a SessionKey)** |

So the client holds a standard 40-byte WoW session key at `authobj+0x140`, right after the login K,
and the world channel uses it with the ordinary AzerothCore formula. **No Ascension secret, no
derivation to reverse:** a local world server only needs those 40 bytes, which we read passively via
RPM (same surface as K).

**Path to in-world (integration, not RE):**
1. Read `authobj+0x140` (40 B) via RPM during/after login (extend `rpm_readk`).
2. Write it to `acore_auth.account.sessionkey` for the account (AC's `HandleAuthSessionCallback`
   reads the key from that column — `SessionKey = fields[1].Get<Binary,40>()`).
3. Point the picked realm's address at the real AzerothCore worldserver; align `realmID` (client
   sends the list's realm id → must equal `realm.Id.Realm`, else `REALM_LIST_REALM_NOT_FOUND`) and
   allow build 12344. Then AC's stock digest check passes → `SMSG_AUTH_RESPONSE(OK)` → char enum.

Content compatibility (Ascension custom DBC/opcodes vs stock AC world) is a separate question from
the handshake, which is now solved.
