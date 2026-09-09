# contrib/AscensionRedirect — packet-layer redirect + auth-send probe

Contributed by another researcher working the same problem independently, and
lightly adapted here. Kept because two things in it are useful to this project,
and because the approach itself is worth recording as a road not taken.

Machine-specific values from the original (a hard-coded LAN address, an
interpreter path, an absolute script path) have been replaced with flags. The
author's own identifiers are deliberately not reproduced.

---

## What it is

| File | What it does |
|---|---|
| `redirect.py` | WinDivert (pydivert) NAT. Rewrites `client → <portal IP>:port` to `client → <your server>:port` and the replies back, so the client's socket accepts them. Hexdumps the first N data packets each way. |
| `probe.py` / `probe.js` | Frida agent hooking `ws2_32!send/sendto/WSASend`, filtering for the `0x00` auth hello, and backtracing the caller chain — labelling each frame with the `Extensions.dll` PE section it lands in, to answer "is the packet-building code inside the VMProtect `.vm_sec` region, or normal compiled code?" |
| `force-realm-glue.lua` | The glue-Lua redirect, ready to paste. Canonical write-up is [`docs/HOW-THE-REDIRECT-WORKS.md`](../../docs/HOW-THE-REDIRECT-WORKS.md) §2 — that document is the source of truth; this file is a convenience copy. |

```
pip install -r requirements.txt          # pydivert, frida
python redirect.py --real 192.168.1.50   # elevated: WinDivert loads a driver
python probe.py                          # elevated, client at the login screen
```

## Why this stack does not use `redirect.py`

The original premise was that the portal address cannot be changed from disk —
"the IP lives inside the client and is decrypted at runtime" — so the packets
have to be NATed instead.

Half of that is right, and independently confirmed here: `Config.wtf` does not
hold. Write `127.0.0.1` into it and the `realmList` CVar reads back as the portal
address by the time the login screen is up. `Data\enUS\realmlist.wtf` is a dead
end too — Ascension ships it neutered.

But a loose `Interface\GlueXML\AccountLogin.lua` does hold, which is the lever
this project actually uses: no kernel driver, no admin, no NAT. See
[`docs/HOW-THE-REDIRECT-WORKS.md`](../../docs/HOW-THE-REDIRECT-WORKS.md) §2.

So `redirect.py` is kept here as an instrument, not as part of the runnable
stack.

## The one thing it can do that the glue lever cannot

**`--map CLIENTPORT:SERVERPORT`** (added here) rewrites the destination *port* as
well as the address, and that is a live escape hatch for the world-port
allow-list.

`Extensions.dll+0xA3C950` compares the world endpoint the client stored — a
cstring at `Ascension.exe 0x00C79C9E` of the form `"127.0.0.1:<port>"` — against
a 91-entry plaintext allow-list in `.rdata`. Only three loopback endpoints are on
it: **`127.0.0.1:8085`, `:8087`, `:8088`**. Anything else lets the client into the
world and then kills it seconds after the world draws, with ERROR #132 at a fixed
EIP of `0xCD0CA1xx`. `tools/allowlist.py` checks this statically.

The check reads **the string the client stored, not the socket's real peer.** So:

```
python redirect.py --real 127.0.0.1 --ports 8087 --map 8087:9087
```

lets the client dial an allow-listed `8087` while the world server listens on
`9087` — the only known way to put the world on a port that is not one of the
three, if `8085`/`8087`/`8088` ever stop being enough.

**Untested.** Designed against the disassembly; this project has not needed it,
because moving the archive world server to `8087` was a one-line fix. The
loopback source-rewriting path in `redirect.py` is likewise untested — a packet
with `src=<LAN IP> dst=127.0.0.1` is not deliverable, so the source has to move to
loopback too and be restored on the way in. Both are flagged in the code.

## A caution about the probe's premise

The probe exists to test the claim that the login is libsodium X25519 +
HMAC-SHA256 with the KDF hidden in `.vm_sec`. **Treat that as an unproven
hypothesis.** It comes from static analysis of `Extensions.dll`; nothing on the
wire requires it, and the server challenge carries the canonical WoW SRP6 modulus
and `g=7`. See [`docs/WIRE-SPEC.md`](../../docs/WIRE-SPEC.md) §4 and its trust
note — that claim, stated confidently in a tool comment, steered real work in the
wrong direction for a while.

Run the probe, but weigh what it says about the DLL against what the bytes say on
the wire, and let the bytes win.

`probe.js` here resolves the `.vm_sec` bounds from the PE section table rather
than the original's hard-coded `base+0xc46000 / 0x8200`: those are correct for one
build, and a stale constant makes every frame silently report "not virtualized",
which is the worst failure mode this tool could have.
