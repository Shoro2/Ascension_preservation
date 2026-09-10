# contrib/InProcessKeyOracle — read the login key from *inside* the client

This is an optional add-on that removes the one privileged step in the redirect stack:
`shim3799.py` normally reads the client's per-session login key **K** with
`ReadProcessMemory`, which forces the shim (and `world_server.py`) to run at the **same
integrity level as the client** — the elevation dance described in
[`docs/HOW-THE-REDIRECT-WORKS.md`](../../docs/HOW-THE-REDIRECT-WORKS.md) §3 and §5.

With this add-on, K is read from **inside** the client instead. No `OpenProcess`, no
`ReadProcessMemory`, no integrity match, no "run it elevated."

**Credit:** the in-process-read idea is from FirstOni's *AscensionAuthGate*. This package
lifts only that one idea into the existing shim rather than adopting the whole DLL; the
reasoning is in [`docs/AUTH-APPROACHES-EVALUATED.md`](../../docs/AUTH-APPROACHES-EVALUATED.md).

---

## How it works

```
Ascension.exe --(static import, by name)--> dinput8.dll        (this proxy)
                                               | forwards all 6 exports
                                               v
                                            dinput8_orig.dll    (your own renamed dinput8)
                                               | DllMain LoadLibrary()s:
                                               v
                                            kexport.dll         (in-process K oracle, :37281)

shim3799.py --(TCP 127.0.0.1:37281, at proof time)--> kexport.dll --> 32-byte K
```

`kexport.dll` runs a loopback server. On each connection it does one live read of the same
pointer chain `rpm_readk.py` uses — `Extensions base + 0xbdbc04 → obj → +0x120` — and returns
`status(1) || K(32)`. `server/inproc_readk.py` is the client; `shim3799.py` already prefers it,
falling back to RPM and then to variant-guess, so **nothing here is required** — it is a pure
upgrade when present.

It only reads memory. It patches nothing, and never touches `Extensions.dll` or `Ascension.exe`
on disk.

## Files

| File | What it is |
|---|---|
| `kexport.c` | The oracle. Reads K in-process, serves it on `127.0.0.1:37281`. |
| `dinput8_proxy.c` | The file-drop loader that pulls `kexport.dll` into the client. |
| `build_kexport.bat` / `build_proxy.bat` | 32-bit MSVC builds (x86, static CRT). |

## Build

Needs the MSVC x86 toolchain ("Desktop development with C++"). Edit the `vcvarsall.bat`
path in each `.bat` if yours differs, then:

```
build_kexport.bat      -> kexport.dll
build_proxy.bat        -> dinput8.dll
```

## Install (into a **writable** client copy only)

> Deploy only in a client copy you own and can write to. Do **not** modify a live client
> install that is a junction / symbolic link to another realm — your files would leak onto it.

1. Copy your own `C:\Windows\SysWOW64\dinput8.dll` next to `Ascension.exe`, renamed to
   `dinput8_orig.dll`.
2. Drop `dinput8.dll` (the proxy) and `kexport.dll` into the same folder.
3. Launch the client normally. Start `shim3799.py` **without** elevation — its banner should
   print `IN-PROCESS ORACLE OK on :37281`.

To uninstall, delete `dinput8.dll`, `dinput8_orig.dll`, and `kexport.dll`.

## Limits

- **One instrumented client at a time** — the oracle binds a single fixed port.
- **Per-build offset.** `0xbdbc04`/`+0x120` are for the same client build as `rpm_readk.py`
  (independently confirmed identical to AuthGate's). A different build needs them re-derived;
  until then, `shim3799.py` still works via its RPM/variant fallback.
- **Client-side redirect is unchanged.** This does not replace the loose-`AccountLogin.lua`
  redirect; it only changes *where the key is read from*.
