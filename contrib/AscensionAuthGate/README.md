# AscensionAuthGate — reviewed local bridge adaptation

Credit to **FirstOni** for the original AscensionAuthGate design and implementation. This preservation adaptation removes diagnostic capture and hardens the credential gate. It targets the original Ascension build 12340 client with the local Ascension bridge on **127.0.0.1:8088**, backed by AzerothCore on 8086. It does not require the legacy `shim3799.py`.

## Verified behavior

On 2026-09-09, the reviewed source built without compiler warnings and passed **59 isolated checks**, plus **two real local authserver checks**: wrong password rejected and correct password accepted with the server's SRP proof verified. The original client then reached the world through the bridge with the shim stopped. The user reported their existing original-client character was **working flawlessly**. The separate test client was removed only after that confirmation; its shared Data junction was unlinked without traversing its target.

This is for one trusted Windows machine, one Ascension client at a time, and the exact executable/extension hashes enforced by the installer. Other WoW clients and other realm databases are outside its scope. Read [SECURITY-REVIEW.md](SECURITY-REVIEW.md) for what was reviewed and the remaining boundaries.

## Build and verify

Requirements: Windows, Visual Studio 2022 Community C++ x86 build tools, Python 3, and the `pefile` Python package. Adjust the vcvars32 path in the batch files if your Visual Studio edition is elsewhere. No precompiled proxy, genuine client DLL, game executable, game data, captured packet or private key is distributed here.

```powershell
python -m pip install pefile
.\build.bat
.\test.bat
python .\verify-build.py
```

Build output stays in ignored `build/`. `verify-build.py` inspects PE32 architecture, the sole `ClientExtensionsDummy` export, forbidden diagnostic markers/imports, and source/build hashes. It does not load the DLL. Review the source yourself before building; an import scan is not a malware certification.

Optional real authserver checks use an existing disposable local test account. Close its game client first, set `AUTHGATE_TEST_USER` and `AUTHGATE_TEST_PASSWORD` in your current shell, and run `.\test.bat --live-gate`. Clear those environment variables afterward. Tests do not create accounts or alter game databases directly; real authentication updates that account's normal session state.

## Install on the original client

Stop the Ascension client. Pass its **real directory**, resolving any hub alias/junction yourself:

```powershell
.\install-client.ps1 -ClientRoot 'C:\YourAscensionClient'
```

The installer validates the exact supported executable and genuine extension, renames the genuine DLL to `Extensions_orig.dll`, and creates the reviewed proxy as `Extensions.dll`. It rejects an unexpected existing proxy or backup rather than overwriting it. The genuine extension remains intact and is chain-loaded for the existing UI. The installer never touches `Data`. An unsuccessful initial copy restores the genuine filename.

For a manual return to the unmodified extension, close the client, verify `Extensions_orig.dll` against the original hash enforced in the installer, remove only this package's verified proxy, and rename the genuine companion back. Configure the old auth route separately if deliberately returning to the legacy shim. Never restore the old key-capturing diagnostic AuthGate build.

## Launch and make it the realm default

The archive's existing loose `Interface/GlueXML/AccountLogin.lua` with its `ASCENSION_ARCHIVE_REALMLIST` marker must already be installed. Run the intended realm's authserver on loopback 3724, worldserver on 8086, and bridge on 8088. Stop the legacy auth shim. From a **normal unelevated** PowerShell:

```powershell
.\start-client.ps1 -ClientRoot 'C:\YourAscensionClient' -Mode coa -ExpectedAuthserverPath 'C:\YourRealm\authserver.exe'
```

Use `-Mode ascension` for Free-Pick. The launcher sets only this process's mode/compatibility environment, preserves unrelated client settings, and sets the archive realm override to loopback 3725. CoA and Free-Pick keep distinct realm names and metadata; the bridge/profile continues to own the character-database selection. `-NoLaunch` performs read-only preflight checks. The launcher rejects another Ascension client, an occupied 3725 listener, incorrect client hashes, shared configuration directories, and an authserver from a different realm when the expected path is supplied. It never starts/stops a realm or changes shared Data.

For an AzerothRealm hub, change **only** the existing `ascension` and `coa` profiles that share this client: set `world.authserver` to `true`, remove only the `shim3799` entry from `world.helpers`, and retain each profile's world config, bridge arguments, and database names. Have their existing launcher call `start-client.ps1` with the selected mode and that realm's expected authserver executable. Leave the other realm profiles and their launchers untouched. The client owns private auth listener 3725; the hub must not treat it as a server helper that must exist before a client starts.

## Privacy and attribution

The proxy writes only `proxy_auth.log` with bounded login/status details, excluding usernames, passwords, keys and packet contents. It does not write `worldkey.bin`, run SQL/commands, scan other processes, install a service, or change the registry. Raw diagnostic files and identified local history copies from the earlier experiment were purged, not included in this package. Delete any old `proxy_key*`, `proxy_net`, `proxy_files` or raw world-key artifacts retained from diagnostic versions; do not archive or publish them.

See [THIRD-PARTY-NOTICE.md](THIRD-PARTY-NOTICE.md) for FirstOni's credit and the supplied package's licensing provenance. This is an adaptation; the author is not represented as endorsing these later changes.
