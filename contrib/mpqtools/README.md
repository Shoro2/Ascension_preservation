# mpqtools — `mpqcat` and `mpqfind`

The two small StormLib programs that `tools/extract_ui.py` and
`tools/extract_tree.py` shell out to. They were written for this project and are
included here as source so a fresh machine can build them; the compiled `.exe`
files are not shipped.

Both take the client's `Data` directory and open every `*.MPQ` there and in
`Data\enUS` **read-only**. Ascension's custom patch archives carry no
`(listfile)`, so tools that enumerate see nothing in them; these resolve an
exact internal path through the hash table instead, which still works.

| Tool | Job |
|---|---|
| `mpqcat <DataDir> <InternalPath> [OutFile]` | extract one file by exact internal path (or `--list <paths.txt> <OutDir>` for many) |
| `mpqfind <DataDir> --which <InternalPath>` | print **every** archive that holds the path, with the size each one holds, so the real override chain can be established by inspection |
| `mpqfind <DataDir> --from <Archive.MPQ> <InternalPath> [OutFile]` | read the path out of **one named archive**, bypassing precedence |

Use `mpqfind --which` before trusting anything `mpqcat` returns: `mpqcat`
orders archives by path length and reverse-lexical name, which is only an
approximation of the client's real precedence, and it will hand you the stock
3.3.5a copy of a file that Ascension overrides. `mpqfind --from` is the reliable
way to take a file from the archive you have decided is authoritative.

## Where things live in the Ascension client (measured)

| File | Archive |
|---|---|
| `Interface\GlueXML\AccountLogin.lua` (the redirect glue) | `patch-B.MPQ` |
| `DBFilesClient\CharacterAdvancement*.dbc` (7 files, CA dataset) | `patch-M.MPQ` |
| `DBFilesClient\CharacterCreationArchetype*.dbc` | `patch-M.MPQ` |
| `DBFilesClient\ChrClasses.dbc` | `patch-M.MPQ` |
| `DBFilesClient\Spell.dbc` (209,509 records) | `patch-T.MPQ` |

## Building

Requires Visual Studio 2022 (any edition; the `.bat` files call `vcvars64.bat`
from Community, edit the path if yours differs) and a StormLib checkout built
as a static Win64 library (<https://github.com/ladislav-zezula/StormLib>, MIT).
Set `STORMLIB` to that checkout, or edit the default in the `.bat`:

```bat
set STORMLIB=C:\src\StormLib
build_mpqcat.bat
build_mpqfind.bat
```

Then point the Python tools at the binaries:

```
set MPQCAT=C:\path\to\mpqcat.exe
set MPQFIND=C:\path\to\mpqfind.exe
```

Any other extractor works in their place as long as it accepts the same
arguments. A pure-Python MPQ reader (v1/v2, sector decompression, PKWARE DCL
explode for compression `0x08`) would remove the compiler dependency entirely
and is welcome here. `mpyq` does **not** work on these archives.
