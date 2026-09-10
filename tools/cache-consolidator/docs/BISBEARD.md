# BisBeard supplemental item importer

This importer preserves a reviewed `ClassicGearPlannerDB_coa` Dexie export as a
separate, queryable item catalog. It does not write a realm database, manufacture
WDB records, replace captured values, or infer loot probabilities.

The current source was supplied as `ClassicGearPlannerDB_coa-260907-132512.rar` and
attributed by its contributor to [BisBeard](https://coa.bisbeard.com/), a CoA gear
planner and item browser. That attribution does not authenticate the export or
establish its accuracy. The original export has no explicit capture timestamp;
the filename is retained here as a source label, not a verified collection date.
No license grant from BisBeard is asserted by this documentation.

## Reproduce the import

Python 3.10 or newer; standard library only. Run from this cache-consolidator
component directory. Obtain the export and the captured `union/itemcache.tsv.gz`
comparison baseline, then use their actual paths in place of the examples.

```sh
python -B tools/import_bisbeard.py import input.dexie --output supplemental/bisbeard --expected-sha256 REVIEWED_SOURCE_SHA256 --cache itemcache.tsv.gz --baseline-revision FULL_BASELINE_GIT_COMMIT --archive input.rar
python -B tools/import_bisbeard.py verify supplemental/bisbeard/REVIEWED_SOURCE_SHA256
python -B tools/test_bisbeard.py
```

`--archive` and `--baseline-revision` are optional. The archive is only hashed;
its local path and bytes are not copied. The exact `.dexie` source bytes are
preserved in gzip form. A `.dexie.gz` from the published snapshot can be restored
with any gzip utility before invoking `import` again.

The SHA-256 argument binds the operation to the export reviewed by the operator.
It does not by itself establish trust. Only the observed Dexie schema, database
version 1.2, 75 phase/category tables, known item fields and nested structures are
accepted. Unknown fields, unknown tables/types, duplicate object keys, duplicate
primary keys within a table, missing blocks, inconsistent counts and personal-data
indicators fail before a snapshot is installed. Nothing from the export is
executed. This is an explicit supplemental workflow; arbitrary `.dexie` files in
the ordinary intake inbox are not silently approved for publication.

## Output contract (schema version 1)

A successful import atomically creates `OUTPUT/<full-source-sha256>/`:

| File | Content |
| --- | --- |
| `source.dexie.gz` | Byte-exact original export, including metadata, ordering and Dexie annotations. |
| `rows.jsonl.gz` | Every row wrapped with source hash, source table, original row index, planner/base IDs, candidate item link, comparison status and original `record` object. |
| `catalog.sqlite.gz` | Searchable database containing all original row objects, source metadata and all 75 table declarations (including empty tables). |
| `comparison.json.gz` | Complete missing-candidate and name-conflict lists, tied to the comparison baseline hash. |
| `manifest.json` | Schema, provenance, source/archive/baseline hashes, counts, interpretation limits and hashes/sizes of every artifact. |

Gzip timestamps are zeroed; builds with the same interpreter, source and baseline
are reproducible. An identical repeat verifies the existing snapshot without
rewriting it. A changed baseline or provenance cannot overwrite that snapshot;
use a separate output root for a new comparison. Interrupted builds never install
a partial snapshot. Input archives and captured cache files are never changed.

`verify` checks every artifact hash, source recovery, schema/counts, each normalized
record, the exact SQLite schema, every SQLite item field, SQLite integrity, comparison report consistency
and text indicators. Artifact hashes detect corruption, not malicious replacement
of a whole snapshot; use its Git history and independently retained source hash to
establish provenance. Comparison accuracy still depends on the specified captured
baseline; the importer does not validate website stats or item-source claims.

## Identity and interpretation

The database primary key is `(source_sha256, source_table, planner_id)`. Planner
IDs and explicit base IDs remain strings, including IDs outside the unsigned
32-bit game-entry range. All rows survive even when IDs recur across tables.
`row_index` retains the original order within each table. Every original field,
including `stats`, `damage`, `tooltip`, `classes`, `setBonuses`, `unique`, and
`$types`, survives inside `record` / `record_json` without renaming or coercion.

`candidate_item_id` follows an explicit `baseItemId` if present, otherwise the
planner ID, only when it is a canonical positive unsigned 32-bit integer string.
This is an association candidate, never proof of a real item. An explicit base ID
differing from the planner ID sets `is_variant`; the planner record remains
separate from that base. An invalid explicit base is not replaced with a guessed ID.

Comparison statuses:

- `name-match`: direct ID exists and a captured name matches case-insensitively.
- `name-conflict`: direct ID exists, but none of the captured names match.
- `candidate-missing`: direct candidate ID is absent from the captured baseline.
- `variant-base-present` / `variant-base-missing`: explicit variant base lookup.
- `unmapped-id`: no valid unsigned 32-bit association is available.

All captured names for an ID are retained in `captured_names`; a matching name
does not verify stats. Phase numbers remain source labels. Source descriptions
remain website claims. Unknown drop rates remain the literal original strings.
The missing-candidate report is a research queue, not an executable SQL migration.

## Query the preserved database

Decompress `catalog.sqlite.gz` to `catalog.sqlite`, then open it read-only in any
SQLite browser or Python. JSON is stored as text and can be queried with SQLite's
JSON functions when available:

```sql
-- All representations associated with an item, preserving planner variants.
SELECT planner_id, name, is_variant, comparison_status,
       json_extract(record_json, '$.stats') AS website_stats,
       json_extract(record_json, '$.source') AS website_source
FROM items WHERE candidate_item_id = 647;

-- Conflicting direct item names for review.
SELECT candidate_item_id, name, captured_names_json
FROM items WHERE comparison_status = 'name-conflict';

-- Candidate additions; these are not verified live-server entries.
SELECT planner_id, name, record_json
FROM items WHERE comparison_status = 'candidate-missing';
```

`source_tables` preserves empty tables and declarations. `sources` identifies the
original export. No local filesystem paths, contributor account identities,
website credentials or personal profiles are added to the database.

Before publishing a new snapshot, run the independent `audit_publish.py` against
the actual destination directory as well as `verify`. The audit reads inside gzip
files, including the SQLite bytes. Schema validation and pattern scans complement
operator review; neither establishes third-party data correctness.
### SQLite byte-layout audit finding in this snapshot

The legacy raw-byte publication scanner reports one GUID-shaped match inside the
compressed SQLite artifact after decompression. It begins at byte offset 35372135:
SQLite's binary encoding of a row index is adjacent to numeric planner/base IDs.
The apparent match is absent from the original Dexie bytes, all normalized JSON
and a complete SQL dump. It is not a stored player identifier.

This finding was reviewed rather than suppressed. `verify` checks the exact
SQLite schema (rejecting extra tables, columns, views or triggers), every stored
field against the source/normalized data, and scans the complete logical SQL dump.
The binary artifact is retained unchanged. Future raw-byte audit findings require
the same specific investigation; a clean text scan or this explanation is not a
blanket exception for other SQLite files or later snapshots.