"""Preserve a reviewed BisBeard Dexie export in a lossless supplemental catalog.

Standard library only. See docs/BISBEARD.md. No realm connections or WDB writes.
"""
import argparse
import collections
from contextlib import closing
import csv
import gzip
import hashlib
import io
import json
import math
import re
import sqlite3
import tempfile
from pathlib import Path

SCHEMA_VERSION = 1
SOURCE_URL = 'https://coa.bisbeard.com/'
DATABASE = 'ClassicGearPlannerDB_coa'
CATEGORIES = set('affixed bloodforged crafting dungeon enchants events gems pvp quests raid reputation vendor worldboe worldboss worldforged'.split())
STRINGS = set('id name slot type quality source version dropRate description icon equipLoc sourceCategory affixId baseItemId setName bloodforgedType tooltip requiredFaction randomSuffixId randomPropertyId'.split())
INTEGERS = set('itemLevel reqLevel phase suffixEntry suffixFactor'.split())
BOOLEANS = {'unique', 'uniqueEquip'}
NESTED = {'stats', 'damage', 'classes', 'setBonuses', '$types'}
REQUIRED = set('id name slot type quality stats source itemLevel reqLevel version dropRate description icon classes uniqueEquip equipLoc phase sourceCategory $types'.split())
STATS = set('stamina hitRating armor strength dodge critRating attackPower fireResist armorPenetration expertise resilienceRating spirit spellPower agility intellect natureResist defense hasteRating frostResist shadowResist parry block feralAttackPower arcaneResist mp5 shieldBlockValue spellPenetration blockValue mana hp5 health holySpellPower arcaneSpellPower fireSpellPower frostSpellPower healingPower shadowSpellPower'.split())
PATTERNS = {
    'email': re.compile(r'[\w.+-]+@[\w-]+\.[a-zA-Z]{2,}'),
    'player GUID': re.compile(r'0x[0-9A-Fa-f]{16}'),
    'account path': re.compile(r'WTF[\\/]+Account[\\/]', re.I),
    'local path': re.compile(r'\b[A-Z]:[\\/]', re.I),
}


SCHEMA_SQL = '''
        PRAGMA user_version=1;
        CREATE TABLE sources (source_sha256 TEXT PRIMARY KEY, metadata_json TEXT NOT NULL);
        CREATE TABLE source_tables (source_sha256 TEXT NOT NULL, table_name TEXT NOT NULL,
            row_count INTEGER NOT NULL, metadata_json TEXT NOT NULL,
            PRIMARY KEY(source_sha256, table_name));
        CREATE TABLE items (source_sha256 TEXT NOT NULL, source_table TEXT NOT NULL,
            row_index INTEGER NOT NULL, planner_id TEXT NOT NULL, base_item_id TEXT,
            candidate_item_id INTEGER, is_variant INTEGER NOT NULL,
            name TEXT NOT NULL, phase INTEGER NOT NULL, source_category TEXT NOT NULL,
            comparison_status TEXT NOT NULL, captured_names_json TEXT NOT NULL,
            record_json TEXT NOT NULL,
            PRIMARY KEY(source_sha256, source_table, planner_id),
            UNIQUE(source_sha256, source_table, row_index));
        CREATE INDEX items_candidate ON items(candidate_item_id);
        CREATE INDEX items_name ON items(name COLLATE NOCASE);
        CREATE INDEX items_status ON items(comparison_status);
        '''


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encode(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'Duplicate JSON object key')
        result[key] = value
    return result


def parse(raw):
    def invalid_constant(value):
        raise ValueError('Non-finite JSON number')
    return json.loads(raw, object_pairs_hook=unique_object, parse_constant=invalid_constant)


def exact_keys(value, keys, label):
    require(type(value) is dict and set(value) == set(keys), 'Unsupported ' + label + ' schema')


def screen(text):
    for label, pattern in PATTERNS.items():
        require(not pattern.search(text), 'Publication review required: ' + label + ' indicator')


def uint32(value):
    if isinstance(value, str) and len(value) <= 10 and re.fullmatch(r'[1-9][0-9]*', value) and int(value) <= 0xffffffff:
        return int(value)
    return None


def validate_row(row, phase, category):
    require(type(row) is dict, 'Item row must be an object')
    require(REQUIRED <= row.keys(), 'Missing required item fields')
    require(row.keys() <= STRINGS | INTEGERS | BOOLEANS | NESTED, 'Unknown item fields need review')
    for key, value in row.items():
        if key in STRINGS:
            require(type(value) is str, 'Expected string field: ' + key)
        elif key in INTEGERS:
            require(type(value) is int, 'Expected integer field: ' + key)
        elif key in BOOLEANS:
            require(type(value) is bool, 'Expected boolean field: ' + key)
    require(bool(row['id']) and bool(row['name']), 'Empty item ID or name')
    require(row['phase'] == phase and row['sourceCategory'] == category, 'Table/row classification mismatch')
    require(type(row['classes']) is list and all(type(v) is str for v in row['classes']), 'Invalid classes')
    require(row['$types'] == {'classes': 'arrayNonindexKeys'}, 'Unknown Dexie type annotations')
    require(type(row['stats']) is dict and row['stats'].keys() <= STATS, 'Unknown stat fields')
    require(all(type(v) is int for v in row['stats'].values()), 'Invalid stat values')
    if 'damage' in row:
        exact_keys(row['damage'], {'min', 'max', 'speed'}, 'damage')
        require(all(type(v) in (int, float) and math.isfinite(v) for v in row['damage'].values()), 'Invalid damage')
    if 'setBonuses' in row:
        value = row['setBonuses']
        require(type(value) is dict and all(re.fullmatch(r'[1-9][0-9]*', k) and type(v) is str for k, v in value.items()), 'Invalid set bonuses')
    screen(encode(row).decode('utf-8'))


def load_source(raw):
    screen(raw.decode('utf-8-sig'))
    doc = parse(raw)
    exact_keys(doc, {'formatName', 'formatVersion', 'data'}, 'export')
    require(doc['formatName'] == 'dexie' and type(doc['formatVersion']) is int and doc['formatVersion'] == 1, 'Unsupported export format')
    data = doc['data']
    exact_keys(data, {'databaseName', 'databaseVersion', 'tables', 'data'}, 'database')
    require(data['databaseName'] == DATABASE and data['databaseVersion'] == 1.2, 'Unsupported database/version')
    require(type(data['tables']) is list and type(data['data']) is list, 'Invalid table lists')
    tables = {}
    for table in data['tables']:
        exact_keys(table, {'name', 'schema', 'rowCount'}, 'table')
        name = table['name']
        require(type(name) is str, 'Invalid table name')
        match = re.fullmatch(r'items_([1-5])_([a-z]+)', name)
        require(match is not None and match[2] in CATEGORIES, 'Unknown table needs review')
        require(name not in tables and table['schema'] == 'id', 'Duplicate table or unsupported key schema')
        require(type(table['rowCount']) is int and table['rowCount'] >= 0, 'Invalid row count')
        tables[name] = table
    expected = {f'items_{phase}_{category}' for phase in range(1, 6) for category in CATEGORIES}
    require(set(tables) == expected, 'Expected all 75 phase/category tables, including empty tables')
    blocks, rows = set(), []
    for block in data['data']:
        exact_keys(block, {'tableName', 'inbound', 'rows'}, 'data block')
        name = block['tableName']
        require(type(name) is str and name in tables and name not in blocks, 'Unknown or duplicate table block')
        require(block['inbound'] is True and type(block['rows']) is list, 'Unsupported data block')
        blocks.add(name)
        require(len(block['rows']) == tables[name]['rowCount'], 'Table row count mismatch')
        _, phase, category = name.split('_')
        seen = set()
        for index, row in enumerate(block['rows']):
            validate_row(row, int(phase), category)
            require(row['id'] not in seen, 'Duplicate primary key within table')
            seen.add(row['id'])
            rows.append((name, index, row))
    require(blocks == set(tables), 'Missing table data blocks')
    return doc, rows


def cache_names(raw):
    rows = csv.DictReader(io.StringIO(gzip.decompress(raw).decode('utf-8'), newline=''), delimiter='\t')
    require(rows.fieldnames is not None and {'entry', 'name'} <= set(rows.fieldnames), 'Expected itemcache TSV entry/name columns')
    result = collections.defaultdict(set)
    for row in rows:
        key = uint32(row['entry'])
        require(key is not None and row['name'] is not None, 'Invalid captured item row')
        result[key].add(row['name'])
    return dict(result)


def normalized(table, index, row, source_hash, captured):
    base = row.get('baseItemId')
    variant = base is not None and base != row['id']
    candidate = uint32(base if base is not None else row['id'])
    names = sorted(captured.get(candidate, ()))
    if candidate is None:
        status = 'unmapped-id'
    elif variant:
        status = 'variant-base-present' if names else 'variant-base-missing'
    elif not names:
        status = 'candidate-missing'
    elif row['name'].casefold() in {name.casefold() for name in names}:
        status = 'name-match'
    else:
        status = 'name-conflict'
    return dict(source_sha256=source_hash, source_table=table, row_index=index,
                planner_id=row['id'], base_item_id=base, candidate_item_id=candidate,
                is_variant=variant, planner_id_is_uint32=uint32(row['id']) is not None,
                comparison_status=status, captured_names=names, record=row)


def gz_write(path, data):
    path.write_bytes(gzip.compress(data, compresslevel=9, mtime=0))


def build_database(path, source_meta, table_meta, records):
    with closing(sqlite3.connect(path)) as db, db:
        db.executescript(SCHEMA_SQL)
        db.execute('INSERT INTO sources VALUES (?,?)', (source_meta['sha256'], encode(source_meta).decode()))
        db.executemany('INSERT INTO source_tables VALUES (?,?,?,?)',
            [(source_meta['sha256'], t['name'], t['rowCount'], encode(t).decode()) for t in table_meta])
        db.executemany('INSERT INTO items VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)',
            [(r['source_sha256'], r['source_table'], r['row_index'], r['planner_id'], r['base_item_id'],
              r['candidate_item_id'], int(r['is_variant']), r['record']['name'], r['record']['phase'],
              r['record']['sourceCategory'], r['comparison_status'], encode(r['captured_names']).decode(),
              encode(r['record']).decode()) for r in records])
        require(db.execute('PRAGMA integrity_check').fetchone()[0] == 'ok', 'SQLite integrity failure')


def record_counts(records, table_count):
    return dict(tables=table_count, rows=len(records),
                unique_planner_ids=len({r['planner_id'] for r in records}),
                variants=sum(r['is_variant'] for r in records),
                ids_outside_uint32=sum(not r['planner_id_is_uint32'] for r in records),
                known_drop_rates=sum(r['record']['dropRate'].strip().casefold() not in ('', 'unknown') for r in records),
                comparison_status=dict(sorted(collections.Counter(r['comparison_status'] for r in records).items())))


def database_schema(db):
    return db.execute('SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name').fetchall()


def compare(records, baseline_hash):
    direct = collections.defaultdict(list)
    for r in records:
        if not r['is_variant'] and r['candidate_item_id'] is not None:
            direct[r['candidate_item_id']].append(r)
    missing, conflicts = [], []
    for key in sorted(direct):
        values = direct[key]
        for r in values:
            item = dict(candidate_item_id=key, source_table=r['source_table'], planner_id=r['planner_id'],
                        planner_name=r['record']['name'], captured_names=r['captured_names'])
            if r['comparison_status'] == 'candidate-missing':
                missing.append(item)
            elif r['comparison_status'] == 'name-conflict':
                conflicts.append(item)
    return dict(baseline_sha256=baseline_hash, method='ID association and case-insensitive names only; no stat or source verification',
                direct_candidate_ids=len(direct), missing_candidate_ids=len({r['candidate_item_id'] for r in missing}),
                name_conflict_rows=len(conflicts), missing_candidates=missing, name_conflicts=conflicts)


def verify(folder):
    folder = Path(folder)
    manifest = parse((folder / 'manifest.json').read_bytes())
    require(manifest['schema_version'] == SCHEMA_VERSION, 'Unknown catalog schema')
    expected_files = {'source.dexie.gz', 'rows.jsonl.gz', 'catalog.sqlite.gz', 'comparison.json.gz'}
    require(set(manifest['artifacts']) == expected_files, 'Unexpected artifact list')
    require({p.name for p in folder.iterdir()} == expected_files | {'manifest.json'}, 'Unexpected snapshot files')
    for name, metadata in manifest['artifacts'].items():
        blob = (folder / name).read_bytes()
        require(sha(blob) == metadata['sha256'] and len(blob) == metadata['bytes'], 'Artifact mismatch: ' + name)
    raw = gzip.decompress((folder / 'source.dexie.gz').read_bytes())
    require(sha(raw) == manifest['source']['sha256'], 'Original source hash mismatch')
    doc, source_rows = load_source(raw)
    source_hash = sha(raw)
    records = [parse(line) for line in gzip.decompress((folder / 'rows.jsonl.gz').read_bytes()).splitlines()]
    require(len(records) == len(source_rows) == manifest['counts']['rows'], 'Lost or added rows')
    for record, (table, index, original) in zip(records, source_rows):
        captured = {record['candidate_item_id']: set(record['captured_names'])} if record['captured_names'] else {}
        require(encode(record) == encode(normalized(table, index, original, source_hash, captured)), 'Normalized record or original field mismatch')
    require(encode(manifest['counts']) == encode(record_counts(records, len(doc['data']['tables']))), 'Summary count mismatch')
    comparison = parse(gzip.decompress((folder / 'comparison.json.gz').read_bytes()))
    require(comparison == compare(records, manifest['baseline']['sha256']), 'Comparison mismatch')
    with tempfile.TemporaryDirectory(prefix='bisbeard-verify-') as tmp:
        dbpath = Path(tmp) / 'catalog.sqlite'
        dbpath.write_bytes(gzip.decompress((folder / 'catalog.sqlite.gz').read_bytes()))
        with closing(sqlite3.connect(dbpath.as_uri() + '?mode=ro', uri=True)) as db:
            with closing(sqlite3.connect(':memory:')) as expected_db:
                expected_db.executescript(SCHEMA_SQL)
                require(database_schema(db) == database_schema(expected_db), 'Unexpected SQLite schema')
            require(db.execute('PRAGMA user_version').fetchone()[0] == SCHEMA_VERSION, 'SQLite schema version mismatch')
            require(db.execute('PRAGMA integrity_check').fetchone()[0] == 'ok', 'Invalid SQLite database')
            require(db.execute('SELECT count(*) FROM items').fetchone()[0] == len(records), 'SQLite row loss')
            require(db.execute('SELECT source_sha256,metadata_json FROM sources').fetchall() == [(manifest['source']['sha256'], encode(manifest['source']).decode())], 'SQLite source mismatch')
            require(db.execute('SELECT count(*) FROM source_tables').fetchone()[0] == len(doc['data']['tables']), 'SQLite table count mismatch')
            for digest, name, count, meta in db.execute('SELECT source_sha256,table_name,row_count,metadata_json FROM source_tables'):
                require(digest == source_hash and parse(meta)['name'] == name and parse(meta)['rowCount'] == count, 'SQLite table declaration mismatch')
            tables = {name: parse(meta) for name, meta in db.execute('SELECT table_name,metadata_json FROM source_tables')}
            require(tables == {t['name']: t for t in doc['data']['tables']}, 'SQLite table metadata mismatch')
            for r in records:
                expected = (r['row_index'], r['base_item_id'], r['candidate_item_id'], int(r['is_variant']),
                            r['record']['name'], r['record']['phase'], r['record']['sourceCategory'],
                            r['comparison_status'], encode(r['captured_names']).decode(), encode(r['record']).decode())
                actual = db.execute('SELECT row_index,base_item_id,candidate_item_id,is_variant,name,phase,source_category,comparison_status,captured_names_json,record_json FROM items WHERE source_sha256=? AND source_table=? AND planner_id=?', (r['source_sha256'], r['source_table'], r['planner_id'])).fetchone()
                require(actual == expected, 'SQLite record mismatch')
            # Scan logical values, not coincidental byte sequences spanning SQLite
            # serial-type headers, integer storage and neighboring text cells.
            for statement in db.iterdump():
                screen(statement)
    for name in expected_files:
        if not name.endswith('.sqlite.gz'):
            screen(gzip.decompress((folder / name).read_bytes()).decode('utf-8-sig'))
    screen((folder / 'manifest.json').read_text(encoding='utf-8'))
    return manifest


def ingest(source, output, expected_sha256, baseline, baseline_revision=None, archive=None):
    raw = Path(source).read_bytes()
    source_hash = sha(raw)
    require(source_hash == expected_sha256, 'Source does not match explicitly reviewed SHA-256')
    doc, source_rows = load_source(raw)
    baseline_raw = Path(baseline).read_bytes()
    baseline_hash = sha(baseline_raw)
    if baseline_revision is not None:
        require(re.fullmatch(r'[0-9a-f]{40}', baseline_revision) is not None, 'Expected full baseline Git commit')
    captured = cache_names(baseline_raw)
    source_meta = dict(name=DATABASE, sha256=source_hash, bytes=len(raw), url=SOURCE_URL,
                       attribution='User-supplied export attributed to BisBeard; not independently authenticated',
                       format_name='dexie', format_version=1, database_version=1.2)
    if archive is not None:
        source_meta['archive_sha256'] = sha(Path(archive).read_bytes())
    target = Path(output) / source_hash
    if target.exists():
        old = verify(target)
        require(old['source'] == source_meta and old['baseline']['sha256'] == baseline_hash
                and old['baseline']['revision'] == baseline_revision, 'Snapshot already exists with different provenance or comparison baseline; use a separate output root')
        return target
    records = [normalized(t, i, r, source_hash, captured) for t, i, r in source_rows]
    counts = record_counts(records, len(doc['data']['tables']))
    manifest = dict(schema_version=SCHEMA_VERSION, source=source_meta,
                    baseline=dict(sha256=baseline_hash, format='itemcache.tsv.gz', revision=baseline_revision,
                                  distinct_entries=len(captured)), counts=counts,
                    semantics=dict(kind='supplemental third-party catalog', game='Conquest of Azeroth (source attribution)',
                                   authority='unverified website claims; captured data remains authoritative',
                                   phases='source labels, chronology not verified',
                                   missing_ids='investigation candidates, not proven game items',
                                   drop_rates='original strings; no probabilities inferred'), artifacts={})
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.bisbeard-build-', dir=target.parent) as tmp:
        staging = Path(tmp) / 'snapshot'
        staging.mkdir()
        gz_write(staging / 'source.dexie.gz', raw)
        gz_write(staging / 'rows.jsonl.gz', b''.join(encode(r) + b'\n' for r in records))
        gz_write(staging / 'comparison.json.gz', encode(compare(records, baseline_hash)) + b'\n')
        database_path = Path(tmp) / 'catalog.sqlite'
        build_database(database_path, source_meta, doc['data']['tables'], records)
        gz_write(staging / 'catalog.sqlite.gz', database_path.read_bytes())
        for p in sorted(staging.iterdir()):
            blob = p.read_bytes()
            manifest['artifacts'][p.name] = dict(bytes=len(blob), sha256=sha(blob))
        (staging / 'manifest.json').write_bytes(encode(manifest) + b'\n')
        verify(staging)
        staging.rename(target)
    return target


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    imp = sub.add_parser('import', help='Validate and atomically create an immutable source snapshot')
    imp.add_argument('source', type=Path)
    imp.add_argument('--output', type=Path, required=True)
    imp.add_argument('--expected-sha256', required=True, help='SHA-256 of the source reviewed for publication')
    imp.add_argument('--cache', type=Path, required=True, help='Captured union itemcache.tsv.gz used only for comparison')
    imp.add_argument('--baseline-revision', help='Full Git commit identifying the captured comparison baseline')
    imp.add_argument('--archive', type=Path, help='Optional original archive; record its hash, never its local path')
    check = sub.add_parser('verify', help='Check hashes and lossless source/JSONL/SQLite agreement')
    check.add_argument('snapshot', type=Path)
    args = parser.parse_args()
    try:
        if args.command == 'import':
            target = ingest(args.source, args.output, args.expected_sha256, args.cache, args.baseline_revision, args.archive)
            print('Preserved and verified: ' + str(target))
        else:
            result = verify(args.snapshot)
            print(f"Verified {result['counts']['rows']} records across {result['counts']['tables']} tables")
    except (ValueError, OSError, sqlite3.Error) as error:
        parser.exit(1, 'Import refused: ' + str(error) + '\n')


if __name__ == '__main__':
    main()