"""Lossless preservation, publication refusal and repeatability tests."""
import copy
from contextlib import closing
import gzip
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

import import_bisbeard as importer


def row(ident='647', **changes):
    value = dict(id=ident, name='Destiny', slot='Weapon', type='Sword', quality='Epic',
                 stats={'stamina': 14}, source='World Drop', itemLevel=57, reqLevel=52,
                 version='Unknown', dropRate='Unknown', description='Preserved description',
                 icon='inv_sword', classes=['All'], uniqueEquip=False, equipLoc='Two-Hand',
                 phase=1, sourceCategory='worldboe', **{'$types': {'classes': 'arrayNonindexKeys'}})
    value.update(changes)
    return value


def source():
    tables, blocks = [], []
    for phase in range(1, 6):
        for category in sorted(importer.CATEGORIES):
            rows = []
            if phase == 1 and category == 'worldboe':
                rows = [row(), row('999', name='Uncaptured')]
            elif phase == 1 and category == 'bloodforged':
                rows = [row('8000000647', name='Destiny Bloodforged', baseItemId='647', sourceCategory=category)]
            elif phase == 2 and category == 'worldboe':
                rows = [row(phase=2, name='Different captured name')]
            name = f'items_{phase}_{category}'
            tables.append(dict(name=name, schema='id', rowCount=len(rows)))
            blocks.append(dict(tableName=name, inbound=True, rows=rows))
    return dict(formatName='dexie', formatVersion=1,
                data=dict(databaseName=importer.DATABASE, databaseVersion=1.2, tables=tables, data=blocks))


class ImportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.src = self.root / 'input.dexie'
        self.cache = self.root / 'itemcache.tsv.gz'
        self.cache.write_bytes(gzip.compress(b'entry\tname\n647\tDestiny\n', mtime=0))
        self.doc = source()
        self.save()

    def tearDown(self):
        self.tmp.cleanup()

    def save(self):
        self.src.write_bytes(importer.encode(self.doc))

    def ingest(self, **extra):
        return importer.ingest(self.src, self.root / 'out', importer.sha(self.src.read_bytes()), self.cache, **extra)

    def first_row(self):
        return next(b['rows'][0] for b in self.doc['data']['data'] if b['rows'])

    def test_lossless_all_formats_and_variants(self):
        target = self.ingest()
        manifest = importer.verify(target)
        self.assertEqual(gzip.decompress((target / 'source.dexie.gz').read_bytes()), self.src.read_bytes())
        self.assertEqual(manifest['counts']['rows'], 4)
        self.assertEqual(manifest['counts']['tables'], 75)
        self.assertEqual(manifest['counts']['variants'], 1)
        records = [json.loads(line) for line in gzip.decompress((target / 'rows.jsonl.gz').read_bytes()).splitlines()]
        self.assertEqual({r['comparison_status'] for r in records}, {'variant-base-present', 'name-match', 'candidate-missing', 'name-conflict'})
        variant = next(r for r in records if r['is_variant'])
        self.assertEqual(variant['planner_id'], '8000000647')
        self.assertEqual(variant['candidate_item_id'], 647)
        self.assertFalse(variant['planner_id_is_uint32'])
        self.assertEqual(sum(r['planner_id'] == '647' for r in records), 2)

    def test_repeat_import_is_noop(self):
        target = self.ingest()
        before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in target.iterdir()}
        self.assertEqual(target, self.ingest())
        self.assertEqual(before, {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in target.iterdir()})

    def test_deterministic_independent_builds(self):
        first = self.ingest()
        second = importer.ingest(self.src, self.root / 'other', importer.sha(self.src.read_bytes()), self.cache)
        self.assertEqual({p.name: p.read_bytes() for p in first.iterdir()}, {p.name: p.read_bytes() for p in second.iterdir()})

    def test_changed_baseline_cannot_overwrite_snapshot(self):
        target = self.ingest()
        original = (target / 'manifest.json').read_bytes()
        self.cache.write_bytes(gzip.compress(b'entry\tname\n647\tChanged\n', mtime=0))
        with self.assertRaisesRegex(ValueError, 'different provenance'):
            self.ingest()
        self.assertEqual(original, (target / 'manifest.json').read_bytes())

    def test_wrong_reviewed_hash_writes_nothing(self):
        with self.assertRaisesRegex(ValueError, 'reviewed SHA'):
            importer.ingest(self.src, self.root / 'out', '0' * 64, self.cache)
        self.assertFalse((self.root / 'out').exists())

    def test_unknown_fields_refused(self):
        self.first_row()['playerProfile'] = 'unexpected'
        self.save()
        with self.assertRaisesRegex(ValueError, 'Unknown item fields'):
            self.ingest()
        self.assertFalse((self.root / 'out').exists())

    def test_personal_data_refused_even_in_allowed_field(self):
        self.first_row()['description'] = 'sample' + '@' + 'example.invalid'
        self.save()
        with self.assertRaisesRegex(ValueError, 'Publication review required'):
            self.ingest()

    def test_duplicate_json_keys_refused(self):
        with self.assertRaisesRegex(ValueError, 'Duplicate JSON'):
            importer.load_source(b'{"formatName":"dexie","formatName":"dexie"}')

    def test_count_and_missing_blocks_refused(self):
        self.doc['data']['tables'][0]['rowCount'] += 1
        self.save()
        with self.assertRaisesRegex(ValueError, 'row count'):
            self.ingest()
        self.doc = source()
        self.doc['data']['data'].pop()
        self.save()
        with self.assertRaisesRegex(ValueError, 'Missing table'):
            self.ingest()

    def test_duplicate_primary_key_refused(self):
        block = next(b for b in self.doc['data']['data'] if b['rows'])
        block['rows'].append(copy.deepcopy(block['rows'][0]))
        next(t for t in self.doc['data']['tables'] if t['name'] == block['tableName'])['rowCount'] += 1
        self.save()
        with self.assertRaisesRegex(ValueError, 'Duplicate primary key'):
            self.ingest()

    def test_invalid_nested_schema_refused(self):
        for field, value in [('stats', {'player': 12}), ('$types', {'classes': 'unknown'}), ('classes', {'account': 'x'}), ('damage', {'min': 1, 'max': 2, 'speed': 'fast'})]:
            self.doc = source()
            self.first_row()[field] = value
            self.save()
            with self.assertRaises(ValueError):
                self.ingest()

    def test_invalid_identifier_not_coerced(self):
        r = row('8000000647', baseItemId='not-a-game-id')
        normalized = importer.normalized('items_1_worldboe', 0, r, 'a' * 64, {647: {'Destiny'}})
        self.assertIsNone(normalized['candidate_item_id'])
        self.assertEqual(normalized['comparison_status'], 'unmapped-id')
        self.assertIsNone(importer.uint32('000647'))
        self.assertIsNone(importer.uint32('4294967296'))

    def test_corrupt_artifact_refused(self):
        target = self.ingest()
        (target / 'rows.jsonl.gz').write_bytes(b'corrupted')
        with self.assertRaisesRegex(ValueError, 'Artifact mismatch'):
            importer.verify(target)

    def test_changed_record_refused_even_with_updated_hash(self):
        target = self.ingest()
        path = target / 'rows.jsonl.gz'
        records = [json.loads(line) for line in gzip.decompress(path.read_bytes()).splitlines()]
        records[0]['record']['stats']['stamina'] = 999
        path.write_bytes(gzip.compress(b''.join(importer.encode(r) + b'\n' for r in records), mtime=0))
        mpath = target / 'manifest.json'
        manifest = json.loads(mpath.read_bytes())
        manifest['artifacts'][path.name] = dict(bytes=path.stat().st_size, sha256=importer.sha(path.read_bytes()))
        mpath.write_bytes(importer.encode(manifest))
        with self.assertRaisesRegex(ValueError, 'original field mismatch'):
            importer.verify(target)

    def update_artifact_hash(self, target, path):
        mpath = target / 'manifest.json'
        manifest = json.loads(mpath.read_bytes())
        manifest['artifacts'][path.name] = dict(bytes=path.stat().st_size, sha256=importer.sha(path.read_bytes()))
        mpath.write_bytes(importer.encode(manifest))

    def test_extra_sqlite_table_refused_even_with_updated_hash(self):
        target = self.ingest()
        compressed = target / 'catalog.sqlite.gz'
        plain = self.root / 'modified.sqlite'
        plain.write_bytes(gzip.decompress(compressed.read_bytes()))
        with closing(sqlite3.connect(plain)) as db, db:
            db.execute('CREATE TABLE unexpected (content TEXT)')
            db.execute('INSERT INTO unexpected VALUES (?)', ('unreviewed material',))
        compressed.write_bytes(gzip.compress(plain.read_bytes(), mtime=0))
        self.update_artifact_hash(target, compressed)
        with self.assertRaisesRegex(ValueError, 'Unexpected SQLite schema'):
            importer.verify(target)

    def test_incorrect_summary_refused(self):
        target = self.ingest()
        path = target / 'manifest.json'
        manifest = json.loads(path.read_bytes())
        manifest['counts']['variants'] += 1
        path.write_bytes(importer.encode(manifest))
        with self.assertRaisesRegex(ValueError, 'Summary count mismatch'):
            importer.verify(target)

    def test_multiline_capture_and_multiple_names_preserved(self):
        raw = gzip.compress(b'entry\tname\n647\t"Line one\nLine two"\n647\tDestiny\n', mtime=0)
        self.assertEqual(importer.cache_names(raw)[647], {'Line one\nLine two', 'Destiny'})


if __name__ == '__main__':
    unittest.main()