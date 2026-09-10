# Repository migration — 2026-09-10

| Before | Canonical owner |
|---|---|
| azeroth-control public copy + hub control sources | azeroth-control |
| Ascension_preservation public copy + deployed realm helpers | Ascension_preservation |
| ascension-cache-consolidator/tools | Ascension_preservation/tools/cache-consolidator/tools |
| BindMySoul-Ascension-Importer | Ascension_preservation/tools/character-importer |
| cachedata and supplemental snapshots | ascension-data (renamed data repository) |

The importer keeps its package name and CLI. Its full Git history is connected to
this repository. Cache tool history was split by path before import, keeping bulk
dataset history in the data repository. Original repositories, author attribution,
licenses and pre-migration backups remain available. No history was force-pushed.

Old installed file paths remain valid deployments. Make future changes in the
canonical source and use a reviewed deployment plan; do not maintain independent
runtime/public source copies. Private configurations, intake contents, databases,
clients and character state remain in the installation/archive.

The old character importer repository is retired after the replacement is published
and verified. The cache repository becomes the data repository, retaining its URL
redirects, current dataset and history. It remains active for future submissions;
its source code lives here. The `.ascension-data.json` marker prevents the cache
publisher from copying tool source back into the data repository.

Unfinished alternate AuthGate work and generated stock-client data were preserved
locally. They were not promoted to a tested runtime during consolidation.
