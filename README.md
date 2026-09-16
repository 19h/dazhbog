<h1 align="center">dazhbog</h1>

<h5 align="center">An embedded Lumina server for IDA Pro with context-aware retrieval, search,<br/>binary intelligence, and a built-in web workbench</h5>

<div align="center"><code>Lumina v0-6</code> • <code>sled</code> • <code>Tantivy</code> • <code>HTTP/1.1 + h2c</code> • <code>Binary graphs</code> • <code>Metadata parsing</code></div>

<br />

`dazhbog` is a self-contained Lumina-compatible server that stores, retrieves, indexes, and analyzes function metadata from IDA Pro. It combines embedded deployment, context-aware version selection, binary analytics, full-text search, native metadata decoding, and a browser workbench.

It answers more than "do I have this function?" It also answers "which binary families contain it?", "which version best fits this caller?", and "what metadata does Lumina have for this symbol?"

---------------

<h3 align="center">Public dazhbog server</h3>

<div align="center">TLS and plaintext supported<br/>No special configuration required</div>

<h3 align="center"><i>host</i>: ida.int.mov<br/><i>port</i>: 1234</h3>
<h3 align="center"><i>user</i>: guest<br/><i>pass</i>: guest</h3>

---------------

<h3 align="center">Live public-server snapshot</h3>

<div align="center">Refreshed every 15 minutes from the public deployment</div>

<br />

<p align="center">
  <a href="https://github.com/19h/dazhbog-graph/raw/refs/heads/master/dazhbog-stats.svg">
    <img src="https://github.com/19h/dazhbog-graph/raw/refs/heads/master/dazhbog-stats.svg" alt="Live dazhbog public server statistics" width="96%" />
  </a>
</p>

---------------

## At a glance

### Preparing an existing database

Existing dumps require one offline preparation before serving with the current
search projection. Work on a consistent copy; preserve the original
`segments_db`, `index`, and `context_db`. Set `engine.data_dir` in a separate
configuration to that copy, and adjust `engine.index_dir` if configured.

```sh
cargo run --locked --release --bin dazhbog -- --prepare /path/to/copy-config.toml
cargo run --locked --release --bin dazhbog -- /path/to/copy-config.toml
```

Preparation populates exact persistent counters and context indexes, streams a
new search generation, and publishes it only after completion. Prior search
generations remain available on disk. Normal startup does not count the full
corpus or silently rebuild incompatible indexes. Missing original context must
be recovered separately; function records cannot reconstruct every observation.
Recovery `--rebuild-search DATA_DIR` uses the same preparation path with default
index-directory settings. Use the main CLI when configuring an index override.

The current `canonical_projection_v4` binds each generation to its configured
`lumina.name_rejection` policy and retains the live historical annotation vocabulary
introduced in v3. Older projections and policy changes require offline preparation
before serving. Preparation preserves prior search generations, raw records and
historical observation IDs. Offline replay can inspect legacy or differently
configured projections with a warning; their search results are not certified for
the current policy. Database push/delete/revert operations require a compatible
projection even when opened for replay. Storage handles remain writable; replay
is not filesystem-enforced read-only access.

The configuration text remains `lumina.name_rejection`. Rust callers now set
`Config.engine.name_rejection`; the policy applies to the whole database, including
preparation, replay, HTTP and alternate RPC. Standalone semantic helpers without a
policy argument use `Prefixes`; use their explicit policy variants for other modes.

If preparation encounters unreadable records or inconsistent history, it stops.
On an offline copy, `dazhbog --prepare-salvage CONFIG` explicitly permits excluding
keys with invalid or missing records from the search projection. Every excluded
key and error is written to `quarantine.jsonl` in the new search generation and
the completion log reports the count. Raw records, latest pointers and context
remain available for forensic recovery. Other I/O errors still stop preparation.
`storage-audit CONFIG [LIMIT]` provides a bounded audit of the first keys in index
order; it opens writable storage handles and must also use an offline copy.
`storage-audit CONFIG --key KEY [VERSION_ID]` instead traces one hexadecimal key,
up to 4096 records. An optional 64-digit version ID is checked against current and
legacy identities. The JSON distinguishes rejected names, tombstones, foreign
links, read errors and traversal bounds; `live_candidates` counts distinct accepted
raw variants before selector caps or provenance filtering. This command diagnoses
records without repairing them. It stops at a tombstone or foreign-key record.

Metadata suggestions default to a coherent stored name/payload pair. Set
`scoring.experimental_synthesis = true` only to evaluate cross-version synthesis.
Browser search and unconditioned detail use canonical metadata. Binary function
lists, detail and neighbor analysis select variants for the viewed binary;
`/api/function/KEY?md5=MD5` and `/api/function/KEY/neighbors?md5=MD5` expose the
same context. The browser preserves it in `#f=KEY&b=MD5` links. Missing or stale
observations retain the selector's fallback. Neighbor retrieval also uses a bounded
vocabulary from live historical annotations; reranking validates the annotation
selected for the viewed binary. Default text search remains canonical. Latest
and history remain distinct.
Neighbor family scoring checks the selected family's memberships directly; the
short binary-reference list shown with each hit no longer limits this evidence.
Binary comparison shows each side's selected annotation and whether it matches that
binary's last recorded observation. Shared keys can have different annotations;
timing-only changes are ignored, while incomplete parses remain unjudged. Comparisons
state their bounded key coverage, and exports include both sides. Coverage summaries
use each binary's selected annotations, report examined keys and truncation, and
distinguish unavailable records from fallback selections. A bounded process-local
cache replaces legacy persisted facet values, which remain untouched and ignored.
Schema compatibility now includes token positions, enabling searches
for compound symbols such as `parse_headers`.

Shutdown stops new connections, gives existing connections 30 s to finish, waits
for outstanding blocking work, and flushes storage. Incompatible indexes and
failed flushes produce errors. No cold-start latency guarantee is implied by
removing the corpus scans; benchmark the prepared dump on the deployment host.

`scripts/benchmark-startup.mjs` (Node.js 20+) starts an owned server process on
the loopback ports configured in an offline copy, verifies public operations and
checks graceful shutdown on each run. Usage:
`node scripts/benchmark-startup.mjs SERVER CONFIG HTTP_PORT RPC_PORT 20 warm`.
The optional `purge` mode invokes macOS `/usr/sbin/purge` before each run and fails
if cache eviction is unavailable. Its JSON output separates listener/metrics
readiness from completion of the first useful request set.

### Capabilities

| Area | What it does |
|------|------------------|
| **Lumina RPC** | Speaks protocol versions `2` through `6` (`helo_result` from v5, newer clients refused like the reference); pull, push, function histories, delete (undo last change), popular functions, info and stats, checked byte-for-byte against packets captured from the Hex-Rays server |
| **Storage** | Uses sled-backed append-only segment trees plus a persistent latest-record index |
| **Context** | Tracks binary MD5s, basenames, observations, per-version stats and overlap caches in `context_db`; binary facets are cached in memory |
| **Search** | Indexes raw names, demangled names, language tags, and binary names with Tantivy |
| **Web UI** | Serves a dashboard plus APIs for function detail, binary browsing, overlap, timelines, graph views, and binary comparison |
| **Metadata** | Parses Lumina metadata natively in Rust, including types, frame data, comments, and switch/jumptable hints |
| **Recovery** | Can migrate context data, rebuild indexes, rebuild search, rebuild basenames, and run full recovery flows |
| **Upstream** | Optionally forwards cache misses to one or more upstream Lumina servers by priority |

## Why dazhbog

- **Embedded, not operationally heavy** - no external database, search service, or queueing tier required
- **More than a cache** - keeps history, context, binary observations, and per-version statistics
- **Browsable corpus** - ships with an HTTP workbench instead of leaving the data behind the Lumina protocol
- **Built for reverse-engineering workflows** - binary overlap, function history, demangling, comment/type extraction, and metadata-rich comparison are first-class features
- **Recoverable by design** - segment data, context data, and search state can be rebuilt with dedicated tooling

## Installation

```bash
cargo build --release
./target/release/dazhbog config.toml
```

For a development run:

```bash
cargo run -- config.toml
```

If IDA is talking to a non-TLS `dazhbog` instance:

```bash
export LUMINA_TLS=false
```

---------------

## What it does

`dazhbog` gives teams local Lumina compatibility with search, context, and visibility into the dataset.

- **A context database** in `context_db/` for binary metadata, per-key basenames, binary/version stats and overlap caches; facet summaries are computed on demand
- **A search layer** in `search_index/` using Tantivy for symbols, demangled names, languages, and binary names
- **Web APIs and a browser workbench** in `src/api/http/` for function details, binary explorer views, graph exploration, overlap analysis, and compare workflows
- **Universal symbol demangling** for Itanium C++, MSVC, Rust, Swift, Go, and D
- **A native Lumina metadata parser** in `src/protocol/lumina/metadata.rs`
- **Recovery tooling** that can migrate context data, rebuild the latest index, rebuild basenames, rebuild search, and run full recovery passes
- **Binary analysis features** including family timelines, overlap percentages, related binaries, and compare buckets such as shared, left-only, right-only, metadata-rich, rare-symbol, and freshest-drift

## Features

### Core server

- **Embedded storage** - no external database required
- **Protocol support** - compatible with IDA Pro Lumina protocol versions `2-6`; result codes, the `size` field, frequency counters and history indexes follow the Hex-Rays reference server
- **Append-only records** - immutable history via `prev_addr` chains
- **Context-aware version selection** - chooses the best candidate using binary MD5, basename similarity, co-occurrence, stability, recency, and binary popularity
- **Optional upstream forwarding** - one or more upstream Lumina servers with priority ordering
- **TLS support** - PKCS#12 via `native-tls` or PEM via `rustls`

### Search and web workbench

- **Function search** by stored symbol, demangled symbol, or associated binary name
- **Binary search** by basename and observed metadata
- **Function detail API** at `/api/function/:key`
- **Binary detail API** at `/api/binary/:md5`
- **Binary graph API** at `/api/binary/:md5/graph`
- **Binary overlap API** at `/api/binary/:md5/overlap`
- **Binary comparison API** at `/api/binary-compare/:left/:right`
- **Prometheus metrics** at `/metrics`
- **Metrics JSON** at `/api/metrics`

The dashboard shows demangled names, parsed metadata, language badges, binary relationships, timeline views, coverage/facet summaries, and compare panels.

### Binary intelligence

- **Per-binary summaries** with observation counts, function counts, first/last seen timestamps, and host tracking
- **Binary overlap** discovery based on shared functions
- **Binary family timelines** for related samples
- **Neighborhood graphs** for exploring binary clusters
- **Comparison buckets** for shared, unique, metadata-rich, rare-symbol, and freshest-drift function sets
- **Facet summaries** showing typed/commented/switch-heavy coverage across a binary

### Metadata parsing

The Rust parser in `src/protocol/lumina/metadata.rs` can decode and expose:

- function type information
- frame descriptions and frame members
- decompiler elapsed values
- function comments and repeatable comments
- instruction comments and repeatable instruction comments
- derived switch and jumptable hints from parsed comments

The `analysis/` directory contains reverse-engineering notes and Python parsers used to validate the format against real dumped payloads.

---------------

## Architecture

`dazhbog` is built around four main on-disk stores and two serving layers.

### Request flow

```text
IDA client / browser
        |
        v
  Lumina RPC server / HTTP server
        |
        +--> latest key index ---------------> fetch current record
        |
        +--> context_db ---------------------> score versions, attach binaries, compute overlap/facets
        |
        +--> search_index -------------------> search functions and binaries
        |
        +--> segments_db --------------------> walk history, read raw records, parse metadata
        |
        +--> upstream servers (optional) ----> fill local cache on misses
```

### Storage layout

| Path | Purpose |
|------|---------|
| `segments_db/` | Append-only sled trees named `seg.00001`, `seg.00002`, ... containing serialized records |
| `index/` | Persistent key -> latest address lookup |
| `context_db/` | Binary metadata, basename associations, version stats, overlap caches, popularity data; legacy facet values are ignored |
| `search_index/` | Tantivy full-text index for functions and binaries |

### Record model

The append-only segment record keeps:

- a 128-bit function key
- timestamps and popularity
- a pointer to the previous version via `prev_addr`
- the function name
- the raw Lumina metadata payload
- tombstone state for deletes

That layout lets `dazhbog` answer three different kinds of query from the same corpus:

- **latest-value lookup** through the persistent key index
- **history traversal** by following `prev_addr`
- **binary/context-driven retrieval** by joining against `context_db`

### Serving layers

1. **Lumina RPC server** - handles Lumina clients, protocol negotiation, pull/push/delete/history flows, TLS, and upstream forwarding
2. **HTTP server** - serves the dashboard, JSON APIs, metrics, and cleartext HTTP/2 (`h2c`)

When TLS is enabled, the server can also expose HTTP over the Lumina side with ALPN-aware handling.

### Version selection

When an explicit query binary MD5 is available, selection first prefers that
binary's validated last-observed variant, then its observed historical variants.
Targeted retrieval can reach beyond the recent-version cap, within the live
history interval and a 4,096-record traversal bound.

Selection recognizes current version IDs and the historical 64-bit little-endian
writer's IDs as aliases of the same stored variant. New writes retain the current
encoding. Alias counters are combined by maxima, since overlapping observations
cannot be distinguished; positive binary memberships from either encoding apply.
Zero-count observation rows cannot supply last-version identity, batch votes,
evaluation labels or overlap support. Offline preparation does not promote them
into history. Raw rows and independently stored history remain intact. Old overlap
cache entries are ignored and recomputed on demand under the positive-count policy;
this adds no startup scan.

Wire pulls currently provide function keys without explicit binary identity.
Selection infers binary context from the other distinct keys in the batch: each
key contributes one unit of evidence divided over its observed binaries. The
target cannot vote for itself, and repeated uploads do not multiply this evidence.
Membership scans exceeding 256 physical rows contribute no vote, including when
zero-count placeholders consume the bound; at most 64 inferred binaries are
considered per target. These weights are not calibrated probabilities.

By default, `scoring.binary_priority = true` prefers the variant supported by the
best matching individual binary; several weaker binary matches cannot collectively
override it. A binary's last observed variant is preferred to its older submissions
when retrievable. Otherwise its historical candidates share its evidence. Heuristic
scores break ties and handle absent evidence. Set `scoring.binary_priority = false`
to evaluate weighted scoring without this inferred preference; explicit binary
identity still takes precedence. Batch inference also applies to an explicit MD5
that has no usable observation for the queried function.

Candidate retrieval also seeks the stored canonical variant beyond the recent
window. Canonical refresh reconsiders that incumbent alongside recent submissions,
so lower-quality uploads cannot replace it merely by pushing it out of the window.
It remains subject to normal scoring, tombstones and the 4096-record history bound.
No data migration is required; this does not reconstruct previously lost choices.

With `scoring.binary_single_key_tolerance = true` (default), partial binary matches
can admit alternatives within a conservative one-neighbor sensitivity bound.
An alternative must have stronger independent semantic corroboration, with a matched
term appearing in a function name or decoded prototype on at least one side.
Repeated comments alone cannot override stronger binary evidence. A binary covering
every informative neighboring key retains strict priority. Set this option false
to reproduce strict binary ranking; explicit observed identity always takes precedence.

Within the eligible candidates, scoring also considers:

- basename suffix similarity
- binary co-occurrence evidence
- observation stability
- recency
- binary popularity
- requested metadata coverage, metadata consistency and semantic batch anchors

Semantic batch anchors use names, decoded prototypes, frame members, comments and
printable operand metadata. Each qualifying neighboring function contributes one
unit of evidence after generic terms are removed. Selection compares terms that
distinguish the eligible variants, excluding the target's own contribution.
Common terms and unrelated extra metadata cannot dilute those matches. This is
relative semantic support, not calibrated confidence; binary priority still applies.

`scoring.batch_identifier_components = true` (default) lets batch evidence connect
identifiers such as `http_read_header` and `HttpDecodeHeader`. Components augment
names, decoded prototypes, frame annotations, comments and printable operand text.
They help rank eligible variants; relaxing binary priority still requires the
original whole-token corroboration. Set the option false for ablation. Canonical
quality scores and persisted search tokens are unchanged; no rebuild is required.

`scoring.batch_consensus_anchors = true` (default) retains shared evidence when a
neighboring function has several equally plausible variants. Only tokens present
in every eligible strongest-binary variant contribute; field intersections keep
comment text from acquiring identifier status. The target still cannot vote for
itself. Set this option false to use only decisive source variants. Consensus affects
ranking evidence; returned metadata still comes from the selected stored variant.

Stored names and payloads remain paired by default. Cross-version synthesis is
experimental. No new persisted format is required by this selection logic;
existing dumps use the offline preparation procedure above. Missing historical
observations remain unavailable. See [the investigation](docs/semantic-relevance.md)
for regression evidence, assumptions and remaining accuracy-evaluation work.

Semantic-neighbor retrieval analyzes compound metadata identifiers using the
index's tokenizer. For example, `packet_state` matches its indexed adjacent words
in order; isolated `packet` or reversed `state_packet` does not satisfy that clause.
This applies to prototype, frame, comment, operand, origin and aggregate semantic
fields. Existing compatible indexes already contain the required positions, so
this correction needs no rebuild or migration.

### Protocol and transport

- Lumina protocol versions `2` through `6`
- plaintext or TLS on the Lumina side
- HTTP/1.1 and cleartext HTTP/2 (`h2c`) on the HTTP side
- optional HTTP handling on the TLS/Lumina side when enabled
- optional upstream miss forwarding with priority ordering

---------------

## Repository map

- `src/main.rs` - server entrypoint
- `src/db/` - high-level database API, search enrichment, binary compare logic, version scoring
- `src/engine/` - segments, indexes, context index, search index, runtime wiring
- `src/protocol/lumina/` - Lumina wire handling and metadata parsing
- `src/api/http/` - dashboard templates, HTTP handlers, router, metrics APIs
- `src/bin/recover.rs` - rebuild, migration, and recovery utility
- `src/bin/dump_functions.rs` - dump stored raw metadata payloads
- `src/bin/dump_function_names.rs` - export function names from the corpus
- `tests/` - protocol, metadata, fuzz, boundary, stress, and TLS-oriented coverage
- `analysis/` - parser notes and Python validation tooling

## Quick start

```bash
# Build
cargo build --release

# Run
./target/release/dazhbog config.toml

# If IDA should use plaintext instead of TLS
export LUMINA_TLS=false
```

In IDA, point Lumina at your configured host and port. The default (empty) username is accepted, as is `guest`; set `lumina.accept_any_username = true` to accept any name. Passwords are not checked.

For a live instance, use the public server block at the top of this README.

## Configuration

The config file looks like TOML, but the parser is intentionally lightweight rather than a full TOML implementation. Dotted keys and `#` comments work; advanced TOML features do not.

Main config groups:

- `limits.*` - protocol and memory limits
- `engine.*` - storage paths, segment size, mmap reads, deduplication, index tuning
- `lumina.*` - bind address, deletes, history, TLS enablement
- `tls.*` - PKCS#12 or PEM certificate settings
- `http.*` - HTTP bind address
- `upstream.<n>.*` - ordered upstream Lumina servers
- `scoring.*` - version-selection weights and caps
- `debug.*` - protocol hello dumping

TLS modes:

- **PKCS#12 / native-tls** - fits IDA-style certificate setups
- **PEM / rustls** - preferred for modern browser behavior and HTTP/2 ALPN

If both are configured, the code prefers the PEM/rustls path.

### Important operational settings

- `engine.deduplicate_on_startup` - rewrites away redundant records at startup; effective, but slow on large corpora
- `lumina.get_history_limit` - caps history entries returned per function (default 128; `0` disables the request)
- `lumina.accept_any_username` - accept any hello username instead of only empty/`guest`
- `lumina.name_rejection` - `off` (reference behaviour: store any name), `prefixes` (default: drop IDA dummy names such as `sub_`), or `heuristic` (also drop address-like suffixes and statistically implausible names)
- `limits.max_pull_items` / `limits.max_push_items` - controls large batch behavior from clients
- `scoring.*` - controls how aggressively context influences version selection
- `upstream.<n>.priority` - lower number means higher precedence for miss forwarding

### Example config

```toml
# Connection and resource limits
limits.hello_timeout_ms = 3000
limits.command_timeout_ms = 15000
limits.max_active_conns = 2048
limits.max_pull_items = 524288
limits.max_push_items = 524288

# Storage engine
engine.data_dir = "data"
engine.segment_bytes = 1073741824
engine.shard_count = 64
engine.index_capacity = 1073741824
engine.deduplicate_on_startup = false

# Lumina server
lumina.bind_addr = "0.0.0.0:1234"
lumina.server_name = "dazhbog"
lumina.allow_deletes = false
lumina.get_history_limit = 128
lumina.accept_any_username = false
lumina.name_rejection = "prefixes"
lumina.use_tls = false

# HTTP server
http.bind_addr = "0.0.0.0:8080"

# Optional upstream
upstream.0.enabled = true
upstream.0.priority = 0
upstream.0.host = "lumina.hex-rays.com"
upstream.0.port = 443
upstream.0.use_tls = true
upstream.0.insecure_no_verify = true
upstream.0.hello_protocol_version = 6
upstream.0.license_path = "license.hexlic"
upstream.0.timeout_ms = 8000
upstream.0.batch_max = 131072
```

## Admin and recovery commands

```bash
# List sled trees
./target/release/recover --list-trees data

# Migrate old context trees into context_db
./target/release/recover --migrate-context data

# Rebuild the latest key index
./target/release/recover --rebuild-index data

# Rebuild per-key basenames from binary metadata
./target/release/recover --rebuild-basenames data

# Rebuild the search index
./target/release/recover --rebuild-search data

# Run the combined rebuild flow
./target/release/recover --rebuild-all data
```

Other helpers:

```bash
# Dump metadata payloads for parser work
./target/release/dump_functions --dump 2000 analysis/data

# Dump function names from the corpus
./target/release/dump_function_names --output function_names.txt --unique
```

The recovery tool covers context migration, search refreshes, basename reconstruction, and full rebuild flows.

## API surface

| Endpoint | Purpose |
|----------|---------|
| `/` | Interactive dashboard |
| `/api/search?q=...&mode=functions|binaries` | Function or binary search |
| `/api/function/:key` | Full function detail, parsed metadata, binaries |
| `/api/binary/:md5` | Binary summary plus facets, related views, and overview data |
| `/api/binary/:md5/functions` | Paginated function list for a binary |
| `/api/binary/:md5/overlap` | Related binaries by shared functions |
| `/api/binary/:md5/graph` | Graph neighborhood data |
| `/api/binary-compare/:left/:right` | Binary-to-binary comparison |
| `/metrics` | Prometheus scrape endpoint |
| `/api/metrics` | Metrics JSON snapshot |

## Binary intelligence

`dazhbog` models how functions appear across binaries, not just how they map to keys.

Each function can be linked to:

- binaries that contained it
- last-seen versions for specific binaries
- observation counts
- basename aliases
- host information
- overlap caches
- facet summaries like typed/commented/switch-heavy coverage

That enables:

- binary search by basename
- paging through functions for a binary
- binary-family timelines
- related-binary discovery by overlap
- graph exploration around a binary neighborhood
- direct binary-to-binary comparison across shared and unique sets

## Metadata analysis workflow

Use the parser workflow in `analysis/` for validation and exploration:

```bash
./target/release/dump_functions --dump 2000 analysis/data
python3 analysis/lumina_metadata.py
python3 analysis/fast_parser.py
```

## Testing

For paired binary-selection evaluation, append `--all-cases` after the mode:
`cargo run --bin eval-binary-context -- CONFIG 32 64 2 transfer --all-cases`.
Each binary report then includes every case instead of only bounded diagnostic
examples. Pair cases by binary MD5 and function key; compare both gains and losses.
This measures retrospective observation agreement, not independently labeled accuracy.
See [identifier component evaluation](docs/identifier-component-evaluation.json).

Evaluation now distinguishes missing identity probes, proven shared variants missed
by retrieval, and annotations whose cross-binary provenance cannot be established.
`sharing_not_proven` does not mean private. Availability errors are reported separately
without discarding successful selections. See the
[candidate retrieval audit](docs/candidate-retrieval-evaluation.json).

### Independent symbol-name evaluation

For local SQLite/ELF fixture pairs, extract labels from binary symbols and compare
them with the existing database without inserting labels:

```sh
cargo build --locked --release --bin eval-symbol-labels
set -o pipefail
node scripts/extract-symbol-labels.mjs FIXTURE.sqlite3 BINARY.elf FAMILY test |
  target/release/eval-symbol-labels /path/to/offline-copy-config.toml
```

`--directory ROOT FAMILY test` replaces the first two extractor arguments to
process all directly contained SQLite files with a same-stem ELF. The extractor
uses `sqlite3` and `llvm-readelf`, checks the fixture's sole input MD5 against the
binary, retains SHA-256 provenance, and accepts only defined nonzero-size function
symbols with exact address and extent matches. It retains aliases and reports
exclusions. It never uses stored annotation names as labels or adjusts addresses.

The evaluator compares explicit binary identity, inferred batch context, latest,
and canonical selection. JSON counts distinguish all cases, available annotations,
and exact symbol-name matches, with totals separated by partition. Expected names
never enter selection. Related builds must share a family/partition. Symbol-name
agreement does not establish metadata correctness or held-out transfer accuracy;
names may be valid despite differing from the compiler symbol. Replay opens
writable storage handles, so use a consistent offline copy. Local fixture content
is not included in this repository.

Add `--disagreements` after the evaluator configuration path to emit diagnostics
for available explicit-binary suggestions with no exact name match. Each row
includes candidate count and a history probe returning at most 64 accepted versions
and 32 distinct names. Positive name/version matches establish observed presence;
a bounded or policy-filtered miss does not establish absence. Probe errors are
reported without changing agreement counts. These diagnostics never feed selection.

### Independent neighbor evaluation

Run `cargo run --locked --release --bin eval-neighbors -- CONFIG LABELS.jsonl 12`
against a prepared offline copy. Each JSONL case has `case_id`, `family`,
`partition` (`development` or `test`), `provenance`, a 32-digit hexadecimal `key`,
and `judgments` containing `{ "key": "...", "relevant": true }` or false.
Use independently established source/binary identities and relevance judgments;
do not derive labels from the name or token overlap being evaluated. Group
related builds, compiler variants and forks in one family. A family cannot occur
in both partitions. Optional `binary_md5` (32 hexadecimal digits) and
`strict_family` (boolean, default false) evaluate the browser's contextual and
strict-family paths. The same key may have separate cases for different binaries;
duplicate key/binary pairs are rejected. Omitted identity preserves the original
canonical evaluation mode.

The evaluator compares 96, 192 and 384 retrieved candidates at the same output
size. It emits per-case JSON with the binary context, strict-family flag, candidate
and returned key lists, candidate recall against positive labels,
returned recall, judgment coverage, precision and time in seconds. Precision is
undefined if any returned hit lacks a judgment. Recall is relative to the supplied
positive set, so incomplete labels cannot establish corpus-wide recall. Aggregate
by family before comparing development and test results.
`eval-binary-context CONFIG [BINARIES=32] [FUNCTIONS=64] [SEED=1] [observed|transfer]` samples observed
binary batches from an offline prepared copy. It reports exact variant agreement,
candidate availability, latest/canonical baselines, semantic payload agreement
(excluding only decompilation timing), and latency. Failed batches and unavailable
labels remain explicit. It uses the serving selector without supplying binary
identity, plus an explicit-identity retrieval probe. These are retrospective
observations, not independent accuracy labels or a family-disjoint test set.

The default `observed` mode retains the sampled binary in inference. `transfer`
withholds its identity, excludes variants without positive provenance in another
binary, and suppresses observation-count, recency and canonical priors. It retains
related binaries and the bounded physical history; it does not reconstruct a
family-disjoint training database. The explicit-ID/latest/canonical probes still
use the full corpus and are diagnostic references. Available mismatches include
expected/selected type declarations, frame summaries and metadata chunk lengths.
Stored annotations can themselves be incorrect. Empty samples and failed batches
produce a nonzero exit status. Both modes open writable storage handles; use a copy.

`eval_semantic` evaluates retrospective stored-version agreement; its context
still includes held-out observations.

Run the full suite:

```bash
cargo test --all -- --nocapture
```

Focused runs:

```bash
cargo test metadata_parser -- --nocapture
cargo test protocol_test -- --nocapture
```

Current coverage includes:

- metadata parser tests against real dumped payloads
- live protocol handshake and pull behavior tests
- boundary and fuzz-style network tests
- TLS/security placeholders and stress-oriented suites

Some integration tests expect a live local server and will skip if it is not running.

## Notes

- **Auth model** - the username must be empty or `guest` unless `lumina.accept_any_username` is set; passwords and license blobs are not validated
- **Network posture** - best used on trusted networks unless you place it behind your own access controls
- **Migration** - run `recover --migrate-context` if `context_db` is missing
- **Search quality** - best after rebuilding basenames and search data from a populated context database
- **Runtime split** - RPC and HTTP work run on dedicated runtimes to keep the UI responsive under protocol load
- **Demangling** - search and detail views can expose precomputed demangled names and language hints
- **Parser provenance** - the Rust metadata parser was validated against dumped real-world payloads in `analysis/`
- **Name** - Dazhbog is a Slavic sun deity

## License

MIT License

Copyright (c) 2025 Kenan Sulayman
