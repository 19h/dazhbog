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
canonical search projection. Work on a consistent copy; preserve the original
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

If preparation encounters unreadable records or inconsistent history, it stops.
On an offline copy, `dazhbog --prepare-salvage CONFIG` explicitly permits excluding
keys with invalid or missing records from the search projection. Every excluded
key and error is written to `quarantine.jsonl` in the new search generation and
the completion log reports the count. Raw records, latest pointers and context
remain available for forensic recovery. Other I/O errors still stop preparation.
`storage-audit CONFIG [LIMIT]` provides a bounded audit of the first keys in index
order; it opens writable storage handles and must also use an offline copy.

Metadata suggestions default to a coherent stored name/payload pair. Set
`scoring.experimental_synthesis = true` only to evaluate cross-version synthesis.
Browser search and detail use canonical metadata; latest and history remain
distinct. Schema compatibility now includes token positions, enabling searches
for compound symbols such as `parse_headers`.

Shutdown stops new connections, gives existing connections 30 s to finish, waits
for outstanding blocking work, and flushes storage. Incompatible indexes and
failed flushes produce errors. No cold-start latency guarantee is implied by
removing the corpus scans; benchmark the prepared dump on the deployment host.

### Capabilities

| Area | What it does |
|------|------------------|
| **Lumina RPC** | Supports protocol versions `0` through `6`, including push, pull, delete, and history flows |
| **Storage** | Uses sled-backed append-only segment trees plus a persistent latest-record index |
| **Context** | Tracks binary MD5s, basenames, observations, per-version stats, overlap caches, and binary facets in `context_db` |
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

- **A context database** in `context_db/` for binary metadata, per-key basenames, binary/version stats, overlap caches, and facet summaries
- **A search layer** in `search_index/` using Tantivy for symbols, demangled names, languages, and binary names
- **Web APIs and a browser workbench** in `src/api/http/` for function details, binary explorer views, graph exploration, overlap analysis, and compare workflows
- **Universal symbol demangling** for Itanium C++, MSVC, Rust, Swift, Go, and D
- **A native Lumina metadata parser** in `src/protocol/lumina/metadata.rs`
- **Recovery tooling** that can migrate context data, rebuild the latest index, rebuild basenames, rebuild search, and run full recovery passes
- **Binary analysis features** including family timelines, overlap percentages, related binaries, and compare buckets such as shared, left-only, right-only, metadata-rich, rare-symbol, and freshest-drift

## Features

### Core server

- **Embedded storage** - no external database required
- **Protocol support** - compatible with IDA Pro Lumina protocol versions `0-6`
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
| `context_db/` | Binary metadata, basename associations, version stats, overlap caches, facet caches, popularity data |
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

When multiple versions exist for a key, `dazhbog` scores candidates using weighted signals:

- exact binary MD5 match
- basename suffix similarity
- binary co-occurrence probability
- observation stability
- recency
- binary popularity

If context data is not available yet, it falls back to the latest stored version.

### Protocol and transport

- Lumina protocol versions `0` through `6`
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

In IDA, point Lumina at your configured host and port and use `guest` / `guest`.

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
- `lumina.get_history_limit` - caps history traversal returned to clients
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
lumina.get_history_limit = 32
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

- **Auth model** - username must be `guest`; password validation is intentionally minimal
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
