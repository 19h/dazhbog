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

> [!NOTE]
> **Dazhbog 2.0** — concrete suggestion and annotation quality improvements:
>
> - **Context-aware binary priority and corroboration filtering** — prefers candidates from the strongest matching inferred binary while enforcing conservative one-neighbor sensitivity bounds (`scoring.binary_single_key_tolerance`), requiring independent function-name or decoded-prototype corroboration before weaker candidates can challenge binary priority and preventing comment-only repetition (such as compiler PIC annotations) from overriding binary identity
> - **Leave-target-out batch inference and historical candidate recall** — derives binary context across batch keys without target self-votes while omitting ubiquitous functions (>256 memberships), supplements the global top-64 donor pool with up to 64 target-specific donors, and retrieves historical `binary_versions` annotations beyond the recent-version cap within a 4,096-record traversal bound
> - **Companion context completion and consensus anchors** — recovers up to 128 stored forward-membership companion identities for sparse queries lacking target observations to infer related binaries, and extracts shared invariant tokens across tied source variants (`scoring.batch_consensus_anchors`) to supply batch semantic evidence without synthesizing unverified responses
> - **Eligible-population prior normalization and contrastive re-weighting** — bounds recency, diversity, and observation normalizations strictly to the surviving eligible candidate pool to prevent excluded timestamp or count extrema from distorting relative scores, while restricting final lexical distinctions to surviving variants to eliminate artificial contrast introduced by rejected donors
> - **Lexical recovery for suffixed symbols and undecoded types** — extracts root namespace identifiers from Swift symbols bearing decimal collision suffixes (up to four `_N` groups), recovers bounded field-name strings (up to 8 KiB / 64 entries) from unrendered function and frame types, and decomposes compound identifiers across snake_case, camelCase, and acronym boundaries for secondary ranking
> - **Per-key mutation serialization and transactional evidence accounting** — serializes online pushes, deletes, and reverts across 1024 striped mutexes to eliminate history forks and unreachable records; updates paired observations, retained summaries, and popularity within single sled transactions; and gates diversity increments on unobserved donors to prevent repeated-upload counter inflation
> - **Context-conditioned API resolution and comparison fidelity** — serves binary-specific variants across function detail, semantic neighbors, and workbench deep links via explicit `?md5=` context; resolves left and right sides independently during binary comparison; and filters out IDA dummy names (`sub_`, `nullsub_`, and address-like suffixes) via configurable admission policies
> - **Pattern classification and skeleton answers** — reads each key's stored candidates as *specific*, a *template member* (one member, many specialization arguments: `__func<λ>::__clone`, `QCallableObject<…>::impl`, `vector<T>::~vector`), a *coincidence* (unrelated names on a widely shared trivial body) or an ordinary *disagreement*; serves a template member whose specialization cannot be resolved for the requester as a re-mangled name with a placeholder type (`std::__1::__function::__func<__lumina_T>::__clone() const`, `QtPrivate::QCallableObject<__lumina_T>::impl(…)`, `__lumina_T::qt_metacall(…)`) verified by demangling, with a prototype only when every typed specialization declares it identically and never a decompiler guess (`scoring.template_skeleton_names`, `scoring.skeleton_placeholder`, `scoring.class_hole_members`); refuses pushed names carrying the placeholder; and withholds generic keys from batch anchoring so their foreign specializations cannot steer neighbouring keys
> - **Provenance-gated verbatim names and coincidence suppression** — serves another program's stored name only when the requester names a binary that observed it, covers a substantial fraction of a donor's functions (`scoring.related_donor_coverage`, two-sided: request share alone never qualifies), a neighbouring function of the request pins the specialization, or several unrelated program families observed the name independently (`scoring.library_min_families`, families judged by bounded pairwise function sampling under `scoring.family_overlap`, unknown relations treated as one family); otherwise answers `NOTFOUND` (`scoring.foreign_specific_decline`), and never serves a coincidence to a requester judged unrelated (`scoring.coincidence_suppress`)
> - **Sibling corroboration from request order** — exploits IDA's address-ordered pulls and compilers' contiguous emission of one specialization's thunks: a rare neighbour within `scoring.sibling_window` positions that was itself served on credible provenance, that a donor of one candidate also carries, and whose name mentions that candidate's argument pins the specialization and serves it verbatim at that position (`scoring.sibling_max_binaries`, `scoring.sibling_min_corroborations`); ties and foreign neighbours leave the skeleton in place
> - **Repeated-pattern decline, donor-size discount and collision-suffix normalization** — declines a pattern matching several functions of one request (`scoring.max_key_repeats`; template members still receive the skeleton) and counts the pull once per key rather than once per position; scales each donor's batch vote by `(query size / donor size)^scoring.donor_size_exponent` so a 145k-function binary cannot outvote a 12k-function one on fewer shared keys; and strips IDA's duplicate-name suffix (`…__cloneEv_0`) on push and on serve so one symbol is one stored variant (`scoring.normalize_collision_suffixes`)
> - **Served log, echo flags and decision diagnostics** — remembers versions served verbatim (`scoring.served_log`) and records a later push of that name from a binary that never carried the key as an echo of the server's own answer, excluded from family witnesses and the binary vote; captures pulls as replayable fixtures (`debug.dump_pull`), replays them with `analyze-pull` (every candidate, class, provenance and decision per position, donor table and outcome counts), and exposes the same decision as `pattern` on `/api/function/{key}`

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

To locate a known version outside that chain, use
`storage-audit CONFIG --key KEY VERSION_ID --physical ROW_LIMIT`, with an explicit
limit from 1 to 100000000 rows. The additional `physical_scan` report checks embedded
keys across registered segment trees and validates matching records with the serving
reader. It reports current/legacy ID matches, matches outside the inspected history,
invalid matching rows and truncation, retaining at most 64 record examples. Unrelated
records are not CRC-validated. This opt-in scan can read the entire record store;
it neither restores records nor establishes that an off-chain annotation should
be served. Use an offline copy; the handles are writable and no cross-store snapshot
is enforced.

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
| **Context** | Tracks binary MD5s, basenames, observations, per-version stats and overlap caches in `context_db`; binary facets are cached in memory. One neighbourhood scan per binary, spread over threads and cached, feeds overlap, related binaries, the graph and the family timeline |
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
- **Shared code API** at `/api/binary/:left/shared/:right`
- **Binary overlap API** at `/api/binary/:md5/overlap`
- **Binary comparison API** at `/api/binary-compare/:left/:right`
- **Recent submissions APIs** at `/api/recent/functions` and `/api/recent/binaries`
- **Prometheus metrics** at `/metrics`
- **Metrics JSON** at `/api/metrics`

The dashboard shows demangled names, parsed metadata, language badges, binary relationships, timeline views, coverage/facet summaries, and compare panels. Related binaries render either as a ranked list or as an interactive force-directed network that expands neighbours on demand. Its bottom panel lists the most recently pushed functions and binaries, each linking to a full page (`#r=functions&rn=100`, `#r=binaries&rn=100&ro=first_seen`) of the 25 to 200 most recent submissions.

### Binary intelligence

- **Per-binary summaries** with observation counts, function counts, first/last seen timestamps, and host tracking
- **Binary overlap** discovery based on shared functions
- **Binary family timelines** for related samples
- **Neighborhood graphs** for exploring binary clusters, expanded breadth-first from cached overlap and rendered as an interactive canvas network with lazy per-node expansion
- **Shared component inference** naming the library two binaries have in common from the namespace and prefix conventions of their rarest shared symbols
- **Containment and variant relations** read from how much of each binary the shared functions cover, so an embedded component is distinguished from another build of the same binary
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
| `context_db/` | Binary metadata, basename associations, version stats, overlap caches, popularity data, the served log (`served`) and echo flags (`echo`); legacy facet values are ignored |
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

Concurrent pushes, deletes and last-version reverts are serialized per function
key within a shared engine runtime. This keeps accepted versions in one reachable
history chain and suppresses duplicate payload appends while preserving binary
observations. Lock storage is bounded to 1024 stripes; different keys can share a
stripe. The separate stores still do not form a crash-atomic transaction, and
existing orphaned history is not repaired automatically.

### Serving layers

1. **Lumina RPC server** - handles Lumina clients, protocol negotiation, pull/push/delete/history flows, TLS, and upstream forwarding
2. **HTTP server** - serves the dashboard, JSON APIs, metrics, and cleartext HTTP/2 (`h2c`)

When TLS is enabled, the server can also expose HTTP over the Lumina side with ALPN-aware handling.

### Version selection

When an explicit query binary MD5 is available, selection first prefers that
binary's validated last-observed variant, then its observed historical variants.
Targeted retrieval can reach beyond the recent-version cap, within the live
history interval and a 4,096-record bound per traversal. If the explicit binary's
last observation is missing or cannot be retrieved, selection also examines up to
64 historical membership rows for that binary/function and can repeat collection
once with additional observed version IDs. These are bounded hints, not recovered
payloads: tombstones, name policy and record validation still apply. A retrievable
last observation avoids the extra scan; holdout evaluation never reads this history
for the withheld binary. No storage migration is required.

Selection recognizes current version IDs and the historical 64-bit little-endian
writer's IDs as aliases of the same stored variant. New writes retain the current
encoding. Alias counters are combined by maxima, since overlapping observations
cannot be distinguished; positive binary memberships from either encoding apply.
New observations use historical membership to prevent repeated uploads from being
counted as additional binaries when the uploader is omitted from a retained
summary. Membership and version statistics update atomically together. Older
inflated aggregate counts are preserved; this does not certify or reconstruct
historical cardinality, and it requires no migration or startup scan.

Per-key forward/reverse observations, the retained binary summary and popularity
indexes also update transactionally. Concurrent submissions no longer lose these
increments, and returning donors recover their accumulated per-key count when
competing for a summary slot. Popularity saturates at `u32::MAX`. Existing divergent
or inflated counts remain unchanged until explicitly repaired; an entire push
still spans several independent updates. No migration is needed.

Binary metadata observations and function/version count increments now use atomic
read/modify/write operations with exact tree statistics. Concurrent uploads to
different functions in the same binary preserve one another's counts and labels.
First/last observation times use minimum/maximum timestamps. Existing metadata
layouts remain readable; previously lost observation totals are not reconstructed.
Membership, aliases and binary metadata still have separate commit boundaries.

Binary-name discovery preserves concurrent aliases and supports more than 255
builds sharing one name. Search ranks each binary by its strongest matching alias,
including secondary names, and uses a stable MD5 tie-break for pagination. New
name/MD5 entries coexist with readable legacy alias lists; startup does not convert
them. Offline preparation recovers primary-name associations still present in
binary metadata. Already-lost secondary aliases cannot be inferred from those names.

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
zero-count placeholders consume the bound. Each target retains the strongest 64
inferred binaries plus up to 64 additional inferred donors known to contain that
function. The additional donors use the same evidence from other keys; the target's
own membership contributes no weight. This prevents unrelated global donors from
using every candidate slot. The original shortlist remains available for incomplete
legacy membership. Omitted weight is not redistributed. These weights are not
calibrated probabilities; the total donor bound is 128 per target. Each donor's
votes are scaled by `(reference / donor function count)^scoring.donor_size_exponent`
(default `0.5`, clamped to one), where the reference is the explicit query binary's
function count when known and otherwise the number of requested keys, so a very
large binary does not lead inference merely by containing more shared code. An
observation flagged as an echo (see below) does not vote. Set the exponent to `0`
for the unscaled vote.

By default, `scoring.binary_priority = true` prefers the variant supported by the
best matching individual binary; several weaker binary matches cannot collectively
override it. A binary's last observed variant is preferred to its older submissions
when retrievable. Otherwise its historical candidates share its evidence. Heuristic
scores break ties and handle absent evidence. Set `scoring.binary_priority = false`
to evaluate weighted scoring without this inferred preference; explicit binary
identity still takes precedence. Batch inference also applies to an explicit MD5
that has no usable observation for the queried function.

For an explicit MD5 with a missing or unusable per-function observation, selection
can complete a sparse request with other function identities already observed in
that binary. It examines at most 128 stored membership rows, verifies positive
observations and deduplicates keys. The query binary is excluded from donor
inference whether context keys were supplied by the caller or added by the server;
its exact observed variants still take precedence. This enables
related-binary retrieval from a single-function request without supplying expected
names. Holdout evaluation disables completion. The bounded prefix can miss useful
context and does not establish independent ranking accuracy.

If a positive observation points to an unavailable payload, completion runs only
after exact and historical candidate retrieval fail. Newly inferred donor targets
can trigger one additional bounded history walk; the maximum is three walks of
4,096 records per affected key. Exact and historical observed candidates retain
precedence. Coverage-cache dependencies include the companion prefix for fallback
results, including stale positive observations. No persistent format changes apply.

Coverage has a fast path when the validated history head matches the binary's
positive last observation: it parses that annotation directly and skips ranking.
Other cases retain the full selector. The preliminary probe reads at most one
physical record and preserves name filtering, tombstones and current/legacy IDs.
Coverage caches remain process-local and require no migration or preparation.

Candidate retrieval also seeks the stored canonical variant beyond the recent
window. Canonical refresh reconsiders that incumbent alongside recent submissions,
so lower-quality uploads cannot replace it merely by pushing it out of the window.
It remains subject to normal scoring, tombstones and the 4096-record history bound.
No data migration is required; this does not reconstruct previously lost choices.

If a related binary's last-observed annotation is unavailable, retrieval also
checks its recorded historical versions beyond the recent window. Inferred donors
share a 64-row allowance, searched by evidence strength with stable MD5 ties.
Explicit identity retains its separate 64-row allowance and selection precedence.
All hints must resolve through the live, validated history; deleted annotations
are not restored. This uses the existing context index without migration or a
startup scan. Bounded prefixes do not establish exhaustive historical recall.

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

Recency and observation/diversity scores are normalized over candidates eligible
for the current scoring pass. Excluded annotations cannot rescale those scores;
for example, an unrelated far-future upload cannot dilute recency among a binary's
eligible historical variants through normalization. Candidate diagnostics still
show the full retrieved set. Existing counters and canonical projections need no
migration; scores and margins can change where excluded records supplied extrema.

Semantic batch anchors use names, decoded prototypes, frame members, comments and
printable operand metadata. Each qualifying neighboring function contributes one
unit of evidence after generic terms are removed. Selection compares terms that
distinguish the eligible variants, excluding the target's own contribution.
Common terms and unrelated extra metadata cannot dilute those matches. This is
relative semantic support, not calibrated confidence; binary priority still applies.

After binary compatibility removes a candidate, lexical weights are restricted
again to distinctions among the survivors. A rejected annotation cannot dilute
their semantic match by introducing extra supported terms or making a shared term
appear distinctive. This does not relax the independent corroboration required to
override binary priority, and requires no database migration.

When a function or frame-member type cannot be rendered, its independently framed
field names can still supply lexical batch context. Malformed lists contribute
nothing. Selection inspects at most 8 KiB of such lists and retains 64 names per
candidate, across the function type and first 63 frame members. These words are
not decoded prototypes and cannot supply the corroboration needed to override
binary priority. Raw metadata and decode errors remain intact. This affects batch
selection only; canonical/search fingerprints and stored projections are unchanged.

`scoring.batch_identifier_components = true` (default) lets batch evidence connect
identifiers such as `http_read_header` and `HttpDecodeHeader`. Components augment
names, decoded prototypes, frame annotations, comments and printable operand text.
They help rank eligible variants; relaxing binary priority still requires the
original whole-token corroboration. Set the option false for ablation. Canonical
quality scores and persisted search tokens are unchanged; no rebuild is required.

With that option enabled, batch selection can also recover lexical words from
Swift symbols decorated with decimal collision suffixes such as `_0`. Recovery
requires a successfully demangled Swift prefix, examines at most four suffixes
and accepts at most 4096 input bytes. Stored names and payloads remain intact;
recovered words cannot supply the separate witness required to relax binary
priority. This adds no search-index migration or startup work.

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

#### What a pattern can identify

A Lumina pattern hashes a function body with relocations masked, so one key can
stand for every specialization of a template member whose code does not depend on
its argument (`std::__function::__func<λ>::__clone`, `::target`, `::destroy`,
`QtPrivate::QCallableObject<…>::impl`, `vector<T>::~vector`, `__tree<T>::destroy`),
for every moc dispatcher of one shape, or for every trivial destructor. Before
ranking, each key's collected candidates (at most `scoring.max_versions_per_key`)
are classified from their names alone:

- **specific** — one name after collision-suffix normalization;
- **template member** — every decodable candidate shares one skeleton (the
  demangled name with each top-level template argument list blanked, abi tags
  removed and closures canonicalized), that skeleton has at least one hole, the
  heaviest group holds at least `scoring.skeleton_min_share` of the key's
  observing-binary weight, and the specializations beyond the heaviest name carry
  real weight (one stray push beside a well-attested name does not qualify);
  members of plain classes listed in `scoring.class_hole_members` (moc's
  `qt_metacall` and relatives) form a class-hole member when they differ only in
  the class;
- **coincidence** — several unrelated names on a key carried by at least
  `scoring.generic_min_binaries` binaries (or beyond the 256-row membership bound),
  or on a body whose names are all trivial (destructors, assignments, static
  initializers) across four or more groups, or below `scoring.trivial_body_bytes`;
- **disagreement** — anything else; it keeps the previous behaviour.

Template members and coincidences contribute no batch anchors: their candidates
name other programs. A pattern that recurs in one request beyond
`scoring.max_key_repeats` (default `1`) identifies none of the functions it
matched; template members still receive the skeleton, every other class is
declined, and the pull counter moves once per key.

After ranking, the winning record passes a provenance judgement before it is
served verbatim. In order: the request names a binary that observed the record
(explicit); a donor of the record is covered by the request's rare keys at
`scoring.related_donor_coverage` of its functions (related — a large binary's
share of the request never qualifies on its own); the record was observed by at
least `scoring.library_min_families` independent program families (library-like,
where two observers are one family when a sample of at most 64 functions of the
smaller one is present in the larger at `scoring.family_overlap`, unknown relations
count as one family, and at most 32,768 such probes are spent per request);
otherwise the name is *foreign* and the position answers `NOTFOUND` when
`scoring.foreign_specific_decline` is set. A coincidence is served only to an
explicit or related requester when `scoring.coincidence_suppress` is set; a request
without a provenance judgement (inspection, holdout evaluation) keeps the ranked
answer.

A template member with a related or explicit requester serves that specialization
verbatim. Otherwise, when `scoring.template_skeleton_names` is set, it serves the
skeleton: the heaviest specialization's mangled name with the class template
argument list replaced by `scoring.skeleton_placeholder` (`__lumina_T`), accepted
only if the result demangles back to the skeleton with the placeholder in every
hole — shapes whose substitution table cannot be reconciled fall back to a plain
identifier such as `std_1_tree_lumina_T_destroy`. Its metadata is the `MDK_TYPE`
chunk only when every typed specialization declares (`userti`) the same prototype
bytes; guessed or differing prototypes serve nothing. `base_version_id` still names
the donor; `used_synthesis` is set. Pushed names carrying the placeholder are
refused under every name policy.

A skeleton can still be pinned per position. IDA sends patterns in address order
and a compiler emits one specialization's thunks together, so within
`scoring.sibling_window` positions of a template-member position, a neighbour that
is specific, carried by at most `scoring.sibling_max_binaries` binaries, served to
this requester on explicit or related provenance, observed by a donor of one
candidate and whose demangled name mentions that candidate's argument words,
serves that candidate verbatim there (`ServedForm::Corroborated`). Two candidates
so corroborated at one position, or a foreign neighbour, leave the skeleton.
Corroboration uses candidates already in memory and no further reads.

Versions served verbatim are recorded in the `served` tree (`scoring.served_log`).
When a binary that never carried the key later pushes that same version after it
was served, the observation is flagged in the `echo` tree: it still counts as a
membership for retrieval but is neither a family witness nor a vote. Both trees
are created on first use and need no migration; echoes recorded before the log
existed are not reconstructed. None of these judgements are calibrated
probabilities: coverage and family thresholds are conservative defaults to be
tuned per corpus, and every mechanism has a configuration switch.

### Protocol and transport

- Lumina protocol versions `2` through `6`
- plaintext or TLS on the Lumina side
- HTTP/1.1 and cleartext HTTP/2 (`h2c`) on the HTTP side
- optional HTTP handling on the TLS/Lumina side when enabled
- optional upstream miss forwarding with priority ordering

---------------

## Repository map

- `src/main.rs` - server entrypoint
- `src/db/` - high-level database API, search enrichment, binary compare logic, version scoring; `pattern.rs` (classification and decisions), `provenance.rs` (relatedness and family judgement), `sibling.rs` (specialization pinning from request order), `family.rs` (batch binary vote)
- `src/common/skeleton.rs`, `src/common/remangle.rs` - name skeletons, collision-suffix normalization, placeholder re-mangling with round-trip verification
- `src/engine/` - segments, indexes, context index, search index, runtime wiring
- `src/protocol/lumina/` - Lumina wire handling and metadata parsing
- `src/api/http/` - dashboard templates, HTTP handlers, router, metrics APIs
- `src/bin/recover.rs` - rebuild, migration, and recovery utility
- `src/bin/analyze-pull.rs` - replay a captured pull and explain every decision
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
- `scoring.*` - version-selection weights and caps, pattern classification, provenance gating, skeleton serving
- `debug.*` - protocol hello dumping and pull capture

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
- `scoring.max_key_repeats` - positions of one pattern per request above which it is declined (default `1`)
- `scoring.foreign_specific_decline` / `scoring.coincidence_suppress` - withhold another program's name, or a coincidence, from a requester judged unrelated (default `true`)
- `scoring.related_donor_coverage`, `scoring.library_min_families`, `scoring.family_overlap` - what makes a requester related to a donor, and a name library-like
- `scoring.template_skeleton_names`, `scoring.skeleton_placeholder`, `scoring.class_hole_members` - serve template members with a placeholder type; the placeholder is refused on push
- `scoring.sibling_window`, `scoring.sibling_max_binaries`, `scoring.sibling_min_corroborations` - pin a specialization from the request's own neighbourhood (`0` disables)
- `scoring.donor_size_exponent` - donor-size discount in batch inference (`0` disables)
- `scoring.normalize_collision_suffixes`, `scoring.served_log` - collision-suffix normalization and the served log behind echo detection
- `debug.dump_pull`, `debug.dump_pull_dir`, `debug.dump_pull_payloads` - write each pull's raw payload and served answers for `analyze-pull`
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
# Page cache for context_db. The binary overlap, related-binary and graph
# scans walk per-key postings there, so this is the knob that decides whether
# they read memory or the filesystem; size it against data/context_db.
engine.context_cache_bytes = 268435456
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

# Pattern-aware serving (defaults shown; each switch can be turned off)
scoring.max_key_repeats = 1
scoring.template_skeleton_names = true
scoring.skeleton_placeholder = "__lumina_T"
scoring.foreign_specific_decline = true
scoring.coincidence_suppress = true
scoring.related_donor_coverage = 0.15
scoring.library_min_families = 3
scoring.sibling_window = 8
scoring.donor_size_exponent = 0.5
scoring.served_log = true

# Capture pulls as replayable fixtures for analyze-pull
debug.dump_pull = false
debug.dump_pull_dir = "debug_dumps"
debug.dump_pull_payloads = false

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
./target/release/dazhbog-recover --list-trees data

# Migrate old context trees into context_db
./target/release/dazhbog-recover --migrate-context data

# Rebuild the latest key index
./target/release/dazhbog-recover --rebuild-index data

# Rebuild per-key basenames from binary metadata
./target/release/dazhbog-recover --rebuild-basenames data

# Rebuild the search index
./target/release/dazhbog-recover --rebuild-search data

# Run the combined rebuild flow
./target/release/dazhbog-recover --rebuild-all data
```

Run recovery on an offline copy. `--rebuild-index` reconstructs each head from
physical append order, including tombstones and reinsertion; equal or decreasing
timestamps do not select an older version. It validates all scanned records before
replacing the index and refuses malformed input rather than skipping possible
tombstones. It maintains index counters and invalidates search projection markers
while retaining old search directories. Then run `dazhbog --prepare CONFIG` before
serving (`--rebuild-all` includes search preparation). If writing is interrupted,
rerun index rebuilding before preparation. Reconstruction cannot establish whether
an original append was published or whether an old pointer-only undo was intended.
The separate `--full-recover` flow does not share these guarantees and still has
timestamp-ordering and relocated-history limitations.

Other helpers:

```bash
# Dump metadata payloads for parser work
./target/release/dump_functions --dump 2000 analysis/data

# Dump function names from the corpus
./target/release/dump_function_names --output function_names.txt --unique

# Replay a captured pull (debug.dump_pull) and explain every answer
./target/release/analyze-pull CONFIG debug_dumps/pull-<ts>-<n>.bin --hits-only > decisions.jsonl
```

`analyze-pull` opens the store like the server and must run against an offline
copy or a stopped server. It prints the inferred donor table, the class split of
the known keys and the served/declined outcome counts to stderr, and one JSON
line per position to stdout: the served name, class, skeleton, provenance,
decision, repeat count and every stored candidate with its observing binaries.
`--max-versions N` bounds candidates per key and `--binary-cap N` the membership
count. The recovery tool covers context migration, search refreshes, basename
reconstruction, and full rebuild flows.

## API surface

| Endpoint | Purpose |
|----------|---------|
| `/` | Interactive dashboard |
| `/api/search?q=...&mode=functions|binaries` | Function or binary search |
| `/api/function/:key` | Full function detail, parsed metadata, binaries, and `pattern`: the class, skeleton, provenance and served form a client would receive (`?md5=` sets the requester's binary) |
| `/api/binary/:md5` | Binary summary plus facets, related views, and overview data |
| `/api/binary/:md5/functions` | Paginated function list for a binary |
| `/api/binary/:md5/overlap` | Related binaries by shared functions |
| `/api/binary/:md5/graph` | Graph neighborhood data |
| `/api/binary-compare/:left/:right` | Binary-to-binary comparison |
| `/api/recent/functions?limit=N` | Newest visible function versions in physical append order (`limit` 1..200, default 10); reports the rows scanned, undecodable rows and whether the 4096-row scan bound was reached |
| `/api/recent/binaries?limit=N&order=last_seen\|first_seen` | Binaries ordered by last observed push (default) or first observation, ties by MD5 |
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

Holdout evaluation runs without a provenance gate and without request positions,
so it measures ranking, not the decline and skeleton decisions; template members
served as skeletons count as name mismatches there. For those, capture a real pull
with `debug.dump_pull`, replay it with `analyze-pull` and compare the outcome
counts before and after a change. `tests/skeleton_fixture.rs` classifies such a
capture offline from its `analysis.jsonl` (the file
`research/fixtures/binaryninja-pull-16752.analysis.jsonl`, kept outside version
control) and asserts the class of its reference keys; it is skipped when the
capture is absent.

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

Sharing checks also inspect the bounded donors inferred from other requested keys.
Their exact version observations can supply provenance when a target's membership
list exceeds its scan limit or its summary is missing. Relatedness alone remains
insufficient, and the held-out binary cannot supply this evidence. This requires
no migration or startup scan.

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
