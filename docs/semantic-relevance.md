# Binary-conditioned variant selection

## Objective and baseline

The objective is to maximize selection of the function variant appropriate to the
querying binary, including unseen builds and ambiguous function hashes. Improving
metadata richness alone does not establish that objective. Baseline for this
investigation: `60aee144b100ca224b811f968d5499cebd6d5da3`; tracked tree clean,
pre-existing `research/` preserved. Source edits use file editing tools only.

## Evidence and change surface

Both pull handlers currently construct `QueryContext` with keys and requested
metadata keys, but no binary MD5, basename, host or origin. Binary inference from
the other requested functions is therefore a primary serving signal. Existing
selection multiplies binary votes by repeated observation counts and includes the
target's own membership. Candidate provenance consults capped `top_md5s` despite
the existing `binary_versions` index. Generic richness and recency can override
an explicitly known binary's last observed variant. History retrieval is capped
before the scorer sees an older binary-specific version.

Affected: selection, history candidate retrieval, context reads, offline evaluation,
tests and documentation. Wire encoding, raw record layout, configuration syntax,
session authorization, upstream transport and search schema are unchanged by the
first implementation group. Browser variant conditioning, further metadata use,
independent evaluation and migration completeness remain part of the full objective.

## Assumption Register

| ID | Assumption / basis | Dependent result | Stress test / falsification probe | Status |
|---|---|---|---|---|
| S1 | Distinct keys in one pull usually describe one input binary; handlers expose no explicit binary identity. | Batch binary evidence | Mixed-library and mixed-binary batches, ubiquitous keys, permutations and repeated keys; measure on held-out binary batches. | Retained; not guaranteed by the wire format |
| S2 | A binary/key's recorded last version is stronger evidence of its submitted variant than global richness. | Explicit identity preference | Missing, corrupt, pre-tombstone and stale version references; compare against original binary annotations. | Retained; observations are not authenticated ground truth |
| S3 | Existing `binary_versions` membership is positive evidence, but absence in migrated data is not proof of incompatibility. | Historical and inferred support | Old context fixtures, top-list overflow and prepare/reopen comparison. | Retained; reconstruction completeness must be measured |
| S4 | The earlier APFS clone preserves the supplied dump sufficiently for investigation; no original writer was observed during cloning, but the copy was not an enforced cross-store snapshot. | Production-derived agreement and corruption observations | Compare an application-quiesced snapshot; see the startup review's A1. | Retained |
| S5 | Legacy observations use the historical 64-bit little-endian Rust Hash feed and zero-key SipHash-1-3. Basis: writer source at `8e1ffd2`, Rust source, and matching persisted IDs. | Legacy ID read compatibility | Empty, Unicode/NUL, 8-byte and 256-byte boundaries against the historical writer; repeat fixed dump sample. A mismatching stored ID with known raw bytes falsifies applicability to that writer. | Confirmed for recovered observations; other writer platforms remain unknown |
| S6 | Current and legacy counters for one raw variant can contain overlapping observations; the overlap is unrecoverable from summary counters. | Use maxima rather than sums; union positive membership | Duplicate aliases, reversed merge order, saturated u32 counters, disjoint binary summaries. Original observation logs establishing disjoint sets would permit a different aggregation. | Retained; no claim that maxima repair existing counter bias |
| S7 | The best matching individual observed binary is a stronger variant signal than metadata richness or the number of weaker matching sibling binaries. | Default inferred binary priority | Many partial matches against one complete match, sparse/tied/mixed batches, unknown MD5 and weighted-scoring ablation; family-disjoint unseen-binary evaluation can falsify generalization. | Retained; known-binary retrieval confirmed on two fixed samples, unseen-binary accuracy unknown |

## Required validation and remaining work

- Compare selection against the baseline on fixed adversarial fixtures and
  production-derived batches, separating candidate availability from ranking.
- Prevent target self-evidence, repeated-upload amplification and capped top-list
  omissions; preserve duplicate outputs, misses and requested-key shaping.
- Expand binary-specific candidate recall without crossing tombstones or accepting
  corrupt/foreign history. Keep storage and request work bounded.
- Evaluate cross-binary function variants using metadata/provenance evidence;
  distinguish retrospective observation agreement from independent accuracy.
- Audit prototypes, calling conventions, frame layouts, operand offsets, comments,
  origins and language evidence for compatibility and useful discrimination.
- Add reproducible evaluation with family-disjoint samples, ablations, uncertainty,
  latency and migration checks. Do not describe heuristic scores as probabilities.

The full objective remains unverified until these requirements have direct evidence.

## First implementation group: binary evidence and candidate recall

Implemented without changing persisted formats:

- Query-time binary membership comes from `key_md5`, not lossy `key_bins` upload
  counters. Each distinct key contributes total weight one, divided over its
  binaries. Lists exceeding 256 binaries are omitted as insufficiently specific.
- Leave-one-out scoring removes the target's contribution and normalizes by the
  remaining informative keys. At most 64 binary candidates survive; their weights
  are not renormalized after truncation. Input ordering and duplicates do not
  change this evidence. [S1]
- Targeted history retrieval supplements the recent distinct-version cap with
  last-observed versions of those binaries and the explicit query binary. Raw
  ancestry is still bounded at 4,096 records and stops at a tombstone. [S2, S3]
- Explicit binary identity first selects its validated last-observed version;
  otherwise it restricts scoring to observed historical candidates when available.
  Requested-key shaping remains strict, even if that version lacks a requested
  component. Synthesis cannot substitute a different binary's variant. [S2]
- Inferred support consults `binary_versions` in addition to the historical
  top-16 summaries. Analysis and version statistics are loaded once per candidate.
  Ties use score, timestamp and version ID deterministically. [S3]

The unchanged production structures remain readable through the existing offline
preparation path. No new migration is required for this group; lost observations
are not reconstructed by the new query logic.

### Regression evidence

`tests/binary_selection.rs` was executed with the baseline database selector from
`60aee144`, using file-tool replacement followed by restoration of the candidate
implementation. Three of four cases failed on that baseline and all four passed
on the candidate: exact-binary retrieval beyond the recent cap, repeated uploads
against independent neighboring keys, and binary membership beyond the top-16
summary. Tombstone isolation passed in both versions. This is a controlled
synthetic comparison, not a corpus accuracy estimate.

The final affected checks passed 83 tests: library 36 (including bounded membership
and malformed timestamp validation), binary selection 6, database integration 8,
Lumina codec fixtures 10, semantic matching 9, neighbors 2 and startup/projection
12. The final added library boundary test was run separately after the combined
82-test run. Strict Clippy passed for the library, server, replay evaluator and
new integration target. These checks ran on native macOS; cross-platform execution
and production-sized batch latency have not yet been measured for this group.

Owned files: `src/db/database.rs`, `src/db/family.rs`, `src/db/mod.rs`,
`src/engine/context_index.rs`, `src/engine/mod.rs`, `tests/binary_selection.rs`,
`README.md`, `AGENTS.md` and this report. The guide was reconciled with the new
evidence and traversal contracts; an encountered stale shutdown description was
also corrected against `src/main.rs`. Production data and `research/` were not
modified or opened by this implementation group's tests.

### Complexity and limits

For K distinct keys, membership degree bound D = 256, C = 64 inferred binaries,
V retained variants and R traversed history records per key:

- Membership work reads at most K(D + 1) rows; aggregation retains O(KD) entries
  and sorts at most KD binary totals. BTreeMap accumulation costs O(KD log(KD)).
- Each target's bounded heap examines at most C + D affected candidates after
  aggregate sorting, with O((C + D) log C) heap work and O(C) output storage.
- Candidate history reads O(min(R, 4096)) records per key, retaining at most the
  configured recent cap plus C + 1 targeted variants. Missing targets may require
  the full traversal bound. Metadata bytes remain an additional cost.
- Binary support performs at most O(KVC) point lookups per scoring pass, with
  top-summary hits avoiding the lookup. Production latency for large batches is
  not established by the synthetic tests.

### Adjacent findings retained for subsequent work

| Impact | Evidence / consequence | Disposition |
|---|---|---|
| High | `record_key_observation` rebuilds absent entries of capped `key_bins` at count one; a discarded binary can repeatedly fail to reenter despite many uploads. | Query inference now bypasses this summary; write-side statistics require a separate repair/migration audit. |
| High | `version_stats.num_binaries` increments when a binary is absent from a capped top list, even when historical membership already exists. | Global popularity remains a potentially biased feature; repair and ablation remain in scope. |
| Medium | Legacy preparation reconstructs some version memberships only from last-version observations. | Positive membership is usable; missing history remains unknown. |
| Medium | Replay still contains held-out observations and a separate anchor path. | It cannot substantiate independent accuracy; evaluation must address leakage. |

## Second group: observed-binary evaluation

`eval-binary-context` samples bounded sets of binary IDs and function keys by
seeded hash priority, then invokes the same selector used by wire pulls. Diagnostic
candidate IDs are retained only when requested. Labels are the binary/key's last
observed version ID; the request itself supplies no binary identity. A separate
explicit-ID query tests whether the labeled variant is retrievable. No push or
context update is performed. Sampling scans binary metadata and selected binary
memberships with O(sample size) heap memory, rather than collecting those stores.

An initial release run on `/tmp/dazhbog-review-snapshot-20260915`, seed 1, requested
32 binaries × 64 keys. One batch failed with a cross-key history error. Among the
remaining 1,984 keys: 1,457 labeled variants entered the candidate set, 1,415 were
selected, 1,358 matched latest-version selection, and 1,384 matched canonical
selection. Of 291 ambiguous available cases, 249 matched the recorded variant.
Explicit identity retrieved the same 1,457 labels. The 527 unavailable labels and
64-key failed batch remain part of the reported limitation. [S1–S4]

These are known-binary observation-agreement counts, not independent accuracy.
Exact version identity includes volatile decompilation timing. The tool therefore
also compares names and parsed raw chunks while excluding only `VdElapsed`; parse
failures are unjudged and unknown keys remain significant.
During validation, truncated chunk keys/lengths were found to terminate parsing
without an error. They now report errors while retaining decoded prefix chunks,
so evaluation and quality scoring can distinguish incomplete data from empty data.

### Compatibility finding

Missing-label examples contain the queried key in the first 16 bytes, a different
64-bit value in the next eight bytes, and a small integer in the final eight.
Repository commit `8e1ffd218046f850b3daff1145524954402100a5` introduced a private
`src/db/database.rs::version_id` using `DefaultHasher` over key, name and data,
followed by the name length. Its separately introduced common helper uses the
current name/data hashes instead. The dump contains references shaped like the
former encoding. Restoring compatible provenance is the next required probe;
the exact number of recoverable references is not yet established.
The Rust standard library does not guarantee that `DefaultHasher` remains the
same across releases, and `Hash` inputs can vary with platform byte order and type
width. Compatibility therefore requires fixed fixtures and corpus verification,
not merely calling the current standard-library hasher.
Sources: [DefaultHasher](https://doc.rust-lang.org/std/hash/struct.DefaultHasher.html),
[Hash portability](https://doc.rust-lang.org/std/hash/trait.Hash.html#portability).

Initial raw JSON evidence is retained outside the repository at
`/tmp/dazhbog-binary-eval-seed1-initial.jsonl`. Existing `research/` was inspected
for corpus provenance but not executed or modified; its pair tables derive from
binary membership and do not supply independent variant labels.

The final evaluator rerun retained the same exact-agreement counts. All 1,457
retrievable references were also judgeable by the raw-chunk comparison: 1,415
matched semantically and 1,449 matched by name. Thus 34 of the 42 available-variant
mismatches retained the right name but different metadata. Examples changed
`Type`/`FrameDesc` (keys 1/9), or `Cmts`/`Ops` (keys 5/10). Excluding timing did
not erase these mismatches. This directly motivates structural and per-binary
variant discrimination rather than optimizing name agreement alone.

Final evidence: `/tmp/dazhbog-binary-eval-seed1-baseline.jsonl`. Command:
`target/release/eval-binary-context /tmp/dazhbog-review-benchmark.toml 32 64 1`.
The nonzero exit is intentional: one corrupt-key batch failed, and partial
results are reported rather than silently presented as a complete evaluation.

Validation for this group: 86 affected tests passed across the executed suites
(library 37, binary selection 7, database 8, Lumina fixtures 10, semantic matching
10, neighbors 2, startup/projection 12); selected-target strict Clippy and all-target
test compilation passed. The release evaluator was built and exercised on the
copied dump. Legacy Cargo binary-name and stress-test unused-variable warnings
remain. `AGENTS.md` and README describe the diagnostic API, sampling/label limits
and incomplete-frame reporting. No persisted format was changed by this group.

## Third group: historical version-ID read compatibility

Baseline: `7cb402161a163ea15307a228d49906b98624cc9b`. The pinned legacy writer
uses the exact historical feed described in `AGENTS.md`; it does not depend on
the current standard-library hashing implementation. New records and observations
continue using the current ID. No original context tree or raw record is rewritten.
Targeted retrieval, exact binary filtering, historical membership, canonical hints,
canonical visibility, replay context and evaluation all recognize aliases. Candidate
diagnostics count variants once and expose parallel current/legacy ID vectors.
Cached alias statistics take per-counter maxima and union positive binary summaries
without adding potentially duplicated upload counts. [S5, S6]

### Migration and affected representations

Raw layout, wire framing, metadata shaping, configuration syntax, session policy,
upstream transport and the search schema are unchanged. Selection, context reads,
canonical HTTP/search visibility, offline replay and search reconstruction change.
Recognizing old canonical pointers can replace a prior newest-record fallback.
Therefore serving requires `canonical_projection_v2`. Offline preparation builds
a new generation, retains v1's files and marker, and publishes v2 only after flush.
An interrupted or corrupt-record preparation does not certify the old projection.
`open_for_replay` may inspect a v1 generation with a warning, without upgrading its
marker; that mode's old search documents are unsuitable for a search evaluation.

The migration regression reproduces a v1 search document disagreeing with an older
legacy canonical pointer. Normal open rejects it; replay resolves the raw variant;
preparation restores the correct searchable name. Raw count, latest address,
canonical ID, old marker and old search manifest remain unchanged. The public
materializing rebuild helper now delegates pointed histories to the same bounded
resolver; the migration regression also verifies its alias projection. The
production copy was evaluated without rebuilding its complete search generation
in this group.

### Fixed production-derived comparison

Command: `target/release/eval-binary-context /tmp/dazhbog-review-benchmark.toml 32 64 1`.
Artifact: `/tmp/dazhbog-binary-eval-seed1-legacy.jsonl`.

| Quantity | Before aliases | After aliases |
|---|---:|---:|
| Successful keys, in 31 batches | 1,984 | 1,984 |
| Available / explicitly retrievable labels | 1,457 | 1,900 |
| Selected exact agreement | 1,415 | 1,851 |
| Latest exact agreement | 1,358 | 1,782 |
| Canonical exact agreement | 1,384 | 1,813 |
| Ambiguous available / correct | 291 / 249 | 323 / 274 |
| Semantic agreement, excluding timing | 1,415 / 1,457 | 1,851 / 1,900 |
| Name agreement among available references | 1,449 | 1,892 |

Availability gained 443 labels; exact agreement gained 436. Availability changed
from 73.4% to 95.8% of successful keys; exact agreement from 71.3% to 93.3%.
These rounded percentages are descriptive of this fixed retrospective sample,
not independent accuracy or estimates with a binomial independence assumption.
The same 64-key batch still fails with a cross-key history error, and 84 labels
remain unavailable. The tool exits 1 to expose that incomplete evaluation. [S1–S5]

The restored evidence also changes ranking: binary `0efb700dca8b82edf8dc29ff28c02025`
falls from 32 to 28 correct of 63 available. Historical membership gives multiple
submitted variants positive support, whereas the label represents the last observed
one. Resolving that distinction is subsequent ranking work; aggregate gains do
not erase the four regressions. Of 49 available mismatches after aliases, 41 retain
the right name but differ in metadata. Independent labels remain unavailable.

### Validation, complexity and limits

92 affected tests passed: library 40, binary selection 9, database 8, Lumina
fixtures 10, semantic matching 10, neighbors 2, startup/projection 13. Coverage
includes a historical-writer oracle at every payload length 0..513, fixed byte
fixtures, UTF-8/NUL names, saturated counter aggregation, legacy top-list overflow,
targeted recall, duplicate diagnostic cardinality, shaping, and both current/legacy
references across deletion. Strict Clippy passed for library, server, both
evaluators and the two changed integration targets. Native macOS execution only.
All-target test compilation also passed; existing Cargo binary-name and stress-test
unused-variable warnings remain.

For B total name/metadata bytes hashed across visited records, compatibility adds
O(B) CPU work and O(1) hash workspace. Each retained candidate adds one context
statistics lookup and 32 B for its legacy ID. Membership requires at most two point
lookups per candidate/binary. Writer-produced top-16 summaries union to at most
32 entries. The persisted u8 count permits 255 per alias, so the decoder's maximum
union is 510 entries. Existing candidate and history bounds remain unchanged.
No corpus scan is added to normal startup. Cold startup timing and production-sized
projection rebuild timing were not remeasured in this group.

Bounded findings: **high**—one corrupt key still aborts a whole serving/evaluation
batch; **high**—historical membership can prefer an older annotation over the
inferred binary's last observation; **medium**—84 sampled labels remain unreachable;
**medium**—older 32-bit or big-endian writer compatibility is unknown. Existing
counter bias and independent-label gaps remain as recorded above. These findings
bound this compatibility group and remain part of the broader active objective.

Owned paths: `src/common/{hash.rs,legacy_version.rs,mod.rs}`, `src/db/{database.rs,
evaluation.rs,types.rs}`, `src/engine/{context_index.rs,mod.rs,visibility.rs}`,
`src/engine/search/rebuild.rs`, `tests/{binary_selection.rs,startup_projection.rs}`,
README, root AGENTS and this
report. The guide was reconciled with alias identity, replay and projection rules.
Production `data/`, ignored configuration and pre-existing `research/` were preserved.

## Fourth group: binary priority and conserved evidence

Baseline: `c934b88e4de73e3e6211f1720dacdf62b1294a31`. Final selection gives
explicit observations precedence as before. With no usable explicit observation,
the default `scoring.binary_priority = true` makes the strongest individual inferred
binary match primary. Metadata and weighted scores break ties and handle absent
evidence. Setting the option false disables this inferred preference for ablation;
it does not disable explicit identity. The parser tests defaults, both booleans and
invalid input, and the integration test exercises both runtime settings. [S1, S2, S7]

### Algorithm and cost

For a target key, let `w_b` be binary b's weight inferred from the other distinct
keys, and `L_b` the eligible candidates for b: its retrievable last observed variant,
or its historical candidates if that last variant is unavailable. All candidates
come from validated live history. The implementation computes:

```text
mass[v]  = sum(w_b / |L_b| for b where v belongs to L_b)
match[v] = max(w_b         for b where v belongs to L_b), or 0
```

Thus `sum(mass) <= sum(w_b) <= 1`, subject to floating-point rounding. Missing
binary/candidate mass remains missing. Repeated historical variants cannot multiply
one binary's evidence. The primary filter retains maximal `match`, with absolute
tolerance 1e-12 in these dimensionless units; below that scale it retains heuristic
scoring. This is a numerical tie tolerance, not a calibrated confidence threshold.
Several weaker sibling binaries cannot combine their mass to defeat a stronger
individual match. The secondary `w_coh` score uses conserved `mass`.

Last-version IDs already read for targeted retrieval are reused. Inferred support
is computed once for both scoring passes. For C <= 64 inferred binaries and V
retained candidates, CPU work is O(CV + C log C); scratch memory is O(C + V).
Each candidate retains two f64 values (16 B). Historical fallback performs at most
CV logical membership checks, each with up to two alias tree lookups; matching a
retrievable last variant avoids those historical lookups. The previous two scoring
passes could each perform CV checks. Explicit-identity filtering has its separate
existing lookup cost. Optional diagnostics add two V-element f64 vectors.

Only query-time selection, configuration, diagnostics and evaluation change. Wire
encoding, raw record/context formats, canonical projection, session policy,
upstreams and startup are unchanged. No migration beyond the preceding v2 search
preparation is required. Canonical refresh and single-key replay have no inferred
binary evidence and retain their existing heuristic behavior.

### Behavioral and corpus evidence

The superseded-annotation fixture failed before conserved support and passes now.
The partial-binary fixture failed with aggregate-mass priority and passes with the
final policy. It has one binary matching both neighboring keys versus nine binaries
each matching only one; their combined count cannot override the complete match.
Additional tests cover five historical fallback candidates sharing only 0.5 total
available mass, explicit unknown MD5, disabled priority, richness versus empty
metadata, synthesis isolation, duplicates and input permutations.

The two fixed release samples each request 32 binaries × 64 keys, seeds 1 and 2:

| Policy | Seed 1 selected agreement | Seed 2 selected agreement |
|---|---:|---:|
| Conserved mass, weighted scoring | 1,851 | 1,753 |
| Aggregate-mass priority | 1,900 | 1,790 |
| Final individual-binary priority | 1,900 | 1,847 |
| Retrievable labels | 1,900 | 1,847 |
| Successful evaluated keys | 1,984 | 2,048 |
| Ambiguous retrievable labels, all correct in final policy | 323 | 590 |

The final policy matches every retrievable label in both samples, including the
four regressions from alias restoration and the four-count regression in one
seed-2 binary under aggregate priority. Exact and semantic payload counts agree.
No per-binary aggregate regressed against weighted scoring in the final comparison.
Seed 1 still has 84 unavailable labels and one failed 64-key batch; seed 2 has
201 unavailable labels and no failed batch. Seed 1 exits 1, seed 2 exits 0.

This establishes retrospective known-binary retrieval, not independent accuracy.
By construction, the sampled source binary contains the sampled keys; its overlap
can therefore attain the maximum. The evaluator does not remove that binary's
observations. Both samples informed this investigation and are not held-out final
test sets. Unseen builds, mixed batches and independently labeled variants still
require separate evaluation. [S1–S4, S7]

Commands use `target/release/eval-binary-context /tmp/dazhbog-review-benchmark.toml
32 64 SEED`. Evidence files: `/tmp/dazhbog-binary-eval-seed1-mass.jsonl`,
`/tmp/dazhbog-binary-eval-seed2-weighted.jsonl`,
`/tmp/dazhbog-binary-eval-seed1-priority.jsonl`,
`/tmp/dazhbog-binary-eval-seed2-priority.jsonl`, and final
`/tmp/dazhbog-binary-eval-seed1-nearest.jsonl`,
`/tmp/dazhbog-binary-eval-seed2-nearest.jsonl`.
Query timing in these runs is cache- and load-dependent; no controlled latency
improvement or cold-start result is inferred from it.

Diagnostics expose selected/expected aggregate support and strongest individual
match, plus total available support. Margin and entropy describe candidates after
binary filtering and cannot express uncertainty about binary identity.

Validation: 97 affected tests passed (library 41, binary selection 13, database 8,
Lumina 10, semantic matching 10, neighbors 2, startup/projection 13); strict Clippy
and all-target test compilation passed. Native macOS only; prior Cargo naming and
stress-test warnings remain. Root `AGENTS.md` and README were updated and checked
against runtime consumers and tests. Owned files: those guides, this report,
`src/config/{parser.rs,types.rs}`, `src/db/{database.rs,evaluation.rs,types.rs}` and
`tests/binary_selection.rs`; a comment in `src/engine/context_index.rs` also corrects
the decoded summary bound above. Original data, ignored configuration and `research/`
remain intact; only the existing disposable copy was opened for corpus evaluation.

Bounded findings: **high**—corrupt-head isolation and unavailable variant recall
remain unresolved; **high**—known-binary agreement does not establish unseen-build
accuracy; **medium**—mixed or indistinguishable batches can tie or misidentify binary
context. No claim is made that this group completes the full relevance objective.

## Fifth group: binary identity holdout and inspectable mismatches

Baseline: `4ba57a611e4e0bbb53a58d7c332eec6dde18d5f9`. This group separates
known-binary retrieval from transfer to a withheld binary. The evaluator now accepts
`observed` (default) or `transfer` as its final argument. Empty samples fail explicitly.

### Assumption register and scope

| ID | Assumption and basis | Dependent result | Stress test / falsification probe | Status |
|---|---|---|---|---|
| S8 | Positive last-version or historical membership in another binary establishes that a variant has other-binary provenance. Persisted observation trees and alias summaries supply this evidence. Absence remains unknown. | Transfer candidate eligibility | Private-only variants, omitted top-16 membership, current/legacy aliases; compare retained variants with complete original upload logs if available. | Retained; synthetic boundaries verified, original logs unknown |
| S9 | Withholding one MD5 provides a useful transfer diagnostic despite related binaries, incomplete provenance and bounded physical history remaining. | Interpretation of transfer results | Suppress held-out counts, timestamps and canonical hints; reverse those fields and verify invariant selection. An independently reconstructed family-disjoint corpus can falsify generalization. | Retained; invariance verified, independent accuracy unknown |

S1–S7 retain their preceding scope. Selection, history filtering, diagnostics, tool
behavior and regression coverage are affected. Configuration syntax, both wire
encodings, sessions, mutation formats, search projection, HTTP, upstreams, recovery
formats and runtime ownership are unaffected by this group. No migration is needed.
Owned paths: `src/db/{database.rs,evaluation.rs,mod.rs}`,
`src/bin/eval-binary-context.rs`, `tests/binary_selection.rs`, root `AGENTS.md`,
README and this report. Original `data/`, local configuration and `research/` remain
user-owned and unchanged; corpus runs use the existing disposable copy.

### Algorithm, isolation and resource bounds

Transfer removes the withheld MD5 before the 256-membership cap and normalization.
It retains only variants with positive provenance in another binary, counting the
recent-version cap after this filter. It suppresses global observation-count,
binary-count, recency and canonical priors, including timestamp tie-breaking.
It constructs its own context without identity, basename, hostname or origin hints.
Semantic anchors therefore come from eligible variants. No persistent observations
or records are removed. A foreign-key head remains an error; older foreign ancestry
ends traversal even when filtering leaves no eligible candidate. [S3, S8, S9]

The full corpus still supplies explicit-identity label retrieval and latest/canonical
diagnostics. These are not uncontaminated transfer baselines. Physical history order,
the 4,096-record traversal bound, retained-candidate cap and incomplete membership
can affect eligibility; the procedure is not equivalent to rebuilding training
storage after deleting a binary or source family. Related MD5s remain in training.

For K distinct keys, R <= 4,096 visited records per key, D <= 257 inspected binary
memberships and V retained variants, added holdout work is O(KRD) point lookups in
the worst case, plus metadata analysis for retained variants. Scratch provenance
storage is O(D) per key in addition to existing O(R + V) retrieval storage. Each
candidate provenance check uses two alias-statistics reads and may use two historical
membership reads per other binary; positive summary evidence short-circuits that
loop. Storage reads remain bounded, but are not negligible on cold storage.

Normal scoring now skips binary-metadata reads when no basename, hostname or origin
hint exists. This removes up to 2VM metadata reads per key across two scoring passes,
where M is `max_md5_per_version` capped by retained summary length. Hint-bearing
queries preserve their scoring path. No measured end-to-end latency claim follows.

### Production-derived evidence

Commands: `target/release/eval-binary-context /tmp/dazhbog-review-benchmark.toml
32 64 SEED transfer`. JSONL artifacts: `/tmp/dazhbog-transfer-seed1.jsonl` and
`/tmp/dazhbog-transfer-seed2.jsonl`. Both seeds were examined during development.

| Measurement | Seed 1 | Seed 2 |
|---|---:|---:|
| Successfully evaluated keys | 1,984 | 2,048 |
| Labels retrievable with full binary identity | 1,900 | 1,847 |
| Expected variants eligible after holdout | 1,089 | 1,099 |
| Exact and semantic agreements | 1,070 | 973 |
| Ambiguous eligible cases | 198 | 390 |
| Agreements among ambiguous eligible cases | 179 | 264 |
| Failed 64-key batches | 1 | 0 |

The seed-1 foreign-head batch remains an explicit failure (exit 1); seed 2 exits 0.
Of full-identity retrievable labels, 811 and 748 respectively become ineligible
after holdout. Private annotations, incomplete provenance and retrieval bounds can
all contribute; these counts do not identify their individual contributions.
Agreement among eligible cases is 1,070/1,089 = 98.3% and 973/1,099 = 88.5%, rounded
to 0.1 percentage point. These are descriptive sample fractions, with no independent
accuracy or population confidence interval implied. [S2–S4, S8, S9]

Available mismatches now include names, decoded type declarations (up to 512 Unicode
scalar values with truncation indicated), frame dimensions/member counts and ordered
metadata-key/payload-length pairs in bytes. Seed 2 exposes template instantiations
sharing a function key but differing in class type, missing type chunks, and frame
payload differences despite identical frame dimensions. It also contains stored
declarations whose class name differs from the function symbol's class. For example,
key `05f3e767ddff3fcbf066aafbb297df971` has a SwiftUI symbol but its observed type names
an appleaccountd class. This is evidence of annotation inconsistency, not proof of
which annotation is correct. Increasing exact-label agreement alone could reproduce
such inconsistencies. Raw artifacts preserve the inspected comparisons.

Validation: strict Clippy and all-target test compilation passed. Existing manifest
naming and stress-target warnings remain. 102 affected tests passed (library 41, binary selection 18, database 8,
Lumina 10, semantic matching 10, neighbors 2, startup/projection 13). Added fixtures
cover private variants before the cap, other-binary provenance, held-out prior
invariance, filtered foreign ancestry and CLI failure modes. Native macOS execution;
no independent source-label validation or cold-start claim is added by this group.
The final release `observed` rerun for seed 1 preserves 1,900/1,900 retrievable
agreements and all 323 ambiguous agreements; its existing corrupt-head batch still
fails. Evidence: `/tmp/dazhbog-observed-seed1-holdout-regression.jsonl`.

Bounded findings: **high**—observation labels contain inconsistent class/type evidence,
so exact agreement is not a correctness oracle; **high**—unavailable variants and
corrupt-head batch failure remain; **medium**—physical history and related binaries
limit holdout independence. These findings constrain interpretation and prevent a
claim that the full relevance objective is complete. Root guide and README contracts
were reconciled with selector/evaluator consumers and executable tests.
