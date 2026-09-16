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
| S7 | A clear individual observed binary match is a stronger variant signal than metadata richness or the number of weaker matching sibling binaries. | Default inferred binary priority | Many partial matches against one complete match, sparse/tied/mixed batches, unknown MD5 and weighted-scoring ablation; family-disjoint unseen-binary evaluation can falsify generalization. | Revised: complete informative coverage retains strict priority; partial-match exceptions require S12–S14 below. Known-binary retrieval is confirmed, independent accuracy unknown |

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
The nonzero exit is intentional: one batch failed during a latest/canonical diagnostic probe, and partial
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

Bounded findings: **high**—foreign-history diagnostic isolation and unavailable variant recall
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
agreements and all 323 ambiguous agreements; its existing foreign-history diagnostic batch still
fails. Evidence: `/tmp/dazhbog-observed-seed1-holdout-regression.jsonl`.

Bounded findings: **high**—observation labels contain inconsistent class/type evidence,
so exact agreement is not a correctness oracle; **high**—unavailable variants and
foreign-history diagnostic batch failure remain; **medium**—physical history and related binaries
limit holdout independence. These findings constrain interpretation and prevent a
claim that the full relevance objective is complete. Root guide and README contracts
were reconciled with selector/evaluator consumers and executable tests.

## Sixth group: distinguishing semantic evidence within binary candidates

Baseline: `9099dc2515798aa90adf9bc058c39e1272bf368c`. The prior batch anchor scorer
divided matched token weight by every candidate token, including generic ABI/frame
terms and unrelated metadata. Common terms could dominate normalization. A synthetic
batch with equally matching binary memberships selected the canonical Cobalt variant
despite an unambiguous neighboring Orchid function. That assertion failed on the
baseline and passes with distinguishing-token evidence.

### Assumption register and change surface

| ID | Assumption and basis | Dependent result | Stress test / falsification probe | Status |
|---|---|---|---|---|
| S10 | Supported terms distinguishing competing variants carry more useful batch context than terms common to those variants. Names and metadata expose subsystem/class identifiers. | New anchor scoring | Equal binary overlap with different subsystem names; common/generic-only anchors; incorrect neighboring annotations or independently labeled mixed-family batches can falsify applicability. | Retained; synthetic selection gain verified, population gain not established |
| S11 | Each qualifying anchor function should have bounded evidence mass independent of metadata verbosity. | Source normalization | Repeated terms, all token families, rich versus sparse fingerprints, source/input permutations; a labeled corpus showing consistently greater reliability of verbose sources would challenge this weighting. | Retained; numerical mass and permutation invariants verified |

Owned paths: new `src/db/anchors.rs`, `src/db/{database.rs,mod.rs}`,
`tests/binary_selection.rs`, root `AGENTS.md`, README and this report. Selection,
resource costs and regression tests are affected. Both wire paths call the changed
batch selector; encoding, shaping, synthesis policy and session behavior are unchanged.
Storage/context formats, migration, mutation, history, canonical refresh, search
projection, HTTP routing, upstreams and startup are unaffected. No database migration
is required. Original data, ignored configuration and `research/` remain unchanged.

### Algorithm and limits

The first pass retains existing source eligibility: a single binary-compatible
candidate, or a top-score margin >= 1.0. Each source's union tokens receive weight 1,
with the existing additional prototype/frame/comment/operand weights 0.5/0.35/0.25/0.2.
Generic terms use the existing shared neighbor filter. Duplicate occurrences within
a field count once; each nonempty source's weights sum to 1 after normalization.

For target i, let `E_i(t)` be aggregate source weight for token t minus source i's
own contribution. Let `D_i` contain tokens occurring in some but not all candidates
remaining after binary compatibility filtering. Remove weights <= 1e-12 to suppress
floating-point subtraction noise. With `Z_i = sum(E_i(t), t in D_i)`, compute:

```text
semantic_support(v) = sum(E_i(t), t in D_i intersect tokens(v)) / Z_i
```

If `Z_i = 0`, support is zero. Support is dimensionless in [0,1] and retains the
existing 0.75 coefficient in secondary scoring. Extra unsupported candidate tokens
do not change the numerator or denominator. Common terms cannot distinguish the
remaining candidates and contribute nothing. The normalization is relative: a lone
supported distinguishing term can yield 1.0. This is not calibrated confidence and
does not prove that an inferred anchor annotation is correct. [S10, S11]

Let T be total source token occurrences across fields, U distinct source tokens,
and C total candidate token occurrences across queried keys. Ordered accumulation
costs O(T log(U + 1)); target lookup/counting costs O(C log(U + 1)) plus hash-table
candidate scoring. Retained evidence memory is O(T + U), with O(V) eligible candidate
indices per key and per-target O(C_i) scratch. Token bytes add their actual storage
and comparison cost. No new storage reads are introduced. The existing metadata,
history and batch limits still bound the input; this is not a process memory bound.

Canonical refresh has no batch anchors. Search fingerprints and the historical
single-key replay scorer are unchanged; the latter remains unsuitable as an oracle
for serving-batch semantics. No canonical projection version change is necessary.

### Evidence and bounded findings

Four module tests cover common/generic/self exclusion, metadata dilution, duplicate
terms, field weights, unit source mass, candidate/source ordering and target position.
The integration regression exercises equal binary evidence, neighboring subsystem
support and single-key fallback to the existing canonical preference. The prior
scorer failed that behavioral assertion; the replacement passes.

Production-derived holdout comparisons retain the previous counts: seed 1 has
1,070 agreements / 1,089 eligible labels, seed 2 has 973 / 1,099. These sample totals
do not establish a corpus-wide gain. The seed-1 foreign-history diagnostic batch remains a failure.
Both samples are development evidence with the preceding label/provenance limits.

The final release commands use `target/release/eval-binary-context
/tmp/dazhbog-review-benchmark.toml 32 64 SEED transfer`. Artifacts are
`/tmp/dazhbog-anchors-seed1-transfer.jsonl` and
`/tmp/dazhbog-anchors-seed2-transfer.jsonl`. The final implementation compares
distinguishing tokens only within the binary-compatible pool; excluded variants
cannot dilute that comparison.

Validation: 107 affected tests passed (library 45, binary selection 19, database 8,
Lumina 10, semantic matching 10, neighbors 2, startup/projection 13). Strict Clippy,
all-target test compilation and the release evaluator build passed. Existing Cargo
target naming and stress-target warnings remain. Validation ran natively on macOS;
no new platform, live upstream, cold-start or independent-label claim is made.
The root guide and README were updated against the selector, private anchor module,
test assertions and final diff. Whitespace checks passed.
The final known-binary seed-2 check retains 1,847/1,847 retrievable agreements,
including all 590 ambiguous cases, with no failed batch. Evidence:
`/tmp/dazhbog-anchors-seed2-observed.jsonl`. The scorer returns zero immediately
for empty evidence, avoiding token-set allocation in the anchor-free first pass.

Bounded findings: **high**—incorrect anchor annotations can propagate contextual
errors; **medium**—strict binary priority can exclude a semantically supported variant
before secondary scoring. This group fixes a demonstrated tie-resolution defect;
it does not establish improvement on the remaining unequal-binary-evidence cases.
S1–S9 and preceding corpus/cold-start limitations remain in force.

## Seventh group: binary sensitivity with identifier corroboration

Baseline: `724178c1773e53fbdabb84b5470f33ccb9399859`. Strict primary ranking could
exclude a corroborated variant because a partial binary match received more weight
from one other key. The replacement preserves complete-coverage precedence while
allowing a bounded, independently corroborated alternative. The same code serves
wire selection and binary holdout evaluation.

### Assumption register

| ID | Assumption and basis | Dependent result | Stress test / falsification probe | Status |
|---|---|---|---|---|
| S12 | A partial binary advantage dependent on one neighboring key can be ambiguous. Sparse membership and differing build coverage motivate a deterministic sensitivity bound. | Partial-match eligibility | Exhaustively recompute single-key contributions, remove the target, vary membership degree and compare complete/partial coverage; independently labeled unseen builds can falsify usefulness. | Retained; numerical oracle and synthetic selection verified, generalization unknown |
| S13 | Coverage of every informative other key warrants strict priority over partial matches. This is coverage of retained observation lists, not every function in the executable. | Preservation of known-binary behavior | Complete match versus many partial siblings, missing/overflow membership and held-out identity; inaccurate observation lists can falsify the inference. | Retained; both known-binary samples preserve all retrievable agreements |
| S14 | Corroboration involving a name/prototype identifier is stronger identity evidence than repeated comment/operand text alone. | Gate on weaker binary candidates | Repeated “PIC mode” comments; cross-field matches in both directions; subtract target provenance and prevent borrowing another candidate's identifier status. | Retained; observed regression isolated and removed, incorrect name/type annotations remain possible |

Owned paths: `src/config/{parser.rs,types.rs}`, `src/db/{anchors.rs,database.rs,
evaluation.rs,family.rs,types.rs}`, `src/bin/eval-binary-context.rs`,
`tests/binary_selection.rs`, root `AGENTS.md`, README and this report. Affected planes
are configuration, selection, diagnostic JSON, resource costs and tests. Transport,
wire encoding, request shaping, session policy, raw mutation/history/context formats,
search projection, HTTP routing, upstreams and recovery formats remain unchanged.
No migration is required. Original data, local configuration and `research/` remain
unchanged; corpus evaluation used only the existing disposable copy.

### Rule, provenance and bounds

For target k, let m be the number of other informative distinct keys, and d_j the
complete retained binary membership count for key j. Binary b's weight is:

```text
w_b = sum(1 / d_j for j != k where b contains j) / m
h_b = max(1 / d_j for j != k where b contains j) / m
l_b = w_b                 if b covers every informative other key
      max(0, w_b - h_b)   otherwise
```

Zero informative context gives no inferred cutoff. Only binaries supporting a
retrievable last-observed or historical candidate contribute a cutoff. Let
`L = max(l_b)` over those binaries. Candidate v's strongest individual match must
meet L within absolute 1e-12 tolerance. Removing a key changes the common denominator
for all binaries, so the bound uses the original denominator for comparison.
The bound is conservative: different binaries may attain their lower values by
removing different keys. It does not assert that every admitted alternative wins
under one common deletion, nor does it estimate statistical confidence. [S12, S13]

Initial anchors still follow strict best-binary ranking. A lower-match candidate
must additionally have greater corroborated support than every strict-best candidate.
For a matched distinguishing token, the source or that candidate must contain it in
its name or decoded prototype. A source's identifier count excludes the target;
one candidate cannot borrow another candidate's identifier provenance. Names,
prototypes, frame tokens, comments and printable operands still contribute to the
ordinary semantic score. A comment can corroborate an identifier on the opposite
side; comment-only repetition cannot override stronger binary evidence. The original
best-match candidates always remain eligible. Explicit observations override these
inferred filters. [S10, S11, S14]

`scoring.binary_single_key_tolerance = true` is the default; false restores strict
binary ranking for ablation. `scoring.binary_priority = false` retains weighted
scoring without either inferred filter. Parser boundaries and the integration test
exercise these settings. `binary_priority_floor` is diagnostic and includes the
configured cutoff, before explicit-ID and corroboration constraints. The evaluator
prints both policy booleans in its sample header. Available mismatches also include
up to four comment and four printable operand samples, each limited to 128 Unicode
scalar values; raw metadata is preserved and these samples are not exhaustive.

For M total key/binary memberships and B distinct observed binaries, accumulating
each binary's coverage count and two strongest key contributions costs O(M log(B+1))
CPU and O(B) extra memory. Two contributions suffice to exclude any one target.
For K targets and C <= 64 retained inferred binaries per target, cutoff lookup costs
O(KC(log(K+1) + log(B+1) + log(D+1))), D <= 256. Identifier provenance uses O(T)
extra memory and expected O(T) hash operations for T anchor token occurrences.
Final corroboration is expected O(C_v) in candidate token occurrences, with O(V)
score scratch for V retained variants; it is skipped when no lower-match candidate
survives the cutoff. There are no extra persistent reads or writes for these rules.
Byte-string hashing/comparison additionally scales with token length. No end-to-end
latency improvement or process memory bound is claimed.

### Behavioral and corpus evidence

The synthetic partial-build fixture fails under the baseline strict selector and
passes with corroboration. Its companion neutral-context case preserves the stronger
binary despite the other variant's canonical hint. Both tolerance settings, explicit
identity, duplicates and input permutations execute. The exhaustive influence oracle
covers complete and partial membership, missing target, ties and zero-context cases.
The identifier test covers comment-only repetition, cross-field support in both
directions, candidate-specific provenance and self exclusion.

An unguarded sensitivity experiment produced 1,040 versus 1,070 agreements on seed 1
and 995 versus 973 on seed 2. A token-only guard still lost 31 agreements in seed-1
binary `0efb700dca8b82edf8dc29ff28c02025`. The inspected differences were repeated
“PIC mode” instruction comments and operand chunks, with unchanged names, types
and frame dimensions. Their token overlap supplied misleading identity evidence.
The final identifier-aware rule removes that concentrated regression without adding
a corpus-specific stopword. This rejected experiment explains the provenance gate.
Artifacts: `/tmp/dazhbog-sensitivity-unguarded-seed1.jsonl` and
`/tmp/dazhbog-sensitivity-unguarded-seed2.jsonl`.

Each release sample requests 32 binaries × 64 keys. Seed 3 was newly evaluated after
formulating the rule; its baseline used the strict configuration on the same copy.

| Transfer sample | Strict agreements | Final agreements | Eligible expected variants | Successful keys |
|---|---:|---:|---:|---:|
| Seed 1 | 1,070 | 1,070 | 1,089 | 1,984 |
| Seed 2 | 973 | 979 | 1,099 | 2,048 |
| Seed 3 | 1,113 | 1,116 | 1,179 | 2,048 |

No per-binary aggregate agreement count decreased in these final comparisons.
This is an aggregate statement; the limited example output is not a complete
per-case regression audit. Seed 2's changes occur in two binaries (+1, +5), seed 3's
in two (+2, +1). Seed 1 retains its existing failed foreign-history diagnostic batch and exit 1;
seeds 2 and 3 exit 0. Known-binary reruns preserve 1,900/1,900 and 1,847/1,847
retrievable agreements, including all 323 and 590 ambiguous cases. No independent
semantic accuracy or population confidence interval is inferred. [S2–S4, S8–S14]

Commands use `target/release/eval-binary-context /tmp/dazhbog-review-benchmark.toml
32 64 SEED MODE`; the strict seed-3 baseline substitutes
`/tmp/dazhbog-review-strict-binary.toml`, which sets only the tolerance option false
in addition to the copied data path and loopback binds. Final artifacts are
`/tmp/dazhbog-identifier-{1,2,3}-transfer.jsonl`,
`/tmp/dazhbog-identifier-{1,2}-observed.jsonl` and
`/tmp/dazhbog-identifier-strict-seed3-transfer.jsonl`.

Validation: 110 affected tests passed (library 47, binary selection 20, database 8,
Lumina 10, semantic matching 10, neighbors 2, startup/projection 13). Strict Clippy,
all-target test compilation and the release evaluator build passed. Existing Cargo
binary-name and stress-target warnings remain. Root `AGENTS.md` and README were
reconciled with runtime consumers, parser boundaries, diagnostics and the final diff.
Native macOS evidence only; live upstream/TLS and other platforms were not revalidated
because their owning code and contracts are unchanged. Whitespace checks passed.

Bounded findings: **high**—repeated annotation text can imitate semantic identity,
and incorrect names/prototypes remain a residual failure mode; **high**—unavailable
variants and foreign-history diagnostic batch failure remain; **medium**—binary holdout still
retains related builds and incomplete physical history/provenance. The full relevance
objective and cold-start verification remain open.

## Eighth implementation group: candidate availability and diagnostic isolation

Baseline `0b755ba40d106fd64780c396ead8f3344b3cf55e`; the tracked tree was clean.
Owned paths: `src/bin/storage-audit.rs`, `src/bin/eval-binary-context.rs`,
`src/db/evaluation.rs`, `tests/binary_selection.rs`, README, this report and root
`AGENTS.md`. Pre-existing `research/`, original `data/` and local configuration
were preserved. All edits used the file editing tool.

### Assumption reconciliation and change surface

| ID | Assumption / basis | Dependent result | Stress test / falsification probe | Status |
|---|---|---|---|---|
| S15 | The seed-1 error meant a corrupt head caused serving selection to fail. Earlier inference from a whole-batch evaluator error. | Earlier corruption diagnosis | Trace `497eb538454ba4dabc98e48813dc11cc` with `storage-audit --key`; compare selection with latest/canonical probes. | Falsified: valid rejected-name prefix, then a foreign link; the diagnostic abort discarded completed selection |
| S16 | Unavailable observed labels can reflect name-policy exclusion rather than absent records. Three targeted current/legacy IDs were found in raw history but rejected. | Candidate availability interpretation | Audit the listed keys and expected IDs; finding no matching raw version falsifies this explanation for that key. | Confirmed for three examples only; aggregate prevalence unknown |

S4 still qualifies all dump-derived observations. Affected planes: offline tools,
evaluation result serialization, bounded history diagnosis, tests and documentation.
Selection, mutation, persisted formats/migration, configuration, both wire protocols,
session policy, search, HTTP/UI, upstream and transport are unchanged: their owning
implementations are absent from this group's diff. Both crate roots compile.

`storage-audit CONFIG --key KEY [VERSION_ID]` reports current/legacy identity matches,
name rejection, accepted distinct variants and the precise traversal stopping point.
It reads at most 4096 records, displays at most 256 Unicode scalar values per name,
and never follows a tombstone or foreign-key record. If `R <= 4096` records contain
`B` total bytes and the largest record is `M` bytes, CPU and record I/O are O(B + R),
with O(R + M) working/output memory excluding storage-engine caches. Counted variants
precede selector caps and provenance filtering; they are not guaranteed candidates.
Writable storage handles still require an offline copy. No repair is performed.

Latest/canonical probe errors now attach to individual evaluation cases. Selection
results survive those diagnostic failures, with separate error and judged counts.
Failed probes are unjudged, not ordinary mismatches. Error examples are capped at
three keys per binary; totals remain complete. CLI exit status remains nonzero when
any diagnostic fails. Actual selector errors still fail the batch. Added per-case
bookkeeping is O(K) for K evaluated keys, without additional database reads.

### Direct corpus evidence

The audited key has 29 valid-key records rejected by the existing name policy,
followed by a foreign record at `00020000cb82c100`; head `000400143fde8700` is valid.
The audit stops at that foreign record. Earlier references to a corrupt head were
corrected above; earlier batch counts remain historical measurements.

Three unavailable-label probes all found their expected raw version, excluded by
name policy: `b8df478bebb3e493c7d8aa6bd414eb1a` (`_OUTLINED_FUNCTION_540_0`),
`8634b7fb99386a43dc85f4561b3deb33` (`__ZN3xpc6bridgeERKNS_6objectE_0`, legacy ID),
and `e584ccf5cbf6219847b240eef9f117d1`
(`__ZNK4llvm13format_objectIJiEE7snprintEPcj_0`). This is not evidence that every
unavailable label has the same cause or that these labels are correct (S2, S16).

Commands: `target/debug/eval-binary-context /tmp/dazhbog-review-benchmark.toml
32 64 1 MODE`, on the disposable copy, native macOS arm64, Rust
`1.100.0-nightly (f248f4038 2026-09-05)`. All 32 batches now produce selection results:

| Mode | Keys | Expected available | Selected exact | Ambiguous exact / available | Diagnostic failures |
|---|---:|---:|---:|---:|---|
| observed | 2048 | 1959 | 1959 | 373 / 373 | 3 latest + 3 canonical, same 3 keys |
| transfer | 2048 | 1138 | 1117 | 196 / 217 | 3 latest + 3 canonical, same 3 keys |

The previously discarded binary contributes 59 observed agreements or 47 transfer
agreements. This changes measured coverage, not ranking behavior. Both modes exit 1
with zero failed selection batches. Errors identify the foreign-history key above
and missing records for `4db07e785493f840e9ad56d9f72a5bb4` and
`0c1778c0cc3f4a66c01b3b72a8fbc985`. Each diagnostic judges 2045 labeled keys.
Artifacts: `/tmp/dazhbog-diagnostics-seed1-{observed,transfer}.jsonl` and
`/tmp/dazhbog-foreign-history-audit.json`. Retrospective/holdout limitations above apply.

Validation: 69 tests passed (47 library, 22 binary-selection integration), including
CLI exit/count assertions on corrupt ancestry, unaffected-key preservation, missing
labels, rejection, current/legacy identity probes, foreign-link/tombstone stops and
malformed hexadecimal input. The tightened hexadecimal parser received a subsequent
focused regression pass. Strict Clippy for both roots, both tools and integration
tests passed; all-target test compilation passed. Existing Cargo naming and stress
test warnings remain. Root guide and README document the changed diagnostic contract.

Bounded findings: **high**—incomplete raw histories remain unrepaired; **medium**—the
observed-label denominator includes policy-rejected names and must not be interpreted
as recoverable valid annotations. Neither blocks this diagnostic group. The full
relevance objective, independent validation and cold-start verification remain open.

## Ninth implementation group: preserve binary context in the workbench

Baseline `12fc7b2056b9b2c0c2f50a800773fb20974189c6`, tracked tree clean;
pre-existing `research/` preserved. Owned paths are `src/db/{database,types}.rs`,
`src/api/http/{handlers,router,templates}.rs`, `tests/{binary_selection,semantic_neighbors}.rs`,
`scripts/test-browser-context.mjs`, README, root guide and this report. The production
dump was not opened or changed by this group. All edits used file editing tools.

### Evidence and behavior

The previous binary function list called `get_latest` for each associated key.
Clicking a row called the unconditioned function endpoint, which used `get_canonical`.
Consequently the list and detail could each show an annotation from a different
binary, despite an exact binary identity already being available. This bypassed the
binary-aware selector improved in the earlier groups.

`get_function_in_context` now uses that selector with one key and explicit MD5;
without MD5 it retains canonical visibility. Binary function pages, detail and
neighbor seed/candidate analysis use this method. Metadata length is calculated
from selected bytes with checked u32 conversion. `SelectedVariant.ts_sec` carries
the stored donor's Unix timestamp, including when experimental synthesis is enabled.
The list and detail therefore agree on the selected annotation and its age.

Detail and neighbors accept `?md5=32_HEXADECIMAL_DIGITS`, reject duplicate/empty/
malformed context before database work, and return the requested `binary_md5`.
This field does not assert observation provenance. Unknown/stale observations keep
the serving selector's fallback. Binary pages and these selection reads execute
on the blocking pool; binary pagination checks offset multiplication for overflow.

The browser passes context from binary rows through detail and neighbor requests,
neighbor links and `#f=KEY&b=MD5` history/deep links. Global function navigation
clears it. The overview identifies the binary context and explains fallback.
Generation counters suppress stale function/binary responses and delayed search
completion during hash restoration. Neighbor request signatures include MD5.

### Assumptions, scope and complexity

No new material assumptions. S2 qualifies the use of recorded observations as the
best available identity evidence; original binary annotations remain its falsification
probe. Context identity is explicit here, so S1's single-binary batch assumption is
not needed for this path. S4 applies only to earlier corpus examples reviewed here.

Affected planes: selection callers, HTTP routing/JSON, binary function lists,
neighbor reranking/family seed, browser state, public selected-record timestamp,
tests and documentation. Raw versions, context indexes, latest/history, wire formats,
session policy, upstream forwarding, configuration and search schema are unchanged;
their owning write/serialization implementations are absent from the diff. No data
migration or search rebuild is needed. Existing callers of the neighbor-budget API
retain unconditioned semantics. All Cargo targets must compile with the added field.

Each browser key now incurs the existing bounded single-key selector cost rather
than only latest/canonical traversal. For P page keys the total selection cost is
the sum of P independent selections, without retaining cross-key candidate pools;
P <= 100 at the HTTP boundary. Each traversal reads at most 4096 records. Neighbor
work adds one seed selection and at most C candidate selections, with HTTP
C <= 96 (the offline API permits C <= 384). Search retrieval, parsing, metadata
bytes, provenance lookups and response allocation remain additional costs. No
production latency measurement or process-wide memory-bound claim is made.

### Validation and remaining findings

The HTTP/1.1 regression executes the real router over a Tokio duplex connection:
two binaries share two keys, the global annotations are newer, and the recent-version
cap is one. The binary page, detail metadata and neighbor result return the older
binary-specific annotations and donor timestamps. Unconditioned detail returns the
canonical annotation. Invalid/duplicate context yields 400, absent keys yield 404,
and a maximum-usize page with a 100-row page size yields 400 without overflow.

`node scripts/test-browser-context.mjs` compiles the shipped inline script and
executes its navigation functions with deterministic DOM/network doubles. It checks
MD5 forwarding, hash restoration, context clearing, neighbor cache identity, delayed
success/error suppression, and stale search completion. This is executable browser
logic coverage, not a full DOM rendering or screenshot verification.

85 Rust tests passed: library 47, binary selection 23, neighbors 2 and
startup/projection 13. The page-overflow assertion received a subsequent focused
pass. Strict Clippy passed for both roots and affected integration tests after
correcting an existing default-field initializer lint in the neighbor fixture.
All-target test compilation passed; existing Cargo naming and stress-test warnings
remain. Whitespace checks passed. No independent visual rendering was performed.
README and root guide now describe context-conditioned behavior and fallback.

Bounded findings: **high**—neighbor candidates are still retrieved from the canonical
search projection, so reranking cannot recover a binary-specific variant whose key
was never retrieved; **medium**—binary comparison buckets and cached coverage facets
still use global record projections and require a separate representation audit;
**medium**—some retrospective type labels contradict their stored function names,
so optimizing exact label agreement alone can reward a misleading type. None blocks
the implemented list/detail/neighbor context path. Independent semantic accuracy,
complete metadata utilization, broader corpus latency and cold startup remain open.

## Tenth implementation group: compare binary-specific annotations

Baseline `90228cb2c78867cd3998dc4ac6e9f8f5117fbe6d`; tracked tree clean,
pre-existing `research/` preserved. Owned paths: `src/db/{database,types,mod,evaluation}.rs`,
`src/engine/context_index.rs`, `src/api/http/{handlers,templates}.rs`,
`tests/binary_selection.rs`, `scripts/test-browser-context.mjs`, README, root guide
and this report. Original storage and local configurations were not changed.

### Observed failure and implementation

The old comparison selected one global latest record for a shared key. It could not
show the different annotations actually selected for the left and right binaries.
It also computed one-sided membership by subtracting two bounded key prefixes:
a shared key outside one prefix was incorrectly classified as private to the other.

Each comparison row now independently resolves both sides through the explicit-MD5
serving selector. It includes names, donor timestamps in Unix seconds, donor version
IDs, metadata richness, synthesis flags and agreement with each last observation.
Missing selections remain explicit nullable sides. Separate membership flags describe
the forward `binary_functions` tree. Compatibility name/time/richness fields use the
left selection when available, otherwise right; they do not summarize both variants.

`annotation_relation` is `same`, `different`, `unjudged` or `unavailable`. It uses the
evaluator's metadata comparator: only `VdElapsed` is ignored, unknown chunks and their
per-key multiplicity/order remain significant, and partial parses are unjudged.
Name differences also count. This measures selected annotation agreement, not binary
code equivalence or correctness of the annotations. S2 continues to qualify labels;
synthesized results never claim exact last-observation agreement.

The union of the two 8192-key prefixes remains the bounded comparison universe.
For keys missing from the opposite prefix, exact forward-tree lookups determine
membership before classification. Counts therefore describe examined keys rather
than whole-binary totals; response fields and UI state that scope. Each key/side is
resolved once and reused across buckets. Recent/richness ordering uses the maximum
of both selections with deterministic key tie-breaking. Freshest Drift includes
different shared-key annotations and genuinely one-sided examined keys; timing-only
changes and unjudged comparisons do not become shared-key drift.

Both names participate in filtering. Side-specific links retain MD5. JSON, Markdown
and CSV exports preserve the pair and its relation; the CSV column schema now has
separate names, timestamps, label agreement and richness. Comparison reads run on the
blocking pool. Storage errors propagate as HTTP 500, rather than the old summary
lookup pattern turning every error into a missing-binary 404.

### Assumptions and change surface

No new material assumptions. S2 is retained; its falsification probe remains original
binary annotations. Membership is explicitly defined by the inspected forward tree,
not inferred from prefix absence or asserted as independently verified code presence.
Reads are not an atomic snapshot across concurrent observations; reported relation
concerns the two selections obtained by the request.

Affected planes: context membership reads, selection callers/diagnostics, comparison
classification/ranking, HTTP and export schemas, browser navigation, tests and guide.
Record layout, persisted identities, context encodings, search schema, wire codecs,
mutation paths, configuration and upstream behavior are unchanged. The evaluator's
comparison helper was reused without changing its algorithm. No migration or rebuild
is required for this group. The previous context-preserving detail/neighbor path
continues through the extracted single-key selection helper.

For N examined keys (N <= 16384) and row limit L <= 100, set construction, membership
probes and key sorting cost expected O(N) lookups/space plus O(N log N) sorting.
At most 7L distinct row keys are needed across primary buckets and the 4L-key union
ranking prefix. Each has at most two bounded selections; repeated buckets reuse the
result. Sorting these rows costs O(L log L), and retained row summaries are O(L)
excluding variable-length names. Selector record reads/parsing and existing facet
scans are additional costs. The former repeated bucket scans and quadratic drift
membership checks are removed. No production latency improvement is claimed.

### Validation and bounded findings

87 Rust tests passed: library 47, binary selection 25, neighbors 2 and
startup/projection 13. New cases execute the real HTTP router, with an unrelated
global latest record and a recent-version cap of one. They verify independent side
names/timestamps, label agreement and fallback, reversal of sides, filtering by the
right name, timing-only equality, unknown-key differences, partial-parse abstention,
one-sided annotations and drift membership. A separate 8193-key fixture verifies
that a shared key omitted from the left prefix still appears as shared.

The browser harness executes rendered side click handlers and checks HTML escaping,
MD5 forwarding, and both names/statuses/timestamps in CSV and Markdown exports.
Existing navigation/deep-link/stale-response checks also pass. Strict Clippy for
both roots and affected integration tests, all-target test compilation and whitespace
checks passed. Existing Cargo naming and stress-test warnings remain. Full browser
rendering and production comparison latency were not measured.

Bounded findings: **high**—coverage facets still summarize global annotations and
use an unversioned 64 B cache (eight little-endian u64 fields); per-binary observation
invalidation does not establish freshness for global records changed by another
binary. Replacing that meaning needs explicit cache-format/version and invalidation
work. The comparison UI identifies the existing coverage meaning. **Medium**—bounded
prefixes and row samples cannot establish whole-binary annotation agreement.
Neither invalidates the explicitly scoped pair comparison. Independent relevance
validation, metadata utilization, neighbor recall and cold-start verification remain
part of the active objective.

## Eleventh implementation: binary-selected coverage and bounded cache coherence

### Acceptance and behavior

Coverage now uses the same explicit-MD5 single-key selector as binary detail and
comparison. `function_count` is the examined-key denominator, including unavailable
records. `key_limit` is clamped to 8192, including a valid zero limit; an extra key
probe sets `truncated`. `unavailable_functions` counts absent selections and
`fallback_functions` counts available selections that do not exactly match the last
observation (including synthesis). Extra comments now contribute to comment coverage.
`BinarySummary.coverage` carries these fields; existing scalar counts are retained.
The UI preserves zero counts, uses the examined denominator and labels absent coverage.
Binary search attaches cached coverage only, avoiding thousands of extra selections
per search result. Opening a binary computes coverage on demand. Search badges state
the examined denominator or explicitly identify coverage as not computed.
Binary-key enumeration now returns `InvalidData` for malformed membership key lengths
inside the examined prefix; skipping them could falsely imply prefix exhaustion.

The previous eight-u64 persistent cache had neither selection-policy identity nor
complete mutation invalidation. It is replaced by a 64-entry process-local LRU cache,
with exact per-entry limits and up to 8192 key dependencies. Old `binary_facets` values
are ignored and preserved byte-for-byte. Reopening starts empty, including after
scoring configuration changes. No record/context encoding migration, search rebuild
or startup scan is introduced. The unsafe public facet setter is removed; internal
publication requires the read generation and examined keys.

Push/delete guards cover each full item mutation, including context-free pushes,
duplicate observations and errors. Direct context metadata, observation and canonical
setters are guarded too. A mutation invalidates affected entries, advances a generation
and increments the active-writer count. Publication is allowed only with the original
generation and no active writer. Nested writers are supported; RAII releases counts
on error. Counter exhaustion disables caching until restart. Unaffected existing
entries remain usable during unrelated mutations. A concurrent request may return
non-atomic observations but cannot retain an overlapping calculation in the cache.

### Assumption register and change surface

No new unverified material assumptions. Cache dependency closure was checked against
`select_binary_variant`, `select_batch`, `score_candidate` and the context setters:
single-key family evidence excludes that key, no other-key anchors exist, metadata
hints are absent, and recency is normalized across stored timestamps rather than wall
time. The runtime is private to Database's module; external raw EngineRuntime writes
do not share an open Database runtime. A future selector dependency change must extend
invalidation. Falsification probes are the cross-binary mutation and direct-setter
tests plus inspection for new selector reads. S2 still qualifies last-observation
agreement: it is not independently established ground truth.

Affected: selection callers, mutation invalidation, context cache ownership, resource
bounds, HTTP JSON/UI, tests, guide and documentation. Unaffected: selection scoring,
wire framing/codecs, session/upstream behavior, record/history/address encodings,
search schema and startup preparation. Legacy recovery remains compatible because
primary data are unchanged and coverage is derived lazily. The old context facet
setter's Rust API removal is intentional; all repository callers were replaced.

For K examined keys (K <= 8192), a miss costs K bounded selections plus one prefix
probe, retaining O(K) dependencies and one selected record at a time. Cache hits cost
O(C) LRU bookkeeping, C <= 64; mutation invalidation costs expected O(C) hash probes.
Evicting or invalidating D entries additionally releases up to O(DK) dependencies.
Persistent coverage writes are eliminated. Stored dependency key payload is bounded
by 64 × 8192 × 16 B = 8 MiB; hash tables, names, selected metadata and allocator
overhead are additional. This is not a process memory bound. Requests are not
coalesced: simultaneous misses can duplicate selector work.

### Validation and bounded findings

The integration regression exercises two different annotations for one shared key,
extra-comment coverage, zero/exact/oversized limits, new membership, duplicate
observation, context-free reinsertion, deletion, summary projection and reopening
with a deliberately invalid legacy cache value. Cache tests cover dependency and
binary invalidation, nested writers, stale publication, error exit, LRU capacity,
oversized dependencies and generation exhaustion. Direct context setters are tested
separately. The browser harness checks absent coverage, sampled denominators and zero
overrides. Binary search tests distinguish cold-cache and populated-cache projections.

Validation: 92 Rust tests passed (library 51, binary selection 26, neighbors 2,
startup/projection 13). The final malformed-membership boundary passed a focused
10-test engine rerun. All-target test compilation and the browser harness passed;
the server target compiled and has no independently duplicated engine unit tests.
Existing Cargo binary-naming and stress-test warnings remain. Final strict Clippy
for the library, server and binary-selection integration target passed, as did the
focused search/coverage regression, browser harness and whitespace checks.

Bounded findings: **medium**—uncached coverage now performs actual bounded selection
instead of one latest-record read per key, so first-request latency can increase;
production coverage latency is unknown. **Medium**—concurrent cache misses can repeat
work, and mutation publication fences do not provide a cross-store snapshot. These
limits are explicit and do not invalidate the cache contract. The high-impact global
coverage/stale-cache finding in implementation ten is addressed by this group.
Independent relevance validation, additional metadata utilization, neighbor retrieval
recall and cold-start verification remain part of the active objective.

## Twelfth implementation: identifier components with separate evidence strength

### Mechanism and acceptance

The previous tokenizer preserved underscores and lowercased whole words. Consequently,
`http_read_header` and `HttpDecodeHeader` supplied no common batch tokens. A transient
batch fingerprint now preserves whole tokens and adds components at ASCII separators,
lowercase-to-uppercase boundaries, and acronym suffix boundaries (`HTTPReader`). It
uses names and demangled names, decoded prototypes, frame names/types/comments,
function/instruction/extra comments, and printable operand/stack-point metadata.
Generic tokens are excluded before and after splitting; prefix-sensitive compiler
syntax such as `__customcall` and `__m128` cannot become new evidence after splitting.

`scoring.batch_identifier_components` defaults true and is consumed only when the
deduplicated batch has more than one key. Source eligibility, one-unit source mass,
leave-one-key-out evidence and contrastive candidate normalization remain in force.
Expanded evidence contributes to secondary ranking. A separate original-token anchor
accumulator supplies the existing corroboration required to relax inferred binary
priority. Components alone cannot cross that boundary. Explicit observed identity
retains precedence, and disabling the setting restores the original batch evidence.
Canonical quality/consistency, persisted search tokens, neighbor retrieval and the
older replay scorer retain their original fingerprints. No persisted encoding,
search schema, migration or startup scan changes.

The evaluator accepts a final `--all-cases` argument and emits every case in a
`cases` array (null when disabled), while retaining its bounded diagnostic examples.
This permits paired analysis by binary MD5 and key instead of assuming aggregate
gains imply no regressions. The sample record reports the option and selection policy.

### Assumption register and scope

| ID | Assumption | Basis and dependent result | Stress test / falsification probe | Status |
|---|---|---|---|---|
| S17 | Lexical identifier components can carry useful cross-function evidence | Observed tokenization gap; transient ranking expansion | Cross-style controlled fixture; paired transfer decisions with components disabled/enabled | Confirmed for fixture; broader accuracy remains unknown |
| S18 | Components are insufficient by themselves to relax binary priority | Initial trial selected an unrelated `RBX::Mesh` destructor over `HdMeshEdgeIndexTable` | Component-only partial-priority fixture and seed-1 case `4e453e97ff33bbd0bf42d0fcf632f48b` | Confirmed counterexample; whole-token guard retained |

S2 (observation labels are proxies), S4 (non-atomic copied dump), and S9 (holdout is
not family-disjoint) remain retained. A better match to these labels does not establish
semantic truth. Original binary/source annotations remain the falsification probe.

Affected planes: parsed configuration/defaults/runtime consumer, transient selection
evidence and resource use, evaluator JSON/CLI, tests, guide and documentation.
Unchanged: wire codecs, request shaping, record/history identity, canonical/search
projection, mutation/cache dependencies, HTTP schemas, upstream/session behavior,
recovery and startup. Both protocol handlers already use the changed serving selector.
Single-key coverage/detail has no component expansion, preserving its cache dependency
contract. All edits used file-editing tools; original data and research were preserved.

For T source-text bytes and U emitted tokens across retained candidate versions,
component scanning costs O(T); token sorting/deduplication costs O(U log U) string
comparisons, plus the pre-existing demangler cost. Additional retained token payload
and anchor maps are O(T + U), excluding allocator overhead. Record I/O counts and
history caps are unchanged. The original and expanded anchor accumulators each retain
one normalized source contribution per eligible function. No production memory or
latency bound is inferred from these asymptotic statements.

### Paired corpus evidence

Each seed samples 32 binary batches × 64 keys = 2048 cases from the disposable dump
copy. The baseline is revision `0f1d4b19` with the all-case diagnostic addition;
the final selector preserves whole-token priority corroboration. All cases were
evaluated; decision pairs were retained for every ambiguous case with an available
reference. Seeds may overlap, so their sum is not an independent sample size.

| Seed | Available reference | Baseline exact | Final exact | Paired ambiguous cases | Correct→incorrect | Incorrect→correct |
|---|---:|---:|---:|---:|---:|---:|
| 1 | 1138 | 1117 | 1117 | 217 | 0 | 0 |
| 2 | 1099 | 979 | 980 | 390 | 0 | 1 |
| 3 | 1179 | 1116 | 1116 | 289 | 0 | 0 |

The 896 ambiguous pairs contain two changed decisions: one newly matches its
observation and one remains incorrect. The corrected case is binary
`00d9315521c86a0c2bb6e8c21c4610e7`, key `3690d5235a9d99a61c8c7ccec7df46f8`:
the selected name changes from a nlohmann output-string-adapter reference-count
destructor to the observed exception-pointer reference-count destructor. The two
records each contain 26 B of metadata. This is one label-agreement improvement,
not evidence of a large general accuracy gain. The still-incorrect case is binary
`c1c75d87b6efce9cf06ae2f6916cc1f7`, key `c17db2b52e5f5b6a19536ca4ed913456`;
it retains the function name but chooses different annotation bytes.

An initial trial allowed components to corroborate relaxed binary priority. It lost
one correct seed-1 case and gained three seed-2 cases. That mechanism was rejected
after inspecting the destructor mismatch, rather than accepting its net aggregate
gain. The final split between whole-token corroboration and component ranking removes
that observed regression. Seed 1 still reports three latest and three canonical
diagnostic failures already identified in implementation eight; all selection batches
completed. Seeds 2 and 3 report no diagnostic failures.

Counts and both changed version identities are stored in
[identifier-component-evaluation.json](identifier-component-evaluation.json).
Per-seed baseline/final ambiguous decision records are also saved locally as
`/tmp/dazhbog-{baseline,components}-seed{1,2,3}-transfer-pairs.json`.
Reproduce with `eval-binary-context CONFIG 32 64 SEED transfer --all-cases` and compare
`scoring.batch_identifier_components = false` versus true on the same offline copy.
The disabled-option seed-2 rerun reproduced the baseline counts and all 390 ambiguous
decisions exactly, verifying the ablation switch against the previous implementation.

Validation: 103 Rust tests passed (library 53, binary selection 27, semantic matching
10, startup/projection 13). They cover cross-style resolution, ablation, explicit
identity, duplicates/permutation, whole-token versus component-only binary priority,
all metadata source families, compiler-prefix exclusions, untouched original search
fingerprints, all-case CLI output and existing persistence/visibility contracts.
Strict Clippy passed for the library, server, evaluator and selection integration test.
All-target test compilation and whitespace checks passed. Existing Cargo naming and
stress-test warnings remain. No original production-dump repair or rewrite was made.

Bounded findings: **medium**—ASCII boundaries do not recover every identifier's lexical
structure (for example, unconventional acronym casing), and shared components may
still misrank equally supported variants. **Medium**—batch fingerprints and a second
anchor accumulator add CPU/allocation cost; production impact is unmeasured.
**High, unresolved objective**—independent, family-disjoint relevance labels and broader
metadata exploitation remain necessary to establish general accuracy. Neighbor recall
and cold-start verification also remain open. These limits are not completion claims.

## Thirteenth implementation: canonical candidate continuity and availability audit

### Confirmed defects and resulting behavior

Canonical refresh previously collected only the most recent configured number of
variants. A better incumbent could therefore disappear from consideration after
enough weaker submissions, even though it remained live and retrievable. A controlled
fixture with a two-variant cap reproduces that loss after the second later submission;
all later names are accepted and push status is checked. Refresh now targets the
incumbent ID as well as recent variants. It receives no incumbent score bonus: normal
scoring can replace it with a better new annotation. The fixture verifies retention,
replacement, search projection, restart and delete/reinsert isolation.

Serving selection also read canonical hints only after bounded collection. A hint
outside the recent window could never affect the result. Hints now participate in
targeted retrieval before scoring. The test exercises current and historical version
IDs with a one-variant cap and verifies that explicit binary identity still wins.
Transfer evaluation continues to omit canonical hints from retrieval and scoring;
the held-out binary's global canonical choice must not supply evidence.

Both changes reuse existing validated history traversal: rejected names, tombstones,
wrong-key ancestry, cycles and the 4096-record bound retain their existing contracts.
They add at most one canonical target. They introduce no record/context encoding,
search schema or migration change. Already-forgotten choices are not reconstructed.

### Availability diagnostics

The evaluator previously reported reference absence without distinguishing retrieval
limits from missing positive provenance. It now probes absence only after selection:

| `candidate_absence` | Meaning |
|---|---|
| `unlabeled` | No nonzero last-observation ID exists for this key/binary |
| `identity_probe_unavailable` | The explicit-identity probe did not recover the reference within its serving bounds |
| `reachable_but_not_retrieved` | Observed-mode selection omitted a reference recovered by explicit identity |
| `shared_but_not_retrieved` | Transfer omitted a recovered reference with positive recorded provenance in another binary |
| `sharing_not_proven` | The bounded provenance checks found no positive evidence in another binary |
| `membership_scan_limit` | Complete key memberships exceed the probe's 257-entry bound and version summaries did not prove sharing |

Available references have no absence reason. The probe checks both version-ID aliases,
positive version-summary observations and per-binary last/historical observations.
It follows the existing transfer provenance criterion. Absence of evidence is never
reported as proof of privacy. I/O or malformed-value errors become `availability_error`
without discarding successful selections; the CLI counts them, includes examples,
and exits unsuccessfully. Its policy record now includes `max_versions_per_key`.

### Assumption register and change surface

| ID | Assumption | Basis / dependent result | Stress test and falsification probe | Status |
|---|---|---|---|---|
| S19 | A better incumbent can be lost solely through recent-window eviction | Inspected refresh collector; canonical-continuity fix | Accepted lower-quality pushes under a two-variant cap; failed before and passed after; better replacement and tombstone probes | Confirmed |
| S20 | Increasing the recent cap substantially improves sampled reference availability | Candidate retrieval audit hypothesis | Same 32 × 64 transfer samples with caps 16 and 64, seeds 1 and 2 | Falsified for these samples; general effect unknown |

S2 (proxy labels), S3 (absence is not incompatibility), S4 (non-atomic dump copy) and
S9 (not family-disjoint) remain retained. The availability probe describes recorded
provenance and bounded retrieval, not independent evidence about original executable
contents. Its predicates are covered by current/legacy identity fixtures and a
malformed historical-membership fixture that preserves successful selection output.

Affected planes: canonical refresh/candidate discovery, search-update input,
evaluation CLI/JSON, tests and documentation. Scoring weights/default cap, wire
codecs, request shaping, metadata fingerprints, session/upstream policy, persistent
encodings, startup preparation and cache invalidation dependencies are unchanged.
Existing push/context/canonical guards already invalidate key-dependent coverage.
Refresh remains part of a multi-store mutation, not an atomic transaction; errors
after append/index/context updates can leave partial state as before.

For R visited history records, traversal remains O(min(R, 4096)) record reads and
visited-address storage. An older incumbent can increase actual reads beyond the
recent cap; retained analyzed candidates increase by at most one. Its validation
must not be replaced by an unchecked address lookup. A provenance diagnostic loads
two version summaries, scans at most 258 membership rows to detect overflow, and
performs at most three lookups per retained other binary. This adds bounded evaluation
work, not serving work. No production latency improvement is claimed.

### Corpus results and validation

The observed-mode before/after comparison pairs all 2048 seed-1 cases. Every selected
version and candidate count is unchanged: 1959 available references and 1959 exact
matches. The canonical fixes address demonstrated lifecycle gaps without changing
this snapshot's sampled answers. The original dump was not modified; tests use
disposable fixtures and corpus probes use the existing disposable copy.

| Transfer seed | Cap-16 available / exact | Cap-64 available / exact | Identity probe unavailable | Sharing not proven | Membership limit | Proven shared retrieval miss |
|---|---:|---:|---:|---:|---:|---:|
| 1 | 1138 / 1117 | 1138 / 1117 | 89 | 820 | 1 | 0 |
| 2 | 1099 / 980 | 1099 / 980 | 201 | 748 | 0 | 0 |

Each row covers 2048 cases. The absence counts reconcile exactly:
1138 + 89 + 820 + 1 = 2048 and 1099 + 201 + 748 = 2048.
Increasing the cap produced no aggregate availability or exact-match improvement in
these two samples. The default remains 16. No availability probe failed; seed 1 retains
the previously diagnosed three latest and three canonical errors, with zero failed
selection batches. Seed 2 has no diagnostic failures. Seeds can overlap; these are
not independent accuracy samples.

[candidate-retrieval-evaluation.json](candidate-retrieval-evaluation.json) records the
counts and observed-mode pairing result. Full observed decision vectors are saved
locally in `/tmp/dazhbog-canonical-{before,after}-seed1-observed.json`.
Commands use `target/debug/eval-binary-context CONFIG 32 64 SEED MODE --all-cases`;
the cap-64 config points to the same offline copy and changes only
`scoring.max_versions_per_key = 64`. Compare both candidate availability and errors.

106 Rust tests passed (library 53, binary selection 30, semantic matching 10,
startup/projection 13). Additional focused reruns verify all six absence reasons,
legacy provenance and isolated malformed-membership diagnostics. Strict Clippy passed
for the library, server, evaluator and selection integration target.
The final focused diagnostic test also verifies a nonzero CLI exit caused solely by
availability errors, with zero failed selection batches and zero latest/canonical
errors. All-target test compilation and whitespace checks passed; existing Cargo
naming and stress-test warnings remain.

Bounded findings: **medium**—preserving a much older incumbent can increase per-push
history work up to the existing bound; production latency is unmeasured. **Medium**—
the current dump can already contain lost canonical choices, incomplete provenance
and broken ancestry; this change does not repair them. **High, unresolved objective**—
independent relevance labels and further metadata-informed ranking remain needed.
Neighbor recall and cold-start verification remain open.

## Fourteenth implementation: consensus from ambiguous source variants

### Evidence gap and implementation

An initial batch source previously contributed no semantic evidence unless its
binary-compatible pool had one candidate or its highest score led by at least 1.0.
This discards invariant evidence together with the uncertain parts of an annotation.
For example, `OrchidSession::openLeft` and `OrchidSession::openRight` both identify
the subsystem even when neither complete annotation is preferred decisively.
The new integration fixture failed before implementation: a neighboring ambiguous
target selected `CobaltSession::parseHeaders`. It now selects the Orchid variant.

`scoring.batch_consensus_anchors` defaults true and supports false for ablation.
For a source lacking a decisive variant, the selector intersects fingerprints from
its eligible variants after initial strict binary-priority filtering. It intersects
name, prototype, frame, comment and operand families separately, as well as the
aggregate token set. A token present in one variant's name and another's comment
does not acquire shared name provenance. Original whole-token and expanded component
fingerprints remain separate; only the former can supply priority corroboration.

The consensus passes through the same generic filter, per-source mass normalization,
target exclusion and distinguishing-token selection as decisive sources. It never
chooses a source variant or constructs a response. Explicit binary identity,
complete-match priority, the one-key sensitivity cutoff and raw name/payload pairing
retain their contracts. A one-key request cannot use its own consensus as evidence.
No additional history/context reads, stored fields, search projection or migration
are introduced. The CLI records the new boolean in its selection policy.

### Assumption register and change surface

| ID | Assumption | Basis / dependent result | Stress test and falsification probe | Status |
|---|---|---|---|---|
| S21 | Ambiguous source variants can share useful distinguishing evidence | Inspected source-margin gate; consensus fallback | `ambiguous_sources_supply_only_shared_batch_evidence` fails before the change and passes after; disabled option restores the earlier choice | Confirmed for the controlled fixture |
| S22 | Invariant tokens identify the appropriate subsystem outside controlled fixtures | Lexical intersection is weaker than independent executable semantics; default consensus policy | Paired transfer evaluation, family-disjoint labels and contradictory shared boilerplate; a correct-to-incorrect selection falsifies improvement for that case | Retained; general accuracy gain unknown |

S2 (observation labels), S3 (missing evidence), S4 (copied dump) and S9 (not
family-disjoint) still apply to corpus conclusions. Uncertainty shared by every
candidate remains uncertainty; intersection does not validate the annotations.

Affected: scoring configuration/parser, initial semantic-anchor construction,
evaluation policy output, regression tests, README and AGENTS contracts. Both wire
handlers consume the batch selector; their codecs, request/result ordering and
shaping are unchanged. Mutation/history/identity/recovery encodings, canonical
refresh, search reconstruction, HTTP/UI schemas and upstream/session policy are
unchanged. The new fingerprint is local to one request; there is no new shared
cache, synchronization or startup operation.

For K distinct requested keys, at most V considered source variants per key and
at most T token occurrences per fingerprint (counting field copies), intersections
take expected O(KVT) token hash/equality operations and O(T) temporary auxiliary
storage while processing a source. Token-byte hashing is proportional to token
length. The two representations add a constant factor. Existing anchor storage can
now retain consensus tokens for formerly omitted sources, up to O(KT) tokens.
No throughput or memory-reduction claim follows from these bounds.

### Behavioral validation

`cargo test --lib --test binary_selection --test semantic_matching --test startup_projection`
passed 109 tests: 55 library, 31 selection, 10 semantic and 13 startup/projection.
The new cases cover the original failure, disabled-option behavior, input permutation,
duplicate keys, explicit identity, self-exclusion, field provenance, prototype/frame/
comment/operand evidence, generic filtering and per-source mass. Existing tests retain
strict complete-binary precedence and holdout isolation coverage.
Strict Clippy passed for the library, server, evaluator and selection test;
all-target test compilation passed. Existing Cargo naming and stress-test warnings
remain. This task does not claim live-protocol, deployment or cold-start measurements.

The exact owned paths are `src/db/anchors.rs`, `src/db/database.rs`,
`src/config/types.rs`, `src/config/parser.rs`, `src/bin/eval-binary-context.rs`,
`tests/binary_selection.rs`, `README.md`, `AGENTS.md`, this report and its
`consensus-anchor-evaluation.json` companion. Baseline: `651f70739f70b4586bdce1feeb240bf581fbd0c8`.
Original `data/`, local configuration and untracked `research/` remain preserved.

### Corpus comparison and bounded findings

All runs use the prepared disposable copy, 32 binaries and 64 keys per binary,
transfer mode, identifier components enabled and the default recent-variant cap.
Consensus is the only new selection policy. Seed 4 was evaluated after the
implementation and was not used to tune it. These are retrospective observation
labels, not independently verified semantic truth [S2, S4, S9, S22].

| Seed | Available references | Exact matches, before → after | Ambiguous available | Paired scope | Changed selections |
|---|---:|---:|---:|---|---:|
| 1 | 1138 | 1117 → 1117 | 217 | 217 ambiguous available cases | 0 |
| 2 | 1099 | 980 → 980 | 390 | All 2048 cases | 0 |
| 3 | 1179 | 1116 → 1116 | 289 | 289 ambiguous available cases | 0 |
| 4 | 1047 | 959 → 959 | 258 | All 2048 cases | 0 |

The first three rows cover 217 + 390 + 289 = 896 ambiguous available cases.
Including seed 4 gives 1154 such case occurrences, not necessarily distinct keys
or independent binaries. Seed 1 retains three latest and three canonical diagnostic
errors; every row has zero failed selection batches and zero availability errors.
There is **no measured corpus accuracy gain** in these samples. The demonstrated
gain is the controlled ability to use invariant metadata from an ambiguous source.
Enabling consensus preserves these sampled choices while covering that omitted
evidence path; its broader effect remains unknown [S22].

[consensus-anchor-evaluation.json](consensus-anchor-evaluation.json) records policies,
counts and pairing scope. Seeds 1 and 3 pair against the prior saved component
evaluation; the intervening canonical-continuity change is suppressed in transfer
mode. Seed 2 has a fresh pre-change baseline. Seed 4 compares the same implementation
with `scoring.batch_consensus_anchors` false and true. Local paired vectors are in
`/tmp/dazhbog-consensus-{baseline,candidate}-seed{2,4}.json`; candidate vectors for
seeds 1 and 3 accompany the earlier `/tmp/dazhbog-components-seed{1,3}-transfer-pairs.json`.

Bounded findings: **medium**—shared incorrect annotations or common terminology
can still provide misleading evidence; consensus is not verification. **Medium**—
more source fingerprints add request-time CPU and retained anchor tokens; production
latency is unmeasured. **High, unresolved objective**—general accuracy improvement
still needs independently judged, family-disjoint evaluation and further work on
metadata-informed binary selection. Neighbor recall and cold-start verification
remain open. No full-objective completion claim is made.

## Fifteenth implementation: exact membership within the selected neighbor family

### Confirmed defect and resulting behavior

Neighbor reranking previously called `get_binary_refs_for_key(candidate, 8)` and
`family_support_rationale` examined at most those eight records. The context method
takes the first eight available metadata records in MD5-key order, then sorts that
prefix; it does not return an exhaustive or globally most-observed membership set.
A candidate's membership in the explicitly requested binary could therefore be
omitted. Its direct-family score became zero, and strict-family filtering could
remove it despite successful lexical retrieval.

The regression constructs an explicitly requested binary with MD5 `ff...ff`, a
candidate shared with eight earlier MD5s, and twelve closer siblings that exhaust
related-family discovery. Search retrieves the candidate, but the old prefix path
drops it. The corrected path probes membership in the selected family directly and
retains it. A controlled reintroduction of the prefix lookup reproduced the failure
with the final, valid metadata fixture.

The family already contains at most four direct binaries and twelve related binaries
per direct binary. Their metadata is now pooled per request, sorted by support and
MD5, and reused across candidates. Each candidate receives targeted `key_md5` probes
for those IDs. Positive observation counts establish recorded key membership.
Strict-family nonmembers are excluded before candidate decoding. The rationale uses
all matching family members when computing its maxima; its three examples per
category remain a presentation limit. Candidate retrieval and score weights are
unchanged. This repairs family evidence among retrieved candidates; it does not
recover a candidate absent from the canonical search index.

### Contextual evaluation and fixture correction

`eval-neighbors` label cases now accept optional `binary_md5` and `strict_family`.
The MD5 must contain exactly 32 hexadecimal digits; omission preserves canonical
selection, and strictness defaults false. Duplicate key/context pairs are rejected
after decoding the identity, while the same shared key can have distinct cases for
different binaries. Existing family/partition separation still applies. Reports
include request context plus candidate and returned key lists, so metrics can be
audited against the actual contextual neighbor path.

The existing `tests/semantic_neighbors.rs` metadata helper used fixed-width little-
endian headers, whereas the owning parser reads packed integers. Consequently its
comments were not being decoded as intended. The helper now builds a packed comment
chunk and asserts complete parsing, no errors and the exact comment. No production
metadata decoder changed. The CLI fixture uses replay opening to avoid retaining its
database through global metrics before the subprocess opens it; storage handles are
released before that subprocess runs.

### Assumption register and scope

| ID | Assumption | Basis / dependent result | Stress test and falsification probe | Status |
|---|---|---|---|---|
| S23 | The candidate's first eight references need not include the requested family | `ContextIndex::get_binary_refs_for_key`; targeted membership fix | Eight preceding MD5s and twelve closer siblings; prefix reintroduction drops a retrieved direct-family candidate | Confirmed |
| S24 | Positive `key_md5` observations are usable recorded membership evidence | Existing serving identity/context contract; neighbor family score | Same basename and same parsed comment in an isolated binary must not create family support; missing observations remain unsupported | Retained as recorded provenance, not independent semantic truth |

Affected planes: neighbor family scoring/filtering/explanations, evaluation input
and output, tests, README and AGENTS contracts. HTTP already calls the contextual
neighbor method; its routes and JSON schema are unchanged. The two binary wire
codecs, pull selection, synthesis, upstream/session policy, mutation ordering,
history, persisted identity, recovery, startup and search schema/reconstruction are
unchanged. No migration or data rewrite is required. Request-local metadata pooling
adds no shared cache or invalidation contract.

Let C be retrieved candidates, F unique selected-family IDs, and S the total pooled
binary-metadata bytes. The new membership phase performs F metadata lookups plus
CF point lookups and O(F log F) ordering, with O(S + F) extra request memory. Here
C ≤ 384 and F ≤ 4(1 + 12) = 52, giving at most 19,968 membership probes; explicit
identity uses at most 13 IDs and 4,992 probes. These bounds describe the added phase.
Existing family discovery can scan up to 4096 seed keys and their memberships;
it is not bounded by CF. No latency improvement is claimed.

The owned files are `src/db/database.rs`, `src/bin/eval-neighbors.rs`,
`tests/semantic_neighbors.rs`, `README.md`, `AGENTS.md` and this report. Baseline:
`5e94383352d5de16db8539492ed4c80f37d7cafd`. Original `data/`, ignored configuration
and untracked `research/` were preserved. No production-copy evaluation was used
to claim general neighbor accuracy for this change.

Bounded findings: **high, unresolved objective**—retrieval still indexes canonical
annotations and can omit binary-specific semantic neighbors before reranking.
**Medium**—seed-family discovery and overlap caches retain their existing limits;
the new membership probes establish completeness only within that chosen family.
**Medium**—missing or malformed observations are unsupported under the existing
decoder contract, not proof of absence. Independent relevance labels, broader
metadata-informed matching and cold-start verification remain open.

### Validation and requirement coverage

`cargo test --lib --bin eval-neighbors --test semantic_neighbors --test binary_selection --test semantic_matching --test startup_projection`
passed 115 tests: 55 library, 3 evaluator, 3 neighbors, 31 binary selection,
10 semantic matching and 13 startup/projection. A final focused rerun of the six
neighbor/evaluator tests passed after strengthening the CLI fixture to use the
same seed key under all three binary IDs. Its nine reports cover direct, related
and unrelated contexts at candidate budgets 96, 192 and 384; dropping context from
the CLI dispatch would fail the unrelated-context assertion.

The regression checks lexical retrieval separately from strict-family retention,
direct and related rationale IDs beyond the eight-entry prefix, canonical seed
mode, explicit context, absence of family support despite identical basenames and
comments, and non-strict lexical eligibility. Evaluator tests cover old-label
compatibility, malformed MD5s, normalized duplicate identity, distinct binary
contexts and family partition separation. Metadata fixtures assert complete
decoding rather than relying on incidental name or family matches.

Strict Clippy passed for the library, server, evaluator and neighbor tests;
all-target test compilation, source-format and whitespace checks passed. Existing
Cargo naming and stress-test warnings remain. No live endpoint, full production
neighbor corpus, cross-platform execution or cold-start test was run for this
group; no such result is claimed. AGENTS and README were checked against the
membership loop, family bounds, CLI parser/dispatcher and executed fixtures.

## Sixteenth implementation group: positive observation evidence

Baseline: `2820f9d8313d0ee95ac7a9ae8f7eb04aead66b9b`. Owned paths:
`src/engine/context_index.rs`, `src/db/database.rs`, `src/db/evaluation.rs`,
`tests/binary_selection.rs`, `AGENTS.md`, `README.md` and this report.

### Defect and correction

Batch membership discovery read `key_md5` identities without decoding observation
counts. Explicit selection and evaluation accepted a zero-count row's last-version
pointer; alias-summary membership checks likewise accepted zero-count entries.
The new integration fixture reproduced selection of an old annotation solely from
such a pointer. Filtering the serving reads initially failed to fix it: offline
preparation had copied that pointer into `binary_versions`, manufacturing historical
evidence. Preparation now skips zero-count rows for reverse-index/history population.

Serving and evaluation use one positive-observation accessor, while the raw public
accessor preserves stored values. Alias unions retain only positive memberships.
Bounded family enumeration decodes each value, rejects malformed values within its
scan budget, and counts zero rows toward the physical-row budget. A bound exceeded
by placeholders causes abstention rather than unbounded scanning or partial votes.
Independent historical entries, including a valid timestamp of zero seconds, remain
usable; raw records and observation rows are not rewritten.

Overlap and related-binary aggregation require positive counts on both sides,
including verification of seed keys obtained from old reverse indexes. Streaming
observation enumeration no longer visits zero-count rows. Old cached overlap counts
must consequently be recomputed. Cache values now contain ASCII `DOV2`, an unsigned
one-byte entry count n, and n entries of 16 B MD5 plus unsigned 64-bit little-endian
shared-function count. Their exact length is `5 + 24n B`, with `0 <= n <= 255`.
The maximum is `5 + 24(255) = 6125 B`. Valid old values have length `1 + 24n B`,
so exact-length validation prevents accidental interpretation as a new value.
Old or malformed cache values become misses and rebuild lazily on request. There
is no startup scan, destructive migration, or change to primary record encoding.

### Assumption register and change surface

| ID | Assumption | Basis / dependent result | Stress test and falsification probe | Status |
|---|---|---|---|---|
| S25 | A stored count of zero does not establish an observation | Count semantics and the existing positive-evidence contract; identity, inference, labels and overlap filtering | Raw zero rows with valid last IDs, zero alias summaries, stale reverse rows and legacy overlap caches; `cargo test --test binary_selection zero_count_observations` | Confirmed by controlled fixtures; frequency in the original dump is unknown |
| S26 | Existing independently persisted history must survive a zero current count | Historical membership has no provenance discriminator for earlier preparation; preservation decision | Insert an eight-byte timestamp-zero history entry, prepare, then assert it remains usable; context selection unit tests | Retained; the format cannot distinguish independent history from prior erroneous promotion |

Affected planes: selection, inferred identity, candidate retrieval, evaluation labels,
HTTP coverage/comparison/family values, derived overlap cache encoding, offline
preparation, tests and documentation. Mutation ordering, raw history traversal,
canonical pointer storage, search schema and reconstruction, both wire codecs,
transport, session/upstream policy, configuration syntax and metadata synthesis
encoding are unchanged. Existing readers handle the dump's primary records without
a migration. Old derived caches are intentionally ignored. No new concurrent state
or lock is introduced; overlap cache publication retains its existing concurrency
contract. The original `data/`, local ignored configuration and `research/` remain
untouched; corpus runs use the existing disposable copy.

For a bounded membership scan with R physical rows and limit L, at most
`min(R, L + 1)` rows are read; at most L fixed-size values are decoded. CPU and
temporary memory are O(min(R, L)); storage iteration adds its existing prefix-seek
cost. The extra point-read predicate is O(1) CPU after the storage lookup. Alias
filtering is O(A) time in-place for A summary entries, at most 510 after merging.
Overlap cache rebuilding adds at most K seed point probes (K <= 4096); related
aggregation reuses its existing seed probes (K <= 8192). Membership enumeration
and aggregation retain their previous fan-out costs; this is not a total work or
latency bound. No additional startup operation is introduced.

Bounded findings: **high, retained**—old preparation may already have promoted
placeholders into history; deleting those entries would also delete indistinguishable
independent history. This group prevents new promotion but cannot reconstruct missing
provenance. **Medium**—point lookups retain malformed-value-as-missing behavior,
while bounded membership enumeration reports malformed values. **Medium**—first
overlap requests rebuild legacy caches and may be slower. These limitations do not
invalidate the specified positive-count behavior. Canonical-only neighbor retrieval,
independent accuracy labels and cold startup verification remain open objectives.

### Validation

`cargo test --lib --bin eval-neighbors --test semantic_neighbors --test binary_selection --test semantic_matching --test startup_projection`
passed 119 tests: 58 library, 3 evaluator, 3 neighbor, 32 binary-selection,
10 semantic-matching and 13 startup/projection tests. New assertions cover aliases
in both directions, preserved raw bytes and independent history, zero-row work
bounds, malformed memberships, cache truncation/trailing bytes, 255-entry encoding,
explicit selection, batch inference, missing evaluation labels, and recomputed
overlap in both directions followed by cached reads. Strict Clippy for the library,
server, both evaluators and affected integration targets passed. All-target test
compilation passed; pre-existing manifest naming and stress-test warnings remain.
AGENTS and README now specify positive evidence, physical-row bounds and lazy cache
replacement. No claim of cold-start verification or independently labeled accuracy
is made for this group.

Copied-corpus validation used
`target/debug/eval-binary-context /tmp/dazhbog-review-benchmark.toml 32 64 2 transfer --all-cases`.
All 2048 binary/key cases paired with the saved consensus-enabled seed-2 run;
no selected version changed. There were 1099 available expected variants and 980
exact selections, including 271 exact selections among 390 ambiguous available
cases. All 32 batches completed with zero latest, canonical or availability errors.
This sample establishes no corpus accuracy gain for the zero-count correction;
the improvement is demonstrated by the adversarial fixtures. An initial comparison
pipeline failed in its `jq` postprocessing; the corrected full rerun exited zero
and supplied these results. Original production data was not opened.

## Seventeenth implementation group: compound metadata retrieval

Baseline: `60fe91ad69c165bea45a2efa41ac0f4c434da220`. Owned paths are
`src/engine/search/index.rs`, `tests/semantic_neighbors.rs`, `AGENTS.md`,
`README.md` and this report. Original data, local configuration and `research/`
were preserved. All edits used the file-editing tool.

### Reproducer and algorithm

`tokenize_semantic_text` preserves underscores. Search indexing uses Tantivy's
`SimpleTokenizer` followed by `LowerCaser`, which splits underscores. The old
neighbor query sent each fingerprint token directly to `TermQuery`; consequently
`packet_state` asked for an index term that did not exist. A plain `sentinel`
distractor produced a primary hit, disabling fallback and making the omission
observable: the original regression returned only key 3 rather than keys 2, 3
and 7 (compound match, distractor and uppercase compound match).

Query construction now shares the index analyzer factory. One analyzed term uses
`TermQuery`; two or more use a zero-slop, position-aware `PhraseQuery`. This restores
compound matching while rejecting reversed order, intervening words, partial
identifiers and the same words in separate indexed values. Equivalent analyzed
sequences within one field retain the strongest selected-token boost instead of
accumulating duplicate votes. More than 64 analyzed terms causes that entire
selected token to be omitted, avoiding a truncated-prefix match. The fallback
parser remains separate and unchanged; this bound describes the primary query.

The regression covers all six fields: prototype, frame, comment, operand, origin
and aggregate semantic tokens. It includes a distractor in each field so a fallback
result cannot masquerade as a repaired primary query. A serving integration test
pushes independently constructed packed comment chunks and checks retrieval,
contextual reranking, the shared-comment rationale and direct binary membership
with and without explicit MD5. The 64/65-term boundary and duplicate-normalization
score invariance are asserted separately.

### Assumptions, scope and cost

| ID | Assumption | Basis / dependent result | Stress test / falsification probe | Status |
|---|---|---|---|---|
| S27 | Compound fingerprint identifiers are split by the current index analyzer | Repository tokenizer registration plus the locked Tantivy 0.25.0 `simple_tokenizer.rs`; query correction | A primary distractor suppresses fallback; the baseline fails the prototype case, and the same constructor serves all six fields | Confirmed |
| S28 | Ordered adjacent analyzed words preserve the available index evidence for a compound | Existing `WithFreqsAndPositions` schema and Tantivy `PhraseQuery` with zero slop; phrase construction | Reversed, separated, partial and cross-value negative controls; duplicate case variants; 64/65-part bound | Confirmed for the tested index representation; punctuation distinctions erased during indexing are not recoverable |

Affected planes: neighbor candidate retrieval and its lexical score, query
construction, analyzer-factory reuse, tests and documentation. The indexed schema,
tokenization output, canonical projection, stored records, observation identities,
history and cache formats are unchanged. Both wire codecs, pull variant scoring,
request shaping, synthesis, configuration, upstream/session policy, HTTP JSON,
runtime ownership and startup are unchanged. No new shared state or locks are
introduced. Existing compatible indexes already store the necessary positions;
no migration or preparation is needed for this correction. Canonical-only indexing
still limits which variant metadata is available to retrieve.

Let B be analyzed input bytes and p_i the number of retained indexed terms for
selected token i. Additional query construction costs O(B + sum(p_i log p_i))
CPU, including phrase offset sorting, and O(B + sum(p_i)) temporary memory.
The existing six field limits select at most `10 + 10 + 8 + 10 + 4 + 24 = 66`
tokens. Each contributes at most 64 indexed terms, so at most 4224 positive terms
enter the primary query, plus the exclusion clause. This is a term-count bound,
not a bound on token bytes, postings traversal, fallback work or process memory.
Phrase execution additionally reads positions; no latency improvement is claimed.

Bounded findings: **high, open objective**—metadata absent from the canonical
document still cannot retrieve a candidate before contextual reranking. **Medium**—
the fallback query has broader matching semantics and separate expansion behavior.
**Medium**—independent neighbor labels are unavailable, so greater corpus accuracy
is unknown. These findings do not prevent correcting the demonstrated analyzer
mismatch. Full objective completion and cold-start verification remain unproven.

### Validation

The selected library/evaluator/integration suite passed 122 tests: 58 library,
3 evaluator, 6 neighbors, 32 binary selection, 10 semantic matching and
13 startup/projection. Strict Clippy passed for the library, server, neighbor
evaluator and neighbor tests. The fixture asserts raw packed comment decoding;
selection, rationale and primary candidate presence are checked independently.
All-target test compilation passed, retaining pre-existing manifest naming and
stress-test warnings. A final three-test focused rerun passed after adding index
close/reopen to every field fixture. Source-format and whitespace checks passed.
AGENTS and README were updated against the executed query and storage behavior.

An unlabeled copied-corpus smoke run used `eval-neighbors` with three sampled
binary/key pairs and budgets 96, 192 and 384. All nine requests completed and
returned 12 neighbors each using the existing search generation, without a rebuild.
Measured request times ranged from 0.484 s to 5.33 s; these are individual debug
runs with unequal cache state, not a benchmark or evidence of a speedup. All
precision/recall metrics remained null because no relevance judgments were supplied.
The keys were `c926e9a217aaed1bcdc44ec647664e41`,
`efc65bf1e0e5ec35820219784df75d82` and `c290dc0c104c02386568311d00d48d18`.
Source provenance for tokenizer/phrase behavior was inspected in the locked local
Tantivy source as well as repository schema and query constructors; no independent
accuracy claim is inferred from implementation agreement.

## Eighteenth implementation group: live-variant retrieval vocabulary

Baseline: `630b6b06139d95531534b6a83259f0fd2516b648`. This group addresses the
previously recorded canonical-only retrieval gap. A separate `variant_token`
field can retrieve a function whose annotation for the requested binary differs
from the canonical annotation. The canonical name, timestamp and normal text-query
fields retain their original meaning. Candidate metadata is still selected with
the existing binary-context selector; no payload is synthesized by this change.

### Evidence and scope decision

A fresh seed-2 transfer run reproduced 119 available-variant mismatches among 1099
available labels, with 980 exact selections and no diagnostic errors. Of those
mismatches, 102 retain the same function name; 48 differ only in metadata keys 5
and 10. Many comparisons show generated `PIC mode` comments and operand changes,
and some type declarations contradict their stored symbols. These observations
do not establish which annotation is correct. Ranking was therefore not tuned
blindly toward these exact labels. The directly demonstrable retrieval gap is
addressed instead.

The new integration fixture has an older `orchid` annotation for binary A and a
canonical `quartz` annotation for binary B at the same key. Normal search for
`orchid` excludes that key. Neighbor retrieval for binary A now includes it and
returns its `orchid` annotation; canonical-context reranking excludes the unrelated
`quartz` annotation even though its historical vocabulary retrieved the key.
Deleting the key removes the document, and reinserting `topaz` does not restore
pre-deletion vocabulary. A separate exact legacy-schema fixture proves that the
old schema misses the historical candidate while the new schema retrieves it;
a primary distractor disables fallback in both cases.

### Construction, visibility and migration

`engine/search/variants.rs` walks at most 4096 records newest-first in the current
live interval. It skips rejected names, duplicate version IDs and the canonical
variant already analyzed for the primary document. It extracts the existing
semantic fingerprint from names, demangled names and decoded metadata. Generic
tokens, canonical tokens and tokens longer than 256 B are excluded. At most 64
ranked tokens per variant enter a sorted union, which stops at 8192 distinct tokens.
These bounds intentionally limit coverage; they do not index every historical
annotation. Older missing/foreign records and cycles end the usable prefix, while
an invalid head fails construction. Tombstones terminate the interval.

Live updates, streaming preparation and the older library rebuild helper share
the vocabulary constructor. `variant_token` uses the existing symbol analyzer and
stores positions, but is absent from normal text search's default query fields.
Neighbor retrieval adds at most 24 clauses from the seed's semantic tokens with
base boost 0.5, a heuristic coefficient rather than a calibrated probability.
The candidate budget is unchanged. Vocabulary hits can displace other candidates
within that budget; monotonic corpus recall is not claimed.

Reranking requires evidence in the annotation actually selected for the request:
semantic/origin overlap, or informative identifier-component overlap if exact
fingerprint tokens do not overlap. The latter preserves legitimate compound-name
matches such as different `orchid` identifiers. Binary membership alone cannot
validate an otherwise unrelated visible annotation. The first broad run exposed
a compound-name fixture excluded by an exact-token-only check; the component
check corrected it, and the existing browser-context regression then passed.

Serving now requires `canonical_projection_v3`. Offline preparation creates a new
generation and publishes it only after completion, preserving v1/v2 markers and
directories. Replay can open the exact legacy schema with no vocabulary field;
it warns that neighbor retrieval lacks the new projection. Other incompatible
schemas remain errors. Primary record and context encodings are unchanged. Existing
dumps require one offline preparation before serving with this version. The
public Rust `SearchDocument` gains `variant_tokens`; external struct literals must
supply it. HTTP and wire response schemas are unchanged.

### Assumptions, cost and bounded findings

| ID | Assumption | Basis / dependent result | Stress test / falsification probe | Status |
|---|---|---|---|---|
| S29 | A valid live historical annotation provides useful retrieval vocabulary even when it is not canonical | Existing context selector can return that annotation; added field | Legacy/new schema fixture and explicit-binary versus canonical-context integration fixture | Confirmed for controlled cases; population accuracy remains unknown |
| S30 | A retrieved key must be validated against its selected annotation | Historical lexical evidence does not establish current-context relevance | Unrelated canonical `quartz` must be excluded despite historical `orchid` and shared family membership; compound browser regression must remain valid | Confirmed by fixtures |
| S31 | Current primary records suffice to reconstruct this derived vocabulary within the stated bounds | No new observation or client data is inferred; common constructor | Prepare/reopen, old-schema compatibility, tombstone/reinsertion, foreign ancestry and term-bound tests; full copied-dump preparation | Confirmed for fixtures and the copied dump's validated history prefixes; complete historical coverage is not assumed |

Affected planes: search schema, queries, document construction, live mutation's
derived search update, preparation/rebuild, generation selection, neighbor candidate
validation, public Rust document shape, tests and documentation. Configuration
syntax, both binary codecs, session/upstream policy, pull variant scoring, original
record/history encoding and context identity are unchanged. No new shared cache,
lock or eager startup scan is added. Search failure handling retains its existing
nontransactional relationship to record/context writes.

Let R <= 4096 be visited records, B their total bytes, and T_i the token occurrences
analyzed for distinct noncanonical variant i. Construction reads O(R) records and
uses O(B + sum(T_i log T_i)) CPU for hashing, decoding and token ranking. The retained
token-character payload is at most `8192 * 256 B = 2,097,152 B = 2 MiB` per document,
plus collection overhead, visited IDs/addresses and the current record's analysis.
The output cap is not a process-memory or decoding-work bound. Single-variant
functions avoid a second metadata analysis, but still require the bounded history
read and identity hash. Neighbor query construction now permits at most 90 selected
tokens, each with at most 64 analyzed terms: 5760 positive terms plus exclusion.
Postings/position traversal and existing fallback work have separate costs.

Bounded findings: **high, residual**—history, vocabulary and candidate-budget bounds
can still omit a relevant annotation or key. **Medium**—preparation/index size and
write latency increase with distinct historical metadata; measured results must
be distinguished from unchanged startup algorithmic behavior. **Medium**—the older
library rebuild helper's missing-latest-pointer fallback cannot reconstruct a live
history interval, so its vocabulary is empty for such a key. Independent relevance
labels and cold-start verification remain open; the full objective is not complete.

Owned paths: `src/db/database.rs`, `src/engine/mod.rs`,
`src/engine/search/{index,mod,rebuild,types,variants}.rs`,
`tests/{binary_selection,semantic_neighbors,startup_projection}.rs`, `AGENTS.md`,
`README.md` and this report. Original `data/`, ignored configuration and untracked
`research/` remain untouched. The full-copy migration uses only
`/tmp/dazhbog-review-snapshot-20260915` through its existing separate configuration.

### Validation

The selected suite passed 125 tests: 60 library, 3 neighbor-evaluator, 6 neighbors,
33 binary selection, 10 semantic matching and 13 startup/projection. Strict Clippy
passed for the library, server, evaluator and affected integration targets.
Vocabulary tests cover duplicate payloads, canonical-token exclusion, 64/65 tokens
per variant, 256/257 B token lengths, the 8192-token union, tombstones and foreign
ancestry. Additional final boundary checks and copied-dump results follow below.

The final focused boundary test also passed for an invalid foreign head and 4096
visited records followed by an otherwise reachable older token. All-target test
compilation passed. The expanded lifecycle fixture passed for live insertion of
a noncanonical annotation and reconstruction of the same vocabulary after another
preparation. Its initial equal-quality fixture did not hold the intended canonical
annotation; a repeatable comment makes that precondition explicit and asserted.

The legacy-schema fixture also covers an empty, unmarked legacy index. Replay
leaves its v3 marker absent; normal serving rejects it; preparation creates and
publishes the current schema. This exposed and corrected a publication guard
that otherwise could certify an empty legacy schema as v3. The focused test
passed after the correction.
All 13 startup/projection integration tests also passed after this correction.

Full-copy preparation completed successfully with
`target/release/dazhbog --prepare-salvage /tmp/dazhbog-review-benchmark.toml`.
Its record/index phases completed at cumulative 32.785 s and 44.518 s; context
preparation completed at 225.822 s before search construction began. These are
offline preparation measurements, not serving startup times. The prior generation
has 14,598,322 physical documents in its manifest. Historical-vocabulary traversal
has exposed pre-existing foreign and missing older records beyond the previously
sampled chains. Valid prefixes are retained; there is no claim of complete history
reconstruction. Preparation completed at cumulative 1236.640376 s with 14,598,322
documents and 556 quarantined keys, matching the previous generation's counts.
The new `search_index.prepared-1789518095733285000` manifest contains the new field;
its quarantine report has 556 lines. Normal serving reopened the published v3
generation and bound both configured loopback listeners.

Allocated directory sizes measured with `du -sk` were 5,991,708 KiB for the previous
generation and 8,361,556 KiB for v3. Dividing by 2^20 gives 5.714 GiB and 7.974 GiB,
respectively: `(8,361,556 / 5,991,708 - 1) * 100 = 39.55%` more allocated space.
This comparison also includes projection changes since the earlier preparation;
it does not isolate the vocabulary field's marginal cost. The observed process RSS
at 18 min was 5,496,768 KiB (5.24 GiB); this is a sample, not a peak measurement.

All nine release neighbor probes (three explicit-binary seeds, candidate budgets
96/192/384, K=12) completed on v3, each returning 12 results. Elapsed query times
were 0.0379–0.1568 s with uncontrolled cache state. They have no relevance judgments,
so precision and recall remain unknown. These release timings cannot be compared
directly with the previous group's debug-binary timings.

The first post-migration startup benchmark reached both listeners but failed its
30 s binary-detail request deadline for `cc835e8e71dbad02d0c8a77d9a7d4095`; the
owned server then shut down. No successful startup timing series is claimed.
Inspection found that related-binary ranking constructs full contextual facets
for every related binary before truncating its output. This is a **high** adjacent
performance finding requiring the next implementation group; it blocks the full
useful-startup target, not publication of the validated vocabulary projection.
Final strict Clippy, Rust 2021 formatting checks and `git diff --check` passed.
