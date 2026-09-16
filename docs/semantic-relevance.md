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

## Nineteenth implementation group: rank related binaries before coverage analysis

Baseline: `9bb303dc9b10fd8d1e6b131f06e1c1206bebe3a0`. The preceding group's push
encountered remote commit `5c649d5` (Lumina protocol and name-policy changes).
Rebasing applied without conflicts; 147 selected tests, including the new Lumina
fixtures, passed on the combined tree before it was pushed. The preceding
full-dump preparation and neighbor timings predate that integration and remain
measurements of that earlier build.

### Reproducer and change

The startup benchmark selected binary `cc835e8e71dbad02d0c8a77d9a7d4095`, whose
metadata reports 23,849 functions. `profile-binary CONFIG MD5` now isolates
sequential open, coverage, function-page, related-binary, graph and timeline phases
on an offline prepared copy. Later phases reuse earlier caches; this is a diagnostic
tool, not an independent cold-cache benchmark. It opens replay handles and can
write derived overlap caches. Invalid MD5 syntax is rejected before opening storage.

The baseline profile took 2.061 s to open, 5.778 s for the seed's 8192-key coverage
sample, 0.226 s for its function page, **80.716 s for related binaries**, 1.118 s
for the graph and 0.147 s for the timeline. The related-binary implementation had
computed coverage for every aggregate candidate before truncating to eight rows.
That coverage work selects and decodes up to 8192 functions per candidate, even
though none of its results participates in relationship ranking.

Related-binary aggregation now loads metadata, orders candidates by shared
observations, shared functions, last-seen timestamp and MD5, then truncates.
Only returned rows receive contextual coverage. Zero-limit calls return before
reading storage or populating coverage caches. Function counts and observation
totals still provide overlap-percentage denominators. A discarded candidate's
coverage failure can no longer fail a result that would not have included it;
metadata-read failures and returned-row coverage failures still propagate.

The controlled regression failed before the change because a zero-result request
populated coverage caches. It now verifies no work for zero results, no coverage
for discarded rows, coverage for retained rows, stable MD5 tie ordering, shared
counts and 100% overlap in a fully shared fixture. All 34 binary-selection tests
and 13 startup/projection tests passed; the final tie-case extension also passed.
Strict Clippy and release compilation passed for the library, server, profiling
tool and affected integration targets.

### Assumptions and change surface

| ID | Assumption | Basis / dependent result | Stress test / falsification probe | Status |
|---|---|---|---|---|
| S32 | Contextual coverage does not determine relationship order or overlap denominators | The sort reads shared counts, timestamp and MD5; `apply_facets` changes only coverage-related fields | Fixed memberships with tied ranks, zero output and discarded rows; compare returned counts, ordering and percentages | Confirmed by source and regression |

Affected planes: binary relationship aggregation, coverage-cache population,
HTTP binary-detail latency through its existing caller, diagnostics, tests and
guide. Configuration, wire encoding, storage layout, mutation invalidation,
function selection, search schema and returned JSON fields are unchanged.
No migration is required by this group.

For M aggregate candidate binaries and K = min(M, requested limit), metadata reads
remain O(M) and sorting O(M log M). Existing membership scanning and its O(M)
aggregation storage remain. If C_i is contextual coverage cost for candidate i,
coverage work falls from the sum over all M candidates to the sum over K retained
candidates. Coverage-cache churn is reduced correspondingly; this is not a bound
on the membership scan or the retained candidates' record-analysis work.

The revised diagnostic run measured open 1.529 s, seed coverage 1.195 s, function
page 0.015 s, related binaries 1.659 s, graph 0.00036 s and timeline 0.137 s. The
seed coverage counts were identical. OS cache state and concurrent test activity
were uncontrolled, so these runs do not establish a causal speedup factor. The
regression establishes the eliminated work independently of timing.

Bounded findings: **high, residual**—large binary coverage samples still require
thousands of contextual selections; this group does not establish the full-useful
2 s startup target. **Medium**—membership aggregation remains proportional to the
observed associations, and cold storage latency remains unverified. A final warm
startup series is recorded below after completion.

The final 20-run series completed every request and clean shutdown:

| Measurement | Median / s | p95 / s | Maximum / s |
|---|---:|---:|---:|
| Metrics readiness | 1.571 | 1.644 | 1.651 |
| Full useful request set | 4.446 | 4.566 | 4.612 |

Command: `node scripts/benchmark-startup.mjs target/release/dazhbog /tmp/dazhbog-review-benchmark.toml 29668 29667 20 warm`.
These are uncontrolled warm-cache measurements; percentiles use nearest rank.
Binary detail took approximately 2.83–2.96 s and dominates the useful request set.
The original timeout is resolved, but the full-useful 2 s target remains unmet.
Cold-cache performance is unknown. Final formatting and whitespace checks passed.

Owned paths: `src/db/database.rs`, `src/bin/profile-binary.rs`,
`tests/binary_selection.rs`, `AGENTS.md` and this report. The original `data/`,
ignored configuration and untracked `research/` remain untouched.

## Twentieth implementation group: defer analysis until candidate eligibility

Baseline: `236762b85b8eb541fab2d0c4f26be2f359771bd5`. The selector previously decoded
and fingerprinted every collected record and scored every candidate before
applying binary-identity eligibility. An exact last-observed annotation can make
all other collected annotations ineligible independently of their semantic scores.

`AnalyzedVersion` now holds a `OnceLock<SemanticAnalysis>` initialized from its
immutable name, metadata bytes and captured name quality. A shared scoring helper
constructs candidate
indices, applies the existing identity/observation filter, then scores retained
candidates. Both anchor selection and final selection use that helper. Population
normalization still uses every collected candidate; discovery order, canonical
hints, history limits and diagnostic candidate-ID arrays are unchanged. Synthesis
and comparison paths obtain the same memoized analysis when needed.

The unit regression recreates the previous score-all/filter/sort order as an
oracle. For current and legacy observation IDs, it checks bit-identical selected
scores, identical donor identity, retained diagnostic candidates, no synthesis
from an ineligible donor, and no analysis of that donor. Removing explicit context
still analyzes both eligible annotations. The regression passed.

### Assumptions and bounds

| ID | Assumption | Basis / dependent result | Stress test / falsification probe | Status |
|---|---|---|---|---|
| S33 | Eligibility does not depend on semantic scores | `retain_binary_compatible_candidates` reads identities, observation membership and precomputed binary evidence; it ignores tuple scores | Previous-order oracle with competing canonical hint, both ID encodings and absent explicit context | Confirmed for inspected predicate and fixtures |
| S34 | Deferred analysis depends only on immutable name/data and captured name quality | Name quality reads process-wide rejection policy; its value is captured during collection | Test explicit quality values independent of current policy; audit record mutation sites and compare semantic results | Revised: the initial name/data-only assumption was falsified by policy lookup; capture and regression address that dependency |

The public analysis helper now computes name quality once and shares it between
quality and consistency calculations. Deferred candidate analysis receives the
captured value instead of rereading policy. Two explicit values for the same name
are tested without mutating process policy, avoiding interference between tests.
Process-wide policy ownership across concurrently configured databases remains
an existing limitation; this group does not redesign it.

The parity claim assumes stable context reads that succeed. Pruned candidates no
longer perform scoring-only storage reads, so errors reachable exclusively through
those reads no longer fail selection. Retained-candidate errors still propagate.
Concurrent observations are not an atomic snapshot; this change introduces no
transaction or cross-request cache.

For V collected candidates and E eligible candidates, record reads, identity
hashing and statistics retrieval remain unchanged. Single-key analysis falls from
the sum of analysis costs over V candidates to the sum over E; the same applies
to scoring work. Sorting still operates on E candidates. The fixed version-vector
storage remains O(V); decoded metadata and token allocations exist only for demanded
analyses. Multi-key identifier-component construction can still demand analysis
of all V candidates before eligibility, and replay diagnostics can demand it too.
No universal latency reduction follows when all candidates are eligible.

Affected planes: private version representation, selector evaluation order,
canonical refresh/replay/compare consumers of analysis, tests and guide. Wire
formats, public result shapes, configuration, record formats, search projection,
mutation ordering and recovery formats are unchanged. No migration is required.

Owned paths: `src/db/{database,semantic,selection_tests}.rs`, `AGENTS.md` and this
report. The original dump, local configurations and `research/` remain untouched.
Bounded finding: **medium, residual**—candidate discovery is unchanged and even a
single eligible candidate still needs metadata analysis; large coverage samples
may remain expensive.

The initial 129-test suite passed: 63 library, 3 evaluator, 34 binary selection,
10 semantic matching, 6 neighbors and 13 startup/projection tests. After capturing
name quality, both selector unit tests and all 10 semantic-matching tests passed.
Final strict Clippy, all-target test compilation (including both module roots),
release builds, Rust 2021 formatting and whitespace checks passed. Existing
manifest naming warnings and unrelated stress-test warnings remain.
The final 20-run startup series completed every request and clean shutdown:

| Measurement | Median / s | p95 / s | Maximum / s |
|---|---:|---:|---:|
| Metrics readiness | 1.689 | 1.799 | 2.253 |
| Full useful request set | 4.230 | 4.387 | 15.177 |

The same benchmark command and copy were used as in group 19. The first run took
12.615 s for binary detail; later runs took 2.472–2.674 s. That first-run outlier
is retained. Cache state was uncontrolled and no OS purge was performed, so this
is not a cold-cache result or a controlled estimate of the change's speedup.
Readiness variation also changed between series. The full-useful 2 s target is
still unmet, and cold performance remains unknown. Eligibility/score parity and
the elimination of ineligible-candidate analysis are established by the regression,
independently of these host-specific timings.

## Twenty-first implementation group: isolate name policy and certify projections

Baseline: `f1cf4f643215dd1a6b2d7d9012f878065f36dc8f`. A regression reproduced an
annotation disappearing from an `Off` database immediately after opening a second
database configured with `Prefixes`. The process-global atomic policy also meant
offline replay and CLI preparation could use a different policy from serving.

The policy now belongs to each engine configuration. The text key remains
`lumina.name_rejection`; Rust callers use `Config.engine.name_rejection`. Admission,
visible/history records, selection, deferred quality scoring, synthesis, upstream
filtering, neighbor analysis, live search documents and both rebuild paths receive
the owning runtime's policy. Standalone helpers retain deterministic `Prefixes`
defaults and offer explicit policy variants. The global setter/getter are removed.

Preparation publishes one JSON value under `canonical_projection_v4`, containing
`generation` and `name_rejection`, after flushing the new generation and stores.
Normal startup refuses legacy or mismatched-policy projections without scanning
records. Replay can inspect them with a warning, but Database push/delete/revert
reject such handles before persistent mutation. Unmarked existing search storage
is not certified merely because the record store is empty. Malformed publication
values fail closed; explicit preparation can replace them. Previous generations,
legacy markers, raw records and observations remain intact. This is a derived-state
migration, not a record or context encoding change.

### Assumption register

| ID | Assumption | Basis / dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|
| S35 | Policy is a database property, not a process-global setting | One Config owns storage and its search projection; independent databases are public API objects | Concurrently open Off and Prefixes; reopen through replay | `cargo test --test name_policy database_name_policies` | Confirmed by regression; baseline global ownership falsified |
| S36 | Legacy projections cannot establish which policy built them | v1/v2/v3 markers contain only directory names; preparation previously ignored configured policy | Old v3 marker and policy changes in both directions | `cargo test --test name_policy` | Retained; requires explicit rebuild, never inferred from schema |

### Change-surface map and complexity

Affected: configuration ownership/parser, admission and mutation guards, history
visibility, selection/synthesis, upstream result filtering, search construction and
publication, replay/recovery preparation, tools, tests and guide. HTTP and both
protocols inherit Database behavior without wire or response-schema changes.
Unchanged: transport/TLS/session authentication, raw identity/record serialization,
tombstone ordering, context observation encoding and candidate-discovery bounds.
Name-analysis complexity is unchanged. Startup adds one publication-manifest
decode and comparison: O(M) CPU/temporary memory for M manifest bytes, independent
of record count; no corpus traversal. Existing rebuild and query bounds remain.

Owned paths: `src/config/{types,parser}.rs`, `src/db/{database,semantic}.rs`,
`src/engine/{mod,visibility}.rs`, `src/engine/search/{mod,index,rebuild,variants}.rs`,
`src/net/handler.rs`, `src/bin/{profile-binary,storage-audit}.rs`,
`tests/{name_policy,startup_projection,database_integration,lumina_fixtures}.rs`,
`README.md`, `AGENTS.md`, and this report. No original dump or configuration edits.

### Bounded findings and guide audit

- **Medium, residual:** global metrics retain the first serving database's sled
  tree through `OnceLock` (`src/api/metrics.rs::init`), preventing in-process reopen
  of that store. The policy test exercises serving on a separate store and replay
  for the reopened store. Metrics ownership is independent of annotation policy;
  it does not block this change.
- **High, resolved:** a replay handle using a mismatched policy could otherwise
  mutate a search generation still certified for its original policy. Database
  mutation guards close that route. Public low-level storage APIs remain writable;
  replay is not operating-system-enforced read-only access.
- **Medium, opportunity:** the supplied IDA corpus contains unstripped ELF files,
  source/build recipes and compiler DWARF. Its Lumina fixtures deliberately rename
  functions, so their stored names and post-pull listings are unsuitable independent
  labels. Function-hash/address mappings may be joined to binary symbols after
  verifying input identity. This investigation is separate from policy correctness.

The guide's preparation and admission contracts now describe per-database policy
and v4 certification. Its stale claim that `get_history` crosses tombstones was
corrected to match the existing implementation, without changing history code.

Validation: 134 tests passed (64 library, 3 neighbor evaluator, 34 binary selection,
4 policy lifecycle, 10 semantic matching, 6 semantic neighbors, 13 startup). Both
module roots and every Cargo target compiled. Strict Clippy on the library, server,
affected tools and new tests passed, as did Rust 2021 formatting and whitespace
checks. Release server/profile/evaluator builds passed. Existing manifest-name and
unrelated stress-test warnings remain. The complete copied-corpus v4 preparation
was started separately; no large-corpus completion or new latency result is claimed
here. The earlier 2 s useful-startup target and independent relevance evaluation
remain open.

## Twenty-second implementation group: independent binary-symbol labels

Baseline: `87d1d61856372d59516522061c51c6e9c3091167`. The supplied
`~/hexrays/ida/tests/input/` contains unstripped ELF files, compiler DWARF, source
files and build recipes. In `src/lumina_samples`, fixture SQLite databases map
Lumina hashes to function addresses and extents. Their hints deliberately rename
functions before pushing, so stored names and post-pull listings are not independent
ground truth. The new extractor reads no stored names or metadata: it joins those
hash/address mappings to defined, nonzero-size ELF `STT_FUNC` symbols at the exact
same address and size. Symbol aliases are retained as an acceptable-name set.

The fixture's distinct input-MD5 set must equal the actual binary's single MD5;
each hashed function must have a history/IDB link to that verified input.
SHA-256 identifies both source artifacts, checked for changes during extraction.
WAL/journal-backed fixtures are refused. No rebasing, instruction-set address-bit
masking, function-descriptor interpretation or size relaxation is inferred.
Exclusions remain explicit. Source files and recipes were inspected but not rebuilt;
bit-reproducible source builds are not established.

The direct-directory audit found 33 SQLite/ELF pairs and 55,517 hash rows.
31,584 rows across 27 binaries had exact symbol address/extent matches; 21,608
lacked a matching defined sized function symbol and 2,325 had different extents.
There were no duplicate binary/key case IDs. Eight MIPS artifacts emitted LLVM
dynamic-table warnings; successful symbol extraction does not establish general
ELF structural validity. These are correlated builds, not 31,584 independent
statistical observations. They are assigned one conservative source family and
the test partition; no matching weights were tuned using these labels.

### Assumption register

| ID | Assumption | Basis / dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|
| S37 | ELF function symbols provide an independent name oracle | Symbol tables belong to input binaries; fixture scripts replace annotation names afterwards | Reject undefined/zero-sized/non-function symbols, wrong extents and duplicate keys; preserve aliases and addresses beyond IEEE-754 exact integer range | `node --test scripts/extract-symbol-labels.test.mjs` | Retained for exact-name agreement only; no metadata-accuracy claim |
| S38 | Fixture hash/address mapping belongs to the supplied binary | Exactly one input MD5 equals the binary digest; source SHA-256 retained | Supply the ARM hello database with the SQLite binary | Extractor exits 1 before joining: input identity mismatch | Confirmed for inspected pairs; no adversarial MD5-collision resistance claim |

`eval-symbol-labels` reads at most 64 MiB of JSONL and 65,536 cases, validates
provenance/identity/partition consistency before opening storage, and compares
explicit-binary, inferred-batch, latest and canonical selection. It passes only
keys and optional binary MD5 to the selector. Names, source addresses, sizes and
provenance remain evaluation-only. Counts distinguish availability from exact-name
agreement and partition totals remain separate. A synthetic end-to-end regression
uses competing stored annotations: explicit identity returns both expected names,
while latest matches only one; source-record and search-document counts are unchanged.

Affected planes: offline tooling, evaluation tests and documentation. Serving
selection, storage formats, projection schema, configuration, wire protocols and
UI are unchanged. Extractor inputs are limited to 256 MiB per artifact and subprocess
output to 32 MiB per call. For S symbols and H hash rows in one pair, JavaScript
parsing/joining uses expected O(S + H) work and O(S + H) retained entries plus artifact bytes and
subprocess output; alias sorting adds the sum of O(A log A) for alias-set sizes A.
SQL extraction adds indexed provenance joins and an O(H log H) row sort.
Directory extraction retains at most 65,536 accepted cases across pairs. Evaluation adds O(C)
label/group storage to the existing selector costs for C cases. Bounds are not
claims about total process RSS or sled caches.

Owned paths: `scripts/extract-symbol-labels{,.test}.mjs`,
`src/bin/eval-symbol-labels.rs`, `tests/symbol_evaluation.rs`, `README.md`,
`AGENTS.md`, and this report. Original IDA fixtures are read-only inputs and are
not copied into the repository or published.

Bounded findings: **medium, residual**—direct symbol/address matching has low or
zero coverage for several compressed-instruction and 64-bit PowerPC fixtures;
ABI-specific normalization needs independent evidence before broadening labels.
**High, interpretation**—exact symbol-name disagreement does not prove an annotation
is semantically incorrect, and current stored observations may include the same
binary. This evaluation is independent-label agreement, not unseen-family transfer
or a blinded estimate of metadata accuracy.

Validation: both extractor unit tests, both evaluator unit tests and the CLI
integration regression passed. A wrong-binary probe failed before symbol joining.
All 33 local pairs passed input/history-link checks with the exclusion counts above.
Strict Clippy, release evaluator build, Rust formatting and whitespace checks passed.
Copied-corpus name-agreement results are pending completion of v4 preparation; no
accuracy estimate is inferred from extraction coverage.

## Twenty-third implementation group: preserve contextual donor size

Baseline: `001dc12652bd851a43f4917534d3f2e161c438c2`. `get_function_in_context`
converted a selected variant into `FuncLatest` using metadata length for
`len_bytes`, contradicting the declared-size contract introduced by the earlier
protocol change. The regression returned 0 B for a donor declared as 1,024 B.
The conversion now copies `SelectedVariant.func_size`, preserving the donor's
stored field and its documented legacy interpretation. It no longer performs a
fallible metadata-length conversion. HTTP `data_size` still uses actual returned
metadata bytes; wire encoding and stored records are unchanged.

Assumption register: None. The field contract is explicit in `src/db/types.rs`
and independently exercised with 1,024 B and 2,048 B donors containing empty
metadata, plus a zero-sized donor containing nonempty metadata. The regression
failed before the fix and passed afterward. The existing browser-context test
covers raw legacy records separately. Time and extra space remain O(1).

Affected planes: contextual Rust result conversion, regression tests and guide.
Selection order, metadata synthesis/shaping, persistence, configuration, recovery,
transport, wire layouts and HTTP JSON shapes are unchanged. Owned paths:
`src/db/database.rs`, `tests/binary_selection.rs`, `AGENTS.md`, and this report.
Bounded adjacent findings: None for this conversion.

The new size regression and existing browser-context regression passed. Strict
Clippy compiled both module roots and the affected integration target; formatting
and whitespace checks passed.

## Completed copied-corpus validation after groups 21–23

Validation checkout: `e0c84b2c960ec411b7031a5982ee6819b85f0a5c`. The server and
symbol evaluator were rebuilt in release mode. Offline v4 preparation completed
successfully on `/tmp/dazhbog-review-snapshot-20260915` using the separate loopback
benchmark configuration. The original `data/` and IDA input fixtures were not edited.

Preparation published `search_index.prepared-1789522416353807000`, containing
14,943,314 search documents and a 210-line quarantine report. Cumulative startup
phases were segments 34.504577 s, index 48.178410 s, context 224.847358 s and completed
search 1,146.058423 s. External wall time was 1,147.74 s (reported to 0.01 s).
Allocated search storage reported by `du -sk` was 8,118,904 KiB, or
8,118,904 / 1,048,576 = 7.743 GiB, rounded to three decimals. Prior generations
remain. The projection has 344,992 more documents than the earlier v3 run; changed
admission policy also changes whether a validated history prefix can be used.
The smaller quarantine count is not evidence that damaged primary history was
repaired. Existing malformed/missing ancestry warnings remain.

Three serving smoke runs completed metrics readiness, search (24 hits), function
detail, neighbor retrieval (8 hits), binary detail, both protocol probes, and clean
shutdown. Readiness was 1.567 / 1.660 / 1.745 s; the complete useful request set took
4.921 / 4.203 / 4.322 s. Cache state was uncontrolled and followed preparation.
These are functional publication/reopen checks, not a cold-start benchmark or a
controlled speedup estimate. The complete useful-startup target of 2 s remains unmet.

Independent-label evaluation used the release extractor/evaluator pipeline from
the README with `--directory ~/hexrays/ida/tests/input/src/lumina_samples`, one
conservative family (`lumina-source-fixtures`) and partition `test`. It exited 0
after all 27 labeled binaries. No labels were inserted into the database.

| Selection mode | Labeled cases | Available suggestions | Exact symbol-name matches |
|---|---:|---:|---:|
| Explicit binary | 31,584 | 539 | 458 |
| Inferred batch | 31,584 | 539 | 458 |
| Latest | 31,584 | 539 | 458 |
| Canonical | 31,584 | 539 | 458 |

Availability is 539 / 31,584 = 1.71%; exact-name agreement conditional on availability
is 458 / 539 = 85.0%, rounded to one decimal percentage point. These denominators
must remain separate. There are 81 available name disagreements. Identical
aggregate counts do not prove identical per-case selections or distinguish ranking
quality in ambiguous cases. This baseline does not establish an improvement over
latest/canonical selection, unseen-family accuracy or metadata accuracy [S37–S38].
Candidate-level availability of the expected names and the causes of those 81
disagreements remain unknown. Source keys absent from this dump cannot measure
ranking among stored alternatives. No selector weights were adjusted after observing
these test labels. No new assumptions were needed for the arithmetic or timings.

## Twenty-fourth implementation group: diagnose independent-name disagreements

Baseline: `b23541344e629495d6122750e2a12f5c420cdc97`. The independent evaluator
now accepts `--disagreements`. For each available explicit-binary result with no
exact expected-name match, it reports the selected name, candidate count, synthesis
state, binary evidence score, and a separate history probe. Expected labels enter
only the comparison and post-selection diagnostics. They never affect selection.

The probe returns at most 64 accepted versions, reports up to 32 sorted distinct
names, and checks expected-name versions against selected candidate identities.
`absence_established` is always false: history traversal is bounded, filtered by
the configured name policy, and stops at tombstones. A probe error is diagnostic
data and does not change the selection or agreement counts.

### Assumption register

| ID | Assumption | Basis / dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|
| S39 | Observed history is sufficient to identify an expected-name candidate when that version is returned | Version identity is computed from the returned key/name/payload and checked against captured candidate IDs | An expected older annotation competes with a newer same-binary name; misses remain inconclusive | CLI integration regression requires `expected_candidate_seen: true`, while `absence_established` remains false | Confirmed for positive presence; absence remains unknown |

The copied-corpus diagnostic run returned 81 disagreement rows without probe
errors. Of these, 67 had one candidate and 14 had multiple candidates. No probe
returned an expected symbol name, and no expected-name candidate was observed.
The largest returned history contained six versions. The initial diagnostic run
allowed 4,096 returned versions; the final implementation reduces that bound to
64. Repeating the full extractor/evaluator pipeline with that final bound exited
0 and reproduced all 81 rows, the candidate counts, maximum history length, zero
probe errors and zero expected-name observations. All four modes still returned
539 available suggestions and 458 exact matches across 31,584 cases.
These observations do not prove the expected names are absent from all storage.
They provide no demonstrated case in this sample where reranking a retrieved
expected-name candidate would repair the disagreement [S37–S39]. No scoring
weights were tuned using these test labels.

Affected planes: offline evaluation tooling, integration tests, documentation.
Selection, storage formats, projection publication, configuration, transport,
wire protocols, HTTP/UI and recovery are unchanged. Owned paths:
`src/bin/eval-symbol-labels.rs`, `tests/symbol_evaluation.rs`, `README.md`,
`AGENTS.md`, and this report. Pre-existing `research/` remains outside this group.

For D disagreement cases, each probe traverses at most 4,096 raw records through
the existing history reader and retains at most H = 64 accepted records. Added
work is O(D × (R + H × (A + C) + H log H)) record/name operations, where R ≤ 4,096,
A is the expected alias count, and C is the captured candidate count; hashing and
record decoding also depend on payload bytes. Incremental retained payload space
is bounded by the bytes of H records, not a fixed byte budget. Probes run
sequentially and diagnostic rows are emitted immediately.

Bounded findings: **high, relevance evidence**—this corpus does not demonstrate
that selection can recover the missing symbol names from existing candidates;
an independently annotated donor corpus is needed to isolate transfer ranking.
**Medium, interpretation**—binary evidence scores are normalized over informative
query keys, not all input functions, and are not correctness probabilities.
Neither finding justifies adjusting weights against exposed test labels.

Validation: both evaluator unit tests and the CLI integration regression passed;
the regression also verifies unchanged primary-record/search-document counts.
Strict Clippy, Rust formatting and whitespace checks passed. The guide and README
now document the optional diagnostic schema and its non-absence contract. The
original production dump and private input fixtures were not modified.

## Twenty-fifth implementation group: complete sparse known-binary context

Baseline: `c506692099d1da27bd66e6ffddad643148d40809`, tracked tree clean;
pre-existing `research/` remains user-owned. Further inspection of the 31,584
symbol-backed cases found 29,248 distinct keys. Across leave-one-binary donor sets,
4,648 cases shared a key with another binary and 4,642 had an acceptable symbol
name available there. No case had both an acceptable and an unacceptable donor
name. This corpus therefore provides no conflicting-name ranking discrimination
under that construction [S37–S38]. The user confirmed no additional such corpus
is presently available. No selector weights were fitted to these test labels.

### Implemented behavior

An explicit binary MD5 previously constrained known per-key observations but did
not supply its other stored function identities when a request was sparse. A
single missing-observation request could therefore choose a recent unrelated
annotation even when independently observed companion functions linked the known
binary to an older donor variant.

`complete_binary_context` now activates when a nonempty, non-holdout request has
an explicit MD5 and at least one requested key lacks a positive current observation
for it. It examines the first 128 physical forward-membership rows in storage
order, admits only keys with positive current observations, and deduplicates them
against the request. If keys were added, donor inference excludes the query MD5;
the added identities do not become semantic name/type/comment anchors. Existing
leave-target-out family voting, targeted history discovery, candidate eligibility,
explicit-observation precedence and request shaping then apply unchanged.

Empty requests, no-MD5 requests, all-positive requests and holdout evaluation do
not enumerate extra keys. Unknown binary identities add no keys. The common
no-completion path borrows the original key slice rather than allocating a copy.
This changes selection when relevant context was already stored; it does not
write observations, import evaluation labels or infer a binary identity from a
filename. A stale positive observation whose variant cannot be retrieved does
not by itself trigger completion; existing historical fallback still applies.

Coverage caching now includes the inspected membership prefix as dependencies
when a returned fallback lacks a positive current observation. Otherwise a small
coverage sample could remain cached after an auxiliary key's donor memberships
changed in another binary. Coverage counts still describe the requested sample.
Both prefixes use the same enumeration order, so the dependency union has at most
max(sample limit, 128) ≤ 8,192 keys. The existing generation fence rejects
publication across concurrent mutations.

### Assumption register

| ID | Assumption | Basis / dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|
| S40 | Other positively observed identities of the known binary provide relevant donor-family evidence for a missing annotation | Existing binary membership model; new completion fallback depends on these identities, not stored annotation names | Unknown MD5, partial/mixed donors, duplicate/permuted requests, one-version cap, exact conflicting observations, deletion and holdout | Sparse-query regression fails at the baseline and passes with completion; independent conflicting-annotation corpus can falsify broader relevance benefit | Confirmed for constructed regression; general accuracy unverified |
| S41 | Coverage and supplemental dependency prefixes share enumeration order | Both call `get_binary_function_keys` on the same forward tree; cache publication is mutation-fenced | Coverage limit 1 with dependencies outside the sample; mutate another binary's observations | Dependency regression fails without dependency extension and passes with it | Confirmed for tested lifecycle; direct out-of-process store edits remain outside the cache contract |

### Change surface and cost

Affected: explicit-context selection, targeted candidate discovery through extra
family evidence, contextual HTTP/search enrichment and binary coverage results,
coverage-cache dependencies, tests and documentation. Existing no-MD5 wire pulls
retain their inference input. Wire layouts, configuration syntax, stored records,
context schema, search projections, upstream policy and session authorization are
unchanged. No migration or preparation is required. Owned paths:
`src/db/database.rs`, `src/db/selection_tests.rs`, `tests/binary_selection.rs`,
`README.md`, `AGENTS.md`, and this report.

For Q distinct query keys and K ≤ 128 inspected membership rows, completion adds
at most Q + K positive-observation lookups and K forward-row visits. Extra family
evidence visits at most K × 257 membership rows (the existing cap plus one
excluded-query slot), before the existing 64-donor-per-target bound. Expected
deduplication CPU and extra key storage are O(Q + K) when completion is attempted;
the no-MD5 path adds O(1) work and no key allocation. Storage lookup costs depend
on sled and cache state. Existing family construction, candidate history reads and
metadata analysis remain; this is not a total request-time bound. Adding evidence
can increase targeted history work, still bounded by 4,096 raw records per key.

Bounded findings: **medium, sampling**—the first 128 physical rows are a storage
prefix, not a representative statistical sample; placeholders can exhaust the
budget. **High, validation limit**—the available independent labels do not measure
this conflicting-donor case. The regression establishes the evidence path and
its invariants, not a production-wide accuracy gain. The original data dump and
private fixtures remain unchanged.

Validation for group 25: 65 library tests, 37 binary-selection regressions,
6 semantic-neighbor tests and the symbol-evaluation CLI regression passed (109
tests total). The server target compiled and has no unit tests in this invocation.
The final extension of the context-boundary test also passed after adding a
zero-observation row: it consumes the physical budget but contributes no evidence.
Strict Clippy for both roots and affected integration targets, Rust formatting and
whitespace checks passed. The sparse-context regression failed before completion
was implemented; the coverage regression failed with only the dependency extension
removed and passed after restoration.

The full independent-label pipeline was repeated against the prepared offline
copy. It exited 0 with unchanged totals in all four modes: 31,584 cases, 539
available suggestions and 458 exact-name matches. All 81 explicit-binary
disagreement diagnostic rows were identical to the pre-change run. This supplies
a bounded regression check, not evidence of a relevance gain on those labels.
README and guide contracts were audited for context completion, holdout isolation
and cache dependency scope. No persistent-format or migration contract changed.

## Twenty-sixth implementation group: invariant explicit-context donor voting

Baseline: `a8691f8c8c1fa2399853ff159d428a4e6c0fe953`, tracked tree clean except
user-owned `research/`. Adversarial review found that group 25 excluded the query
MD5 from donor membership only if completion actually added a key. Supplying the
same companion identities explicitly therefore changed rarity weights. A new
regression selected `inspect_packet` for the sparse request but `decode_pixels`
for the identical completed identity set supplied by the caller.

With three companion keys, donor A belongs to one key and donor B to two keys.
After excluding the query identity, those membership degrees are 1, 2 and 2.
Their dimensionless normalized evidence is A = 1 / 3 and
B = (1/2 + 1/2) / 3 = 1 / 3. Including the query identity changes degrees to
2, 3 and 3: A = (1/2) / 3 = 1/6 and B = (1/3 + 1/3) / 3 = 2/9.
That creates a donor lead from request representation alone.

Donor-family construction now always excludes the explicit query MD5, or the
withheld identity in transfer evaluation. Exact last-observation and historical
identity precedence remain separate and unchanged. No-MD5 wire batches retain
their existing behavior. The regression compares selected names, candidate IDs,
individual donor match strengths and aggregate support for sparse versus explicit
identity sets, then checks reordered inputs and duplicate target keys. It failed
before the correction and passed afterward. Semantic annotation anchors can still
differ when callers supply extra annotated keys; only membership-vote invariance
is asserted generally, and this fixture uses nondistinguishing companion metadata.

Assumption register: None for the correction; identical membership inputs and
exclusions must produce identical donor weights. Existing relevance assumptions
and independent-accuracy limits remain. Affected planes: explicit-context selection
and dependent contextual results, integration tests, README and guide. Persisted
records, context/search schemas, configuration, recovery and wire formats are
unchanged. No migration is required. Owned paths: `src/db/database.rs`,
`tests/binary_selection.rs`, `README.md`, `AGENTS.md`, and this report.

The existing family algorithm and asymptotic costs are unchanged. Explicit-MD5
requests consistently allow up to 257 physical membership rows before removing
the excluded identity and enforcing the 256-member cap; no-MD5 requests keep the
256-row bound. The guide's obsolete claim that single-key MD5 selection has no
other-key family dependencies was corrected to describe bounded completion.

Bounded adjacent finding: **medium, metadata coverage**—batch fingerprints consume
decoded prototypes, frame annotations, comments and printable operand fragments.
Raw type field-name bytes contribute only through successful declaration rendering;
a failed type decode can therefore discard potentially usable identifier evidence.
Their independent extraction needs format validation and explicit provenance rules
before treating those bytes as prototype evidence. This does not block the donor
voting correction. Independent ranking accuracy remains unverified.

Validation: all 38 binary-selection tests, six semantic-neighbor tests and the
symbol-evaluation CLI regression passed (45 integration tests). Strict Clippy
compiled both library/server roots and affected integration targets; formatting
and whitespace checks passed. The rebuilt independent-label evaluator pipeline
exited 0 with unchanged counts in all four modes (31,584 cases, 539 available,
458 exact names). All 81 disagreement rows were unchanged. No original production
data or private fixture was modified. README and guide now state the invariant
exclusion and the applicable physical membership bound.

## Twenty-seventh implementation group: lexical evidence from undecoded type fields

Baseline: `d303929d4535a515273ab0d7b9c4ff620a2e7364`, tracked tree clean;
`research/` remains outside the task. The metadata audit found that field-name
bytes were preserved but excluded from batch context whenever their type could
not be rendered. The new regression supplies an unsupported type with a valid
`OrchidSession` field name. Previously the batch selected the newer unrelated
`CobaltSession::parseHeaders`; the field-name signal was lost.

### Provenance and assumptions

Primary local IDA sources inspected: `base/typeinf.hpp` defines `p_list` as a
sequence of length-prefixed strings; `base/typeinf.cpp::deserialize_name` consumes
each name independently of type decoding; `base/varloc.cpp::serialize_dt` and
`deserialize_dt` establish its integer encoding. `dt` stores length + 1 in one
byte through encoded value 127, otherwise in seven low bits followed by eight
high bits. This is not Lumina `dd`. Tests use literal independent width-boundary
fixtures: name lengths 126, 127 and 128 begin with `7f`, `80 01` and `81 01`.
The original IDA source bodies and private corpus contents are not copied into
the repository.

| ID | Assumption | Basis / dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|
| S42 | A well-framed field-name list can be decoded independently of an unsupported type | Local primary serialization/deserialization owners above; lexical extraction only | Width transitions, truncated lengths/names, zero extension, trailing garbage, invalid UTF-8, embedded NUL/control, byte/entry bounds | `independent_field_names_validate_lengths_text_and_bounds` | Confirmed for accepted framing; no argument-position/type-shape claim |
| S43 | These field-name words can distinguish otherwise ambiguous batch annotations | Existing lexical-context model; new evidence is aggregate-only and bounded | Components enabled/disabled, permutations, duplicate targets, exact identity, partial stronger binary lead, malformed names, frame fields, unchanged raw data/error/canonical | New anchor and binary-selection regressions | Confirmed for constructed cases; independent general accuracy unverified |

### Implementation and representation boundaries

`decode_field_names` borrows accepted UTF-8 strings from complete `p_list` bytes.
It rejects malformed framing or textual content without returning a prefix.
Empty entries and trailing zero terminators are accepted; interior NUL/control
characters are rejected. A list may contain at most 64 encoded entries (including
empty names) and 8,192 B. This is a conservative accepted subset; rejected raw
bytes remain available in the original metadata.

`selection_fingerprint` considers unrendered function-type fields and unrendered
types from the first 63 frame-member positions. Across those sources it inspects
at most 8,192 B and retains at most 64 nonempty names per candidate. Lists larger
than the remaining byte budget are skipped; inspected malformed lists consume
their byte budget and contribute no words. Valid names become aggregate lexical
tokens, with optional identifier splitting controlled by the existing component
setting. They never populate decoded-prototype or name-token fields. The separate
whole-token priority/corroboration path still uses original fingerprints.

Transient fingerprints are now constructed after first-pass identity eligibility,
only for retained eligible candidates. The first pass has empty anchor weights,
so this movement does not change its score. It avoids expanding candidates that
cannot participate. Both decisive and consensus source handling retain their
existing one-unit evidence budget and leave-target-out rule.

Affected planes: multi-key selection evidence, a bounded type-field lexical helper,
regression tests and documentation. Raw parsing results, type declarations/errors,
donor payloads, request shaping, canonical scores, persisted search projections,
neighbor component reranking, configuration syntax, transport and wire layouts are
unchanged. One-key coverage therefore gains no new dependencies from this group.
No migration or startup preparation is required. Owned paths: `src/db/anchors.rs`,
`src/db/database.rs`, `src/protocol/lumina/type_decoder.rs`,
`tests/binary_selection.rs`, `README.md`, `AGENTS.md`, and this report.

For B ≤ 8,192 inspected field-list bytes and N ≤ 64 retained names, framing/text
validation and lexical scanning add O(B) work; at most 64 field-list slots are
considered. Borrowed decoded-name storage is O(N); token storage depends on B.
For F bytes of existing token content and T resulting tokens, combination uses
O(F + B + T) retained space and O(T log T) lexical string comparisons; comparison
byte costs depend on token lengths. Existing component expansion,
metadata parsing and candidate discovery retain their own costs. The 8 KiB cap
does not bound total record size, metadata parsing, or process memory.

Bounded findings: **high, interpretation**—field names do not prove a type decoded
correctly or an annotation fits the target binary; they only add lexical evidence
within the existing eligibility policy. **Medium, recall**—malformed, oversized,
non-UTF-8 lists and frame members beyond the bounded prefix remain unused. The
new signal is not added to persisted search vocabulary in this group.

Validation: 67 library tests, 39 binary-selection tests, ten semantic-matching
tests, six neighbor tests and the symbol-evaluation CLI regression passed (123
tests). The server target compiled; it has no unit tests in that invocation.
Final anchor tests passed after extending the aggregate-name/frame-position
boundary checks and avoiding a redundant sort when no fallback words exist.
The focused batch-selection regression also passed on the final source. It
demonstrates the improvement with identifier components both enabled and disabled,
preserves duplicates, leaves canonical/raw/error representations intact, and
retains exact and stronger partial-binary precedence. Strict Clippy, formatting
and whitespace checks passed.

The rebuilt independent-label pipeline exited 0 on the prepared offline copy.
All four modes retained 31,584 cases, 539 available suggestions and 458 exact names;
all 81 disagreement diagnostic rows were unchanged. These labels remain a bounded
regression check and do not establish a general accuracy gain for the new signal.
The README/guide were audited for evidence provenance, limits, lazy analysis,
unchanged projections and migration requirements. Original production data and
private fixtures were not modified.

## Twenty-eighth implementation group: omit singleton self-anchor work

Baseline: `ef673eb3087871bc6ace5d4d678808d0916aeb06`.
Owned paths: `src/db/database.rs`, `tests/binary_selection.rs`, `AGENTS.md` and
this report. Baseline tracked changes were empty; untracked `research/` is
user-owned. The production `data/` and local configuration remain untouched.

### Evidence boundary and native corpus probe

The user confirmed that another independently labeled conflict corpus is not
currently available. The existing symbol corpus has zero leave-one-binary cases
with both a correct and an incorrect donor name for the same function key.
That evidence cannot establish independent ranking accuracy.

A disposable C++ harness compiled against the local IDA SDK's
`init_library`, `open_database`, `auto_wait` and `calc_function_metadata` APIs.
An original two-function C source compiled to an AArch64 ELF object. Execution
used macOS `sandbox-exec` to deny network access and writes outside its temporary
directory, with `NO_IDAPYTHON=1`. With an isolated `IDAUSR`, initialization reported
no valid license. With the normal profile it timed out opening `ida.reg` under
the write restrictions. Neither run generated hashes. The cause of the normal
profile timeout outside this sandbox is unknown; no license or registry change
was attempted to bypass it. These temporary artifacts are not a validated corpus
and are not committed. SDK provenance is the inspected local headers and
`lumina/funcpat.cpp`; no IDA implementation was copied into this repository.

### Change and assumption register

Single-distinct-key requests previously scored candidates twice and constructed
semantic anchors that were then removed as self-evidence. After deduplication,
the selector now leaves that key's anchor contribution and initial eligible-index
list empty. The final pass still performs candidate eligibility, scoring, binary
priority, shaping and synthesis, and retains the same diagnostics. Additional
identities obtained by known-binary completion remain available to family voting;
they never supplied annotation anchors in this path.

| ID | Assumption | Basis / dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|
| S44 | Removing singleton anchor construction leaves final semantic weights empty and selection unchanged for a fixed storage state | `BatchAnchors::excluding` subtracts the sole source; `select_from_versions` independently performs final eligibility/scoring | Exact and unknown MD5s, no MD5, duplicates, shaping, synthesis/components enabled and disabled, all public diagnostics | `singleton_selection_matches_batch_without_external_evidence` compares against the normal two-key path with an absent second key; existing completion/holdout regressions | Confirmed by focused regression; broader validation recorded below |

Affected planes: selection CPU/allocation cost; HTTP coverage and function views,
both pull protocols and offline evaluators through the shared selector; tests and
guide. Configuration, transport/wire encodings, session policy, persisted identity,
record/history formats, mutation ordering, cache invalidation, search projections,
upstream handling and recovery formats are unchanged. No migration is required.
The existing nontransactional concurrent-read semantics remain; this does not
establish a snapshot across stores.

For V collected candidates, E eligible candidates and T anchor token occurrences,
the singleton removes one eligibility/scoring pass, one O(E log E) score sort,
and anchor map/set construction and token traversal. Final scoring and its
O(E log E) sort remain. Candidate discovery, record reads, metadata parsing and
their bounds are unchanged. Avoided temporary storage includes O(E) score/index
entries and O(T) anchor content; this is not a process-wide memory bound or a
claim that metadata is no longer parsed. Coverage amortizes the saving across
up to 8192 single-key selections per uncached binary.

Bounded findings: **high, unresolved**—general independent ranking accuracy is
unknown without conflicting labeled donor choices. **High, residual**—useful
startup still includes bounded but substantial per-binary coverage work; cold
performance and the 2 s useful-startup target remain unverified. **Medium**—native
hash generation is not currently validated under the isolated IDA configuration.

Validation: 67 library tests, 40 binary-selection tests, ten semantic-matching
tests, six neighbor tests, 13 startup/projection tests and one symbol-evaluation
CLI test passed (137 total). The server target compiled and ran zero unit tests.
The new parity regression exercises 48 combinations of synthesis, identifier
components, binary identity and requested metadata, each with single and repeated
keys and both diagnostic and wire-facing selection results. It compares every
public diagnostic and payload, with bitwise score/margin/entropy checks. Strict
Clippy for both roots, the profiling tool and affected integration targets passed;
formatting and whitespace checks passed. Existing manifest binary-name warnings
remain. README needs no change because CLI and product behavior are unchanged;
the guide now records the singleton optimization and its deduplication boundary.

Release profiling on the prepared copy retained all coverage values for binary
`cc835e8e71dbad02d0c8a77d9a7d4095`: 8192 sampled functions, 7983 typed, 8192 framed,
377 commented, 148 switches, 7286 demangled, no unavailable/fallback/partial rows,
and `truncated=true` for 23,849 total functions. Before/after isolated profile
timings were 4.017/0.794 s for seed coverage and 4.028/1.160 s for related binaries.
Those individual runs had different cache histories and do not establish a causal
speedup factor. Both profile runs and startup runs use only the prepared temporary
copy through `/tmp/dazhbog-review-benchmark.toml`; replay can write derived caches.

Three-run startup series immediately before and after the change used:
`node scripts/benchmark-startup.mjs target/release/dazhbog /tmp/dazhbog-review-benchmark.toml 29668 29667 3 warm`.
The OS cache was uncontrolled; no cold-cache claim follows.

| Measurement / s | Before: median (range) | After: median (range) |
|---|---|---|
| Metrics readiness | 1.534 (1.505–1.590) | 1.610 (1.438–1.638) |
| Full useful request set | 4.101 (3.964–4.125) | 3.697 (3.606–3.780) |
| Binary-detail request | 2.419 (2.412–2.525) | 2.131 (2.077–2.149) |

All runs returned 24 search hits and eight neighbors, completed function detail,
both protocol probes and binary detail, and shut down cleanly. The warm useful
latency decreased in this small series; this does not establish a causal percentage
improvement or cold latency. The requested 2 s useful-startup target remains unmet.
The semantic diff and guide were checked against the fixed-state equivalence
assumption, deduplication, completion, candidate diagnostics and synthesis paths.
No independent accuracy improvement is claimed for this performance change.

## Twenty-ninth implementation group: recover observed historical candidates

Baseline: `809e65b46c68a4882664ead2b77755469f457de3`, tracked tree clean. Owned
paths: `src/db/database.rs`, `src/engine/context_index.rs`,
`tests/binary_selection.rs`, `README.md`, `AGENTS.md` and this report.
Untracked `research/`, original `data/` and ignored configuration remain unchanged.

### Failure and correction

The existing selector preferred a binary's historical annotations only when they
were already in the candidate set. With a recent-version cap of one and a stale
last-observation pointer, an older annotation observed in the requested binary
was omitted even though its membership remained in `binary_versions`. A newer
unrelated annotation won. The new regression reproduced that failure before the
change and passed afterward for current and supported historical version IDs.

After ordinary candidate discovery, an explicit-MD5 query with a nonempty candidate
set and no retrievable last observation now reads at most 64 physical historical
membership rows for that binary/function. Additional IDs trigger one repeated
collection with those identities as targets. The first candidate payloads are
dropped before the second traversal. This extends candidate recall; eligibility,
weights, ranking, shaping and synthesis are unchanged. A missing current positive
observation does not invalidate independently stored historical membership.

Both supported version-ID encodings start with the 16 B function key in little
endian. `ContextIndex::binary_function_versions` uses the existing 32 B prefix
`binary MD5 || function key LE`. It requires each visited row to have a 48 B key
and an 8 B timestamp value. Timestamp zero remains valid historical membership,
as in `binary_has_version`. Malformed inspected rows return `InvalidData`.
The prefix is ordered by identity bytes, not timestamp. Alias rows consume the
physical limit separately; a prefix miss does not establish historical absence.

Hints cannot return payloads directly. The same live-chain reader enforces name
policy, record validation, alias matching, tombstones, cycle handling and the
4096-record bound on each traversal. At most two traversals occur for a requested
key; the second cannot reach beyond the original live interval. Exact retrieved
observations avoid the membership scan. Empty candidate sets, cap zero, no-MD5
requests and holdout selection also avoid it. The latter retains its requirement
for independent non-held-out provenance.

### Assumption register

| ID | Assumption | Basis / dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|
| S45 | Both supported stored version-ID formats begin with key-LE | `common/hash.rs`, pinned historical writer fixtures, `binary_version_key`; enables the existing-tree prefix lookup | Nontrivial 128-bit key, wrong key/binary, current and historical IDs | Literal storage-prefix unit test and the old-writer integration fixture on 64-bit little-endian hosts | Confirmed for supported formats; other historical platform encodings remain unknown |
| S46 | Independently stored historical membership is usable identity evidence when the current pointer is unavailable | Existing `version_observed_in` policy already accepts this evidence; change retrieves its payload candidates | Candidate outside recent cap and top-16 summary, malformed hints, zero timestamp, exact observation, unknown binary, duplicates, tombstone/reinsertion | New failing-before/passing-after regression plus scanner and scan-avoidance regressions | Confirmed retrieval behavior; independent relevance accuracy remains unknown |

### Change surface and resource cost

Affected: explicit-context candidate discovery, historical index reads, contextual
HTTP/coverage results and observed-binary evaluation, regression tests and guide.
Wire encodings, no-MD5 pulls, session policy, configuration, mutation ordering,
record/context/search schemas, canonical refresh, persisted projections, upstream
handling and recovery formats are unchanged. Existing key/binary invalidation
covers these target-key history dependencies; no auxiliary family keys are added
by this change. There is no migration, new persistent tree or startup scan.
Concurrent reads still do not constitute an atomic snapshot across stores.

Let V be the initial candidate count, H ≤ 64 the visited membership rows and
R ≤ 4096 the records reachable in one bounded live-chain walk. Checking the exact
candidate costs O(V) identity comparisons and uses already-loaded observations.
Fallback adds O(H) index-row visits, O(HV) alias comparisons and expected O(H)
set insertions. A retry adds at most R record reads and the collector's existing
per-record/statistics work. Thus both walks together read at most 8192 records
per key; repeated reads do not expand the allowed ancestry. Returned hint-vector
elements occupy at most 64 × 32 B = 2048 B = 2 KiB. The target and remaining-ID
sets add O(H) copied identities and allocator overhead. The
retained candidate bound increases by at most 64 identities before alias collapse;
record payload sizes remain variable and this is not a process memory bound.
Metadata analysis is still deferred until final eligibility and memoized there;
candidate statistics can be read again during retry.

### Bounded findings

- **High, residual:** if neither the latest nor historical binary-specific
  annotation is retrievable, a stale positive observation still suppresses the
  existing companion-key completion trigger. This group recovers available
  binary-specific evidence first; inferred-family recovery for the remaining case
  is still open.
- **Medium, recall:** the 64-row prefix and 4096-record live interval can omit
  historical candidates; lost payloads cannot be reconstructed from identity rows.
- **High, interpretation:** stored observations are not independent correctness
  labels. Earlier preparation may have promoted zero-count placeholders into
  historical membership; existing data cannot distinguish those from independent
  historical events. This change preserves the existing membership policy.
- **High, performance target:** useful startup below 2 s and cold-cache behavior
  remain unverified; this change adds bounded work only to explicit fallback.
- **High, scoring data:** `record_key_observation` starts a binary omitted from
  `top_md5s` at count one, then truncates a stable count sort. Repeated observations
  can remain omitted and increment `num_binaries` repeatedly. This can distort
  the popularity prior. The writer and already-stored inflation require separate
  treatment; this group uses historical identity independently of the summary.

### Validation

The failing-before/passing-after test uses a one-version recent cap, both supported
ID formats, and an older observed annotation outside its lossy top-16 binary
summary. It checks duplicate results, unchanged latest/canonical values, historical
fallback coverage, and deletion/reinsertion without resurrection. A separate test
puts malformed rows first in the history prefix: exact observations and disabled
collection succeed without inspecting them, while a fallback request reports the
malformation. No-MD5 and unrelated-MD5 requests are unaffected. Literal scanner
fixtures verify 64/65-row limits, zero-length requests, key/binary isolation,
zero timestamps and short matching keys.

The full run passed 68 library tests, 42 binary-selection tests, ten semantic
matching tests, six neighbor tests, 13 startup/projection tests and one symbol
evaluation CLI test (140 total). The server target compiled; it has no unit tests
in that invocation. Strict Clippy passed for both roots, the binary evaluator and
affected integration targets. The final focused test includes the extended
top-16 exclusion assertion; formatting and whitespace checks cover the final diff.
That assertion initially failed because the fixture had inserted the query binary
before filling the summary. It now fills the summary first and verifies exclusion.
The existing legacy-family test had the same unverified premise; its setup and
explicit assertion were corrected too. Both focused tests passed afterward.

`target/debug/eval-binary-context /tmp/dazhbog-review-benchmark.toml 8 32 1 observed`
completed on the prepared temporary copy with exit 0: 256/256 labeled cases had
their expected variant available and retrievable with explicit identity;
256/256 selections matched stored observations, including all 75 ambiguous
available cases. Latest matched 240 and canonical 247. All latest, canonical and
availability error counts and failed batches were zero. The sample is a bounded
compatibility check of observations, with no before/after causal or independent
accuracy claim. The available conflicting-label gap and the earlier startup
limitations remain. No original production data or private corpus was changed.

## Thirtieth implementation group: prevent repeated-upload diversity inflation

Baseline: `4bd28a8ab94303d318371ce8f18c014f354038a8`, tracked tree clean. Owned
paths: `src/engine/context_index.rs`, `tests/binary_selection.rs`, `README.md`,
`AGENTS.md` and this report. Original `data/`, ignored configuration and untracked
`research/` remain untouched.

### Reproducer and implementation

Sixteen initial binaries fill a version's retained summary. Ten observations from
a seventeenth binary produce 26 total observations but only 17 distinct binaries.
The baseline writer reported `num_binaries=26`: an omitted binary was repeatedly
treated as new. The regression failed with that exact discrepancy. After the
change it reports 17; a further observation after reopening reports 27 total
observations and still 17 binaries.

`record_version_observation` now updates the existing `binary_versions` and
`version_stats` trees in one sled transaction. Diversity increments only when
the binary/version history row is absent and the decoded summary has no positive
entry for that binary. The latter condition preserves evidence from legacy
summaries that predate the history index. A zero-count summary entry is not
positive evidence. The transaction independently returns whether a historical
row was newly inserted for the existing binary-metadata update.

Observation totals and retained summary counters increment within the same
transaction. Unsigned 32-bit counters saturate at 4,294,967,295; timestamp behavior
and byte layouts are unchanged. Undecodable version statistics and historical
timestamp values whose length is not 8 B return `InvalidData`; neither protected
row is silently replaced. The existing decoder's accepted legacy forms remain
accepted. This is not a new exhaustive validator for all plausible statistics.

Overlap invalidation now precedes the version transaction because a new validation
error can occur after earlier key/membership updates. Facet mutation fencing still
surrounds `record_key_observation`. The transaction is limited to two trees:
earlier key counters, membership and popularity updates can remain after failure;
later binary-metadata updates can fail after the version transaction commits.
Their existing cross-tree races are not fixed by this change. The concurrency test
asserts only the statistics/membership guarantees actually covered here. A successful
transaction is not a claim of power-loss durability without the applicable flush.

### Assumption register

| ID | Assumption | Basis / dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|
| S47 | For a fresh, continuously maintained stored version ID, historical pair membership distinguishes a repeated binary from a new binary | Existing `binary_versions` key includes MD5 and full version ID; distinct-count prevention depends on its continuity | More than 16 binaries, repeated omitted donor, reopen, zero summary counts, saturation, legacy summary without a history row | New diversity regression and transaction boundary test | Confirmed for fresh/tested states; missing legacy history and pre-existing inflation remain unknown |
| S48 | The two same-database trees commit together, and transaction retries repeat only local computation | Locked sled 0.34.7 `transaction.rs`, existing repository transactional usage, new pure closure | Eight concurrent writers, malformed history/statistics, independently preserved earlier key updates | New concurrent and abort regressions | Confirmed for tested process-visible behavior; no crash/power-loss test claimed |

### Selection effect and change surface

The serving regression isolates the diversity prior with `w_pop_bin=100`: one
annotation has 17 distinct donors and 50 further submissions from its omitted
donor; another has 20 distinct donors. The latter wins despite a canonical hint
favoring the repeated annotation. Explicit identity for the first annotation's
binary still selects it. This verifies that the diversity component follows
distinct membership rather than duplicate volume [S47]; it does not fit weights
or establish independent annotation accuracy. The observation-volume prior remains
separate and unchanged.

Affected planes: context mutation, per-version counters consumed by scoring and
canonical refresh on future writes, concurrent updates and error propagation,
overlap invalidation order, tests and guide. Configuration syntax/defaults, wire
encodings, session policy, record history, identity formats, retrieval bounds,
metadata synthesis, search schema/projection format, upstream handling and recovery
formats are unchanged. Existing context files remain readable; no migration,
preparation or startup scan is required. The code neither opens nor repairs the
production dump. Previously inflated aggregate values remain preserved.

For M decoded summary entries (M ≤ 255 from the encoded count), one transaction
attempt performs two point reads, O(M) searches/encoding, O((M+1) log(M+1)) sorting
and two point writes. The stored summary is truncated to 16 entries, as before.
Auxiliary CPU space is O(M), plus sled's transaction buffers. With A conflict
attempts, computation scales by A; the dependency's retry loop provides no fixed
latency bound. Fresh normal rows contain at most 16 entries. The statistics value
is 25 B + 20 B × retained entries, at most 345 B after a new write. The history
value remains 8 B under its existing 48 B key. Other observation-method work,
filesystem caches and durability costs are outside these bounds.

### Bounded findings

- **High, residual:** historical `num_binaries` inflation remains in existing
  stores and can still affect the popularity prior. Missing historical pairs,
  summaries and alias overlap prevent certifying an exact repair from the aggregate
  alone. This change prevents the demonstrated repeated-omission inflation going
  forward under [S47]; it does not certify historical cardinality.
- **Medium, unchanged:** retained summaries can still discard an omitted donor
  repeatedly at a count-one tie. They are neither complete provenance nor exact
  global frequency rankings; exact membership checks remain separate.
- **High, scoped atomicity:** key observation counters, binary metadata, raw
  append/latest/search updates and their failure/race behavior remain outside this
  two-tree transaction. Power-loss validation is not established by the live test.
- **High, objective limits:** independent conflict-label accuracy and useful
  startup below 2 s remain open. There is no startup or accuracy gain claim here.

### Validation and guide audit

The complete run passed 71 library tests, 43 binary-selection tests, eight database
integration tests, ten semantic-matching tests, six neighbor tests, 13 startup/
projection tests and one symbol-evaluation CLI test: 152 tests. The server target
compiled and ran zero unit tests. The new tests cover the exact failing baseline,
reopening, selection consequences, explicit-identity precedence, concurrent
observation totals and memberships, saturation, legacy positive/zero summaries,
corrupt-row preservation and the scope of partial updates on abort.

Strict Clippy passed for the library, server and the binary-selection, semantic,
neighbor, symbol-evaluation and startup/projection integration targets. The
extended strict check did not pass: unchanged `src/bin/recover.rs` has 41 existing
style lint errors (including `io_other_error`, `ptr_arg` and sorting/default
idioms), and unchanged `tests/database_integration.rs:23` has one
`field_reassign_with_default` error. A short-format rerun verified all 42 locations;
those files have no task diff. No lint suppression or incidental recovery-tool
rewrite was introduced. Database integration tests themselves passed.

Formatting and whitespace checks passed on the edited files. The guide/README
now distinguish new-writer prevention from historical counter repair and scope the
transaction to its two actual trees. The code audit traced the observation writer,
the diversity prior's population normalization, the unchanged encoded fields,
cache invalidation and pre/post-transaction failure points. All database writes
in this group occurred in disposable test fixtures; the production and prepared
copied dump were not opened. General annotation accuracy and repair
of old aggregates remain unproven.

## Thirty-first implementation group: complete context after stale observation failure

Baseline: `0f8fdec444a723b40f8d9e3d210b5c20091b8f1b`, tracked tree clean. Owned
paths: `src/db/database.rs`, `src/db/selection_tests.rs`,
`tests/binary_selection.rs`, `README.md`, `AGENTS.md` and this report. The original
`data/`, ignored configuration and unrelated untracked `research/` are preserved.

### Failure and acceptance criteria

A positive `key_md5` row previously prevented companion-context completion even
when neither its last-observed payload nor any observed historical candidate could
be retrieved. A singleton query then had no other function identity from which to
infer related binaries. This is distinct from historical candidate recovery: the
query binary may have no surviving annotated payload for the requested function.

The new regression has two candidate annotations, a stale positive query-binary
observation, two companion functions shared with donor A and one with donor B.
With a recent-version cap of one and the canonical/latest pointer favoring B,
the baseline selected `decode_pixels` instead of A's `_Z12parse_headerv`.
The focused baseline run failed with that exact difference. Acceptance requires
recovering A through companion identities, preserving explicit/historical identity
precedence, retaining the physical bounds and invalidating dependent coverage.
This fixture establishes the stated evidence policy, not independent name accuracy.

### Implementation and representation trace

The initial missing-observation completion and explicit/historical retrieval remain.
For an explicit MD5 outside holdout evaluation, if completion has not yet enumerated
the prefix, inspect the retrieved pools for exact or historical observation evidence.
A nonempty pool without either kind of evidence permits late completion. The helper
returns whether it enumerated the prefix, even if no positive identities were added;
the caller never repeats that enumeration in the same selection request.

If completion adds identities, rebuild leave-target-out family evidence with the
query binary excluded. For fallback pools only, previously untargeted donor last IDs
can trigger one additional history traversal. Existing candidate IDs remain targets,
so changing the family does not deliberately discard earlier candidates. Old payloads
are released before recollection. The usual live-history validator still controls
every candidate. Recompute support for all requested pools using the completed
family before building semantic anchors; exact/historical eligibility retains its
existing precedence. Companion annotations themselves never become semantic anchors.

`candidate_last_versions` centralizes the unchanged positive-observation and nonzero
ID checks. The common path does not retain a last-version map for every key. Its
new fallback flags use O(K) space. Late completion computes donor maps one key at a
time. Repeated context reads are not an atomic database snapshot; concurrent writes
retain the existing request-consistency limitations.

Coverage conservatively records companion-prefix dependencies for every selected
fallback, including stale positive observations and historical fallbacks. Cached
counts still describe only the requested coverage sample. This can invalidate more
historical-only entries than strictly necessary; it avoids silently retaining a
summary whose selection depended on an unsampled companion.

| Plane | Result / owning evidence |
|---|---|
| Selection and identity | Changed fallback admission and donor targeting in `select_unique_versions`; exact ID and alias matching unchanged |
| History / resource bounds | One conditional extra call to the existing validated collector; no tombstone or name-policy bypass |
| HTTP/UI and caches | Contextual consumers share the selector; `get_binary_facets` expands fallback dependencies; JSON and UI formats unchanged |
| Lumina / alternate RPC / session / upstream | No codec or handler changes; current wire requests still omit explicit MD5, so this new branch does not run for them |
| Mutation / recovery / persistence | No new writes, trees, layouts or migration; existing facet publication guards apply |
| Configuration / startup | No option/default change, startup scan or preparation requirement |
| Search / synthesis | Search schema and raw metadata unchanged; existing eligibility, shaping and synthesis consume the final pool |
| Concurrency | Existing non-snapshot reads retained; cache dependency regression exercises a completed mutation between reads |
| Tools / build / provenance | Evaluator uses the shared selector; library/server and affected integration targets validated as recorded below |

### Assumption register

| ID | Assumption | Basis / dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|
| S49 | With no retrievable explicit annotation, verified companion memberships are admissible evidence for the existing related-binary policy | Same evidence already used for missing observations; late completion depends on this policy, not on absence proving incompatibility | Stale pointer, cap one, singleton/duplicates/explicit companion batch, exact and historical bypass, no-MD5 and unknown binary | New stale-observation and malformed-context integration tests | Confirmed for policy mechanics; independent annotation accuracy remains unknown |
| S50 | Tracking the coverage prefix plus the completion prefix invalidates the demonstrated companion-dependent result | Existing facet mutation guards and per-key dependencies; new fallback dependency rule | Change donor membership of companions outside a one-function sample, without changing the target key/query-binary observation | `stale_observation_completes_context_and_invalidates_coverage_dependencies` | Confirmed for the tested mutation path; no atomic multi-tree read snapshot claimed |

### Bounds and complexity

Let K be distinct requested keys, P ≤ 128 inspected forward rows, D = 256 retained
donor memberships per informative key, C = 64 inferred donors per target, V the
candidate count, and R ≤ 4096 records in a single history walk. Completion happens
at most once per selection request. The existing degree check permits one excluded
query-MD5 row and fetches one overflow-detection row: at most D + 2 = 258 physical
membership rows per key during family construction, retaining no truncated vote.

The late family rebuild has at most K + P identities and E ≤ (K + P)D retained
edges. With B ≤ E distinct donor binaries, its sorting/tree aggregation costs
O((K + P)D log D + (K + P) log(K + P) + E log(B + 1)) CPU and O(E + K + P) space.
Per-target bounded donor selection costs O((D + C) log C), plus tree lookup costs.
New-target checking costs O(C(C + V)) comparisons; support assignment costs
O(CV) membership checks plus donor sorting and tree lookups. These reuse the
existing algorithms and bounds. Completed and original family structures can
coexist until selection finishes, so both must be included in peak memory.

At most three validated history walks occur for an affected key: initial discovery,
optional explicit-history retry, optional completed-family retry. Thus the absolute
record-read bound is 3 × 4096 = 12,288, compared with the prior 8192 maximum. Each
walk uses O(R) visited-address/version storage plus record bytes and retained
payloads. For configured recent cap L and N candidates before the last retry,
its wanted set contains at most N + C + 2 IDs (prior candidates, donor/explicit IDs,
canonical ID), and its output is conservatively bounded by min(R, L + N + C + 2).
This is a count bound, not a process-wide byte or latency bound. Old payloads are
dropped before the final walk; the cleared vector's capacity can coexist with the
new vector. No new network I/O or persistent write is added by selection.

### Bounded findings and objective limits

- **High, unchanged:** companion membership is heuristic evidence. No independent
  corpus presently supplies both correct and incorrect candidate names for the same
  function hash. General ranking accuracy remains unverified [S49].
- **Medium:** stale-observation fallback can add a third history walk. Bounded
  retrieval can still miss useful companion rows, donor IDs and older payloads.
  The change does not claim a latency improvement or unbounded recall.
- **Medium:** conservative facet dependencies can cause extra invalidation and
  surface malformed forward rows within the newly inspected prefix. Exact and
  historical selection themselves bypass that prefix when no fallback needs it.
- **High, unchanged:** useful startup ≤2 s and old diversity-counter repair remain
  open. This group changes neither storage preparation nor startup architecture.

### Validation

The complete affected run passed 154 tests: 71 library, 45 binary-selection,
eight database integration, ten semantic-matching, six semantic-neighbor,
13 startup/projection and one symbol-evaluation test. The server target compiled
and ran zero unit tests. No tests in this run were ignored or filtered out.

```sh
cargo test --locked --lib --bin dazhbog --test binary_selection \
  --test database_integration --test semantic_matching --test semantic_neighbors \
  --test startup_projection --test symbol_evaluation
cargo clippy --locked --lib --bin dazhbog --test binary_selection \
  --test semantic_matching --test semantic_neighbors --test symbol_evaluation \
  --test startup_projection -- -D warnings
rustfmt --edition 2021 --check --config skip_children=true \
  src/db/database.rs src/db/selection_tests.rs tests/binary_selection.rs
git diff --check
```

Strict Clippy passed for that scope. The preceding group's 42 pre-existing strict
lint failures in the untouched recovery tool/database integration test remain
outside this scoped lint claim; the full all-target lint gate was not rerun or
claimed passed. Compilation used rustc `1.100.0-nightly (f248f4038 2026-09-05)` and
Cargo `1.100.0-nightly (3c0b53475 2026-09-04)` on `aarch64-apple-darwin`, debug test
profile and the locked dependency graph. No cross-platform or release-performance
claim follows from these checks.

The expanded completion unit test verifies the forced stale path's 128-row cap,
deduplication, zero-count placeholders, empty/no-MD5 handling and holdout bypass.
The new integration tests verify the observed baseline failure, recovery beyond
the recent cap, singleton/duplicate/explicit-companion requests, donor-dependent
coverage invalidation outside the sample, deletion, exact/historical bypass of
malformed forward context, propagation when context is needed, zero-cap bypass
and unknown/no-MD5 selection. Existing suites cover legacy aliases, input/output
ordering, transfer invariance, synthesis/shaping, tombstones, corrupted ancestry
and browser selection paths.

On the inspected temporary prepared copy, the current debug evaluator completed:

```sh
target/debug/eval-binary-context /tmp/dazhbog-review-benchmark.toml 8 32 1 observed
```

All 256 labeled cases were available, reachable and selected consistently with
their stored observations; all 75 ambiguous available cases matched. Latest
matched 240 and canonical 247. Availability/latest/canonical errors and failed
batches were zero. This checks compatibility on a fixed bounded observation
sample; it does not establish independent accuracy or exercise a measured number
of stale-pointer fallbacks. Only the prepared temporary copy was opened for this
evaluation. Original production data was untouched.

The guide audit updated `AGENTS.md` sections 9.5/10.3 and the evaluation-context
contract to distinguish stale positive observations, conservative facet dependencies,
support recomputation and the additional history bound. README describes the same
behavior. The final source review traced both helper call sites, candidate eligibility,
holdout isolation, target exclusion, collector lifetime and facet invalidation.
Formatting/whitespace checks passed. General accuracy and the ≤2 s useful-startup
objective remain open; this semantic group is not a completion claim for the goal.

## Thirty-second implementation group: retain donors that contain the target

Baseline: `7a001ba6cc750027a77d76182c0cf98dd9018c27`, tracked tree clean. Owned
paths: `src/db/family.rs`, `tests/binary_selection.rs`, `README.md`, `AGENTS.md`
and this report. Original `data/`, ignored configuration and untracked `research/`
are preserved. The previous group made verified implementation/commit progress;
this group extends candidate discovery rather than changing scoring coefficients.

### Evidence and implementation

`BatchFamilyEvidence::excluding` previously retained only the globally strongest
64 inferred donors after removing the target's vote. Those slots could all belong
to binaries with no usable annotation for the requested function, while a weaker
related donor containing it was excluded. Existing targeted history discovery could
then never request that donor's older annotation.

The reproducer supplies a target, one companion observed in 64 stronger donors,
and another companion in 128 weaker donors. The target's related annotation comes
from one weaker donor; its latest/canonical annotation comes from an unsupported
binary. At recent cap one, the baseline returns `decode_unrelated_pixels` rather
than `parse_related_headers`. The new integration test failed with that difference
before the change. A separate unit regression failed because the relevant donor
was missing from the 64-entry result.

Selection now preserves the global top 64 and supplements it with up to 64
additional donors from the target's already-loaded positive membership list.
Supplemental weights subtract the target's contribution and use the same
leave-target-out denominator. Donors with no remaining evidence receive no slot.
Each supplemental donor must have evidence from another query/context key; target
membership is only an admission hint [S51]. Equal weights use the existing MD5
ordering. Existing selected donors are excluded from the additional heap, so their
mass is counted once. Omitted mass is not renormalized.

The original shortlist is retained because missing reconstructed membership does
not prove that a donor never contained the target. Missing/over-limit target
membership gives no supplemental list. Positive checks, physical degree limits,
query-MD5/holdout removal, explicit-version precedence, alias matching and history
validation remain with their existing owners. No extra storage enumeration is
needed to discover the additional donors: the family already loaded these rows.

Aggregate vote totals now live in `BinaryInfluence.total`; global sorting and
supplemental point lookup use that same value. The former separate aggregation
`BTreeMap` is removed. Source-key iteration and addition order remain unchanged.
Candidate collection, support assignment, anchors and response shaping continue
through the shared selector, using the expanded donor map. Latest/canonical/raw
records are not rewritten. This policy needs no schema migration or startup scan.

### Assumption register and change surface

| ID | Assumption | Basis / dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|
| S51 | Positive target membership is a useful bounded donor-admission hint when other-key evidence exists | Existing verified membership index; expansion depends on this retrieval policy, not annotation correctness | Irrelevant global donors, cap-one history, donor with only a self-vote, 128-result cap, ties, input order, exact identity | New unit/integration regressions and exhaustive leave-one-out oracle | Mechanics confirmed; general accuracy remains unknown |

Affected planes are candidate discovery/ranking, transient family memory, downstream
history work, diagnostics and serving consumers of the shared selector. Both wire
protocols can benefit through their key batches; wire bytes, session policy and
upstream handling are unchanged. HTTP contextual selection shares the same policy.
Facet dependencies already contain requested/completed keys, including the target
whose membership supplies the additional hint; no new dependency category is added.
Configuration syntax/default values, persistence, recovery, identity formats, search
schema/projection and metadata serialization are unchanged. Holdout filtering still
precedes family construction. Build validation covers the library/server and affected
integration consumers; no platform-support expansion is claimed.

### Bounds, calculations and tests

For D ≤ 256 retained target memberships, B distinct inferred binaries and C = 64
slots per list, supplemental selection uses O(D log B + D log C) CPU and O(C)
heap space. It adds no storage reads itself. Together with existing global selection,
per-target CPU is O((D + C) log C + D log B), excluding family construction. The
returned map has at most 2C = 128 entries. Family aggregation remains O(E log B)
for E membership edges, now updating one tree instead of two; the influence tree
retains one additional f64 total per binary. Global ranked storage remains O(B).

Downstream donor lookups/support assignment can now process 128 rather than 64
donors. With configured recent cap L, initial retained candidates are bounded by
min(4096, L + 130): up to 128 inferred IDs, one explicit ID and one canonical hint.
The separate explicit-history retry can add at most 64 target IDs, giving the
conservative bound min(4096, L + 194). The stale-context retry described in group 31
still adds at most one walk and reuses its formula with C = 128. The maximum remains
three walks × 4096 = 12,288 record reads per key; more targets may make an existing
walk longer. Payload memory is additional to these entry counts. No latency or
process-wide memory reduction is claimed.

The simple unit oracle expects each of 64 global donors to retain weight 1/128,
and the additional relevant donor to retain 1/256. Total selected mass is therefore
64/128 + 1/256 = 0.50390625, with the omitted mass left omitted. The cap/tie test
retains 64 global plus 64 supplemental donors, mass 0.75, excludes the self-only
donor, and preserves results after input reversal and duplicate source rows.
The exhaustive oracle removes each target physically before summing votes, then
independently sorts the two admitted sets. Integration verifies older-candidate
recovery, duplicate/permuted query keys, singleton fallback, explicit identity and
unchanged latest/canonical annotations.

### Copied-dump evaluation and limitations

Before and after the change, the following command completed on the same inspected
prepared temporary copy, without concurrent database processes:

```sh
target/debug/eval-binary-context /tmp/dazhbog-review-benchmark.toml 32 64 2 transfer
```

Both runs report 2048 labeled cases, 1203 available expected annotations, 1047 exact
selections, 525 ambiguous available cases and 369 exact selections among those.
The remaining 845 cases lack proven sharing outside the held-out binary. All
availability/latest/canonical error counts and failed-batch counts are zero.
Conditional agreement is 1047/1203 ≈ 87.0%; ambiguous conditional agreement is
369/525 ≈ 70.3%. Aggregate counts did not improve or regress in this sample.
Latest/canonical full-corpus diagnostics matched 1728/1801 observations respectively;
they retain held-out information and are not fair transfer baselines.

This sample motivated inspection but supplies no independent correctness labels.
Observed disagreements include names differing by suffix, differing type metadata,
and comments present in only one annotation. None alone proves which annotation is
correct. The new structural regression demonstrates the corrected exclusion case;
the copied-data result does not establish how frequently it occurs or an accuracy
gain. No coefficient or threshold was fitted to these observations.

### Bounded findings

- **High, unresolved:** independently labeled conflicting candidates remain absent.
  The 156 available transfer disagreements require stronger labels before claiming
  an accuracy improvement or changing weights to favor their stored observations.
- **Medium:** expanded donor maps can increase history and support-assignment work.
  Physical history bounds remain, and incomplete/over-limit provenance can still
  prevent donor discovery. Membership is not proof of a surviving payload [S51].
- **High, unchanged:** old inflated diversity counters and useful startup ≤2 s remain
  open. This group neither repairs counters nor improves startup architecture.

### Validation and guide maintenance

The complete affected run passed 157 tests: 73 library, 46 binary-selection,
eight database integration, ten semantic-matching, six semantic-neighbor,
13 startup/projection and one symbol-evaluation test. None were ignored or filtered
out. The server target compiled and ran zero unit tests. The focused unit and
integration reproductions both failed before implementation and passed afterward.

```sh
cargo test --locked --lib --bin dazhbog --test binary_selection \
  --test database_integration --test semantic_matching --test semantic_neighbors \
  --test startup_projection --test symbol_evaluation
cargo clippy --locked --lib --bin dazhbog --test binary_selection \
  --test semantic_matching --test semantic_neighbors --test symbol_evaluation \
  --test startup_projection -- -D warnings
rustfmt --edition 2021 --check --config skip_children=true \
  src/db/family.rs tests/binary_selection.rs
git diff --check
```

Scoped strict Clippy, formatting and whitespace checks passed. Full all-target
Clippy was not rerun: the previously recorded 42 pre-existing errors in unchanged
recovery/database-integration files remain outside this claim. Validation uses the
locked dependency graph and debug profile; no release timing, cross-platform,
container or independent corpus accuracy claim is made.

The post-change observed-mode compatibility run (`8 32 1 observed` with the same
temporary configuration) also passed: all 256 expected annotations were available,
reachable and selected, including all 75 ambiguous available cases. Latest matched
240 and canonical 247, with zero diagnostic errors or failed batches. As above,
these are stored-observation agreement counts. The original production data was
not opened; evaluator opens were restricted to the prepared disposable copy.

`AGENTS.md` and README now describe the two 64-entry lists, the 128-donor bound,
self-vote exclusion, retained legacy fallback, shared aggregate totals and the
consequent candidate-discovery bound. The final source audit traced family
construction, initial and completed-context donor maps, history target formation,
support allocation, explicit eligibility, holdout filtering and cache dependencies.
No persistent schema or preparation contract changes. Independent conflicting-label
accuracy and the ≤2 s useful-startup requirement remain open.

## Thirty-third implementation group: avoid ranking exact heads for coverage

Baseline: `d9f0cb2d6ec9f403461b8226bd38089d536ddbf0`, tracked tree clean. Owned
paths: `src/db/database.rs`, `src/db/selection_tests.rs`,
`tests/binary_selection.rs`, `README.md`, `AGENTS.md` and this report. The production
`data/`, ignored configuration and untracked `research/` are preserved. The prior
turn made verified implementation/commit progress. This group addresses the cost
of obtaining useful contextual binary results after startup.

### Mechanism and acceptance criteria

Coverage previously ran the complete single-key selector for every function,
including an exact observed head. That path collected candidates, built context,
computed fingerprints and scores, copied the selected payload and then parsed it
again for coverage. An exact observed identity already determines eligibility;
coverage does not consume ranking diagnostics. The accepted optimization must
preserve coverage fields, selection fallback, visibility policy and cache invalidation.

Coverage now reads a positive last-observation row and, when its ID is nonzero and
the configured candidate cap is nonzero, probes exactly one physical history record.
The existing collector is factored through `collect_versions_bounded`, whose
physical budget is clamped to 4096; ordinary collection still uses that maximum.
The one-record probe shares header/CRC/structure validation, function-key checks,
name policy, tombstones, current/legacy ID calculation and statistics loading.
It does not initialize the candidate's memoized semantic analysis.

If the accepted head matches the observation, coverage consumes its raw name/data,
parses metadata once and marks it as an exact result [S52]. No synthesized payload
is possible in this path. A nonmatching, rejected, deleted or unavailable head
falls back to the unchanged full selector. Missing/zero-count observations and a
zero configured cap skip the probe. The probe counts rejected physical records;
it cannot silently walk an entire rejected chain before fallback.

This is deliberately demand-driven validation. An exact hit does not enumerate
unneeded family observations, so unrelated malformed family rows no longer prevent
that coverage result. The full selector and fallback still expose those errors.
Raw head validation is not relaxed. Scoring metrics now count only selector calls
actually executed; fast coverage hits do not contribute scoring batches/versions/time.
Response fields, percentages, sampled-key denominators and cache keys are unchanged.

### Assumption register

| ID | Assumption | Basis / dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|
| S52 | In a fixed valid store, the accepted head matching a positive current/legacy version identity is the annotation selected by explicit eligibility | Existing identity/alias contract and current-version deduplication; coverage fast path depends on it | Current/legacy IDs, synthesis enabled, caps 0/1/16, older/stale IDs, rejected/deleted heads, partial metadata | New coverage parity fixture against the full public selector; copied-data feature comparison | Confirmed for tested states; existing noncryptographic identity and concurrent-read limitations remain |
| S53 | Warm repeated runs on the prepared copy describe this local workload, without establishing cold or deployment latency | Explicit loopback configuration, owned child lifecycle and successful operations | Three release runs before/after; retain all observations including outliers | Startup harness output and phase profiler | Retained measurement scope; cold-cache behavior unknown |

### Change surface and bounds

Affected planes: contextual coverage computation, shared collector factoring,
read work/memory, demand-driven validation and scoring-metric accounting.
The HTTP binary detail/related/comparison paths benefit through existing coverage
calls. Stored annotations, latest/canonical pointers, search projection, observation
formats, recovery, protocol encodings, query scoring coefficients, synthesis and
configuration defaults are unchanged. There is no new persistent cache, schema
migration or startup preparation step. Normal selector diagnostics and wire pulls
retain their existing path. The facet generation token, mutation guards and key
dependencies still surround both fast and fallback computation.

For K sampled functions, at most K ≤ 8192 preliminary record reads are added.
An exact head costs one validated record read, existing point lookups, hashing and
name validation, then one metadata parse and coverage projection. If its name and
metadata occupy B bytes, byte processing is O(B) plus existing decoder/demangler
costs; one record payload and parsed metadata coexist. No family map, semantic
fingerprint or score vector is constructed for that hit. The ordinary collector's
visited-address set is bounded to one entry in the probe.

A missed probe releases its candidate before full selection. Worst-case coverage
now performs 1 + 3 × 4096 = 12,289 record reads per function, compared with the
selector's unchanged 12,288. The improvement is a common-case reduction, not a
new whole-process byte/latency bound. No background task or extra runtime is added.
Read consistency is unchanged: a concurrent mutation can affect a returned
uncached result, while the generation guard prevents publishing stale cache state.

### Behavioral validation

The coverage parity fixture passed before and after implementation. It compares
full-selector names and aggregate coverage for current/legacy exact heads, an
older exact observation, stale historical fallback, a rejected head, a tombstone,
partial metadata, synthesis enabled and caps 0/1/16. It checks every feature count,
unavailability, fallback count and truncation. The internal collector regression
checks one physical rejected record, zero budgets, normal older-version recovery,
uninitialized semantic analysis and rejection of a foreign-key head.

A separate error-boundary fixture verifies that exact coverage does not read corrupt
unneeded family observations, while fallback does. Its first version failed during
offline preparation, which correctly rejects malformed observations. The fixture
was corrected to prepare valid data first and introduce corruption afterward;
the focused corrected test passed. A broader run already using the earlier test
binary also reported that same fixture failure; the final integration rerun uses
the corrected fixture. No production behavior was changed to bypass preparation.

### Release measurements

Both versions are built with `cargo build --locked --release --bin dazhbog
--bin profile-binary` using the manifest's optimized release profile. Host:
Apple M4 Max, aarch64, macOS 27.0, 137,438,953,472 B RAM = 128 GiB. Toolchain:
rustc `1.100.0-nightly (f248f4038 2026-09-05)`, Cargo
`1.100.0-nightly (3c0b53475 2026-09-04)`. Data is the existing prepared disposable
copy under `/tmp/dazhbog-review-snapshot-20260915`, with explicit loopback ports
29668/29667 and no upstreams in `/tmp/dazhbog-review-benchmark.toml`.

```sh
node scripts/benchmark-startup.mjs target/release/dazhbog \
  /tmp/dazhbog-review-benchmark.toml 29668 29667 3 warm
target/release/profile-binary /tmp/dazhbog-review-benchmark.toml \
  cc835e8e71dbad02d0c8a77d9a7d4095
```

The harness requires successful search, detail, neighbors, binary overview, RPC
pull and Lumina hello before recording useful startup, and verifies owned-child
shutdown. Its polling interval is 0.010 s. Runs are `warm-uncontrolled`, not OS-cache
purged; local activity/cache state are not controlled causal factors [S53].

Baseline ready times were 1.995, 1.705 and 1.688 s; useful times were 13.211,
3.875 and 3.832 s. Medians: ready 1.705 s, useful 3.875 s. The first outlier remains
in the reported range. Binary overview phase times were 10.856, 2.160 and 2.134 s.
The sequential baseline profiler measured open 1.874 s, summary/facets 0.835 s,
functions 0.016 s, related 1.264 s, graph 0.0004 s and timeline 0.159 s. Later phases
reuse earlier caches and are not independent cold timings.

The initial candidate benchmark's final output was unavailable after session
compaction; its process handle had expired. Process and listener inspection found
no remaining benchmark/server before another complete three-run invocation. The
following values are from that additional invocation, which completed with exit
status 0 and verified clean child shutdown. The inaccessible invocation is not
included in the numerical comparison; its extra cache warming is uncontrolled.

| Candidate run | Ready (s) | Useful (s) | Binary overview (s) | Search (s) |
|---|---:|---:|---:|---:|
| 1 | 2.421623417 | 11.185003000 | 8.458245250 | 0.304615542 |
| 2 | 1.707131625 | 2.947787750 | 1.230139084 | 0.010097625 |
| 3 | 1.645971167 | 2.906945958 | 1.251289583 | 0.009433125 |

Candidate medians were ready 1.707 s and useful 2.948 s. The useful-startup
median difference was 3.875087583 s − 2.947787750 s = 0.927299833 s,
or 23.9% of baseline. Binary overview medians were 2.159646625 s and
1.251289583 s, a 42.1% difference. These descriptive comparisons do not isolate
the change from filesystem cache/local activity; three samples do not establish
tail latency or a confidence interval [S53]. Both first-run outliers are retained.
The candidate still fails the useful-startup ≤2 s target even in this warm sample.

The candidate sequential profiler completed successfully: open 1.646 s,
summary/facets 0.484 s, functions 0.016 s, related 0.763 s, graph 0.0003 s and
timeline 0.149 s. All coverage fields matched baseline except the expected cache
timestamp: 8192 examined keys, key limit 8192, truncated true, 7983 typed,
8192 framed, 377 commented, 148 switch, 7286 demangled, zero partial parses,
zero fallback and zero unavailable functions. The binary contained 23,849
functions. This confirms projection parity on the sampled binary, not all data.

### Final validation and guide maintenance

The final runs passed 160 tests: 74 library tests and 86 integration tests
(48 binary-selection, eight database integration, ten semantic-matching,
six semantic-neighbor, 13 startup/projection and one symbol-evaluation).
The server target compiled and ran zero unit tests. The corrected integration
rerun passed all six integration targets after the fixture failure recorded above.

```sh
cargo test --locked --lib --bin dazhbog --test binary_selection \
  --test database_integration --test semantic_matching --test semantic_neighbors \
  --test startup_projection --test symbol_evaluation
cargo test --locked --test binary_selection --test database_integration \
  --test semantic_matching --test semantic_neighbors --test startup_projection \
  --test symbol_evaluation
cargo clippy --locked --lib --bin dazhbog --test binary_selection \
  --test semantic_matching --test semantic_neighbors --test symbol_evaluation \
  --test startup_projection -- -D warnings
cargo build --locked --release --bin dazhbog --bin profile-binary
rustfmt --edition 2021 --check --config skip_children=true \
  src/db/database.rs src/db/selection_tests.rs tests/binary_selection.rs
git diff --check
```

Scoped strict Clippy, release compilation, formatting and whitespace checks passed.
The previously reported all-target Clippy debt remains outside this claim; no
cross-platform or container validation was performed. The final source audit
traced head validation, current/legacy identity, explicit eligibility, fallback,
metadata projection and cache generation/dependencies. `AGENTS.md` and README now
record the coverage shortcut, physical read bound, demand-driven error boundary
and changed scoring-metric accounting. No migration or preparation changes apply.

### Bounded findings

- **Medium:** workloads dominated by older/stale observations pay an extra probe;
  the one-record limit bounds this overhead. Exact coverage intentionally does not
  certify unrelated context-store integrity.
- **High, unchanged:** independent ranking accuracy and cold useful startup ≤2 s
  remain unverified. This optimization changes coverage work, not ranking policy.
- **High, unchanged:** old diversity-counter inflation and cross-store mutation
  consistency are outside this group; no data repair or atomic snapshot is claimed.

## Thirty-fourth implementation group: preserve concurrent per-key evidence

Baseline: `d195a585982686ca08e0352ff09ff2aff046eb1c`, tracked worktree clean;
the prior goal turn completed and pushed a measured coverage optimization.
Owned paths: `src/engine/context_index.rs`, new
`src/engine/context_index/observation.rs`, `AGENTS.md`, `README.md` and this report.
Production `data/`, ignored configuration and unrelated `research/` are untouched.
Validation uses newly created disposable databases only.

### Evidence, mechanism and acceptance criteria

`record_key_observation` previously read and wrote five related trees separately.
Concurrent submissions could overwrite observation increments, replace the forward
and reverse last-version pointers in different orders, lose summary updates and
leave multiple popularity rank entries. Malformed observation/summary rows were
silently replaced with defaults. Popularity used an unchecked u32 sum and sliced
a stored value before checking its length. These fields supply explicit binary
identity, membership, binary-function ordering, related-binary overlap, basename
resolution and popular-key results. They are evidence bookkeeping, not independent
correctness labels or calibrated relevance probabilities.

An omitted per-key summary donor also restarted at count one on every upload,
even while its complete per-key observation row accumulated evidence. A bounded
fixture of 16 donors observed twice, followed by a seventeenth observed four
times, left the seventeenth absent. Its correct retained count is four, and the
top-16 sum is 4 + 15 × 2 = 34 observations. This affects the summary projection;
the main family inference already enumerates full positive membership rows.

The new private module implements one sled transaction across `key_md5`,
`binary_functions`, `key_bins`, `pop_val` and `pop_rank`. Both observation counters
increment with saturation; supplied IDs and arrival timestamps update together.
A missing ID preserves the prior ID in each row. Existing inconsistent legacy
counts are incremented separately rather than summed or silently reconciled [S54].
The transaction returns whether the reverse membership row was newly inserted,
which drives the existing separate binary metadata increment.

The summary uses the greater of the incremented retained count and the updated
forward observation count. A returning omitted binary can therefore compete with
its accumulated evidence. Sorting retains the existing stable arrival-order tie
policy and the 16-entry cap. Popularity remains a nondecreasing retained-summary
projection; its sum now saturates at 2^32 − 1 = 4,294,967,295 observations. Existing
inflated values, orphan rank rows and missing legacy observations are not repaired.

Undecodable observation/summary values and popularity values not exactly 4 B abort
without modifying the five transaction-owned trees. Existing decoder acceptance
is preserved for observations/summaries, including tolerated trailing bytes; this
is not a comprehensive format validator. Storage errors propagate from the helper.
The database push caller continues to log context errors under its existing
partial-success policy. Other stores may already have changed.

Acceptance criteria: preserve every completed concurrent increment for consistent
input rows; update paired identity and rank projection atomically; let a returning
summary donor recover its count; reject malformed state without replacing it;
saturate counters; preserve old formats, tie policy, unknown-ID behavior and legacy
counter discrepancies; retain the observation method's cache guards.

### Assumption register

| ID | Assumption | Basis / dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|
| S54 | Existing forward, reverse and retained counters may describe overlapping but unreconstructible observations | Prior nontransactional writers and incomplete legacy stores; no summation/repair is inferred | Seed divergent counts and IDs; a retained count stronger than the forward row | `legacy_counts_are_not_summed_or_silently_repaired` checks exact increments, preserved IDs and summary maximum | Retained compatibility policy; historical truth unknown |
| S55 | The locked sled transaction serializes the five trees on this database and may retry its closure | Inspected sled 0.34.7 `transaction.rs`, `Transactional::transaction`, tuple implementation and commit path | Eight barrier-released threads, two per binary, 400 observations on one key | Assert 100 observations per pair, byte-identical forward/reverse rows, four summary counts of 100 and one rank of 400 | Confirmed for exercised interleavings; no crash/power-loss or deployment throughput claim |

### Change surface, complexity and failure boundaries

Affected: context mutation, concurrency, retained summaries, popularity projection,
error handling and cache invalidation order. Selection equations, candidate limits,
wire fields, configuration, segment/latest/canonical formats, search schema,
recovery parsers, startup and upstream forwarding are unchanged. HTTP and selection
consumers read the same representations. Library and server roots both include the
new module. No migration, offline preparation or startup scan is required.

For C decoded summary entries, one transaction attempt performs O(C log C) CPU
work for stable sorting and O(C) temporary storage, plus a constant number of
point reads/writes. The one-byte encoded count bounds C ≤ 255; insertion makes
at most 256 temporary entries, and output retains at most 16. Ordinary current
rows start with C ≤ 16. Five trees are accessed, with at most six row writes/removals
when popularity changes. If conflicts require R attempts, these costs multiply
by R; no bounded contention latency or throughput gain is claimed [S55]. There
is no network I/O, scan, user callback or external side effect in the closure.

The facet mutation guard still surrounds the complete method. Overlap invalidation
now follows the paired-evidence transaction before basename recording, so a later
basename/version failure does not bypass that invalidation. As before, overlap
deletion errors are ignored. Version membership/statistics use their separate
two-tree transaction afterward. Binary metadata increments and aliases remain
separate operations. Readers performing multiple independent reads do not gain a
snapshot. Failures or interruption between stages can leave partial overall push
state; a returned success does not by itself establish power-loss durability.

### Regression evidence and validation

Four new tests were executed against the unchanged writer before implementation.
All failed: the concurrent test observed 93 instead of 100 for a binary; the
omission test retained donor zero rather than donor sixteen at the head; corrupted
evidence returned success; and popularity addition panicked on overflow. These
same four tests passed after the transaction change. An additional legacy fixture
checks the deliberate no-repair boundary and reverse-row insertion result.
The omission fixture flushes and reopens storage before checking retained evidence.
The corruption fixture snapshots all five trees for malformed values in each of
the four decoded stores and verifies byte-for-byte preservation after failure.

The complete affected run passed 165 tests: 79 library, 48 binary-selection,
eight database integration, ten semantic-matching, six semantic-neighbor,
13 startup/projection and one symbol-evaluation. None were ignored or filtered.
Both library and server roots compiled; the server ran zero unit tests.
Scoped strict Clippy, formatting and whitespace checks passed.

```sh
cargo test --locked --lib --bin dazhbog --test binary_selection \
  --test database_integration --test semantic_matching --test semantic_neighbors \
  --test startup_projection --test symbol_evaluation
cargo clippy --locked --lib --bin dazhbog --test binary_selection \
  --test semantic_matching --test semantic_neighbors --test symbol_evaluation \
  --test startup_projection -- -D warnings
rustfmt --edition 2021 --check --config skip_children=true \
  src/engine/context_index.rs src/engine/context_index/observation.rs
git diff --check
```

These are local debug-profile results on the previously recorded Apple M4 Max /
macOS / Rust nightly host and locked dependencies. Full all-target strict Clippy
was not rerun because the recorded unrelated recovery/database-integration debt
remains. Release throughput, crash injection, cross-platform and container checks
were not performed; no claims depend on them. The existing startup measurement
is not relabeled as a measurement of this writer change.

The final review traced the database push caller, both observation transactions,
metadata-count increment, summary readers, preparation, cache guards and module
inclusion. `AGENTS.md` now distinguishes per-key and per-version summary behavior,
records the five-tree ownership and failure boundary, and lists the new module.
README states the transactional behavior and no-repair/no-migration scope.

### Bounded findings

- **High, unchanged:** binary metadata read/modify/write operations, basename
  aliases and separate version/record/search stages are not one transaction.
  Existing inconsistencies remain possible outside the five-tree boundary.
  This limits whole-push consistency claims, not the scoped transaction tests.
- **Medium:** hot keys can cause transaction retries; write throughput under
  production contention remains unknown. The per-version top-16 summary still
  lacks a complete per-binary/version counter and retains its prior lossy behavior.
- **High, unchanged:** independent conflict-label ranking accuracy and useful
  startup ≤2 s remain unproven. This group strengthens stored evidence rather
  than asserting a measured accuracy or startup improvement.

## Thirty-fifth implementation group: recover suffixed Swift vocabulary

Baseline: `27f303764bb9aa26abccbcd38bd0dc313ab3a1ed`, tracked worktree clean.
The previous turn completed and pushed the per-key transaction fixes. Owned
paths: `src/db/anchors.rs`, `tests/binary_selection.rs`, `AGENTS.md`, `README.md`
and this report. Production `data/`, ignored configuration and untracked
`research/` remain untouched. Corpus evaluation opens only the existing prepared
temporary copy. A temporary Cargo probe source was removed after execution;
standalone compiler inputs/objects under `/tmp` are not repository deliverables.

### Revalidated evidence and independent symbol probe

A fresh baseline transfer run (`32 64 2 transfer --all-cases`) found the same
2048 labeled cases, 1203 available references and 1047 exact selections as the
earlier sample. Among 156 available disagreements, 154 selected a variant with
strictly stronger inferred-binary match, two tied within 1e-12, and none selected
a weaker match. Forty-six disagreed in name. These are retrospective observations;
they do not prove the stronger donor wrong and do not justify tuning a coefficient
to prefer those labels. Several annotations carry numeric symbol suffixes.

The locked razgad 1.0.0 demangler already recovers useful names from the tested
Itanium/MSVC decimal suffixes, but rejects the tested Swift suffix. For example,
`$s6Orchid7processyS2iF` demangles while `$s6Orchid7processyS2iF_0` does not. Existing
component splitting sees encoding text such as `Orchid7processy`, losing the
separate `orchid` namespace token. The same issue can affect either a candidate
or another function supplying batch context.

The symbol spelling was independently checked using Apple Swift 6.4
(`swiftlang-6.4.0.34.1 clang-2100.3.34.1`, target arm64-apple-macosx27.0.0).
An original source fixture contains:

```swift
public func process(_ value: Int) -> Int { value &+ 1 }
public func dispatch() {}
```

Compiling separately with module names `Orchid` and `Cobalt` produced the symbols
`_$s6Orchid7processyS2iF`, `_$s6Orchid8dispatchyyF` and corresponding `Cobalt` names,
verified with `nm`. `xcrun swift-demangle --compact` rendered the undecorated
process symbol as `Orchid.process(Swift.Int) -> Swift.Int` and left its `_0` spelling
unchanged. Reproduction uses `xcrun swiftc -parse-as-library -module-name Orchid
-emit-object INPUT.swift -o OUTPUT.o` and repeats with `Cobalt`.

Suffix provenance was separately inspected in the local primary source
`/Users/int/hexrays/ida/base/name.cpp`: collision resolution near lines 2393–2450
appends an underscore and a decimal counter to an occupied name. No IDA source
implementation is copied into this repository. This does not establish that every
similarly spelled stored name arose from that mechanism [S56]. The fixture verifies
symbol spelling and namespace extraction, not Lumina function hashes or blind
annotation accuracy; integration function keys remain constructed test identities.

### Change, assumptions and acceptance criteria

With `batch_identifier_components` enabled, transient selection fingerprints now
try bounded suffix recovery for an unclassified name with a recognized Swift
spelling prefix. Inputs exceeding 4096 B are skipped. At most four trailing groups
of `_` plus nonempty ASCII digits are removed, with a demangle attempt after each.
The first successfully demangled Swift prefix supplies additional lexical whole
words and components [S56]. A nondecimal/empty group stops recovery. No integer conversion
is needed for the decimal text. Already language-classified symbols are unchanged.

The new words enter selection name/aggregate tokens only. Original fingerprints,
language classification, quality scores, raw names/data and version IDs stay intact.
The independent whole-token accumulator still controls exceptions to inferred
binary priority. Neighbor component fingerprints do not use this recovery helper.
One-distinct-key selection still skips batch anchors. Disabling identifier
components reproduces the prior behavior for this evidence source.

| ID | Assumption | Basis / dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|
| S56 | A successfully decoded Swift prefix preceding bounded decimal suffix groups supplies useful lexical context without establishing identical function identity | Compiler-confirmed names, Swift demangler probe and inspected IDA collision mechanism; transient ranking vocabulary depends on this interpretation | Malformed/Unicode suffixes, valid underscore-containing symbols, four/five suffixes, 4096/4097 B, Mach-O spelling, disabled option, conflicting binary identity | New unit and selection regressions; copied-corpus evaluation | Mechanics confirmed; general annotation accuracy and suffix origin remain unknown |

Acceptance criteria: recover namespace words for both source and candidate symbols;
prefer the corresponding annotation when lexical context is the deciding evidence;
preserve exact donor name/data, explicit identity, stronger inferred binary priority,
canonical/latest behavior, disabled mode, duplicates/order, bounds and original
fingerprints. No new weight, probability interpretation or observation rewrite is
introduced.

### Change surface and bounds

Affected: transient batch semantic vocabulary and ranking within eligible candidates.
Configuration syntax/defaults, transport and both protocol encodings, session policy,
push/storage/history formats, identity, synthesis, canonical/search projection,
HTTP shapes, upstream/recovery, donor inference and physical retrieval limits are
unchanged. There is no schema migration, preparation pass or startup scan. Both
library/server roots compile the helper through the existing `db::anchors` module.

Let B ≤ 4096 be inspected name bytes, R ≤ 4 suffix removals, D(B) the existing Swift
demangler's maximum per-call work for inputs up to B bytes, L its returned text
length and T the resulting token count.
Added work is O(R × (B + D(B)) + L + T log T), with token sorting/deduplication;
this expression does not assume the demangler is linear or that L ≤ B. Memory
includes one recovered display and the expanded tokens in addition to the existing
fingerprints. Already classified/non-Swift/oversized names perform only guard work;
malformed suffixes stop early. Existing per-source unit-mass normalization and
target exclusion still apply. There are no new storage/network operations or locks.

### Behavioral validation

Before implementation, the new unit fixture failed because `orchid` was absent
from the transient name tokens, and the new selection fixture chose the newer
canonical `Cobalt` annotation despite `Orchid` context. Both passed after the
change. Expanded tests cover source and candidate decoration, Mach-O names,
one/four/five suffix groups, empty/nondecimal/Unicode groups, malformed Swift
prefixes, 4096/4097 B, valid original identifiers, existing C++ demangling,
unchanged original/neighbor fingerprints, component ablation, singleton requests,
duplicate/permuted keys, explicit identity, stronger inferred donor evidence,
unchanged latest/canonical names and exact returned name/payload identity.

The candidate transfer run on the same prepared copy completed without diagnostic
errors or failed batches. Aggregate counts were unchanged: 2048 labeled cases,
1203 available references, 1047 exact selections, 525 ambiguous available cases,
369 exact selections among those, and 1240 name matches across all cases. The
845 unavailable references still lacked proven sharing. The disagreement split
remained 154 stronger selected matches, two ties, zero weaker selected matches
and 46 name disagreements. These aggregates do not prove that every individual
selected payload remained identical. They establish no measured aggregate accuracy
gain; the demonstrated improvement is the constructed namespace-context regression.

Both before/after invocations used:

```sh
target/debug/eval-binary-context /tmp/dazhbog-review-benchmark.toml \
  32 64 2 transfer --all-cases
```

Output was reduced in memory to counts and selected diagnostic fields, without
editing corpus data or writing a new corpus artifact. The existing retrospective
and independent-label limitations remain. No scoring coefficient was fitted to
this sample.

The complete affected run passed 167 tests: 80 library, 49 binary-selection,
eight database integration, ten semantic-matching, six semantic-neighbor,
13 startup/projection and one symbol-evaluation. None were ignored or filtered.
The server target compiled and ran zero unit tests. Scoped strict Clippy,
formatting and whitespace checks passed:

```sh
cargo test --locked --lib --bin dazhbog --test binary_selection \
  --test database_integration --test semantic_matching --test semantic_neighbors \
  --test startup_projection --test symbol_evaluation
cargo clippy --locked --lib --bin dazhbog --test binary_selection \
  --test semantic_matching --test semantic_neighbors --test symbol_evaluation \
  --test startup_projection -- -D warnings
rustfmt --edition 2021 --check --config skip_children=true \
  src/db/anchors.rs tests/binary_selection.rs
git diff --check
```

Validation used the locked graph and previously recorded local Rust nightly debug
profile. No release latency, cross-platform or container checks were performed;
the previously recorded all-target Clippy debt remains outside the scoped claim.
The final audit traced transient/source/consensus fingerprints, separate priority
corroboration, singleton skipping, explicit selection, metadata shaping and the
neighbor caller. README and `AGENTS.md` now document the guard/retry bounds, unchanged
identity/projections and test requirements. No migration or startup contract changed.

### Bounded findings

- **Medium:** accepted suffix structure does not prove how a stored name was
  created; the recovered prefix supplies bounded lexical evidence only [S56].
  More than four suffixes or names longer than 4096 B retain the original evidence.
- **High, unchanged:** 156 transfer disagreements are not independent error
  labels. The available symbol-backed corpus still has no correct-and-incorrect
  competing donor-name cases, so general accuracy remains unverified.
- **High, unchanged:** useful startup ≤2 s and cross-store push consistency remain
  unresolved. This group adds no startup architecture or data repair change.

## Thirty-sixth implementation group: normalize within eligible candidates

Baseline: `3dba76b6ec1e8eb1dd14099307e8d8925a93a712`, tracked worktree clean.
The previous turn completed and pushed the bounded Swift-vocabulary change.
Owned paths: `src/db/database.rs`, `src/db/selection_tests.rs`,
`tests/binary_selection.rs`, `AGENTS.md`, `README.md` and this report. Production
`data/`, ignored configuration and unrelated `research/` are preserved. Tests use
new temporary stores; corpus probes use only the existing prepared temporary copy.

### Reproduction and corrected contract

Candidate eligibility was determined before most metadata analysis, but score
normalization still used every retrieved candidate's timestamps, observation
totals and binary diversity. Thus a record excluded by explicit binary identity
could rescale the relative importance of priors among eligible annotations. The
same dependency existed for inferred exclusions and candidates finally rejected
by the independent semantic-corroboration requirement. Initial anchor scores
were also normalized before enforcing strict inferred binary priority.

A new public-selector regression demonstrated a default-weight selection change.
Two historical annotations from the query binary have identical names and opaque
metadata chunk structure, with different one-byte payloads. The older annotation
has eight observations at timestamp 1 s; the newer has one at 2 s. The query's
last-observation pointer is stale, so both historical annotations are eligible.
Ignoring equal score terms, the old normalization gives:

- Older: 0.5 × (8/8) + 0.5 × 0 = 0.5.
- Newer: 0.5 × (1/8) + 0.5 × 1 = 0.5625.

The 0.0625 score difference selects the newer annotation. Adding an unrelated,
ineligible record at timestamp `u64::MAX` dilutes the newer annotation's recency
to `1/(2^64 − 2)` instead of one. Its score contribution becomes approximately
0.0625, and the older annotation wins. These scores are dimensionless; timestamps
are unsigned seconds and only their differences enter recency. The tiny EPSILON
term in the implementation's observation denominator does not change these
decisions. This is a concrete default-weight payload change, not a hypothetical
coefficient issue or an independent correctness judgment about either annotation.

The corrected contract normalizes each pass over its final eligible candidate
indices [S57]. `retain_binary_compatible_candidates` now handles indices directly.
The initial source-anchor pass applies explicit eligibility and strict inferred
priority before computing extrema and scores. The final selection pass applies
explicit eligibility, inferred cutoff and semantic corroboration before scoring.
`score_candidate_population` owns this ordering and computes bounds internally;
`select_from_versions` no longer accepts caller-provided normalization extrema.

`version_population_bounds` accepts an iterator of candidate references and
computes the same extrema/defaults in one pass. Canonical refresh still uses all
of its candidates. The legacy single-key replay's initial full-pool pass remains
unchanged; its final selection follows the new eligible-population contract.
The source-anchor comparison still retains the broader cutoff candidate set for
constructing final lexical distinctions. Candidate diagnostics retain the original
retrieved IDs/support arrays, even for excluded records. Raw stored annotations,
counts, selection precedence, support allocation and score coefficients are unchanged.

### Assumption register and acceptance criteria

| ID | Assumption | Basis / dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|
| S57 | With eligibility, retained annotations, canonical hint and query evidence fixed, a version excluded from a scoring pass should not rescale that pass's priors | Explicit/inferred compatibility policy; the default-weight reproduction violates isolation | Excluded `u64::MAX` timestamp, `u32::MAX` observation/diversity counts, explicit history, inferred cutoff and post-corroboration rejection | New unit checks identical donor/data/score/margin/entropy with and without the excluded candidate; public-selector and source-anchor fixtures | Confirmed for tested paths; this is a ranking invariant, not independently calibrated accuracy |

Acceptance criteria: eliminate excluded-population influence in both scoring
passes; preserve explicit and inferred eligibility, all-candidate diagnostics,
lazy analysis, input order/duplicates, raw donor payloads and canonical refresh;
maintain finite bounded normalization terms at integer extremes; require no
persistent schema change, data rewrite or startup scan.

This invariant is conditional. An upload that changes a canonical hint, family
membership, an eligible annotation or another source's usable metadata can still
legitimately change the query evidence. The implementation does not promise
invariance to every unrelated database mutation or an atomic read snapshot.

### Change surface and complexity

Affected: score normalization, initial semantic-source choice, final eligible
ranking and associated score/margin/entropy diagnostics. Experimental synthesis
can change because its donor ordering and margin input change. There are no new
score weights or configuration fields. Transport, both wire codecs, session
policy, context/store formats, mutation ordering, history traversal, version
identity, search schema, HTTP shapes, upstream and recovery formats are unchanged.
Binary workbench consumers inherit the corrected selector. Cache dependencies
already cover the candidate keys; no new evidence source or cache format is added.

For N retrieved candidates and E final eligible candidates, eligibility retains
its existing membership-read cost. Bounds require O(E) CPU and O(1) additional
space, rather than four scans of N candidates. Scoring executes E times and
sorting costs O(E log E); retained index/score vectors use O(N + E) entries.
The first pass can still analyze candidates in the broader inferred cutoff pool
for subsequent lexical comparison, even when they cannot supply a source anchor.
Final corroboration can also inspect such candidates before excluding them.
No process-wide memory or latency bound follows from this entry-count analysis.

Minimum normalization counts remain one. Empty bounds are `(0, 0, 1, 1)`;
equal timestamp bounds give recency one. Timestamp subtraction stays within u64
because the minimum/maximum come from the same pool. Observation/diversity counts
are compared, not added. No new I/O, locks, background tasks or migration are added.
Historical counter inflation remains a separate evidence-quality issue.

### Behavioral evidence and validation

The unit and default-weight public-selector regressions both failed before the
implementation: introducing the excluded future record switched the chosen
version/payload. Both passed afterward. The unit fixture additionally exercises
timestamp, observation and diversity extrema across explicit-history, inferred
and corroboration-rejection modes; donor/data and score/margin/entropy bits remain
identical while diagnostic candidate count grows from two to three. The earlier
lazy-analysis oracle was updated deliberately: a unique eligible version now uses
its own extrema, while unselected candidates remain unanalysed where their metadata
is not required for corroboration.

A further integration fixture verifies that an excluded future annotation cannot
switch the initial source anchor and thereby change another requested function.
It uses explicit configured prior weights to establish a decisive source margin,
and exercises request permutations/duplicates. This additional fixture passed
after implementation; no before-change execution is claimed for it.

The affected integration suites passed: binary selection 51, database integration
8, semantic matching 10, semantic neighbors 6, startup projection 13 and symbol
evaluation 1. The combined command also compiled the server test target and exited
successfully. The repeated library run passed all 81 tests, for 170 distinct tests
across these suites. The source-anchor fixture also passed again after adding its
cardinality assertion. Scoped strict Clippy, Rust formatting and whitespace checks
passed; Cargo still reports six pre-existing
auxiliary-binary naming warnings. No all-target Clippy claim is made.

Copied-corpus evaluation used `/tmp/dazhbog-review-benchmark.toml`, with the same
selection policy and seeds as the recorded references:

| Probe | Cases | Expected available | Selected agreement | Ambiguous available / agreement | Failed batches / diagnostic errors |
|---|---:|---:|---:|---:|---:|
| Transfer, 32 binaries × 64 functions, seed 2 | 2048 | 1203 | 1047 | 525 / 369 | 0 / 0 |
| Observed, 8 binaries × 32 functions, seed 1 | 256 | 256 | 256 | 75 / 75 | 0 / 0 |

Transfer also retained 845 `sharing_not_proven` cases, 1240 matching names and
2048 expected versions reachable with identity. Latest/canonical agreement was
1728/1801. All these totals match the fresh pre-change transfer reference from
group 35. Transfer suppresses observation, recency, diversity and canonical priors,
so it cannot measure the benefit of the normalization fix. Observed latest/canonical
agreement was 240/247, matching the older group-32 reference; no fresh pre-change
observed run is claimed. Neither probe supplies independent accuracy labels or
shows an aggregate accuracy gain. Both completed without failed batches or
availability/latest/canonical diagnostic errors.

Final output from the first Clippy/corpus run was lost during context compaction;
the processes had terminated before repeating those checks. The repeated checks
above provide the reported terminal results. Library tests were also repeated to
retain their complete final count. No latency inference uses these additional runs.

Reproducible commands:

```sh
cargo test --locked --lib --bin dazhbog --test binary_selection \
  --test database_integration --test semantic_matching --test semantic_neighbors \
  --test startup_projection --test symbol_evaluation
cargo test --locked --lib
cargo test --locked --test binary_selection \
  unrelated_population_cannot_change_batch_source_anchors
cargo clippy --locked --lib --bin dazhbog --test binary_selection \
  --test semantic_matching --test semantic_neighbors --test symbol_evaluation \
  --test startup_projection -- -D warnings
rustfmt --edition 2021 --check --config skip_children=true \
  src/db/database.rs src/db/selection_tests.rs tests/binary_selection.rs
git diff --check
target/debug/eval-binary-context /tmp/dazhbog-review-benchmark.toml 32 64 2 transfer
target/debug/eval-binary-context /tmp/dazhbog-review-benchmark.toml 8 32 1 observed
```

Final review traced canonical, source-anchor, final-selector and replay consumers
of the shared extrema helper. Candidate order is immaterial to the integer token
occurrence counts in `BatchAnchors::excluding`; sorting still occurs before anchor
choice and final selection. The source-anchor fixture explicitly checks response
cardinality before its zipped assertions. README and `AGENTS.md` sections 10.2–10.3
now describe the changed normalization population, ordering, diagnostics and required
regressions. There is no additional applicable descendant guide. No release latency,
cold-start, container or cross-platform validation was performed for this group.

### Bounded findings

- **Medium:** returned scores, margins, entropy and experimental synthesis may
  differ where excluded extrema previously rescaled priors. They are diagnostics,
  not calibrated probabilities, and must not be compared as a stable cross-version
  confidence scale. Canonical refresh keeps its full population.
- **High, unchanged:** original counters can be inflated or incomplete, and
  independent conflicting-label accuracy remains unverified. Eligible normalization
  isolates those priors; it does not establish their truth or repair stored evidence.
- **High, unchanged:** useful startup ≤2 s and whole-push consistency remain open.
  This group makes no new startup, deployment or durability claim.

## Thirty-seventh implementation group: preserve variants under concurrent mutation

Baseline: `211b50ad343bb8d7ad35e1e4b9073c2dcff8ee71`, tracked worktree clean.
The previous goal turn made progress by implementing, validating and pushing
eligible-population normalization. This group owns `src/db/database.rs`,
`src/db/mutation_tests.rs`, `src/engine/mod.rs`, `src/engine/mutation_locks.rs`,
`AGENTS.md`, `README.md` and this report. Original `data/`, local configuration and
pre-existing `research/` are preserved. All concurrency fixtures use fresh temporary
stores. Source edits, including formatter output, use `apply_patch` only.

### Evidence and acceptance criteria

Before mutation serialization, two concurrent pushes could both read head H,
append records A and B with `prev_addr = H`, and overwrite the latest pointer in
either order. The losing successor remains physically stored but becomes unreachable
from the live chain. Its binary/version observation can still exist. Candidate
retrieval cannot recover that annotation, even with explicit binary identity and
a sufficient traversal cap. Better ranking cannot compensate for the lost branch.

Two new concurrency regressions failed before implementation:

- Twelve writers submitted three distinct annotations each. Only 3 of the 36
  annotations remained reachable in history.
- Twelve writers submitted the same payload. Statuses contained one insertion and
  zero unchanged results, instead of one insertion and eleven unchanged results.

The first reproduction used a barrier at each of three rounds. The final fixture
uses one initial barrier so an error or assertion in a worker cannot strand peers
at a later barrier. Both fixtures passed with serialization; the history fixture
also retrieves the final annotation for each of the twelve explicit binary MD5s.
No rate or probability of the race is inferred from one observed schedule.

Acceptance criteria: accepted concurrent distinct pushes remain reachable;
identical concurrent uploads append once while retaining each binary observation;
do-not-override retains one stored payload; delete and revert use the same ordering;
cloned runtimes share that ordering; deletion boundaries survive reinsertion;
mutex storage is bounded and no mutex is held across an await. No format migration
or eager scan of the supplied dump is required.

### Assumption register

| ID | Assumption | Basis / dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|
| S58 | Online Database mutations sharing an EngineRuntime must observe preceding mutations to the same key before deriving their new history head | `push_with_ctx_sync`, `delete_keys_sync` and `revert_last_versions_sync` own online latest-pointer changes; lost branches prevent binary-specific retrieval | Twelve competing writers, duplicate/no-override pushes, cloned-runtime undo/delete, public push/delete races, reinsertion | Run `db::database::mutation_tests`; any missing accepted distinct version or nonserial history falsifies the implementation | Confirmed for tested paths; direct engine writes and cross-store failures are outside the serialization contract |

### Mechanism, lock order and bounds

`EngineRuntime` owns an `Arc<MutationLocks>`, initialized once during open and
shared by derived runtime clones. The gate hashes the full 128-bit function key
with `RandomState` into 1024 `parking_lot::Mutex<()>` slots. Different keys sharing
a slot serialize; no allocation or map insertion occurs per acquired key. Mutex
storage is O(1024) for each independently opened runtime and lock selection is
O(1) CPU for the fixed-width key. Gate construction is O(1024); it reads no records.
This is a contention bound on lock identities, not a bound on queued requests or
process memory. Latency under hot-key or stripe contention remains workload-dependent.

Push acquires the guard after name/length admission and before reading the current
head. It keeps the guard through duplicate/no-override checks, append, latest-index
publication, context observation, canonical refresh and search enqueue. Delete and
revert likewise acquire before their head reads and retain it through their derived
updates. Each item releases its guard before the next key; reversed batch key orders
cannot hold two stripes simultaneously. The guard is released on ordinary error
returns and unwinding. Release panic-abort still terminates the process.

The acquisition order is key stripe, facet mutation fence, then existing segment,
sled/context and search operations. The facet fence counts active writers; it does
not keep its internal mutex held during storage work. Search methods acquire their
writer mutex internally and never acquire a key gate. Push/revert commit their
batched search changes after releasing the stripe. Search add/delete enqueue order
for one key is protected even if another batch commits those pending operations.
No helper called under a gate acquires another key gate. Queries do not acquire it.

Delete now copies its key slice and delegates to `spawn_blocking`, matching push
and revert. A contended synchronous mutex therefore does not block a Tokio worker.
Cancellation stops waiting on the result; an already running delete worker may
still finish and mutate storage. Existing admission/projection checks and return
codes remain unchanged. Gate hashing and false contention have not been benchmarked.

### Change surface and failure boundaries

Affected: online mutation ordering, history reachability, duplicate suppression,
binary-specific candidate availability, context/canonical/search write ordering,
runtime clone state and delete execution lifetime. No score coefficient or eligibility
rule changes. Both wire protocols and HTTP callers inherit Database serialization;
wire bytes, configuration, raw records, version identities, context tree formats,
search schema, read shaping and offline recovery formats remain unchanged. Offline
tools and direct engine/context/index writes do not participate in these gates.

This is not cross-store atomicity. Append can succeed before latest-index publication
fails, leaving an orphan. Context errors are logged by `record_context_observation`;
canonical refresh can return an error after prior updates; search enqueue/commit
errors can be logged without failing a push. Delete still has its existing behavior
of counting index failures without propagating them. A crash can interrupt any of
these sequences. Readers can observe intermediate states because they do not take
the mutation gate. No automatic repair of old branches, observations or projections
is introduced. Successful responses retain their previous flush/durability semantics.

### Validation and evaluation

The five new mutation tests passed in the focused run. They verify all 36 unique
history entries and twelve explicit-binary selections; one physical record and
twelve observations for duplicate pushes; one payload under do-not-override;
twelve successive concurrent undo operations and exactly one live-key deletion
across twelve cloned runtimes; reinsertion without stale-history resurrection;
and valid serial outcomes for eight public push/delete races. The lock unit test
checks same-stripe exclusion, release and progress on a different stripe.

Before implementing this group, an additional copied-corpus transfer probe ran
32 binaries × 64 functions with seed 3 on the existing prepared temporary copy.
Of 2048 labeled cases, 1233 expected variants were available, 1150 were selected,
and 299 of 382 ambiguous available cases agreed. There were 815
`sharing_not_proven` cases, 1270 name matches, and all 2048 expected variants were
reachable with explicit identity. Latest/canonical agreement was 1871/1868, with
zero failed batches or diagnostic errors. Among available disagreements, only one
had tied binary-match scores; it kept the same Objective-C name and differed in
frame metadata. This read-only workload does not test the mutation fix, and these
observations do not establish independent accuracy. No weights were tuned to it.

The final affected suite passed **186 tests**: library 87, binary selection 51,
database integration 8, Lumina fixtures 10, semantic matching 10, semantic neighbors
6, startup/projection 13 and symbol evaluation 1. The server test target compiled
and contained zero tests. Scoped strict Clippy, Rust formatting and whitespace
checks passed. Cargo's six existing auxiliary-binary naming warnings remain; no
all-target Clippy claim is made. Validation used macOS arm64, rustc
`1.100.0-nightly (f248f4038 2026-09-05)` and cargo
`1.100.0-nightly (3c0b53475 2026-09-04)`, with the locked dependency graph and debug
test profile. No release contention/latency benchmark, cross-platform execution,
container run or power-loss test was performed.

```sh
cargo test --locked --lib db::database::mutation_tests -- --nocapture
cargo test --locked --lib --bin dazhbog --test binary_selection \
  --test database_integration --test semantic_matching --test semantic_neighbors \
  --test startup_projection --test symbol_evaluation --test lumina_fixtures
cargo clippy --locked --lib --bin dazhbog --test binary_selection \
  --test semantic_matching --test semantic_neighbors --test symbol_evaluation \
  --test startup_projection --test lumina_fixtures -- -D warnings
rustfmt --edition 2021 --check --config skip_children=true \
  src/db/database.rs src/db/mutation_tests.rs src/engine/mod.rs \
  src/engine/mutation_locks.rs
git diff --check
target/debug/eval-binary-context /tmp/dazhbog-review-benchmark.toml \
  32 64 3 transfer --all-cases
```

The final guide audit reconciled `AGENTS.md` sections 9.4 and 13 with all three
mutation call sites, runtime construction/cloning, facet fences and search writer
locking. README documents per-key serialization, bounded stripes and the absence
of automatic orphan repair. No descendant guide applies. Tests check actual
records, history, per-binary selection, statuses and observation counts; successful
lock acquisition alone is not the behavior oracle.

### Bounded findings

- **High:** existing orphaned branches are not repaired. The fix prevents the
  reproduced online race; it does not make the existing dump complete.
- **High:** cross-store partial failure and concurrent different-key updates to
  shared binary metadata remain separate consistency issues. The gates protect a
  key's writer sequence, not every binary's aggregate counters or a reader snapshot.
- **Medium:** stripe collisions and same-key serialization can increase mutation
  latency. Fixed gate storage avoids an unbounded per-key lock registry; blocking
  queues and owned request buffers retain their existing resource limitations.
- **High, unchanged:** independently labeled conflicting donors and useful startup
  ≤2 s remain unverified. This group claims neither calibrated accuracy nor a startup
  improvement.
