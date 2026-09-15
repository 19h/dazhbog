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
