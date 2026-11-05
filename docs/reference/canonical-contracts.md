# Canonical contracts and historical decoding

The repository is migrating project-owned sequential labels to one descriptive,
unversioned contract per responsibility. **The coordinated cutover is still in
progress.** This page records verified portions, not readiness or research completion.
External package/model/protocol versions and original historical identities are facts.
No historical artifact, receipt, snapshot, frozen hash or approval is rewritten.

## Verified mappings (campaign started 2026-11-05)

Old labels in this table are historical facts, not supported alternate write APIs.

| Responsibility | Historical label | Canonical write label | Historical behavior |
| --- | --- | --- | --- |
| Content-addressed checkpoint audit | `tesis.checkpoint.audit.v1` | `tesis.checkpoint.audit` | Explicit read-only decoding with the same per-entry SHA-256 checks; malformed/unknown references fail closed. |
| Runtime descriptor | `runtime-descriptor.v1` | `runtime-descriptor` | Catalog preserves original bytes/schema and source hashes; descriptor writer refuses historical instances and historical output files. |
| Static AKG snapshot | `akg-snapshot.v1` | `akg-snapshot` | Catalog recognizes original identity without relabelling or rewriting the snapshot. |
| Failure detail | `stage6.failure.v1` | `execution-failure` | Existing saved details remain original input; new writer preserves status, evidence and errors. |
| Containment summary | `containment-summary.v1` | `containment-summary` | Classification and counts unchanged; saved summaries retain their recorded labels. |
| Provider input-token cache accounting | `provider-input-tokens.v1` | `provider-input-tokens` | Token-rate meaning unchanged; never reinterpret older local-response cache rates as token rates. |
| State schema | `state.v3` | `exploitation-state` | Original metadata remains readable; old schema is not a resume alias for a new source epoch. |
| Checkpoint metadata | `checkpoint.v2` | `execution-checkpoint` | Exact state/checkpoint/graph/coordinate/target gates remain mandatory. |
| Execution graph identity | `graph.v2` | `execution-graph` | No topology change; old source/schema identity does not authorize cross-epoch resume. |
| Coordinate fingerprint framing | `coordinate.v2` | `coordinate-setup` | Fingerprint still covers effective coordinate settings; old fingerprints are not patched or blindly equated. |
| Method workflow | `workflow.v2` | `method-workflow` | Shared protocol constant; visit budgets, eligibility and stop behavior unchanged. |
| Tri-state observation facts | `preconditions.v1` | `method-preconditions` | Fact applicability, provenance, chronology and unknown-value behavior unchanged. |
| Optional fixed-method coverage plan | `scoring-v4-fresh-matrix-plan.v1` | `method-matrix-plan` | Original plans remain untouched; no old-schema/source plan may execute under new code. |
| Fixed-method tool output namespace | `scoring-v4-remediation-*`, `scoring_v4_matrix_*` | `method-matrix-*`, `method_matrix_*` | Newly emitted plan/run metadata uses descriptive names. This is not the two-model primary design. |
| Final evidence-based rubric | `scoring.v4` | `thesis-scoring` | Original sources/receipts retain a read-only view; no new evaluator/finalizer writes under that identity. |
| Provisional runtime rubric | `scoring.v2` | `runtime-scoring` | Recorded runtime identities/values remain facts; no substitution for thesis grades. |
| AI judge identity | `judge.v1` | `artifact-judge` | Old judge identity is accepted only in the original read-only review context, with all evaluator/source checks. |
| Scoring policy | `scoring-policy.v4.3` | `scoring-policy` | Original ordered four-file digest stays independently anchored; current ordered six-file inputs include the shared formula and identity registry. |
| Research metrics / rates | `research-metrics.v2`, `event-rates.v2` | `research-metrics`, `event-rates` | Stored bundles remain unchanged; unsupported old rubrics cannot invoke a legacy metrics calculator. |
| Metric definition IDs | `research-metrics.v1/v2`, `method-alignment.v1` | Descriptive metric names, including `method-alignment` | Preserve recorded definitions; no change to current metric populations or arithmetic. |
| Runtime display labels | `runtime_provisional_scoring.v2`, `provisional_scoring.v2` | `runtime-provisional`, `provisional-score` | Display responsibility is separate from the recorded rubric/status, which remain null if unknown. |
| Selection consistency | `selection-consistency.v1` | `selection-consistency` | Same repeated-outcome calculation and denominators. |
| Fidelity / baseline reports | `fidelity-ledger.v1`, `baseline-audit.v1` | `fidelity-ledger`, `baseline-audit` | Original reports remain untouched; new metadata does not imply a new research epoch. |
| Hypothesis ordering | `p1-ranking.v1` | `hypothesis-ranking` | Same lexicographic order, evidence/risk rules and falsified exclusions. |
| Remaining evidence audit | `scoring_v4_remaining_evidence_audit` | `remaining_scoring_evidence_audit` | Same read-only audit responsibilities. |
| New manual UI review provenance | `human.v1` | `manual-assessment` | Existing human identities/versions remain original facts; no human review is required when AI is selected. |

## Owners and integrity boundaries

- [Historical label registry](</home/kevin/coding/tesis/core/historical_contracts.py>)
  contains immutable read-side facts only. Membership does **not** establish
  source/hash, epoch, chronology or resume compatibility, and must not be used
  when constructing new runtime artifacts.
- [Checkpoint audit serializer](</home/kevin/coding/tesis/core/checkpoint_audit.py>)
  writes only its canonical marker. Historical nested and typed-wrapper formats
  remain readable. The outer wrapper must bind to the inner manifest format;
  absent/tampered evidence is never dropped or synthesized.
- [Checkpoint metadata store](</home/kevin/coding/tesis/core/checkpoint_store.py>)
  keeps original stored rows on read. Current completed metadata can resume only
  an exact compatible coordinate; changed targets, budgets, schema/graph identity
  and missing completion receipts continue to refuse execution.
- [Runtime descriptor writer](</home/kevin/coding/tesis/tesis/live_runtime.py>)
  cannot emit an old schema or overwrite a historical/unsupported descriptor.
  [Catalog discovery](</home/kevin/coding/tesis/tesis/artifact_catalog.py>)
  retains original schema values and byte hashes instead of converting input data.
- [State schema](</home/kevin/coding/tesis/core/state.py>) owns the shared workflow
  protocol value consumed by [workflow policy](</home/kevin/coding/tesis/core/workflow_policy.py>).
  [Observation facts](</home/kevin/coding/tesis/foundation/preconditions.py>)
  preserve the measured-positive/measured-negative/unknown distinction.

## Scoring integrity and read/write separation

[scoring_contracts.py](</home/kevin/coding/tesis/core/scoring_contracts.py>) owns
both provisional/final identities and the unchanged weights. Current scoring
policy hashes the ordered six-file set published by
[research_metrics.py](</home/kevin/coding/tesis/evaluation/research_metrics.py>),
including that owner, its immutable historical registry, the evidence/grading
code and the verifier. Moving weights cannot leave them outside the digest.
The original four-file list is a read-side fact, never a current write option.

[Historical receipt discovery](</home/kevin/coding/tesis/evaluation/observer_reviews.py>)
retains original rubric, policy, source-file list and judge identities only after
checking exact admitted file sets, SHA-256 values, independent whole-source
identity, source scoring epoch and matching original policy metadata. Existing
candidate/source/config/grader, proof-ceiling, reference and arithmetic checks
still apply. An old label does not make anything compatible by itself. The saved
source auditor reuses this same gate instead of implementing a looser adapter.

[The reviewer](</home/kevin/coding/tesis/evaluation/thesis_scoring.py>) exposes
known original sources as explicitly read-only. Live single/matrix launches,
AI evaluation, telemetry publication and finalization refuse historical labels.
An older saved queue cannot bypass the evaluator guard by omitting the new flag:
its rubric must still be exactly canonical. Existing valid receipts are reused,
not relabelled or sent to a new grader. The obsolete metrics fallback calculator
was removed; stored legacy metrics remain readable, but missing legacy bundles
are unavailable rather than reconstructed from runtime vectors or defaults.

Human and AI captions now describe the same manual-assessment role and validated
receipt requirement. AI selection is not described as needing human sign-off.
No DOCX was edited; only future helper output prose lost an obsolete contract
name. The helper's historical DOCX text lookup remains an original-input fact,
and its DOCX writer was not executed.

## Entry-point and test path cutover

The fixed-method tool moved from historical `evaluation/scoring_v4_matrix.py` to
[method_matrix.py](</home/kevin/coding/tesis/evaluation/method_matrix.py>), with
[test_method_matrix_driver.py](</home/kevin/coding/tesis/tests/test_method_matrix_driver.py>)
as its current contract check. Live imports, simulated module identity, output
root checks, emitted artifact types and CLI help migrated together. There is no
forwarding module at the old path. Historical handoffs retain their original
names/commands; their source identities describe the old checkout, not a promise
that the old import will execute in the new code epoch.

The three version-named evidence tests now live at
[test_scoring_evidence_e2e.py](</home/kevin/coding/tesis/tests/test_scoring_evidence_e2e.py>),
[test_permission_chain_e2e.py](</home/kevin/coding/tesis/tests/test_permission_chain_e2e.py>) and
[test_probe_replay_e2e.py](</home/kevin/coding/tesis/tests/test_probe_replay_e2e.py>).
All helper imports migrated; `scoring_artifact` replaces the version-suffixed
fixture helper. Fresh synthetic output uses unversioned evidence paths and the
`TESIS_SCORING_EVIDENCE` / `TESIS_PROBE_REPLAY_EVIDENCE` overrides, without a live
old-variable alias. Previously generated evidence directories are not moved.

## Verification evidence

These are implementation checks, not DVWA/provider experiments or thesis-score proof.

- [Checkpoint contract JUnit](</home/kevin/coding/tesis/results/validation/scoring-completion-2026-11-05/checkpoint-contract-junit.xml>):
  9 passed for canonical audit writes, original historical decoding, integrity,
  corruption/missing-evidence refusal and existing recovery regression.
- [Artifact contract JUnit](</home/kevin/coding/tesis/results/validation/scoring-completion-2026-11-05/artifact-contract-corrected-junit.xml>):
  30 passed for descriptor/snapshot/failure/cache/containment contracts, historical
  discovery, naming guard, existing cache/config behavior and observer publication.
  The retained first attempt had an invalid synthetic status-reason fixture;
  the fixture was corrected without relaxing the production reason validator.
- [Checkpoint identity JUnit](</home/kevin/coding/tesis/results/validation/scoring-completion-2026-11-05/checkpoint-identity-junit.xml>):
  14 passed for current metadata round-trip/exact resume, historical schema
  rejection, target/budget mismatch refusal, opt-in/start failure and audit decoding.
  These overlap earlier tests; do not sum them as unique independent experiments.
- [Planner/workflow offline E2E JUnit](</home/kevin/coding/tesis/results/validation/scoring-completion-2026-11-05/method-matrix-workflow-junit.xml>):
  4 passed, including freeze/verify of the unchanged fixed-method 108-coordinate
  design, candidate replay ownership and mocked graph visit-budget/negative-stop
  paths. Synthetic outputs are retained under the scoped offline evidence root;
  this did not freeze or launch the authorized primary study.
- [Evidence-path offline E2E JUnit](</home/kevin/coding/tesis/results/validation/scoring-completion-2026-11-05/evidence-contract-offline-junit.xml>):
  25 passed for renamed artifact, permission, chain, probe replay and saved-review
  flows plus their helper callers. All transports/models are fixtures; no live
  DVWA/provider request occurred. These establish mechanics, not AC research scores.
- [Shared reader/fact checks](</home/kevin/coding/tesis/results/validation/scoring-completion-2026-11-05/canonical-readers-facts-junit.xml>):
  13 passed after wiring catalog discovery to the descriptor owner's constants,
  covering original-byte historical discovery, current writes, exact checkpoint
  resume and measured true/false/unknown fact scope/provenance.

```bash
.venv/bin/python -m pytest -q tests/test_checkpoint_audit_contract.py tests/test_checkpoint_recovery_regression.py --junitxml=results/validation/scoring-completion-2026-11-05/checkpoint-contract-junit.xml
.venv/bin/python -m pytest -q tests/test_artifact_contract_cutover.py tests/test_live_runtime.py tests/test_chapter3_slice_d.py tests/test_naming_guard.py tests/test_observer_export.py --junitxml=results/validation/scoring-completion-2026-11-05/artifact-contract-corrected-junit.xml
.venv/bin/python -m pytest -q tests/test_checkpoint_identity_contract.py tests/test_checkpoint_recovery_regression.py tests/test_checkpoint_optin_regression.py tests/test_durable_checkpoints.py tests/test_checkpoint_audit_contract.py --junitxml=results/validation/scoring-completion-2026-11-05/checkpoint-identity-junit.xml
.venv/bin/python -m pytest -q tests/test_method_matrix_driver.py tests/test_workflow_remediation.py --basetemp=results/validation/scoring-completion-2026-11-05/workflow-offline-e2e --junitxml=results/validation/scoring-completion-2026-11-05/method-matrix-workflow-junit.xml
TESIS_SCORING_EVIDENCE=results/validation/scoring-completion-2026-11-05/scoring-evidence-offline TESIS_PROBE_REPLAY_EVIDENCE=results/validation/scoring-completion-2026-11-05/probe-replay-offline .venv/bin/python -m pytest -q tests/test_scoring_evidence_e2e.py tests/test_permission_chain_e2e.py tests/test_probe_replay_e2e.py tests/test_akg_oracle_regressions.py tests/test_remaining_evidence_audit_e2e.py --basetemp=results/validation/scoring-completion-2026-11-05/evidence-offline-temp --junitxml=results/validation/scoring-completion-2026-11-05/evidence-contract-offline-junit.xml
.venv/bin/python -m pytest -q tests/test_artifact_contract_cutover.py tests/test_observer_export.py tests/test_checkpoint_identity_contract.py --junitxml=results/validation/scoring-completion-2026-11-05/canonical-readers-facts-junit.xml
```

## Still pending

Scoring/rubric/metrics, payload/control/template/prompt contracts, main execution
and matrix artifacts, profile/oracle/readiness/study contracts, associated CLI/test
identifiers and current documentation still require coordinated migration.
The repository-wide guard currently reports 214 violations; it must pass before
a final prospective source/policy freeze. Future freezes must bind actual source/content identities;
removing a suffix never proves compatibility by itself.

Overall acceptance and experiment/evidence work remain in the
[persistent checklist](</home/kevin/coding/tesis/docs/active/SCORING_COMPLETION_PROGRESS.md>).
