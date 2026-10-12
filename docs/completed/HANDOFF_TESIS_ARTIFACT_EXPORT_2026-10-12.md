# Handoff: TESIS artifact export and metadata for the web observer

Status: **completed for TESIS producer scope, 2026-10-12**. Implementation and authorized producer acceptance passed. Web consumer/API/browser integration remains outstanding in the companion handoff.

## 1. Objective and inspection boundary

Implementation repository: `/home/kevin/coding/tesis`.

Prepare TESIS artifact metadata, atomic publication, and an offline observer projection so the web observer can retrieve current and historical experiments reliably. This document owns the Python producer work and shared retrieval contract. Frontend/API implementation is assigned to the [TESIS Web handoff](../upcoming/HANDOFF_TESIS_WEB_ARTIFACT_RETRIEVAL_2026-10-12.md). The producer handoff follows its implementation lifecycle; the web handoff remains under `docs/upcoming/`.

The recent execution/security outcome split is already implemented in TESIS. This work exposes and preserves that behavior for artifact consumers.

Inspected repository heads:

| Repository | HEAD |
| --- | --- |
| TESIS | `b8be4b34db4fe5c69951698be296829b2682edc4` |
| TESIS Web | `0fd9eee3fb954e6b352a8d0410e853b070c06c8b` |

Both working trees were clean before this handoff. The scan covered the filesystem adapters, API routes, schemas, browser client, normalizer, event reducer, dashboard, result components, Python artifact writers/readers, metrics, status classifier, and review writer. It inspected saved metadata and hashes without running application tests, a web server, E2E, DVWA requests, provider calls, or experiments. This is source-backed planning; reported frontend defects have not been reproduced in a running browser.

The [scan record](../../results/validation/tesis-web-artifact-sync-2026-10-12/source-scan.json) retains source hashes for both repositories, representative artifact paths/hashes/field lists, and the historical classification counts. Generated evidence remains under `results/`; existing research artifacts were preserved.

The relevant recent commits were checked explicitly:

- `0e155c0`: repaired evidence capture and source-bound review joins.
- `26ac3c1`: separated execution lifecycle from security outcome across artifacts, metrics, reports, runtime, and TUI.
- `b8be4b3`: documented the status split and compatibility rules.

## 2. Current producer contract

Runtime code establishes implemented behavior. Research semantics come from [the artifact schema](../reference/summary_en.md#11-artifact-schema), [thesis scoring](../reference/thesis_scoring.md), and [runtime architecture](../reference/architecture.md).

### Files and identities

The TUI/headless layout normally writes:

```text
results/runs/<single-run|matrix>-YYYY-MM-DD[-N]/
  runtime.json
  runtime.events.jsonl
  akg.snapshot.json
  experiment.manifest.json
  <execution_id>.json                         # single execution
  <execution_id>.events.jsonl                 # enriched trace, when enabled
  <execution_id>.rich.json                    # enriched metadata, when enabled
  <execution_id>.failure.json                 # failures, when generated
  <matrix_execution_id>.matrix.json           # matrix parent
  run-NNN-<provider>-<surface>-<level>-<mode>/
    <child_execution_id>.json
    <child_execution_id>.events.jsonl
    <child_execution_id>.rich.json
    <child_execution_id>.failure.json
    reviews/                                 # default source-local reviews
      <identity>.decisions.json
      <identity>.review-status.json
      <identity>.human-verified.json
      <identity>.ai-verified.json
      <identity>.evaluator.json
      history/*.review-history.json
```

This is the common layout, not a universal location or filename requirement. Evaluation runners also support a flat `output_dir`, and explicit research runs/reviews can use separate directories. The current matrix cohort is in `results/validation/scoring-v4-remediation-2026-10-12-matrix-epoch7/`, with review outputs in `ai-review-epoch1/`, `ai-review-epoch2/`, and `ai-review-epoch3/`. Older thesis cohorts also exist under `results/thesis-experiment-*`. Merely setting `TESIS_ROOT` cannot make the existing web adapter discover these locations.

| File family | Current discriminator | Role |
| --- | --- | --- |
| Runtime descriptor | `schema_version=runtime-descriptor.v1` | Invocation identity, heartbeat, status, coordinates, paths |
| Experiment manifest | `artifact-manifest.v1`, `artifact_type=experiment_manifest` | Relative primary/aggregate paths and run index |
| Primary coordinate | `schema_version=tui.v1` | Full execution source and `final_state` |
| Provider matrix | `schema_version=stage8.v1`, `runs` array | Parent identity, embedded children, totals, cancellation, group summaries |
| Other aggregate reports | Writer-specific schema; `matrix_*.json` can be `artifact_type=matrix_aggregate` | Support through an explicit legacy adapter |
| Rich sidecar | `stage7.rich.v1` | Supplemental trace metadata; not a separate execution |
| AKG snapshot | `akg-snapshot.v1` | Static topology captured for the invocation |
| Final thesis receipt | `artifact_type=thesis_score_receipt`, `rubric_version`, `scoring_mode`, `status=final` | Source-bound Human or AI score vector |
| Pending/final review status | `artifact_type=thesis_review_status`, `workflows` | Per-workflow pending reasons, candidate grades, receipt links |

`execution_id` identifies a particular execution; `run_id` is not a globally unique execution key. Keep parent and child IDs separate. Manifest indexes are one-based, `matrix.run.*.data.coordinate_index` is zero-based, and `repeat_index` must be copied rather than inferred from a directory name. Modern execution IDs start with `exec-`, but recognized older/test artifacts can use other IDs.

### Execution and security outcome: required recent change

Read these fields independently from the run envelope, falling back to `final_state` where appropriate:

| Field | Values / meaning |
| --- | --- |
| `execution_status` | `completed`, `failed`, `interrupted`; null for unknown attribution or an unstarted/skipped coordinate |
| `security_outcome` | `confirmed`, `no_finding`, `unconfirmed`, `fixture_limited` |
| `execution_reason` | Nullable object: `code`, `detail`, `evidence_refs` |
| `security_outcome_reason` | Nullable object with the same shape |

Execution completion means the coordinate reached its normal terminal point. `no_finding` requires linked usable response evidence and affirmative negative verifier evidence. Missing or ambiguous proof remains `unconfirmed`; unavailable independent fixture/permission/session controls can produce `fixture_limited`. A failed or interrupted execution can retain a confirmed finding already established by its evidence.

New primary artifacts retain `status=success|error|cancelled` as lifecycle aliases. Runtime descriptors retain their own observer vocabulary such as `active|finished|failed|cancelled|stale`. `task_result=INCOMPLETE` and `incomplete_reason` are legacy diagnostic labels, not independent evidence of an execution failure. Candidate disposition rows have a different `execution_status=executed|not_executed`; do not parse that field using the run lifecycle enum.

`core/run_status.py:terminal_status` owns conservative historical interpretation and proof-based outcome classification. Do not implement a simpler browser rule such as `INCOMPLETE => failed`, `HTTP 200 => confirmed`, or `no signal => no_finding`. A legacy incomplete error maps to completed only when the saved terminal trace, required provider activity, and request evidence support that mapping. Ambiguous attribution remains unknown.

### Matrix counters and denominators

`evaluation/metrics.py:aggregate_runs` now emits:

- `total_runs`, `completed_runs`, `error_runs`, `cancelled_runs`, `skipped_runs`, and `execution_unknown_runs`.
- `execution_status_counts` keyed by the three execution statuses.
- `security_outcome_counts` keyed by the four outcome categories; current aggregation excludes rows without an attributed execution status.
- `confirmed_runs` separately from completion counts.
- `successful_runs` as a compatibility alias for **completed executions**.

Render these as separate groups. Label the completion alias as completed, never as exploit successes. Preserve unknown and skipped/unstarted counts. `cancellation.total_runs` and `cancellation.not_started_runs` describe planned coverage; `totals.total_runs` counts artifacts supplied to aggregation. The legacy `cancellation.completed_runs` stores collected child artifacts, including terminal failures, and must not replace canonical `totals.completed_runs`. Provider/group summaries must use the same semantics as the whole matrix.

### Historical analysis categories and current canonical outcomes

Two different saved views exist for the same matrix epoch:

| Saved view | Counts | Interpretation |
| --- | --- | --- |
| Original execution matrix | 61 legacy success, 47 legacy error/INCOMPLETE | Immutable pre-status-split source |
| [Incomplete outcome audit](../../results/validation/scoring-v4-remediation-2026-10-12-matrix-epoch7/incomplete-outcome-audit-v2.json) | 36 `executed_without_candidate_confirmation`; 4 `executed_unconfirmed_weak_or_partial_signal`; 7 `fixture_permission_oracle_unavailable` | Diagnostic classification of the 47 incomplete rows |
| [Current compatibility view](../../results/validation/execution-security-status-2026-10-12-review/historical-compatibility.json) | 108 completed; 57 confirmed, 10 no_finding, 9 unconfirmed, 32 fixture_limited | Derived classification under the current reader; all source hashes preserved |

Display the old audit's `classification` / summary's `incomplete_disposition` as historical analysis detail, with its source and epoch. It is not the current `security_outcome`. There is no direct one-to-one mapping from the three diagnostic labels to the four canonical outcome categories. Do not rewrite the old 61/47 totals or merge the old audit categories into canonical counts. The compatibility JSON joins by source path and hash; resolve its source artifact to recover the execution ID, then bind that identity to the hash.

### Scores and metric availability

Runtime score fields remain provisional `scoring.v2`, even when the frozen config selects `scoring.v4`. Primary artifacts currently carry `thesis_scoring_status=pending_review` and `composite_score_status=historical_provisional_scoring.v2`.

Final reviews are separate files. Read `components`, `Spayload_final`, `Srun_final`, `candidate_grades`, `component_evidence_refs`, `numerator`, `denominator`, `scoring_mode`, `rubric_version`, and source binding from the receipt. Pending review workflows carry null finals and pending reasons. Keep Human and AI workflows separate.

`Spayload_final` averages distinct eligible executed validated exploit/bypass candidates for the final method. The current frontend's maximum over runtime `payload_scores` does not implement that final metric. Final components can be fractional; preserve precision and the receipt's four-decimal final rounding. A missing component or ineligible denominator leaves the final composite pending. The formula remains:

```text
Srun = 0.20*Smethod + 0.20*Spayload + 0.30*Sexploit + 0.10*Schain + 0.20*Soutput
```

For `consistency_score`, `token_cost`, and `token_cost_per_success`, follow `evaluation/metrics.py:metric_reading`, `artifact_summary`, and `aggregate_metric`. Explicit availability and finite numeric values are required; old bare numeric placeholders are unavailable with reason `legacy_numeric`. Null is not zero. Aggregates retain `mean`, `n_available`, `n_unavailable`, and `unavailable_reasons`. `report.summary` is the preferred metric source, with supported top-level fallback; `llm_performance_summary` is provider performance, not a substitute for the metric summary.

## 3. Required changes in TESIS

The current runtime already emits the canonical lifecycle/outcome fields and matrix counters. Do not duplicate that work or modify its proof thresholds to accommodate the UI. The producer work concerns discovery, identity, and safely published read models.

| Priority | Files / proposed area | Change and purpose |
| --- | --- | --- |
| P0 | `evaluation/thesis_scoring.py` | Add `execution_id`, `run_id`, `source_path`, `generated_at`, and `selection` to `thesis_review_status`; retain its existing `source_sha256`, rubric, scoring rule hash, config, method, workflows, and ledger path. Current pending status output lacks direct execution/source-path identity and timestamp, especially problematic in isolated review epochs. Final receipts already carry the main source binding. |
| P0 when historical parity is required | `tesis/artifact_repository.py`, `core/run_status.py`, `evaluation/metrics.py`; proposed `evaluation/observer_export.py` and a small CLI entry | Produce a read-only, explicitly invoked offline observer projection for configured historical source/review roots. Reuse the existing classifier, metric readers, and source-bound receipt discovery; serialize canonical metadata, aggregate counts, pending/final workflows, and relative detail locations. Write a derived file under `results/`, with its own schema version, generation time, classifier/code epoch, and original source hashes. The web app reads that file; it never launches the exporter. This avoids independently implementing Python proof gates in TypeScript and gives old immutable artifacts the same interpretation as the current TUI. |
| P1 | `tesis/artifact_layout.py:write_manifest` | Add model/model profile, `repeat_index`, creation/timing metadata, parent execution identity, and explicit relative journal/snapshot/detail locations where known. Preserve condition, target method, payload mode, child execution IDs, and one-based indexes. Keep paths relative to the owning manifest; an external configured review root uses a root identifier plus relative path rather than an unchecked arbitrary filename. |
| P1 | `evaluation/reporter.py:write_json_report`, artifact/review publication sites | Publish reader-facing JSON through a same-directory temporary file and atomic replacement. Runtime descriptors and review outputs already use atomic replacement; the generic primary/manifest/matrix writer currently uses direct `write_text`, so polling can encounter partial JSON. Preserve serialization, error propagation, historical source hashes, and append-only journal behavior. |
| P1 | `tesis/artifact_repository.py` / observer projection | Expose a transport-neutral catalog of primary sources, matrix parent/child membership, source hashes, final Human/AI receipts, pending review status, and explicit source/epoch selection. Existing `_latest_bound_receipts` is useful for final source binding but does not provide the complete pending-workflow transport contract. Avoid flattening final receipts into new runs. |
| P2, only if needed for new runs | `tesis/live_runtime.py`, manifest/export metadata | Carry explicit snapshot/journal references and parent identity through supported producer layouts. Do not infer a child's parent from a filename or reuse child lifecycle to end a parent. Preserve already implemented canonical terminal metadata and event identity. |
| With implementation | `docs/reference/summary_en.md`, `summary_id.md`, `architecture.md`, `thesis_scoring.md` | Document the finalized additive fields, projection schema, availability rules, and review/discovery precedence in both methodology languages and affected architecture references. Move this handoff to active during implementation, then completed only after its required acceptance checks pass. |

The offline projection is an integration mechanism for legacy interpretation, not a new experiment or a rescore. It must not rewrite primary artifacts, change verifier decisions, request fresh oracle evidence, or fabricate missing identifiers/grades. If omitted from the first implementation slice, historical artifacts without a verified derived view must visibly retain unknown attribution; that slice cannot claim parity with the current historical classification.

## 4. Retrieval contract owned by TESIS

Freeze one small additive DTO with the web consumer before implementation. TESIS owns the projection schema; TESIS Web validates and adapts it at its API boundary. Use these groups rather than flattening incompatible status/score fields:

| Group | Required content |
| --- | --- |
| Identity | Execution ID, nullable run ID, nullable matrix parent ID, coordinate index and its convention, condition, target/selected method, payload mode, repeat index, provider/model/profile, surface/level, config fingerprint |
| Source | Root identifier, relative primary path, original-byte SHA-256, source schema, original status/task result, projection schema/code epoch when applicable |
| Execution | Canonical lifecycle or null; structured reason; observer connection/heartbeat separately |
| Security | Canonical outcome or unknown when a legacy source cannot be classified; structured reason; optional separately attributed historical analysis label |
| Coverage | Canonical totals and both count maps, unknown/skipped/unstarted, planned versus represented counts |
| Runtime scores | Stored provisional dimensions/composite and their rubric/status/source |
| Thesis review | Separate `human` and `ai` status/reason/component-pending reasons, nullable components/finals, bound receipt path/hash/time, candidate numerator/denominator |
| Metrics | Nullable value, availability, unavailable reason; aggregate availability counts/reasons |
| Detail | Source-specific evidence references and availability of trace, candidate dispositions, verifier history, snapshot, and child artifact |
| Diagnostics | Missing/unreadable/schema-incompatible files, missing or stale source binding, ambiguous identity, absent snapshot/journal, and explicit fallback source |

Hash raw source bytes on the server before redaction; never hash the normalized API JSON and compare it with a receipt's source hash. Keep rubric/formula checks and source identity checks separate. Select the latest eligible final receipt per `(execution_id, source_sha256, scoring_mode)` within the declared review roots and epoch policy, using timestamp and deterministic tie resolution. A newer unrelated hash/role or an older failed review epoch must not replace a valid current workflow. Detect differing rubric/config bindings explicitly.

For legacy pending status files missing IDs/timestamps, join only through a verified source hash plus validated ledger/source associations and the explicitly selected review epoch. Directory names alone are insufficient. Once producer metadata is available, use its direct identity rather than heuristic inference.

## 5. Implementation order and dependencies

1. Freeze the additive retrieval contract in section 4 with the [web consumer](../upcoming/HANDOFF_TESIS_WEB_ARTIFACT_RETRIEVAL_2026-10-12.md#3-required-changes-in-tesis-web). Settle schema version, source/review root identifiers, index conventions, null semantics, and source/epoch selection.
2. Add identity/timestamp fields to pending review outputs and enrich the manifest metadata. Keep old files readable; use additive fields for newly written artifacts.
3. Publish reader-facing artifact JSON atomically, preserving existing serialization and failure reporting.
4. Extend the artifact catalog and build the explicitly invoked offline projection by reusing the current classifier, metric readers, and source-bound review discovery.
5. Provide sanitized saved fixtures and projection examples for the web adapter, with source hashes, canonical counts, pending/final workflow examples, and publication semantics.
6. Complete authorized focused checks, update both methodology languages and affected architecture references, and save evidence for this code/config epoch.

Web resolver, normalization, and UI work can proceed against existing artifacts and the agreed contract while producer changes are underway. Full historical classification parity depends on a hash-bound TESIS projection or an explicitly supported verified compatibility view. The web observer must never invoke the exporter, evaluator, or experiment runner. An operator runs the exporter offline and selects its output for retrieval.

The [web handoff](../upcoming/HANDOFF_TESIS_WEB_ARTIFACT_RETRIEVAL_2026-10-12.md#5-acceptance-requirements-for-the-web-implementation) owns API, browser, replay, and UI acceptance. Its completion does not close producer gates. Producer completion does not establish frontend compatibility.

## 6. Acceptance requirements for the TESIS implementation

These requirements were declared during the documentation split; completed producer evidence is recorded in section 7. Follow the user's requested verification scope. Do not add or run TESIS tests automatically. Framework E2E is opt-in, including offline/mocked E2E; live checks require explicit DVWA/provider scope. Artifact export needs no new live experiment.

| Gate | Acceptance behavior |
| --- | --- |
| Review metadata | Newly generated pending/final status files retain execution ID, run ID, source path/hash, generated timestamp, selection, config/method/rubric, and separate Human/AI workflows. Missing finals remain null. |
| Manifest metadata | Model/profile, repeat, parent/child identity, explicit relative source/journal/snapshot paths, and one-based indexes are preserved where known. Existing readers and old manifests remain usable. |
| Atomic publication | Polling readers see the prior complete JSON or the new complete JSON. Write failures retain correct error reporting; temporary publication does not overwrite immutable historical sources or change journal semantics. |
| Catalog | Normal, flat, configured research roots, and embedded matrix children preserve exact execution identity and membership. Sidecars and receipts do not become new runs. Ambiguous copies and missing primaries are diagnosed. |
| Status classification | Reuse `core/run_status.py` for all 12 execution/outcome combinations. Unknown historical execution and skipped/unstarted coordinates remain explicit. Candidate executed/not_executed status remains separate. |
| Historical projection | A hash-bound export of the current compatibility cohort retains 108 completed and outcomes 57 confirmed, 10 no_finding, 9 unconfirmed, 32 fixture_limited. Original 61/47 legacy counts and the three historical incomplete categories retain their source/epoch attribution. All original source hashes are preserved. |
| Coverage | Planned, represented/collected, completed, failed, interrupted, confirmed, unknown, and skipped/unstarted counts retain their own meanings. Outcome counts follow the current aggregation's attribution rule. |
| Review catalog | Validate original source hash, execution identity, method/config/rubric/workflow, and receipt arithmetic. Human and AI remain separate; pending/stale/missing workflows retain nulls. The epoch7 associations account for 97 final AI workflows and 11 pending workflows without counting old status files as current runs. |
| Scores and metrics | Provisional runtime scores retain their origin. Final payload mean, fractional components, full formula, and receipt rounding remain intact. Unavailable metrics preserve null/reason and availability counts; legacy numeric placeholders are excluded from means. |
| Projection publication | Version the projection independently and retain generation/classifier epoch, root identifiers, original-byte source hashes, and source-specific detail links. No DVWA/provider call, evidence fabrication, source rewrite, or fresh scoring occurs. |
| Consumer handoff | Supply sanitized representative exports and field documentation sufficient for the web adapter. Record the agreed contract/version and remaining integration gates. |

Reuse existing checks when their relevant code/config is unchanged. Relevant checks include `tests/test_artifact_layout.py`, `test_execution_security_status.py`, `test_execution_status_review_regressions.py`, `test_evaluation_metrics.py`, and `test_nullable_metrics_regression.py`, plus existing repository/review/publication checks as applicable. Add a focused test only for an authorized behavior not already covered. Save validation artifacts under `results/` and distinguish pure/offline adapter checks from E2E and live execution.

This handoff closes only when its TESIS changes and authorized acceptance gates pass. Integration completion additionally requires the web handoff's accepted retrieval and display behavior.

## 7. Implemented producer contract and acceptance

The producer contract is frozen as [`observer-projection.v1`](../reference/observer_projection.md), and the companion web handoff now references that version. This establishes the producer interface and consumer handoff; it does not claim a tested web adapter or browser integration.

Implementation:

- `evaluation/reporter.py` publishes reader-facing JSON atomically using unique same-directory temporary files. Primary, manifest, matrix, failure and review writers use it; descriptor and append-only journal contracts remain intact.
- `evaluation/thesis_scoring.py` adds execution/run identity, source path/hash, selection and generation time to review statuses, plus per-workflow components and numerator/denominator. Rule hashing resolves package paths independently of the operator's working directory.
- `tesis/artifact_layout.py` adds model/profile, repeat, parent identity, timing, explicit index conventions and available relative detail locations without changing the manifest v1 discriminator.
- `tesis/artifact_catalog.py`, exposed through `ArtifactRepository.catalog()`, catalogs configured normal/flat/research/file roots and exact embedded membership. It verifies real-path containment and original bytes, diagnoses ambiguous copies and missing primaries, and requires declared ownership for shared snapshots/journals.
- `evaluation/observer_reviews.py` validates separate Human/AI source, method/config/rubric/workflow, candidate/decision/evidence and arithmetic bindings. Pending selection follows explicit epoch order; eligible final receipts follow timestamp with deterministic ties. Stale or unrelated files cannot displace valid finals.
- `evaluation/observer_export.py` and `python -m tesis export-observer` create only a new derived projection under `results/`, using existing status/metric semantics. The projection carries source-byte hashes, classifier/publication code hashes, canonical coverage, stored legacy totals, separate historical labels and source-specific detail links.
- Both methodology languages, architecture and scoring references document the contract. `tests/fixtures/observer_projection/epoch7-example.json` supplies a sanitized four-outcome metadata excerpt with original bindings and a fractional final example. Its embedded `fixture` metadata explains that original source files are not bundled.

Evidence directory: [`results/validation/artifact-export-2026-10-12/`](../../results/validation/artifact-export-2026-10-12/).
The [acceptance audit](../../results/validation/artifact-export-2026-10-12/acceptance.json) binds the final [projection](../../results/validation/artifact-export-2026-10-12/observer-projection.json), current code hashes, JUnit files, historical comparison, consumer example and live smoke manifest. The read-only acceptance script is `verify_export.py` in that directory.

| Gate | Result and evidence |
| --- | --- |
| Review metadata | New pending/final status identity, timestamp, selection, config/rubric/method and independent workflows pass focused controls; null finals remain null. |
| Manifest metadata | Model/profile/repeat, parent ID, stored timing, relative invocation detail and one/zero-based index conventions pass focused controls and existing manifest compatibility checks. |
| Atomic publication | Polling readers see complete prior/new JSON during concurrent writers. A replacement failure retains prior bytes, removes the temporary file and propagates its exception. |
| Catalog | Flat, file, invocation, research, standalone and embedded child controls pass. Copies, missing primaries, external symlinks and absent shared detail are diagnosed. |
| Classification | All 12 lifecycle/outcome pairs pass. Candidate executed/not_executed remains separate; a completed child cannot terminate an active parent. Invalid historical lifecycle fields remain unknown. |
| Historical projection | All 108 original hashes and canonical reason/outcome fields match the saved compatibility view: 108 completed; 57 confirmed, 10 no_finding, 9 unconfirmed, 32 fixture_limited. |
| Historical attribution | Original matrix status counts remain 61 success / 47 error. The 47 separately bound analysis rows retain 36 executed_without_candidate_confirmation, 4 executed_unconfirmed_weak_or_partial_signal and 7 fixture_permission_oracle_unavailable. |
| Coverage | Matrix planned/represented/completed = 108, unstarted = 0; confirmed = 57 independently. Canonical groups reuse aggregate_runs and its outcome-attribution denominator. |
| Review catalog | Epoch1/2/3 roots produce 97 final AI and 11 pending workflows, with zero invalid review bindings. Old status files are never additional coordinates. Human/AI and fractional arithmetic controls pass. |
| Scores and metrics | Runtime scores retain their provisional source, absent dimensions remain null, final candidate means/fractional components and four-decimal formula are validated. Unavailable metrics retain counts and reasons. |
| Publication/consumer handoff | Final projection and metadata example retain independent schema/code/source bindings. Export made no requests, evaluator calls, source writes or new grading decisions. Consumer implementation remains in the web handoff. |

Focused command (151 passed; no full suite):

```bash
.venv/bin/python -m pytest -q tests/test_observer_export.py tests/test_observer_export_e2e.py tests/test_artifact_layout.py tests/test_reporting_telemetry.py tests/test_execution_security_status.py tests/test_execution_status_review_regressions.py tests/test_evaluation_metrics.py tests/test_nullable_metrics_regression.py tests/test_runtime_interfaces.py --junitxml=results/validation/artifact-export-2026-10-12/junit.xml
```

After the final identity-fallback edit, the affected adapter/CLI checks were rerun: 28 passed in `junit-final-adapter.xml`; unchanged writer, manifest, status and metric evidence was reused. The saved-artifact CLI E2E is offline and focused on source → review → projection publication. It is not an attack-graph or live experiment E2E.

Reproducible offline export:

```bash
.venv/bin/python -m tesis export-observer   --source-root epoch7=results/validation/scoring-v4-remediation-2026-10-12-matrix-epoch7   --review-root epoch1=results/validation/scoring-v4-remediation-2026-10-12-matrix-epoch7/ai-review-epoch1   --review-root epoch2=results/validation/scoring-v4-remediation-2026-10-12-matrix-epoch7/ai-review-epoch2   --review-root epoch3=results/validation/scoring-v4-remediation-2026-10-12-matrix-epoch7/ai-review-epoch3   --historical-analysis epoch7:incomplete-outcome-audit-v2.json   --output results/validation/artifact-export-2026-10-12/observer-next.json
```

Choose a new output filename for each publication. `PYTHONPATH=. .venv/bin/python results/validation/artifact-export-2026-10-12/verify_export.py` produced the final acceptance audit and example; its publication assertion prevents overwriting that evidence epoch.

### Authorized live smoke boundary

The user authorized only three high-security coordinates using `openai_compatible` and AI scoring from `config.yaml`. The implemented live scope was explicitly limited to authenticated, contained read-only SQLi/BF/AC page requests and one AI review of an already saved candidate per surface. It did not execute payloads, attack agents, a new experiment, or the matrix. The saved evaluator's immutable non-secret profile was retained; credentials/provider/model came from the current configuration. The current config uses a 1024-token evaluator budget while the saved source froze 4096; this smoke retained the saved 4096 budget rather than rewriting its configuration.

The first network attempt was sandbox-blocked and retained in `live-smoke/`. The approved retry completed in `live-smoke-epoch2/`: detected level high, three HTTP 200 surface responses, three actual provider calls, three accepted AI decisions, and unchanged original sources. The source-bound review results are one final (BF) and two pending (SQLi/AC), because only one candidate per coordinate was reviewed. Missing grades were not filled in. Login/security setup requests are separate from the three surface GETs and are not experiment coordinates.

Live command:

```bash
ARTIFACT_SMOKE_OUTPUT=results/validation/artifact-export-2026-10-12/live-smoke-epoch2 PYTHONPATH=. .venv/bin/python results/validation/artifact-export-2026-10-12/live-smoke/run_smoke.py
```

The [live manifest](../../results/validation/artifact-export-2026-10-12/live-smoke-epoch2/smoke-manifest.json) binds config/source hashes, bounded call counts, HTTP metadata and review outputs. Final adapter code revalidated these saved live outputs into `live-smoke-epoch2/observer-current.json` with no additional calls. Final additive workflow metadata/identity refinements were covered offline; the earlier live smoke is not claimed as fresh attack-graph acceptance for that final code epoch.

The historical cohort has 109 absent invocation journals and 109 absent snapshots (108 children and their parent), plus four unsupported auxiliary schemas. These are explicit discovery diagnostics, preserved in the acceptance audit; the exporter did not create missing historical evidence. API/browser retrieval, source revalidation at the web boundary, and UI/replay acceptance remain outstanding in the companion web handoff. No commit or push was made.
