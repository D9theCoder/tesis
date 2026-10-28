# Handoff: TESIS Web artifact retrieval and display

Status: **upcoming, 2026-10-12**. Source inspection and a saved-artifact comparison are complete. Implementation and acceptance remain outstanding.

## 1. Objective and inspection boundary

Implementation repository: `/home/kevin/coding/tesis-web`.

Update the read-only Next.js observer to retrieve TESIS experiments, preserve execution identity and evidence, and display lifecycle, security outcome, metric availability, and thesis reviews correctly. This document owns the web filesystem/API adapter, schemas, normalization, live reducer, and UI work. Python artifact publication and historical projection are assigned to the [TESIS handoff](../completed/HANDOFF_TESIS_ARTIFACT_EXPORT_2026-10-12.md). The producer handoff follows its implementation lifecycle; this web handoff remains upcoming.

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

## 2. Producer contract and recent metric changes

The [TESIS handoff's current producer contract](../completed/HANDOFF_TESIS_ARTIFACT_EXPORT_2026-10-12.md#2-current-producer-contract) documents the complete file layout, discriminators, matrix counters, scoring rules, and historical categories. Its [retrieval contract](../completed/HANDOFF_TESIS_ARTIFACT_EXPORT_2026-10-12.md#4-retrieval-contract-owned-by-tesis) is the shared DTO to freeze before coding. These sections describe the inputs the web adapter consumes; their producer implementation belongs to the companion handoff.

Read current fields first and tolerate missing additive fields in older sources. Do not require forthcoming manifest/review metadata to load existing artifacts. Preserve these rules throughout listing, results, coordinate details, polling, and downloads:

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

## 3. Required changes in TESIS Web

Paths below are relative to `/home/kevin/coding/tesis-web`.

| Priority | Files | Observed gap | Required change |
| --- | --- | --- | --- |
| P0 | `lib/server/fs-util.ts`, `lib/server/resolve-run.ts`, all runtime/results routes | Discovery is rooted only at `TESIS_ROOT/results/runs` and assumes shallow dated directories. `isExecutionJson` requires `exec-`; `resolveRun` does not collect `.matrix.json` as a primary artifact and uses prefix/directory-substring matching. Flat roots and the current research cohort are missed. | Add configured, server-only artifact roots and review roots; retain `results/runs` as the default. Share one manifest/content-aware resolver across routes. Support a root that is itself an experiment or a flat artifact directory. Resolve exact IDs and distinguish primary sources, aggregates, reviews, and sidecars. Detect ambiguous identity matches rather than selecting by filename prefix. |
| P0 | `app/api/runtime/runs/route.ts` | First summary wins through `seen`, so a descriptor/manifest can suppress richer artifact fields. Manifest children are given the parent's mode/directory and `matrixExecutionId` is set to their own ID. Later child fallback sets it to null. No pagination beyond the first 200 entries. | Merge descriptor, manifest, and primary metadata by execution identity with explicit precedence. Resolve each child's actual directory and parent ID, retain its condition/method/repeat/model, and expose artifact availability. Sort by stored timestamps with an explicit fallback. Add bounded pagination rather than silently hiding older runs. |
| P0 | `lib/schemas.ts`, `lib/result-normalizer.ts`, `lib/formatters.ts` | Public result/live/coordinate types expose one status string, omit canonical reasons/counters, and omit repeat identity. Existing schemas are mostly optional and several are never parsed; `normalizedResultSchema` accepts any record. | Define typed execution, outcome, reason, identity, counts, metric availability, review workflow, and receipt schemas. Keep legacy status separately. Parse API/filesystem boundaries rather than asserting types. Permit additive unknown fields while validating discriminators and actual nullability. Use separate schemas for run and candidate execution statuses. |
| P0 | `lib/result-normalizer.ts`, `components/results/scoring-table.tsx` | `buildScoreRows` fills missing scores with zero; `deriveDimensions` recomputes a partial composite and rounds dimensions to integers. It does not load final review receipts or pending workflows. | Keep provisional runtime scores and final Human/AI review vectors distinct. Preserve nulls, pending reasons, precision, rubric, and score origin. Show finals only from an accepted source-bound receipt. Remove partial-component final recomputation and correct the interpretations/evidence basis for v4. |
| P0 | results/runtime summary components and `components/results/coordinate-index.tsx` | Badges and summary fields depend on legacy success/error, while the new category split is absent. | Show Execution and Security outcome independently, with structured reason codes/details and reference links. Add the canonical matrix counters, unknown attribution, and planned/unstarted coverage. Offer separate filters for lifecycle, outcome, and historical incomplete classification. |
| P0 | results routes, `lib/api-client.ts`, new shared review resolver | Current endpoints return only the execution source; isolated review epochs are never joined. | Discover configured review outputs and join final receipts by execution ID, exact source SHA-256, and Human/AI workflow. Check rubric/method/config binding and receipt shape/arithmetic before exposing a final. Hash the original file bytes before redaction. Show pending, stale/mismatched, missing, or unavailable workflows explicitly. Retain historical receipts for inspection. |
| P1 | `lib/server/resolve-run.ts`, coordinate route, `lib/result-normalizer.ts` | Coordinate lookup requires a dated parent's exact `.matrix.json` filename. Embedded children are normalized without merging `final_state`; failed detail lookup uses `selectedCoordinate`, which substitutes scores but retains parent evidence/config/raw data. | Resolve parent membership by exact child execution ID. Support embedded-only children and configured roots. Normalize each child independently using its own `final_state` and config. Embedded fallback must use that child's complete data or report detail unavailable. Never present parent evidence as the selected child's evidence. |
| P1 | `app/results/[executionId]/page.tsx` | Coordinate requests do not guard out-of-order responses; selected state can survive route changes, and failed detail retrieval falls back to the mixed parent/child view. | Reset dependent state on execution changes and cancel/guard stale child requests. Keep selected identity, header, evidence, JSON download, and scoring on the same child source. |
| P1 | `lib/event-reducer.ts`, `components/runtime/runtime-shell.tsx`, events route | Every `*.completed` event can set `endedAt`, including `llm.completed`; child finishes can end matrix timing. Matrix children share one accumulated graph/findings state. Child journals are not resolved through the parent when absent locally. | Treat only the selected execution's terminal run/matrix events as terminal. Maintain parent lifecycle separately and partition child state by execution ID, using `data.coordinate_execution_id` for `matrix.run.*`. Filter/identify child events in a shared parent journal; an advancing byte cursor still measures the underlying journal. Keep graph and outcome unions within a child rather than merging unrelated coordinates. |
| P1 | events route and `lib/server/fs-util.ts` | The journal reader allocates the entire remaining file; `hasMore` is always false. Malformed/unreadable inputs degrade silently, and legacy status defaults to running even after a saved run finished. | Bound bytes/events per response, preserve UTF-8 byte offsets and partial-line handling, and return correct continuation state. Detect truncation/replacement and reset the browser reducer with a journal identity. Surface parse/read diagnostics and derive terminal metadata from the selected source when a descriptor is absent. |
| P1 | `app/api/akg/route.ts`, `lib/api-client.ts`, runtime shell, `lib/akg-snapshot.ts` | `/api/akg` selects a root snapshot or the first experiment snapshot, independently of the selected run; the shell fetches it once. | Accept an execution selector and resolve the invocation's captured snapshot, including a matrix child's parent snapshot. Return snapshot identity/hash/source. Reload on execution change. Mark a static fallback explicitly. Preserve topology; tolerate the producer's snake_case metadata and nullable node surface. |
| P1 | `lib/result-normalizer.ts`, `components/results/detail-table.tsx`, `components/results/evidence-drawer.tsx` | Responses use `response_excerpt`, but normalization reads `response_snippet`. Missing `transport_ok` becomes a transport error. Evidence gets array-index IDs, blank timestamps, and no related-event joins; a detected signal is labeled success without the verifier's proof decision. | Use stored timestamps/excerpts/statuses and stable evidence/request/candidate/visit IDs. Link execution events, validation, response/timing evidence, verifier history, candidate dispositions, and score references. Show transport, signal, and verifier outcome as separate facts. Do not upgrade a signal or infer a negative from missing fields. |
| P1 | `lib/result-normalizer.ts`, scoring/metrics components | Metric availability/reasons and canonical totals are absent; null can become zero through `asFloat(null)`. Several experiment rates are sought in provider performance summaries. | Implement the documented metric source precedence and availability contract; expose denominator and unavailable reasons. Preserve unknown provider usage/cost. Use provider summaries only for their actual fields. |
| P1 | `lib/server/fs-util.ts`, all file-backed routes | `resolveInside` only checks lexical paths and is not applied consistently. Future manifest/review paths can be external; generic redaction is primarily key-based, and routes do not supply known secrets for strings. Broad key rules can also mask non-secret identifiers such as `credential_pair_id`. | Enforce canonical real-path containment under configured roots for all source/manifest/review/snapshot references, including symlinks. Keep source/review roots separate and explicit. Apply schema-aware redaction before API responses/downloads, including free text, request structures, excerpts, and model output. Preserve safe IDs, hashes, and token usage metadata. |

Suggested API additions should be additive: retain existing URLs, add a typed result bundle containing execution metadata, final review workflows, source binding, diagnostics, and source-specific detail links. A matrix summary response should contain coordinate metadata; load full child evidence on selection instead of returning the entire embedded matrix to every summary request. The server owns filesystem resolution, validation, hash checks, and redaction; the browser owns presentation and deterministic replay.

Do not let the web observer run the TESIS runner or review evaluator, mutate `TESIS_ROOT`, trigger providers, or contact DVWA. The existing local mock flow stays distinct from live data. No new database, experiment service, or writable experiment endpoint is needed for this synchronization.

## 4. Implementation order and dependencies

1. Agree the [shared retrieval DTO](../completed/HANDOFF_TESIS_ARTIFACT_EXPORT_2026-10-12.md#4-retrieval-contract-owned-by-tesis) with TESIS and prepare sanitized saved fixtures. Start with canonical lifecycle/outcome, review binding, null semantics, and metric availability.
2. Implement one configured-root resolver and use it across discovery, results, exact child membership, journals, snapshots, and review discovery. Preserve backward compatibility with existing artifacts.
3. Implement validated normalization and separate Human/AI review retrieval, retaining source hash, rubric, workflow, score origin, reasons, and metric availability.
4. Update counts, status/outcome badges and filters, historical analysis details, score tables, evidence links, and source-specific coordinate views.
5. Partition live state by execution, correct terminal handling, switch run snapshots, and bound journal reads. Keep local mock replay isolated from live discovery.
6. Complete the agreed focused checks, update the web README/configuration guidance, and save acceptance evidence bound to the web code and input artifact/projection epoch.

TESIS producer tasks are in the [companion handoff](../completed/HANDOFF_TESIS_ARTIFACT_EXPORT_2026-10-12.md#3-required-changes-in-tesis). New review identities/timestamps and richer manifests are additive dependencies; the web adapter must handle older files conservatively while they are introduced. Configured roots, new category display, source-specific evidence, and most replay fixes can be implemented against current files without waiting for all producer tasks.

For historical canonical parity, consume the TESIS offline projection or an explicitly supported verified compatibility view and verify its source hashes. Until that input is available, display unknown historical attribution and record the parity gate as incomplete. Do not independently port Python proof gates into browser heuristics, launch the exporter from an endpoint, or rewrite source artifacts.

The TESIS producer owns classification/publication/schema acceptance. This handoff owns API/UI behavior and consumer acceptance. Complete this document only after its required web gates pass; record cross-repository dependencies still outstanding.

## 5. Acceptance requirements for the web implementation

These are future checks, not checks performed for this documentation split. Follow the user's verification scope and the TESIS Web repository guide. Use saved fixtures and pure adapter/reducer checks for initial integration. Browser/framework E2E requires an agreed scope; no live DVWA/provider run or matrix is authorized by this handoff.

| Gate | Acceptance behavior |
| --- | --- |
| Discovery | Retrieve a normal single run, matrix parent, exact child, flat legacy source, and the explicitly configured epoch7 root. Listing does not turn rich/failure/review/audit sidecars into extra executions. Missing primaries remain unavailable even when a descriptor/manifest exists. |
| Identity | One-based manifest and zero-based event indexes normalize consistently. Child retains parent, condition, method, mode, and repeat. Duplicate run IDs cannot select another execution. Ambiguous execution IDs/root copies are diagnosed. |
| Recent status split | Cover all 12 execution/outcome combinations; interrupted/failed can retain findings, and completed can have no_finding/unconfirmed/fixture_limited. Candidate executed/not_executed stays separate. |
| Historical compatibility | For the hash-bound 108-row compatibility view, show 108 completed and outcomes 57/10/9/32 as above. Display the preserved 61/47 raw legacy totals only as historical metadata. Display the three old incomplete categories with their original analysis attribution. Preserve original hashes. |
| Coverage | Unknown historical execution and skipped/unstarted rows remain visible and outside the wrong denominator. Planned/collected/completed/confirmed counts have distinct labels. |
| Review | Correct receipt source bytes, hash, ID, method, rubric, workflow, and arithmetic are required. Human and AI remain independent; pending/stale/missing proof yields null. Epoch7 has 97 saved final receipts across its review outputs; use the approved current epoch associations to account for the 11 pending workflows, rather than counting all 146 historical status files as current workflows. |
| Scoring | Missing components cannot produce a final composite. A supported zero remains zero. Final payload mean and fractional components are preserved; runtime max-candidate scoring stays provisional. A final component is not rounded to an integer. |
| Metrics | Unknown/null cost or consistency is N/A with reason; unavailable legacy numeric placeholders are not averaged as zero. Correct report-summary precedence and aggregate availability counts are retained. |
| Evidence | Request/validation/response/verifier/candidate joins open the matching source. Excerpts and timestamps use the current fields. Signal detected does not claim independent confirmation; missing transport metadata does not claim a transport failure. |
| Live reducer | `llm.completed` and child terminal events do not end a matrix parent. Concurrent child paths/findings stay distinct. Cancellation preserves evidence and applies the selected execution's canonical metadata. Switching sessions rejects stale async responses. |
| Journal | Bounded byte/event pages preserve partial lines and multibyte characters. Filtering a parent journal to one child advances the underlying cursor correctly. Journal replacement/truncation resets state predictably. |
| Snapshot | Switching runs switches captured topology; parent snapshot serves a child only with declared ownership. Static fallback is labeled. |
| Read-only containment/redaction | No run launch/cancel/review mutation endpoint is introduced. Paths, symlinks, and review source references stay inside configured roots. Secrets in structured and free-text fields are redacted while safe IDs/hashes/usage remain readable. |
| UI consistency | Coordinate header, evidence drawer, score origin, status/reasons, and JSON download all refer to the same selected source. Rapid selection cannot show a stale child's data. |

Reuse existing web checks where they cover these behaviors; add focused tests only for uncovered contract behavior when authorized. TESIS Web currently has AKG/mock/layout/runtime-shell coverage but no dedicated artifact resolver, result-normalizer, or review adapter test files. Follow its repository guide for applicable typecheck/lint/build checks and README/configuration updates. Browser and framework E2E require an agreed scope, and live checks require separately specified DVWA/provider authorization.

TESIS checks and producer acceptance are owned by the [companion handoff](../completed/HANDOFF_TESIS_ARTIFACT_EXPORT_2026-10-12.md#6-acceptance-requirements-for-the-tesis-implementation). Save consumer evidence against the web code and input artifact/projection epoch. Source inspection, an offline adapter check, and a browser/live integration check establish different facts; report any requested gate left incomplete.

Completion requires implemented retrieval and display behavior plus evidence for the accepted web gates. This handoff and its source scan establish the changes to make; they do not establish frontend compatibility or a new live research result.

## Producer contract frozen on 2026-10-12

The TESIS producer supplies [`observer-projection.v1`](../reference/observer_projection.md). Use its grouped DTO, declared source/review roots and epoch policy, original-byte hashes, zero-based coordinate indexes, and independent Human/AI workflows at the API boundary. The producer CLI is explicitly offline; the web observer must not invoke it. Representative sanitized projection metadata is supplied in `tests/fixtures/observer_projection/epoch7-example.json` in TESIS. Consumer schema adaptation, source revalidation, API/browser checks, and frontend compatibility remain outstanding in this handoff.
