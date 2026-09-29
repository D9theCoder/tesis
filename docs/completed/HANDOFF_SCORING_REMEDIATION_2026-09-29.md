# Handoff: scoring correctness and evidence remediation

Status: completed. The baseline audit below was read-only. The remediation changed
runtime scoring, evidence export, and methodology; the original experiment
artifacts remain immutable. Final acceptance is recorded at the end.

Baseline: `ed07851a343a829eb3cd0f1f17869d014589190c`, after the three approved
commits. Start implementation by checking for subsequent changes.

## Objective and boundaries

Make every score reproducible from the evidence that earned it. Resolve the
confirmed assignment/export defects and determine which routed chains actually
complete. Higher scores are not the acceptance criterion: correcting candidate
attribution can lower scores, and legitimate zeros must remain zero.

Preserve all six dimensions and the existing formula:

```text
Srun = 0.20*Smethod + 0.20*Spayload + 0.30*Sexploit + 0.10*Schain + 0.20*Soutput
```

Keep the nine DVWA methods, static AKG, containment enforcement, experiment
conditions, `target_method`, payload mode, and repeat identity intact. Do not
replace the selected method with the highest-scoring method, award points for
unexecuted candidates, reweight unavailable dimensions, or relax confirmation
policy. Update both methodology languages and affected architecture guidance
when implementing clarified scoring semantics.

## Baseline evidence

The [completed matrix report](../completed/METHOD_AGENTS_POST_REVIEW_MATRIX_2026-09-29.md)
contains 297 coordinates at three repeats: 81 forced static, 162 forced hybrid,
and 54 automatic hybrid. There were 189 supported confirmations and 108
unverified outcomes, comprising 99 access-control fixture gaps and nine
high-level error-SQLi outcomes with suppressed errors. Those outcomes do not
establish model failure.

The matrix-era offline suite passed 1,600 tests with two skips. The
[subsequent replay export acceptance](../completed/REPLAY_MANUAL_EVIDENCE_REVIEW_2026-09-29.md)
passed 1,602 with the same skips. These are historical checks, not acceptance of
the proposed scoring repairs. The skips concern medium SQLi controls for a
session-input flow available only at high security.

New audit receipts live under
`results/validation/scoring-handoff-2026-09-29/`:

- [Failure inventory](../../results/validation/scoring-handoff-2026-09-29/failure-inventory.json),
  written before the isolated diagnostics.
- [Audit results](../../results/validation/scoring-handoff-2026-09-29/audit.json),
  including code hashes, score vectors, exact witnesses, and synthetic diagnostics.
- [Source manifest](../../results/validation/scoring-handoff-2026-09-29/source-manifest.json),
  pinning all 297 source artifact hashes and coordinates.
- [Route audit](../../results/validation/scoring-handoff-2026-09-29/chain-routes.json),
  deduplicating append-only history by source artifact and route position.
- [Repeatable audit script](../../results/validation/scoring-handoff-2026-09-29/audit_scoring.py).

Run from the repository root with the original evidence available:

```bash
PYTHONPATH=. .venv/bin/python results/validation/scoring-handoff-2026-09-29/audit_scoring.py
```

Observed: 297 inputs checked, zero formula mismatches, zero fresh HTTP calls,
and zero fresh provider calls. Transport and provider entry points are patched
to reject calls during the synthetic diagnostics. This audit demonstrates the
mechanisms below; it is not graph E2E acceptance. `results/` is gitignored:
retain the receipt directory and source evidence when transferring this handoff.
After repairs, write a separate comparison script/output directory rather than
overwriting the baseline receipts.

| Observation | Count | Interpretation |
| --- | ---: | --- |
| Stored `Srun` agrees with the weighted formula | 297/297 | No observed arithmetic defect |
| `Soutput = 0`, with navigation-only containment events | 297/297 | Output quality is penalized for discarded page links |
| `Schain = 0` | 297/297 | Requires eligibility and completion audit |
| Forced coordinates that intentionally stop after their target | 243 | A chain zero can be correct |
| Distinct routed chain transitions | 27 | Routing occurred; completion is a separate question |
| Routed brute-force destinations with positive verifier evidence | 9 | Login confirmed; dependency on extracted data is unproved |
| Routed visits without a method-selection score | 27 | Nine `bf_dictionary`, eighteen `ac_idor` visits |
| Scored candidate with only negative exploit events in the audit | 1 | Concrete candidate-score inflation witness |
| Successful surface runs with final-method `Sexploit < 3` | 3 | Earlier success and final selected-method score differ |

## Required fixes

### F1 — Separate discarded navigation from output scope violations

Priority: P2. Confirmed scoring attribution defect.

[Recon](../../foundation/recon.py) emits `kind: navigation` when an external
page link is discarded before HTTP. [The scorer](../../core/scorer.py) assigns
`Soutput = 0` for any containment event, without checking its kind or origin.
All 297 containment-event arrays contain only these navigation observations:
1,485 events in total. This penalizes static controls as well as hybrid runs
and attributes DVWA page content to LLM output quality.

An offline matched diagnostic changes only one discarded navigation event:
`Soutput` falls from 4 to 0 and `Srun` from 2.9 to 2.1 for the vector
`(Smethod, Spayload, Sexploit, Schain) = (3, 3, 3, 0)`. This is not a prediction
that every corrected run gains 0.8; other output failures retain their penalties.

Classify events at their existing producers and consume that classification in
the scorer. Keep discarded navigation visible as a containment observation.
Actual out-of-scope payloads and attempted requests/redirects must remain
rejected, recorded, and penalized. Give events origin and method/visit context
where known. Do not blanket-ignore containment events or silently treat unknown
legacy events as benign.

### F2 — Record proved chain completion and credit the relevant method

Priority: P2. Confirmed completion/crediting gaps; historical chain success is
unresolved without a dependency control.

Relevant code: [shared agent updates](../../agents/state_utils.py),
[chaining coordinator](../../core/chaining_coordinator.py), and
[static AKG](../../core/knowledge_graph.py). All nine agents call `chain_check()`.
For example, UNION and dictionary agents call it with a method-confirmed node
and the incoming state, before their new outcomes are merged.

The helper examines only direct `is_chain` edges from that node and requires
the edge target in `achieved_outcomes`. Many predefined edges originate at
surface/enabling nodes, while other targets name executable methods whose
confirmation belongs in `confirmed_vulns`. `_derive_surface_confirmed()` also
maps a method back to its method-confirmed node instead of the surface node
its name/docstring promises. The router records `status: routed`, but no
corresponding completion receipt ties the downstream verifier to that route.
`make_update()` derives the chain component only from an aggregate method
score of at least 4. These paths leave all saved chain maps at zero.

The audit found nine `credentials_extracted -> bf_dictionary` routes and
eighteen routes to `ac_idor`. Nine routed dictionary destinations confirmed
login. A login by an independent static credential pair or an existing admin
session does not prove that the extracted material enabled it. Access-control
visibility without an independent permission oracle remains unverified.

Use the existing post-method coordinator, which sees merged verifier evidence,
to distinguish ready, routed, executed, completed, failed, and unverified
transitions. Derive surface aliases from the predefined registry/AKG; do not
append an enabling outcome as a new vulnerability confirmation.

Proposed rule: award `Schain = 4` to the destination method visit only when a
recorded route has proved prerequisites, the destination consumed the relevant
source material/session, and its verifier proved the required downstream
outcome. Otherwise retain 0 with a reason. Identify the source evidence,
destination evidence, route, and credited method explicitly. Keep historical
completed chains visible even if a later selected method has `Schain = 0`.

Inspect credential representation before declaring the SQLi-to-brute-force
chain feasible. Extracted DVWA password hashes are not plaintext passwords.
Reuse the existing bounded dictionary and supported account identifiers where
applicable; do not add hash cracking, new attack methods, or invented credentials.
If the executor cannot consume the extracted representation, record that gap
and retain zero rather than crediting an unrelated login.

### F3 — Grade candidates from their own evidence

Priority: P2. Confirmed candidate-score inflation.

`payload_score_updates()` in [shared agent updates](../../agents/state_utils.py)
assigns the invocation's final method score to every validated payload string
in `tried_payloads`. A failed exploit can therefore inherit another candidate's
score 3. This also affects payload-success metrics in
[evaluation metrics](../../evaluation/metrics.py).

The saved witness is `sqli_time_blind_high_bypass_3` in the automatic linear
high-SQLi `run-003` artifact identified in `audit.json`: score 3 despite its only
linked exploit event being HTTP 404 with `success: false`. The isolated
diagnostic likewise gives both a failed candidate and a successful candidate 3.

Replace uniform assignment in the shared helper with candidate-specific,
stage-aware evidence and verifier decisions. Keep seed/generated provenance
and invocation identity. A valid false Boolean result, a probe signal, an HTTP
success, and a confirmed exploit have different meanings; grade against the
declared criterion rather than status code or a sibling candidate's result.
Unexecuted candidates remain null/unscored. On revisits, preserve the evidence
that earned any historical maximum and the later negative decision separately.

### F4 — Prevent old maxima from erasing output penalties

Priority: P2. Confirmed offline reproduction; prevalence in the matrix is not
established because every original output score was already zero.

[State score reducers](../../core/state.py) retain maxima for all score maps,
including output and composite scores. [The scorer](../../core/scorer.py)
also takes the maximum old/new output score, but computes the new composite
using the raw current output score.

Diagnostic: after a clean `Soutput = 4, Srun = 2.9`, introduce a genuine request
containment violation. The node returns stored output 4 and composite 2.1,
which disagree under the formula. Applying the real reducers retains output 4
and composite 2.9, hiding the new penalty altogether.

Define output-event scope before changing aggregation. The methodology describes
selected-method output, while current code counts run-wide events. Proposed
policy: within the declared scoring context, an actual scope violation cannot
be erased by an earlier clean response. Retain per-visit output decisions and
earlier exploitation evidence; compute the final composite from the same
stored component vector. Change output/composite merging where needed rather
than replacing all monotonic reducers.

Document how orchestrator and payload-generator failures attach to a method
visit, and how run-wide violations apply. Keep provider timeouts, returned
schema violations, invalid JSON, native response-mode mismatches, guardrails,
and deterministic fallback distinct. Specify their rubric mapping; do not
invent invalid-JSON evidence or alter parsing to increase output scores.

### F5 — Score and identify deterministic routed selections

Priority: P2. Confirmed selection-score omission.

The [orchestrator](../../agents/orchestrator.py) assigns `Smethod` when it selects
a method: 3 for a viable choice and 1 for an in-scope nonviable choice. The
[router](../../core/chaining_coordinator.py) selects downstream methods directly
and bypasses that assignment. All 27 audited routed visits enter execution
without a method-selection score for the destination.

Reuse the existing selection grading rule at the common selection boundary.
Store the selection source (`forced`, model/orchestrator, deterministic
fallback, or AKG route), method, visit, contemporaneous viability/prerequisites,
grade, and reason. Assess cross-surface destinations against their own surface
and proved prerequisites, not the stale source surface. Do not attribute an
AKG/forced selection to the model. A later successful exploit does not
retroactively prove that the method was viable when selected.

### F6 — Preserve scoring inputs and decision links in exports

Priority: P2. Confirmed artifact omissions.

[Runner export](../../evaluation/runner.py) projects a subset of final state.
All 297 exports omit `chain_history`, `current_chain`, `found_credentials`,
`attempted_agents`, and `tried_payloads` from that final-state projection.
Earlier frozen inputs recover some history, but are not the terminal scoring
input. Router events contain route fields at the top level; the runner emits
only `event["payload"]`, producing `akg.route.selected` events with `data: {}`.

Extend the existing artifact writer/state projection and normalize route events
to the established telemetry contract. Preserve sanitized scoring inputs and
append decision receipts for all dimensions, identifying their method/visit,
candidate or route, rubric version, source evidence, and aggregation rule.
Retain source/target, prerequisites, route status, stop reason, and verifier
links. Sanitize credentials with the existing redaction rules.

Update [manual scoring export](../../evaluation/manual_scoring_sheet.py) to link
the decision that earned a score, rather than a later unrelated verifier for
the same method. Preserve the existing fresh-execution scope for diagnostic
replay sheets; do not reintroduce inherited scored rows without evidence links.
Use the existing writer, schemas, and export helpers, without a new reporting
service or parallel score engine.

## Interpretation that must remain explicit

- The 243 forced coordinates intentionally stop after their target. Linear
  runs disable AKG chain credit. Neither condition should receive invented
  chain points or an altered `target_method` to make its score larger.
- The primary composite describes the final selected/last executed method.
  An earlier confirmed method can make the surface/run successful while a
  later unverified method has a lower composite. Three saved coordinates
  exhibit this. Show both contexts instead of substituting the earlier score.
- Current selection and ordinary exploitation components reach 3. A clean
  non-chain `(3, 3, 3, 0, 4)` vector yields 2.9, not 4. Explain eligibility and
  reachable component ranges; a nominal 0–4 rubric is not a guarantee that
  every experimental coordinate can earn 4 in every dimension.
- The 108 fixture-limited outcomes and the previously recorded model/provider
  failures retain their evidence-based classifications. This audit establishes
  code defects in grading/export, not that every unsuccessful payload was
  caused by code or that the LLM is uniformly effective.

## Implementation sequence and acceptance

Write the artifact-producing E2E failure controls before production changes.
Extend the existing method-agent/revisit and manual-evidence controls; fake only
external transport/providers and use the real graph, validator, reducers,
router, verifier, scorer, and export. Keep pure helper checks only for failures
the E2E assertions cannot observe.

1. **Event scope and scoring receipts — F1, F4, F6.** Prove navigation-only
   observations leave a clean output score at 4, while real forbidden payloads,
   requests, and redirect hops remain blocked and penalized. Exercise clean
   execution followed by a genuine violation through graph reducers: earlier
   positive exploitation evidence survives, the penalty remains visible, and
   the final stored vector reproduces `Srun`. Check route metadata and complete
   sanitized scoring inputs in the written artifact.
2. **Candidate attribution — F3.** Execute a failing and successful candidate
   in one visit, then revisit with a later negative result. Assert distinct
   candidate grades, accurate seed/generated attribution, null unexecuted
   scores, and exact score-to-response/verifier links. Include Boolean false
   controls and probe/exploit separation so a simplistic success flag cannot
   replace method verification.
3. **Routing and completion — F2, F5.** A ready/unexecuted route earns no chain
   credit. Neither a failed/unverified destination nor an unrelated login earns
   it. A positive reference must demonstrate source data/session consumption
   and the downstream verifier result. Check correct surface aliases,
   deterministic selection grades/provenance, no duplicate completion on
   revisits, and admin visibility without a permission oracle remaining
   unverified. Forced-target stops and linear runs retain their intended zeros.
4. **Report consistency.** Preserve a successful earlier method followed by a
   weaker final method, showing both the surface result and selected-method
   vector. Check stored/recomputed manual sheets agree, fresh replay scope is
   unchanged, and every changed grade has a traceable decision receipt.

Each control writes inputs/config, expected and observed decisions, actual
request/response evidence, final state, score vector, and export to
`results/validation/scoring-remediation-<date>/`. Retain failing baseline and
passing receipts in separate code epochs. No control may make an external
request or fresh provider call while labeled offline.

After focused controls pass, run the existing broader gates from repository
root and retain logs/JUnit receipts. These commands were run for acceptance:

```bash
.venv/bin/python -m pytest -q tests/test_method_agents_e2e.py tests/test_manual_scoring_evidence.py --junitxml=results/validation/scoring-remediation-2026-09-29/focused-junit.xml
.venv/bin/python -m pytest -q tests --junitxml=results/validation/junit.xml
.venv/bin/python -m tesis run --dry-run --config results/validation/method-agents-post-review-2026-09-29/accepted/dry-run-sqli.yaml
.venv/bin/python -m tesis run --dry-run --config results/validation/method-agents-post-review-2026-09-29/accepted/dry-run-access_control.yaml
.venv/bin/python -m tesis run --dry-run --config results/validation/method-agents-post-review-2026-09-29/accepted/dry-run-brute_force.yaml
```

Use a fresh dated evidence directory for each code epoch. If the archived
configs are unavailable, reconstruct equivalent dry-run configs and record
their hashes. Dry runs validate local configuration/graph/payloads, not live
permissions or exploit outcomes.

## Saved-data repair and bounded live follow-up

First attempt pure rescoring of the 297 immutable sources with zero HTTP and
provider calls. Link every derived result to the original hash, original score,
corrected score, reason, evidence, and executing-code/rubric epoch. Preserve all
coordinates and compare each dimension, including expected unchanged results.
Do not infer complete terminal inputs from an earlier snapshot or infer chain
completion from accumulated confirmations alone. Mark missing legacy evidence
as unrecoverable/unresolved and list the next discriminating control.

If saved evidence cannot establish source-material consumption, run only the
necessary independent chain controls after the offline/dry-run gates. Prefer
saved/static inputs and zero provider calls. Use fresh serialized sessions and
an independent credential/permission reference within the existing DVWA scope;
never reset the target or add providers. If model calls are needed, retain the
authorized `openai_compatible` boundary and freeze effective role profiles,
settings, retry policy, and equal repeats before execution.

Keep these supplemental automatic chain controls outside the 243 forced-method
primary coordinates and original equal-repeat dataset. A new usable permission
fixture does not retroactively make the 108 historical outcomes verified. Stop
dependent live controls if their independent references are unavailable, and
record that acceptance gap.

Completion requires passing controls for all six fixes, reproducible score
vectors/decision links, original evidence retained, a per-component comparison
ledger, and synchronized [English methodology](../reference/summary_en.md),
[Indonesian methodology](../reference/summary_id.md), and
[affected architecture guidance](../reference/architecture.md). Document any
remaining fixture or legacy-evidence gaps. Move this handoff to `docs/active/`
when implementation starts and `docs/completed/` only after required acceptance
passes; update links when moving it. A full matrix rerun is warranted only if
the repairs change execution behavior or saved evidence cannot answer the
declared scoring questions.

## Acceptance record — 2026-09-30

The E2E failure inventory and failing baseline are retained in
`results/validation/scoring-remediation-2026-09-29/failure-inventory.json` and
`baseline/`. The final controls exercise F1–F6 through the graph, method agents,
validator, reducers, scorer, and artifact writer with only external HTTP and
provider calls faked. They retain response, verifier, route, score, and export
receipts under `controls/`. Expected: candidate and chain credit require their
own verifier/dependency evidence, true scope violations retain their penalty,
and stored score vectors reproduce the formula. Observed: those controls pass.

| Check and configuration | Observed result | Receipt |
| --- | --- | --- |
| Focused E2E controls, method agents, and manual evidence; `.venv/bin/python -m pytest -q tests/test_scoring_remediation_e2e.py tests/test_method_agents_e2e.py tests/test_manual_scoring_evidence.py --junitxml=results/validation/scoring-remediation-2026-09-29/focused-junit.xml` | 308 passed, 2 skipped | `focused-final-rerun.log`, `focused-junit.xml` |
| Full offline suite; `.venv/bin/python -m pytest -q tests --junitxml=results/validation/junit.xml` | 1,619 passed, 2 skipped | `full-final.log`, `../junit.xml` |
| Three `run --dry-run --config` commands above, using the archived SQLi, access-control, and brute-force configs | 12, 9, and 6 payload coordinates validated; graph and AKG compiled | `dry-run-*-final.log` |
| `PYTHONPATH=. .venv/bin/python results/validation/scoring-remediation-2026-09-29/compare_saved.py` against the hash-pinned 297-coordinate manifest | 297 compared; zero HTTP/provider calls; zero formula mismatches | `compare-saved-epoch3.log`, `saved-data-epoch3/comparison-ledger.json` |
| Bounded live `live_hash_dependency.py` with the original frozen low-SQLi static input and fresh DVWA sessions | Independent login succeeded; five extracted password hashes; destination unverified; `Schain = 0`; zero provider calls; source hash unchanged | `live-hash-dependency-escalated.json`, `live-hash-dependency-escalated.log` |

The full-suite skips are the two previously identified medium SQLi controls
whose high-security session-input flow does not apply. The first live attempt
was blocked by sandbox network permission before any request; its separate
`live-hash-dependency.json` receipt remains. The authorized retry reached only
the configured DVWA host. The live control is supplemental and does not change
the original equal-repeat matrix.

The saved-data ledger reports 297 corrected `Soutput` and `Srun` values after
classifying archived discarded recon links, 27 routed-selection receipts, and
one supported lower candidate grade. It retains `Schain = 0` in all legacy
exports: terminal route/material inputs are absent. Another 944 individual
candidate grades lack enough legacy verifier detail for supported relabeling.
These are explicitly unresolved; neither a historical chain completion nor a
model-effectiveness claim is inferred. Fresh E2E controls prove a plaintext
source can earn destination chain credit, while the live hash-only dependency
control proves the DVWA representation cannot earn it through the bounded
dictionary. The original matrix's validated queues and route decisions are
unchanged; the new dictionary binding applies only to validated plaintext,
which the live DVWA SQLi source did not provide. A full matrix rerun was not
used to fill missing historical facts.
