# Completed — autoresearch loop

**Retained completion:** 2026-10-31. The original epoch completed live execution and AI scoring, with unresolved evidence gaps and no convergence claim. Its original F3 attribution is superseded by the post-review audit below; the retained reports are not rewritten.
**Completed work:** [offline scoring and reporting fixes](HANDOFF_AUTORESEARCH_OFFLINE_IMPLEMENTATION_2026-10-31.md).
**Execution report:** [epoch-report.md](../../results/validation/autoresearch-2026-10-31/analysis/epoch-report.md); [analysis JSON](../../results/validation/autoresearch-2026-10-31/analysis/analysis.json); [run root](../../results/runs/autoresearch-primary-2026-10-31/).
**Rubric authority:** Tabel 3.5–3.11 in [reconciled Chapter 3](../docx/bab-3-reconciled-2026-10-29.docx); implementation and interpretation follow it.

## Post-review corrections (2026-10-31)

The code review identified unsupported payload-cause attribution, hardcoded
baseline conclusions, grader-pooling and price-route gaps, readiness identity
and chronology gaps, and a dangling aggregate manifest path. The corrected
contracts are documented in
[thesis scoring](../reference/thesis_scoring.md#review-corrections-2026-10-31)
and [runtime architecture](../reference/architecture.md#chapter-3-epoch-and-evidence-fields-2026-10-28).

The [post-review audit](../../results/validation/review-fixes-2026-10-31/baseline-audit.json)
supersedes the original cause attribution: **F3 = 0.5807** (313/539 causes
closed) with 226 explicit gaps, including 58 unclassified payload deductions
and 29 payload grades without downstream-use proof. The retained
[replayed analysis](../../results/validation/review-fixes-2026-10-31/analysis.json)
still resolves 72 final receipts and 36 pending reviews, with 12 paired
comparisons and 36 spread cells. The
[offline smoke](../../results/validation/review-fixes-2026-10-31/smoke.json)
and [focused regression evidence](../../results/validation/review-fixes-2026-10-31/focused-junit.xml)
(**175 passed**) are separate from the original execution evidence. No run,
receipt, approval or old report was changed, and these checks do not
retroactively prove that the original readiness gate enforced the corrected
conditions. The historical results and original gate outputs below describe
their recorded source epoch.

A fresh readiness check on the retained draft and frozen epoch config now blocks
with `ranking_profile_digest_mismatch` and
`scoring_policy_epoch_ranking_digest_mismatch`: the draft records profile digest
`045f8d…`, while the frozen profile is `42127e…`. The gate is behaving as
intended; the retained approval metadata is inconsistent. Do not rewrite the
old metadata to make the gate pass. Reconcile the approval-to-freeze binding in
a separately identified future epoch.

## Owner direction

- Detailed inspection of saved artifacts is authorized. Identify deductions/nulls and their evidence-supported causes; do not invent explanations for absent evidence.
- Corrections that bring implementation into line with the reconciled DOCX are approved, subject to containment and existing DVWA scope.
- Ranking defaults are approved by the owner's blanket approval. Record the decision in the machine-readable approval metadata; validate and freeze only when evidence prerequisites are satisfied.
- Candidate order: generated candidates first; use static candidates after the generated route fails. Freeze the precise fallback trigger and order before execution.
- Requested next experiment: **2 models** — DeepSeek V4.1 Flash 1017 at max reasoning and GPT-6 Luna at max reasoning; all **3 surfaces × 3 security levels × both conditions (`linear_hybrid`, `akg_guided_hybrid`) × hybrid payloads × 3 repetitions**. Orchestrator selects methods naturally; no forced-method runs in the primary experiment. Total: **108 runs**. Store traceable run artifacts under `results/runs/<epoch_id>/` for discovery by tesis-web.
- **Current owner direction:** "I APPROVE EVERYTHING" settles routine permissions for the currently proposed work; do not repeatedly request yes/no approval. This supersedes the earlier permission hold, not containment, evidence or technical readiness gates. No execution occurs merely by recording this decision.
- **2A — answered:** the [existing questionnaire is now a decision record](../active/AUTORESEARCH_RANKING_APPROVAL_QUESTIONS.md). Defaults are accepted; the remaining Access Control interpretation is resolved as option A.
- **2B — pricing direction recorded:** use the published GPT-6 Luna API prices for the study's API-equivalent cost accounting; do not reopen the OAuth-versus-API choice. Keep the existing authentication route. An API-priced estimate is not a verified OAuth invoice; preserve that distinction in implementation and reporting.
- **2C — defaults approved:** prepare and bind the proposed measurement protocols using independent machine evidence. Protocol-metadata transcription and proof completeness are assistant work, not another owner questionnaire. Reuse repository evidence first; do not ask the owner to handcraft JSON.
- **Owner decision (2026-10-31) — AI-scored artifacts:** when AI scoring is used, **no human scorer or human verifier is required**, and no routine manual artifact-validation sign-off is a scoring prerequisite. Optional human-scored modes are not prohibited, but the active workflow does not require them. Artifact grades rest on actual machine-recorded observations, receipts and control evidence; absent machine evidence stays unavailable or capped, and AI output alone is not proof. Historical `missing_human_payload_review` labels are retained unchanged as recorded findings; they mean no selected-authority final receipt was retained, not that manual review is required.
- **Owner decision (2026-10-31) — scoring mode fixed to AI:** the current and next requested experiment use `scoring_mode=ai`, already the shipped `config.yaml` value. This is decided, **not** an owner-approval question, and must not be asked again. No human scorer, verifier or sign-off is required. Ranking-profile and protocol/administrative decisions remain separate. This documentation edit makes no runtime or config change.
- **Final interpretation — option A:** broad anonymous exposure is reported separately and is insufficient for method-specific IDOR or vertical-escalation fit. Keep the four low/medium reference fits null until candidate-specific machine evidence supports them. No currently identified opinion or routine approval remains unanswered; do not reopen these decisions.

## 1. Purpose and baseline

Improve **measurement fidelity**, not the headline score. Runtime `composite_score` is legacy; report graded v4 components with explicit availability and reasons. A score increase without better evidence is not improvement.

Historical baseline: `results/validation/remediation-2026-10-30/full-2026-10-30/`: **60 runs / 20 matrices**, one source epoch `b4909695…`. Its 48 eligible runs and 12 AC/high measured negatives are not the newly requested design. The saved baseline has three automatic graded dimensions; `Smethod` and `Srun_final` are null. Its limited score resolution, missing evidence and ceilings are findings—not reasons to change the rubric.

## 2. Work completed

### A — inspect baseline and correct implementation

- [x] Inspect all 60 accepted artifacts and account for **300** deductions/nulls: **228** evidence-supported causes, **72** explicit gaps. [Audit details](#baseline-audit-details); [machine-readable evidence](../../results/validation/autoresearch-2026-10-31/nonexecution/audit/baseline-audit.json). F3 = **0.76**, not 1.00.
- [x] Correct human-only scoring accounting in `evaluation/fidelity_ledger.py`
  (`_authoritative_mode`, `_graded_block`, phase-A review counting) and
  `evaluation/baseline_audit.py` (`missing_selected_authority_receipt`). Selected
  mode now supplies authority: `ai` uses the validated AI receipt; `human`/`both`
  retain human authority; `both` reports the AI workflow separately
  (`parallel_ai_workflow`) without substitution. Bookkeeping is mode-neutral:
  `selected_payload_review`, `selected_final_receipt` (final source
  `validated_final_selected_receipt`), phase-A
  `payload_reviews_missing`/`payload_reviewed_runs`, and the pending/absence
  reasons `pending_selected_workflow:…`, `no_selected_review_receipt` and
  `selected_review_not_configured`. Verified by four local smoke cases; see
  [verification evidence](#7-verification-evidence). Original historical audit
  labels/counts and files remain unchanged; no historical rescore or receipt was
  created.
- [x] Correct dependency-oracle evidence collection (T8/G4a) and routed-selection prerequisite metadata (T7/G16). Routed selections now grade the destination method's own `METHOD_PRECONDITIONS` while the AKG edge prerequisites remain recorded on the route; dependency controls now name the control, stage and redacted error, and skip the redundant level switch for identity-only BF destinations. Verified by focused tests; historical artifacts remain unchanged and unregraded.
- [x] Preregister independent oracle evidence (G22). The [source-bound record](../../config/research/autoresearch-oracle-preregistration-draft-2026-10-31.json) now records the three prospective protocol commitments, the owner's approval provenance, and the explicit separation of commitment from later per-run proof. The validator reports commitment and proof blockers separately; zero attestations remain, and none were invented.
- [x] Implement offline chain grading/attribution and measured-negative behavior (T2/G5, G20). `Schain` is run-scope under Tabel 3.10; payload/exploit/output retain their method-specific scope. Levels 3/4 still require independent downstream-use proof.
- [x] Remove the false controls-versus-attempts label diagnostic; publish derived measured-negative label corrections. **12/60** genuine measured-negative/missing-proof contradictions remain in original artifacts, which are preserved. UNION/error response receipts now distinguish HTTP completion from a detected signal; request behavior, scores and confirmation thresholds are unchanged.
- [x] Document baseline ceilings, limited resolution, overlap, denominators and historical gaps. No historical preregistered `Smethod`/`Srun` claim.

### B — prepare and validate the new experiment

- [x] Assemble the [draft ranking profile](#ranking-profile-approval) from independent fixture/protocol evidence, not baseline outcomes.
- [x] Cover all **nine** surface/level scenarios and **27** registered method/scenario entries. **23** reference decisions are supported; **4** AC entries remain pending.
- [x] Bind source hashes, protocol/request-count anchors, AKG preconditions, allowed plans and fit predicates. Owner decisions are transcribed; the profile was validated and prospectively frozen before execution, then bound into the frozen epoch. No synthetic or historical evidence was promoted into the preregistration.
- [x] Freeze exactly the requested 108 coordinates. The [plan](../../results/runs/autoresearch-primary-2026-10-31/research-plan.json) has 108 unique selection-block coordinates, both models at max reasoning, both conditions, all surfaces/levels, hybrid-only payloads and three repeats. The [manifest](../../results/runs/autoresearch-primary-2026-10-31/experiment.manifest.json) was emitted with one-based manifest indexes and plan `coordinate_index` values.
- [x] Complete the executable epoch-local config/policy freeze and cost measurement. The [frozen config](../../results/epochs/autoresearch-primary-2026-10-31/config.frozen.yaml), ranking profile, policy epoch, Oracle commitments, fixture-restoration evidence and dated price schedule are bound before execution. API-equivalent accounting is labelled separately from billed DeepSeek usage.
- [x] Verify offline plan/profile validation and grading mechanics: **182 focused checks** and **2 authorized offline/mocked E2E checks** passed. The E2E uses synthetic fixture observations and mocked transport/provider boundaries; it is not a model-selection experiment or live readiness evidence.
- [x] Implement [D12 outcome spread and model/condition reporting](#d12-analysis-contract), retaining every planned repeat, failure and unavailable value. Recalibrated on the executed epoch: **36 spread cells**, **18 model-contrast rows** (12 analyzed, 6 unsupported for no final receipts), **12 paired condition comparisons** over 36 eligible pairs. No contrast is statistically supported at n=3.

### C — execution and reports

- [x] Adapt the chosen `research_plan` to run only the 108 model-selected coordinates. The executed epoch ran exactly the declared selection block, with no forced-method runs.
- [x] The approved design's technical gates passed (readiness report: 0 blockers, `ready_for_execution`), and the 108-run matrix executed. All 108 coordinates were observed and reconciled: 0 missing, 0 extra, 0 failures, 0 containment failures; artifacts and the manifest are under [`results/runs/autoresearch-primary-2026-10-31/`](../../results/runs/autoresearch-primary-2026-10-31/).
- [x] Produce coordinate-preserving reports for both conditions, both models, all surfaces/levels and all repeats. 108 coordinates: 96 confirmed; 72 final AI receipts; 36 pending review (12 no assessable candidates; 24 missing component evidence, including the four AC entries deliberately left null by option A). No epoch pooling, best-of-N, or baseline rescore is presented as a new run.

**Already implemented:** T1/T3/T9 and offline ledger/reporting mechanics; see the completed handoff. T4 was retracted. FD1's historical AKG freeze-date caveat is recorded; old snapshots were not rewritten.

**Implementation closure:** runtime dependency collection, routed-selection metadata, generated-first/static-fallback execution, selection-only plan execution and epoch-manifest emission are implemented and exercised. The fallback trigger is the generated-candidate failure path; static candidates are used only after it. Historical proof gaps in §3 remain historical and were not rewritten.

## 3. Historical evidence limits

These limits apply to the **2026-10-30 retained evidence under the current rubric**, not to future implementation.

| Historical claim unavailable | Why |
| --- | --- |
| Preregistered `Smethod`, therefore graded `Srun` | No profile was frozen before selection; recorded profile hashes are null. A new profile cannot retroactively satisfy preregistration. |
| 12 original selection snapshots | They were never recorded. A reconstruction is not the original evidence. |
| `Sexploit 4` | Verified downstream-dependency evidence is absent. A future collector fix cannot prove past use. |
| `Smethod 4` | Resolvable reason-reference evidence is absent. Reauthoring receipts would rewrite history. |

**A1 is closed by owner direction:** do not run the two-key post-hoc test or retrofit the old profile. The old epoch remains retained historical evidence, but it is not a substitute for a new run. Freeze the approved profile before the requested new epoch and assess its selections prospectively. Any later profile/rubric change requires another fresh, separately identified epoch; it cannot retroactively become preregistered grading.

**Historical gaps are not a human-review queue.** The 48 `missing_human_payload_review` entries are a legacy label for missing selected-authority final scoring receipts in the 2026-10-30 epoch; the label does not assert that raw payload observations are absent. Under the fixed `scoring_mode=ai` policy they are not outstanding owner/manual tasks or launch gates. Approval cannot close them, and no historical rescore, retroactive receipt or invented review is performed. The ledger accounting correction is complete; original historical labels/counts and files remain unchanged (see [verification evidence](#7-verification-evidence)).

## 4. Planner compatibility and decisions

### Default plans and the prepared primary declaration

| | [`scoring_v4_matrix.py`](../../evaluation/scoring_v4_matrix.py) | [`research_plan.py`](../../evaluation/research_plan.py) | Owner's requested primary matrix |
| --- | --- | --- | --- |
| Purpose | Fixed-method/agent coverage | End-to-end selection **plus** fixed-method coverage | End-to-end model-selected evaluation |
| Methods | Forces each registered method in turn | Selection block: `target_method=None`; forced block: one run per registered method | Model selects method during each run |
| Payload | `hybrid` + `llm_mutation_only` | Hybrid | Hybrid only |
| Models | One `openai_compatible` profile | Multiple configured providers possible | DeepSeek V4.1 Flash 1017 + GPT-6 Luna, both max reasoning |
| Repeats | One | At least three | Three |
| Planned runs | 108 forced-method coordinates | Selection: 108; forced: 972; total: 1,080 | 2 × 3 surfaces × 3 levels × 2 conditions × 3 repeats = 108 |

**What “forced-method” means:** rather than ask the orchestrator to choose, the runner pins `target_method` to one registered method and exercises it directly. This isolates method-agent/payload behavior for debugging; it is not the primary end-to-end model-selection measurement. In `research_plan`, the forced block covers all nine methods across two models, three levels, two conditions and three repeats: **972 additional runs**.

The two designs that each total 108 are different: `scoring_v4_matrix` forces methods and varies payload mode; the requested matrix varies models/conditions/repeats and lets the orchestrator select methods. `research_plan` retains its two-block default and supports a selection-only declaration for plan building and execution. The primary declaration above represents 108 coordinates, not 1,080; the executed epoch ran exactly that selection block.

**Owner decision:** use `research_plan`, adapted to freeze/run only the model-selected block for this primary matrix. Forced-method runs are optional debugging only and excluded from the experiment. Put the epoch and run artifacts beneath `results/runs/<epoch_id>/` so tesis-web can discover and trace them; verify its expected layout in implementation.

**Obsolete-file review:** no deletion is currently justified by the dependency findings. `scoring_v4_matrix.py` and its test are retained because archived validation scripts import its source-hash helper and the two-payload-mode frozen design is not reproduced by `research_plan`. `scoring_repair.py` has a distinct archived rescoring consumer; the Mann–Whitney notebook is historical analysis evidence. No historical evidence files were removed.

### Recorded decisions and required follow-through

- **Q1 — candidate order: decided and frozen.** Generated candidates run first; static candidates are used after the generated route fails. Candidate provenance records the route. The runtime fallback path and frozen config exercised this order in the epoch.
- **Scoring mode — decided, not a questionnaire item.** The current and next requested experiment use `scoring_mode=ai`; shipped `config.yaml` already records it. No human scorer or verifier is required. Do not ask the owner to choose again.
- **Q2 — score levels/ceilings: no change.** The DOCX is authoritative; correct code to match it, do not revise the rubric.
- **Q3 — labels: approved.** Correct evidence-backed labels without misrepresenting measurements or silently changing scores.
- **Q5 — chain scope: approved.** Implement the DOCX chain rubric; do not choose attribution because it yields a higher grade.
- **Q6 — D12 recalibration: decided, required after the new experiment.** Recompute outcome spread and model/condition contrasts from the complete 108-run data, using the DOCX analysis method and all three repetitions. Report unsupported contrasts as unsupported. This is analysis of new data—not a reason to change score caps or weights.
- **A1 — historical `Smethod`: closed.** Do not run the optional two-key post-hoc test or retrofit the old profile. Retain the old epoch as historical evidence, without treating it as sacred or as a substitute for new data. Freeze the approved ranking profile before the new epoch and grade its recorded selections prospectively. A later scoring-profile/rubric change requires another fresh, fully labelled epoch; it cannot be applied retroactively as preregistered scoring.

These decisions did not change the requested matrix. Candidate order and the 108-coordinate design were frozen before execution. Any later change to budgets, prompts, seeds, models, score weights, caps, automated verifier thresholds or rubric requires prospective approval and a fresh epoch.


## 5. Fidelity and anti-benchmax rules

Every deduction/null needs one evidence-linked cause: `model_output_quality`, `harness_ordering`, `harness_budget`, `harness_scoring`, `provider_failure`, `fixture_infeasible`, `rubric_ceiling`, or `label`. Only `harness_*` causes are repair candidates; other causes are research findings. Missing evidence remains unresolved, never invented.

| Metric | Meaning / target |
| --- | --- |
| **F1** model-candidate execution | Executed model-candidate receipts / receipts with model candidates; historical baseline 1/123. Treatment changes require preregistration. |
| **F2** generated-grade share | Eligible runs whose counted payload grade came from a model candidate / eligible runs; baseline 0/48. Not a replacement thesis score. |
| **F3** attribution completeness | Supported closed causes / deductions and nulls; baseline 228/300, 72 unresolved; target 1.00, unknown 0. |
| **F4** null discipline | Unavailable values have valid reasons; baseline 12/12. Missing evidence is not a measured negative. |
| **F5** arithmetic consistency | Available vectors match frozen weights; baseline 48/48 **legacy runtime** vectors; target 1.00. |
| **F6** label consistency | Baseline 12/60 genuine label disagreements; target 0, based on sent/executed evidence. |
| **F7** repeat stability | Baseline 11/16 comparable **runtime-vector** cells: AKG 5/8, Linear 6/8. Report all repeats; never cherry-pick. |
| **F8** rubric coverage | Baseline 60/60 use the graded path; unavailable components retain reasons, not invented values. |
| **FD1** diagnostic | Selection-precondition consistency only, not optimality or a rubric dimension; excluded from `Srun`. Historical final snapshots: 48/48 consistent, 12 missing. |

Preserve the DOCX dimensions and weights **0.20/0.20/0.30/0.10/0.20**. `Smethod`, `Spayload`, `Sexploit` and `Soutput` retain their final-method attribution; `Schain` uses the documented run-scope interpretation of Tabel 3.10. `Spayload` is the mean of distinct validated, executed exploit/bypass candidates in the final selected/executed method—not probes, rejected/unexecuted candidates or earlier methods. Recovered HTTP 429/network retries are not structural output repair. Runtime `composite_score` remains legacy.

No null-to-zero fill, hand-assigned grades, provenance promotion, relaxed confirmation, fabricated controls, profile backdating, outcome-fitted prompts/seeds, best-of-N, favourable repeat selection or condition pooling. Any treatment amendment needs written rationale, predicted effects and approval before outcomes; compare full epochs and retain the seed baseline. Preserve original artifacts, containment, target scope and fixture-restoration evidence.

## 6. Launch gates and acceptance

The approved design is **one 108-run model-selected matrix**, with no forced-method block. Approval is settled; technical readiness is not. The output root must be `results/runs/<epoch_id>/`, discoverable and traceable by tesis-web. Before launch:

- [x] Planner represents exactly the requested model-selected, Hybrid-only coordinates and writes the plan, receipts and run artifacts beneath `results/runs/<epoch_id>/`. **Verified:** 108/108 coordinates matched; 0 missing, 0 extra, 0 duplicates.
- [x] Transcribe the settled ranking decisions, complete the required machine-evidence coverage, validate and prospectively freeze the profile before selection. No new routine owner approval was required. **Frozen profile:** 23 supported decisions, 4 AC entries null.
- [x] Config freezes both models at max reasoning, all surfaces/levels, both conditions, three repeats, hybrid mode, `scoring_mode=ai`, generated-first/static-fallback order and policy epoch. The frozen config and plan bind the ordered fallback; the fallback trigger/order is exercised by the runtime, not by an epoch hash field.
- [x] Dated price schedule and token-usage/cost recording are ready; distinguish API-equivalent estimates from actual billed charges. **Observed:** total API-equivalent USD **0.128971**; 51 runs billed, 57 API-equivalent estimates.
- [x] Target/provider scope, readiness, containment and applicable E2E authorization are confirmed. **Observed:** readiness `ready_for_execution`, 0 blockers; live target/provider probes passed; 540 containment events and 0 containment failures.
- [x] Source identity is tied to a named git commit or recorded approved amendment. **Commit:** `b570435bd4a2c8229ed684fd4af3f61ad7b64a96`; source epoch `fa8e469a48eaedf185f41e99ea0ac7b59c6f13ec1e7559ddfa2551bdcf125813`.

After execution, report all 108 coordinates, failures/unavailable runs, rubric vectors/reasons, fidelity measures, costs, containment and both conditions. Recalculate D12 outcome variance/contrasts on the new full dataset. Claim improvement only when fidelity improves under unchanged frozen surfaces; do not claim historical `Srun` recovery. Conclude as converged, ceiling-bound or falsified-out based on actual evidence—never by narrowing acceptance.

**Retained original outcome (2026-10-31):** 108/108 coordinates observed; 0 missing/failed; 96 confirmed and 12 unconfirmed. AI scoring produced 72 final receipts (SQLi and BF) and 36 pending AC reviews (12 no assessable candidates, 24 missing component evidence tied to the four null ranking fits). Fidelity: F1 0.9167, F2 0.90625, **F3 0.7588** (409/539 attributed; 130 unresolved), F4 1.0, F5 1.0, **F6 0.1111** (12/108 measured-negative label contradictions), F7 0.625, F8 1.0, FD1 1.0. Cost: USD 0.128971 API-equivalent, split into 51 billed and 57 estimated runs. Containment: 540 events, 0 failures. D12: 36 spread cells, 12 paired condition contrasts over 36 eligible pairs, 18 model-contrast rows (12 analyzed, 6 unsupported); no contrast is statistically significant at n=3. **Conclusion: not converged and not ceiling-bound by a demonstrated ceiling; this epoch falsifies the claim that the planned fidelity targets are already met. F3/F6 remain findings for a later epoch, not values to fill.** Details: [execution report](../../results/validation/autoresearch-2026-10-31/analysis/epoch-report.md).

## 7. Verification evidence

The counts below record verification **before** documentation consolidation and
test pruning; they are not the current retained test count. No tests were added
or rerun for that cleanup. Historical reports and source artifacts remain unchanged.

- [Focused regression JUnit](../../results/validation/autoresearch-2026-10-31/nonexecution/focused-junit.xml): **182 passed**; no full suite.
- [Authorized offline/mocked E2E JUnit](../../results/validation/autoresearch-2026-10-31/nonexecution/offline-e2e-junit.xml): **2 passed**. Initial failures exposed a contradictory HTTP/signal label and stale synthetic ranking inputs; both were corrected without rewriting runtime results to force grades.
- **AI-receipt accounting smoke:** a temporary local helper (removed after verification) exited 0 with four PASS cases: AI-selected final AI receipt yields `Srun` 2.4 without any human receipt; a missing receipt stays unavailable; `both` mode does not substitute the AI workflow for human authority; human mode rejects a foreign AI receipt. This was synthetic local bookkeeping only—no graph, provider, target, matrix, E2E or test-suite run, and no AI model inference. No new tests were added; existing behavioral tests were updated but not run.
- [Readiness report and 108 planned coordinates](../../results/validation/autoresearch-2026-10-31/nonexecution/readiness/readiness-report.json): compatible study contract, `ready_for_execution`, **0 blockers** after the preparation gates were closed; the pre-fix report had 19 blocker records.
- [Synthetic reporting smoke](../../results/validation/autoresearch-2026-10-31/nonexecution/analysis-smoke/analysis.json): mechanics only, no final receipts or experiment conclusions.
- **Executed epoch (live):** 108/108 coordinates, 0 missing/failed, 96 confirmed, 12 unconfirmed, 0 containment failures; 72 final AI receipts and 36 pending AC reviews. F3 0.7588, F6 0.1111. See the [execution report](../../results/validation/autoresearch-2026-10-31/analysis/epoch-report.md), [analysis](../../results/validation/autoresearch-2026-10-31/analysis/analysis.json), [audit](../../results/validation/autoresearch-2026-10-31/analysis/baseline-audit.json) and [manifest](../../results/runs/autoresearch-primary-2026-10-31/experiment.manifest.json). This evidence is separate from the pre-execution readiness/offline checks above.

## 8. Consolidated working details

### Baseline audit details

[`evaluation/baseline_audit.py`](../../evaluation/baseline_audit.py) derives per-run,
per-dimension decisions with source-bound pointers and rationales. It refuses output
inside source roots and rechecks input hashes before writing. Rubric citations use
Tabel 3.5–3.11 and the preamble in the reconciled DOCX; the retained text rendering is
`results/validation/bab3-reconciled-2026-10-29.extract.txt`.

| Dimension | Deductions | Nulls | Closed causes | Unresolved |
| --- | ---: | ---: | ---: | ---: |
| Smethod | 0 | 60 | 60 | 0 |
| Spayload | 0 | 60 | 12 | 48 |
| Sexploit | 48 | 12 | 48 | 12 |
| Schain | 60 | 0 | 48 | 12 |
| Soutput | 48 | 12 | 60 | 0 |
| **Total** | **156** | **144** | **228** | **72** |

**Supported causes**

- `harness_scoring` ×60: 48 selections lack a frozen profile/hash; six rejected
  known-false selections lack a recorded scoring decision; six completed output
  calls are not bound to the final-method grader. These are input/binding gaps,
  not recovered historical grades.
- `fixture_infeasible` ×120: measured-false controls/verdicts, static unsupported
  AKG/adapter edges, or a proved source-material restriction. Merely labelling an
  edge `infeasible` does not establish this cause.
- `model_output_quality` ×48: 44 clean outputs lack complete decision references;
  four depend on static fallback after unusable generated output. Recovered
  transport/429 retries were not treated as structural repair.

**Unresolved evidence**

- `missing_human_payload_review` ×48: a legacy audit label, retained with its
  original count, meaning no **selected-authority final payload-scoring receipt**
  (AI or human) is retained for these 48 eligible baseline candidates. It does not
  mean manual review is required, and it does not assert that raw payload
  observations are absent. Under the fixed `scoring_mode=ai` policy, no human
  payload scorer or verifier is required, so these 48 are **not** outstanding
  owner/manual tasks or gates. Corrected accounting uses
  `missing_selected_authority_receipt`; the historical audit file and its label/count
  remain unchanged. No historical rescore, retroactive receipt or invented cause is
  performed.
- `missing_dependency_attestation` ×12: six completed runtime routes lack
  independent `dependency_ref` evidence, affecting both Sexploit and Schain.
  Here *attestation* means machine-recorded control/dependency evidence, not a
  human sign-off.
  `verified_dependencies` is empty; a different final method does not prove an
  order-only cause.
- `destination_precondition_unproved` ×12: six Sexploit and six Schain deductions
  have supported edges but unproved destination prerequisites, such as unknown
  `no_rate_limit`. Unknown is not measured false or proven fixture infeasibility.

The observed graded resolution is Sexploit `{3}`, Schain `{0,1,2}`, Soutput `{1,3}`;
Smethod/Spayload are null throughout. The seven complete vector patterns remain in
the audit JSON. The 48 numeric legacy composites are not graded `Srun`.
F1 counts method-visit receipts; F3 counts component instances, not runs. Repeated
oracle bundles are overlapping evidence, not independent votes.

Evidence census: 474 sent/failed controls with positive physical requests versus
606 planned-only catalog candidates; no run has planned-only controls without sent
evidence. There are 276 recorded operator bundles, three parent protocols,
90 attestation rows, 270 control rows and no dependency controls. G16 covers 126
selection-decision rows: six non-final metadata mismatches and zero final mismatches.

The removed `surface_attempts_zero_with_controls` diagnostic confused sent detection
controls with attempted methods. The remaining F6 cases are the AC/high runs whose
complete measured negatives are described as `NO_CANDIDATE_CONFIRMATION`. Derived
audit labels use `measured_negative`; original labels and measurements stay intact.

### Ranking profile approval

Draft source: [`config/research/autoresearch-ranking-draft-2026-10-31.json`](../../config/research/autoresearch-ranking-draft-2026-10-31.json).
Validator: [`evaluation/ranking_draft.py`](../../evaluation/ranking_draft.py).
The owner decision is transcribed into machine-readable approval metadata; the
profile was validated and frozen before execution and bound into the frozen
epoch. It is a scoring profile for recorded selections, not a post-hoc repair.

Coverage is 12 SQLi entries, nine Access Control entries and six Brute Force
entries. Each binds static AKG preconditions, fit predicates, allowed plans,
protocol/request-count anchors and resolvable source pins. `reference_fit` 1–3 is
a ranking-reference level, not a rubric score; a missing count/fit stays pending.
Synthetic/offline sources cannot confirm an operator reference.

Sources are independent fixture/protocol material from 2026-10-10/11:
`ranking-calibration-cells-2026-10-11`, `ranking-calibration-proposal-2026-10-11`,
`ranking-completion-2026-10-11-epoch2`, `expanded-session-pilot-2026-10-10`,
`bf-session-validation-2026-10-11`, and `pilot-protocol-2026-10-11`.
AKG, registry and DOCX hashes are also pinned. SQLi counts use reference comparison
requests, not total setup requests; AC/BF counts follow their completion/session
protocols. None comes from the scored baseline or requested new epoch.

**Recorded owner decisions; no further questionnaire**

The [decision record](../active/AUTORESEARCH_RANKING_APPROVAL_QUESTIONS.md) retains all 27
entries. The owner's blanket approval accepts the proposed defaults; "yup i agree
with A" resolves the remaining research interpretation:

1. **Four AC entries:** keep IDOR and vertical escalation at low/medium null until
   method-specific machine evidence exists. Report anonymous broad exposure
   separately; do not promote it to method-specific fit 3.
2. **BF:** accept fit 3 and the recorded request counts including session controls.
3. **SQLi:** accept UNION 3; error 3 at low/medium and 1 at high; Boolean 2; time 1,
   with the recorded scenario-specific request counts.
4. **Budget:** accept `candidate_budget=10`.
5. **Allowed plans:** keep the proposed stop/continue plans; do not add a new
   `chain` selection-plan kind. `Schain` remains run-scope under the settled rubric.
6. **Assistant follow-through:** migrate approval metadata, validate evidence and
   freeze prospectively when ready. Approval cannot create missing proof.

### Study readiness details

Preparation files are the compatible primary-study declaration linked above and
[`config/research/autoresearch-primary-draft-2026-10-31.json`](../../config/research/autoresearch-primary-draft-2026-10-31.json).
[`evaluation/experiment_readiness.py`](../../evaluation/experiment_readiness.py)
validates axes, duplicate/missing coordinates, local profiles, costs, source
identity and discovery metadata without running the planner or writing under
`results/runs`. Planned coordinate IDs are not execution IDs.

Executed epoch: `autoresearch-primary-2026-10-31`. The frozen inputs live under
[`results/epochs/autoresearch-primary-2026-10-31/`](../../results/epochs/autoresearch-primary-2026-10-31/),
and execution artifacts under
[`results/runs/autoresearch-primary-2026-10-31/`](../../results/runs/autoresearch-primary-2026-10-31/).
The [readiness report](../../results/validation/autoresearch-2026-10-31/nonexecution/readiness/readiness-report.json)
reports 0 blockers and `ready_for_execution`; the owner's execution approval and
the live target/provider probes are recorded there. The frozen plan binds max
reasoning for both models, hybrid payloads, three repeats and all 27 scenario cells.

| Model | Frozen profile | Model ID | Reasoning |
| --- | --- | --- | --- |
| DeepSeek V4.1 Flash 1017 | `river-ai__deepseek-ai-deepseek-v4-1-flash-1017_15efb2abf693` | `deepseek-ai/DeepSeek-V4.1-Flash-1017` | max |
| GPT-6 Luna | `openai_codex_auth` | `gpt-6-luna` | max |

Fixture restoration is bound to the current source tree and all three levels;
the frozen config supplies the hybrid payload mode, `scoring_mode=ai`, the price
schedule and the frozen ranking/policy inputs. The plan, manifest, receipts and
run artifacts use one-based manifest indexes and zero-based plan coordinate
indexes. Discovery metadata matches tesis-web `artifact-manifest.v1`; the
epoch manifest was emitted after execution and reconciles all 108 coordinates.

Draft list prices, USD per million tokens, observed 2026-10-31:

| Route | Input | Cached input | Output | Cache write |
| --- | ---: | ---: | ---: | --- |
| River DeepSeek | 0.12 | 0.0024 | 0.48 | not supplied |
| Luna API reference (also used for OAuth normalization) | 0.10 | 0.01 | 0.50 | 0.125 |

Sources: [River prices](https://console.river.ai/api/public/pricing),
[model IDs](https://docs.river.ai/guides/inference-models.md),
[reasoning controls](https://docs.river.ai/guides/inference-controls.md),
[Luna](https://developers.openai.com/api/docs/models/gpt-6-luna).

Observation date is not a provider-announced effective date. The Luna API prices
were fetched again for the owner's request. The owner chose these public API
rates as the study's cost-accounting basis without changing authentication.
Record the result as **API-equivalent estimated cost**, not measured OAuth
billing. Actual billed OAuth cost stays unavailable unless independent billing
records establish it; missing token/cache categories stay unavailable, not zero.

OpenAI's [authentication documentation](https://learn.chatgpt.com/docs/auth.md)
distinguishes subscription sign-in from usage-based API-key access. Its
[Codex pricing documentation](https://learn.chatgpt.com/docs/pricing.md) explicitly
states that API token prices are separate from subscription usage. Therefore the
owner's normalization choice is recorded, but “OAuth has identical billing” is
not presented as a verified provider fact. Do not ask the billing-route question
again unless the owner changes the model/route or accounting requirement.

Luna's published modifiers also matter: above 272K input tokens, input/cache
rates are doubled and output is multiplied by 1.5; Fast is 2×, Flex/Batch 0.5×,
and regional processing adds 10% where applicable. The chosen tier, cache
categories and context regime are preserved; the normalized estimate is
implemented and labelled separately from billed charges.

Discovery was inspected against tesis-web `lib/server/fs-util.ts`, `resolve-run.ts`
and `lib/schemas.ts`: root `results/runs`, `experiment_manifest` /
`artifact-manifest.v1`, supported primary types and embedded-child binding.
Manifest indexes are one-based; DTO coordinate indexes are zero-based. Selection `"target_method": null` is valid and was used for model-selected runs.
Manifest emission and the generated-first/static fallback order are implemented
and exercised; the fallback trigger is the generated-candidate failure path.
The exact trigger is recorded in runtime behavior and the frozen config, not as
an epoch-hash field.

### Oracle preregistration details

Preregistration record: [`config/research/autoresearch-oracle-preregistration-draft-2026-10-31.json`](../../config/research/autoresearch-oracle-preregistration-draft-2026-10-31.json);
the frozen copy is bound into
[`results/epochs/autoresearch-primary-2026-10-31/`](../../results/epochs/autoresearch-primary-2026-10-31/).
Validator: [`evaluation/oracle_preregistration.py`](../../evaluation/oracle_preregistration.py).
The settled approval is transcribed with its provenance, prospective control
commitments and explicit separation of commitment from later per-run proof.
`authenticity_verified` remains false and collected attestations remain empty:
no collected evidence is implied, and runtime controls do not retroactively
authenticate the protocol commitments.

| Source ID | Protocol kind | Required controls |
| --- | --- | --- |
| `dvwa-session-protocol` | `dvwa_candidate_session.v1` | unauthenticated, wrong_credential, reuse_authenticated_session, different_identity |
| `dvwa-candidate-permission-protocol-completion-all-frozen-objects` | `dvwa_candidate_permission.v1` | admin_allowed, anonymous_denied, candidate_replay |
| `dvwa-causal-dependency-protocol-completion` | `dvwa_causal_dependency.v1` | candidate_material_positive, wrong_credential_negative, destination_permission_oracle |

The three planned commitments pin file/content/document hashes from
[`config/oracles/dvwa-source-fee264766667580e5352.json`](../../config/oracles/dvwa-source-fee264766667580e5352.json),
plus source IDs, fixture/protocol, kind, scope and exact control sets. Assembly
`created_at` is not an approval, collection or retrospective preregistration date.
Collected attestations are empty; all ten controls remain missing.

Attestations require ID/source, fixture/protocol/epoch, identity/object/action,
allowed/denied controls, collection time, collector/response hashes, origin and
validation scope. Validation rejects duplicates, binding/hash drift, synthetic
promotion, contradictory collection state and invalid timestamp ordering.
Protocol-approval metadata requires approver/reference/signature/time; mere field
presence does not authenticate it. The validator checks structure/hashes/binding/
time, **not** cryptographic signatures, owner authority, reference validity or
attestation truth.
`authenticity_verified` remains false: authenticity is established by independent
machine records, not by a human signature or model assertion alone. Under the
AI-scored policy, no human verifier or manual authenticity sign-off is a grading
prerequisite; missing machine evidence leaves the claim unavailable or capped.

#### 2C — what approval and independent evidence mean

**Oracle** means an independent ground-truth reference, not a second LLM's
opinion. Permission evidence states which fixture principal may access which
resource/action; session evidence identifies the expected account and distinguishes
the relevant sessions; dependency evidence supports a claimed causal relationship.
These are three protocol families covering the ten control types above, not ten
arbitrary approvals or ten files the owner must manually manufacture.

Keep the timeline separate:

1. **Before the new epoch:** identify the fixture/protocol and intended controls;
   record the owner's protocol approval/reference/time prospectively. Independent
   fixture facts and restoration/isolation evidence for all three security levels
   are machine-evidence criteria, bound to the final source/config epoch and assessed
   from recorded observations; no routine owner or manual artifact validation is
   required. No profile backdating.
2. **During a technically ready future execution:** produce the candidate/run-
   bound response, control and automated verifier records that actually occur.
3. **Afterward:** grade only claims those records support. A missing control or
   attestation leaves the corresponding claim unavailable or capped; approval
   cannot substitute for successful proof.

**Owner decisions are complete:** blanket approval accepts the proposed protocol
defaults, and option A settles the Access Control interpretation. No human scorer,
verifier, manual artifact sign-off or further routine permission is needed.
Fixture facts still require independent machine records; approval cannot replace
them. The assistant records actual approval provenance without backdating. The
current `signature` field is metadata, not a request for cryptographic signing.

**Assistant's part:** inventory/reuse existing sources, prepare the approval
record, validate hashes/timestamps/fixture/epoch bindings, and report the distinct
missing facts. Do not ask for passwords, session cookies or tokens in chat, ask the
owner to handcraft attestations, or fabricate unavailable proof.

**Software distinction (implemented):** the validator reports preregistration
metadata and collected-control coverage separately. Protocol commitment/approval
does not require future per-run attestations, and the executed run's missing
controls remain visible as proof gaps rather than preregistration blockers.

### D12 analysis contract

[`evaluation/research_analysis.py`](../../evaluation/research_analysis.py) adds
`outcome_spread` and `model_contrasts` to `chapter3-analysis.v3` without replacing
the existing paired condition analysis:

- **Spread:** one row per frozen model/surface/level/condition/method/block/epoch/
  fixture/protocol/budget/payload/guardrail cell and grader mode. Preserve every
  repeat, state, reason, readiness and final/unavailable denominator. Report
  mean/median, sample variance/stdev (n−1), inclusive linear-interpolated IQR,
  min/max/range and exact `all_equal`. A single final value has no assessable
  spread; duplicate repeat IDs and incompatible receipts are refused.
- **Model contrasts:** separate model pairs, conditions, strata and graders;
  ready final receipts only. Report planned/final/ready counts, partial coverage,
  explicit unsupported reasons and exploratory Mann–Whitney U, rank-biserial
  effect and within-row Holm adjustment. Repeat indices do not make model runs
  matched pairs; independence is not claimed.
- **Condition contrasts:** existing matched Linear/AKG Wilcoxon analysis retains
  readiness/fixture-equivalence and scorer compatibility checks, bootstrap
  median-difference CI, effect size and Holm adjustment. Unmatched coordinates
  remain visible.

The DOCX's exploratory analysis permits model comparisons; n=3 remains small.
No best-of-N, zero fill or pooling across epochs/conditions/graders. **Recalibrated
on the executed epoch:** 36 spread cells, 18 model-contrast rows (12 analyzed,
6 unsupported for no final receipts) and 12 paired condition comparisons over 36
eligible pairs; no contrast is statistically significant. See
[analysis JSON](../../results/validation/autoresearch-2026-10-31/analysis/analysis.json).

### Offline reproduction commands

These commands read saved/local inputs; they do not launch a matrix or collect
target/provider evidence. Generated outputs belong under `results/validation/`.

```bash
.venv/bin/python -m evaluation.baseline_audit \
  --source results/validation/remediation-2026-10-30/full-2026-10-30 \
  --output results/validation/autoresearch-2026-10-31/nonexecution/audit/baseline-audit.json
.venv/bin/python -m evaluation.ranking_draft --root .
.venv/bin/python -m evaluation.oracle_preregistration --root .
.venv/bin/python -m evaluation.experiment_readiness check \
  --draft config/research/autoresearch-primary-draft-2026-10-31.json \
  --study config/research/autoresearch-primary-study-2026-10-31.json \
  --config config.yaml --repo-root . --web-root ../tesis-web \
  --output-dir results/validation/autoresearch-2026-10-31/nonexecution/readiness
```

Valid-but-blocked drafts exit 0 normally. Ranking `--require-freeze-ready` and
oracle `--require-preregistered` exit 2 while blocked; readiness
`--fail-on-blockers` exits 3. For an independently frozen plan, the saved-artifact
analysis command is `python -m evaluation.research_analysis --plan PATH
--source-root NAME=PATH --review-root NAME=PATH --output PATH`; it is not a launch.

## References

- [Completed implementation and verification](../completed/HANDOFF_AUTORESEARCH_OFFLINE_IMPLEMENTATION_2026-10-31.md).
- [Scoring reference](../reference/thesis_scoring.md) and [methodology summary](../reference/summary_en.md).
- Planner code: `evaluation/research_plan.py`, `evaluation/scoring_v4_matrix.py`. Existing evidence tools: `evaluation/fidelity_ledger.py`, `evaluation/thesis_scoring.py`, `evaluation/research_analysis.py`.
