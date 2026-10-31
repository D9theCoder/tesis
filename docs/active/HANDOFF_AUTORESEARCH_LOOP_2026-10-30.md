# Active — autoresearch loop

**Updated:** 2026-10-31. **Status:** owner decisions settled; independent evidence, runtime changes, approval-metadata transcription and technical execution gates remain. **No matrix execution performed.**
**Completed work:** [offline scoring and reporting fixes](../completed/HANDOFF_AUTORESEARCH_OFFLINE_IMPLEMENTATION_2026-10-31.md).
**Rubric authority:** Tabel 3.5–3.11 in [reconciled Chapter 3](../docx/bab-3-reconciled-2026-10-29.docx); implementation and interpretation must follow it.

## Owner direction

- Detailed inspection of saved artifacts is authorized. Identify deductions/nulls and their evidence-supported causes; do not invent explanations for absent evidence.
- Corrections that bring implementation into line with the reconciled DOCX are approved, subject to containment and existing DVWA scope.
- Ranking defaults are approved by the owner's blanket approval. Record the decision in the machine-readable approval metadata; validate and freeze only when evidence prerequisites are satisfied.
- Candidate order: generated candidates first; use static candidates after the generated route fails. Freeze the precise fallback trigger and order before execution.
- Requested next experiment: **2 models** — DeepSeek V4.1 Flash 1017 at max reasoning and GPT-6 Luna at max reasoning; all **3 surfaces × 3 security levels × both conditions (`linear_hybrid`, `akg_guided_hybrid`) × hybrid payloads × 3 repetitions**. Orchestrator selects methods naturally; no forced-method runs in the primary experiment. Total: **108 runs**. Store traceable run artifacts under `results/runs/<epoch_id>/` for discovery by tesis-web.
- **Current owner direction:** "I APPROVE EVERYTHING" settles routine permissions for the currently proposed work; do not repeatedly request yes/no approval. This supersedes the earlier permission hold, not containment, evidence or technical readiness gates. No execution occurs merely by recording this decision.
- **2A — answered:** the [existing questionnaire is now a decision record](AUTORESEARCH_RANKING_APPROVAL_QUESTIONS.md). Defaults are accepted; the remaining Access Control interpretation is resolved as option A.
- **2B — pricing direction recorded:** use the published GPT-6 Luna API prices for the study's API-equivalent cost accounting; do not reopen the OAuth-versus-API choice. Keep the existing authentication route. An API-priced estimate is not a verified OAuth invoice; preserve that distinction in implementation and reporting.
- **2C — defaults approved:** prepare and bind the proposed measurement protocols using independent machine evidence. Protocol-metadata transcription and proof completeness are assistant work, not another owner questionnaire. Reuse repository evidence first; do not ask the owner to handcraft JSON.
- **Owner decision (2026-10-31) — AI-scored artifacts:** when AI scoring is used, **no human scorer or human verifier is required**, and no routine manual artifact-validation sign-off is a scoring prerequisite. Optional human-scored modes are not prohibited, but the active workflow does not require them. Artifact grades rest on actual machine-recorded observations, receipts and control evidence; absent machine evidence stays unavailable or capped, and AI output alone is not proof. Historical `missing_human_payload_review` labels are retained unchanged as recorded findings; they mean no selected-authority final receipt was retained, not that manual review is required.
- **Owner decision (2026-10-31) — scoring mode fixed to AI:** the current and next requested experiment use `scoring_mode=ai`, already the shipped `config.yaml` value. This is decided, **not** an owner-approval question, and must not be asked again. No human scorer, verifier or sign-off is required. Ranking-profile and protocol/administrative decisions remain separate. This documentation edit makes no runtime or config change.
- **Final interpretation — option A:** broad anonymous exposure is reported separately and is insufficient for method-specific IDOR or vertical-escalation fit. Keep the four low/medium reference fits null until candidate-specific machine evidence supports them. No currently identified opinion or routine approval remains unanswered; do not reopen these decisions.

## 1. Purpose and baseline

Improve **measurement fidelity**, not the headline score. Runtime `composite_score` is legacy; report graded v4 components with explicit availability and reasons. A score increase without better evidence is not improvement.

Historical baseline: `results/validation/remediation-2026-10-30/full-2026-10-30/`: **60 runs / 20 matrices**, one source epoch `b4909695…`. Its 48 eligible runs and 12 AC/high measured negatives are not the newly requested design. The saved baseline has three automatic graded dimensions; `Smethod` and `Srun_final` are null. Its limited score resolution, missing evidence and ceilings are findings—not reasons to change the rubric.

## 2. Work remaining

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
- [ ] Correct dependency-oracle evidence collection (T8/G4a) and routed-selection prerequisite metadata (T7/G16). Six non-final G16 mismatches are diagnosed, not repaired. A future fix cannot create historical proof.
- [ ] Preregister independent oracle evidence (G22). The [source-bound draft and validator](#oracle-preregistration-details) cover three configured protocols. Transcribe the settled approval, distinguish prospective commitments from later per-run proof, and retain missing machine evidence as missing. Future results are not required before preregistration; hash/schema/time validation does not prove authenticity.
- [x] Implement offline chain grading/attribution and measured-negative behavior (T2/G5, G20). `Schain` is run-scope under Tabel 3.10; payload/exploit/output retain their method-specific scope. Levels 3/4 still require independent downstream-use proof.
- [x] Remove the false controls-versus-attempts label diagnostic; publish derived measured-negative label corrections. **12/60** genuine measured-negative/missing-proof contradictions remain in original artifacts, which are preserved. UNION/error response receipts now distinguish HTTP completion from a detected signal; request behavior, scores and confirmation thresholds are unchanged.
- [x] Document baseline ceilings, limited resolution, overlap, denominators and historical gaps. No historical preregistered `Smethod`/`Srun` claim.

### B — prepare and validate the new experiment

- [x] Assemble the [draft ranking profile](#ranking-profile-approval) from independent fixture/protocol evidence, not baseline outcomes.
- [x] Cover all **nine** surface/level scenarios and **27** registered method/scenario entries. **23** reference decisions are supported; **4** AC entries remain pending.
- [x] Bind source hashes, protocol/request-count anchors, AKG preconditions, allowed plans and fit predicates. Owner decisions are settled; the draft remains outside the selector until machine-readable approval metadata, evidence validation and prospective freeze are complete. No synthetic or historical evidence is promoted into a new preregistration.
- [ ] Freeze exactly the requested 108 coordinates after prerequisites are ready. The [compatible primary-study declaration](../../config/research/autoresearch-primary-study-2026-10-31.json) and [readiness draft](#study-readiness-details) specify both models at max reasoning, both conditions, all surfaces/levels, hybrid-only mode, three repeats and `results/runs/<epoch_id>/`. Offline build/verify supports selection-only plans; executing them is explicitly unsupported by this preparation path.
- [ ] Complete the executable epoch-local config/policy freeze and cost measurement. A dated, sourced, non-empty **draft** schedule is available. The owner chose published Luna API rates for API-equivalent accounting; implement that estimate separately from unverified actual OAuth charges. Shipped `config.yaml` is unchanged.
- [x] Verify offline plan/profile validation and grading mechanics: **182 focused checks** and **2 authorized offline/mocked E2E checks** passed. The E2E uses synthetic fixture observations and mocked transport/provider boundaries; it is not a model-selection experiment or live readiness evidence.
- [x] Implement [D12 outcome spread and model/condition reporting](#d12-analysis-contract), retaining every planned repeat, failure and unavailable value. A synthetic empty-epoch smoke retained 108 missing coordinates, 36 spread cells and 18 unsupported model contrasts. Recalibration on real data still awaits the new epoch.

### C — execution remains unperformed; technical prerequisites remain

- [ ] Adapt the chosen `research_plan` to run only the 108 model-selected coordinates; verify target/provider scope, cost measurement, containment/readiness and applicable E2E authorization.
- [ ] Once the approved design's technical gates pass, execute the 108-run matrix and store the plan, receipts and run artifacts under `results/runs/<epoch_id>/` for tesis-web discovery/tracing. Do not ask for the same routine approval again.
- [ ] Produce coordinate-preserving reports for both conditions, both models, all surfaces/levels and all repeats. Distinguish missing, failed and unavailable runs. Do not pool epochs, select best-of-N, or present a baseline rescore as a new run.

**Already implemented:** T1/T3/T9 and offline ledger/reporting mechanics; see the completed handoff. T4 was retracted. FD1's historical AKG freeze-date caveat is recorded; old snapshots were not rewritten.

**Remaining-work distinction:** runtime dependency collection, routed-selection metadata and generated-first/static-fallback execution remain unfinished; the fallback trigger is unfrozen. Selection-only execution is explicitly disabled by the preparation path, and epoch-manifest emission is missing. These are implementation and machine-evidence gaps, not unanswered owner opinions or routine permissions.

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

The two designs that each total 108 are different: `scoring_v4_matrix` forces methods and varies payload mode; the requested matrix varies models/conditions/repeats and lets the orchestrator select methods. `research_plan` retains its two-block default and now supports a selection-only declaration for offline plan building/verification. The primary declaration above represents 108 coordinates, not 1,080; its execution remains blocked.

**Owner decision:** use `research_plan`, adapted to freeze/run only the model-selected block for this primary matrix. Forced-method runs are optional debugging only and excluded from the experiment. Put the epoch and run artifacts beneath `results/runs/<epoch_id>/` so tesis-web can discover and trace them; verify its expected layout in implementation.

**Obsolete-file review:** no deletion is currently justified by the dependency findings. `scoring_v4_matrix.py` and its test are retained because archived validation scripts import its source-hash helper and the two-payload-mode frozen design is not reproduced by `research_plan`. `scoring_repair.py` has a distinct archived rescoring consumer; the Mann–Whitney notebook is historical analysis evidence. No historical evidence files were removed.

### Recorded decisions and required follow-through

- **Q1 — candidate order: decided.** Try generated candidates first; fall back to static candidates when the generated route fails. Freeze that order and the exact failure/fallback trigger before execution; preserve candidate provenance and record which route produced the result.
- **Scoring mode — decided, not a questionnaire item.** The current and next requested experiment use `scoring_mode=ai`; shipped `config.yaml` already records it. No human scorer or verifier is required. Do not ask the owner to choose again.
- **Q2 — score levels/ceilings: no change.** The DOCX is authoritative; correct code to match it, do not revise the rubric.
- **Q3 — labels: approved.** Correct evidence-backed labels without misrepresenting measurements or silently changing scores.
- **Q5 — chain scope: approved.** Implement the DOCX chain rubric; do not choose attribution because it yields a higher grade.
- **Q6 — D12 recalibration: decided, required after the new experiment.** Recompute outcome spread and model/condition contrasts from the complete 108-run data, using the DOCX analysis method and all three repetitions. Report unsupported contrasts as unsupported. This is analysis of new data—not a reason to change score caps or weights.
- **A1 — historical `Smethod`: closed.** Do not run the optional two-key post-hoc test or retrofit the old profile. Retain the old epoch as historical evidence, without treating it as sacred or as a substitute for new data. Freeze the approved ranking profile before the new epoch and grade its recorded selections prospectively. A later scoring-profile/rubric change requires another fresh, fully labelled epoch; it cannot be applied retroactively as preregistered scoring.

These decisions do not change the requested matrix. Freeze candidate order before execution. Any later change to budgets, prompts, seeds, models, score weights, caps, automated verifier thresholds or rubric requires prospective approval and a fresh epoch.


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

- [ ] Planner represents exactly the requested model-selected, Hybrid-only coordinates and writes the plan, receipts and run artifacts beneath `results/runs/<epoch_id>/`.
- [ ] Transcribe the settled ranking decisions, complete the required machine-evidence coverage, validate and prospectively freeze the profile before selection. No new routine owner approval is required.
- [ ] Config freezes both models at max reasoning, all surfaces/levels, both conditions, three repeats, hybrid mode, `scoring_mode=ai`, generated-first/static-fallback order and policy epoch.
- [ ] Dated price schedule and token-usage/cost recording are ready; distinguish API-equivalent estimates from actual billed charges. Future run usage is recorded during execution, not demanded before launch.
- [ ] Target/provider scope, readiness, containment and applicable E2E authorization are confirmed.
- [ ] Source identity is tied to a named git commit or recorded approved amendment; `b4909695…` is a tree hash, not a commit.

After execution, report all 108 coordinates, failures/unavailable runs, rubric vectors/reasons, fidelity measures, costs, containment and both conditions. Recalculate D12 outcome variance/contrasts on the new full dataset. Claim improvement only when fidelity improves under unchanged frozen surfaces; do not claim historical `Srun` recovery. Conclude as converged, ceiling-bound or falsified-out based on actual evidence—never by narrowing acceptance.

## 7. Verification evidence

The counts below record verification **before** documentation consolidation and
test pruning; they are not the current retained test count. No tests were added
or rerun for that cleanup. Historical reports and source artifacts remain unchanged.

- [Focused regression JUnit](../../results/validation/autoresearch-2026-10-31/nonexecution/focused-junit.xml): **182 passed**; no full suite.
- [Authorized offline/mocked E2E JUnit](../../results/validation/autoresearch-2026-10-31/nonexecution/offline-e2e-junit.xml): **2 passed**. Initial failures exposed a contradictory HTTP/signal label and stale synthetic ranking inputs; both were corrected without rewriting runtime results to force grades.
- **AI-receipt accounting smoke:** a temporary local helper (removed after verification) exited 0 with four PASS cases: AI-selected final AI receipt yields `Srun` 2.4 without any human receipt; a missing receipt stays unavailable; `both` mode does not substitute the AI workflow for human authority; human mode rejects a foreign AI receipt. This was synthetic local bookkeeping only—no graph, provider, target, matrix, E2E or test-suite run, and no AI model inference. No new tests were added; existing behavioral tests were updated but not run.
- [Readiness report and 108 planned coordinates](../../results/validation/autoresearch-2026-10-31/nonexecution/readiness/readiness-report.json): compatible study contract, blocked execution, **19 blocker records** (18 distinct IDs).
- [Synthetic reporting smoke](../../results/validation/autoresearch-2026-10-31/nonexecution/analysis-smoke/analysis.json): mechanics only, no final receipts or experiment conclusions.
- All **469** protected inputs retained their byte hashes: 467 baseline files, shipped `config.yaml` and the source DOCX. The intended new epoch directory was not created. No live DVWA or experiment-model inference was performed.

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

Draft: [`config/research/autoresearch-ranking-draft-2026-10-31.json`](../../config/research/autoresearch-ranking-draft-2026-10-31.json).
Validator: [`evaluation/ranking_draft.py`](../../evaluation/ranking_draft.py).
The JSON still records `draft_unapproved_unfrozen`: machine-readable approval metadata has not yet been migrated. Owner decisions are settled in the linked decision record; the draft is not frozen, a scoring profile or selector input.

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

The [decision record](AUTORESEARCH_RANKING_APPROVAL_QUESTIONS.md) retains all 27
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

Intended epoch: `autoresearch-primary-2026-10-31`. Its directory is not created.
The study declares max reasoning for both models; the unchanged shipped inputs differ:

| Model | Configured profile | Model ID | Configured reasoning |
| --- | --- | --- | --- |
| DeepSeek V4.1 Flash 1017 | `river-ai__deepseek-ai-deepseek-v4-1-flash-1017_15efb2abf693` | `deepseek-ai/DeepSeek-V4.1-Flash-1017` | default (`null`) |
| GPT-6 Luna | `openai_codex_auth` | `gpt-6-luna` | `low` |

Only DeepSeek is in the configured providers list; shipped `payload_mode` is
`static_only` and `scoring_mode` is `ai` (fixed for this study), repeats are 1,
the price schedule is empty, and frozen profile/policy inputs are missing.
Fixture restoration covers only low and an older source tree. All levels
need current evidence; a named commit or approved amendment is still required.
Authenticated-provider/live containment readiness is not established offline.

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
and regional processing adds 10% where applicable. Preserve the chosen tier,
cache categories and context regime; implementing the normalized estimate is
still preparation work, not something completed by fetching the price page.

Discovery was inspected against tesis-web `lib/server/fs-util.ts`, `resolve-run.ts`
and `lib/schemas.ts`: root `results/runs`, `experiment_manifest` /
`artifact-manifest.v1`, supported primary types and embedded-child binding.
Manifest indexes are one-based; DTO coordinate indexes are zero-based. An explicit
selection `"target_method": null` is valid; an absent key is not. Other required
summary fields cannot be null. No string substitution or invented execution ID is
allowed. Aggregate fallback exists, but epoch-manifest emission remains unimplemented.
The exact generated-first fallback trigger/order also remains unimplemented/unfrozen.

### Oracle preregistration details

Draft: [`config/research/autoresearch-oracle-preregistration-draft-2026-10-31.json`](../../config/research/autoresearch-oracle-preregistration-draft-2026-10-31.json).
Validator: [`evaluation/oracle_preregistration.py`](../../evaluation/oracle_preregistration.py).
The JSON still records `draft_not_preregistered`; transcribing the settled administrative approval and completing prospective bindings remain assistant work. No collected evidence is implied.

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

**Remaining software distinction:** the current draft validator reports
preregistration metadata and collected-control coverage together. Readiness must
distinguish protocol commitment/approval from later per-run proof completeness;
future run attestations must not be required merely to preregister the protocol.
This remains preparation/reporting work under the settled owner direction; missing
machine evidence is not another request for owner opinion or manual verification.

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
No best-of-N, zero fill or pooling across epochs/conditions/graders. These are
analysis mechanics, not completed D12 recalibration or new experiment results.

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
