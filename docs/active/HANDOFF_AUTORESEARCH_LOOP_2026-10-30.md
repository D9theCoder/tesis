# Active — autoresearch loop

**Updated:** 2026-10-31. **Status:** offline implementation partly complete; artifact audit, rubric-aligned fixes and next-epoch preparation remain.
**Completed work:** [offline scoring and reporting fixes](../completed/HANDOFF_AUTORESEARCH_OFFLINE_IMPLEMENTATION_2026-10-31.md).
**Rubric authority:** Tabel 3.5–3.11 in [reconciled Chapter 3](../docx/bab-3-reconciled-2026-10-29.docx); implementation and interpretation must follow it.

## Owner direction

- Detailed inspection of saved artifacts is authorized. Identify deductions/nulls and their evidence-supported causes; do not invent explanations for absent evidence.
- Corrections that bring implementation into line with the reconciled DOCX are approved, subject to containment and existing DVWA scope.
- Assemble a draft ranking-profile document for owner review. Do not freeze or use it until approved.
- Candidate order: generated candidates first; use static candidates after the generated route fails. Freeze the precise fallback trigger and order before execution.
- Requested next experiment: **2 models** — DeepSeek V4.1 Flash 1017 at max reasoning and GPT-6 Luna at max reasoning; all **3 surfaces × 3 security levels × both conditions (`linear_hybrid`, `akg_guided_hybrid`) × hybrid payloads × 3 repetitions**. Orchestrator selects methods naturally; no forced-method runs in the primary experiment. Total: **108 runs**. Store traceable run artifacts under `results/runs/<epoch_id>/` for discovery by tesis-web.
- The owner permits execution after this discussion and applicable gates. This is not permission to launch before the profile/config and technical gates are ready.

## 1. Purpose and baseline

Improve **measurement fidelity**, not the headline score. Runtime `composite_score` is legacy; report graded v4 components with explicit availability and reasons. A score increase without better evidence is not improvement.

Historical baseline: `results/validation/remediation-2026-10-30/full-2026-10-30/`: **60 runs / 20 matrices**, one source epoch `b4909695…`. Its 48 eligible runs and 12 AC/high measured negatives are not the newly requested design. The saved baseline has three automatic graded dimensions; `Smethod` and `Srun_final` are null. Its limited score resolution, missing evidence and ceilings are findings—not reasons to change the rubric.

## 2. Work remaining

### A — inspect baseline and correct implementation

- [ ] Inspect accepted artifacts in detail. Account for the **300** currently unattributed deductions/nulls; assign a closed cause only when supported by evidence. Otherwise record the evidence gap.
- [ ] Correct dependency-oracle evidence collection (T8/G4a) and routed-selection prerequisite metadata (T7/G16). Six non-final G16 mismatches are diagnosed, not repaired. A future fix cannot create historical proof.
- [ ] Preregister independent oracle evidence (G22) as needed for the DOCX-defined rubric claims.
- [ ] Implement chain grading/attribution and measured-negative behavior according to the DOCX (T2/G5, G20); do not choose interpretations because they yield larger scores.
- [ ] Correct artifact labels that contradict recorded measurements without changing the finding or score unless the DOCX requires it. A sent control is not necessarily an exploit attempt; a planned control is not evidence it was sent.
- [ ] Document baseline ceilings, limited resolution, evidence overlap, denominators and historical gaps. Do not claim a preregistered historical `Smethod`/`Srun`.

### B — prepare and validate the new experiment

- [ ] Assemble a draft ranking profile from the static AKG, protocol material and independent fixture evidence—not baseline outcomes.
- [ ] Cover all **nine** surface/level scenarios and every registered method: 3 Access Control + 2 Brute Force + 4 SQLi methods for each surface/level where defined. Total: **27 method/scenario entries**.
- [ ] Bind sources, protocol/request-count anchors, AKG preconditions, allowed plans, fit predicates and reference decisions. Keep the ranking outside the selector. Freeze only after owner approval and before the first selection.
- [ ] Freeze exactly the requested 108 coordinates; validate both model profiles and max reasoning, both conditions, all surfaces/levels, hybrid-only mode, three repeats and output placement under `results/runs/`.
- [ ] Prepare an epoch-local config with explicit policy epoch and a dated, non-empty token-price schedule; arrange cost measurement. Shipped `config.yaml` remains unchanged unless separately approved.
- [ ] Prove plan/profile validation and post-freeze grading mechanics before provider execution. Synthetic fixtures demonstrate mechanics only; they are not experiment results.

### C — execute after readiness gates

- [ ] Adapt the chosen `research_plan` to run only the 108 model-selected coordinates; verify target/provider scope, cost measurement, containment/readiness and applicable E2E authorization.
- [ ] Execute the approved 108-run matrix only after the gates pass. Store plan, receipts and run artifacts under `results/runs/<epoch_id>/` for tesis-web discovery/tracing.
- [ ] Produce coordinate-preserving reports for both conditions, both models, all surfaces/levels and all repeats. Distinguish missing, failed and unavailable runs. Do not pool epochs, select best-of-N, or present a baseline rescore as a new run.

**Already implemented:** T1/T3/T9 and offline ledger/reporting mechanics; see the completed handoff. T4 was retracted. FD1's historical AKG freeze-date caveat is recorded; old snapshots were not rewritten.

## 3. Historical evidence limits

These limits apply to the **2026-10-30 retained evidence under the current rubric**, not to future implementation.

| Historical claim unavailable | Why |
| --- | --- |
| Preregistered `Smethod`, therefore graded `Srun` | No profile was frozen before selection; recorded profile hashes are null. A new profile cannot retroactively satisfy preregistration. |
| 12 original selection snapshots | They were never recorded. A reconstruction is not the original evidence. |
| `Sexploit 4` | Verified downstream-dependency evidence is absent. A future collector fix cannot prove past use. |
| `Smethod 4` | Resolvable reason-reference evidence is absent. Reauthoring receipts would rewrite history. |

**A1 is closed by owner direction:** do not run the two-key post-hoc test or retrofit the old profile. The old epoch remains retained historical evidence, but it is not a substitute for a new run. Freeze the approved profile before the requested new epoch and assess its selections prospectively. Any later profile/rubric change requires another fresh, separately identified epoch; it cannot retroactively become preregistered grading.

## 4. Planner compatibility and decisions

### Why the existing plans do not match the requested 108 runs

| | [`scoring_v4_matrix.py`](../../evaluation/scoring_v4_matrix.py) | [`research_plan.py`](../../evaluation/research_plan.py) | Owner's requested primary matrix |
| --- | --- | --- | --- |
| Purpose | Fixed-method/agent coverage | End-to-end selection **plus** fixed-method coverage | End-to-end model-selected evaluation |
| Methods | Forces each registered method in turn | Selection block: `target_method=None`; forced block: one run per registered method | Model selects method during each run |
| Payload | `hybrid` + `llm_mutation_only` | Hybrid | Hybrid only |
| Models | One `openai_compatible` profile | Multiple configured providers possible | DeepSeek V4.1 Flash 1017 + GPT-6 Luna, both max reasoning |
| Repeats | One | At least three | Three |
| Planned runs | 108 forced-method coordinates | Selection: 108; forced: 972; total: 1,080 | 2 × 3 surfaces × 3 levels × 2 conditions × 3 repeats = 108 |

**What “forced-method” means:** rather than ask the orchestrator to choose, the runner pins `target_method` to one registered method and exercises it directly. This isolates method-agent/payload behavior for debugging; it is not the primary end-to-end model-selection measurement. In `research_plan`, the forced block covers all nine methods across two models, three levels, two conditions and three repeats: **972 additional runs**.

The two designs that each total 108 are different: `scoring_v4_matrix` forces methods and varies payload mode; the requested matrix varies models/conditions/repeats and lets the orchestrator select methods. `research_plan` includes the requested selection block but currently requires and executes the additional forced block.

**Owner decision:** use `research_plan`, adapted to freeze/run only the model-selected block for this primary matrix. Forced-method runs are optional debugging only and excluded from the experiment. Put the epoch and run artifacts beneath `results/runs/<epoch_id>/` so tesis-web can discover and trace them; verify its expected layout in implementation.

### Recorded decisions and required follow-through

- **Q1 — candidate order: decided.** Try generated candidates first; fall back to static candidates when the generated route fails. Freeze that order and the exact failure/fallback trigger before execution; preserve candidate provenance and record which route produced the result.
- **Q2 — score levels/ceilings: no change.** The DOCX is authoritative; correct code to match it, do not revise the rubric.
- **Q3 — labels: approved.** Correct evidence-backed labels without misrepresenting measurements or silently changing scores.
- **Q5 — chain scope: approved.** Implement the DOCX chain rubric; do not choose attribution because it yields a higher grade.
- **Q6 — D12 recalibration: decided, required after the new experiment.** Recompute outcome spread and model/condition contrasts from the complete 108-run data, using the DOCX analysis method and all three repetitions. Report unsupported contrasts as unsupported. This is analysis of new data—not a reason to change score caps or weights.
- **A1 — historical `Smethod`: closed.** Do not run the optional two-key post-hoc test or retrofit the old profile. Retain the old epoch as historical evidence, without treating it as sacred or as a substitute for new data. Freeze the approved ranking profile before the new epoch and grade its recorded selections prospectively. A later scoring-profile/rubric change requires another fresh, fully labelled epoch; it cannot be applied retroactively as preregistered scoring.

These decisions do not change the requested matrix. Freeze candidate order before execution. Any later change to budgets, prompts, seeds, models, score weights, caps, verifier thresholds or rubric requires prospective approval and a fresh epoch.


## 5. Fidelity and anti-benchmax rules

Every deduction/null needs one evidence-linked cause: `model_output_quality`, `harness_ordering`, `harness_budget`, `harness_scoring`, `provider_failure`, `fixture_infeasible`, `rubric_ceiling`, or `label`. Only `harness_*` causes are repair candidates; other causes are research findings. Missing evidence remains unresolved, never invented.

| Metric | Meaning / target |
| --- | --- |
| **F1** model-candidate execution | Executed model-candidate receipts / receipts with model candidates; historical baseline 1/123. Treatment changes require preregistration. |
| **F2** generated-grade share | Eligible runs whose counted payload grade came from a model candidate / eligible runs; baseline 0/48. Not a replacement thesis score. |
| **F3** attribution completeness | Supported closed causes / deductions and nulls; target 1.00, unknown 0. |
| **F4** null discipline | Unavailable values have valid reasons; distinguish missing evidence from measured negatives. |
| **F5** arithmetic consistency | Available vectors match frozen rubric weights; target 1.00. |
| **F6** label consistency | Internal label disagreements; target 0, based on sent/executed evidence. |
| **F7** repeat stability | Report variation across three repeats; never cherry-pick. Historical baseline: 11/16 stable cells. |
| **F8** rubric coverage | Reported runs use the graded path; every unavailable component has a reason. |
| **FD1** diagnostic | Selection-precondition consistency only; not a rubric dimension or optimality measure, and excluded from `Srun`. Historical final snapshots: 48/48 consistent; 12 missing. |

Preserve the DOCX dimensions, final-method scope and weights **0.20/0.20/0.30/0.10/0.20**. `Spayload` is the mean of distinct validated, executed exploit/bypass candidates in the final selected/executed method—not probes, rejected/unexecuted candidates or earlier methods. Recovered HTTP 429/network retries are not structural output repair. Runtime `composite_score` remains legacy.

No null-to-zero fill, hand-assigned grades, provenance promotion, relaxed confirmation, fabricated controls, profile backdating, outcome-fitted prompts/seeds, best-of-N, favourable repeat selection or condition pooling. Any treatment amendment needs written rationale, predicted effects and approval before outcomes; compare full epochs and retain the seed baseline. Preserve original artifacts, containment, target scope and fixture-restoration evidence.

## 6. Launch gates and acceptance

The owner approves **one 108-run model-selected matrix** after the discussion and readiness gates. No forced-method block. The output root must be `results/runs/<epoch_id>/`, discoverable and traceable by tesis-web. Before execution:

- [ ] Planner represents exactly the requested model-selected, Hybrid-only coordinates and writes the plan, receipts and run artifacts beneath `results/runs/<epoch_id>/`.
- [ ] Ranking profile is drafted, owner-approved, validated and frozen before selection; it covers all required scenarios/methods.
- [ ] Config freezes both models at max reasoning, all surfaces/levels, both conditions, three repeats, hybrid mode, generated-first/static-fallback order and policy epoch.
- [ ] Dated price schedule and cost measurement are available.
- [ ] Target/provider scope, readiness, containment and applicable E2E authorization are confirmed.
- [ ] Source identity is tied to a named git commit or recorded approved amendment; `b4909695…` is a tree hash, not a commit.

After execution, report all 108 coordinates, failures/unavailable runs, rubric vectors/reasons, fidelity measures, costs, containment and both conditions. Recalculate D12 outcome variance/contrasts on the new full dataset. Claim improvement only when fidelity improves under unchanged frozen surfaces; do not claim historical `Srun` recovery. Conclude as converged, ceiling-bound or falsified-out based on actual evidence—never by narrowing acceptance.

## References

- [Completed implementation and verification](../completed/HANDOFF_AUTORESEARCH_OFFLINE_IMPLEMENTATION_2026-10-31.md).
- [Scoring reference](../reference/thesis_scoring.md) and [methodology summary](../reference/summary_en.md).
- Planner code: `evaluation/research_plan.py`, `evaluation/scoring_v4_matrix.py`. Existing evidence tools: `evaluation/fidelity_ledger.py`, `evaluation/thesis_scoring.py`, `evaluation/research_analysis.py`.
