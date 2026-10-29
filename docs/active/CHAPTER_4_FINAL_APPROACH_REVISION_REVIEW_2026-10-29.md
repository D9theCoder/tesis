# Chapter 4 revision review: final thesis approach

Status: **revision in progress**. The Chapter 3 and Chapter 4 DOCX drafts have
been revised, but result-table completion and human assessment remain open.
The existing 324-run results do not match the final main-study design, so their
scores have not been presented as main-study results or AI placeholders.

The revision preserves recoverable inputs and a hash-bound structural audit in
`results/validation/thesis-final-revision-20261029/`. Both DOCX files were
rendered with LibreOffice; selected pages and overview sheets were inspected.
The earlier audit in `docs/completed/` applies to the previous Chapter 3 hash;
the new audit is the verification record for the current revisions.
No tests, experiments, rescoring, or provider/target calls were run for this
revision. The table-by-table notes below remain the acceptance and completion
guide for the thesis draft.

## Governing decisions

- Present only the final research approach and its results. Do not add a development history, preliminary-results section, old-versus-new comparison, or remediation narrative.
- The reconciled Chapter 3 governs the experiment: Linear and AKG-guided conditions, hybrid payloads, model-selected methods, three security levels, three surfaces, and three repetitions.
- Nine methods describe the available method repertoire, not nine independently assigned main-study coordinates. Manual targeting remains diagnostic.
- Do not introduce a second forced-method research block, Template, or an additional ablation.
- Owner clarification, 2026-10-29: the thesis uses **human evaluators only**. AI scoring is an experiment/development aid outside the thesis methodology. AI scorer outputs may populate draft result tables as placeholders pending human evaluation; they must not be presented as completed human assessments.
- A placeholder assessment must still belong to the stated experiment population and rubric. Using AI grades temporarily cannot turn forced-method mutation-only runs into autonomous hybrid runs.
- Keep provisional values distinguishable during drafting. Remove provisional markings only after the required human evaluation and evidence checks are complete. Do not invent a human evaluator identity or sign-off.
- IMPORTANT NOTES: Revised text must be COLORED RED

## Sources and review limits

Reviewed the text and tables of:

- [Chapter 4 source](../docx/bab%204%20only.docx).
- [Reconciled Chapter 3](../docx/bab-3-reconciled-2026-10-29.docx).
- [Owner reconciliation decisions](../completed/HANDOFF_COMBINED_THESIS_DOCX_RECONCILIATION_2026-10-29.md), particularly sections 3.1–3.5. The human-only clarification above supersedes its human/AI/both narrative for the thesis.
- [Scoring contract](../reference/thesis_scoring.md).
- [Metric definitions and implementation](../../evaluation/research_metrics.py).
- [Execution and security outcome classification](../../core/run_status.py).
- [Orchestrator](../../agents/orchestrator.py), [payload generator](../../foundation/payload_generator.py), and [graph assembly](../../core/graph_builder.py).
- [Implementation acceptance limits](../completed/HANDOFF_CHAPTER_3_EXPERIMENT_FLOW_DRIFT_2026-10-28.md), section 8.

The prior pass read all 324 execution artifacts in `results/thesis-experiment-2026-08-21-v2/`: all had forced targets matching the selected method, all used `llm_mutation_only`, 36 had fallback events, all output scores were zero, and every AKG path was empty. Their only recorded model role was payload generation. These facts establish why the current Chapter 4 numbers cannot simply be relabeled as the final approach; they are review evidence and are **not material to add as a historical narrative to the thesis**.

This pass also inspected the newer hybrid and Template ablation manifests under `results/`. They do not establish a complete two-model, two-condition, three-level, three-surface, three-repeat main study. This was not an exhaustive acceptance audit of every result directory.

This review examines textual consistency and evidence requirements, not visual pagination or independently verified literature claims.

## Required final chapter structure

Retain the existing six-part organization: implementation/validation, AKG method selection, payload/exploitation/chaining, model comparison, containment/guardrails, and synthesis. Rewrite each around the final study rather than adding a historical experiment section.

Implementation passages should explain what the final framework does and the evidence validating it. Discussion should explain observed final-study behavior, its relationship to the research questions, and limitations intrinsic to that study. Repository cleanup, code defects, and changes between software versions do not belong in that narrative.

## Table-by-table revision specification

| Table | Required revision for the final approach | Evidence needed for numeric entries |
| --- | --- | --- |
| 4.1 Experiment realization | Replace the nine-method multiplier with three vulnerability surfaces; retain nine methods only as supported coverage. With exactly two models, two conditions, three levels, three surfaces, and three repeats, the planned total is **108** runs. This is a design count, not an assertion of completed execution. | Frozen main-study manifest; planned, executed, skipped, and failed counts. |
| 4.2 Framework validation | Describe validation of the final graph, precondition enforcement, hybrid candidate construction, validation, method-bound evidence, routing, containment, and final scoring. Do not transfer test counts or pass labels from a different code/configuration epoch. | Applicable saved validation receipts. Separate offline checks from actual DVWA/provider execution. |
| 4.3 Selection comparison | Use actual model-origin choices and the frozen ranking reference. Separate rejected choices, deterministic fallback, and route selection. Recompute first-choice accuracy and adaptation with their proper populations. | Model selection-call receipts, observation snapshots, ranking profile, rejection records, and supported adaptation opportunities. |
| 4.4 Selection by surface/level | Keep separate condition columns and state how models and repetitions are aggregated. Remove the current claim that conditions are pooled when the table compares them separately. | Eligible model-selection observations and assessable counts in each cell. |
| 4.5 Adaptation | Show opportunities after supported method failure, re-selections, changed-method decisions, and controlled stops. Payload recovery is not method adaptation. | Ordered decisions and failure evidence. Zero opportunities do not produce an adaptation rate of zero percent. |
| 4.6 Payload provenance/validity | Report actual static and model-generated candidates in the hybrid pipeline. Remove the empty `llm_mutated` row if it is not a real source category. Report combined and model-only validity separately. | Parsed and validated exploit/bypass candidates, trusted provenance, and rejection reasons. Controls are excluded. |
| 4.7 Payload effectiveness by method | Separate candidate confirmation rate from run-level full exploit rate. Define attempts as distinct candidate positions, not raw requests or control requests. Add the number of runs selecting/attempting each method. | Candidate execution/verifier links, human candidate grades, independent proof where required, and eligible denominators. Unattempted methods are not zero-success methods. |
| 4.8 Chaining | Distinguish enabling outcomes, weak opportunities, eligible routes, attempted transitions, and independently verified chains. Do not assign a grade solely from an outcome label or missing transition. | Static edge, prerequisite evidence, source material consumption, destination confirmation, and the applicable chain rubric. |
| 4.9 Model scores | Use final-rubric components and the fixed composite formula. The thesis identifies human evaluation as its assessment method. AI-derived draft values are placeholders until human assessment is complete. Remove the unused third comparison column. | Compatible human evaluation records for final publication; provisional AI grades may fill draft cells when linked to the correct runs/rubric. Missing required components leave the composite unavailable. |
| 4.10 Consistency/reliability | Separate method-choice repeat agreement, score-vector consistency, and outcome variation. Do not call forced-target agreement model consistency. Remove the unused third column. | Comparable repeated input scenarios and the declared consistency definition. Grouping must not condition away differences in chosen methods. |
| 4.11 Efficiency/guardrails/cost | Include both selection and generation calls, and distinguish structured-output retry from transport retry. Separate actual token use from price-based cost. | Retained call usage, request-role telemetry, and an applicable timestamped price schedule. Missing prices do not mean zero cost. |
| 4.12 Guardrail handling | Give counts and denominators for experiment-model calls. With no refusal events, report that observation without claiming tested recovery effectiveness. | Refusal, parsing, retry, fallback-use, and stop records for the main-study calls. Human evaluation introduces no evaluator-model call population. |
| 4.13 Containment | Separate discarded external page references from candidate-origin scope violations and actual escaped requests. Keep each numerator and outcome explicit. | Main-study HTTP/validator events. Blocked navigation is not automatically model misconduct or output score zero. |
| 4.14 RQ synthesis | Rewrite every answer from the final-study tables. No retained conclusion may depend on forced selection, a different payload policy, provisional composites, or inferred chain readiness. | Final table populations and human-approved assessments. |

## Additional corrections found on the second pass

### 1. Method alignment is a separate assessment

The current chapter equates correct method family/parameter validation with 100% method alignment. Current metric definitions require an evidence-linked alignment verdict for executed, assessed candidates. Validator acceptance supports structural compatibility; it does not supply that independent verdict. Human evaluation must provide the required assessment before the final alignment claim is made.

### 2. Rates need explicit units and denominators

The current text uses a percentage of successful runs as `payload_execution_success_rate`. The current contract defines this metric over eligible valid exploit/bypass candidates. Report the candidate rate and run-level full exploit rate separately. Do not combine candidate counts, candidate-score records, successful runs, and enabling outcomes into one funnel unless the links between those populations are demonstrated.

### 3. Missing opportunities are different from failed opportunities

First-choice accuracy requires an actual model choice. Adaptation requires a supported opportunity for model re-selection. Route validity requires recorded routes. If the relevant population is empty or proof is missing, report the applicable unavailable/not-applicable status and reason; do not manufacture a zero percentage from all runs as the denominator.

### 4. Execution status and security result are independent

Use execution completion/failure/cancellation separately from confirmed, no finding, unconfirmed, or fixture-limited security outcomes. A completed run may have no confirmed finding. Missing independent proof is not verified negative evidence. Remove the assertion that every non-confirmation is an execution error.

### 5. Human assessment and evidence ceilings govern final scores

Report the human evaluator procedure, actual assessed population, candidate evidence, reasons, and any limitations. Human judgment does not substitute for required independent permission/session/causal evidence. Apply the same evidence ceiling to provisional AI table placeholders. Missing evidence must not be silently converted into a numeric zero, and human approval must not be presumed from an AI-generated value.

### 6. Chaining needs causal proof

`credentials_extracted` or `authenticated_session` does not alone establish an executable edge or a completed chain. The implemented `chain_enabled_exploit_flag` requires a qualifying chain score, rather than counting every enabling outcome label. Use distinct descriptive labels for these counts. Missing chains also do not automatically force every chain grade to zero: assess weak opportunities and prerequisite-complete readiness under the declared rubric.

### 7. Final model comparison must compare the same study

Use the same final design, comparable fixtures, budgets, prompt policy, repetitions, rubric, and human evaluation procedure. Avoid silently substituting newer ablation runs or model versions for either declared study model. Per-method results are conditional on which methods were actually selected, so unequal method distributions need to be visible when interpreting model differences.

### 8. Statistics must use the final analysis population

Remove the existing U statistics, p-values, and effect sizes from the final-results draft unless they have been recomputed for the actual final population. Chapter 3 currently specifies exploratory Mann–Whitney analysis; do not silently replace that method in Chapter 4. If a matched/repeated design requires a different analysis, reconcile both chapters before reporting it. The phrase comparing groups pairwise does not, by itself, define a paired-sample statistical test.

### 9. Presentation cleanup

- Replace the misplaced opening heading “Analisis Eksploratif Menggunakan Mann-Whitney U Test” with the appropriate implementation/setup heading.
- Give the duplicated selection-comparison heading its actual surface/security-level topic.
- Remove “Tidak digunakan” comparison columns from Tables 4.9 and 4.10.
- Use natural Indonesian explanations for statuses and assessment availability; keep English technical terms where useful.
- Keep concrete actual-study limitations, including missing prices or absent observed refusals when true. Such limitations are valid thesis discussion and do not require a software-development narrative.

## Necessary companion correction to Chapter 3

The reconciled Chapter 3 still explicitly describes human/AI/both workflows and an AI evaluator configuration. The owner's latest human-only decision supersedes those passages. They must be revised to describe human evaluation consistently, while AI scoring remains outside the thesis methodology. This does not require changing the score weights, evidence requirements, or main-study axes.

## Boundary for revision

The chapter's organization and final-method explanations can be revised now. The supplied 324-run dataset cannot supply final results for a different experimental design through text edits, AI placeholder grades, or arithmetic changes alone. Populate final tables from compatible experiment evidence and human assessment; use clearly provisional drafting cells where that work is incomplete. Do not introduce a historical-results section to fill the gap.
