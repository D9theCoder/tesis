# Experiment Findings and Codebase Remediation Report

## Scope

This report summarizes the main codebase and methodology issues identified from the 324-run DVWA experiment stored under `results/thesis-experiment-2026-08-21-v2`. The matrix compared Linear and AKG-guided orchestration with GPT-5.6 Luna and DeepSeek V4 Flash. Every coordinate used `llm_mutation_only`.

## Executive Summary

The current experiment cannot demonstrate the full benefit of the AKG because method-level coordinates force `target_method`, bypassing normal method selection and stopping routing after that method is attempted. GPT-5.6 Luna performed better descriptively, but the difference was not statistically significant. The payload terminology also needs correction: the tested mode is mutation-primary generation with deterministic static-seed fallback, not pure mutation-only and not the same as the codebase's true `hybrid` mode.

## 1. AKG Selection and Routing

### Problem

`evaluation/multi_llm_runner.py` expands a method-level matrix by assigning every method to `target_method`. In `agents/orchestrator.py`, a configured target method is selected directly before the normal Linear or AKG-guided selection path, even when it is absent from `viable_methods`. In `core/chaining_coordinator.py`, routing returns to the scorer once the target method has been attempted.

This behavior explains the experimental observations:

- Linear and AKG-guided had identical mean method scores of 2.407, median 3, and first-choice accuracy of 70.4%.
- Each condition had 48/162 coordinates in which `target_method` was not viable.
- `adaptation_rate` was 0 and every recorded `akg_path` was empty.
- Mann-Whitney comparison of the method scores produced `U=13122`, `p=1.000`, and rank-biserial correlation `0.000`.

The result does not prove that the AKG is ineffective. It shows that the method-level evaluation path does not allow the AKG to make or revise the method decision.

### Recommended Solution

1. Keep the current forced-target matrix only for method-agent and payload evaluation.
2. Add a separate orchestrator experiment with `target_method=None`, allowing both conditions to choose from the same reconnaissance snapshot.
3. Treat AKG preconditions as a hard execution gate. A forced method outside `viable_methods` should be marked infeasible instead of executed.
4. After a `not_confirmed` verifier decision, record the failed method, remove it from the active candidate set, and allow a bounded reroute.
5. Permit the chaining router to evaluate `confirmed_vulns` and `achieved_outcomes` after the initial method, then persist every transition in `akg_path` and `chain_history`.
6. Use a paired statistical design for matched Linear/AKG coordinates. Wilcoxon signed-rank or a paired permutation test is more appropriate as the primary comparison; Mann-Whitney can remain supplementary.

## 2. Scoring and Terminal Reporting

### Problem

In `core/scorer.py`, any non-empty `containment_events` collection forces `Soutput=0`. The experiment recorded five safely blocked external navigation links during reconnaissance in every run. Consequently, all 324 runs received `Soutput=0`, even though containment succeeded and no request escaped the allowed DVWA host.

Separately, `evaluation/runner.py` converts an incomplete run without a specific reason to `UNSPECIFIED`. This hides whether the actual cause was no viable method, no valid payload, exhausted methods, or a verifier `not_confirmed` result.

### Recommended Solution

- Score an output as failed only for a containment failure or an unblocked policy violation. A safely blocked navigation event should be neutral or positive evidence of enforcement.
- Set a deterministic terminal reason at the router or scorer boundary, such as `NO_VIABLE_METHODS`, `NO_VALID_PAYLOADS`, `METHOD_NOT_CONFIRMED`, or `ALL_METHODS_FAILED`.
- Recompute `Soutput` and `Srun` after correcting the scoring rule before using composite scores for final thesis claims.

## 3. GPT-5.6 Luna Versus DeepSeek V4 Flash

GPT-5.6 Luna was better descriptively in this experiment:

- Full exploit rate: 35.8% versus 29.0%.
- Mean `Srun`: 1.302 versus 1.222.
- Mean `Spayload` and `Sexploit`: 1.642 versus 1.481.
- Static fallback rate: 6.8% versus 15.4%.
- Total token use: 118,878 versus 147,305.

However, the per-run `Srun` comparison produced `U=13882`, `p=0.3517`, and rank-biserial correlation `0.0579`; both medians were 1.1. The defensible conclusion is therefore that GPT-5.6 Luna had a better descriptive profile, not that it was statistically superior. This comparison should be repeated after fixing `Soutput` and with more repetitions. A proportion test should be used separately if the thesis makes a claim specifically about full-exploit rates.

## 4. Hybrid and Mutation-Only Payload Semantics

### Problem

The implementation distinguishes the modes as follows:

- `hybrid`: static seeds and LLM-generated variants are combined in the candidate pool.
- `llm_mutation_only`: generated variants are preferred, but `foundation/payload_generator.py` falls back to static seeds when generation returns no candidate.
- `foundation/payload_validator.py` performs another static-seed fallback when all generated candidates are invalid.

The experiment recorded 324 generated candidates, of which 288 were valid and 36 were rejected. Those 36 runs triggered static-seed fallback and produced 167 valid static candidate records. Therefore, the tested behavior was not pure mutation-only. It was also not equivalent to true hybrid candidate pooling.

### Recommended Solution

The thesis should describe the tested strategy as **seed-grounded LLM mutation with deterministic static fallback**. If the word "hybrid" is retained, it must be defined at the pipeline level: static seeds act as mutation anchors and recovery candidates, rather than competing with generated candidates in every run.

The artifact schema should explicitly record:

- `generation_strategy: seed_grounded_mutation`
- `fallback_policy: static_seed_on_invalid`
- `fallback_used`
- `effective_payload_source`

Report all-run results separately from a sensitivity analysis that excludes fallback runs. If the thesis instead defines hybrid as simultaneous static and generated candidate pooling, the existing experiment does not test that definition and the matrix must be rerun using the actual `hybrid` mode.

## Recommended Implementation Order

1. Correct containment-aware `Soutput` scoring and terminal reason reporting.
2. Separate forced method-agent evaluation from automatic orchestrator/AKG evaluation.
3. Enable bounded AKG rerouting and auditable chain transitions.
4. Clarify payload-mode names and provenance fields.
5. Rerun the paired Linear/AKG experiment, then repeat the model comparison with additional repetitions.

No remediation described in this report has been implemented by this document-only change.
