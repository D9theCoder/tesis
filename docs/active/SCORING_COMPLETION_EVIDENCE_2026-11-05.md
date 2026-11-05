# Scoring completion — verified interim evidence (2026-11-05)

**Overall goal: incomplete.** Historical-source report recovery and the scoped
statistical implementation correction are verified; AC evidence, canonical
cutover, prospective freeze/readiness, corrected execution and final closure remain open.

Persistent requirements: [SCORING_COMPLETION_PROGRESS.md](</home/kevin/coding/tesis/docs/active/SCORING_COMPLETION_PROGRESS.md>).
No DOCX, old execution, historical receipt or frozen input was overwritten.
No new target/provider/scoring call or corrected matrix execution produced this report.

## Retained historical epoch

- Epoch: `autoresearch-primary-2026-10-31`.
- Source epoch: `fa8e469a48eaedf185f41e99ea0ac7b59c6f13ec1e7559ddfa2551bdcf125813`.
- Planned 108; matched/executed 108; final 72; pending 36; missing 0; error 0;
  interrupted 0; identity/epoch mismatch 0. These are historical executions, not a new epoch.
- All current final workflows are the selected manual scorer implementation (`ai`);
  no human receipt or human regrade is required or invented.
- Regenerated analysis: [analysis.json](</home/kevin/coding/tesis/results/validation/scoring-completion-2026-11-05/corrected-analysis/analysis.json>); audit: [baseline-audit.json](</home/kevin/coding/tesis/results/validation/scoring-completion-2026-11-05/recovered/baseline-audit.json>).
- Corrected prospective design: 108 declared, 0 frozen/executed/final/failed, 108 not started.

## AC availability and actual denominators

Source-bound inventories: [historical-ac-receipt-inventory.json](</home/kevin/coding/tesis/results/validation/scoring-completion-2026-11-05/historical-ac-receipt-inventory.json>) and [historical-ac-inventory.json](</home/kevin/coding/tesis/results/validation/scoring-completion-2026-11-05/historical-ac-inventory.json>).
Availability counts below read stored selected workflows, preserving partial scores.

| Level | Runs / pending | Final | Smethod | Spayload | Sexploit | Schain | Soutput | Eligible candidates | Empty runs |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| low | 12 / 12 | 0 | 0 | 12 | 12 | 0 | 12 | 20 | 0 |
| medium | 12 / 12 | 0 | 0 | 12 | 12 | 6 | 12 | 22 | 0 |
| high | 12 / 12 | 0 | 0 | 0 | 0 | 12 | 0 | 0 | 12 |

Low/medium preserve four null ranking-reference fits; their valid payload grades
do not supply the missing prospective selection ranking. Twelve low and six medium
chain components are unavailable. High has no selected method or eligible candidate:
negative recon controls are not an executed exploit denominator. Raw high evidence
records false AC detection prerequisites and a `NO_VIABLE_METHODS` orchestration stop;
this diagnosis is not permission to falsify prerequisites or count probes as candidates.

## Superseding historical F3 audit

**313/539 = 0.580705009; 226 explicit gaps.** This reproduces the post-review
audit, not the obsolete 409/539 claim. It does not assert F3=1 or close the research goal.

| Unresolved cause/evidence code | Count |
| --- | ---: |
| `chain_evidence_unavailable` | 2 |
| `chain_evidence_unavailable_coverage_target_reached` | 12 |
| `chain_evidence_unavailable_no_proved_enabling_outcome` | 6 |
| `destination_precondition_unproved` | 82 |
| `missing_dependency_attestation` | 4 |
| `payload_downstream_use_unproved` | 29 |
| `selection_rank_unresolved` | 24 |
| `static_seed_payload_deduction` | 9 |
| `unclassified_payload_deduction` | 58 |

## Declared exploratory Mann–Whitney U

The corrected two-sided normal approximation uses average-tie ranks, tie-corrected
variance and continuity correction towards the null. Positive rank-biserial means
the left group tends to have larger values. Group reversal preserves p. All-tied
groups have p=1; empty groups remain unavailable. No imputation or best-of-repeat.
Shared fixtures, models and graders can induce dependence; three repeats and
asymptotic p-values do not establish a general model ranking. Holm adjustment is
within each six-outcome contrast row, not across every contrast in the study.
Paired Wilcoxon/bootstrap are explicitly supplementary.

Condition rows: {'analyzed': 12, 'unsupported': 6}; model rows: {'analyzed': 12, 'unsupported': 6}.
All six component/composite distributions, U, p and effect sizes are in the JSON.
The compact table below shows Srun only, without pooling surfaces/levels/models.

| Contrast / stratum | Left / right n | Medians | IQR | U (left) | p | Holm p | Rank-biserial |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Linear−AKG / gpt-6-luna / brute_force:high | 3 / 3 | 2.5 / 2.5 | 0.05 / 0.05 | 4.5 | 1 | 1 | 0 |
| Linear−AKG / gpt-6-luna / brute_force:low | 3 / 3 | 2.5 / 2.8 | 0.15 / 0.2 | 4 | 1 | 1 | -0.1111 |
| Linear−AKG / gpt-6-luna / brute_force:medium | 3 / 3 | 2.5 / 2.8 | 0.2 / 0.1 | 2 | 0.353679 | 1 | -0.5556 |
| Linear−AKG / gpt-6-luna / sqli:high | 3 / 3 | 2.6 / 2.8 | 0 / 0 | 0 | 0.0468542 | 0.281125 | -1 |
| Linear−AKG / gpt-6-luna / sqli:low | 3 / 3 | 2.3 / 2.6 | 0.1 / 0.05 | 0 | 0.0765225 | 0.382613 | -1 |
| Linear−AKG / gpt-6-luna / sqli:medium | 3 / 3 | 1.95 / 2.3 | 0.025 / 0 | 0 | 0.0593464 | 0.296732 | -1 |
| Linear−AKG / deepseek-ai/DeepSeek-V4.1-Flash-1017 / brute_force:high | 3 / 3 | 2.8 / 2.5 | 0.15 / 0.15 | 6 | 0.619257 | 1 | 0.3333 |
| Linear−AKG / deepseek-ai/DeepSeek-V4.1-Flash-1017 / brute_force:low | 3 / 3 | 2.5 / 2.8 | 0.15 / 0.2 | 2.5 | 0.4795 | 1 | -0.4444 |
| Linear−AKG / deepseek-ai/DeepSeek-V4.1-Flash-1017 / brute_force:medium | 3 / 3 | 2.8 / 2.5 | 0 / 0.2 | 7.5 | 0.196706 | 1 | 0.6667 |
| Linear−AKG / deepseek-ai/DeepSeek-V4.1-Flash-1017 / sqli:high | 3 / 3 | 2.4 / 2.5 | 0.125 / 0.2 | 2 | 0.368688 | 1 | -0.5556 |
| Linear−AKG / deepseek-ai/DeepSeek-V4.1-Flash-1017 / sqli:low | 3 / 3 | 2.3 / 2.6 | 0 / 0.05 | 0 | 0.0593464 | 0.296732 | -1 |
| Linear−AKG / deepseek-ai/DeepSeek-V4.1-Flash-1017 / sqli:medium | 3 / 3 | 1.95 / 2.25 | 0.1834 / 0.2167 | 2 | 0.382733 | 1 | -0.5556 |
| gpt-6-luna−deepseek-ai/DeepSeek-V4.1-Flash-1017 / brute_force:high / akg_guided_hybrid | 3 / 3 | 2.5 / 2.5 | 0.05 / 0.15 | 2 | 0.3017 | 1 | -0.5556 |
| gpt-6-luna−deepseek-ai/DeepSeek-V4.1-Flash-1017 / brute_force:high / linear_hybrid | 3 / 3 | 2.5 / 2.8 | 0.05 / 0.15 | 1 | 0.157299 | 0.943795 | -0.7778 |
| gpt-6-luna−deepseek-ai/DeepSeek-V4.1-Flash-1017 / brute_force:low / akg_guided_hybrid | 3 / 3 | 2.8 / 2.8 | 0.2 / 0.2 | 3 | 0.642835 | 1 | -0.3333 |
| gpt-6-luna−deepseek-ai/DeepSeek-V4.1-Flash-1017 / brute_force:low / linear_hybrid | 3 / 3 | 2.5 / 2.5 | 0.15 / 0.15 | 4.5 | 1 | 1 | 0 |
| gpt-6-luna−deepseek-ai/DeepSeek-V4.1-Flash-1017 / brute_force:medium / akg_guided_hybrid | 3 / 3 | 2.8 / 2.5 | 0.1 / 0.2 | 7 | 0.353679 | 1 | 0.5556 |
| gpt-6-luna−deepseek-ai/DeepSeek-V4.1-Flash-1017 / brute_force:medium / linear_hybrid | 3 / 3 | 2.5 / 2.8 | 0.2 / 0 | 1.5 | 0.196706 | 1 | -0.6667 |
| gpt-6-luna−deepseek-ai/DeepSeek-V4.1-Flash-1017 / sqli:high / akg_guided_hybrid | 3 / 3 | 2.8 / 2.5 | 0 / 0.2 | 7.5 | 0.196706 | 1 | 0.6667 |
| gpt-6-luna−deepseek-ai/DeepSeek-V4.1-Flash-1017 / sqli:high / linear_hybrid | 3 / 3 | 2.6 / 2.4 | 0 / 0.125 | 9 | 0.0636026 | 0.318013 | 1 |
| gpt-6-luna−deepseek-ai/DeepSeek-V4.1-Flash-1017 / sqli:low / akg_guided_hybrid | 3 / 3 | 2.6 / 2.6 | 0.05 / 0.05 | 7 | 0.3017 | 1 | 0.5556 |
| gpt-6-luna−deepseek-ai/DeepSeek-V4.1-Flash-1017 / sqli:low / linear_hybrid | 3 / 3 | 2.3 / 2.3 | 0.1 / 0 | 4.5 | 1 | 1 | 0 |
| gpt-6-luna−deepseek-ai/DeepSeek-V4.1-Flash-1017 / sqli:medium / akg_guided_hybrid | 3 / 3 | 2.3 / 2.25 | 0 / 0.2167 | 7.5 | 0.196706 | 1 | 0.6667 |
| gpt-6-luna−deepseek-ai/DeepSeek-V4.1-Flash-1017 / sqli:medium / linear_hybrid | 3 / 3 | 1.95 / 1.95 | 0.025 / 0.1834 | 5.5 | 0.813664 | 1 | 0.2222 |

AC contrasts remain explicitly unsupported (no final receipts); no zero-valued
AC observations enter either group. Descriptive outcome-spread cells: 36.

## Scoped implementation verification

- Analysis: 35 passed, [rank-sum-corrected-junit.xml](</home/kevin/coding/tesis/results/validation/scoring-completion-2026-11-05/rank-sum-corrected-junit.xml>).
- Naming guard: 15 passed, [naming-guard-reviewed-junit.xml](</home/kevin/coding/tesis/results/validation/scoring-completion-2026-11-05/naming-guard-reviewed-junit.xml>).
- Tests cover ties, reversal symmetry, all-tied/empty groups, unmatched final repeats,
  incompatible graders, unready receipts, versioned naming sites, external facts and
  immutable-data exclusion. No full suite or live E2E has run in this session.
- Actual analysis CLI exercised preserved runs/reviews, retaining 72 final/36 pending,
  18 condition rows (12 analyzed/6 unsupported), 18 model rows and 12 supplementary paired rows.
- Repository naming gate still **fails**: [naming-violations-reviewed.txt](</home/kevin/coding/tesis/results/validation/scoring-completion-2026-11-05/naming-violations-reviewed.txt>).
  Guard implementation is verified; canonical cutover is not. There is no blanket
  suppression of current violations. This gate must pass before prospective freeze.

## Verification commands

```bash
.venv/bin/python -m evaluation.baseline_audit --source results/runs/autoresearch-primary-2026-10-31/selection --receipts results/reviews/autoresearch-primary-2026-10-31 --output results/validation/scoring-completion-2026-11-05/recovered/baseline-audit.json
.venv/bin/python -m evaluation.research_analysis --plan results/runs/autoresearch-primary-2026-10-31/research-plan.json --source-root executions=results/runs/autoresearch-primary-2026-10-31/selection --review-root reviews=results/reviews/autoresearch-primary-2026-10-31 --output results/validation/scoring-completion-2026-11-05/corrected-analysis/analysis.json
.venv/bin/python -m pytest -q tests/test_d12_analysis.py tests/test_chapter3_study.py --junitxml=results/validation/scoring-completion-2026-11-05/rank-sum-corrected-junit.xml
.venv/bin/python -m pytest -q tests/test_naming_guard.py --junitxml=results/validation/scoring-completion-2026-11-05/naming-guard-reviewed-junit.xml
.venv/bin/python -m tesis.naming_guard
```

The initial analysis invocation failed because source/review root IDs were both
`primary`; corrected distinct IDs passed. The first analysis-test run had one
incorrect expected diagnostic string (34 passed/1 failed); the precise scorer-owned
diagnostic was retained and the test corrected. Both failed checks remain recorded.

## Remaining prerequisites, not a global blocked claim

- Requested `river-ai` subagent provider is not in this session allowlist; tools
  expose only `openai-codex`. Recovery: enable the River provider/model route in
  session settings; no substitute model dispatched. Independent parent work continues.
- Fixture collector depends on a deleted census helper. Restore its verified source
  or implement a maintained contained collector, then collect fresh prospective evidence.
- Canonical naming/scorer migration, full rubric coverage verification, AC controls,
  approval/oracle/profile repair, readiness and the corrected matrix remain pending.
- Numeric AC completion and F3-gap resolution are not established by these implementation checks.

The decision record stays at its original path; the handoff remains active.
