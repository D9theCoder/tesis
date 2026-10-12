# Handoff: Separate execution status from security outcome

Status: **completed**. Drafted and completed 2026-10-12. Runtime, reporting, documentation, and focused non-E2E acceptance passed.

## Problem

The runtime currently overloads `task_result=INCOMPLETE` to represent more than
one condition. The scorer sets it when no vulnerability or enabling outcome is
confirmed. The runner then maps it to artifact `status=error`, even when the
graph completed normally and the provider call and HTTP requests completed.
This makes a completed negative or unresolved experiment look like an execution
failure.

The scoring rules already distinguish verified negative evidence from missing
evidence. A supported negative signal may score 0; missing proof, an unavailable
oracle, or a pending review remains null/pending. Execution status must not
override that distinction or alter the scoring formula.

## Goal

Represent two independent questions in runtime state and saved artifacts:

1. Did the experiment execute to a normal terminal point?
2. What security result does its evidence support?

Use these fields in reports, matrix aggregates, the TUI, and documentation.
Keep successful execution distinct from successful exploitation. Do not lower
verifier thresholds or turn absent evidence into a negative finding.

## Behavior before implementation and preserved baseline

- [`core/scorer.py`](../../core/scorer.py) sets `task_result` to `SUCCESS` when
  findings exist and otherwise defaults to `INCOMPLETE`.
- [`evaluation/runner.py`](../../evaluation/runner.py) maps `INCOMPLETE` to
  `UNSPECIFIED` when no reason is present, and emits `status=error` for a
  normally completed graph with an incomplete terminal result.
- [`docs/reference/summary_en.md`](../reference/summary_en.md) and
  [`summary_id.md`](../reference/summary_id.md) document this behavior for an
  exhausted method with no confirmed finding.
- [`thesis_scoring.md`](../reference/thesis_scoring.md) and
  [`metrik_penilaian_tesis.docx`](../../metrik_penilaian_tesis.docx) define
  evidence-based scores. The DOCX says a confirmed negative signal scores 0;
  missing or indeterminate evidence leaves the score null/pending.

The current fresh matrix is preserved at
`results/validation/scoring-v4-remediation-2026-10-12-matrix-epoch7/`. It has
108 planned and reconciled coordinates, 61 `SUCCESS`, and 47 `INCOMPLETE`.
The 47 were classified as 36 executed without candidate confirmation, four
weak/partial signals, and seven Access Control force-browse cases without an
independent permission oracle. Provider calls completed for all coordinates;
these findings do not establish 47 execution failures or 47 verified negatives.
Use the [independent matrix audit](../../results/validation/scoring-v4-remediation-2026-10-12-matrix-epoch7/independent-matrix-audit-v2.json)
and [incomplete-outcome audit](../../results/validation/scoring-v4-remediation-2026-10-12-matrix-epoch7/incomplete-outcome-audit-v2.json)
as immutable evidence.

## Required status model

### `execution_status`

Use the terminal execution lifecycle, independently of findings:

- `completed`: the planned coordinate reached a normal terminal point. A
  negative, unconfirmed, or fixture-limited security outcome can still be
  completed.
- `failed`: an unexpected runtime, provider, target, or artifact error prevented
  normal completion.
- `interrupted`: an explicit cancellation or interruption stopped the run before
  normal completion.

Do not use `failed` to mean that no exploit was confirmed. Preserve a distinct
reason for a failure or interruption.

### `security_outcome`

Record the strongest conclusion supported by the evidence:

- `confirmed`: required method evidence and applicable independent controls
  confirm a vulnerability or enabling outcome.
- `no_finding`: the method ran and sufficient negative evidence/controls show
  that the assessed exploit signal did not occur.
- `unconfirmed`: the run produced evidence, but it is insufficient or ambiguous
  to confirm either outcome.
- `fixture_limited`: a required principal, permission/session oracle, fixture
  behavior, or control was unavailable, preventing a valid conclusion.

Attach a structured `security_outcome_reason` where the result is not
`confirmed`, such as `NO_CANDIDATE_CONFIRMATION`, `PARTIAL_SIGNAL`, or
`PERMISSION_ORACLE_UNAVAILABLE`. Keep execution failure details in a separate
`execution_reason`. Do not emit `UNSPECIFIED` when evidence supports a reason.

`no_finding` requires affirmative negative evidence. A missing response, missing
candidate link, missing oracle, or verifier `unverified` result is not proof of
absence; classify it as `unconfirmed` or `fixture_limited`.

## Scoring and reporting contract

- Preserve the scoring.v4 rubric, proof ceilings, and
  `Srun = 0.20*Smethod + 0.20*Spayload + 0.30*Sexploit + 0.10*Schain + 0.20*Soutput`.
- A verified negative may earn 0 on the affected score dimension. An
  unconfirmed or fixture-limited dimension remains null/pending when its required
  proof is absent; never impute 0. Score independently supported dimensions as
  the rubric permits.
- Emit `Srun_final` only when all required component evidence, eligible
  denominator, and selected review workflow are complete. A completed
  execution does not make an unassessable score final.
- Count `completed + no_finding`, `completed + unconfirmed`, and
  `completed + fixture_limited` as completed executions in coverage. Report
  security outcomes separately from execution reliability and exploit rate.
- Use execution status for run, matrix, and TUI lifecycle indicators. Display
  security outcome and its reason separately. A completed coordinate with no
  confirmed exploit must not produce a run-level `error` solely for that reason.

## Implementation scope

1. Add typed status fields and reason codes to `core/state.py`; define one
   shared validation/mapping helper rather than duplicating string rules.
2. Update `core/scorer.py`, `agents/orchestrator.py`,
   `core/chaining_coordinator.py`, and `evaluation/runner.py` so outcome
   classification does not set execution failure status. Preserve genuine
   provider, transport, exception, cancellation, and resume failures.
3. Propagate both fields through primary artifacts, error artifacts, matrix
   child/aggregate records, reports, journals/descriptors, and TUI result rows.
   Audit readers and writers in `evaluation/multi_llm_runner.py`,
   `evaluation/reporter.py`, `evaluation/thesis_scoring.py`,
   `tesis/tui_state.py`, `tesis/tui_drawers.py`, and artifact repository code.
4. Keep readers backward-compatible with historical `task_result` and
   `incomplete_reason` artifacts. New artifacts must make the two new fields
   canonical; do not rewrite historical artifacts. Document any temporary
   compatibility alias and prevent old `INCOMPLETE` from being presented as a
   new execution failure without inspecting its evidence.
5. Update the thesis DOCX with separate tables for execution status and security
   outcome, with definitions and examples, make sure the edited/added text is colored dark blue. Update both `summary_en.md` and
   `summary_id.md`, `thesis_scoring.md`, and affected architecture/artifact
   documentation so their status and scoring rules agree. The repository has
   no file named `summary.md`; these localized summaries are the current files.

## Required controls and acceptance

- Unit controls cover each execution status crossed with each security outcome,
  including `completed + no_finding`, `completed + unconfirmed`,
  `completed + fixture_limited`, and `failed/interrupted + unconfirmed`.
- Prove that a sufficiently controlled negative scores 0 on the relevant
  dimension, while missing evidence/oracle remains null or pending. Verify that
  one zero component does not force the entire weighted `Srun` to zero.
- Verify runner status, matrix counts, serialized artifact fields, report text,
  TUI presentation, and backward reads of historical artifacts.
- Include focused controls for true provider/transport failure and explicit
  cancellation so they remain `failed` and `interrupted`, respectively.
- Run requested non-E2E checks. E2E is opt-in under `AGENTS.md`; ask before any
  mocked/offline E2E or live DVWA/provider validation. The prior full matrix
  authorizes no new matrix for this separate status change.
- Run `git diff --check`; record test commands/results and artifact paths in the
  completion handoff. Do not claim a live research outcome from offline tests.

## Completion criteria

This handoff can move to `docs/completed/` only after the new status contract is
implemented across runtime and reporting, the DOCX and reference docs agree,
focused acceptance controls pass, and historical artifact compatibility is
demonstrated. Preserve all prior experiment artifacts and source hashes.

## Implementation and acceptance record (2026-10-12)

- Added typed `execution_status`, `security_outcome`, and structured reasons to
  shared state and checkpoint persistence. `core/run_status.py` owns validation,
  proof-based classification, legacy mapping, and matrix terminal status.
- Normal terminal execution without confirmation now retains a completed
  lifecycle. Provider/activity, target request/transport, unexpected runtime,
  resume, and primary artifact failures remain failed. Explicit cancellation
  remains interrupted; partial method evidence is retained.
- Propagated canonical fields through primary/failure/rich artifacts, score
  reports and review receipts, matrix children and aggregate/group counts,
  manifests, journals/descriptors, CLI reports, and TUI rows/details. Execution
  indicators and security outcomes are separate. Unknown historical lifecycle
  is shown as unknown, including historical incomplete events without enough
  evidence. Skipped coordinates remain unstarted and outside executed coverage.
- The candidate proof gates, verifier thresholds, scoring formula, eligibility,
  independent human/AI workflows, and final-score pending gates are unchanged.
  Legacy `status`, `task_result`, and `incomplete_reason` remain compatibility
  aliases as documented in both localized summaries and the architecture.
- Updated the English and Indonesian summaries and `thesis_scoring.md`. Added
  separate execution/outcome tables to the thesis DOCX; all added text is dark
  blue (`17365D`). Original body content, formatting, section properties, and
  other ZIP members were preserved.

### Initial focused non-E2E controls

The initial acceptance command was:

```bash
.venv/bin/python -m pytest -q tests/test_execution_security_status.py tests/test_evaluation_runner.py tests/test_scorer.py tests/test_chaining_coordinator_terminal_success.py tests/test_orchestrator.py tests/test_orchestrator_method_selection.py tests/test_evaluation_multi_llm_runner.py tests/test_headless.py tests/test_artifact_layout.py tests/test_live_runtime.py tests/test_runtime_journal.py tests/test_reporting_telemetry.py tests/test_evaluation_metrics.py tests/test_nullable_metrics_regression.py tests/test_scoring_v4_matrix_driver.py --tb=short --junitxml=results/validation/execution-security-status-2026-10-12/junit.xml
```

Result: **162 passed**. Evidence:
[`junit.xml`](../../results/validation/execution-security-status-2026-10-12/junit.xml).
The graph/provider/target boundaries in runner and launcher controls are stubs;
these are unit/adapter controls, not a framework E2E or live experiment.

Controls cover all 12 execution/outcome combinations, genuine provider and
transport failure, interruption, serialized fields, matrix counts, reports,
TUI state and distinct result cells, journal/descriptor/manifest propagation,
checkpoint sanitization, and backward reads. Scoring controls distinguish zero
negative proof from missing proof, retain supported partial visibility with a
pending review when its permission oracle is absent, and demonstrate
`(3,0,0,0,3) -> Srun_final=1.2000` only after required components are complete.
That finalization unit supplies the unrelated component queue contract; it does
not establish live ranking or oracle acceptance.

### Historical compatibility and artifact preservation

The initial read-only compatibility pass inspected the preserved epoch7 manifest
and 108 primary artifacts using the reader at that implementation epoch. All 108 map to completed
execution with their original source hashes preserved. The derived security
view contains 57 confirmed, 10 no_finding, 9 unconfirmed, and 32 fixture_limited.
These are reader classifications, not a new experiment or a replacement for
historical verifier decisions, audits, score receipts, or `SUCCESS`/`INCOMPLETE`
labels. No historical artifact or receipt was rewritten or rescored.

Evidence:
[`historical-compatibility.json`](../../results/validation/execution-security-status-2026-10-12/historical-compatibility.json).
The manifest itself was also checked unchanged. Ambiguous legacy errors without
normal terminal/provider/request evidence retain null execution status; the
unit controls prove they are not counted or presented as new execution failures.

### DOCX acceptance and limits

Source SHA-256: `478ce522ac8e28085000fc419020c40969f1d785f2f65cb8939b073f0ea3474e`.
Edited SHA-256: `75dd6e877c504e2d7ce37ad8f74df54d0e198463f32b08b8111b00400c50e7d1`.
Two added tables and all added text passed XML/package/format preservation and
dark-blue checks. Evidence:
[`docx-validation.json`](../../results/validation/execution-security-status-2026-10-12/docx-validation.json).
Rendered pagination and appearance remain unverified; the older Word visual
inspection applies only to the prior DOCX hash.

`git diff --check` passed. The acceptance record and source hashes are saved in
[`acceptance.json`](../../results/validation/execution-security-status-2026-10-12/acceptance.json).
E2E coverage was declined in favor of non-E2E controls. The later TokenHarbor
permission was recorded, but no provider call, live DVWA execution, or new matrix
was performed. Offline controls and backward reads establish the status
contract only; they do not establish a new live security or thesis result.


## Review corrections and current acceptance (2026-10-12)

Resolved all four static review findings:

1. Method setup exceptions now carry `execution_status=failed` and an explicit
   `execution_reason` through the shared update helper, including paths that
   produce no response evidence. All nine method exception handlers preserve
   the caught error type; explicit login rejection records `SESSION_LOGIN_FAILED`.
   Transport errors retain `TARGET_TRANSPORT_FAILURE`; other caught method
   exceptions use `METHOD_EXECUTION_FAILURE`. The runner retains these details
   in primary and failure artifacts. Controlled stops using `failure_agents`
   remain distinct from exceptions.
2. Security classification includes complementary evidence owned through
   `source_candidate_id`. It passes the same linked references to the existing
   proof gates, preserving supported Boolean confirmation. Controls owned by
   another candidate/visit or missing verifier links do not supply confirmation.
3. An executed candidate recorded in `tried_payloads` without response evidence
   adds an unknown assessment and prevents `no_finding`. An unexecuted candidate
   remains outside the assessed set. No verifier threshold or score ceiling changed.
4. `run.cancelled`, `matrix.cancelled`, and `run.cancellation` apply canonical
   terminal metadata and refresh the evidence region. Early cancellation notices
   retain existing security evidence; matrix child cancellation does not
   terminalize the parent. The launcher terminal event supplies the final outcome.

Current focused command:

```bash
.venv/bin/python -m pytest -q tests/test_execution_status_review_regressions.py tests/test_execution_security_status.py tests/test_evaluation_runner.py tests/test_state_utils.py tests/test_scorer.py tests/test_chaining_coordinator_terminal_success.py tests/test_headless.py tests/test_evaluation_multi_llm_runner.py tests/test_sqli_union_agent.py tests/test_sqli_error_agent.py tests/test_sqli_boolean_blind_agent.py tests/test_sqli_time_blind_agent.py tests/test_ac_idor_agent.py tests/test_ac_force_browse_agent.py tests/test_ac_vertical_escalation_agent.py tests/test_bf_dictionary_agent.py tests/test_bf_spray_agent.py --tb=short --junitxml=results/validation/execution-security-status-2026-10-12-review/junit.xml
```

Result: **192 passed**. The new controls use setup-only session stubs, metadata
snapshots, an isolated runner boundary, and pure TUI events. No framework E2E,
live DVWA request, or provider call was executed. Existing non-E2E method/unit
controls were rerun for the error-handler metadata changes.

Evidence:
[`junit.xml`](../../results/validation/execution-security-status-2026-10-12-review/junit.xml),
[`acceptance.json`](../../results/validation/execution-security-status-2026-10-12-review/acceptance.json).
`git diff --check` passed; existing staged changes were preserved.

A fresh read-only pass against the same 108 historical primary artifacts again
preserved every source hash. The current derived view remains 108 completed
executions: 57 confirmed, 10 no_finding, 9 unconfirmed, and 32 fixture_limited.
The prior compatibility report was retained, with current evidence saved in
[`historical-compatibility.json`](../../results/validation/execution-security-status-2026-10-12-review/historical-compatibility.json).
This pass does not replace historical verifier decisions, receipts, or results.
The DOCX was unchanged by these corrections, so its valid structural/package
checks were reused. Its rendered appearance remains unverified.
