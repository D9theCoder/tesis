# Handoff: Separate execution status from security outcome

Status: **upcoming**. Drafted 2026-10-12. Implementation and acceptance have not started.

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

## Current behavior and baseline

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
