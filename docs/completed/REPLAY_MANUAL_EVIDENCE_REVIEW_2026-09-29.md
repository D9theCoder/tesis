# Replay manual-evidence export review

Status: completed. The four regression controls failed before the repair and
pass afterward. The full offline suite passes 1,602 tests with two existing
inapplicable skips. These checks use mocked external transport and providers;
no live DVWA or provider experiment was required for this export defect.

## Defect and repair

A later frozen snapshot retains earlier candidate provenance and scores in
`final_state`, including a UNION exploit with score 3. Replay top-level response
and timing arrays contain only fresh evidence. The manual export previously
included historical candidates without response references or verifier decisions.
The defect also appeared on same-method revisits and rejected replay queues.

`manual_scoring_rows()` now restricts diagnostic replay rows to candidates with
fresh response-evidence links. Historical scores, provenance, and accumulated
evidence remain in final state and the linked source artifact. Ordinary run
exports still retain all candidate rows, including unexecuted null-score entries.
Replay declares `manual_scoring_scope: fresh_replay_execution` and includes the
export helper in executing-code hashes. Rejected queues export an empty sheet.

The existing graph/revisit control now checks both later-method and same-method
snapshots with accepted and rejected queues. It checks fresh candidate links,
verifier decisions, stored/recomputed sheet agreement, inherited score retention,
source/input immutability, and zero new provider calls. Rejected queues make no
fresh HTTP requests. Each replay also writes an offline fixture receipt.

## Repeatable checks and evidence

Run from the repository root:

```bash
.venv/bin/python -m pytest -q tests/test_method_agents_e2e.py -k revisited_replay_preserves_saved_order_and_accumulated_state --junitxml=results/validation/replay-manual-evidence-2026-09-29/baseline-junit.xml
.venv/bin/python -m pytest -q tests/test_method_agents_e2e.py tests/test_manual_scoring_evidence.py --junitxml=results/validation/replay-manual-evidence-2026-09-29/focused-junit.xml
.venv/bin/python -m pytest -q tests --junitxml=results/validation/junit.xml
```

The first command was recorded before the production repair: four failures at
the fresh-row assertion. After repair, the focused suites pass 289 tests with
two skips; the full suite passes 1,602 with two skips. The skips are the existing
medium SQLi controls for a high-only session-input flow. `git diff --check` passes.

Evidence root: `results/validation/replay-manual-evidence-2026-09-29/`.
It contains the failure inventory, baseline/focused/full JUnit receipts, and
`saved-export-audit.json`. That audit links four preserved failing diagnostic
artifacts to separate corrected exports under `saved-export-corrections/`.
Matched saved sheets change from 11/12 rows to 3/2 fresh rows for executable
snapshots, and to zero rows for rejected snapshots. Final state, raw evidence,
scores, verifier decisions, and original diagnostic files are unchanged.
The saved-export corrections make zero HTTP requests and zero provider calls.

This follow-up changes diagnostic export scope. It does not rerun or replace
the original 297-coordinate matrix or change its method outcomes.
