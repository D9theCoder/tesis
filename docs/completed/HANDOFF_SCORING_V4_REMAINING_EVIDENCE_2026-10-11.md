# Handoff: remaining scoring.v4 evidence and attribution

Status: **completed, 2026-10-11.** Required evidence accounting and offline
capture/replay acceptance passed. The permitted unresolved causes, null scores,
deferred AI decisions and fixture/replay limits remain explicit. This continues the [scope-limited closed
handoff](../completed/HANDOFF_SCORING_V4_RANKING_ORACLE_ACCEPTANCE_2026-10-10.md).
Keep its 108-run matrix, 49-run diagnostic retry, and source hashes separate.
The [60 incomplete v2 runs](../upcoming/HANDOFF_MATRIX_60_INCOMPLETE_ERRORS_V2_2026-10-11.md)
are an earlier cohort and have their own investigation.

Actual repair and prevention work is tracked separately in the
[defect remediation handoff](../upcoming/HANDOFF_SCORING_V4_DEFECT_REMEDIATION_2026-10-11.md).

## Remaining work

Failure modes declared before the audit implementation: stale initial review
sidecars hide later diagnostic receipts; a receipt joins by run ID despite a
different execution hash; a missing receipt becomes a zero; probes enter the
payload denominator; a pending or unassessable grade becomes numeric; source
artifacts change during auditing; candidate evidence references do not resolve;
aggregate status assigns model blame; unmatched controls imply fixture ground
truth; reconstructed probes masquerade as historical snapshots. The audit must
fail on invalid joins and preserve legitimate nulls, separate review modes,
and bounded attribution. Existing offline graph controls will validate future
capture and replay in a fresh epoch; they cannot establish live target behavior.

| Task | Required result |
| --- | --- |
| Attribute 46 incomplete retries | For each of the 46, record source hash, coordinate, candidate origin and validation, actual requests/responses, verifier decision, available matched controls or why they are unavailable, and a supported cause or `insufficient_evidence`. Reproduce suspected code defects with the same saved inputs and zero provider calls; fix only proven defects. Keep ineffective executed model candidates as negative results. Do not relax verification to improve success counts. [Retry aggregate](../../results/validation/scoring-v4-completion-2026-10-11/matrix/retry-failed-coordinates-epoch1/matrix-aggregate.json) · [Verification](../../results/validation/scoring-v4-completion-2026-10-11/matrix/retry-failed-coordinates-epoch1/retry-verification.json) |
| Account for 18 null AI scores | Audit all 108 source-to-receipt joins. Classify the 18 null sources individually: 8 with no eligible candidate, 7 `not_assessable`, and 3 pending decisions. Correct a missing or mislinked receipt only with source-bound evidence. Keep legitimate nulls and their denominators explicit; never synthesize zero or `Srun_final`. [Closure counts](../../results/validation/scoring-v4-completion-2026-10-11/handoff-closure.json) · [Scoring rules](../reference/thesis_scoring.md) |
| Resolve or defer three AI decisions | The owner waived these for the closed handoff. If numeric coverage is later required, repair the review service's JSON handling, retain raw responses, and retry only the three hash-bound candidates listed in [completion status](../../results/validation/scoring-v4-completion-2026-10-11/completion-status.json). Until valid decisions exist, report them as pending; do not substitute Human scores for AI scores. |
| Disposition original-nine replay | Search immutable source traces for the missing probe snapshots and full request method, path, query/body, and session context. If absent, document exact replay as irrecoverable and keep the 9 catalog-reconstructed replays labeled diagnostic. Verify forward capture and zero-provider replay on a new, complete input epoch. [Original-nine manifest](../../results/validation/scoring-v4-completion-2026-10-11/replay/original-nine-manifest.json) |
| Bind Access Control fixture | Pin the deployed DVWA source/version for `/security.php` or retain the declared-policy limitation. The observed authenticated non-admin allow and anonymous deny controls do not establish a role restriction. Use candidate-bound controls for the same action before claiming unauthorized access. [Permission controls](../../results/validation/scoring-v4-completion-2026-10-11/matrix/retry-failed-coordinates-epoch1/ac-security-php-policy-controls-20261011T060228Z-5bfd23d4/summary.json) |

## Acceptance

- [x] A source-hash-bound ledger covers 46/46 retry outcomes, distinguishing code,
  fixture, provider/parser, transport, verifier/scorer, evidence, and executed-payload causes. Unresolved cases say
  `insufficient_evidence`; no outcome is assigned to the model from aggregate status.
- [x] Every code repair has before/after saved-input replay and matched controls.
  The original 108-run matrix and 49-run retry remain immutable and are not merged.
- [x] A 108-row scoring coverage ledger accounts for all 18 nulls, with the three
  deferred AI decisions explicit and Human/AI receipts separate.
- [x] The original-nine limitation is resolved by recovered exact inputs or a
  documented irrecoverable finding; a new complete-input replay validates future
  capture without standing in for historical proof.
- [x] Access Control claims use a version-bound permission oracle, or retain the
  limitation. Update the [closed handoff](../completed/HANDOFF_SCORING_V4_RANKING_ORACLE_ACCEPTANCE_2026-10-10.md)
  with the resulting evidence and move this handoff to `docs/completed/` only
  when these checks pass.

Start with targeted saved-input replay. Any live model rerun is limited to
unresolved coordinates, authorized DVWA, and `openai_compatible`; keep it in a
separate diagnostic epoch under `results/`. Preserve candidate provenance,
containment, and the original status of every frozen run.

## Measured evidence

The [read-only auditor](../../evaluation/remaining_evidence.py) follows the
recorded initial review and three retry rounds. It validates source and receipt
identity, candidate citations, distinct eligible denominators, decision history,
component vectors and the fixed score formula. It hashes every input and checks
the hashes again before publishing a separate derived epoch. It makes no target
or provider calls and cannot execute payloads or finalize reviews.

| Requirement | Observed result and evidence |
| --- | --- |
| 46 retry outcomes | [Attribution ledger](../../results/validation/scoring-v4-remaining-evidence-2026-10-11/audit-epoch2/retry-attribution.json): 46 rows with primary and retry source hashes, coordinates, candidate origin/provenance/validation, response references, actual transport references, verifier decisions, controls or their absence, and seven cause axes. Four link to the earlier probe-gate repair as a supported contributor; 42 retain `insufficient_evidence` for causal attribution. |
| Preserve negative model candidates | 34 generated candidates executed with negative or partial results; 12 generated candidates did not execute. The former remain negative/partial observations, and the latter cannot support model-quality attribution. Three additional probe responses lack candidate IDs and remain explicit evidence gaps. |
| Existing repair evidence | The four historical SQLi Error replays bind to the same saved queue values, order and provenance. Each baseline has zero exploit responses and each replay has one; two confirm and two do not. The ledger links the immutable replay summaries and decisions. Existing positive/negative graph controls remain in `tests/test_method_agents_e2e.py`. This work introduces no method, verifier, scoring-rule or provider/parser repair. |
| 108 scoring joins and 18 nulls | [Coverage ledger](../../results/validation/scoring-v4-remaining-evidence-2026-10-11/audit-epoch2/scoring-coverage.json): 108 rows, 90 numeric AI receipts, 8 sources without eligible candidates, 7 not assessable, and 3 pending. Each row retains its eligible and assessed denominators, separate receipt identity and original status. Null `Spayload_final` and `Srun_final` remain null. No Human receipt is used. |
| Three AI decisions | Each pending source and candidate matches `completion-status.json`. The ledger hashes the telemetry from all four review rounds and independently counts eight `JSONDecodeError` abstentions per candidate. These decisions are deferred. Failed historical attempts retain error types and prompt hashes without raw responses, which limits provider/parser attribution. No retry or substitute score is created. |
| Original nine | [Disposition ledger](../../results/validation/scoring-v4-remaining-evidence-2026-10-11/audit-epoch2/original-nine-disposition.json): all nine execution, rich, event and failure traces were searched and hashed. Probe seed definitions are recoverable in original prompt inputs and their values/provenance match the catalog reconstruction. The validated execution-stage snapshots and complete request/session shapes remain absent. Exact historical replay is irrecoverable from the retained sources; the nine catalog replays remain diagnostic. |
| Future input capture | [Forward ledger](../../results/validation/scoring-v4-remaining-evidence-2026-10-11/audit-epoch2/forward-capture.json): a new input epoch covers all nine methods, with saved validated probe controls, exploit queues, request/session structures and unchanged candidate values/order. Replay makes zero provider calls. These are explicitly `offline_synthetic_fixture` controls; redacted synthetic credentials/session values and mocked HTTP do not establish live or historical acceptance. The full suite also exercises capture across both conditions and all three security levels, plus ten rejection cases. |
| Access Control | The existing candidate-bound `/security.php` controls are hash-checked against their six source bindings. The declared policy allows authenticated non-admin sessions and denies anonymous sessions. The deployed source/version remains unpinned; a role restriction and unauthorized role access are not established. This limitation is retained and frozen scores are not rewritten. |

The [audit summary](../../results/validation/scoring-v4-remaining-evidence-2026-10-11/audit-epoch2/summary.json)
binds 629 input hashes, including the auditor, control tests and scoring code.
The original 108-run matrix and 49-run retry remain separate and immutable.
`audit-epoch1` is an intermediate audit and is superseded by `audit-epoch2`,
which adds prompt seed recovery, saved probe provenance and unattributed-response
accounting. The authoritative ledgers are the epoch-2 files above.

## Repeatable validation

Run from the repository root:

```bash
.venv/bin/python -m pytest -q tests/test_remaining_evidence_audit_e2e.py --junitxml=results/validation/scoring-v4-remaining-evidence-2026-10-11/audit-e2e-retry.xml
.venv/bin/python -m evaluation.remaining_evidence --source-root results/validation/scoring-v4-completion-2026-10-11 --forward-manifest results/validation/scoring-v4-remaining-evidence-2026-10-11/forward-input-manifest.json --output-dir results/validation/scoring-v4-remaining-evidence-2026-10-11/audit-repeat
.venv/bin/python -m pytest -q --junitxml=results/validation/scoring-v4-remaining-evidence-2026-10-11/full-suite-final.xml
```

The focused controls produced 17 passes, including seven corrupt-join controls
and nine fresh capture/replay controls. The audit command requires a new output
directory, so an existing epoch cannot be replaced. Its expected result is
46 retry rows, 108 scoring rows, nine forward controls, zero provider calls and
zero live HTTP calls. The saved forward manifest pins the exact control paths
and remains usable when later test runs produce additional control artifacts.

JUnit output uses this separate evidence epoch to preserve the earlier immutable
`results/validation/junit.xml` referenced by the closed handoff. Offline results
do not stand in for new live DVWA/provider experiments. No new live experiment
was needed to account for the evidence and retain the permitted limitations.

The final [JUnit receipt](../../results/validation/scoring-v4-remaining-evidence-2026-10-11/full-suite-final.xml)
records **1,940 passed, zero failures/errors/skips** on the final auditor code.
The [acceptance receipt](../../results/validation/scoring-v4-remaining-evidence-2026-10-11/acceptance.json)
records the commands, expected/observed results, artifact hashes, all five gates
and retained limitations. Use fresh output and JUnit paths for later repetitions
so these accepted receipts remain unchanged. Generated evidence is under the
gitignored `results/` tree; a fresh checkout must regenerate the offline control
artifacts, and the historical audit also requires the retained frozen source
cohorts and review rounds.
