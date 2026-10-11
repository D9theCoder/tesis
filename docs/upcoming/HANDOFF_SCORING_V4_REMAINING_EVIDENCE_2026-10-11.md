# Handoff: remaining scoring.v4 evidence and attribution

Status: **upcoming, 2026-10-11.** This continues the [scope-limited closed
handoff](../completed/HANDOFF_SCORING_V4_RANKING_ORACLE_ACCEPTANCE_2026-10-10.md).
Keep its 108-run matrix, 49-run diagnostic retry, and source hashes separate.
The [60 incomplete v2 runs](HANDOFF_MATRIX_60_INCOMPLETE_ERRORS_V2_2026-10-11.md)
are an earlier cohort and have their own investigation.

## Remaining work

| Task | Required result |
| --- | --- |
| Attribute 46 incomplete retries | For each of the 46, record source hash, coordinate, candidate origin and validation, actual requests/responses, verifier decision, available matched controls or why they are unavailable, and a supported cause or `insufficient_evidence`. Reproduce suspected code defects with the same saved inputs and zero provider calls; fix only proven defects. Keep ineffective executed model candidates as negative results. Do not relax verification to improve success counts. [Retry aggregate](../../results/validation/scoring-v4-completion-2026-10-11/matrix/retry-failed-coordinates-epoch1/matrix-aggregate.json) · [Verification](../../results/validation/scoring-v4-completion-2026-10-11/matrix/retry-failed-coordinates-epoch1/retry-verification.json) |
| Account for 18 null AI scores | Audit all 108 source-to-receipt joins. Classify the 18 null sources individually: 8 with no eligible candidate, 7 `not_assessable`, and 3 pending decisions. Correct a missing or mislinked receipt only with source-bound evidence. Keep legitimate nulls and their denominators explicit; never synthesize zero or `Srun_final`. [Closure counts](../../results/validation/scoring-v4-completion-2026-10-11/handoff-closure.json) · [Scoring rules](../reference/thesis_scoring.md) |
| Resolve or defer three AI decisions | The owner waived these for the closed handoff. If numeric coverage is later required, repair the review service's JSON handling, retain raw responses, and retry only the three hash-bound candidates listed in [completion status](../../results/validation/scoring-v4-completion-2026-10-11/completion-status.json). Until valid decisions exist, report them as pending; do not substitute Human scores for AI scores. |
| Disposition original-nine replay | Search immutable source traces for the missing probe snapshots and full request method, path, query/body, and session context. If absent, document exact replay as irrecoverable and keep the 9 catalog-reconstructed replays labeled diagnostic. Verify forward capture and zero-provider replay on a new, complete input epoch. [Original-nine manifest](../../results/validation/scoring-v4-completion-2026-10-11/replay/original-nine-manifest.json) |
| Bind Access Control fixture | Pin the deployed DVWA source/version for `/security.php` or retain the declared-policy limitation. The observed authenticated non-admin allow and anonymous deny controls do not establish a role restriction. Use candidate-bound controls for the same action before claiming unauthorized access. [Permission controls](../../results/validation/scoring-v4-completion-2026-10-11/matrix/retry-failed-coordinates-epoch1/ac-security-php-policy-controls-20261011T060228Z-5bfd23d4/summary.json) |

## Acceptance

- [ ] A source-hash-bound ledger covers 46/46 retry outcomes, distinguishing code,
  fixture, provider/parser, transport, verifier/scorer, evidence, and executed-payload causes. Unresolved cases say
  `insufficient_evidence`; no outcome is assigned to the model from aggregate status.
- [ ] Every code repair has before/after saved-input replay and matched controls.
  The original 108-run matrix and 49-run retry remain immutable and are not merged.
- [ ] A 108-row scoring coverage ledger accounts for all 18 nulls, with the three
  deferred AI decisions explicit and Human/AI receipts separate.
- [ ] The original-nine limitation is resolved by recovered exact inputs or a
  documented irrecoverable finding; a new complete-input replay validates future
  capture without standing in for historical proof.
- [ ] Access Control claims use a version-bound permission oracle, or retain the
  limitation. Update the [closed handoff](../completed/HANDOFF_SCORING_V4_RANKING_ORACLE_ACCEPTANCE_2026-10-10.md)
  with the resulting evidence and move this handoff to `docs/completed/` only
  when these checks pass.

Start with targeted saved-input replay. Any live model rerun is limited to
unresolved coordinates, authorized DVWA, and `openai_compatible`; keep it in a
separate diagnostic epoch under `results/`. Preserve candidate provenance,
containment, and the original status of every frozen run.
