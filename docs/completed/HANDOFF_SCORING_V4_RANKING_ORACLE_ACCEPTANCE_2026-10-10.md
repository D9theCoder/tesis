# Handoff: scoring.v4 ranking, oracle, and matrix acceptance

Status: **closed 2026-10-11 by owner direction, AI-only and scope-limited.**
The three unresolved AI candidate decisions were waived. This closes the requested
handoff; it does not claim a final score for every matrix source. Existing run,
review, and completion artifacts remain immutable.

| Workstream | Result |
| --- | --- |
| Ranking | Replacement profile frozen: 9 scenarios, 27 references, 0 pending. Historical profile unchanged. [Profile](../../results/validation/scoring-v4-completion-2026-10-11/ranking/epoch2/ranking-profile-complete.json) |
| Matrix and transport | 108/108 coordinates; 59 success, 49 error. Independent transport audit covers all 108, with 5,059 DVWA requests and no containment failures. [Matrix](../../results/validation/scoring-v4-completion-2026-10-11/matrix/matrix-end.json) · [Audit](../../results/validation/scoring-v4-completion-2026-10-11/matrix/transport-summary.json) |
| Failed-coordinate retry | Separate diagnostic epoch retried 49/49 errors: 3 success, 46 still incomplete. Retries do not replace primary results. [Verification](../../results/validation/scoring-v4-completion-2026-10-11/matrix/retry-failed-coordinates-epoch1/retry-verification.json) |
| Access Control and causal proof | Paired `/security.php` controls support the declared authenticated-only policy; deployed DVWA version is unpinned. `bf_dictionary` evidence was consumed by confirmed `ac_force_browse` and `ac_idor` outcomes. AI `Spayload=4`, automatic `Sexploit=4`, destination `Schain=3`; `Soutput` remains separate. [Causal evidence](../../results/validation/scoring-v4-completion-2026-10-11/causal/epoch4/causal-summary.json) · [Permission controls](../../results/validation/scoring-v4-completion-2026-10-11/matrix/retry-failed-coordinates-epoch1/ac-security-php-policy-controls-20261011T060228Z-5bfd23d4/summary.json) |
| SQLi replay | The [SQLi Error agent](../../agents/sqli/sqli_error_agent.py) now proceeds to validated exploit candidates when probes return HTTP 200 without a recognized database error. Four saved-input replays passed login and executed probes plus exploit with zero provider calls: 2 confirmed, 2 not confirmed. [Replay](../../results/validation/scoring-v4-completion-2026-10-11/matrix/retry-failed-coordinates-epoch1/code-fix-replay-sqli-error-high/session-recovery-replay-20261011T055922Z-02287ae8/summary.json) |
| Original nine mutation-only inputs | Replayed 9/9 with zero provider calls using the pinned historical payload catalog. Original probe snapshots and full request shapes were absent, so these are reconstructed replays, not exact historical replays. [Manifest](../../results/validation/scoring-v4-completion-2026-10-11/replay/original-nine-manifest.json) |
| AI-only scoring | 105/108 candidate workflows finalized; 3 remain pending after JSON decode failures and were waived by the owner. Only 90/108 sources have final numeric AI receipts; 18 remain null (8 no eligible candidate, 7 not assessable, 3 pending). No Human receipts were used. |
| Offline validation | 1,921 tests passed, 0 failures/errors/skips. [JUnit](../../results/validation/junit.xml) |

The source [completion status](../../results/validation/scoring-v4-completion-2026-10-11/completion-status.json)
remains immutable. The separate [handoff-closure.json](../../results/validation/scoring-v4-completion-2026-10-11/handoff-closure.json)
binds the owner waiver to its hash and preserves the scoring and replay limits.
Do not infer missing scores or attribute the 46 incomplete retries to the model
without additional evidence.

Earlier implementation and runtime handoffs: [scoring.v4 implementation](HANDOFF_SCORING_EVIDENCE_AND_RUBRIC_COMPLETION_2026-10-01.md) · [TUI and matrix runtime](HANDOFF_TUI_MODEL_CONNECTION_AND_MATRIX_RUNTIME_2026-10-10.md). The [remaining v4 evidence](../upcoming/HANDOFF_SCORING_V4_REMAINING_EVIDENCE_2026-10-11.md) and [older v2 incomplete runs](../upcoming/HANDOFF_MATRIX_60_INCOMPLETE_ERRORS_V2_2026-10-11.md) have separate upcoming handoffs.
