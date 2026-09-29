# Post-review method-agent matrix and failure attribution

Status: completed. All 297 declared coordinates finished at three fresh repeats,
the final offline suite passes 1,600 tests with two inapplicable skips, and the
artifact, transport, replay, source, queue and fixture audits pass. Three further
code/evidence defects were found and repaired. The final study audit passes all
355 checks. No new commit or push was performed.

A [follow-up export review](REPLAY_MANUAL_EVIDENCE_REVIEW_2026-09-29.md) limits
diagnostic manual sheets to fresh response-backed rows. The matrix observations
below retain their original code epoch and outcomes.

Evidence root: `results/validation/method-agents-post-review-2026-09-29/`.
Most accepted evidence is under `accepted/`. The
[earlier report](METHOD_AGENTS_TESTING_REPORT_2026-09-29.md) retains its pre-review
live dataset. The six review fixes have separate offline acceptance under
`results/validation/review-fixes-2026-09-29/`.

## Observed results

| Declared phase | Coordinates | Supported positives confirmed | Unverified fixture | Model calls |
| --- | ---: | ---: | ---: | ---: |
| Forced static controls | 81 | 51 | 30 | 0 |
| Forced-method hybrid, both conditions | 162 | 102 | 60 | 162 |
| Automatic hybrid, both conditions | 54 | 36 | 18 | 366 |
| Total | 297 | 189 | 108 | 528 |

All 99 cells retain R=3. The supported reference outcomes agree with every
static control. Nine access-control method/level combinations lack a non-admin
permission oracle, and high-level error SQLi suppresses extraction errors.
These ten combinations remain explicit unverified outcomes. The runner records
189 successful and 108 incomplete/error coordinates; one access-control
coordinate includes a provider timeout. Four failed role calls are retained
within their actual coordinates, including successful runs using other evidence.

The matrix records 437 method visits: 260 confirmed, 131 not confirmed, and 46
unverified decisions. Nineteen visits have no new method response. Current
negative decisions remain separate from accumulated confirmations and maximum
scores. Automatic surface outcomes use supported confirmations across methods;
the final selected method and its own scores remain visible even when it is an
unverified high-level error method.

The original candidate history contains 338 generated candidates: 286 retained
by validation/ranking, 23 rejected, and 29 excluded by ranking whose original
receipt was omitted. Only 42 generated candidates executed in the main runs.
The other candidates provide no observed effectiveness evidence. Seed-driven
success does not establish generated-payload quality.

## Model output versus code

The 187 saved generated-queue comparisons select saved probe controls and
saved generated exploits, exclude unselected seed exploits, and make zero new
model calls. The initial decisions are 68 confirmed and 119 not confirmed.
After the matched error-response repair, the linked final interpretation is
69 confirmed and 118 not confirmed. Original replay artifacts remain intact.

| Generated replay mechanism | Comparisons | Interpretation |
| --- | ---: | --- |
| Generated exploit supported | 68 | Confirmed from the selected saved generated input |
| Error response recognition defect, repaired | 1 | Valid database leak missed by the method code |
| Supplied parent also ineffective | 48 | Model-only blame unsupported; quoted medium seeds or partial ordinary-row results also fail |
| Ineffective generated input with working parent | 2 | Fixed-task mutation/transport result; no general model ranking |
| One repeatable Boolean predicate | 20 | Partial evidence; low/high require two distinct predicates |
| Conditional sleep branch not entered | 3 | Correct negative timing confirmation; one high response also contains fixture delay noise |
| Credential/strategy representation interaction | 44 | Leading credential pair fails; ordering/pacing prose is not executed |
| Literal encoding/transport interaction | 1 | Percent-encoded SQL characters remain literal in form/session values |

The negative-parent comparisons link 100 child observations to 21 distinct
saved parent controls. They are finite deduplicated diagnostics rather than new
R=3 model experiments. Parent extraction uses verifier decisions or repeatable
Boolean evidence: a successful HTTP transaction alone is insufficient.

Twenty independent conditional timing controls, with two observations each,
cover 32 generated replay links. Each replaces only the visible bounded
`SLEEP(number)` result with literal `1` in a separate request. Every confirmed
conditional replay has a proven delay branch. The high candidate with threshold
114 produces one 3.7-second signal followed by a fast response and does not
confirm; its branch controls are both false. The pinned high blind source can
randomly sleep on missing IDs. This supports fixture noise as the slow-response
mechanism, rather than crediting that observation to the generated sleep.

Some generic medium seeds retain quotes even though the deployed medium SQL
uses an unquoted numeric expression and escapes quotes. Their saved parents
also fail. UNION `LIMIT 1` parents can return the ordinary original account row
without extracting the UNION credential row. Neither result establishes a
method-verification defect or uniquely weak model output. Boolean low/high
comparisons with a single generated variant also cannot satisfy the declared
two-predicate confirmation policy.

Four role failures are separately attributed: two returned-output schema
violations (unknown source seed and disallowed mutation type), one native
response-mode mismatch (plain JSON plus commentary when a native object was
required), and one provider transport timeout with no model response. Complete
JSON text responses are handled by the existing same-response compatibility
path. The native mismatch cannot be assigned uniquely to the underlying model
or gateway with the available metadata.

The 23 original candidate rejection receipts contain 16 duplicates, five invalid
leading credential pairs, and two scope rejections. Duplicating a seed does not
prove weak exploit generation. One relative path rejection is a conservative
containment-normalization boundary. Rejected candidate instances never execute;
a duplicate may share bytes with an independently accepted static seed.

All investigated replay mechanisms have evidence-supported classifications.
Exact suppressed database errors, intended strategy semantics, non-admin
permissions, gateway response handling, sampling defaults, underlying model
revision, and timeout location remain bounded uncertainties. The detailed
[attribution ledger](../../results/validation/method-agents-post-review-2026-09-29/accepted/failure-attribution-ledger.json)
retains confidence, source hashes, parent/branch/repair links and next controls.

## Repairs and preserved code epochs

The starting commit is `2a5d38fed974d8a56e651d54dd1d548723c85daf` with the
existing uncommitted review repairs. All baselines, failures and source epochs
are retained.

1. **Shared bounded SLEEP parser.** Removing block comments joined `AND` and
   `SLEEP`, causing a real 2.782-second high static candidate to receive a zero
   bound. It could also miss an oversized commented sleep during validation.
   Six graph controls failed before correction and pass after comments retain
   token separation. The oversized value is tested only with controlled
   transport and is rejected before any live request. The initial static grid
   and matched corrected replay remain under the evidence root; a fresh accepted
   static grid precedes all model coordinates.
2. **Error SQLi response recognition.** Generated medium replay `105-0.json`
   returns `<pre>Duplicate entry 'dvwa1' for key 'group_key'</pre>` and leaks the
   independently established database name. The method originally records
   score 1 and no confirmation. Six positive graph cases fail before correction;
   twelve negative guards already pass. One added response pattern recognizes
   the complete standard DVWA envelope for either counter bit. All eighteen
   graph cases pass. Replaying all 51 saved error-method visits and 24 generated
   error queues changes exactly the one affected generated decision. Every
   corrected replay has matching physical transport and zero provider calls.
3. **Budget exclusion receipts.** The shared validator checked valid candidates
   then omitted those removed by ranking. Two graph cases reproduce missing
   medium/high receipts; the low-level capacity guard passes. Recording
   `candidate_budget_exceeded` makes all three pass. All 437 saved executable
   queues remain unchanged. Twenty-nine linked post-execution validation
   diagnostics recover the missing reasons without HTTP/model calls; original
   artifacts and null manual scores are preserved.

The 297 main coordinates use `accepted/code-identity.json`, after the parser
repair. Later error recognition is evaluated by matched saved-input replay under
`duplicate-correction/`. The final receipt-only repair is frozen under
`budget-correction/`; its full suite and all three dry runs pass. Relative to the
main epoch, only the error agent, shared validator, and graph control test file
change among the 142 pinned source files. Model prompts, selection logic, score
weights, static AKG and target configuration retain their recorded identities.

## Scores and experiment identity

Both model roles use only `openai_compatible`, requesting
`deepseek-v4.1-flash`; all 527 returned SDK responses report that alias and one
call times out. The installed environment and source hashes are in
`environment-identity-final.json`. Requests use 8,192 maximum completion tokens
and reasoning effort `low`, concurrency 1, no application cache, no retries,
and no checkpoint resume. Requests and fresh DVWA sessions are serialized.
Repository `config.yaml` is unchanged; protected private configs retain the
credentials and sanitized configs retain reviewable experiment settings.

Local role temperature is configured as zero, but the reasoning compatibility
path sets it to `None` and installed LangChain omits it from request parameters.
The provider sampling default remains unverified. SDK receipts contain 381
native tool responses, 145 complete JSON text responses, one commentary-bearing
response and one timeout. Reasoning content appears in 526 responses; separate
reasoning-token counts and effort compliance are unavailable. Provider cache
reads are distinct from disabled application caching.

Every cell preserves `Smethod`, `Spayload`, `Sexploit`, `Schain`, `Soutput`, and
`Srun`, including medians and exact ranges in the
[99-cell table](../../results/validation/method-agents-post-review-2026-09-29/accepted/cell-report.md)
and accompanying JSON. Observed ranges are the same across each phase:
`Smethod` 1–3, `Spayload` 0–3, `Sexploit` 0–3, `Schain` 0, `Soutput` 0,
and `Srun` 0.2–2.1. The formula remains
`0.20*Smethod + 0.20*Spayload + 0.30*Sexploit + 0.10*Schain + 0.20*Soutput`.

The DVWA footer advertises external links, recorded as navigation containment
events. The existing rubric gives output score zero; it does not follow those
links. This explains the reduced aggregate scores for confirmed positives.
No chain-score improvement is observed. These component scores and seed-heavy
executions do not establish a general model ranking or an AKG advantage.

## Acceptance and repeatability

| Check | Observed | Evidence under the evidence root |
| --- | --- | --- |
| Live preflight Doctor | 16/16 pass | `live-doctor.json` |
| Initial review regressions | 31 pass | Separate `review-fixes-2026-09-29/` evidence |
| Parser regressions | Six failing then six passing graph cases | `pre-fix-comments*`, `accepted/comments*` |
| Duplicate-error regressions | Six failing/12 guard passes, then 18 passes | `duplicate-pre-fix*`, `accepted/duplicate-correction/` |
| Budget regressions | Two failing/one guard pass, then three passes | `budget-pre-fix*`, `accepted/budget-correction/` |
| Final full offline suite | 1,600 pass, two inapplicable skips | `accepted/budget-correction/offline-*` |
| Final dry runs | SQLi 12, access control 9, brute force 6 pass | `accepted/budget-correction/dry-run-*.log` |
| Main artifact/physical transport | 297 audited, no issues | `accepted/{static,primary,automatic}-*audit.json` |
| Frozen execution queues | 437 unchanged, no issues | `accepted/frozen-queue-audit.json` |
| Generated replays/parent controls | 187/21 audited, zero model calls | `accepted/replay-transport-audit.json`, `parent-transport-audit.json` |
| Error repair replay | 75 audited; one decision corrected | `accepted/duplicate-correction/replay-summary.json`, `transport-audit.json` |
| Final independent references | 17 supported positives, ten unverified | `accepted/duplicate-correction/live-reference/` |
| Fixture source identity | Twelve deployed pages unchanged | `accepted/reference-discovery/`, `fixture-identity.json` |
| Final study audit | 355 checks pass | `accepted/final-study-audit.json` |

The two skips are `test_failure_controls[medium-sqli_union-failed_submit]` and
`test_failure_controls[medium-sqli_error-failed_submit]`: their POST/result-GET
transaction exists only at high security. Medium POST handling has separate
coverage. These specific cases remain skipped; they do not imply missing high
transaction coverage.

Repeat local acceptance with:

```bash
.venv/bin/python -m pytest tests -q --junitxml=results/validation/junit.xml
.venv/bin/python -m pytest -q tests/test_method_agents_e2e.py \
  -k 'keyword_comment or commented_oversized or generated_duplicate_error or generated_budget_exclusion'
.venv/bin/python -m tesis run --dry-run --config results/validation/method-agents-post-review-2026-09-29/accepted/dry-run-sqli.yaml
.venv/bin/python -m tesis run --dry-run --config results/validation/method-agents-post-review-2026-09-29/accepted/dry-run-access_control.yaml
.venv/bin/python -m tesis run --dry-run --config results/validation/method-agents-post-review-2026-09-29/accepted/dry-run-brute_force.yaml
```

`run_phase.py`, its captured CLI, phase execution logs and coverage ledger
retain the exact live commands and resolved coordinates. The replay API and
saved inputs retain repeatable diagnostic selections. Reusing an output path
reads its existing evidence; a fresh replay requires a new diagnostic output.

Independent audits also corrected observer interpretation: automatic surface
success differs from last selected-method grading; runner final-state exports
omit some full runtime fields; SQL HTTP success alone does not mean extraction;
redacted security cookies require checking successful level-setting responses.
Earlier auditor failures and interpretations remain in separate diagnostic
folders. `observer-manifest-final.json` records observer hashes and intentional
analysis changes. Original execution artifacts remain immutable.
