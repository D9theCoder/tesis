# Method-agent implementation and testing report

Status: completed. A1–A7 remediation and the additional live-discovered
verification, queue-capture, terminal-scoring and probe-jitter fixes pass their
E2E controls. All 297 declared live coordinates, 185 generated-queue replay
comparisons, artifact/transport audits and 27 final independent fixture controls
are accepted. One combined-cause attribution remains explicitly unresolved.
Evidence root: `results/validation/method-agents-2026-09-29/`.

The live counts below describe the pre-review code epoch. The six subsequent
review fixes have offline acceptance documented here. The completed
[post-review study](METHOD_AGENTS_POST_REVIEW_MATRIX_2026-09-29.md) separately
records a fresh 297-coordinate matrix, 187 generated-queue comparisons, matched
later repairs, and final acceptance with 1,600 passing tests and two skips.

## Implemented behavior

A1–A7 from the [completed agent review](../completed/HANDOFF_AGENTS_REVIEW_2026-09-29.md)
are repaired. The real graph now rejects misleading timing/content/token
signals, requires observed brute-force preconditions, treats runtime schema
rejection as authoritative, records later negative decisions, and records the
actual force-browse path. It retains static AKG routing, containment, candidate
provenance and the six score dimensions.

Live controls additionally exposed the high blind module's encoded-cookie
transport, documented missing-ID 404 responses, and an extraction-predicate
counting defect. Boolean extraction accepts either recognized branch after a
consistent repeat; a false branch also requires a complementary true response
proving that the same expression evaluates. Low/high require two different
extraction predicates and medium one. Timing confirmation requires two bounded
delayed transactions of one candidate against successful fresh harmless controls,
using the validator's numeric parser for accepted `SLEEP` representations. The corrected queue
reader follows validator ranking instead of append-only candidate-history order.
Access-control visibility from the admin session is capped at 2 and recorded as
unverified, with no new confirmed node or enabling outcome.

The existing runner saves sanitized `method_execution_inputs` after every
validator visit and before execution, including revisited methods.
The replay API revalidates exact saved values/IDs, optionally selects saved IDs
with both execution stages present, refuses missing/changed/rejected queues,
uses fresh sessions, and forbids provider calls. It writes source/code hashes,
request/timing/verifier evidence and manual-scoring rows. Diagnostic replays
remain separate from the declared model dataset.

## Review remediation: offline acceptance

All six review findings are fixed. Replay accepts unchanged candidate membership,
values, provenance, and budget even when fresh ranking changes order; execution
retains the frozen order. Method/scorer updates use the graph schema's reducers,
preserving prior attempts, monotonic observations, score maxima, and accumulated
evidence. Resume ignores historical validation receipts while still capturing a
new validator receipt. Offline artifact identifiers include forced/automatic
routing so both controls retain their independent target and call-count receipts.

Evidence: `results/validation/review-fixes-2026-09-29/`.

| Check | Expected | Observed | Evidence |
| --- | --- | --- | --- |
| Baseline regression controls | Reproduce verifier, replay, resume, and collision defects | 28 failed; 3 guard controls passed | `corrected-pre-fix.log`, `corrected-pre-fix-junit.xml`, `corrected-pre-fix-artifacts/` |
| Fixed regression controls | All 31 pass without live calls | 31 passed | `accepted-regressions.log`, `accepted-regressions-junit.xml` |
| Full offline suite | No failures | 1,573 passed; 2 inapplicable medium skips | `offline-suite.log`, `offline-junit.xml`, `results/validation/junit.xml` |
| Saved automatic queue validation | Accept unchanged membership and budget despite reranking | 199 queues valid; 15 order changes; zero membership failures | `saved-queue-baseline.json`, `saved-queue-accepted.json` |
| Surface dry runs | Compile/configure all methods at all levels without HTTP/provider calls | SQLi 12, access control 9, brute force 6 coordinates passed | `dry-runs.json`, `dry-run-*.yaml`, `dry-run-*.log` |

Repeat the regression controls with:

```bash
.venv/bin/python -m pytest -q tests/test_method_agents_e2e.py \
  -k 'boolean_generated_false or bounded_sleep_forms or revisited_replay or resume_only_freezes or routing_controls_preserve or replay_membership' \
  --junitxml=results/validation/review-fixes-2026-09-29/accepted-regressions-junit.xml
.venv/bin/python -m pytest tests -q --junitxml=results/validation/junit.xml
```

`dry-runs.json` records the exact per-surface dry-run commands and resolved axes.
The saved-queue audit is validation only, without replaying live requests. The
graph controls use mocked transport/providers, real sessions, validation,
method execution, reducers, scoring, and export. Code snapshots, source hashes,
the baseline diff, and the final diff retain both code epochs. The initial
fixture-setup failures remain in separate logs; the corrected baseline above
uses authoritative validation receipts and reproduces the reported defects.

Existing live artifacts and attribution remain historical evidence, including
the 185 generated-queue comparisons. This remediation made no live target or
provider calls and does not establish their outcomes under the repaired code.

## Experiment identity and independent controls

The base commit is `2a5d38fed974d8a56e651d54dd1d548723c85daf`; remediation remains
an uncommitted working-tree change. Source hashes/diffs are retained in
`code-identity*.json` and `implementation*.diff`. Earlier failing code/controls
are preserved in `diagnostic-pre-missing-response/` and
`diagnostic-pre-predicate-repeat/` rather than replacing their evidence.

The frozen configuration uses the configured authorized DVWA target, admin
principal, one `openai_compatible` profile (`deepseek-v4.1-flash`) for both roles,
three fresh repeats, concurrency 1, no application response cache, candidate
budget 10 and iteration budget 10. Effective local role temperature is 0,
max tokens 8,192 and requested reasoning effort is low. The provider has not
reported reasoning-token evidence. Its own cached-input usage is distinct from
the disabled application response cache. Sanitized settings are in
`resolved-config.json`; credentials stay in an ignored private config file.
Repository `config.yaml` is unchanged.

The release number was not exposed/verified. `fixture-identity.json` pins the
actual deployed source-page snapshots and their hashes. No database reset was
performed. Independent literal requests confirm known account/hash data,
matched Boolean responses, bounded timing differences and valid/invalid
credentials. These controls do not use agent success predicates. All 27
method/level cells remain in `feasibility-ledger.json`: 17 have a supported
positive oracle; nine access-control cells lack a non-admin permission oracle,
and high error SQLi suppresses extraction errors. Those ten remain unverified
or infeasible instead of being invented positives or omitted coordinates.

## Pre-review accepted validation

| Check | Expected | Observed | Evidence |
| --- | --- | --- | --- |
| Full offline suite | No failures | 1,542 passed; 2 inapplicable skips | `offline-junit.xml`, `offline-suite-accepted.log` |
| Surface dry runs | All three compile/configure without provider/HTTP calls | Passed | `dry-run-*.log` |
| Live static controls | 81 coordinates; finite oracle agreement; zero provider calls | 51 supported positives, 30 unverified/infeasible; zero audit issues | `coverage-ledger.json`, `static-audit.json` |
| Primary hybrid controls | 162 coordinates with preserved axes and auditable scores | 102 supported confirmations, 60 unverified/infeasible; zero artifact/transport issues | `primary-audit.json`, `primary-transport-audit.json` |
| Automatic hybrid routing | 54 coordinates with every validated visit captured | 36 supported confirmations, 18 unverified; zero artifact/transport issues | `automatic-audit.json`, `automatic-transport-audit.json` |
| Frozen pre-fix live inputs | Same queues improve without new generation | All seven preserved predicate/repeatability failures confirm | `diagnostic-replay-attribution.json`, `diagnostic-replays/` |

The two skipped checks concern high SQLi POST/result-GET submission failures
parameterized at medium, where that transaction does not exist. Medium's real
POST path is covered separately. Offline E2E uses the real graph, session and
containment code, provider parser, validator/ranker, method agents, reducers,
scorer and artifact/manual export; only external HTTP/provider responses are
replaced. It is distinguished from the live controls above.

The diagnostic CLI receipt wrapper initially omitted the `run` argument. All
CLI-only failures made zero HTTP/provider calls and are retained under
`diagnostic-cli-invocation/`, outside the declared experiment dataset. The
corrected wrapper calls the existing CLI and records target-only transport
receipts with masked tokens, stable coordinate IDs, session identities, actual
parameters/cookies/status/body hashes and redacted bodies.

Automatic routing exposed a later capture defect: a revisited method lacked
its second frozen input. The failing graph control was written before repair.
A validator completion receipt now triggers capture for each visit after its
queue has been validated. The old completed/partial automatic invocations are
quarantined under `diagnostic-pre-revisited-capture/`; all 54 accepted automatic
coordinates were rerun after the offline gate. Static and primary controls
contain single visits and their execution/scoring behavior is unchanged by this
additive receipt.


The completed automatic grid exposed terminal scoring loss: a stop cleared the
active selection after methods executed. A failing graph E2E preceded the
shared scorer correction. The scorer now uses the last method verifier decision
when the selection is empty, without changing model routing or executing again.
Four original artifacts remain immutable; `corrected-scoring/` contains pure
score corrections linked by source hashes in
`scoring-correction-attribution.json`, with zero fresh provider/target calls.
The full suite was repeated after this correction (1,540 passed, two skips).
The combined coverage ledger distinguishes original and corrected score paths.

The transport auditor initially compared force-browse candidates as raw path
suffixes and reported 12 mismatches for normalized aliases. Independent URL
joining of path/query now matches the actual receipts; this was an audit defect,
not a request defect. Both failed/corrected assertions are retained in
`diagnostic-transport-path-normalization.json`.

## Matrix and attribution

The declared matrix remains 297 coordinates: 81 static, 162 explicitly targeted
hybrid primary coordinates and 54 automatic-routing hybrid coordinates. Both
primary conditions are retained at R=3. `run_phase.py` calls the existing CLI;
completed invocations are preserved, errors remain in the coverage ledger,
and all target requests are serialized. The primary and automatic grids pass; attribution reviews all 297 coordinates.
Final fixture controls agree with all 27 initial method/level cells.

Every poor/unused/rejected result is reviewed in the attribution ledger. Valid
saved generated exploits are replayed with saved probe controls and without
seed exploits or fresh model calls. A seed success cannot demonstrate generated
payload quality. Boolean partial evidence from a single generated predicate
must be distinguished from the method's two-predicate confirmation policy.
Rejected candidates must never execute. Provider/parser/validation, method,
fixture and scoring causes stay separate, with unresolved cases retaining
specific missing controls.

A measured scoring limitation is already established: discarded external links
in DVWA navigation produce containment events, and the current documented
`Soutput` rule assigns zero for any such event. This depresses `Srun` even for
correct seed execution. The containment boundary and scoring weights are
preserved; low composite scores alone cannot establish poor model capability.
Forced-target runs bypass model selection, so an AKG selection advantage needs
the separate automatic-routing evidence.

## Attribution results and remaining limits

The accepted dataset contains 189 supported confirmations and 108 unverified
fixture outcomes, with no disagreement against the finite supported controls.
There are 99 method/surface × level × condition cells, each at R=3. Primary runs
made 162 role calls; automatic runs made 375. Static runs made zero. Forty
generated candidates executed in the original hybrid runs: 18 in primary
access-control runs and 22 in automatic routing. All 102 supported primary
confirmations used seeds; they do not measure generated payload quality.

The 185 saved generated queues have 80 confirmed replay decisions and 105
not-confirmed decisions. Every request/evidence link and repeated-transaction
count passes independent transport audit. Three initial probe-gate failures
remain preserved beside corrected identical-input replays (188 physical replay
attempts for these 185 comparisons). Replays made zero fresh provider calls.
Their finite causes are:

| Generated-queue replay assessment | Count | Interpretation |
| --- | ---: | --- |
| Confirmed generated exploit | 80 | Saved generated input produces verifier evidence; this does not validate strategy prose that was never executed |
| Ineffective query for fixed fixture | 40 | Medium quoted inputs or recorded query errors; numeric/static and independent controls succeed |
| Encoding/transport interaction | 5 | Percent escapes remain literal form/session values and return ordinary rows; profile intent and transport representation differ |
| Partial Boolean branch evidence | 22 | Repeatable branch signal below the low/high two-distinct-predicate confirmation requirement |
| Credential/strategy representation interaction | 38 | Leading credential pair fails; additional ordering/pacing/list text is not executed as a strategy |

Probe jitter is a confirmed code cause for three initially skipped generated
queues. Ratio-only timing classified 5–8→35–41 ms as throttling without a status,
header or body marker. The failing graph checks preceded correction. The probe
now requires 100 ms absolute growth as well as the threefold ratio; existing
100→400 ms and explicit-throttle controls remain effective. Corrected replays
execute the same saved generated inputs: two confirm the valid leading pair,
one rejects the wrong pair. Evidence: `probe-jitter-attribution.json` and
`jitter-corrected-replays/`. The final full suite has 1,542 passing tests.

Two native structured-output failures remain visible despite seed success:
one payload-generator response contains fenced JSON; one orchestrator response
contains a JSON prefix plus commentary. `response-mode-attribution.json` records
syntax controls and requested mode. Native object delivery failed, but raw tool
metadata is unavailable, so model noncompliance versus gateway/SDK compatibility
remains unresolved. These are response-format events, not HTTP quota/timeout
failures or proof of generally poor model capability.

One high automatic coordinate combines literal encoded UNION input with one
repeatable generated Boolean predicate. Per-replay mechanisms are supported;
aggregate generated-queue capability attribution remains unresolved. Its ledger
names the missing raw-query/two-predicate control. Other limits include the
unverified exact DVWA release, absent independent access-control permission
fixture, suppressed high error-SQLi details, and the bounded timing heuristic.
The requested reasoning effort and provider model alias are recorded; actual
reasoning-token evidence and underlying gateway model revision are unavailable.

The existing navigation-containment scoring policy is retained. It explains
`Soutput=0` across the supported confirmations and depresses `Srun` independently
of seed correctness. R=3, shared seeds and these integration constraints do not
establish a general model ranking or an AKG advantage. Original CLI manifests
and summaries preserve their original code epoch; accepted score summaries use
the four explicitly linked pure corrections in the coverage/phase ledgers.

Exact candidates, role prompts, schema/prompt hashes, response receipts,
validation, cause confidence and next controls are in
[attribution-ledger.json](../../results/validation/method-agents-2026-09-29/attribution-ledger.json).
The consolidated gates are in
[final-acceptance.json](../../results/validation/method-agents-2026-09-29/final-acceptance.json).
Score medians appear below; exact ranges, routing selections, terminal outcomes,
format/fallback events and source paths are in
[cell-report.json](../../results/validation/method-agents-2026-09-29/cell-report.json).

## Repeatable commands

Run from the repository root; the live driver requires the ignored private
frozen config and the authorized target/provider connectivity.
The drivers reuse completed receipts and accepted corrected replay artifacts;
these commands audit/rebuild this corpus. A fresh empirical repeat uses a new
evidence root and newly predeclared ledger.

```bash
.venv/bin/python -m pytest -q --junitxml=results/validation/junit.xml
PYTHONPATH=. .venv/bin/python results/validation/method-agents-2026-09-29/audit_phase.py static
PYTHONPATH=. .venv/bin/python results/validation/method-agents-2026-09-29/run_remaining.py
PYTHONPATH=. .venv/bin/python results/validation/method-agents-2026-09-29/audit_transport.py primary
PYTHONPATH=. .venv/bin/python results/validation/method-agents-2026-09-29/audit_transport.py automatic
PYTHONPATH=. .venv/bin/python results/validation/method-agents-2026-09-29/run_attribution.py
PYTHONPATH=. .venv/bin/python results/validation/method-agents-2026-09-29/finalize_attribution.py
PYTHONPATH=. .venv/bin/python results/validation/method-agents-2026-09-29/build_report.py
```

The [completed method-testing handoff](HANDOFF_METHOD_AGENTS_RIGOROUS_TESTING_2026-09-29.md)
links this acceptance report. No commit or push was performed.


## Accepted cell results

| Phase | Condition | Method/surface | Level | n | Confirmed / unverified / false negative | Generated executed | Smethod | Spayload | Sexploit | Schain | Soutput | Srun |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| static | linear_hybrid | sqli_union | low | 3 | 3 / 0 / 0 | 0 | 3 | 3 | 3 | 0 | 0 | 2.1 |
| static | linear_hybrid | sqli_union | medium | 3 | 3 / 0 / 0 | 0 | 3 | 3 | 3 | 0 | 0 | 2.1 |
| static | linear_hybrid | sqli_union | high | 3 | 3 / 0 / 0 | 0 | 3 | 3 | 3 | 0 | 0 | 2.1 |
| static | linear_hybrid | sqli_error | low | 3 | 3 / 0 / 0 | 0 | 3 | 3 | 3 | 0 | 0 | 2.1 |
| static | linear_hybrid | sqli_error | medium | 3 | 3 / 0 / 0 | 0 | 3 | 3 | 3 | 0 | 0 | 2.1 |
| static | linear_hybrid | sqli_error | high | 3 | 0 / 3 / 0 | 0 | 3 | 0 | 0 | 0 | 0 | 0.6 |
| static | linear_hybrid | sqli_boolean_blind | low | 3 | 3 / 0 / 0 | 0 | 3 | 3 | 3 | 0 | 0 | 2.1 |
| static | linear_hybrid | sqli_boolean_blind | medium | 3 | 3 / 0 / 0 | 0 | 3 | 3 | 3 | 0 | 0 | 2.1 |
| static | linear_hybrid | sqli_boolean_blind | high | 3 | 3 / 0 / 0 | 0 | 1 | 3 | 3 | 0 | 0 | 1.7 |
| static | linear_hybrid | sqli_time_blind | low | 3 | 3 / 0 / 0 | 0 | 3 | 3 | 3 | 0 | 0 | 2.1 |
| static | linear_hybrid | sqli_time_blind | medium | 3 | 3 / 0 / 0 | 0 | 3 | 3 | 3 | 0 | 0 | 2.1 |
| static | linear_hybrid | sqli_time_blind | high | 3 | 3 / 0 / 0 | 0 | 1 | 3 | 3 | 0 | 0 | 1.7 |
| static | linear_hybrid | ac_idor | low | 3 | 0 / 3 / 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0.2 |
| static | linear_hybrid | ac_idor | medium | 3 | 0 / 3 / 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0.2 |
| static | linear_hybrid | ac_idor | high | 3 | 0 / 3 / 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0.2 |
| static | linear_hybrid | ac_vertical_escalation | low | 3 | 0 / 3 / 0 | 0 | 1 | 1 | 1 | 0 | 0 | 0.7 |
| static | linear_hybrid | ac_vertical_escalation | medium | 3 | 0 / 3 / 0 | 0 | 1 | 1 | 1 | 0 | 0 | 0.7 |
| static | linear_hybrid | ac_vertical_escalation | high | 3 | 0 / 3 / 0 | 0 | 1 | 1 | 1 | 0 | 0 | 0.7 |
| static | linear_hybrid | ac_force_browse | low | 3 | 0 / 3 / 0 | 0 | 3 | 2 | 2 | 0 | 0 | 1.6 |
| static | linear_hybrid | ac_force_browse | medium | 3 | 0 / 3 / 0 | 0 | 3 | 2 | 2 | 0 | 0 | 1.6 |
| static | linear_hybrid | ac_force_browse | high | 3 | 0 / 3 / 0 | 0 | 3 | 2 | 2 | 0 | 0 | 1.6 |
| static | linear_hybrid | bf_dictionary | low | 3 | 3 / 0 / 0 | 0 | 3 | 3 | 3 | 0 | 0 | 2.1 |
| static | linear_hybrid | bf_dictionary | medium | 3 | 3 / 0 / 0 | 0 | 3 | 3 | 3 | 0 | 0 | 2.1 |
| static | linear_hybrid | bf_dictionary | high | 3 | 3 / 0 / 0 | 0 | 3 | 3 | 3 | 0 | 0 | 2.1 |
| static | linear_hybrid | bf_spray | low | 3 | 3 / 0 / 0 | 0 | 3 | 3 | 3 | 0 | 0 | 2.1 |
| static | linear_hybrid | bf_spray | medium | 3 | 3 / 0 / 0 | 0 | 3 | 3 | 3 | 0 | 0 | 2.1 |
| static | linear_hybrid | bf_spray | high | 3 | 3 / 0 / 0 | 0 | 3 | 3 | 3 | 0 | 0 | 2.1 |
| primary | linear_hybrid | sqli_union | low | 3 | 3 / 0 / 0 | 0 | 3 | 3 | 3 | 0 | 0 | 2.1 |
| primary | akg_guided_hybrid | sqli_union | low | 3 | 3 / 0 / 0 | 0 | 3 | 3 | 3 | 0 | 0 | 2.1 |
| primary | linear_hybrid | sqli_union | medium | 3 | 3 / 0 / 0 | 0 | 3 | 3 | 3 | 0 | 0 | 2.1 |
| primary | akg_guided_hybrid | sqli_union | medium | 3 | 3 / 0 / 0 | 0 | 3 | 3 | 3 | 0 | 0 | 2.1 |
| primary | linear_hybrid | sqli_union | high | 3 | 3 / 0 / 0 | 0 | 3 | 3 | 3 | 0 | 0 | 2.1 |
| primary | akg_guided_hybrid | sqli_union | high | 3 | 3 / 0 / 0 | 0 | 3 | 3 | 3 | 0 | 0 | 2.1 |
| primary | linear_hybrid | sqli_error | low | 3 | 3 / 0 / 0 | 0 | 3 | 3 | 3 | 0 | 0 | 2.1 |
| primary | akg_guided_hybrid | sqli_error | low | 3 | 3 / 0 / 0 | 0 | 3 | 3 | 3 | 0 | 0 | 2.1 |
| primary | linear_hybrid | sqli_error | medium | 3 | 3 / 0 / 0 | 0 | 3 | 3 | 3 | 0 | 0 | 2.1 |
| primary | akg_guided_hybrid | sqli_error | medium | 3 | 3 / 0 / 0 | 0 | 3 | 3 | 3 | 0 | 0 | 2.1 |
| primary | linear_hybrid | sqli_error | high | 3 | 0 / 3 / 0 | 0 | 3 | 0 | 0 | 0 | 0 | 0.6 |
| primary | akg_guided_hybrid | sqli_error | high | 3 | 0 / 3 / 0 | 0 | 3 | 0 | 0 | 0 | 0 | 0.6 |
| primary | linear_hybrid | sqli_boolean_blind | low | 3 | 3 / 0 / 0 | 0 | 3 | 3 | 3 | 0 | 0 | 2.1 |
| primary | akg_guided_hybrid | sqli_boolean_blind | low | 3 | 3 / 0 / 0 | 0 | 3 | 3 | 3 | 0 | 0 | 2.1 |
| primary | linear_hybrid | sqli_boolean_blind | medium | 3 | 3 / 0 / 0 | 0 | 3 | 3 | 3 | 0 | 0 | 2.1 |
| primary | akg_guided_hybrid | sqli_boolean_blind | medium | 3 | 3 / 0 / 0 | 0 | 3 | 3 | 3 | 0 | 0 | 2.1 |
| primary | linear_hybrid | sqli_boolean_blind | high | 3 | 3 / 0 / 0 | 0 | 1 | 3 | 3 | 0 | 0 | 1.7 |
| primary | akg_guided_hybrid | sqli_boolean_blind | high | 3 | 3 / 0 / 0 | 0 | 1 | 3 | 3 | 0 | 0 | 1.7 |
| primary | linear_hybrid | sqli_time_blind | low | 3 | 3 / 0 / 0 | 0 | 3 | 3 | 3 | 0 | 0 | 2.1 |
| primary | akg_guided_hybrid | sqli_time_blind | low | 3 | 3 / 0 / 0 | 0 | 3 | 3 | 3 | 0 | 0 | 2.1 |
| primary | linear_hybrid | sqli_time_blind | medium | 3 | 3 / 0 / 0 | 0 | 3 | 3 | 3 | 0 | 0 | 2.1 |
| primary | akg_guided_hybrid | sqli_time_blind | medium | 3 | 3 / 0 / 0 | 0 | 3 | 3 | 3 | 0 | 0 | 2.1 |
| primary | linear_hybrid | sqli_time_blind | high | 3 | 3 / 0 / 0 | 0 | 1 | 3 | 3 | 0 | 0 | 1.7 |
| primary | akg_guided_hybrid | sqli_time_blind | high | 3 | 3 / 0 / 0 | 0 | 1 | 3 | 3 | 0 | 0 | 1.7 |
| primary | linear_hybrid | ac_idor | low | 3 | 0 / 3 / 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0.2 |
| primary | akg_guided_hybrid | ac_idor | low | 3 | 0 / 3 / 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0.2 |
| primary | linear_hybrid | ac_idor | medium | 3 | 0 / 3 / 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0.2 |
| primary | akg_guided_hybrid | ac_idor | medium | 3 | 0 / 3 / 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0.2 |
| primary | linear_hybrid | ac_idor | high | 3 | 0 / 3 / 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0.2 |
| primary | akg_guided_hybrid | ac_idor | high | 3 | 0 / 3 / 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0.2 |
| primary | linear_hybrid | ac_vertical_escalation | low | 3 | 0 / 3 / 0 | 3 | 1 | 1 | 1 | 0 | 0 | 0.7 |
| primary | akg_guided_hybrid | ac_vertical_escalation | low | 3 | 0 / 3 / 0 | 3 | 1 | 1 | 1 | 0 | 0 | 0.7 |
| primary | linear_hybrid | ac_vertical_escalation | medium | 3 | 0 / 3 / 0 | 3 | 1 | 1 | 1 | 0 | 0 | 0.7 |
| primary | akg_guided_hybrid | ac_vertical_escalation | medium | 3 | 0 / 3 / 0 | 3 | 1 | 1 | 1 | 0 | 0 | 0.7 |
| primary | linear_hybrid | ac_vertical_escalation | high | 3 | 0 / 3 / 0 | 3 | 1 | 1 | 1 | 0 | 0 | 0.7 |
| primary | akg_guided_hybrid | ac_vertical_escalation | high | 3 | 0 / 3 / 0 | 3 | 1 | 1 | 1 | 0 | 0 | 0.7 |
| primary | linear_hybrid | ac_force_browse | low | 3 | 0 / 3 / 0 | 0 | 3 | 2 | 2 | 0 | 0 | 1.6 |
| primary | akg_guided_hybrid | ac_force_browse | low | 3 | 0 / 3 / 0 | 0 | 3 | 2 | 2 | 0 | 0 | 1.6 |
| primary | linear_hybrid | ac_force_browse | medium | 3 | 0 / 3 / 0 | 0 | 3 | 2 | 2 | 0 | 0 | 1.6 |
| primary | akg_guided_hybrid | ac_force_browse | medium | 3 | 0 / 3 / 0 | 0 | 3 | 2 | 2 | 0 | 0 | 1.6 |
| primary | linear_hybrid | ac_force_browse | high | 3 | 0 / 3 / 0 | 0 | 3 | 2 | 2 | 0 | 0 | 1.6 |
| primary | akg_guided_hybrid | ac_force_browse | high | 3 | 0 / 3 / 0 | 0 | 3 | 2 | 2 | 0 | 0 | 1.6 |
| primary | linear_hybrid | bf_dictionary | low | 3 | 3 / 0 / 0 | 0 | 3 | 3 | 3 | 0 | 0 | 2.1 |
| primary | akg_guided_hybrid | bf_dictionary | low | 3 | 3 / 0 / 0 | 0 | 3 | 3 | 3 | 0 | 0 | 2.1 |
| primary | linear_hybrid | bf_dictionary | medium | 3 | 3 / 0 / 0 | 0 | 3 | 3 | 3 | 0 | 0 | 2.1 |
| primary | akg_guided_hybrid | bf_dictionary | medium | 3 | 3 / 0 / 0 | 0 | 3 | 3 | 3 | 0 | 0 | 2.1 |
| primary | linear_hybrid | bf_dictionary | high | 3 | 3 / 0 / 0 | 0 | 3 | 3 | 3 | 0 | 0 | 2.1 |
| primary | akg_guided_hybrid | bf_dictionary | high | 3 | 3 / 0 / 0 | 0 | 3 | 3 | 3 | 0 | 0 | 2.1 |
| primary | linear_hybrid | bf_spray | low | 3 | 3 / 0 / 0 | 0 | 3 | 3 | 3 | 0 | 0 | 2.1 |
| primary | akg_guided_hybrid | bf_spray | low | 3 | 3 / 0 / 0 | 0 | 3 | 3 | 3 | 0 | 0 | 2.1 |
| primary | linear_hybrid | bf_spray | medium | 3 | 3 / 0 / 0 | 0 | 3 | 3 | 3 | 0 | 0 | 2.1 |
| primary | akg_guided_hybrid | bf_spray | medium | 3 | 3 / 0 / 0 | 0 | 3 | 3 | 3 | 0 | 0 | 2.1 |
| primary | linear_hybrid | bf_spray | high | 3 | 3 / 0 / 0 | 0 | 3 | 3 | 3 | 0 | 0 | 2.1 |
| primary | akg_guided_hybrid | bf_spray | high | 3 | 3 / 0 / 0 | 0 | 3 | 3 | 3 | 0 | 0 | 2.1 |
| automatic | linear_hybrid | sqli | low | 3 | 3 / 0 / 0 | 0 | 3 | 3 | 3 | 0 | 0 | 2.1 |
| automatic | akg_guided_hybrid | sqli | low | 3 | 3 / 0 / 0 | 0 | 3 | 3 | 3 | 0 | 0 | 2.1 |
| automatic | linear_hybrid | sqli | medium | 3 | 3 / 0 / 0 | 0 | 3 | 3 | 3 | 0 | 0 | 2.1 |
| automatic | akg_guided_hybrid | sqli | medium | 3 | 3 / 0 / 0 | 0 | 3 | 3 | 3 | 0 | 0 | 2.1 |
| automatic | linear_hybrid | sqli | high | 3 | 3 / 0 / 0 | 0 | 1 | 3 | 3 | 0 | 0 | 1.7 |
| automatic | akg_guided_hybrid | sqli | high | 3 | 3 / 0 / 0 | 1 | 3 | 3 | 3 | 0 | 0 | 2.1 |
| automatic | linear_hybrid | access_control | low | 3 | 0 / 3 / 0 | 3 | 1 | 1 | 1 | 0 | 0 | 0.7 |
| automatic | akg_guided_hybrid | access_control | low | 3 | 0 / 3 / 0 | 2 | 3 | 2 | 2 | 0 | 0 | 1.6 |
| automatic | linear_hybrid | access_control | medium | 3 | 0 / 3 / 0 | 5 | 1 | 1 | 1 | 0 | 0 | 0.7 |
| automatic | akg_guided_hybrid | access_control | medium | 3 | 0 / 3 / 0 | 4 | 3 | 2 | 2 | 0 | 0 | 1.6 |
| automatic | linear_hybrid | access_control | high | 3 | 0 / 3 / 0 | 5 | 1 | 0 | 0 | 0 | 0 | 0.2 |
| automatic | akg_guided_hybrid | access_control | high | 3 | 0 / 3 / 0 | 2 | 3 | 2 | 2 | 0 | 0 | 1.6 |
| automatic | linear_hybrid | brute_force | low | 3 | 3 / 0 / 0 | 0 | 3 | 3 | 3 | 0 | 0 | 2.1 |
| automatic | akg_guided_hybrid | brute_force | low | 3 | 3 / 0 / 0 | 0 | 3 | 3 | 3 | 0 | 0 | 2.1 |
| automatic | linear_hybrid | brute_force | medium | 3 | 3 / 0 / 0 | 0 | 3 | 3 | 3 | 0 | 0 | 2.1 |
| automatic | akg_guided_hybrid | brute_force | medium | 3 | 3 / 0 / 0 | 0 | 3 | 3 | 3 | 0 | 0 | 2.1 |
| automatic | linear_hybrid | brute_force | high | 3 | 3 / 0 / 0 | 0 | 3 | 3 | 3 | 0 | 0 | 2.1 |
| automatic | akg_guided_hybrid | brute_force | high | 3 | 3 / 0 / 0 | 0 | 3 | 3 | 3 | 0 | 0 | 2.1 |
