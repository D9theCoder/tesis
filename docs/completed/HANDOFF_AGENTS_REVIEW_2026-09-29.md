# Agents review (2026-09-29)

Status: completed. A1–A7 remediation passes artifact-backed offline graph
controls and the audited 81-coordinate live static gate. The original findings
below describe the pre-fix implementation. Broader matrix/attribution acceptance is documented in the completed
method-testing handoff and final testing report. No new commit or push was performed.

The follow-on [rigorous method-agent testing handoff](HANDOFF_METHOD_AGENTS_RIGOROUS_TESTING_2026-09-29.md)
covers E2E remediation gates, complete method-level matrices, and controlled
model-versus-code failure attribution.

## Scope and evidence

Read every Python file in `agents/`: all nine method agents, the orchestrator,
shared state helpers, telemetry helpers, and all four package export files.
Checked method selection, preconditions, request submission, confirmation,
chaining, partial state updates, candidate identity, and artifact evidence.

| Files reviewed | Result |
| --- | --- |
| `sqli/sqli_union_agent.py`, `sqli/sqli_boolean_blind_agent.py` | No additional original finding in the original review |
| `sqli/sqli_error_agent.py`, `sqli/sqli_time_blind_agent.py` | A1, A2 |
| `access_control/ac_idor_agent.py`, `access_control/ac_vertical_escalation_agent.py` | Stripped-ID evidence repaired; no additional confirmed finding |
| `access_control/ac_force_browse_agent.py` | Candidate provenance repaired; A7 remains |
| `brute_force/bf_dictionary_agent.py`, `brute_force/bf_spray_agent.py` | A3, A4; token-retry candidate identity repaired in the shared helper |
| `orchestrator.py` | A5 |
| `state_utils.py` | A6, A7; candidate identity repaired |
| `agent_telemetry.py`, `__init__.py`, `sqli/__init__.py`, `access_control/__init__.py`, `brute_force/__init__.py` | No additional original finding |

Repeatable reproduction command, run from the repository root:

```bash
PYTHONPATH=. .venv/bin/python results/validation/agents-review-2026-09-29/reproduce.py
```

Expected and observed: 16 reviewed files, seven finding groups, 12 successful
bug reproductions. The script exercises full agent calls for A1–A5 and A7,
and the shared state/export path for A6. Assertions describe the defective
behavior and should fail after remediation. This is an offline review, not a
passing acceptance suite. Sessions, timing, and provider output are mocked;
zero DVWA or provider calls are made.

Artifact: `results/validation/agents-review-2026-09-29/findings.json`. It records
each input/observed result and the path, line count, and SHA-256 of every
reviewed source file. Existing regression tests passing does not negate these
independent reproductions.

## Findings

### A1 — P1: Slow HTTP errors can confirm time-based SQL injection

Location: [sqli_time_blind_agent.py](../../agents/sqli/sqli_time_blind_agent.py#L143).

The exploit phase accepts `_get_baseline_timing()` returning zero after all
baseline requests fail, and confirms a delay without checking the response
status. The probe phase rejects a zero baseline, but the exploit phase measures
a fresh baseline independently and does not apply that guard.

Reproduced through the complete method agent at both medium and high security:
a successful earlier probe followed by slow HTTP 503 exploit responses produces
score 3 and `sqli_time_blind_confirmed`. This occurs with a valid exploit
baseline and with every exploit-baseline request failing. High's two-delay
requirement does not prevent the false confirmation.

Remediation: stop when a usable exploit baseline is unavailable and require
valid method responses before treating latency as injection evidence. Add
negative controls for server errors and failed baselines before changing code.

### A2 — P2: Ordinary tilde content confirms error-based extraction

Location: [sqli_error_agent.py](../../agents/sqli/sqli_error_agent.py#L37).

`_EXPLOIT_SIGNALS` includes bare `~` and other broad markers, and
`contains_any()` treats any one as sufficient. After a successful SQL-syntax
probe, the unrelated exploit response `Approximate value ~ 10; no extracted
database data` produces score 3 and `sqli_error_confirmed`.

The existing comment intends to support DVWA's truncated `~admin` envelope;
accepting any tilde discards the distinction between that evidence and ordinary
page content. Require an extraction/error pattern that retains the documented
truncated case, with a negative ordinary-content control.

### A3 — P1: Rejected brute-force responses can confirm credentials

Locations: [bf_dictionary_agent.py](../../agents/brute_force/bf_dictionary_agent.py#L307)
and [bf_spray_agent.py](../../agents/brute_force/bf_spray_agent.py#L301).

Telemetry's `semantic_success` rejects the CSRF-token error, but the final
confirmation independently checks only success phrases. It ignores both that
token check and unsuccessful HTTP status.

For both complete agents at high security, HTTP 403 responses containing
`CSRF token is incorrect; password protected area` produce score 3, a confirmed
brute-force node, and recorded credentials. The same responses carry
`success=false` in evidence, including both bounded token attempts.

Use one success predicate for telemetry and confirmation, requiring a valid
response and no token rejection. Cover both agents before implementation.

### A4 — P2: Failed brute-force probes become a positive precondition

Locations: [bf_dictionary_agent.py](../../agents/brute_force/bf_dictionary_agent.py#L219)
and [bf_spray_agent.py](../../agents/brute_force/bf_spray_agent.py#L219).

Transport failures append negative probe telemetry but leave
`rate_limit_detected=false` and the timing list empty. The method then writes
`no_rate_limit=true` and proceeds to exploitation.

Reproduced for both complete agents: every configured probe raises `OSError`,
every probe status is null, yet an exploit request is attempted and the method
receives score 1. Missing evidence cannot establish a rate-limit precondition.
Require an accepted probe before returning a positive result; keep unavailable
evidence distinct from an observed absence of throttling.

### A5 — P2: The orchestrator reaccepts schema-rejected provider output

Locations: [orchestrator.py](../../agents/orchestrator.py#L434)
and [orchestrator.py](../../agents/orchestrator.py#L522).

`invoke_once()` catches `LLMOutputError` and returns its raw text with no
structured decision. The later fallback parser reads that text again and
checks only `next_agent`, so output already rejected by the runtime can become
an accepted decision.

A mocked runtime rejecting `{"next_agent":"sqli_union"}` because `reason_code`
is missing still results in `selected_method=sqli_union`, `used_fallback=false`,
and empty invalid-output/fallback events. The executable method allow-list
still applies; the defect is schema enforcement and truthful event reporting.

Keep runtime rejection authoritative. Preserve the relaxed legacy direct-call
contract only for callers that did not use the runtime validation path.

### A6 — P2: Later negative method decisions are never recorded

Location: [state_utils.py](../../agents/state_utils.py#L483).

`make_update()` emits a verifier decision only on confirmation or when state
has no earlier decision. A later method with negative response evidence thus
gets no decision in either final state or graph-state history.

With an earlier `sqli_union` confirmation and a later unsuccessful
`sqli_error` attempt, the latter's manual row has a response link and score 1
but a null verifier decision. The exporter cannot recover a decision that was
never recorded. The completed historical-confirmation repair addresses recorded
history; this finding concerns missing history at its source.

Record every method's decision in auditable history, including negative
results, while preserving confirmed nodes and earlier confirmation evidence.

### A7 — P2: Force-browse evidence records the wrong endpoint

Locations: [ac_force_browse_agent.py](../../agents/access_control/ac_force_browse_agent.py#L70)
and [state_utils.py](../../agents/state_utils.py#L298).

Force-browse events omit their requested endpoint. Shared materialization fills
the method's fixed `authbypass` module endpoint, even when the actual request
was for a different protected page.

The complete agent requests `security.php` and
`vulnerabilities/view_source.php`, but both evidence records report
`http://localhost/dvwa/vulnerabilities/authbypass/`. Candidate IDs now correctly
identify the attempted candidates; the URL evidence still misstates their
request location. Record each requested force-browse URL/path in its event and
verify it against captured session calls.

## Existing limitation

The force-browse exploit docstring already acknowledges missing low-privilege
and unauthenticated controls. This review does not establish that protected
content visible in its authenticated session proves unauthorized access. No
new authentication model or thesis-scope change was introduced.

## Completed evidence repair and validation

The requested review fixes now retain original attempted force-browse values
and attach candidate IDs to request telemetry and response/timing evidence in
the shared builder. Export matches validated candidate identity, method, and
stage. Legacy normalized aliases require a uniquely recorded scored candidate;
ambiguous records remain unlinked. IDOR and vertical IDs match their stripped
`userId=value` representation; SQL remains literal. A bounded brute-force retry
retains the same candidate ID across both responses.

Regression checks were written before implementation: the initial nine new
cases failed, and the later two retry cases failed before their repair.

| Check | Expected | Observed | Evidence |
| --- | --- | --- | --- |
| Focused offline method/export checks | All regressions pass | 80 passed | `results/validation/manual-evidence-2026-09-29/focused.xml` |
| Full offline suite | No failures | 1,330 passed in 98.68 s | `results/validation/manual-evidence-2026-09-29/offline-suite.log`, `results/validation/junit.xml` |
| Existing matrix re-export audit | 18 coordinates, preserved execution/scores/source hashes, complete manual links | Passed; 364 manual rows; zero issues | `results/validation/manual-evidence-2026-09-29/matrix-audit.json` |

The matrix source remains `results/runs/matrix-2026-09-28-4/`; the new offline
export is `results/validation/manual-evidence-2026-09-29/matrix-evidence/`.
No additional live experiment was run, and the audit findings do not establish
which historical live classifications, if any, were affected.

Repeat the completed repair checks:

```bash
.venv/bin/python -m pytest -q tests/test_manual_scoring_evidence.py tests/test_ac_force_browse_agent.py tests/test_ac_idor_agent.py tests/test_ac_vertical_escalation_agent.py tests/test_state_utils.py tests/test_hybrid_payload_pipeline.py tests/test_brute_force_probe.py tests/test_brute_force_high_token_rotation.py --junitxml=results/validation/manual-evidence-2026-09-29/focused.xml
.venv/bin/python -m pytest -q --junitxml=results/validation/junit.xml
PYTHONPATH=. .venv/bin/python results/validation/matrix-2026-09-28/export_evidence.py results/runs/matrix-2026-09-28-4 results/validation/manual-evidence-2026-09-29/matrix-evidence-new
PYTHONPATH=. .venv/bin/python results/validation/matrix-2026-09-28/audit.py results/validation/manual-evidence-2026-09-29/matrix-evidence-new results/validation/manual-evidence-2026-09-29/matrix-audit-new.json
```

Use an unused export destination. Remediation of A1–A7 is not included in these
passing checks and must receive its own negative controls and acceptance record.

## Remediation implementation and acceptance

A1 now requires usable exploit baselines and repeated bounded delay evidence;
403/503 and generic 404 pages cannot confirm. DVWA's independently documented
missing-ID 404 is handled separately. A2 requires an extraction envelope or
structured account/hash result, retaining the truncated XPath case. A3 uses
one status/token/content success predicate. A4 requires accepted probe evidence,
and recon no longer infers no throttling from a discovered form. A5 treats
runtime schema rejection as authoritative. A6 records every invocation decision
while graph history preserves earlier confirmations. A7 records and resolves
the actual force-browse request path.

Access-control visibility in the current admin session remains unverified
(score at most 2), because the deployed fixture has no independent non-admin
permission control. High blind SQLi now uses the deployed cookie transport;
regular SQLi retains the checked POST/result-GET transaction. Validated queues
follow validator ranking while rejected candidate history remains audit data.
The runner records sanitized frozen inputs; diagnostic replay revalidates the
exact queue, preserves candidate IDs, uses fresh sessions, forbids provider
calls, and records source/code hashes plus manual evidence.

Evidence root: `results/validation/method-agents-2026-09-29/`. The original
12 bug reproductions remain under the old review directory. New failure
inventories, pre-fix JUnit/logs, graph/fixture artifacts and corrected controls
are retained separately. Commands and final totals are recorded in the linked
method-testing handoff and its acceptance report. An offline pass is not a live
matrix acceptance label.

Acceptance on 2026-09-29: the full offline suite passed 1,536 tests with two
inapplicable high-transaction cases skipped. The live static audit covered all
81 declared coordinates, with 51 supported positives, 30 correctly unverified
or infeasible outcomes, zero unexpected provider calls and zero audit issues.
Seven preserved blind-method failures confirmed with identical frozen inputs
on corrected code and zero fresh provider calls. These replays establish the
additional predicate/repeatability repairs; they do not claim model quality.

Repeatable commands and artifacts:

```bash
.venv/bin/python -m pytest -q --junitxml=results/validation/junit.xml
PYTHONPATH=. .venv/bin/python results/validation/method-agents-2026-09-29/audit_phase.py static
```

JUnit/log: `offline-junit.xml`, `offline-suite-final.log`; accepted grid:
`coverage-ledger.json`, `static-audit.json`; controls: `live-reference/`;
frozen comparisons: `diagnostic-replay-attribution.json`, `diagnostic-replays/`.
All paths above are relative to `results/validation/method-agents-2026-09-29/`.

Final consolidated acceptance: 1,542 passing offline tests (two inapplicable
skips), 297 declared live coordinates, 185 generated-queue replay comparisons
and matching post-controls. Detailed limits and evidence:
[METHOD_AGENTS_TESTING_REPORT_2026-09-29.md](METHOD_AGENTS_TESTING_REPORT_2026-09-29.md).
