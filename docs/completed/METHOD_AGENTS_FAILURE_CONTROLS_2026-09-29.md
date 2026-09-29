# Method-agent failure controls

Written before runtime changes on 2026-09-29. Evidence root:
`results/validation/method-agents-2026-09-29/`.

All offline controls use the real graph, session manager, HTTP containment,
provider JSON/schema parser, candidate builder/validator/ranker, method agent,
reducers, scorer, and runner artifact/manual export. Only HTTP transport and
provider responses are replaced. Fixture contents are defined independently
of agent predicates. No offline test is live DVWA/provider acceptance.

| Failure | Required assertion |
| --- | --- |
| A1: slow 403/503, failed exploit baseline, failed high POST, uniform slowness, jitter | No timing confirmation; failed transactions are negative evidence |
| A2: tilde, generic xpath, unrelated credentials | No error extraction confirmation; valid truncated `~admin` remains supported |
| A3: token rejection or HTTP error with success text | No credentials/confirmation; evidence agrees for dictionary and spray |
| A4: unavailable/rejected probes or all probes already tried without evidence | No positive rate-limit observation and no exploitation |
| A5: runtime schema rejection | Rejected text never reparsed; invalid-output and fallback events retained |
| A6: negative method after a confirmation | Both decisions are retained in graph history/manual rows; earlier confirmed nodes survive |
| A7: force-browse paths and aliases | Evidence URL equals actual request URL, including failures |
| Union: ordinary HTML and SQL errors | No extraction from navigation/admin text; fixture account data confirms |
| Boolean: always true, unrelated length changes, failed matched controls | No differential confirmation without successful matched true/false evidence |
| Access control: admin-authorized visibility | Mark unverified rather than claiming unauthorized access; retain finite transport/content evidence |
| Pipeline: invalid/duplicate/scope/collision candidates | Rejected values never reach transport; unused rows have null scores/links |
| Lifecycle: fresh sessions/state, exception and CAPTCHA stop | Closed sessions, unchanged input, correct incomplete reason and repeatable artifacts |

The A6 shared-update check is isolated because the ordinary forced-target graph
stops after one method and cannot observe the missing second-method decision.
It saves its reducer/history/export evidence separately.

Run pre-fix controls and save the failing JUnit/log before implementation.
Then rerun the controls and full offline suite. Never start the primary live
matrix until the independent correctness controls pass.

Live-control follow-up, specified before correction: the low boolean fixture has
one true database predicate and one false password-hash predicate. Both recognized
branches must count as extraction evidence after matched controls, only after a
repeat returns the same branch. A changing repeat or generic/error 404 must not
confirm and must carry `success=false` in request evidence.

Timing follow-up, specified before correction: the deployed database name begins
with ASCII 100, so `>77` delays and `>100` correctly does not. One injected
candidate with two bounded delayed transactions and fresh harmless controls
must suffice; requiring two different true predicates rejects valid extraction.
Keep failed controls, oversized delay/jitter and non-repeatable delay negative.

Generated-only replay control, specified before adding queue selection: a hybrid
seed success can hide an unused valid generated exploit. Diagnostic selection
may use only saved IDs (plus explicit saved probe controls); unknown IDs must
stop before HTTP. Preserve values/IDs and zero fresh provider calls, and show
that unselected seed exploits never execute.

Before the replay stage guard: selecting only saved probes must stop before
HTTP, rather than allowing legacy method-stage fallback to restore unsaved
exploit seeds. The same requirement applies when exploit-only selection lacks
saved probes. These are diagnostic restrictions; primary graph queues remain
unchanged.

Automatic live routing follow-up, specified before correction: union may be
visited again after another method. Each visit needs its own validated queue
and pre-execution state, including prior tried payloads. Capture must happen
after that visit's validator, not from the old queue at orchestration. The
real graph E2E must assert all three visits and distinct generated inputs.

Automatic stop scoring, specified before correction: an orchestrator decision
of `scorer` clears the current selection even after real methods have executed.
A terminal stop must retain all six dimensions for the last executed method,
without relabeling the stop as another method execution or changing routing.
The graph control must assert the positive verifier evidence, preserved stop
decision and nonempty final composite. A stop before any method remains an
explicit empty result. Saved live final state permits a pure scoring comparison
with no new model output or target request.

Live replay jitter, specified before correction: low brute-force probes returning
HTTP 200 without throttle markers can rise from 5–8 ms to 35–41 ms. A ratio-only
threefold heuristic incorrectly sets `no_rate_limit=false` and never executes
a valid generated credential. Require material absolute growth as well as the
existing ratio; preserve explicit throttling and the existing 100→400 ms delayed
control. The real graph must still attempt/confirm the known fixture credential
for both dictionary and spray under harmless sub-100 ms jitter. Retain the three
failed saved-input replays and rerun their identical queues after correction,
without fresh generation.

## Acceptance

Review follow-up controls, specified before correction on 2026-09-29:

- A suppressed SQL exception can return the same missing-ID body as a false
  predicate. Two validator-accepted nonexistent-function mutations must not
  receive extraction credit. A valid false predicate must still work when a
  complementary request proves that the same expression evaluates successfully.
  Failed, unchanged, or unavailable complementary controls stay negative.
- Finite bounded `SLEEP` arguments accepted by validation (exponents, signed
  values, trailing decimals, and block comments) must use the same numeric
  interpretation during timing verification. Invalid or excessive delays remain
  rejected before transport; repeatability and harmless controls still apply.
- A revisited method's saved queue can differ from freshly ranked order. Replay
  must accept unchanged membership/values/budget, execute in saved order, and
  still reject missing, duplicated, altered, or over-budget candidates.
- Replaying a later method must retain prior attempts, monotonic observations,
  score maxima, credentials, and accumulated request/timing/telemetry evidence.
  Its new verifier decision and surface attempt counts must match graph reducers.
- Resume at `chaining_router` must not invent an input from historical validation
  receipts or repeat a completed method. Resume before `payload_validator` must
  still capture its fresh receipt before the newly scheduled method executes.
- Forced-target and automatic controls must have distinct artifact and fixture
  paths. Running either must preserve the other's target identity and call count.

These controls save offline source/replay/fixture artifacts; baseline code hashes,
diff, failing JUnit, and logs belong in
`results/validation/review-fixes-2026-09-29/`. Live matrix evidence remains a
historical code epoch until independently revalidated after these repairs.

The review remediation suite passes 1,573 tests with two inapplicable medium
cases skipped, including all 31 review regression controls. The earlier
1,542-test suite, complete 297-coordinate live grid, and 185 generated-queue
comparisons remain evidence for the pre-review code epoch; live results have not
been revalidated after these fixes. Failing controls and original inputs are
retained beside corrected offline runs. See
[METHOD_AGENTS_TESTING_REPORT_2026-09-29.md](METHOD_AGENTS_TESTING_REPORT_2026-09-29.md)
for finite claims, uncertainties and repeatable evidence.
