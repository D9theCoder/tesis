# Remaining tasks (2026-09-17)

Continuation implementation is complete for R1, R2, and the selected R4
repairs. Full offline suite green (`1389 passed`), focused routing/config suite
green (`79 passed`), focused doctor/CLI/TUI/reasoning/diagnostics suite green
(`118 passed`), and offline doctor green (`11/11`, exit 0). The five commits
listed in Housekeeping predate this continuation; the continuation changes are
uncommitted and nothing was pushed. Detailed earlier verified/not-verified record:
[`docs/completed/HANDOFF_REASONING_DOCTOR_2026-09-17.md`](HANDOFF_REASONING_DOCTOR_2026-09-17.md).

## Continuation update (2026-09-19)

- **R1 complete offline**: unpinned roles retain `model_profile=None` and follow
  each matrix coordinate provider. Precedence is explicit role profile > global
  profile > coordinate provider. An offline two-provider matrix-boundary test
  proves distinct provider/model resolution.
- **R2 complete offline**: per-call records, the run artifact, `run.failed`, and
  `*.failure.json` carry the canonical redacted failure object. It includes the
  failure class, provider/model/profile/role, coordinate and call IDs, sanitized
  endpoint, timeout, attempts/retries, elapsed time, exception/cause, HTTP status,
  request ID, parse status, bounded provider message, and remediation. Simulated
  timeout, schema rejection, and quota rejection paths are covered without live
  calls.
- **R4 repairs complete**: V1, N5, N7, N8, N11, N12, and the child-coordinate
  TUI `Continuing` defect are fixed. The artifact schema lists in both summaries
  now match implemented names, and `repeat_index` is top-level for regular and
  synthetic matrix artifacts.
- **Accepted limitations**: N2 remains a validation-only axis for seed-only
  checks; N3 remains an offline scope-helper check rather than a live redirect;
  N9/N10 retain the current narrow structured-output fallback and canonical
  reasoning-field behavior. These do not weaken the runtime execution boundary.
- **Manual TUI startup verified**: `python -m tesis run` rendered the main menu
  in a real PTY and exited cleanly with `q`.
- **Contained DVWA live slice verified**: authentication passed, all three
  security levels (`low`, `medium`, `high`) passed, and all three in-scope
  surfaces (`sqli`, `access_control`, `brute_force`) passed. This command called
  `_dvwa_live_checks` directly so it did not contact the model provider.
- **R3 is explicitly INCOMPLETE**: the final `doctor --live`, real experiment
  matrix, completed-run artifact audit, and provider-side reasoning evidence were
  **not tested because the currently selected API endpoint has no quota**. Do not
  treat the offline routing/failure simulations as a completed experiment. Run
  the exact R3 commands only after provider quota is restored.

## Current hazards (read first)

- The selected model endpoint has no quota. Do not run the real matrix or use
  failed provider probes as experiment evidence until quota is restored.
- The old plaintext `test.py` probe is no longer present or tracked. Do not
  recreate or commit a probe containing a literal bearer token.
- V1 is fixed and regression-tested: rejected duplicate-key YAML no longer
  echoes either raw scalar through Doctor, dry-run, headless/matrix CLI, or TUI.

## Prior baseline TL;DR (superseded by the continuation update above)

- **Doctor module**: `tesis/doctor.py` + `tests/test_doctor.py` (untracked, 27 tests).
  `python -m tesis doctor [--config PATH] [--live] [--json]`; exit 0 passed / 1 failed / 2 usage error; 11 offline checks
  (`coverage.scope`, `akg.integrity`, `graph.compilation`, `payload.static_seeds`, `containment.http`,
  `config.profiles_roles`, `config.credentials`, `config.endpoints`, `environment.dependencies`,
  `output.writability`, `reasoning.controls`). Standalone — never invoked by the experiment runtime.
- **TUI reasoning effort** (`tesis/tui.py`, `tesis/config_fields.py`): distinct per-role efforts render as a mixed state and
  survive save byte-for-byte unless the user moves the global control; profile and global sliders are independent;
  pointer clicks map to the rendered marker track, not the whole widget.
- **Diagnostics/provider/config**: one canonical effort field on the wire with `temperature` stripped; legacy
  `reasoning` / `model_kwargs` / `extra_body` cannot override or duplicate an explicit effort; legacy effort selects the
  8192-token reasoning budget; no silent effort downgrade; chained-cause status/request-id extraction; full URL
  query+fragment redaction; Responses `incomplete` now raises; non-text content blocks skipped.
- **Docs reconciled against code**: `README.md`, `docs/reference/summary_en.md`, `docs/reference/summary_id.md`, `guide.md`.
- **Independent review + repair round**: 6 review defects fixed (URL userinfo leak, malformed-config exit contract,
  missing/directory config path naming, coverage conditions axis, env-provided endpoint, 20-column slider selection);
  +10 regression tests (doctor 18→27, TUI 16→17).
- **Full suite**: `1374 passed` (re-observed this session, 50.35 s).
- **Focused subset**: `99 passed` (re-observed: 27 doctor + 17 TUI + 31 reasoning-config + 24 diagnostics).
- **Doctor offline**: exit 0, exactly one JSON object on stdout, 0 bytes stderr, `{"failed":0,"passed":11,"skipped":0,"total":11}`.

## Remaining tasks

### R1 — COMPLETED OFFLINE: provider-axis routing

**Why**: the matrix `provider` axis is metadata-only. With top-level `provider: openai_compatible`, both roles resolve to
that profile and every coordinate runs the same model. Proven from the aborted matrices: all 130 LLM calls ran on
`openai_compatible` / `deepseek-v4.1-flash:free` with one identical `model_fingerprint`, including the 18 coordinates
declared `provider: openai`.

**Root cause (confirmed by direct load)**: `tesis/config_loader.py:928` computes `default_profile=model_profile or provider`
and `:711-712` materializes that fallback into each role (`RoleConfig(model_profile='openai_compatible', ...)` for both
roles from `config.yaml`, which pins no profile). At call time `llm/runtime.py:203`
(`profile = settings.model_profile or self.default_provider`) therefore prefers the materialized profile and the
coordinate's provider — wired in as `default_provider` at `llm/runtime.py:190` ← `evaluation/runner.py:398` ←
`evaluation/multi_llm_runner.py:770,793` — never wins. The loader must stop collapsing "not pinned" into "pinned".

**Files**: `tesis/config_loader.py` (default-profile assignment + per-role resolution), `llm/runtime.py`
(`role_config` role/base resolution), `evaluation/multi_llm_runner.py` (`execute_coordinate`).

**Acceptance**: a headless matrix routes each coordinate's roles to that coordinate's provider profile when the role does
not pin one; an offline test (no network) proves it; a documented precedence exists for roles that DO pin a profile.

**Verify**:
```bash
# offline proof (new test), then a real matrix once budget is back:
.venv/bin/python -m pytest tests/test_reasoning_config.py -q
.venv/bin/python -m tesis run --headless --mode matrix --config config.yaml --providers openai_compatible --json
```

### R2 — COMPLETED OFFLINE: richer provider-failure messages

**Why**: run-level failure text is unactionable and content-free. Observed in both matrices:
`"APITimeoutError: orchestrator model call failed; deterministic fallback output was retained for audit only"`
(26 coordinates) and `"LLM runtime failure: at least one provider call failed"` (3 coordinates)
(`evaluation/runner.py:603-604` and `:660`; both unchanged since HEAD, as is `evaluation/failure_logger.py`).
The per-call record has `status_code` and `request_id` keys but they are `null` on all 51 `provider_error` calls, and no
artifact anywhere records what a provider call actually dialed or returned: the only endpoint/status values present
(`config.model_config.base_url`, and the `endpoint`/`status_code` pairs in `execution_log`, `response_evidence` and
`timing_evidence`) belong to the configured profile echo and to DVWA HTTP responses. No provider error body, timeout in
effect, or retry/attempt count exists anywhere. A 401 `CreditsError` leaves no trace. Message-level provider-rejection vs
no-answer vs parser-rejection is indistinguishable; the 9 parse-rejected calls additionally record
`error_message: null` and `remediation: null`.

**Files**: `llm/runtime.py`, `llm/diagnostics.py` (extend `provider_error_details` / `format_provider_error`),
`evaluation/runner.py` (run-level `error` + `run.failed` message), `evaluation/failure_logger.py`, `agents/orchestrator.py`
(fallback text).

**Acceptance**: a failing coordinate's `*.failure.json` and the `run.failed` event carry endpoint, failure class,
exception class, cause class, elapsed ms, timeout, http status (when one exists) and a redacted provider error snippet,
with an actionable one-line message.

**Verify**: force one failing coordinate against an unroutable endpoint and diff the two artifacts for the new fields.

### R2 design — what each layer emits today

- **Per-call runtime record** (`llm/runtime.py`): already rich — `provider`, `model`, `role`, `coordinate_id`,
  `call_id` (`<coordinate>:<role>:<n>`), `error_type`, `cause_type`, `status_code`, `request_id`, `error_message`
  (redacted, ≤800), `call_duration_ms`, `parse_status`, `reasoning_effort_requested`, `provider_usage`, `remediation`.
  Capability proven by simulation: a real 401 `APIStatusError` produced `status_code=401`, `request_id=req_live_123`
  and the `CreditsError` body. On the aborted matrices all 51 `provider_error` calls recorded `status_code=null` /
  `request_id=null` because a `ReadTimeout` carries no HTTP metadata — but the loss that matters happens next.
- **Thin callback event** (`evaluation/runner.py:141-150`): `llm.failed` with `data={provider, call_id(UUID), error_type}`
  — a LangChain run UUID, a different id namespace from the runtime's `call_id` (join friction; 49 journal rows for 25
  real failures).
- **Orchestrator fallback** (`agents/orchestrator.py:597-615`): `fallback_events` entry + telemetry carry only
  `error_type` and `next_agent`; the rich provider text goes only to the process log.
- **Run level** (`evaluation/runner.py:603-606` and `:660`): the two class-blind sentences quoted above — no
  provider/model/role/coordinate/endpoint/status/timeout/attempts, even though the rich rows sit in the same artifact
  (`llm_performance`) unreferenced.
- **`*.failure.json`** (`evaluation/failure_logger.py:22-29`): `error` + `final_state` counts + audit lists; it does not
  embed the failing call, so the "one file to read" is not the file with the answer.
- **`run.failed` event and TUI**: `data={error_type, reason}`; the failure pane renders message + node only.

### R2 design — canonical failure shape

One `failure` object, identical in the per-call record, the run artifact, the event data, the failure sidecar and the
rendered log line, plus one single-line message derived from it.

| field | today | source / change |
| --- | --- | --- |
| `failure_class` | new (derived) | one helper beside the record builder (`llm/runtime.py:705-737`) from `parse_status` + `status_code` + `cause_type`; values: `transport_timeout`, `transport_error`, `http_rejected`, `schema_rejected`, `output_truncated`, `provider_error_unknown` |
| `provider`, `model`, `role` | yes | record (`llm/runtime.py:534-536`) |
| `model_profile` | add | already resolved by `CoordinateCallContext.role_config` (`llm/runtime.py:201-208`) |
| `coordinate_id`, `call_id` | yes | record (`llm/runtime.py:537-538`) |
| `run_id` | run level only | add to the block |
| `endpoint` | add | `config.get('base_url')` (`llm/runtime.py:510-512`, `ModelConfig.base_url`), userinfo stripped |
| `timeout_s` | add | `config.get('timeout')` (`config.model_config.timeout` = 60) |
| `attempts`, `max_retries` | add | one invoke per `call_id` (`llm/runtime.py:559-690`); retries from the profile (`llm/provider.py` defaults) |
| `elapsed_ms`, `error_type`, `cause_type`, `http_status`, `request_id`, `parse_status` | yes (when present) | record (`llm/runtime.py:711-733`; `llm/diagnostics.py:95-162`) |
| `message` | yes on `provider_error` | record (`llm/runtime.py:734`); also populate when `parse_status=invalid` from the `LLMOutputError` text (`llm/runtime.py:637-689`) |
| `remediation` | yes on `provider_error` | record (`llm/runtime.py:736`, `llm/diagnostics.py:108-127`); add a quota/billing branch (body or error type contains `insufficient`/`quota`/`balance`/`credits`/`billing`) so a 401 `CreditsError` is not answered with "check the credential" |

```json
{"failure": {"failure_class": "http_rejected", "provider": "openai_compatible", "model": "deepseek-v4.1-flash:free", "model_profile": "openai_compatible", "role": "orchestrator", "run_id": "openai_compatible-sqli-low-hybrid-0", "coordinate_id": "exec-20260917T143332826474Z-decfc2e1753e4fc1acc0f806c3103fd2", "call_id": "exec-20260917T143332826474Z-decfc2e1753e4fc1acc0f806c3103fd2:orchestrator:1", "endpoint": "https://tokenharbor.ai/v1", "timeout_s": 60, "attempts": 1, "max_retries": 0, "elapsed_ms": 812, "error_type": "APIStatusError", "cause_type": null, "http_status": 401, "request_id": "req_live_123", "parse_status": "provider_error", "message": "Error code: 401 - {'error': {'message': 'Insufficient balance', 'type': 'CreditsError'}}", "remediation": "Provider account/budget rejection: top up quota or use another profile; a retry alone will not succeed."}}
```

**Human template**:

```text
{failure_class_verb}: {role} {provider}/{model} @{endpoint} {outcome} after {elapsed_ms} ms (http={http_status|none}, request_id={request_id|none}, timeout={timeout_s}s, attempts={attempts}/retries={max_retries}, parse={parse_status}) [run={run_id} call={call_id}] - {message} | remediation: {remediation}
```

Verbs: `transport_timeout` → "stalled", `transport_error` → "was unreachable", `http_rejected` → "rejected the request",
`schema_rejected` → "answered but the payload was rejected by our schema", `output_truncated` → "hit the output limit",
`provider_error_unknown` → "failed". Render the line at ≤400 chars (the record keeps the 800-char redacted message).
Secrets: endpoint as `scheme://host[:port]` with userinfo stripped (same rule `tesis/doctor.py` now uses); the message
already passes `redact_diagnostic_text`; the runner re-redacts every event payload via `redact_secrets`.

### R2 design — worked examples

**Transport stall** (matrix-14 run-010, `https://tokenharbor.ai/v1`, timeout 60 s, observed 75 082 ms):

```text
transport_timeout: orchestrator openai_compatible/deepseek-v4.1-flash:free @https://tokenharbor.ai/v1 stalled after 75082 ms (http=none, request_id=none, timeout=60s, attempts=1/retries=0, parse=provider_error) [run=openai_compatible-brute_force-low-static_only-0 call=exec-20260917T143332827566Z-f254e6680e27449ea78c16a58e93c896:orchestrator:1] - Request timed out. | remediation: Check provider reachability and timeout settings, then retry the affected coordinate.
```

```json
{"event_type": "run.failed", "run_id": "openai_compatible-brute_force-low-static_only-0", "node": "orchestrator", "message": "<the line above>", "data": {"reason": "LLM_RUNTIME_FAILURE", "failure_class": "transport_timeout", "failure": {"failure_class": "transport_timeout", "provider": "openai_compatible", "model": "deepseek-v4.1-flash:free", "model_profile": "openai_compatible", "role": "orchestrator", "endpoint": "https://tokenharbor.ai/v1", "timeout_s": 60, "attempts": 1, "max_retries": 0, "elapsed_ms": 75082, "error_type": "APITimeoutError", "cause_type": "ReadTimeout", "http_status": null, "request_id": null, "parse_status": "provider_error", "message": "Request timed out.", "remediation": "Check provider reachability and timeout settings, then retry the affected coordinate."}, "llm_activity": {"started": 3, "completed": 2, "failed": 1, "tokens": 0}}}
```

Why better: today's string omits the endpoint, the 60 s budget versus the 75 s elapsed time, that no HTTP answer ever
arrived, that no retry happened, and which coordinate/model was involved — the new line answers all of it in one row.

**Quota rejection** (the observed `openai`-profile 401, field mapping simulated with the real SDK exception):

```text
http_rejected: orchestrator openai/deepseek-v4.1-flash:free @https://tokenharbor.ai/v1 rejected the request after 812 ms (http=401, request_id=req_live_123, timeout=60s, attempts=1/retries=0, parse=provider_error) [run=openai-sqli-low-hybrid-0 call=exec-…:orchestrator:1] - Error code: 401 - {'error': {'message': 'Insufficient balance', 'type': 'CreditsError'}} | remediation: Provider account/budget rejection: top up quota or use another profile; a retry alone will not succeed.
```

Why better: today this case is invisible twice over — the run level would print the same class-blind "model call failed"
sentence as a timeout, and the 401 existed only in the live doctor's stdout at that moment (`grep` for
`CreditsError`/`quota`/`balance` over all 134 run-artifact files returns 0 hits).

### R2 design — triage rule readable from the message alone

- `http=401`/`403` → credential or entitlement, not transient; check the profile's key reference.
- `http=402`/`429`, or the message contains `insufficient`/`quota`/`balance`/`credits` → budget wall; retrying is
  pointless until the account is topped up or the profile is switched.
- `http=none` + `cause_type` in `{ReadTimeout, ConnectTimeout}` + `elapsed_ms >= timeout_s*1000` → endpoint stalled at or
  past its read deadline; **quota cannot be inferred from this** (matrix-14: 24 calls at 60–75 s against `timeout=60`).
- `http=none` + `{ConnectError, DNS/name-resolution}` → endpoint unreachable or misconfigured; compare the printed
  endpoint with the intended `base_url`.
- `http=400`/`422` → request shape (params, reasoning support, structured-output capability).
- `http=404` → endpoint path or model name.
- `http>=500` → provider-side failure; retry with the printed `request_id`.
- `parse=invalid` **with** `provider_usage` populated → the provider answered and was billed; our parse/schema rejected
  it — fix the prompt/schema, not the account.
- `parse=incomplete` → output limit; raise the role's `max_tokens`.
- `attempts=1`/`retries=0` → no retry was performed by design; a manual re-run is the first remedy.

### R2 design — smallest slice with the biggest gain

1. `llm/runtime.py`: add `endpoint`, `timeout_s`, `attempts`, `max_retries`, `model_profile`, `failure_class` to the base
   record and the failure branch, and to the `emit_activity` whitelist (`llm/runtime.py:230-278`) — ~25 lines, no
   behavior change.
2. `evaluation/runner.py`: one helper that formats the canonical line from the first failed record in
   `call_context.records` (available at `:907`), used for `error` in branches A and B and for the `run.failed`
   message + data — ~20 lines.
3. `evaluation/runner.py` + `evaluation/failure_logger.py`: pass `failure=<block>` into `*.failure.json` — ~5 lines.

Migration: additive (new record/event/sidecar keys; the TUI already prints event data verbatim, and the artifact
required-field check is a name list). The one human-facing change is the run-level `error` text; no test asserts either
old string and nothing parses it as structured data, so keep `error` as the canonical one-line string so existing greps
still work. Deliberately **not** now: per-coordinate error rows in the matrix aggregate
(`evaluation/multi_llm_runner.py:145-230`) and merging the thin UUID-keyed `llm.failed` record (touches the counting
semantics documented in the detailed handoff).

### R3 — INCOMPLETE: restore provider budget, then complete the evidence

**Why**: no successful experiment exists. Live doctor and a completed matrix were never finished. Both matrices are
`status=active` with `manifest_path: null` (`heartbeat_at` `2026-09-17T14:58:21.983513+00:00` / `…:19.969377+00:00`);
33 coordinate artifacts exist, of which 29 are `LLM_RUNTIME_FAILURE` and 4 `success`; 51 provider calls died as
`cause_type=ReadTimeout` after 60012–75662 ms against a 60 s configured timeout. A probe proved a 401
`CreditsError: Insufficient balance` on the `openai` profile and read timeouts on `openai_compatible`, so
provider/environment failure was never separated from harness defect.

**Verify**:
```bash
.venv/bin/python -m tesis doctor --config config.yaml --live --json
.venv/bin/python -m tesis run --headless --mode matrix --config config.yaml --providers openai_compatible --json
```
Then audit the newest `results/runs/` matrix directory against the AGENTS.md artifact-field list.

### R4 — Disposition of known limitations

- **N2 — accepted**: the payload-mode axis is validation-only for seed-only
  checks. Generated runtime modes still use their distinct generation paths.
- **N3 — accepted**: the offline containment check exercises request and
  redirect scope helpers, not a live redirect server.
- **N5 — fixed**: URL redaction preserves semicolon-delimited prose and trailing
  punctuation while redacting query/fragment values and URL userinfo.
- **N7 — fixed**: Doctor imports the shared runtime provider-capability rule;
  custom providers with an unsupported explicit effort now fail the check.
- **N8 — fixed**: secret discovery runs through a safe check and returns a
  structured `config.redaction` failure instead of aborting Doctor.
- **N9/N10 — accepted**: the narrow structured-output fallback and canonical
  Chat reasoning field remain intended; conflicting legacy keys are not sent.
- **N11 — fixed**: typed config now carries DVWA username/password, including
  environment overrides, and Doctor receives the resolved values.
- **N12 — fixed offline**: both summaries use the implemented artifact names,
  and regular plus synthetic artifacts carry top-level `repeat_index`. The
  completed-run audit remains part of R3.
- **V1 — fixed**: malformed/duplicate-key loader messages retain the problem,
  duplicate key, and source line while removing raw scalar values across every
  doctor/CLI/TUI surface.
- **TUI child-failure status — fixed**: a child coordinate's `run.failed` shows
  `Continuing: True`; only a matrix-parent terminal event shows `False`.
- **Slider re-selection — accepted**: re-selecting the current slider value
  does not emit `Changed`; consumers already recompute from widget state.

### R5 — Unverified items that remain after the continuation

- **Provider-side reasoning execution is unproven.** The one live probe reported `reasoning_tokens=not_reported` /
  `provider_side_reasoning=unverified`; only request-side serialization is asserted. A setting proves the request, not
  that the provider reasoned.
- **Manual terminal startup is now verified.** The real TUI rendered its main
  menu in a PTY and exited cleanly; no experiment was started.
- **No completed-run artifact audit.** The AGENTS.md field-list audit was performed only against the aborted matrices.
- Live doctor evidence is a single run from a cancelled session (16 checks: 11 offline + 2 `live.model.*` role probes +
  3 `live.dvwa.*`; 15 passed, 1 failed on the harness-handled
  `LLMOutputError: native structured output did not return an object`) and was not repeated on the final tree.
  The three contained `live.dvwa.*` checks were repeated separately on
  2026-09-19 and all passed; the two `live.model.*` checks were not repeated
  because the selected endpoint has no quota.

## Historical drift audit against the frozen record (2026-09-17)

`docs/completed/HANDOFF_REASONING_DOCTOR_2026-09-17.md` stays frozen as the evidence record; the corrections live here.

**Matching — no drift at that time.** The recorded `git status --porcelain` block was identical to that session's (plus
this then-new file). `pytest -q` => `1374 passed in 51.36 s` (recorded 51.63 s). Offline doctor: exit 0, one JSON object, 0 bytes
stderr, `{"failed":0,"passed":11,"skipped":0,"total":11}`. The cited sites resolve as recorded: `tesis/cli.py:263`,
`tesis/tui.py:2519`, `tesis/doctor.py:508,643-644,930`, `tesis/config_loader.py:711-712,928`, `llm/runtime.py:190,203`,
`evaluation/runner.py:398`; `run_doctor` still has exactly those two call sites and neither is on the runtime path. No
file in the change set was modified after the record was written (newest is `tests/test_doctor.py` at 22:18:11, record
written 22:29:45 +0700), so none of its numbers are stale-by-edit.

**Drift found (4).**
1. `test.py`: prose says untracked, but the record's own porcelain block shows `A  test.py` and the index really has it
   staged. See Housekeeping.
2. N8 was tied to the config-echo disclosure; they are separate defects and the prescribed fix does not apply. See **V1**.
3. The TUI "Continuing" line span was wrong (`:1640-1645` → `:1637`). Fixed in R4.
4. The record's "What changed on disk" omits six runtime-affecting changes visible in the diff, so a reader would
   underestimate the blast radius: (a) typed token-limit forwarding fixed, `max_output_tokens` → `max_tokens`
   (`llm/provider.py:83-87`, `:235-238`); (b) `_structured_output_unsupported` narrowed, so non-`{400,404,422}` statuses
   and auth/rate-limit/timeout/connection markers no longer trigger the native→json_prompt fallback
   (`llm/runtime.py:436-455`); (c) failure records and the `llm.failed`/`llm.completed` events gained `model`,
   `coordinate_id`, `reasoning_effort_requested`, `reasoning_token_evidence`, failure `provider_usage` and
   `status_code`/`request_id`/`cause_type`/`error_message`/`remediation`/`incomplete_reason`
   (`llm/runtime.py:244-276`, `:717-737`); (d) `prompt_hash` now folds in `reasoning_effort` (`llm/runtime.py:527`), so
   cache keys and artifact hashes differ from pre-change runs; (e) `_default_api_key` now resolves
   `ANTHROPIC_API_KEY`/`CLAUDE_API_KEY` for `claude` (`tesis/config_loader.py:480-481`); (f) an effective effort forces
   an 8192 role token default (`tesis/config_loader.py:735-747`).

**Experiment-path impact of the uncommitted change set.** On the path: `config.yaml`, `llm/provider.py`,
`llm/runtime.py`, `llm/diagnostics.py`, `tesis/config_loader.py`, `tesis/cli.py`; indirectly `tesis/tui.py` +
`tesis/config_fields.py` (they save `config.yaml` and pass the run override). Off the path: `tesis/doctor.py`, `tests/*`,
all `*.md`, `test.py`, `tesis/model_config.py` (new field defaults to `None`), and `core/knowledge_graph.py` — there the
change is exception type only: `AKGValidationError` subclasses `ValueError`, every raise condition and threshold is
unchanged, and `evaluation/runner.py:162-165` already catches `ValueError`. Untouched entirely: `evaluation/`, `agents/`,
`foundation/`, `core/graph_builder.py`, `core/state.py` — graph topology, state schema, scoring, artifact writers and
containment are unchanged. Consequence to remember before rerunning the matrix: `config.yaml` now carries
`reasoning_effort` (medium/high) and `max_tokens: 8192`, and `temperature` is omitted whenever an effort is present
(`llm/provider.py:74`), so post-change runs are **not directly comparable** with pre-change runs.

## How to re-verify quickly

```bash
.venv/bin/python -m pytest -q
# current expectation: 1389 passed

.venv/bin/python -m tesis doctor --config config.yaml --json
# expect: exit 0, exactly one JSON object on stdout, 0 bytes stderr,
#         status=passed, summary {"failed":0,"passed":11,"skipped":0,"total":11}

git status --porcelain
# expect: the continuation files listed in the 2026-09-19 update to be modified;
#         the baseline doctor files are tracked in the five local commits.
```

## Housekeeping

- The baseline work is in five local commits (`5998e24` through `5ed18f9`), and
  the branch is five commits ahead of its upstream. The 2026-09-19 continuation
  is uncommitted. **No push was performed.**
- `test.py` is absent and is not tracked. `tesis/doctor.py` and
  `tests/test_doctor.py` are tracked by the earlier baseline commits.
- `config.yaml` has only a documentation-comment change in this continuation;
  its provider credentials/settings were not changed.
- Do not modify `docs/completed/HANDOFF_REASONING_DOCTOR_2026-09-17.md`; it is the evidence record for this change set.
