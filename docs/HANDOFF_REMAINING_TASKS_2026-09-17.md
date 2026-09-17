# Remaining tasks (2026-09-17)

Implementation complete. Full offline suite green (`1374 passed`), focused subset
green (`99 passed`), offline doctor green (`11/11`, exit 0). Nothing is committed
(no commit, no push). No live provider budget was available, so no `--live` run
and no completed matrix exist. Detailed verified/not-verified record:
[`docs/HANDOFF_REASONING_DOCTOR_2026-09-17.md`](HANDOFF_REASONING_DOCTOR_2026-09-17.md).

## Hazards (read first)

- **Do not commit `test.py` as-is.** `git status --porcelain` shows `A  test.py` — it is already staged, and its content
  is a one-off probe posting to `https://tokenharbor.ai/v1/chat/completions` with a live bearer token in plaintext, so a
  commit publishes that credential. Unstage or delete it first (details: Housekeeping).
- **V1 — a rejected config echoes raw YAML scalars** into the doctor report, the dry-run/headless/**matrix** stderr and
  the TUI (`tesis/doctor.py:974`, `tesis/cli.py:77,239`, `tesis/tui.py:931,1100,1107,1909,2054,2470`). Reproduced with a
  duplicated `api_key` key: both scalars appear verbatim. Impact and the correct fix — sanitize the loader text; a
  secrets tuple is unobtainable there and plain redaction misses `thk_live_…` — are in R4/V1.

## TL;DR — what completed

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
- **Docs reconciled against code**: `README.md`, `docs/summary_en.md`, `docs/summary_id.md`, `guide.md`.
- **Independent review + repair round**: 6 review defects fixed (URL userinfo leak, malformed-config exit contract,
  missing/directory config path naming, coverage conditions axis, env-provided endpoint, 20-column slider selection);
  +10 regression tests (doctor 18→27, TUI 16→17).
- **Full suite**: `1374 passed` (re-observed this session, 50.35 s).
- **Focused subset**: `99 passed` (re-observed: 27 doctor + 17 TUI + 31 reasoning-config + 24 diagnostics).
- **Doctor offline**: exit 0, exactly one JSON object on stdout, 0 bytes stderr, `{"failed":0,"passed":11,"skipped":0,"total":11}`.

## Remaining tasks

### R1 — Provider-axis routing defect (blocks every provider-axis experiment)

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

### R2 — Richer provider-failure messages

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

### R3 — Restore provider budget, then complete the evidence

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

### R4 — Known limitations to accept or fix

- **N2** — payload-mode axis is inert for seed-only validation. `evaluation/` seed-only path. Low. Accept or mark the
  axis as validated-only for that mode.
- **N3** — containment check exercises the scope helper (`client._assert_in_scope`, request/redirect kinds), not a live
  redirect. `tesis/doctor.py` `containment.http`. Low. Add a live redirect fixture or document the limitation.
- **N5** — URL redaction over-consumes into the tail of the query string. `llm/diagnostics.py`. Low. Tighten the
  component split.
- **N7** — duplicated provider-capability literal: `tesis/doctor.py:508` hardcodes `{"gemini", "claude"}`, but the real
  runtime rule is broader — `llm/provider.py:45` (`_reasoning_kwargs`) rejects an explicit effort for **any** provider
  outside `{openai, openai_compatible}`, so a `deepseek`/custom profile carrying an effort raises at call time while the
  doctor's `reasoning.controls` check stays silent. Low. Import the provider rule from `llm/provider.py`, not just the
  literal.
- **N8** — `_known_secrets` is evaluated outside `_safe_check` (`tesis/doctor.py:930`, which does pass
  `secrets=_known_secrets(config)`). Low-Medium robustness gap: an exception raised while deriving the secrets escapes
  the check wrapper. Wrap it. (Not the same defect as **V1** below, which is about the *failed-load* path.)
- **N9/N10** — structured-output fallback breadth; legacy `reasoning` keys are discarded on the Chat path.
  `llm/runtime.py` / `llm/provider.py`. Low. Document, or map the legacy keys onto the canonical field.
- **N11** — DVWA credentials read with `admin`/`password` defaults because `EngagementConfig` carries no `dvwa_*` fields
  (`tesis/doctor.py:643-644`). Low. Add the fields or document the default.
- **N12** — pre-existing artifact-schema drift across the two summaries and `AGENTS.md`. Docs only. Low. Reconcile in one
  pass with the R3 artifact audit.
- **V1 — config-load rejection echoes raw YAML scalars (reproduced independently; wider than first recorded)**. The
  disclosure is not doctor-only: every surface that prints the loader error echoes it — `tesis/doctor.py:974`
  (`_build_report([check])`, no `secrets=`), `tesis/cli.py:77` (dry run), `tesis/cli.py:239` (headless **and matrix**),
  `tesis/tui.py:931,1100,1107,1909,2054,2470`. Reproduced with a duplicated `api_key` key: both scalars appear verbatim
  in `doctor --json` **and** in the human report (exit 1, 0 bytes stderr).
  Impact Medium (a run's stderr carries it, not just the doctor), trigger narrow (malformed/duplicate-key YAML only).
  The fix prescribed in the previous revision ("pass the secrets tuple") does not work: `_config_error_report` runs
  *because* the config failed to load, so no resolved config exists to derive secrets from, and `redact_diagnostic_text`
  covers only some shapes — measured on this exact message it redacts `sk-live-…` (its `sk-` pattern) and
  `api_key: <value>`, but leaves `thk_live_…` intact. Correct fix: stop embedding the raw loader text — sanitize the
  exception string (redact quoted scalars after `with value`/`original value`, generalize the key-shape patterns), or
  report only the problem class plus YAML line/column. Distinct from **N8**: N8 is `_known_secrets` being called outside
  `_safe_check` at `tesis/doctor.py:930`, which does pass `secrets=_known_secrets(config)` on the success path.
- **NEW (review round)** — a click that re-selects the already-selected slider value no longer emits `Changed`
  (`tesis/tui.py:281` `state_changed = index != self._index or self._mixed`, guarded at `:287`), even though
  `_user_changed` is still set. Benign: the only consumer recomputes from widget state. Accept as-is; no action.
- **NEW (R2 design review)** — the TUI failure pane keys "Continuing" on `event_type` alone (`tesis/tui.py:1637`, in the
  `_consume_runtime_event` pane update at `:1631-1638`; the first revision cited `:1640-1645`, which is the unrelated
  `_set_stage`), so a forwarded child-coordinate `run.failed` renders `Continuing: False` while the matrix keeps running
  — `_SerializedSink.emit` forwards the child event verbatim (`evaluation/multi_llm_runner.py:519-528`). Low-Medium:
  misleading live status for a watcher. Fix by checking whether the failing run is the matrix itself before setting the
  flag.

### R5 — Unverified items that remain

- **Provider-side reasoning execution is unproven.** The one live probe reported `reasoning_tokens=not_reported` /
  `provider_side_reasoning=unverified`; only request-side serialization is asserted. A setting proves the request, not
  that the provider reasoned.
- **No manual terminal check of the TUI.** All TUI verification is Textual-test-harness only (plus the 20-column
  regression). Run the real TUI once by hand on the final tree.
- **No completed-run artifact audit.** The AGENTS.md field-list audit was performed only against the aborted matrices.
- Live doctor evidence is a single run from a cancelled session (16 checks: 11 offline + 2 `live.model.*` role probes +
  3 `live.dvwa.*`; 15 passed, 1 failed on the harness-handled
  `LLMOutputError: native structured output did not return an object`) and was not repeated on the final tree.

## Drift audit against the frozen record (verified this session)

`docs/HANDOFF_REASONING_DOCTOR_2026-09-17.md` stays frozen as the evidence record; the corrections live here.

**Matching — no drift.** The recorded `git status --porcelain` block is identical to today's (plus this new untracked
file). `pytest -q` => `1374 passed in 51.36 s` (recorded 51.63 s). Offline doctor: exit 0, one JSON object, 0 bytes
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
# expect: 1374 passed

.venv/bin/python -m tesis doctor --config config.yaml --json
# expect: exit 0, exactly one JSON object on stdout, 0 bytes stderr,
#         status=passed, summary {"failed":0,"passed":11,"skipped":0,"total":11}

git status --porcelain
# expect: the changed-file list in the detailed handoff, plus
#         ?? docs/HANDOFF_REMAINING_TASKS_2026-09-17.md
#         (still uncommitted; tesis/doctor.py and tests/test_doctor.py untracked)
```

## Housekeeping

- Everything is uncommitted. **No commit, no push.**
- `config.yaml` (modified, staged) and `test.py` are pre-existing user files — leave them alone. **Correction to the
  earlier wording: `test.py` is not untracked — `git status --porcelain` shows `A  test.py`, i.e. already staged as a new
  file.** Its content is a one-off probe posting to `https://tokenharbor.ai/v1/chat/completions` with a live bearer token
  in plaintext, so a commit would publish that credential: unstage/exclude it before committing (it is also the probe
  behind the recorded 401 `CreditsError` evidence). It is not collected by pytest: `pyproject.toml` has no
  `[tool.pytest.ini_options]`, so the default `test_*.py` / `*_test.py` patterns apply and `test.py` matches neither.
- `tesis/doctor.py` and `tests/test_doctor.py` are untracked and must be added by the user's own commit.
- Do not modify `docs/HANDOFF_REASONING_DOCTOR_2026-09-17.md`; it is the evidence record for this change set.
