# Mini handoff: reasoning controls, diagnostics, and the doctor module (2026-09-17)

Status: implementation complete, full offline suite green, independent review
complete and its defects repaired. Live and matrix evidence remains limited (see
below). All changes are uncommitted.

## What changed on disk

- **New `tesis/doctor.py` + `tests/test_doctor.py`** (both still untracked).
  Standalone diagnostics module: `run_doctor(config, live=False)` returns
  `{status, summary{passed,failed,skipped,total}, checks[{id,category,status,summary,details,remediation}]}`.
  CLI: `python -m tesis doctor [--config PATH] [--live] [--json]`; exit 0 passed /
  1 failed / 2 usage error. The doctor is standalone: it never runs automatically
  before an experiment, and it adds no automatic provider preflight or quarantine.
- **TUI reasoning-effort controls** (`tesis/tui.py`, `tesis/config_fields.py`):
  distinct per-role efforts (including one explicit plus one inherited) render as
  a mixed state and are preserved byte-for-byte on save unless the user moves the
  global control. Profile-level and global role sliders are independent. Pointer
  clicks map onto the rendered marker track, not the whole widget.
- **Diagnostics / provider / config** (`llm/diagnostics.py`, `llm/provider.py`,
  `llm/runtime.py`, `tesis/config_loader.py`, `tesis/model_config.py`,
  `tesis/cli.py`):
  - chained-cause status and request-id extraction;
  - ALL URL query and fragment values redacted (named pairs keep their names,
    bare segments are replaced);
  - Responses `incomplete` output now raises instead of accepting valid-looking
    JSON;
  - list/block content extraction skips non-text blocks;
  - legacy `reasoning` / `model_kwargs` / `extra_body` cannot override or
    duplicate an explicit effort;
  - legacy effort selects the 8192-token reasoning budget;
  - no silent effort downgrade;
  - exactly one effort field on the wire, with temperature removed.
- **Documentation reconciled against code**: `README.md`,
  `docs/reference/summary_en.md`, `docs/reference/summary_id.md`, `guide.md`.
- Also on disk from this change set: `core/knowledge_graph.py` (actionable
  `AKGValidationError`), `tests/test_diagnostics.py`,
  `tests/test_reasoning_config.py`, `tests/test_tui.py`.

### Changed-file list

Verbatim `git status --porcelain` at the time of writing:

```
MM README.md
M  config.yaml
M  core/knowledge_graph.py
AM docs/HANDOFF_REASONING_DOCTOR_2026-09-17.md
MM docs/summary_en.md
MM docs/summary_id.md
 M guide.md
AM llm/diagnostics.py
MM llm/provider.py
MM llm/runtime.py
M  tesis/cli.py
M  tesis/config_fields.py
MM tesis/config_loader.py
M  tesis/model_config.py
MM tesis/tui.py
A  test.py
AM tests/test_diagnostics.py
AM tests/test_reasoning_config.py
MM tests/test_tui.py
?? tesis/doctor.py
?? tests/test_doctor.py
```

## Verified

- **Full suite**: `.venv/bin/python -m pytest -q` => **1374 passed in 51.63 s**,
  0 failures. That is +10 tests over the 1364 reported before the repair round
  (see the test-count delta below).
- **Focused verification subset**:
  `.venv/bin/python -m pytest tests/test_doctor.py tests/test_tui.py tests/test_reasoning_config.py tests/test_diagnostics.py -q`
  => **99 passed in 18.35 s** (27 doctor + 17 TUI + 31 reasoning-config + 24
  diagnostics). `.venv/bin/python -m pytest tests/test_doctor.py -q` => 27 passed
  (the previous revision of this document recorded 18; the repair round added 9
  doctor tests and 1 TUI test, which reconciles 1364 + 10 = 1374).
- **Offline doctor**: `.venv/bin/python -m tesis doctor --config config.yaml --json`
  => exit 0, exactly one line/one JSON object on stdout, 0 bytes on stderr,
  `status=passed`, `{"failed":0,"passed":11,"skipped":0,"total":11}`, with the same
  11 check ids: `coverage.scope`, `akg.integrity`, `graph.compilation`,
  `payload.static_seeds`, `containment.http`, `config.profiles_roles`,
  `config.credentials`, `config.endpoints`, `environment.dependencies`,
  `output.writability`, `reasoning.controls`. Human form exits 0 and ends
  `Doctor summary: 11 passed, 0 failed, 0 skipped, 11 total`. Reported coverage:
  3 surfaces, 9 methods, 3 security levels, 3 payload modes, 2 experiment
  conditions; 81 payload coordinates; 438 validation rows.
- **Doctor exit-code contract**: an unknown flag exits **2** (usage error on
  stderr, no stdout). Malformed scalar configs, a missing config path, and a
  directory config path each exit **1** with exactly one JSON object, 0 bytes on
  stderr (no traceback), and the offending path named in
  `checks[0].details` (`config_path=/tmp/bad_scalar.yaml`;
  `ConfigError: Invalid YAML in /tmp: [Errno 21] Is a directory: '/tmp'`).
- **No automatic invocation**: the only `run_doctor` call sites are
  `tesis/cli.py:263` (explicit `doctor` subcommand) and `tesis/tui.py:2519`
  (explicit offline/live doctor buttons). Nothing in the experiment runtime path
  calls it.
- **No network in offline mode**: with an audit hook installed,
  `load_and_resolve_config` + `run_doctor(cfg, live=False)` produced
  `socket.connect` = 0 and `socket.getaddrinfo` = 0 events; a broader hook saw
  only `socket.__new__` and one loopback `socket.bind(('::1', 0))`.
- **Env-provided endpoint**: with `OPENAI_COMPATIBLE_BASE_URL` exported and the
  profile supplying its own `base_url`, the run still exits 0 with 11/11 and
  `config.endpoints` passed (`endpoint_sources=openai=config,openai_compatible=config`).
  The variable is consulted only when the profile has no endpoint
  (`tesis/doctor.py:380-412`); that env-provided case is covered by
  `tests/test_doctor.py`.
- **TUI reasoning-effort controls**: mixed per-role state rendered and preserved,
  profile-level and global sliders independent, pointer mapping onto the rendered
  marker track (regression `test_reasoning_slider_narrow_track_selects_the_rendered_marker`
  drives the app at a 20-column size).
- **Diagnostics/provider/config**: chained-cause status/request-id extraction,
  full URL query/fragment redaction, Responses `incomplete` raising, non-text
  block skipping, legacy-effort precedence and non-duplication, 8192-token legacy
  budget, no silent downgrade, single effort field on the wire without
  temperature.
- **Documentation** reconciled against code in `README.md`,
  `docs/reference/summary_en.md`, `docs/reference/summary_id.md`, `guide.md`.
- **Hygiene**: `git diff --check` and `git diff --cached --check` both exit 0.
  `tesis/doctor.py` and `tests/test_doctor.py` remain untracked.
- **DVWA reachable** at `http://172.19.48.1/dvwa`.

## Independent verification chain

- An independent semantic review (separate session, no edits) confirmed claims
  2, 3, 4, 5 outright and returned PARTIAL for claims 1, 6, 7 with concrete
  defects. Its evidence highlights: offline doctor performs zero network syscalls
  and exits 0 against unroutable endpoints; the doctor has no automatic
  invocation anywhere in the runtime path; wire-level payloads show exactly one
  canonical effort field and no temperature for Chat (`reasoning_effort`) and
  Responses (`reasoning`), with legacy `model_kwargs` / `extra_body` / `reasoning`
  unable to override or duplicate it; precedence CLI > env > role > profile;
  explicit null suppresses stale legacy effort; 8192 default only when an effort
  is effective; unsupported providers raise. The zero-syscall, no-auto-invocation
  and env/precedence-adjacent results above were re-verified directly in this
  session.
- All six defects that review found were then fixed and independently reproduced
  by a different session with its own scripts and subprocess CLI runs:
  1. report no longer leaks URL userinfo and prints host-only;
  2. malformed scalar configs now yield exit 1 + exactly one JSON object + no
     traceback;
  3. missing/directory config paths name the path;
  4. the coverage conditions axis now follows the loader registry;
  5. env-provided `OPENAI_COMPATIBLE_BASE_URL` passes `config.endpoints`;
  6. a 20-column TUI selects exactly the rendered marker cell.
  10 regression tests were added (doctor 18 -> 27, TUI 16 -> 17). No new
  behavioral regression was found. Items 2, 3, 5, 6 were re-verified directly
  here as described under Verified.
- A prior verifier session (cancelled) ran `doctor --live` once: 16 checks,
  15 passed, 1 failed. `live.model.orchestrator` passed
  (`provider_responded=true`, `requested_effort=high`,
  `reasoning_tokens=not_reported`, `provider_side_reasoning=unverified`);
  `live.model.payload_generator` failed with the harness-handled
  `LLMOutputError: native structured output did not return an object`;
  `live.dvwa.authentication`, `live.dvwa.levels` (low, medium, high) and
  `live.dvwa.surfaces` (sqli, access_control, brute_force) all passed. **This is
  the only live evidence in existence, and provider-side reasoning execution
  remains unproven** (the report cannot confirm the provider executed reasoning,
  only that the request asked for it).

## Aborted-matrix findings

Both matrices were interrupted, not completed. Recorded from the artifacts in
`results/runs/matrix-2026-09-17-11` and `results/runs/matrix-2026-09-17-14`:

- `runtime.json` in both directories: `status = "active"`, `manifest_path = null`,
  `heartbeat_at` `2026-09-17T14:58:21.983513+00:00` (-11) and
  `2026-09-17T14:58:19.969377+00:00` (-14). No manifest was ever written.
  `matrix.started` declared 36 coordinates; 33 produced coordinate artifacts.
- **33 coordinates with artifacts: 29 `error`
  (`incomplete_reason=LLM_RUNTIME_FAILURE`), 4 `success`.** The 29 error
  coordinates contain 51 per-call records with `parse_status=provider_error`,
  `cause_type=ReadTimeout`, `provider_usage={}`, `status_code=None`, and
  `call_duration_ms` 60012-75662 ms (60-76 s) against the configured 60 s
  timeout. Artifact-level `error_type` is `APITimeoutError`; the intermediate
  class names `httpx.ReadTimeout` / `httpcore.ReadTimeout` do **not** appear
  anywhere in the artifacts - only the typed `cause_type` is persisted.
- Zero quota strings anywhere in the 134 scan files (`Insufficient`, `quota`,
  `balance`, `CreditsError`: 0 hits). The `401` substring matches are hash
  fragments, `call_id` fragments and durations, not HTTP status codes; no
  provider HTTP status is recorded anywhere.
- 9 calls did receive billed responses and then failed schema validation:
  `parse_status=invalid`, `error_type=ValueError`, `provider_usage` populated,
  rejected body logged, `error_message: null` and `remediation: null`.
- 130 LLM calls total across both matrices, **all** `provider=openai_compatible`,
  `model=deepseek-v4.1-flash:free`, identical `model_fingerprint` - including the
  18 coordinates declared `provider: openai` / `model: gpt-5.6-luna`, whose
  artifacts nevertheless show `config.model_profile=openai_compatible` and role
  resolution to `provider=openai_compatible`.
- 20 of 33 coordinates have non-empty `achieved_outcomes` and a populated
  `akg_path` - exactly the sqli and brute_force coordinates
  (`credentials_extracted`, `authenticated_session`, `akg_path` length 2-4). All
  33 reached `verifier_decision.decision == "confirmed"` with non-empty
  `confirmed_vulns` (`ac_force_browse_confirmed`, `bf_dictionary_confirmed`,
  `bf_spray_confirmed`, `sqli_*_confirmed`). The harness exploits DVWA whenever
  the provider answers.
- One artifact carries `invalid_json_events`
  (`{"event":"payload_generation.invalid_json","method":"ac_force_browse","provider":"openai_compatible"}`);
  there is no `static_seed_fallback` event or field anywhere in the artifacts, so
  the "payload_generation.invalid_json -> static_seed_fallback" pairing is visible
  only as the single recorded invalid-JSON event. `fallback_events` is populated
  in 29 artifacts with `{event: orchestrator.llm_failure, error_type:
  APITimeoutError, next_agent: ...}`.
- `repeat_index` **is** present in every one of the 33 artifacts at
  `config.repeat_index` (value 0 in all 33), and at the same path in the
  pre-change 2026-09-15 matrix artifacts. Per-run artifacts are complete at 31/32
  top-level names from the AGENTS.md list; `repeat_index` is the only name not
  top-level. Correction to the earlier reading: the 2026-08-21 `single-run-*`
  directories contain only `akg.snapshot.json`, `experiment.manifest.json`,
  `runtime.json` and `runtime.events.jsonl` - no per-run artifact, so they cannot
  confirm the path for that date.
- **Event/artifact count reconciliation (corrects the earlier single-coordinate
  reading):** in `runtime.events.jsonl`, every failed call emits `llm.failed`
  **twice** - a thin provider-level record
  (`{call_id, error_type, provider}`) and a role-level record carrying the full
  per-call detail - so raw event counts are about 2x `llm_activity.failed`.
  Counting role-level records only, 24 of 33 coordinates match
  `llm_activity.failed` exactly and 9 exceed it by 1; the worst case is
  **5 role-level events vs `llm_activity.failed = 4`** (matrix-2026-09-17-11
  run-015 and run-017), not a single isolated coordinate.
- **Error-message richness (recorded as a finding, not fixed):** the run-level
  strings (`*.failure.json` `error`, `run.failed.message`) are
  `"APITimeoutError: orchestrator model call failed; deterministic fallback
  output was retained for audit only"` and the content-free
  `"LLM runtime failure: at least one provider call failed"`. The per-call record
  carries provider, model, `model_fingerprint`, role, coordinate/call id,
  `cause_type`, `call_duration_ms`, `parse_status`, `remediation`. Missing
  everywhere in the artifacts: the endpoint/base_url actually dialed, any HTTP
  status or provider error body (a 401 `CreditsError` leaves no trace), provider
  request id, the timeout value in effect, retry/attempt count, and a
  message-level distinction between provider rejection vs no-answer vs parser
  rejection; parse failures additionally carry `error_message: null` and
  `remediation: null`.
- **Budget question, as reported by the earlier session (not re-run here):** a
  single minimal probe of the `openai` profile returned HTTP 401 with a body
  whose error type was `CreditsError` ("Insufficient balance..."), an explicit
  quota/budget rejection; a probe of `openai_compatible` returned no response
  within the timeout (read timeout), which cannot by itself prove quota
  exhaustion.
- **Provider-axis routing defect (recorded with the fix recommendation, not
  fixed):** with a top-level `provider: openai_compatible` and no
  `--model-profile` flag, both roles resolve to `profile=openai_compatible` and
  all 130 LLM calls across both matrices ran on `deepseek-v4.1-flash:free`,
  including the 18 coordinates declared `provider: openai`. An offline control
  (reported by the review session) shows that clearing the role settings makes the
  same coordinate route to the `openai` profile. Consequence: the matrix
  `provider` axis is metadata-only; a single matrix invocation cannot route
  different coordinates to different model profiles. **Recommend per-coordinate
  profile resolution before any provider-axis experiment.**

## Final verification results

Raw numbers from the commands run against the current tree:

```text
$ .venv/bin/python -m pytest -q
1374 passed in 51.63s

$ .venv/bin/python -m pytest tests/test_doctor.py tests/test_tui.py tests/test_reasoning_config.py tests/test_diagnostics.py -q
99 passed in 18.35s        # 27 doctor + 17 tui + 31 reasoning_config + 24 diagnostics

$ .venv/bin/python -m tesis doctor --config config.yaml --json
exit=0
{"checks":[...11 checks...],"status":"passed","summary":{"failed":0,"passed":11,"skipped":0,"total":11}}
stdout_lines=1  stderr_bytes=0

$ .venv/bin/python -m tesis doctor --config config.yaml
exit=0
Doctor summary: 11 passed, 0 failed, 0 skipped, 11 total

$ .venv/bin/python -m tesis doctor --nope
exit=2  (usage on stderr, no stdout)

$ git diff --check          # exit 0
$ git diff --cached --check # exit 0
```

## Not verified

- **No completed experiment matrix.** Both 2026-09-17 matrices were interrupted
  (`runtime.json.status = "active"`, `manifest_path: null`); 29 of 33 coordinate
  artifacts are transport failures. No successful provider-axis experiment exists.
- **Provider-side reasoning execution is unproven.** Only request-side
  serialization is asserted; the one live probe reported
  `reasoning_tokens=not_reported` and `provider_side_reasoning=unverified`. Absent
  provider usage means unknown.
- **Live doctor evidence is a single run** from a cancelled session (16 checks,
  15 passed, 1 failed, with `live.model.payload_generator` failing on the
  harness-handled structured-output error). It was not repeated on the final tree.
  The `--live` path had not been re-run when this document was written.
- **Provider availability at the time of the aborted matrices was degraded**: a
  reported 401 `CreditsError` on the `openai` profile and read timeouts on
  `openai_compatible`. Provider/environment failure versus harness defect has not
  been separated for the aborted runs.
- **TUI verification is limited to the Textual test harness**; no manual terminal
  check was performed.
- **The independent chain's own scripts were not re-run here.** They are reported;
  the items re-verified directly are the ones listed under Verified.
- The artifact audit against the AGENTS.md field list was performed only for the
  aborted matrices (see above), not for a completed run.

## Known limitations

- **N2** - the payload-mode axis is inert for seed-only validation.
- **N3** - the containment check exercises the scope helper
  (`client._assert_in_scope` for request/redirect kinds), not a live redirect.
- **N5** - URL redaction over-consumes into the tail of the query string.
- **N7** - duplicated provider-capability literal in the doctor
  (`tesis/doctor.py:508` hardcodes `{"gemini", "claude"}`).
- **N8** - `_known_secrets` is evaluated outside `_safe_check`
  (`tesis/doctor.py:930`).
- **N9/N10** - structured-output fallback breadth; legacy `reasoning` keys are
  discarded on the Chat path.
- **N11** - DVWA credentials are read with admin/password defaults because
  `EngagementConfig` carries no `dvwa_*` fields (`tesis/doctor.py:643-644`).
- **N12** - pre-existing artifact-schema drift in the two summaries and
  AGENTS.md; not touched by this change set.
- Provider-side reasoning unproven; no completed matrix; no manual TUI check;
  live doctor single-run only.

## Next steps

```bash
# 1. Implement per-coordinate profile resolution (fixes the provider-axis defect), then:
.venv/bin/python -m tesis run --headless --mode matrix --config config.yaml --providers openai_compatible --json

# 2. Re-run the live doctor when provider quota is restored:
.venv/bin/python -m tesis doctor --config config.yaml --live --json

# 3. Re-confirm the frozen tree offline:
.venv/bin/python -m pytest -q
.venv/bin/python -m tesis doctor --config config.yaml --json
```

Then: audit the newest `results/runs/` matrix directory against the AGENTS.md
artifact field list, and separate provider/environment failures from harness
defects.

## Housekeeping

- Pre-existing user files preserved: modified `config.yaml` and untracked
  `test.py`.
- No commit and no push were performed; all changes above are uncommitted.
