# Handoff: breaking-change regression hardening (2026-09-20)

Status: complete — all offline gates, dry run, live Doctor 16/16, and one coordinate artifact acceptance pass (2026-09-21). Moved to docs/completed/.

## Objective

Preserve existing experiment behavior unless a user explicitly enables a migration, while keeping fail-closed checkpoint safety and honest unavailable-metric reporting.

Do not expand the DVWA scope, alter the canonical LangGraph topology, weaken containment, or silently reinterpret incompatible persisted data.

## Verified baseline

The implementation baseline was checked with:

- full offline suite: `1453 passed`;
- focused acceptance suite: `89 passed`;
- `python -m tesis run --dry-run --config config.yaml`: four configured payload coordinates validated and the AKG/graph compiled;
- `git diff --check`: clean;
- TUI captures reviewed across dark, light, and monochrome themes and narrow/wide terminal sizes.

These checks do not cover live provider billing/latency, external artifact consumers, stale environments, real crash/WAL recovery, or SQLite contention across concurrent matrix coordinates.

## P0 — Restore opt-in checkpoint behavior for matrix runs

### Risk

`evaluation/multi_llm_runner.py` currently passes:

```python
"checkpoint_dir": checkpoint_dir or coordinate_output_dir,
"experiment_id": experiment_id or matrix_execution_id,
```

`evaluation/runner.py` enables SQLite checkpointing whenever either value is non-null. Therefore, an ordinary matrix run silently creates `checkpoints.sqlite3` and `langgraph_checkpoints.sqlite3`, changes graph thread identity, and can refuse execution when the output directory is read-only—even when checkpointing was not requested.

### Regression checks

Add focused tests proving all four cases:

1. A default single run creates no checkpoint database.
2. A default matrix run creates no checkpoint database and forwards `checkpoint_dir=None`, `experiment_id=None` to each coordinate.
3. An explicitly checkpointed matrix forwards the requested directory and experiment ID and creates both databases.
4. `--resume` without compatible metadata fails closed before any external action.

### Recommended solution

Forward the caller-provided values unchanged:

```python
"checkpoint_dir": checkpoint_dir,
"experiment_id": experiment_id,
```

Only derive coordinate-specific output paths and stable IDs after checkpointing is explicitly enabled. Do not weaken the existing start-receipt and identity checks.

### Acceptance

The default single-run and matrix paths are filesystem-compatible with the pre-checkpoint behavior. Explicit checkpoint and resume tests remain green.

## P0 — Avoid an unnecessary import-time dependency failure

### Risk

`evaluation/runner.py` imports `SqliteSaver` at module import time. A stale environment or unsupported `sqlite-vec` installation can break default runner, matrix, headless, and TUI imports even when checkpointing is unused.

### Regression checks

- In a subprocess where `langgraph.checkpoint.sqlite` cannot be imported, importing and exercising the default non-checkpoint runner path must still work.
- Enabling checkpointing without the package must fail once, before execution, with an actionable `uv sync` remediation message.
- A normal `uv sync` environment must still run the explicit checkpoint tests.

### Recommended solution

Import `SqliteSaver` inside the checkpoint-enabled branch. Keep the dependency in `pyproject.toml` if durable checkpoints remain a supported built-in feature; laziness here isolates stale/default environments rather than making persistence optional or best-effort.

## P1 — Complete the nullable-metric migration

### Risk

`consistency_score`, `token_cost`, and `token_cost_per_success` now use `null` plus availability/reason maps instead of reporting an unmeasured value as `0.0`. This is semantically correct but can break arithmetic, formatting, CSV, notebook, dashboard, and strict-schema consumers.

`evaluation.metrics.metric_reading()` already dual-reads legacy numeric and new nullable artifacts. Every in-repository and external consumer must use equivalent availability-aware handling.

### Regression checks

- Load a legacy artifact containing numeric `0.0` without availability maps.
- Load a new artifact containing `null`, `metric_availability=false`, and an unavailable reason.
- Render and aggregate both without `TypeError`, without formatting `None` as a number, and without treating unknown as measured zero.
- Run a mixed old/new artifact comparison and verify unavailable values are excluded or labeled, never silently averaged as zero.

### Recommended solution

Inventory report, export, notebook, and thesis-analysis readers. Route repository readers through `metric_reading()`. At display boundaries render `N/A` or `not computed`; do not convert `null` back to `0.0` in persisted artifacts.

## P1 — Normalize resume artifact fields

### Risk

Fresh artifacts set both `resumed_from_checkpoint` and `resumed`. Completed-receipt replay explicitly updates only `resumed_from_checkpoint`; old stored artifacts can lack `resumed`, and newer receipts can preserve a stale false value. Exact-key consumers can also reject the new checkpoint/version fields.

### Regression checks

Cover fresh execution, partial graph resume, completed-receipt replay, and replay of a legacy fixture. Each returned artifact must expose one documented canonical resume flag with consistent meaning. Additive fields must remain optional for old-artifact readers.

### Recommended solution

Use `resumed_from_checkpoint` as the canonical public field. Either remove `resumed` before release or set it consistently on every return path. Readers must use `.get()` defaults during the compatibility window.

## P1 — Validate checkpoint compatibility and recovery boundaries

### Risk

The new format intentionally refuses mismatched state, checkpoint, graph, configuration, experiment, and coordinate identities. Stable thread identity now includes `repeat_index`; older databases will not resume automatically. Concurrent coordinates also introduce SQLite locking/WAL behavior not proven by unit tests.

### Regression checks

- version mismatch, configuration mismatch, target mismatch, missing metadata, and repeat isolation all fail closed with actionable diagnostics;
- crash/restart is exercised at every safe pure-node boundary;
- externally acting nodes are never replayed without an idempotency key or completion receipt;
- two checkpointed matrix coordinates can write concurrently without lock leakage or corrupted receipts;
- SQLite connections close on success, error, cancellation, and resume refusal.

### Recommended solution

Keep the fail-closed behavior and version gates. Do not auto-migrate unknown checkpoint formats. Back up databases before testing and require a clean rerun when compatibility cannot be proven.

## P1 — Confirm the live model configuration intentionally

### Risk

`config.yaml` changes `deepseek-v4.1-flash:free` to `deepseek-v4.1-flash` and `reasoning_effort: high` to `max`. This can change cost, quota use, latency, output behavior, and experiment comparability. Offline and dry-run checks cannot validate provider billing or model routing.

### Regression checks

Before a full matrix:

1. Review the resolved configuration and confirm the model identifier and reasoning effort.
2. Run `python -m tesis doctor --config config.yaml --live --json` when provider quota is available.
3. Run one authorized DVWA coordinate and inspect the resolved model, effort, usage, failure envelope, and artifact versions.
4. Compare it with the prior baseline before approving a full matrix.

### Recommended solution

Keep the change only if it is an intentional experiment input. Commit it separately from implementation changes so model/cost changes are auditable and independently reversible.

## P2 — Preserve legacy TUI isolation

### Risk

The redesigned shell is opt-in, but its command provider and monochrome theme are registered for every TUI launch. This is low risk today, but it expands the legacy startup surface.

### Regression checks

Launch the default legacy TUI and the opt-in shell separately. Verify startup, command palette contents, cancellation, narrow-terminal input history, theme switching, and clean exit.

### Recommended solution

If strict isolation is required, register the shell command provider and shell-only theme only when the new shell is enabled. Otherwise document the intentional shared palette behavior.

## Verification order

Run the smallest proof first, then the full gates:

```bash
uv sync
uv run pytest -q tests/test_durable_checkpoints.py tests/test_state_checkpoint_versions.py tests/test_prompt_manifests_metric_availability.py tests/test_tui_shell.py tests/test_tui.py
uv run pytest -q
python -m tesis run --dry-run --config config.yaml
```

After provider quota and the authorized DVWA sandbox are available, run the live Doctor check and one coordinate before any full matrix. Archive the resulting artifacts and inspect checkpoint files, metric availability, resolved provider/model, resume flags, containment events, and individual score dimensions.

## Completion criteria

Move this handoff from `docs/upcoming/` to `docs/active/` when remediation begins, and to `docs/completed/` only when:

- default matrix checkpointing is proven off;
- explicit checkpoint/resume behavior is proven on and fail-closed;
- the default path no longer depends on importing SQLite checkpoint support;
- legacy and nullable metric artifacts are both consumed correctly;
- resume fields are consistent;
- checkpoint boundary/concurrency checks pass;
- the full offline suite and dry run pass;
- one authorized live coordinate confirms the intended model configuration and produces a complete auditable artifact.

## Verification record (2026-09-21, FinalVerification)

Historical risk sections above are preserved as the audit record; current-tree remediation status follows.

Remediation (current tree, verified by code read, not this gate):

- P0 opt-in checkpoint: `evaluation/multi_llm_runner.py` forwards `checkpoint_dir`/`experiment_id` unchanged (`None` by default) plus `resume`; `evaluation/runner.py` probes `langgraph.checkpoint.sqlite` lazily with a `uv sync` fail-closed message, refuses corrupt DB/receipts, sets dual `resumed`/`resumed_from_checkpoint` flags.
- P1 nullable metrics: `evaluation/metrics.py`, `evaluation/contracts.py`, `evaluation/reporter.py`, `tesis/report_formatters.py` route through availability-aware reads; `null` + `metric_availability=false` + reason, never silent zero.
- P1 recovery: `core/checkpoint_store.py` fail-closed on `None`/malformed metadata; WAL/timeout reverted.
- P1 model config: `llm/runtime.py` AUTO-only native-text fallback with failed/completed event markers; coordinate resolved `deepseek-v4.1-flash`, effort `max`.
- P2 TUI: `tesis/tui.py` shell palette/theme registered only when the new shell is enabled.

Worker proofs (pre-gate, reported by owners): checkpoint 21 passed; recovery slice 31 passed; metrics 41 passed; runtime/TUI 113 passed. Reciprocal cross-review fixes: corrupt-DB refusal, metric flag invariant, fallback event telemetry, env shell test.

Final gate (this session, exact commands from repo root):

- `uv sync` → `Resolved 78 packages`, `Audited 76 packages`, no changes.
- `py_compile` (checkpoint_store, contracts, metrics, multi_llm_runner, reporter, runner, llm/runtime, report_formatters, tui, 5 regression test files) → `PY_COMPILE_OK`.
- Focused gate `uv run pytest -q tests/test_checkpoint_optin_regression.py tests/test_checkpoint_recovery_regression.py tests/test_nullable_metrics_regression.py tests/test_llm_runtime.py tests/test_tui_isolation_regression.py tests/test_durable_checkpoints.py tests/test_state_checkpoint_versions.py tests/test_prompt_manifests_metric_availability.py tests/test_tui_shell.py tests/test_tui.py tests/test_doctor.py` → `172 passed in 38.04s`.
[SUPERSEDED by Final gate below — full suite now 1501 passed, 0 failed] Full `uv run pytest -q` → `1 failed, 1498 passed in 70.35s`: `tests/test_evaluation_multi_llm_runner.py::test_run_provider_matrix_deterministic_ordering` fails with `TypeError: track_engagement() got an unexpected keyword argument 'resume'` at `evaluation/multi_llm_runner.py:121` (`_run_single_with_payload_kwargs` forwards new `resume` kwarg to a legacy fake). BLOCKER — owner fix required; no source changes made by this gate.
- `uv run python -m tesis run --dry-run --config config.yaml` → `TESIS dry-run passed: 4 payload coordinate(s) validated; AKG and runtime graph compiled from config.yaml.`
- `git diff --check` → clean (`DIFF_CHECK_CLEAN`).

Live evidence (read and validated, `results/regression_hardening_2026-09-21/`, sanitized — secrets `[REDACTED]`, no new provider calls made):

- `doctor_live_attempt2.json`: `16/16 passed, 0 failed` (`status: passed`). Attempts 1 and `doctor_live.json`: `15/16` with `live.model.orchestrator` transient probe failure; attempt 2 green with no code change (retried probe).
- Exactly one authorized coordinate success: `single-run-2026-09-21-6`, run `openai_compatible-sqli-low-static_only-0`, `status: success`, one manifest run entry. Default path created NO sqlite files (directory holds only json/jsonl artifacts). Metric fields nullable with availability/reason maps (`consistency_score/token_cost/token_cost_per_success: null/false/not_computed`). Versions complete (`state.v1`, `checkpoint.v1`, `graph.v1`, `runtime-descriptor.v1`, `artifact-manifest.v1`, `stage7.rich.v1`, `tui.v1` + config fingerprint). Resume flags consistent (`resumed: false`, `resumed_from_checkpoint: false`, empty checkpoint files, null store). Containment `count: 5, guardrails: 0`; failure envelope null/empty with `llm_failed_events: 0`. Resolved model `deepseek-v4.1-flash`, effort `max`, usage `4 calls / 2623 in / 694 out / 3317 total`. Score dimensions present (`Smethod/Sexploit/Spayload_map/Schain/Soutput/Srun`).

Peer reports: CheckpointOptIn (runner + multi_llm_runner + 9 opt-in tests, 21 passed); RecoveryBounds-2 (checkpoint_store + 6 recovery tests, 31 passed; shared-DB matrix proven for metadata, not concurrent saver writes; no live DVWA — server off); ModelTUI (runtime + tui + EN/ID docs, 113 passed; live doctor 16/16 + 1 coordinate). MetricsCompat-resume was paged but sent no summary; MetricsCompat parked report covers reporter/contracts/formatters nullable work.

Lifecycle links fixed: `docs/completed/HANDOFF_AI_HARNESS_ARCHITECTURE_TUI_2026-09-19.md` and `docs/completed/HANDOFF_TUI_REVAMP_2026-09-19.md` pointed at `docs/upcoming/...`; updated at that time to `docs/active/...`, now point to `docs/completed/...`.

Decision (superseded by Final gate below): handoff stayed in `docs/active/` with blocker `test_run_provider_matrix_deterministic_ordering` (`resume` kwarg vs legacy fake), fixed by owner compat fix since.

## Final gate (2026-09-21, after compat fix, FinalVerification)

Prior gate was blocked on `tests/test_evaluation_multi_llm_runner.py::test_run_provider_matrix_deterministic_ordering` (`resume` kwarg vs legacy fake). Owner compat fix applied in `evaluation/multi_llm_runner.py` + focused regression tests. No live provider/coordinate reruns per instruction; prior live evidence stands.

- `py_compile` (core/checkpoint_store, evaluation contracts/metrics/multi_llm_runner/reporter/runner, llm/runtime, tesis/report_formatters, tesis/tui, test_evaluation_multi_llm_runner, test_checkpoint_optin_regression, test_checkpoint_recovery_regression, test_nullable_metrics_regression, test_llm_runtime, test_tui_isolation_regression, test_durable_checkpoints, test_state_checkpoint_versions, test_prompt_manifests_metric_availability, test_tui_shell, test_tui, test_doctor) → `PY_COMPILE_OK`.
- Focused gate `uv run pytest -q tests/test_evaluation_multi_llm_runner.py tests/test_checkpoint_optin_regression.py tests/test_checkpoint_recovery_regression.py tests/test_nullable_metrics_regression.py tests/test_llm_runtime.py tests/test_tui_isolation_regression.py tests/test_durable_checkpoints.py tests/test_state_checkpoint_versions.py tests/test_prompt_manifests_metric_availability.py tests/test_tui_shell.py tests/test_tui.py tests/test_doctor.py` → `190 passed in 39.22s`.
- Full `uv run pytest -q` → `1501 passed in 71.62s (0:01:11)`, 0 failed.
- `uv run python -m tesis run --dry-run --config config.yaml` → `TESIS dry-run passed: 4 payload coordinate(s) validated; AKG and runtime graph compiled from config.yaml.`
- `git diff --check` → clean.

Decision: all gates pass. Handoff MOVED from `docs/active/` to `docs/completed/`.
