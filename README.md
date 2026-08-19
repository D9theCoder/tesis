# TESIS

LLM-assisted autonomous penetration-testing experiments for an authorized DVWA sandbox. The framework is restricted to SQL injection, access control, and brute force, with a static payload-aware Attack Knowledge Graph and fixed method agents.

## Start the application

From the repository root:

```bash
uv sync
source .venv/bin/activate
python -m tesis run
```

`python -m tesis run` opens the full-screen Textual application when used
without additional flags. Automation can use the same entry point with
`--headless`, for example:

```bash
python -m tesis run --headless --mode matrix \
  --condition akg_guided_hybrid --providers openai_compatible \
  --levels low,medium,high --surfaces sqli,access_control,brute_force \
  --payload-modes hybrid,llm_mutation_only --repeats 1 --json
```

The headless layer uses the same runners and writes the same auditable
artifacts without requiring a TTY. The repository-root `config.yaml` remains
the default configuration document.

The repository-root `config.yaml` is the sole configuration document. Prefer environment references such as `${OPENAI_API_KEY}` for secrets.

## Screens and keys

The main menu provides:

1. Run Single Experiment
2. Run Experiment Matrix
3. Settings
4. Recent Results
5. Validate Framework
6. Framework Information
7. Exit

Use arrow keys and Enter to navigate, Esc to return, `q` to exit from the menu, Ctrl+C to request graceful cancellation, and Tab to switch between the response stream and redacted LLM trace. Press Ctrl+C again to close immediately if an active provider or HTTP call is stuck; background tasks do not hold the terminal process open.

Single and matrix setup screens expose target, provider/model, security level, surface, target method, experiment condition, payload mode and budgets, stop policy, diagnostics, reporting, guardrail handling, output location, and logging controls. “Validate only” replaces the old dry-run behavior.

Settings offers typed controls and an advanced round-trip YAML editor. YAML ordering, comments, nested model blocks, and unknown keys are retained. Blank secret inputs preserve their existing values; the UI warns before saving a literal secret.

## Runtime dashboard

Runs execute on a daemon background thread. The dashboard shows graph stages, streamed model output, prompt/response trace, method and AKG telemetry, candidate validation, active failures, and matrix progress. Live logs and trace rendering are bounded for terminal stability; the artifact retains the complete execution log. Core runners communicate through UI-independent `RunEvent`, `RuntimeEventSink`, and `CancellationToken` contracts; runtime and evaluation modules do not import Textual.

Cancellation is cooperative: after the active LLM or HTTP operation returns, no later graph or matrix work is scheduled. The latest safe state is persisted with status `cancelled`.

## Results and artifact identity

Recent Results reads both historical and current JSON artifacts, ignores malformed files, supports metadata filters, and provides detail tabs and JSON/Markdown/terminal exports.

Every new execution has:

- `execution_id`: unique physical artifact identity and filename
- `run_id`: stable logical experiment coordinate retained for analysis
- `config_fingerprint`: secret-free hash of effective experiment setup, excluding timestamps, output paths, execution identity, and repeat index

Repeated fingerprints are marked `SAME CONFIG ×N`. Historical artifacts are read without being rewritten.

New TUI and headless runs are grouped under `results/runs` as
`single-run-YYYY-MM-DD` or `matrix-YYYY-MM-DD` directories. Matrix folders
contain one coordinate folder per run and an `experiment.manifest.json` index;
same-day collisions receive a numeric suffix. Existing flat artifacts remain
untouched.

## Architecture

The canonical graph remains:

```text
START → recon → orchestrator → payload_candidate_builder → payload_validator
      → selected method agent → chaining_router
      → orchestrator | payload_candidate_builder | scorer → END
```

Verification remains inside method agents, containment remains enforced by payload validation and the HTTP layer, and the AKG remains static and prevalidated. See [docs/architecture.md](docs/architecture.md), [docs/summary_en.md](docs/summary_en.md), and [guide.md](guide.md).

## Tests

```bash
pytest
```

Before thesis experiments, validate configuration, reachability, registered agents, containment, AKG structure, payload validation, and at least one run per in-scope surface from the TUI.
