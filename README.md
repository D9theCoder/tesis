# TESIS

LLM-assisted autonomous penetration-testing experiments for an authorized DVWA sandbox. The framework is restricted to SQL injection, access control, and brute force, with a static payload-aware Attack Knowledge Graph and fixed method agents.

## Start the application

From the repository root:

```bash
uv sync
source .venv/bin/activate
python -m tesis run
```

`python -m tesis run` opens the full-screen mission-control TUI when used
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

When multiple entries exist under `models`, select one for both LLM roles at
runtime without editing the YAML:

```bash
python -m tesis run --headless --mode matrix --model-profile openai \
  --providers openai --levels low --surfaces sqli \
  --payload-modes static_only --repeats 1
```

Role-specific `--orchestrator-model-profile` and
`--payload-model-profile` flags remain available when the two roles should use
different profiles. `TESIS_MODEL_PROFILE` is the equivalent environment
override.

Without a global or role-specific profile, roles stay unpinned and follow each
matrix coordinate's provider. Precedence is explicit role profile > global
`model_profile` > coordinate provider; this keeps provider-axis experiments
from reusing the top-level single-run provider profile.

Reasoning effort can be set to `low`, `medium`, `high`, `xhigh`, or `max` with
`--reasoning-effort`, `TESIS_REASONING_EFFORT`, or the TUI's discrete slider.
Persist a profile default at `models.<profile>.reasoning_effort`; an explicit
`llm_runtime.roles.<role>.reasoning_effort` overrides it, while null inherits.
Precedence is CLI > environment > YAML role > profile. Canonical
`reasoning_effort` also wins over legacy nested `reasoning.effort`,
`model_kwargs`, or `extra_body` forms; legacy values are normalized and removed
before the provider request is built.

OpenAI and OpenAI-compatible adapters send one canonical effort field, omit
temperature, and remove conflicting legacy request values. An explicit portable
effort on Gemini or Claude raises an actionable error; it is never silently
downgraded. If an effective effort is configured and a role has no explicit
`max_tokens`, that role defaults to an 8,192-token ceiling shared by reasoning
and final output. Null preserves the older defaults (96 for the orchestrator and
`min(512, 96 + 64 * candidate_budget)` for the payload generator). Runtime
artifacts record `reasoning_effort_requested`, provider usage, and explicit
`reasoning_token_evidence` separately; absent provider usage is not evidence
that reasoning was disabled.

Run Doctor explicitly before an experiment:

```bash
python -m tesis doctor --config config.yaml --json
python -m tesis doctor --config config.yaml --live --json
```

Offline Doctor performs 11 local checks: fixed coverage (3 surfaces, 9 methods,
3 security levels, 3 payload modes, and 2 experiment conditions), AKG
invariants, LangGraph compilation, all 81 static-seed method/level/mode
coordinates, HTTP request-and-redirect containment, profile/role resolution,
credentials, endpoints, dependencies, output-directory writability, and
reasoning controls. `--live` additionally makes one benign structured model
probe per role, then checks contained DVWA authentication, all security levels,
and all in-scope surfaces; provider calls can consume credits. A model response
without provider usage is `skipped`, with reasoning-token usage reported as
unknown rather than passed. Usage without a reasoning-token field can pass the
structured probe, but provider-side reasoning remains unverified.

`--json` prints one object with top-level `status`, `summary` (`passed`,
`failed`, `skipped`, `total`), and `checks`; every check has `id`, `category`,
`status`, `summary`, `details`, and `remediation`. Top-level status is failed
only when at least one check fails; skipped checks remain separate. Exit codes
are 0 for a passed report, 1 for a failed report, and 2 for CLI usage errors.
The Doctor drawer
exposes offline and live Doctor actions. Doctor is standalone: it never runs
automatically, gates a run, performs provider quarantine, or changes runtime
topology.

Provider diagnostics walk exception chains for HTTP status and request IDs,
retain redacted role/coordinate/model context with remediation, and redact every
URL query and fragment value. Runtime extracts text from strings or list-based
`text`/`output_text` blocks and treats provider-reported incomplete Responses
output as failure. In automatic mode, compact-JSON fallback is used when the
local client lacks native structured output or the provider specifically
reports that capability as unsupported; authentication, rate-limit, timeout,
and connection failures do not trigger it.

The repository-root `config.yaml` is the sole configuration document. Prefer environment references such as `${OPENAI_API_KEY}` for secrets.

## Mission control and keys

`python -m tesis run` opens the full-screen mission-control TUI when used
without additional flags. It requires a TTY and a minimum 60x18 terminal;
smaller terminals show a size message with only quit/help available. Wide
terminals (120x24 and up) show pipeline, coordinates, and evidence together;
narrower terminals collapse coordinates and evidence into drawers, then to one
focused pane.

The mission-control screen shows pipeline stages, coordinate rows, verified
evidence, and bounded notices. There is no permanent command input: press `/`,
`:`, or Ctrl+P to summon the command launcher (`run`, `matrix`, `plan`,
`cancel`, `coordinates`, `evidence`, `failure`, `trace`, `doctor`, `results`,
`settings`, `export`, `about`, `help`, `quit`). `/run` and `/matrix` open the
guided launcher (Scope, Coordinates, Runtime, Review); Review is the only
place with Start, and Start freezes the resolved request until terminal state.

While a run is active, starting/configuration commands are disabled and only
inspect/export/cancel operations remain available. Press `r` for a single run,
`m` for a matrix, `p` for plan, `d` for Doctor, `1/2/3` for
pipeline/coordinates/evidence, Tab to move focus, Enter to inspect, `?` for
help, and `q` to quit while idle. Ctrl+C requests graceful cancellation;
press Ctrl+C again to close immediately if an active provider or HTTP call is
stuck; background tasks do not hold the terminal process open.

The launch drawers expose target, provider/model, security level, surface,
target method, experiment condition, payload mode and budgets, stop policy,
diagnostics, reporting, guardrail handling, output location, and logging
controls. Review resolves and freezes the exact effective request and is the
only place with Start; validating a configuration without running it stays in
the headless path (`python -m tesis run --dry-run`). The settings
drawer offers the same typed controls and advanced round-trip YAML editor. Its
profile-level reasoning slider and global two-role slider are independent. If
the loaded role values differ--including one explicit value plus one inherited
value--the global slider displays a truthful mixed label such as
`orchestrator=xhigh, payload_generator=inherit` and preserves both values on
save until the operator moves it. Pointer clicks map only to the rendered
marker track. YAML ordering, comments, nested model blocks, and unknown keys
are retained. Blank secret inputs preserve their existing values; the UI warns
before saving a literal secret.

Runs execute on a daemon background thread. The mission-control panes show
graph stages, coordinate rows, verified evidence, bounded notices, and matrix
progress; the full redacted event trace lives in the trace drawer. Notices do
not steal focus. Core runners communicate through UI-independent `RunEvent`,
`RuntimeEventSink`, and `CancellationToken` contracts; runtime and evaluation
modules do not import Textual.

Cancellation is cooperative: after the active LLM or HTTP operation returns, no
later graph or matrix work is scheduled. The latest safe state is persisted
with status `cancelled`.

## Results and artifact identity

The results drawer reads both historical and current JSON artifacts, ignores
malformed files, supports metadata filters, and provides triage detail with a
JSON triage export (`Export JSON` writes the summary to
`tui-results-export.json`). Deep JSON, graphs, and charts stay in the web app.


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

Verification remains inside method agents, containment remains enforced by payload validation and the HTTP layer, and the AKG remains static and prevalidated. See [docs/reference/architecture.md](docs/reference/architecture.md), [docs/reference/summary_en.md](docs/reference/summary_en.md), and [guide.md](guide.md).

## Tests

```bash
pytest
```

Before thesis experiments, validate configuration, reachability, registered agents, containment, AKG structure, payload validation, and at least one run per in-scope surface from the TUI.
