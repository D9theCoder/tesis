# Interactive Runtime Architecture

## Entry point and screens

`python -m tesis run` starts `TesisApp`. For automation, the same entry point
accepts `--headless` and coordinate flags, for example
`python -m tesis run --headless --mode matrix --condition akg_guided_hybrid`.
Headless execution uses the same runners and artifact schema without opening
Textual; network-backed runs should be pointed at an authorized DVWA sandbox.
The app and headless layer read the repository-root `config.yaml` by default.

Useful automation flags include `--condition`, `--target-method`,
`--providers`, `--levels`, `--surfaces`, `--payload-modes`, `--repeats`,
`--candidate-budget`, `--iterations`, `--output-dir`, and `--json`. Lists are
comma-separated, so the thesis matrix can be launched as:

```bash
python -m tesis run --headless --mode matrix \
  --condition akg_guided_hybrid --providers openai_compatible \
  --levels low,medium,high --surfaces sqli,access_control,brute_force \
  --payload-modes hybrid,llm_mutation_only --repeats 1 --json
```

```text
Main menu
├── Single experiment setup ─┐
├── Experiment matrix setup ─┴── Runtime dashboard ── In-app summary
├── Settings (typed + raw round-trip YAML)
├── Recent results ── Result detail ── Export
├── Framework validation
├── Framework information
└── Exit
```

All screens are keyboard navigable. Esc returns, `q` exits at the main menu,
Ctrl+C requests cooperative runtime cancellation, and Tab switches the runtime
pane between the model stream and redacted trace. Live rendering is bounded;
the complete execution log remains in the artifact.

## Separation of concerns

The Textual layer does not execute graph nodes directly. It starts the existing
single or matrix runner in a daemon thread and receives immutable `RunEvent`
objects through a `RuntimeEventSink` callback. Runtime and evaluation modules
do not import Textual.

```text
LangGraph / provider callbacks / evaluation telemetry
                         │
                         ▼
             normalized RunEvent stream
                         │
             central secret redaction
                         │
                         ▼
           thread-safe Textual messages
                         │
     ┌───────────┬─────────────┬─────────────┐
     ▼           ▼             ▼             ▼
 task rail   model trace    telemetry    failure/matrix
```

The runtime event contract covers lifecycle, model start/token/completion,
graph-state transitions, candidate generation and validation, method probes,
verification, scores, guardrails, fallbacks, containment, exceptions, and
matrix coordinates. Providers that expose streaming callbacks produce token
events; a completed response remains available when streaming is absent.

## Cancellation

`CancellationToken` is cooperative and thread-safe. Ctrl+C sets the token; a
second Ctrl+C closes the TUI immediately. Long-running TUI tasks use daemon
threads and stop posting UI messages during shutdown, so a blocked provider or
HTTP operation cannot hold the terminal process open.
The active LLM or HTTP request is not interrupted unsafely; when it returns,
the graph iterator closes, the latest safe state becomes a `cancelled`
artifact, and matrix scheduling stops before the next coordinate.

## Configuration

`tesis/config_fields.py` declares field types, categories, choices, aliases,
constraints, and secret metadata. Choices come from provider, state, payload,
surface, security-level, and method registries. The loader and TUI forms use
this schema.

`ruamel.yaml` loads and saves in round-trip mode so ordering, comments, nested
model blocks, and unknown keys survive typed edits. Advanced YAML is parsed and
fully validated before replacement of `config.yaml`. Blank secret controls do
not overwrite existing values, environment references remain supported, and a
literal secret requires an explicit warning acknowledgement.

## Artifact service and identity

`ArtifactRepository` recursively indexes readable JSON without binding widgets
to historical layouts. It supports old deterministic single artifacts, newer
single artifacts, matrix containers, filtering, sorting, lookup, and duplicate
fingerprint groups; malformed files are ignored individually.

- `execution_id` uniquely names a physical execution and its artifact/sidecars.
- `run_id` remains the logical experiment coordinate for analysis compatibility.
- `config_fingerprint` hashes canonical effective setup after removing secrets,
  timestamps, execution identity, repeat index, and output paths.

New TUI and headless executions are allocated below `results/runs` using a
collision-safe dated directory: `single-run-YYYY-MM-DD` for one run and
`matrix-YYYY-MM-DD` for a matrix. A same-day collision adds `-2`, `-3`, and so
on. Matrix children use sequence plus coordinate names such as
`run-001-openai_compatible-sqli-low-hybrid`, and each experiment directory
contains an `experiment.manifest.json` index. Existing flat artifacts are left
untouched and remain discoverable recursively.

## Preserved security and research architecture

The user interface does not alter the canonical graph topology, static AKG,
method-agent registry, payload validation, containment, verifier behavior, or
scoring formula:

```text
START → recon → orchestrator → payload_candidate_builder → payload_validator
      → selected method agent → chaining_router
      → orchestrator | payload_candidate_builder | scorer → END
```
