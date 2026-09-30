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
`--candidate-budget`, `--iterations`, `--model-profile`, `--output-dir`, and
`--json`. Lists are comma-separated, so the thesis matrix can be launched as:

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

Thesis grading is a post-execution artifact consumer in
`evaluation/thesis_scoring.py`; see the [scorebook](thesis_scoring.md). The launch
drawer and headless config freeze `scoring_mode` and `scoring_evaluator` before
execution and include them in the experiment fingerprint. Results → Enter →
Review payload evidence opens `ReviewDrawer`, exported through `tesis.tui`.
It reads `tesis.tui_state.CONFIG_PATH`, performs disk/evaluator work in workers,
and shows independent human/AI pending or final states. A human grade or fresh
evaluator call cannot change the source artifact, payload validation, method
execution, verifier or graph. Human and AI receipts are separate derived files;
the original runtime composite is labeled historical/provisional. The local
`python -m tesis review` command uses the same grading path. No DVWA request is
part of review; optional evaluator calls use only the matching frozen profile.
CLI and TUI share a validated source-local decisions ledger, so reopening a
CLI-finalized review preserves its final state. Execution-specific evaluator
telemetry and previous receipt/ledger/status versions are retained; discovery
excludes these sidecars and archives. Results triage scrolls beneath a row-selectable
table, while Export/Review actions remain visible at 80×24 and 60×24.
Selecting an older custom-directory receipt carries its path into review for
source-validated history recovery and preserves its receipt/telemetry directory.

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

## TUI module boundaries

`tesis.tui` is the public import root and a small facade for `TesisApp`,
`run_tui`, and the supported names in `__all__`. The implementation lives in
flat sibling modules so callers keep the same public entry point while each
module has a focused responsibility:

- `tesis.tui_security` owns secret redaction, URL sanitization, and safe error
  formatting.
- `tesis.tui_state` owns shared paths, TUI state types, and the run-event
  reducer. It has no Textual dependency.
- `tesis.tui_commands` owns the command registry, navigation and terminal-size
  policy, shared drawer base, and command launcher.
- `tesis.tui_forms` owns launch and settings forms, including configuration
  editing.
- `tesis.tui_drawers` owns coordinate, evidence, failure, trace, result,
  doctor, plan, help, and about views.
- `tesis.tui_mission` owns the mission screen, live rendering, event delivery,
  and runtime cancellation.

State and security modules provide the shared lower-level helpers. Screen,
drawer, and launcher links that would otherwise create import cycles use
method-local imports, keeping the top-level TUI import graph acyclic. Public
exports remain available through `tesis.tui`; moved private helpers are
imported from their owning module.

`tui_state.CONFIG_PATH` is the single owner of the config path; forms,
drawers, and the mission screen read `tesis.tui_state.CONFIG_PATH` at use
time, so rebinding that attribute redirects every TUI reader.
`tesis.tui.CONFIG_PATH` is an import-compatible snapshot binding, not a
synchronized view: it is bound once when the facade imports, so after the owner
is rebound the facade name still reads the original default; assigning to the
facade attribute rebinds only that facade name, and the owner and TUI readers
remain unchanged. Facade assignment is not a supported override and the facade
never forwards it; no duplicate path state exists to emulate one. The explicit
`config_path` argument of `tesis.config_loader` serves direct loader callers
only and is not a TUI-wide override, because TUI readers pass
`tui_state.CONFIG_PATH` themselves. A caller that needs runtime-reconfigurable
TUI paths needs a designed config-path API, not an implicit alias.

## Cancellation

`CancellationToken` is cooperative and thread-safe. Ctrl+C sets the token; a
second Ctrl+C closes the TUI immediately. Long-running TUI tasks use daemon
threads and stop posting UI messages during shutdown, so a blocked provider or
HTTP operation cannot hold the terminal process open.
The active LLM or HTTP request is not interrupted unsafely; when it returns,
the graph iterator closes, the latest safe state becomes a `cancelled`
artifact, and matrix scheduling stops before the next coordinate.

Doctor uses a separate CLI subprocess, managed by a Textual async worker, so
Escape or a rerun can stop even a blocked check. Both output streams are captured
to keep SDK logs out of the terminal display. Closing kills the local subprocess;
reopening creates a new one and rereads `tui_state.CONFIG_PATH`. Already submitted
remote requests may still finish at the service. Its result list scrolls inside
the drawer, with controls kept visible and technical details hidden by default.

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

When multiple named profiles exist under `models`, headless runs can select
one profile for both standard LLM roles with `--model-profile PROFILE`; the
same override is available as `TESIS_MODEL_PROFILE`. TUI run setup exposes the
same selector. Role-specific profile flags remain available for deliberately
different orchestrator and payload-generator models.

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

## Method verification and replay

Method agents retain their own verification boundary. The shared update records
every decision; the runner preserves graph history and sanitized validated
`method_execution_inputs`. Replay uses `evaluation.payload_replay` to revalidate
an unchanged queue against fresh sessions without provider calls. Rejected or
changed queues stop before HTTP and diagnostic artifacts link the source/code
hashes. The candidate history remains append-only; executable queues follow the
ordered validation receipts. Replay compares membership, values, provenance,
and budget independently of fresh ranking, retains saved execution order, and
applies the `ExploitationState` reducers to method and scorer updates. Checkpoint
resume starts its event cursor after historical receipts, so only fresh
validation can capture another pre-execution input.
Replay manual sheets contain only candidates linked to fresh response evidence,
with `manual_scoring_scope: fresh_replay_execution`. Historical scores and
evidence remain in the reduced final state and linked source artifact; a rejected
replay queue produces no manual rows. The export helper is included in code hashes.

## Scoring evidence and route completion

Rubric `scoring.v2` uses the existing scorer and six-dimensional formula. Common
selection grading records forced, model/orchestrator, deterministic fallback and
AKG route origins before execution, with destination-surface viability and a
visit ID. Agents emit candidate-specific verified grades at their existing
verification boundaries. Shared updates append verifier and scoring decisions,
preserving winning candidate/exploitation evidence and later negative decisions.
The post-method router reads merged outcomes and records route lifecycle and
dependency receipts. Actual source consumption plus downstream confirmation
earns destination chain credit; hashes, unrelated static logins, and visibility
without a permission oracle retain zero.

Output events carry producer and method/visit scope. Discarded recon navigation
and external page references remain observable without an output penalty.
Payload/request/redirect violations
stay blocked; the HTTP wrapper captures violations even if an agent handles the
exception. Output aggregation uses minimum within a method, including run-wide
HTTP penalties. Composite entries are recomputed from stored components.
`state.v2` identifies the changed reducer/checkpoint contract.

Terminal exports retain sanitized chain, credential, attempt and payload inputs,
scoring decisions, verifier history and response/timing evidence. Route metadata
uses telemetry `payload`. Manual rows point to the receipt and verifier earning
a candidate maximum, with later decisions separate. Fresh diagnostic replay rows
remain limited to fresh evidence. `evaluation.scoring_repair` links pure repairs
to source hashes and explicitly retains missing legacy terminal inputs as gaps.

Error SQLi recognizes the complete DVWA `<pre>` duplicate-entry envelope for
`dvwa0` or `dvwa1` and `group_key`, alongside XPath and structured credential
leaks. Generic duplicate values, other keys, prose, and failed HTTP responses
receive no duplicate-entry extraction credit.

Profile ranking records `candidate_budget_exceeded` for valid candidates that
do not fit the executable queue. Their provenance remains available, execution
is excluded, and manual scores remain null.

Boolean false-branch extraction also requires a complementary true response
from the same expression, because suppressed SQL errors share DVWA's missing-ID
body. Unrecognized or failed complementary controls receive no extraction
credit. Timing verification shares the validator's bounded numeric `SLEEP`
parser, including exponents, signs, decimal forms, and normalized comments.
Comments retain token separation, so `AND/**/SLEEP(3)` is measured correctly
and an oversized delay with the same spelling is rejected before transport.

High regular SQLi uses POST to `sqli/session-input.php` followed by GET of
`sqli/`; failed submissions stop the transaction. High blind SQLi sets the
encoded `id` cookie and GETs `sqli_blind/`. Brute-force confirmation requires
HTTP 200, accepted tokens, and login content. Recon measures bounded credential
probes before asserting `no_rate_limit`, and does not label admin low privilege.
The current access-control agents lack an independent authorization control;
content-only observations remain unverified (score at most 2) and do not emit
confirmed nodes/outcomes.

A terminal orchestrator stop can clear the active selection. The scorer uses
the last method verifier decision in that case, retaining its selected-method
identity and all six score dimensions without another execution. A stop before
any method executes remains an empty result.

Low/medium brute-force probes require both threefold relative latency and
100 ms absolute growth for timing-based throttle inference. Explicit throttle
responses still stop execution; high-level random delay is excluded from the
relative heuristic.
