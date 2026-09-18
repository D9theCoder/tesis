# Handoff: AI harness architecture and TUI recommendations (2026-09-19)

Status: research and repository review complete; recommendations only. No item
in this document should be treated as implemented or verified unless the current
source and tests independently prove it. This handoff deliberately concerns the
core AI harness, model-call contract, prompts, LangGraph lifecycle, evaluation,
and operator experience. It does not expand the DVWA attack scope or replace the
canonical workflow in `AGENTS.md`.

## Executive summary

The harness already has the right overall shape: a centralized LLM runtime,
static LangGraph topology, predefined AKG and method agents, validation before
execution, deterministic fallbacks, containment, structured artifacts, Doctor,
and a capable Textual UI. The highest-value next work is not a free-form agent or
a new penetration-testing workflow. It is making the existing workflow durable,
observable, replayable, and easier to operate.

Recommended priority:

1. Minimize and version persistent graph state.
2. Replace the in-memory checkpointer with an experiment-local durable store and
   add explicit resume semantics.
3. Define one application-owned model-call contract for retry, deadline,
   cancellation, capabilities, telemetry, and result metadata.
4. Treat prompts as versioned behavioral interfaces with role-level evaluation
   gates.
5. Correct cost and consistency semantics so unavailable values are not reported
   as zero.
6. Add resolved-plan, live-coordinate, failure-inspection, and resume/retry views
   to the TUI.
7. Add comparison, command-palette, worker, snapshot-test, and optional tracing
   improvements after the contracts above are stable.

## Current strengths to preserve

- `llm/runtime.py` centralizes model dispatch, structured-output parsing,
  fallback behavior, caching, telemetry, and the failure envelope.
- Prompts are role-specific and relatively compact; context capsules limit the
  amount of state sent to each call.
- `core/graph_builder.py` defines an explicit static graph. The orchestrator
  selects a method, payloads are built and validated before execution, and
  verification stays inside method agents.
- The AKG remains static, predefined, prevalidated, and payload-aware. The LLM
  does not dynamically create agents or rewrite graph structure.
- The TUI already exposes configuration, run monitoring, cancellation, event
  journaling, result filters, artifact details, export, and Doctor.
- Existing containment and artifact boundaries provide a sound base for the
  durability and operator-experience work proposed below.

## Core architecture recommendations

### P0 — Durable checkpoints and explicit resume

Current concern: the graph is compiled with `MemorySaver` and invoked with a
`thread_id`. Checkpoints disappear with the process, so a crash or restart
cannot reliably continue a long matrix run.

Recommended design:

- Use an experiment-local SQLite checkpointer by default. Keep an in-memory
  implementation only for tests and short dry runs.
- Derive a stable checkpoint/thread identity from the experiment and coordinate,
  not from an incidental process-local identifier.
- Persist `state_schema_version`, `checkpoint_schema_version`, graph/build
  version, config fingerprint, coordinate identity, and last completed node.
- Define retention, cleanup, and migration behavior before relying on the store
  for thesis experiments.
- Expose resumable runs in the CLI and TUI. Resume must validate the graph,
  config fingerprint, target, and state versions before continuing.
- Make externally acting nodes idempotent, or persist stable attempt IDs and
  completion receipts so replay does not silently duplicate an action.

Primary areas: `core/graph_builder.py`, `evaluation/runner.py`, the artifact
repository, CLI, and TUI.

### P0 — One model-call contract for retries, deadlines, and cancellation

Current concern: provider invocation is synchronous and a logical call normally
records one application-level attempt. Cancellation is checked around graph
progress, so an active provider request may remain uninterruptible until the SDK
returns. Retry ownership and total time budget are not explicit enough for
reliable accounting.

Recommended design:

- Create immutable `ModelCallSpec` and `ModelCallResult` types. Resolve the
  provider, model, profile, endpoint, prompt identity, schema identity,
  structured-output mode, reasoning controls, token budget, timeout, retry
  policy, cache policy, and coordinate identity before dispatch.
- Give the application one retry policy. Retry only transient transport errors,
  rate limits, and selected server failures; do not retry schema, credentials,
  entitlement, quota, or deterministic validation failures without an explicit
  rule.
- Use exponential backoff with jitter, honor `Retry-After`, cap attempts, and
  enforce a total call deadline as well as per-attempt timeouts.
- Avoid nested application and SDK retries. Record the configured and effective
  retry ownership.
- Make semaphore acquisition, backoff, and provider invocation cancellation
  aware. Define and test the maximum cancellation latency.
- Record every attempt with provider request ID, status, elapsed time, finish or
  refusal state, usage, failure class, and whether a response may have been
  billed. Aggregate those attempts into the existing canonical failure envelope.
- Maintain a provider capability registry rather than scattering assumptions
  about structured output, reasoning fields, token parameters, and response
  metadata across call sites.

Primary areas: `llm/runtime.py`, `llm/provider.py`, `llm/diagnostics.py`, and
`evaluation/runner.py`.

### P0 — Minimize and version LangGraph state

Current concern: the `messages` reducer can retain formatted prompts and model
responses even when later prompt builders reconstruct context from canonical
state. This makes checkpoints larger, increases accidental coupling, and makes
schema evolution and redaction harder.

Recommended design:

- Keep persistent graph state limited to domain facts, IDs, hashes, decisions,
  bounded evidence references, and routing information.
- Store rendered prompts, full responses, and verbose diagnostics in the
  artifact/trace layer. Put only their stable references and hashes in graph
  state.
- Add explicit state versioning and migration tests before enabling durable
  resume.
- Preserve the existing partial-update, monotonic-observation, provenance, and
  scoring rules from `core/state.py` and `AGENTS.md`.

Primary areas: `core/state.py`, `agents/orchestrator.py`, payload generation,
artifact serialization, and checkpoint tests.

### P1 — Prompts as versioned behavioral interfaces

Current concern: schema versions and prompt hashes exist, but most automated
prompt assurance is structural. A valid JSON response can still represent a
behavioral regression in method selection, payload constraints, provenance,
fallback choice, or injection resistance.

Recommended design:

- Maintain a prompt manifest per role with `prompt_id`, semantic version,
  template hash, input schema, output schema hash, validator version, and eval
  suite version.
- Keep system prompts minimal and role-specific. Pass dynamic repository,
  reconnaissance, and target data separately and label it explicitly as
  untrusted data, not instructions.
- Give prompt builders typed inputs rather than accepting an unrestricted state
  mapping.
- Use stable `reason_code` enums for important decisions. Preserve concise
  decision evidence, not hidden chain-of-thought.
- Add role-level datasets for orchestrator selection and payload generation,
  including malformed data, conflicting observations, prompt-injection text in
  reconnaissance, unsupported methods, containment attempts, and provider
  refusal/truncation cases.
- Run deterministic replay tests on every change and periodic live-provider
  evaluations on pinned model/profile versions. Gate prompt changes on agreed
  behavioral thresholds, not JSON validity alone.

Primary areas: prompt builders in `agents/` and `llm/`, schema validators,
`tests/test_llm_context_capsules.py`, and a new versioned eval-fixture directory.

### P1 — Honest evaluation semantics

Current concern: placeholder `consistency_score`, `token_cost`, and
`token_cost_per_success` values can be emitted as `0.0`. Zero means measured and
free/perfectly absent; it should not mean unknown.

Recommended design:

- Emit `null` plus a machine-readable availability/reason field until a metric
  is actually computed.
- Compute consistency only across a clearly identified repeat group and record
  the grouping/version rule.
- Compute cost from provider-reported usage and a versioned pricing snapshot.
  Preserve the source and effective date; do not infer cost when usage or price
  is unavailable.
- Validate these semantics in artifact audit tests and surface unknown values as
  `N/A`, not `0`, in the TUI.

Primary areas: `core/scorer.py`, reporting, artifact schema checks, and result
views.

### P2 — Optional standards-based tracing

Add an OpenTelemetry-compatible adapter only after call, state, and attempt
identities are stable. Existing JSON artifacts remain the reproducibility source
of truth; external tracing should be optional and must receive only redacted,
bounded attributes.

## LangGraph direction

Keep the canonical topology:

```text
START
-> recon
-> orchestrator
-> payload_candidate_builder
-> payload_validator
-> selected method agent or chaining_router
-> chaining_router
-> orchestrator or payload_candidate_builder or scorer
-> END
```

Do not replace it with a free-form ReAct loop, dynamic agent creation, or an
LLM-editable graph. Preserve the validation boundary and verifier-inside-method-
agent design. The improvement is durable and inspectable execution of the
existing graph, not greater autonomy.

## TUI quality-of-life backlog

### T1 — Resolved execution plan preview

Before starting, show the fully resolved matrix: coordinate count, condition,
surface, security level, method, payload mode, repeat, effective provider/model
per role, reasoning effort, token and timeout limits, retry policy, expected
model calls, output directory, and config fingerprint. Clearly distinguish
explicit values from inherited/default values and flag unsupported combinations.

### T2 — Live coordinate table

Provide one sortable/filterable row per coordinate with status, current node,
provider/model, elapsed time, attempts, tokens, fallback state, failure class,
and artifact availability. Preserve a compact aggregate header for overall
progress.

### T3 — Structured failure inspector

Render the canonical failure object as fields rather than a long log string:
failure class, provider/model/role, endpoint, HTTP status, request ID, call ID,
attempt/deadline information, parse status, bounded provider message, and
remediation. Support copying the redacted JSON and jumping to the relevant
event/artifact.

### T4 — Resume and targeted retry

When durable checkpoints exist, expose resume from checkpoint, retry selected
coordinate, and rerun with a changed provider/profile. Always show which state is
reused and which nodes/actions will execute again.

### T5 — Trace navigation

Add search, event-type/node/coordinate filters, pause-follow, jump to failure,
and copy redacted event. Retain bounded ingestion/backpressure behavior.

### T6 — Run comparison

Compare runs with the same config fingerprint or experiment grouping. Show
coordinate-level deltas for verdict, scores, attempts, latency, token use, cost,
fallbacks, and failure class.

### T7 — Honest ETA and cost

Display estimates with confidence/coverage and show `N/A` when the underlying
usage, pricing, or sample size is insufficient.

### T8 — Operator commands and background work

- Add a harness-specific command palette for start, cancel, resume, open latest
  failure, toggle follow, filter coordinate, run Doctor, and export artifact.
- Move long-running TUI work onto Textual workers with explicit progress,
  cancellation, and error delivery instead of unmanaged daemon threads.
- Add headless/snapshot tests across narrow and wide terminals, empty state,
  active runs, partial failures, terminal failures, and oversized event streams.

## Suggested implementation sequence

1. Define state inventory, remove rendered prompt/response payloads from
   persistent state, and add state/checkpoint versions.
2. Add SQLite checkpointing, stable coordinate/thread IDs, compatibility checks,
   and CLI resume.
3. Introduce `ModelCallSpec` / `ModelCallResult`, capability resolution,
   application-owned attempts, total deadlines, and cancellation tests.
4. Add prompt manifests, typed builders, behavioral fixtures, replay reports,
   and prompt-change gates.
5. Correct consistency and cost availability semantics.
6. Build TUI resolved-plan, coordinate-table, failure-inspector, and resume/retry
   flows.
7. Add comparison, command palette, Textual workers, snapshot coverage, and the
   optional tracing adapter.

Each phase should be a separately reviewable change. Do not combine checkpoint
migration, retry semantics, prompt changes, and major TUI redesign into one
commit.

## Acceptance criteria

- A killed process can restart and resume the same coordinate without rerunning
  completed nodes or silently duplicating completed external actions.
- Incompatible config, graph, or state versions refuse resume with an actionable
  diagnostic.
- Every model-call attempt and total deadline are represented accurately in
  events and artifacts; no hidden nested retry invalidates the count.
- Cancellation bounds queued work, backoff, and active calls to a documented and
  tested latency.
- Persistent graph state contains no rendered system/user prompts or full model
  responses; artifacts retain the auditable, redacted copies and hashes.
- Prompt/template changes run role-specific behavioral evaluations, including
  injection and containment fixtures, before merge.
- Cost and consistency fields are unavailable rather than zero unless their
  required data and computation are present.
- The TUI can identify, inspect, copy, resume, and selectively retry a failed
  coordinate without searching raw files manually.
- Offline unit, integration, artifact-audit, and TUI headless/snapshot suites
  pass. Final experiment acceptance also requires the full authorized DVWA
  matrix with live provider evidence; smoke tests alone are not sufficient.

## Recommended first implementation slice

Start with a design-only state inventory and checkpoint compatibility contract,
then implement SQLite persistence for one coordinate without changing prompt or
retry behavior. This produces a small, measurable slice:

1. Identify persistent versus artifact-only state fields.
2. Add schema/build/config identity to checkpoints.
3. Compile the graph with an experiment-local SQLite saver.
4. Add `--resume` validation and one crash/restart integration test.
5. Add a minimal TUI resumable-run indicator; defer the full retry UX.

Only after this slice is stable should active-call retry and cancellation
semantics change.

## Research sources

- LangGraph persistence:
  <https://docs.langchain.com/oss/python/langgraph/persistence>
- LangGraph Graph API:
  <https://docs.langchain.com/oss/python/langgraph/use-graph-api>
- LangGraph design guidance:
  <https://docs.langchain.com/oss/python/langgraph/thinking-in-langgraph>
- OpenAI prompt engineering:
  <https://developers.openai.com/api/docs/guides/prompt-engineering>
- OpenAI evaluation best practices:
  <https://developers.openai.com/api/docs/guides/evaluation-best-practices>
- Gemini API troubleshooting and retry guidance:
  <https://ai.google.dev/gemini-api/docs/troubleshooting>
- OWASP prompt-injection prevention:
  <https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html>
- Textual command palette:
  <https://textual.textualize.io/guide/command_palette/>
- Textual workers:
  <https://textual.textualize.io/guide/workers/>
- Textual testing:
  <https://textual.textualize.io/guide/testing/>

## Repository evidence reviewed

- Graph compilation and current checkpointer: `core/graph_builder.py`
- Graph invocation, thread configuration, and cancellation checks:
  `evaluation/runner.py`
- State reducers and accumulated messages: `core/state.py`
- Prompt/response state updates: `agents/orchestrator.py` and payload-generation
  code
- Model dispatch, structured output, records, and failure envelopes:
  `llm/runtime.py`, `llm/provider.py`, `llm/diagnostics.py`
- Structural prompt tests: `tests/test_llm_context_capsules.py`
- Placeholder metric values: `core/scorer.py`
- Dashboard, cancellation, result filters, artifact detail, and validation UI:
  `tesis/tui.py`

## Explicit non-goals

- No new vulnerability surfaces or methods.
- No dynamic LLM-created agents or runtime AKG mutation.
- No verifier node added to LangGraph.
- No prompt-based policy bypass or external-target adaptation.
- No automatic live Doctor/preflight gate before every experiment.
- No claim that these recommendations are already implemented.
