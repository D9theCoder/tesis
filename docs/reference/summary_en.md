# Technical Thesis Summary

## 1. Fixed Scope

| Aspect          | Decision                                                                                               |
| --------------- | ------------------------------------------------------------------------------------------------------ |
| Target          | DVWA as the only testing target                                                                        |
| Environment     | Local sandbox, isolated from external targets                                                          |
| Surface         | SQL Injection, Access Control, Brute Force                                                             |
| Security level  | Low, Medium, High                                                                                      |
| LLM role        | Reconnaissance interpretation, method selection, and payload variant generation within AKG constraints |
| AKG             | Static, predefined, pre-validated, payload-aware                                                       |
| Agent           | Static method agents, not created by the LLM at runtime                                                |
| Payload         | Hybrid: validated static seeds plus AKG-constrained LLM variants                                       |
| Main experiment | Linear LLM plus hybrid payloads vs AKG-guided LLM plus hybrid payloads                                 |
| Model           | At least one commercial SOTA model and one open-source or open-weight model                            |
| Scoring         | 0 to 4 rubric, separated by evaluation dimension                                                       |

Other DVWA modules such as Command Injection, File Upload, LFI, CSRF, XSS, Weak Session IDs, Insecure CAPTCHA, JavaScript Attacks, and Open HTTP Redirect are outside the scope.

Credential stuffing is also outside the scope because DVWA does not provide a breach-data environment.

## 2. Technical Stack

| Component       | Technology                                       | Function                                                              |
| --------------- | ------------------------------------------------ | --------------------------------------------------------------------- |
| Main language   | Python 3.12                                      | Framework implementation                                              |
| Target          | DVWA 2.5                                         | Web application sandbox                                               |
| Knowledge graph | NetworkX DiGraph 3.6.1                           | AKG, precondition check, chain traversal                              |
| Orchestration   | LangGraph 1.2.1                                  | Stateful workflow, conditional routing, fallback, scoring             |
| LLM abstraction | LangChain 1.3.1 or internal provider abstraction | Integration with Gemini, OpenAI, Claude, and open-compatible endpoint |
| HTTP client     | httpx 0.28.1                                     | Request and session handling to DVWA                                  |
| HTML parser     | BeautifulSoup4 4.14.3                            | Parsing forms, parameters, and CSRF token                             |
| State schema    | TypedDict plus LangGraph reducers                | State sharing across nodes                                            |
| Interface       | Textual 8.x                                      | Keyboard-first setup, live dashboard, validation, and result review   |
| Configuration   | ruamel.yaml round-trip YAML                      | Typed forms plus comment- and unknown-key-preserving advanced editing |
| Unit test       | pytest 9.0.3                                     | Framework component validation                                        |
| Statistics      | SciPy 1.17.1                                     | Mann-Whitney U test if needed                                         |
| Output          | JSON, Markdown                                   | Run artifacts and experiment reports                                  |

### 2.1 Interactive experiment harness

`python -m tesis run` is the sole entry point. Without additional flags it
opens the interactive TUI, which owns single-run and matrix setup,
configuration validation, settings, framework validation, live execution,
recent results, exports, and framework information. For automation or an LLM
driving a terminal, `python -m tesis run --headless --mode single|matrix`
accepts explicit coordinate flags and uses the same runners. The repository
root `config.yaml` remains the default configuration document.

The workspace uses a narrow pipeline beside runs and evidence at wide sizes,
and one selected pane at smaller sizes. Tab/Shift+Tab move focus; arrows,
PageUp/PageDown, and Home/End navigate the focused control. `/` opens commands
with keyboard selection while typing; `?` opens a centered help popup. Settings
fills the window, with separate API provider, ChatGPT account, runtime, and
evaluator categories. Plan and launch Review show approved fields and effective
API protocols without rendering model objects or credentials. These UI changes
retain profile identities, role-specific reasoning inheritance, and independent
evaluator configuration. See the [TUI design](tui-design.md) for the keyboard
contract and the distinction between implementation and validation evidence.

Settings presents labeled configuration rows and compact evaluator forms.
Up/Down selects categories; Left/Right moves between the category rail, content,
and optional evaluator context while text inputs retain caret navigation.
Selectors use plain option lists, and boolean/multiple selection uses ASCII
`[*]` and `[-]` markers throughout the TUI, including provider model selection.

UI redraws reuse configuration and draft projections until their source inputs
change. Launch previews and YAML-derived controls debounce independently of
typing, while live display work is limited to 30 Hz without skipping state
events. Tables update changed cells and navigation avoids full dashboard
rebuilds. Every Start still performs fresh canonical configuration validation.
Direct local data-method profiling is documented in the
[responsiveness notes](tui-design.md#responsiveness); it does not establish
physical terminal or keyboard latency.

Core runtime code is presentation-independent. Runners optionally accept a
`RuntimeEventSink` and `CancellationToken`, attach normalized LangChain model
callbacks, and emit lifecycle, graph, payload, verification, safety, scoring,
failure, and matrix-progress events. Textual consumes these events from a
daemon thread through a bounded, coalescing UI queue. Trace content is
centrally redacted and live rendering is bounded, while artifacts retain the
complete execution log. Cancellation is cooperative at safe graph/matrix
boundaries and persists the latest state with status `cancelled`; a second
cancel request closes the TUI without waiting for a blocked operation.

Both launchers execute resolved settings through `tesis.headless.run_resolved`.
This shared boundary forwards model profiles, runtime roles/cache/concurrency,
experiment condition, target method, payload mode, repeats, execution limits,
guardrail settings, and scoring configuration. It creates the artifact layout,
redacted event journal, and active runtime descriptor. In matrix mode, child
`run.*` lifecycle events cannot reset the parent identity, timer, or rows;
`matrix.run.*` events update the coordinates. The returned aggregate determines
the terminal UI, journal, and descriptor status. Terminalizing the descriptor
also stops its heartbeat, including on failure or cancellation.

Each physical execution receives a unique `execution_id`; the logical
experiment coordinate remains `run_id`. A secret-free `config_fingerprint`
identifies equivalent effective experiment setups while excluding execution
identity, timestamps, repeat index, and output paths. Historical artifacts are
read without migration or rewriting. New runs are allocated below
`results/runs` as `single-run-YYYY-MM-DD` or `matrix-YYYY-MM-DD` directories;
same-day collisions receive a numeric suffix. Matrix directories contain
sequence-and-coordinate child folders plus `experiment.manifest.json`, while
legacy flat artifacts remain untouched.

## 3. Runtime Architecture

The framework consists of five technical layers:

```text
DVWA Sandbox
  -> Foundation Layer
  -> Static Payload-Aware AKG
  -> LangGraph Execution Graph
  -> Multi-LLM Abstraction Layer
```

### 3.1 DVWA Sandbox

DVWA provides endpoints, forms, sessions, parameters, and application responses. All requests are sent through `httpx` in a local environment.

### 3.2 Foundation Layer

The foundation layer contains utility components used by the entire workflow:

| Component           | Function                                                              |
| ------------------- | --------------------------------------------------------------------- |
| `session_manager`   | DVWA login, security level configuration, session validation          |
| `http_client`       | GET/POST requests, timeout handling, cookie handling                  |
| `recon`             | DVWA crawling, extraction of forms, tokens, endpoints, and parameters |
| `payload_library`   | Stores validated static payload seeds and metadata                    |
| `payload_generator` | Asks the LLM to create payload variants based on AKG constraints      |
| `payload_validator` | Rejects invalid payloads before execution                             |
| `payload_ranker`    | Sorts payload candidates within the attempt budget                    |
| `verifier`          | Evaluates response evidence, timing evidence, and success signals     |

### 3.3 Static Payload-Aware AKG

The AKG is represented as a `NetworkX DiGraph`. The AKG stores:

* surface node
* method node
* confirmed node
* outcome node
* chain edge
* observable precondition
* payload-generation profile
* validation rules
* expected success signals

The LLM must not create new nodes, new edges, or new agents at runtime.

### 3.4 LangGraph Execution Graph

Main flow:

```text
recon
  -> orchestrator
  -> payload_candidate_builder
  -> payload_validator
  -> method_agent
  -> chaining_router
  -> scorer
  -> END
```

Fallback path:

```text
payload_validator -> chaining_router
method_agent -> chaining_router
chaining_router -> orchestrator
chaining_router -> payload_candidate_builder
chaining_router -> scorer
```

Technical verification is performed inside the method agent with help from `verifier`, not as a separate LangGraph node.

### 3.5 Multi-LLM Abstraction Layer

The optional `api_providers` registry stores independent endpoints, API-key
references, protocols, and selected model lists. Each provider/model pair
expands into a stable named profile selectable as a single run or matrix
coordinate. New entries support OpenAI Responses, OpenAI Chat Completions, and
Anthropic Messages. TUI Settings can discover a catalog or accept manual IDs,
select models to retain, and save keys to `.env`. The runtime continues to
resolve role settings per coordinate and preserves method orchestration and
artifact identity. See [API provider configuration](api_providers.md).

The optional `openai_codex_auth` provider uses official Sign in with ChatGPT
OAuth and subscription-backed public Responses streaming. It preserves the
existing API-key providers and agent topology. Account credentials stay in
protected local storage; model choices come from the signed-in account's live
catalog through TUI Settings. The SIWC preview does not accept temperature or
output-token-limit fields, so those shared controls are omitted for this
provider and the limitation is recorded in call telemetry. An equal configured
token limit must not be reported as an equal enforced limit across providers.
See [SIWC setup and acceptance scope](sign_in_with_chatgpt.md).

All models are tested with the same configuration:

* same AKG
* same method agents
* same payload seeds
* same validator
* same candidate budget
* same thesis task and schema contract (with role-specific compact capsules)
* same scoring rubric
* same number of repetitions

### 3.6 LLM Runtime Acceleration

Model latency is reduced without changing the thesis conditions or sharing
adaptive knowledge between matrix coordinates. The repository configuration
enables a maximum of two concurrent LLM operations and a run-local cache:

```yaml
llm_runtime:
  max_concurrency: 2
  cache_scope: run
  roles:
    orchestrator:
      temperature: 0
      max_tokens: 8192  # shared ceiling for reasoning and final output
      structured_output: auto
    payload_generator:
      temperature: 0
      max_tokens: 8192  # shared ceiling for reasoning and final output
      structured_output: auto
```

Each role inherits its provider, endpoint, credentials, timeout, and default
model from its resolved profile. If no global `model_profile` or role-level
profile is set, the role remains unpinned and follows the provider of the
current matrix coordinate. An explicit role profile takes precedence over the
global profile; the global profile takes precedence over the coordinate
provider. An optional role-level `model_name` may override that model. The
payload-generator token limit defaults to
`min(512, 96 + 64 * candidate_budget)` when it is not explicitly set. The
headless `--model-profile PROFILE`/`TESIS_MODEL_PROFILE` and the TUI run-setup
selector can apply one named profile to both roles without editing the YAML.
The role-specific controls may still override the orchestrator or payload
profile independently. Effective concurrency remains bounded to 1--4;
single-run execution uses an effective concurrency of one.

Reasoning effort is an explicit, optional profile/role decoding control:
`low`, `medium`, `high`, `xhigh`, or `max`. Roles inherit profile effort unless
overridden. Precedence is CLI `--reasoning-effort` > `TESIS_REASONING_EFFORT` >
YAML role > profile, and either CLI/environment control applies to both roles.
Within a profile or role block, canonical `reasoning_effort` wins over legacy
`reasoning.effort`, `model_kwargs`, and `extra_body` forms; legacy values are
normalized and stripped from the provider request. Other LLM controls use the
same CLI > environment > YAML precedence, including concurrency, cache, model,
and role profile selectors. When profiles are configured, launcher provider
choices contain only their configured adapters; removing a Gemini profile
removes it from those choices.

OpenAI and OpenAI-compatible adapters send one canonical effort field, remove
temperature and conflicting legacy fields, and never silently lower a rejected
value. An explicit portable effort for Gemini or Claude raises an actionable
error; those providers require null/inherit plus native thinking configuration.
An explicit role token limit wins over the effective model profile's limit.
When both limits are omitted, an explicit effective effort defaults to the
shared 8,192-token reasoning-and-output ceiling; otherwise the historical role
defaults apply. Loader defaults are marked with `max_tokens_default` and are
resolved again for each coordinate's actual profile. Artifacts distinguish
`reasoning_effort_requested`, provider usage, and explicit
`reasoning_token_evidence`; they do not infer hidden reasoning from response
prose. Reasoning settings participate in client/cache fingerprints.

The launch form displays both role efforts and initially selects
`Keep per-role reasoning settings`. Leaving that selection unchanged preserves
different explicit or inherited values. Selecting one effort overrides both
roles; `Inherit profile effort for both roles` clears their role overrides.
Profile settings remain editable in the settings YAML editor.

The independent scoring evaluator freezes its profile's effective API mode,
reasoning effort, sampling settings, and provider options together with its own
token budget and retry limit. It uses the same provider adapter. A changed
effective evaluator configuration cannot silently replace an older artifact's
frozen judging configuration.

`scoring_evaluator.provider` selects the same registered provider/model ID as
the run and matrix selectors. The profile supplies the model, endpoint,
credentials, and API protocol; the resolved evaluator retains its execution
`adapter` separately from provider identity. Settings exposes an **AI evaluator**
section for selecting that pair, the review mode, and independent attempt,
token, and timeout limits. Apply stages the draft and Save persists it without
starting evaluation. Legacy evaluator sections retain their historical resolved
shape. Changed identities or effective settings require a new frozen review
configuration; existing artifacts are never rewritten.

Standalone `python -m tesis doctor` runs only when requested. Its 11 offline
checks cover the fixed 3-surface/9-method/3-level/3-payload-mode/2-condition
scope, AKG invariants, LangGraph compilation, all 81 static-seed coordinates,
request and redirect containment, profiles/roles, credentials, endpoints,
dependencies (including SQLite checkpoints), output writability, and reasoning
controls, including the selected evaluator's reasoning effort. Doctor rejects
a missing requested config file before environment resolution. Offline service
checks are explicitly skipped; local success does not
prove server availability. The artifact check tests `output_dir/runs` and a
temporary write/flush at its nearest existing directory. `--live` adds one
benign structured model probe per role and contained DVWA authentication,
security-level, and surface checks. Surface pages are probed at the requested
high level, with the level-check result reported separately. Model probes use
the effective role/profile and token budget. Valid structured output passes
without optional usage telemetry; absent usage or reasoning-token evidence
leaves provider-side reasoning unverified. Offline reasoning checks establish
adapter forwarding support, not model-specific acceptance. These are readiness
probes, not proof that every experiment coordinate or attack will succeed.

JSON Doctor output is one object containing `status`, a
`summary{passed,failed,skipped,total}`, and `checks`; each check contains `id`,
`category`, `status`, `summary`, `details`, and `remediation`. Top-level status
is failed only when at least one check fails; skipped checks remain separate.
Exit codes are 0 for passed, 1 for failed, and 2 for usage errors. Failures
accumulate with repair guidance and skipped live checks remain explicit. Doctor
never runs automatically, gates runs, quarantines providers, or alters runtime
topology.
Opening the Doctor panel starts fresh offline checks. Escape stops its local
subprocess and closes the panel; reopening starts again. Remote requests already
submitted may still finish at the service. The panel shows plain-language results
with technical details available on demand, while CLI JSON keeps the full report.
Provider failures retain redacted role/coordinate/model context and remediation,
walk exception chains for status and request IDs, and redact every URL query and
fragment value. AKG validation failures identify the invalid graph contract.
These controls do not change the scoring rubric or the two primary hybrid
experiment conditions.

The runtime sends a stable system message containing DVWA authorization and
containment rules, role instructions, and the schema version. A coordinate
gets only a compact, coordinate-local capsule. The orchestrator receives the
surface, security level, viable/attempted/blocked/failed methods,
observations, scores, confirmed findings, outcomes, payload mode, and
remaining iterations. The payload generator receives the selected method,
security level, applicable observations, selected static seeds, mutation
constraints, expected signals, and candidate budget. Full conversation
history, raw HTTP bodies and traces, credentials discovered during execution,
earlier refusal wording, and data from other coordinates are not replayed.
Existing `messages` fields may remain for audit compatibility, but they are not
an automatic model context.

Mutation generation is stage-aware. For `hybrid` and
`llm_mutation_only`, the prompt exposes static seeds with an execution-ready
stage (`exploit` or `bypass`), together with their stage, target parameter, and
expected signal. Detection-only `probe` seeds remain in the local seed catalog
for method-agent preconditions but are not mutation sources for Stage 2. A
generated variant linked to a probe seed is rejected by the builder; if no
execution-ready variant remains, the run records the deterministic static-seed
fallback. `static_only` does not
invoke this LLM mutation path and continues to use the static seed queue.

The orchestrator returns only the following structured decision; expected
outcome and fallback are derived deterministically:

```json
{"next_agent":"sqli_union","reason_code":"best_viable"}
```

The payload generator returns only constrained variants:

```json
{
  "variants": [
    {
      "source_seed_id": "seed-id",
      "mutation_type": "case_variant",
      "payload_or_logic": "value"
    }
  ]
}
```

Candidate ID, source, method, stage, target parameter, expected signal, and
provenance are populated deterministically after validation. In
`structured_output: auto`, the first invocation performs a local client
capability check without a provider request, then uses native structured output
when available or the compact JSON prompt otherwise. Invalid, incomplete, or
schema-invalid output falls back
immediately to static seeds and is recorded; there is no unbounded repair
loop. Only an actual refusal activates guardrail handling. A context capsule
or a cache hit does not count as a guardrail check.

One matrix-scoped runtime service owns bounded client pools keyed by role and a
redacted model-configuration fingerprint. Calls lease clients so provider
connections can be reused without assuming that one provider client is safe
to share concurrently. A coordinate-local context owns its cache and
telemetry; it is never reused by another coordinate. Only successful,
schema-valid responses are cached. Cache keys include role, model fingerprint,
schema version, canonical system/user messages, token limit, and decoding
settings, so a schema or prompt change invalidates old entries. Cache entries
are limited to the current run and never transfer adaptive outcomes or payload
history between coordinates.

Matrix workers may overlap only in the LLM portion up to
`llm_max_concurrency`. Complete reconnaissance and method-agent nodes use one
matrix-wide HTTP semaphore, so DVWA requests, timing evidence, and rate-limit
signals remain serialized. Orchestrator and payload-generation operations are
outside that HTTP gate and may overlap. Coordinate directories and indexes are
allocated before workers start; results are written back in canonical
coordinate order, and a serialized event sink prevents concurrent TUI state
corruption. Cancellation stops new submissions, lets active LLM/HTTP work
reach a safe boundary, and persists completed and cancelled artifacts.

Every call preserves `llm_activity` and adds secret-free role performance
records containing prompt hash, role, model fingerprint, cache hit/miss, queue
wait, call duration, structured-output mode, parse status,
`reasoning_effort_requested`, `provider_usage`, and
`reasoning_token_evidence` when explicitly reported. Aggregate telemetry
reports time by role, cache-hit rate, invalid-output rate, and peak
LLM/DVWA-node concurrency. Raw prompts and secrets are excluded from
performance summaries.

`calls` counts logical calls, while `attempt_records`, `attempts`, and
`provider_dispatches` retain the individual provider dispatches, including a
native-schema rejection followed by JSON-prompt fallback. A cache hit makes
zero dispatches. SDK retries default to zero on every adapter. With explicit
SDK retries, the exact `provider_requests` count remains null;
`known_provider_requests` and `provider_request_count_unknown_calls` keep known
counts and uncertainty separate in run and matrix summaries. Configured DVWA
credentials are scoped to each coordinate's session owner, including oracle
collection, and are never added to graph state or checkpoint inputs.

### 3.7 Architecture Change Log: Before and After

This subsection records the implementation delta introduced by the accelerated
runtime. It is an architectural change to execution and observability, not a
change to the thesis experiment factors. The same DVWA scope, AKG, method
registry, payload seeds, validator, scoring rubric, security levels, payload
modes, conditions, and repeat policy remain in force.

#### 3.7.1 Execution topology and concurrency boundary

Before the runtime change, the matrix runner submitted coordinates serially.
Provider clients were obtained at individual agent call sites, and the
architecture did not distinguish the part of a coordinate that could safely
overlap from the part that must preserve DVWA timing and session evidence. In
practice, the whole coordinate was a serial unit:

```text
coordinate 1: recon -> orchestrator -> payload -> method -> scoring
coordinate 2: recon -> orchestrator -> payload -> method -> scoring
coordinate 3: recon -> orchestrator -> payload -> method -> scoring
```

After the change, a matrix-scoped `LLMRuntime` owns the concurrency controls.
Coordinate workers may overlap only while they are waiting for or executing
LLM operations, with an effective bound of `llm_max_concurrency` (2 in the
repository configuration). Reconnaissance and complete method-agent nodes are
wrapped by one HTTP semaphore of size 1:

```text
matrix workers (maximum two)
  coordinate A: [orchestrator/payload LLM] ----┐
  coordinate B: [orchestrator/payload LLM] ----┤ may overlap
                                               │
  coordinate A: [recon or method HTTP] --------┤ HTTP gate = 1
  coordinate B: [recon or method HTTP] --------┘ waits
```

This boundary is deliberate. LLM latency is parallelized, but simultaneous
DVWA requests are not used as thesis evidence. SQLi timing requests, brute
force requests, cookies, security-level state, rate-limit signals, and timing
classification therefore remain serialized. A single-coordinate run uses the
same service with an effective concurrency of one. Full-coordinate concurrency
is documented separately as a feasibility study and is not enabled by this
architecture.

#### 3.7.2 Model-client ownership and coordinate isolation

Before, each orchestration or payload-generation call could construct or obtain
a provider client at the node boundary. There was no matrix-wide pool identity
for separating roles and incompatible model configurations, and no run-local
response cache that could be audited per coordinate.

After, `llm/runtime.py` provides one matrix-scoped service with bounded client
pools. A pool is keyed by `(role, redacted model-configuration fingerprint)`:

* the orchestrator and payload generator do not accidentally share incompatible
  model settings;
* clients are leased and returned, so connections can be reused without
  assuming a provider client is thread-safe;
* the fingerprint identifies configuration differences without storing API
  keys or other secrets;
* every coordinate receives its own call context, cache, call sequence, and
  performance records.

The cache is deliberately coordinate-local and run-local. A cache entry is
created only after a response passes JSON parsing and schema validation. Its
key includes the role, model fingerprint, schema version, canonical system and
user messages, token limit, temperature, and structured-output setting. Thus a
prompt or schema change invalidates the old entry, and adaptive outcomes or
payload history cannot leak from one matrix coordinate to another. Cache hits
are visible in telemetry but do not perform a new provider request or a new
guardrail check.

#### 3.7.3 Context and output contract

The legacy model contract exposed a larger, less stable response surface. The
orchestrator response could contain a selected method, reasoning summary,
fallback plan, score, and AKG updates. Payload generation could return verbose
candidate objects with metadata that the harness could derive itself. Parsing
was therefore dependent on free-form text and invalid JSON was common.

The new contract separates model judgment from deterministic harness data:

| Concern | Before | After |
| --- | --- | --- |
| Orchestrator input | Broad state and legacy message context could be replayed | Compact capsule containing surface, level, AKG-viable/attempted/blocked/failed methods, observations, scores, findings, outcomes, payload mode, and remaining iterations |
| Payload input | Method context plus larger candidate-generation context | Selected method, level, applicable observations, execution-ready static seeds with stage, mutation constraints, expected signals, and budget |
| Orchestrator output | Verbose/free-form selection and planning fields | `{"next_agent":"...","reason_code":"..."}` |
| Payload output | Larger candidate objects and model-supplied metadata | One constrained Stage 2 variant with `source_seed_id`, `mutation_type`, and `payload_or_logic`; probe-seed provenance is rejected |
| Derived metadata | Partly supplied by the model | Candidate ID, method, stage, target parameter, expected signal, fallback, score, and provenance are filled by the harness |
| Context reuse | Conversation/history could influence later calls | Coordinate-local capsules; full history, raw HTTP bodies, credentials, refusal wording, and other-coordinate outcomes are excluded |

Native structured output is selected after a local client capability check on
the first invocation; that check sends no provider request. The
OpenAI-compatible path uses function calling; other providers use JSON Schema.
When `structured_output` is `auto`, an unavailable local capability or a
gateway error that specifically reports native structured output as unsupported
selects one compact JSON-prompt fallback. When `auto` keeps native mode but the
wrapper reports `parsed=None` with no tool calls, no invalid tool calls, no
refusal, and no truncation, a complete native JSON object returned as text is
validated by the same validator without an extra provider call and recorded as
`native_*_text` with a `native_text` fallback marker. Explicit
`structured_output: native` never reinterprets plain text: the same shape still
fails. Authentication, rate-limit, timeout,
connection, and other provider failures do not trigger this fallback. Response
text is normalized from strings and list-based `text`/`output_text` blocks.
The local validator remains authoritative in both paths.

#### 3.7.4 Failure classification and fallback behavior

The old path treated several different failures as variations of “the model
did not give usable JSON.” The new path preserves their distinction in both
state and artifacts:

| Condition | Before | After |
| --- | --- | --- |
| Malformed JSON | Loose parsing or discarded response; cause was difficult to separate from other failures | `parse_status=invalid`, optional `invalid_json_events`, deterministic role-specific fallback, and no cache insertion |
| Truncated, length-limited, or provider-reported `incomplete` output | Could be mistaken for ordinary malformed JSON | `parse_status=incomplete`; no cache insertion and immediate fallback |
| Disallowed method | A model could name an unavailable or cross-surface method before the final route check | Dynamic allowed-method schema plus local allow-list; the name is never executable, and `fallback_events` records the deterministic choice |
| Probe seed used for Stage 2 mutation | A detection probe could be mutated and treated as an exploit candidate | The prompt exposes only `exploit`/`bypass` seeds, stage is explicit, and probe-derived variants trigger a recorded static-seed fallback |
| Payload validation failure | Invalid model candidates could reduce the usable candidate set without a complete provenance trail | Validation results are authoritative for execution: invalid generated candidates remain audit history but cannot enter the method queue; static seeds are used when no generated candidate is valid, and provenance/validation reasons are stored |
| Unsafe resource-cost mutation | A model could submit an unbounded delay or CPU-heavy SQL mutation and consume the target/request timeout budget | `BENCHMARK(...)` and delay mutations above the bounded safety threshold are rejected before HTTP execution with `unsafe_resource_cost`; the generated payload is never silently treated as a successful exploit |
| Provider/network failure | A fallback could make a partial run appear successful | Exception-chain status/request IDs and redacted context/remediation are recorded; `LLM_RUNTIME_FAILURE` marks `execution_status=failed`, and native-output fallback occurs only for a specific unsupported-capability error |
| No AKG-viable method | The orchestrator could still be called and return an impossible value, producing an ambiguous terminal result | Automatic AKG-guided selection skips the LLM call, routes to `scorer`, and records `NO_VIABLE_METHODS` |
| Method exhausted without confirmation | A scorer stop after an HTTP request could be reported only as `UNSPECIFIED` | If all AKG-viable methods were attempted or blocked without a confirmed vulnerability or enabling outcome, the orchestrator retains legacy `task_result=INCOMPLETE` and `incomplete_reason=ALL_METHODS_FAILED`, while normal terminal execution is `completed` and the security outcome follows its evidence; an HTTP 2xx alone cannot establish confirmation or a verified negative |

There is no unbounded repair loop for malformed or incomplete output. The
orchestrator uses an AKG-constrained deterministic method fallback or scorer;
the payload generator uses static seeds. A static fallback is never treated as
proof that the model-backed call succeeded. The payload validator and HTTP
containment layers remain mandatory after any fallback.

#### 3.7.5 Guardrail/refusal handling

Before, refusal handling and output parsing shared the same broader model
path, so a refusal, malformed JSON response, and provider exception could be
reported too similarly. After the change, guardrail handling is activated only
by an actual refusal response. A context capsule, cache hit, invalid JSON,
schema failure, or timeout is not counted as a guardrail activation.

For an orchestrator refusal in reactive mode, the runtime:

1. records the refusal check and guardrail event;
2. applies a bounded number of structure-only, authorized-DVWA clarification
   retries when configured;
3. records whether the retry succeeded or the retry budget was exhausted; and
4. uses the AKG-constrained fallback or scorer if the refusal remains.

The retry path does not use jailbreaks, deception, roleplay, prompt injection,
or external-target adaptation. A refusal does not mark the fallback method as
blocked, because the refusal is a model-response condition rather than method
evidence. Payload-generation refusals immediately discard generated variants,
record `payload_guardrail_activations`, and use static seeds.

#### 3.7.6 Artifact and observability delta

The legacy artifact already retained core experiment metadata, final state,
execution evidence, and coarse LLM activity. It did not consistently expose
the role-level information needed to explain latency, caching, structured
output capability, or concurrency. The new artifact adds the following audit
layers:

| Artifact layer | Before | After |
| --- | --- | --- |
| Run identity | Run metadata and final state | Run ID plus execution ID, configuration fingerprint, condition, repeat, and effective runtime configuration |
| Provider activity | Coarse started/completed/failure information | Lifecycle records reconciled against runtime records so one call is not counted twice |
| Per-call performance | Limited or provider-specific evidence | Role, provider, model fingerprint, prompt hash, cache hit, queue wait, duration, structured-output mode, parse status, `reasoning_effort_requested`, `provider_usage`, and explicit `reasoning_token_evidence` |
| Output quality | Invalid JSON/fallback fields were present but not uniformly classified | Separate invalid, incomplete, provider-error, refusal, fallback, and no-viable-method evidence |
| Payload audit | Candidates and execution evidence | Generated candidates, accepted/rejected validation results, deterministic provenance, source seed, mutation, target parameter, and expected signal |
| Concurrency | No per-artifact peak LLM/DVWA-node evidence | Peak LLM concurrency, peak DVWA-node concurrency, role time, cache-hit rate, and invalid-output rate |
| Failure audit | Primary artifact could be the only record | Error artifacts include terminal reason, recent events, provider activity, fallback events, and containment events |
| Matrix aggregation | Canonical experiment totals | Canonical coordinate ordering plus aggregate audit totals and role-level performance summaries |

Performance summaries contain hashes and redacted fingerprints rather than raw
prompts or secrets. The execution log and optional JSONL sidecar remain
available for event-level audit, while cancelled coordinates are persisted
with a `CANCELLED` reason instead of being silently dropped.

#### 3.7.7 Deterministic ordering and cancellation

Serial execution previously made artifact ordering implicit. The concurrent
runner now preallocates coordinate directories and indexes before submitting
workers. Workers may finish out of order, but each result is written into its
original coordinate position and aggregate output remains canonical. A
serialized event-sink adapter prevents concurrent workers from corrupting TUI
state or event order.

When cancellation is requested, the runner stops submitting new coordinates,
allows active LLM and serialized HTTP operations to reach a safe boundary, and
persists completed and cancelled artifacts. This preserves partial evidence
without treating a cancelled coordinate as a successful experiment.

#### 3.7.8 Thesis invariants preserved by the architecture change

The before/after change is intended to improve latency and auditability only.
It does not:

* add a vulnerability surface or a dynamic method agent;
* modify the static AKG, its preconditions, or chain semantics;
* share adaptive observations, payload history, or confirmed outcomes between
  coordinates;
* execute unvalidated payloads;
* run simultaneous timing-sensitive DVWA requests against one instance;
* alter the `linear_hybrid` versus `akg_guided_hybrid` condition definition;
* alter the scoring dimensions or manual-scoring evidence requirements.

The implementation therefore changes the runtime envelope around the thesis
workflow while keeping the experiment’s causal factors and evidence rules
constant.

#### 3.7.9 Stage-aware payload mutation: no AKG or LangGraph topology change

The mutation-only remediation refines the payload-generation and execution
contracts but does not change the framework architecture. The AKG remains
static, predefined, pre-validated, and payload-aware; no AKG node, edge,
precondition, payload profile, or chain semantic was added or removed. The
LangGraph topology also remains unchanged:
`recon -> orchestrator -> payload_candidate_builder -> payload_validator ->
method agent -> chaining_router -> scorer/END`, with the existing conditional
routes and state reducers. The prompt and builder expose only execution-ready
seeds; the validator rejects unsafe or out-of-scope variants, and the routing
and method-queue helpers treat only explicit `valid` validation results as
executable. Accumulated candidate history is retained for audit, but rejected
history cannot be dispatched to a method agent.

#### 3.7.10 High-security DVWA transport reconciliation

The static-only high-level acceptance path includes two deterministic DVWA
transport accommodations. During authenticated reconnaissance, the framework
looks for `session-input.php` in the high SQLi page and registers the contained
POST endpoint with its `id` parameter. High UNION and error SQLi agents POST the
candidate to that session-input endpoint, require a successful submission, and
reload the normal SQLi page before verification. High boolean/time-blind agents
set the URL-encoded `id` cookie and GET `/vulnerabilities/sqli_blind/`, matching
the deployed blind module. A blind false predicate or a SLEEP expression returning zero may return 404 with
the documented missing-ID body; generic error pages remain negative evidence. Low and medium SQLi request paths remain
unchanged. A high-level union profile also retains both `-- -` and `#` MySQL
comment forms as static fallback seeds.

For high brute-force probing and exploitation, each credential request fetches
a fresh `user_token`. A response containing `CSRF token is incorrect` triggers
one bounded fresh-token retry for that same credential. DVWA high-level random
sleep is not treated as a relative-latency rate-limit signal; explicit status,
header, and body throttle markers remain authoritative. CAPTCHA solving remains
out of scope.

Low/medium brute-force timing probes require at least 100 ms absolute growth
as well as the existing threefold latency ratio before inferring throttling.
Tiny relative changes alone cannot stop credential execution. This remains a
bounded heuristic; repeated matched controls are needed if jitter exceeds the
floor. Explicit throttle markers remain authoritative.

These are level-scoped HTTP/session and evidence-handling changes exercised by
the `static_only` acceptance coordinate. They do not add AKG nodes, edges,
preconditions, payload profiles, or method agents, and they do not change the
LangGraph topology or the verifier boundary. Mutation-only payload generation
was not changed by this reconciliation.

## 4. AKG Technical Model

### 4.1 Node Types

| Node type      | Function                                                     |
| -------------- | ------------------------------------------------------------ |
| Entry node     | Conceptual starting point, for example `unauthenticated`     |
| Surface node   | Surface grouping: `sqli`, `access_control`, `brute_force`    |
| Method node    | Exploitation method that can be selected by the orchestrator |
| Confirmed node | Evidence that a method produced a valid success signal       |
| Outcome node   | Follow-up result that can be used for scoring or chaining    |

### 4.2 Edge Types

| Edge type                | Relation                                |
| ------------------------ | --------------------------------------- |
| Discovery edge           | `unauthenticated -> surface`            |
| Method availability edge | `surface -> method`                     |
| Confirmation edge        | `method -> method_confirmed`            |
| Aggregation edge         | `method_confirmed -> surface_confirmed` |
| Outcome edge             | `confirmed -> outcome`                  |
| Chain edge               | `outcome -> next_method`                |

A chain edge must have at least the following attributes:

```text
is_chain
preconditions
target_agent
priority
```

### 4.3 Method Coverage

| Surface        | Method node              | Agent                          | Main precondition                |
| -------------- | ------------------------ | ------------------------------ | -------------------------------- |
| SQL Injection  | `sqli_union`             | `sqli_union_agent`             | `union_select_possible`          |
| SQL Injection  | `sqli_error`             | `sqli_error_agent`             | `error_messages_enabled`         |
| SQL Injection  | `sqli_boolean_blind`     | `sqli_boolean_blind_agent`     | `response_diff_detectable`       |
| SQL Injection  | `sqli_time_blind`        | `sqli_time_blind_agent`        | `response_delay_measurable`      |
| Access Control | `ac_idor`                | `ac_idor_agent`                | `object_ids_enumerable`          |
| Access Control | `ac_vertical_escalation` | `ac_vertical_escalation_agent` | `role_based_access_present`      |
| Access Control | `ac_force_browse`        | `ac_force_browse_agent`        | `force_browse_endpoints_visible` |
| Brute Force    | `bf_dictionary`          | `bf_dictionary_agent`          | `no_rate_limit`                  |
| Brute Force    | `bf_spray`               | `bf_spray_agent`               | `no_rate_limit`                  |

### 4.4 Payload Profile Fields

Each method node has a payload profile:

```text
seed_payload_refs
allowed_mutation_types
forbidden_mutation_types
validation_rules
expected_success_signals
payload_budget
provenance_required
output_schema
```

## 5. Main Workflow

### 5.1 Recon

Recon produces:

* endpoint list
* form method and parameters
* CSRF token
* detected security level
* observable preconditions
* target module mapping

Example observation keys:

```text
error_messages_enabled
union_select_possible
response_diff_detectable
response_delay_measurable
object_ids_enumerable
role_based_access_present
force_browse_endpoints_visible
no_rate_limit
low_priv_session_available
```

### 5.2 Orchestrator

The orchestrator receives:

* current surface
* security level
* observations
* viable methods from AKG
* attempted methods
* failed methods
* blocked methods
* current scores
* confirmed findings
* achieved outcomes
* payload mode
* remaining iteration budget

The LLM sees only the compact orchestrator capsule and returns:

```json
{"next_agent":"sqli_union","reason_code":"best_viable"}
```

`selected_method`, expected outcome, fallback plan, AKG path updates, and
scores are derived deterministically. Invalid output is recorded and uses the
static/AKG fallback path described in section 3.6.

### 5.3 Payload Candidate Builder

The builder loads the full static seed catalog from `payload_library`, then
creates LLM variants if `hybrid` or `llm_mutation_only` is active. The mutation
prompt exposes only execution-ready `exploit`/`bypass` seeds and labels their
stage, target parameter, and expected signal. Probe seeds remain available for
Stage 1 method-agent preconditions but are not valid mutation sources for Stage
2. The LLM receives only the selected method, security level, applicable
observations, selected execution-ready seeds, mutation constraints, expected
signals, and candidate budget.

The LLM candidate output is limited to:

```json
{
  "variants": [
    {
      "source_seed_id": "seed-id",
      "mutation_type": "case_variant",
      "payload_or_logic": "value"
    }
  ]
}
```

The builder deterministically enriches each accepted variant with:

```text
candidate_id
method
stage
payload_value or action_value
target_param
source
source_seed_id
mutation_type
expected_signal
provenance
```

`source` may be:

```text
static_seed
llm_mutated
llm_generated
```

For `static_only`, the builder bypasses LLM generation and preserves the
static-seed path. For generated modes, a variant linked to a probe seed is
discarded before it can become an execution candidate; if that leaves no
execution-ready variant, the deterministic static-seed fallback is recorded.

### 5.4 Payload Validator

The validator rejects candidates that:

* do not match the schema
* do not have required fields
* belong to the wrong method family
* target the wrong parameter
* are duplicates without justification
* are outside the DVWA scope
* use a forbidden mutation type
* do not have provenance
* refer to an unknown seed
* contain destructive actions

Rejected payloads are not executed by the method agent.

### 5.5 Static Method Agent

Each method agent follows this general pattern:

```text
load endpoint
run probe
check precondition
execute validated candidates
verify expected signal
record evidence
update score
update confirmed nodes
return partial state update
```

The method agent does not ask the LLM to create a new agent and does not modify the AKG.

### 5.6 Chaining Router

The chaining router determines the next step:

* return to orchestrator
* execute another method that is still viable
* continue to the next method through a chain edge
* stop and enter scorer

Chaining is only allowed if the initial outcome is proven through artifacts.

Conceptually valid chain example:

```text
sqli_confirmed -> credentials_extracted -> bf_dictionary or credential_validation
authenticated_session -> ac_idor or ac_force_browse
admin_session_obtained -> sqli_union
```

`credentials_extracted` does not automatically mean `brute_force_confirmed`. Brute Force still requires execution or login validation.

## 6. Experiment Design

### 6.1 Conditions

| Condition                           | AKG      | Payload source                                 | Function                       |
| ----------------------------------- | -------- | ---------------------------------------------- | ------------------------------ |
| Linear LLM plus hybrid payloads     | Not used | Static seeds plus LLM variants                 | Baseline without AKG structure |
| AKG-guided LLM plus hybrid payloads | Used     | Static seeds plus AKG-constrained LLM variants | Tests AKG contribution         |

Static-only mode may be retained as a debugging mode or internal ablation, but it is not the main condition in the current thesis draft.

### 6.2 Matrix

```text
Nrun = NLLM x Ncondition x Nlevel x Nmethod x Nrepetition
```

Minimum configuration:

```text
Nlevel = 3  # Low, Medium, High
Nrepetition = 3
Ncondition = 2
Nmethod = 9
NLLM >= 2
```

Surface is counted through method coverage because each method is already tied to a specific surface.

### 6.3 Repetition Rule

Each scenario is executed at least three times. Repetition is used to measure:

* stability of selected method
* stability of payload candidate
* stability of execution outcome
* variation in guardrail activation
* variation in token cost
* consistency score

### 6.4 Runtime Acceptance and Concurrency Feasibility

Runtime acceleration is applied identically to `linear_hybrid` and
`akg_guided_hybrid`: the condition, surface, level, payload mode, method
coverage, repeat count, validator, scoring, and containment rules do not
change. The authorized 18-coordinate re-run must retain exactly those
coordinates and report, per artifact, a peak LLM concurrency no greater than
2 and a peak DVWA-node concurrency of exactly 1. Acceptance also requires a
payload invalid-JSON rate at or below 5%, no containment failure or
cross-coordinate state leakage, no increase from the baseline guardrail count
of zero, at least a 30% reduction in total LLM wall time, and complete
role/cache/performance telemetry. If the payload invalid-JSON threshold is
exceeded, that generator role is rejected for the main experiment.

Full-coordinate concurrency is a separate feasibility study and is not
enabled for thesis evidence. First compare serial and two-worker execution
for non-timing methods on the existing DVWA instance. Test SQLi timing and
brute-force concurrency only on isolated DVWA replicas; simultaneous
timing-sensitive requests against one instance are never evidence. Enabling a
future `matrix_max_concurrency` option would require three-repeat results with
zero cookie/security-level leakage, unchanged confirmed findings and terminal
statuses, unchanged timing classifications, under 10% non-delay P95 latency
drift, and no new rate-limit or containment events. Until every gate passes,
HTTP serialization and replica-based scheduling remain the policy.

## 7. Evaluation Metrics

### 7.1 Composite Score

```text
Srun = 0.20 Smethod + 0.20 Spayload + 0.30 Sexploit + 0.10 Schain + 0.20 Soutput
```

| Component  | Weight | Content                                   |
| ---------- | -----: | ----------------------------------------- |
| `Smethod`  |   0.20 | Method selection quality                  |
| `Spayload` |   0.20 | Payload quality                           |
| `Sexploit` |   0.30 | Exploitation outcome                      |
| `Schain`   |   0.10 | Chain outcome                             |
| `Soutput`  |   0.20 | LLM output quality and guardrail handling |

New thesis launches use [scoring.v4](thesis_scoring.md), with an
experiment-wide `human|ai|both` selection. Both graders use one immutable
execution and the same signal/proof gate, producing separate receipts.
`Spayload_final` is the arithmetic mean over distinct executed validated
exploit/bypass candidates in the final selected/last executed method. Rejected,
probe and unexecuted candidates are excluded; empty denominators, missing proof
and incomplete reviews leave the thesis composite null. Full precision is kept
in the stored vector and final scores are rounded to four decimals.

Method selection uses a preregistered hash-pinned evaluator profile for the
last selection snapshot: 0 outside surface, 1 unproved prerequisites, 2 eligible
but lower-ranked, 3 tied top rank, 4 tied top rank with verified references and
plan. Fit level ranks before reference protocol request count; actual requests
never determine initial rank. Unknown predicates or absent profiles leave
eligible selection pending. This narrows the v3 meaning of grade 3; historical
v3 artifacts retain their own rules. Forced choices are recorded separately
from model selection. Profiles stay outside the selector's input.
The ranking reference combines prior research with independent DVWA controls
for the same vulnerability-confirmation goal and candidate budget. Additional
expert approval is optional. A method with only partial or unmatched proof
remains pending in the research profile; no ranking is inferred from the scored
main runs. The current calibrated proposal and remaining gaps are recorded in
the active ranking handoff.

Calibrated profile entries can carry `reference_status`, `reference_fit` and
`reference_reason`. Confirmed fit is an integer from 1 to 3, explained by the
frozen pilot protocol; pending fit is null. Matching predicates use that fit,
otherwise fit is 1. Legacy entries retain 2/1. An eligible pending competitor
leaves Smethod null (`ranking_reference_pending`); proved-ineligible competitors
can be excluded, while unknown observations still block assessment.

Candidate base proof reaches 0 absent, 1 weak, 2 partial or 3 independently
confirmed. Full Access Control and Brute Force require operator fixture oracles,
identity/object/session bindings, source hashes and independent controls;
visibility/login markers alone cap at 2. Candidate tier 4 needs independently
verified downstream use. Exploit 4 separately requires confirmed source-method
material and that same proved use, never the candidate ceiling alone. Passive
weak chain evidence earns 1 without opening routes; fully proved prerequisites
without destination confirmation earn 2; one verified dependency earns 3 and
two causally linked dependencies earn 4. Missing required logs stay pending.
Final-method denominators never import source-method candidates, and target
stops are preserved. Live full-credit reachability remains unverified.

Output is unusable 0, validated static fallback 1, repaired 2, clean valid 3 or
clean valid with verified decision/provenance references to call inputs 4.
All required experiment-model calls in the final method context and run-wide
scope events contribute; evaluator calls are excluded. Stability is separate:
modal Soutput frequency / assessable repeats, with final/pending/planned counts
and null for one repeat. It does not raise a run's score. Zero-call controls
have Soutput not_applicable and no thesis composite. The current frozen machine
profile covers nine scenarios with five fully ranked and ten pending competitor
entries across four scenarios. A live static Brute Force control has bound
fresh-session proof; Access Control permission and causal dependency proof
remain unavailable. The owner authorized provider egress to `tokenharbor.ai`
for `openai_compatible/deepseek-v4.1-flash`, and the frozen 108-coordinate
matrix completed with 49 success and 59 error artifacts. Review of all 108 saved
sources used 74 evaluator calls and accepted 65 AI decisions, producing 74 final
v4 receipts and 34 pending workflows. Immutable execution sources retain their
initial `pending_review` and historical provisional v2 composites; derived
receipts and tables carry the v4 results. Pending final scores remain null.
All source hashes and 234 checked historical receipt hashes were preserved.
All methods were forced, so `Smethod` measures reference fit. One repeat keeps
stability null. Synthetic controls establish only the offline contract.

Nine mutation-only saved-input replays stopped before HTTP because their saved
probe stages were missing. Nine matched hybrid controls made 104 actual DVWA
transactions with zero provider calls and no containment violations; five
confirmed fresh results. The 59 incomplete outcomes have evidence-based cause
categories, while the original `UNSPECIFIED` reasons and unresolved
model-versus-code attribution remain recorded. Independent wire audits cover
diagnostic controls; the matrix scope audit uses framework receipts. Permission
and causal proof, ten pending ranking comparisons, and complete mutation-only
replay inputs keep full live acceptance open. See the active handoff and its
[score table](../../results/validation/scoring-v4-live-acceptance-2026-10-10/score-table.csv).

Permission proof permits an existing low-privilege session; authentication proof
requires a fresh session. Synthetic dependency evidence requires an explicit
offline fixture label. Output fallback credit is limited to its role and visit.
Repeat grouping uses stable oracle protocol settings while retaining execution
attestations and control results in each receipt.

An operator protocol can explicitly enable `dvwa_candidate_session.v1` collection
before immutable export. The collector validates an executed candidate through a
new DVWA login, independent identity, rejected-credential, inherited-session and
different-identity controls. Agents retain the original session fingerprint;
sources retain safe fingerprints and request/response hashes, never raw passwords,
cookies or tokens. Missing or failed controls leave proof partial. Collection
does not alter graph verdicts, routing or chain credit, and saved-artifact review
does not repeat target requests. The current admin-session Access Control agents
cannot establish an unauthorized permission decision.

The evaluator is the configured `openai_compatible/deepseek-v4.1-flash` model in
a fresh, separate judging role, with two attempts, 1,024 output tokens and a
60-second timeout. This is not an independent-model comparison. Failed judge
responses stay pending; a human result cannot fill an AI receipt. Corrections
are append-only and receipts retain the source hash, candidate citations,
reviewer identity, versions, denominator, component vector and formula.
CLI and TUI use one validated source-local review ledger. Repeated evaluation
links predecessor decisions, and telemetry is saved per execution with archived
prior versions. Repeat comparisons separate reviewer identities and review
versions as well as the grading workflow and frozen configuration.
Opening an older receipt from Results can restore its source-validated history
without a ledger, including custom output directories; further derived writes
stay in that receipt's directory.

The automatic runtime scores below are **historical/provisional scoring.v2**;
they remain in execution artifacts and do not replace thesis `Srun_final`.
Rubric `scoring.v2` records each selection before execution with a visit ID.
`Smethod` is 3 for contemporaneous viability and 1 for an in-scope choice whose
prerequisites are not proved. Forced, model/orchestrator, deterministic fallback
and AKG route origins remain distinct. Routed selections use their destination
surface and frozen prerequisites. Later success never establishes selection
viability retrospectively.

`Spayload` comes from the candidate's own verifier evidence: 0 for no verified
signal, 1 for a proved probe precondition, 2 for partial extraction or visibility,
and 3 for verified exploitation. HTTP acceptance alone earns no exploit credit.
Boolean false needs complementary expression controls and repeatability.
Unexecuted candidates remain null. Candidate/exploitation maxima retain their
earning receipt, with later negative visits separate. Ordinary `Sexploit` is
capped at 3.

`Schain` is 4 only for a recorded route's destination visit with proved
prerequisites, actual source data/session consumption and its own downstream
confirmation. Ready, routed, failed, unverified and unrelated logins earn 0.
The post-method coordinator reads merged outcomes and records ready → routed →
executed → completed/failed/unverified, deduplicated by route ID. Surface aliases
come from the predefined method registry and serve only as prerequisites;
enabling outcomes never become vulnerability confirmations. Recovered plaintext
may bind an existing validated bounded dictionary pair. Extracted hashes are
not plaintext; no hash cracking or invented credentials are used. Other routes
lack session consumption or independent permission controls and retain zero.
Earlier completed chains remain visible when a later selected method earns 0.

`Soutput` is 4 for clean output, 3 for deterministic fallback (including provider
timeouts), 2 for returned invalid JSON/schema violations/native response-mode
mismatches/incomplete responses/guardrails, and 0 for actual payload, request or
redirect scope violations. These event categories remain distinct. Discarded
recon navigation and page references remain observable without an output penalty. Unknown legacy
containment remains penalized. Orchestrator failures attach to the selected
fallback visit, or the last executed visit for terminal stops; generator and
validator failures attach to their selected visit. Unknown scope and actual HTTP
violations apply run-wide. Per-visit output is aggregated by minimum within each
method, including run-wide penalties. Composite entries are replaced with the
weighted stored vector, so earlier clean output cannot erase a later penalty.
Selection, candidate and exploitation maxima retain the evidence that earned them.

The primary composite describes the final selected/last executed method, while
earlier confirmation may make the surface/run successful. Both contexts remain
visible; scoring does not substitute a better earlier method. A clean ordinary
`(3,3,3,0,4)` vector yields 2.9. Forced-target stops and linear runs intentionally
have chain 0. A nominal 0–4 rubric does not guarantee every coordinate can earn
4 in every component.

If an automatic orchestrator stop clears the active selection after execution,
the scorer uses the last method's verifier decision to retain that method's
identity and score dimensions. It does not execute another method or change
the recorded routing/stop decision. A stop before any execution has no selected
method to score.

### 7.2 Metric List

For `scoring.v3`, payload execution success uses valid exploit/bypass candidates
as denominator; missing executed evidence leaves the rate unavailable.
Optimal first-choice accuracy, separate method alignment, edge-by-edge AKG path
validity and token cost remain null with explicit reasons when their required
ranking/verdict/trace/price schedule is absent. Do not equate optimal selection
with eventual first-method success. Compare completed receipts within the same
rubric and grading workflow; retain all pending/unassessable counts and separate
environment, model, evidence and provider integration inconsistency. The
historical one-model matrix does not satisfy the commercial-plus-open model
comparison requirement.

| Metric                           | Function                                                 |
| -------------------------------- | -------------------------------------------------------- |
| `method_selection_score`         | 0 to 4 score for method selection                        |
| `first_choice_accuracy`          | Whether the first choice matches the best viable method  |
| `adaptation_rate`                | Ability to switch methods after failure                  |
| `payload_quality_score`          | 0 to 4 score for payload                                 |
| `payload_validity_rate`          | Ratio of payloads that pass the validator                |
| `method_alignment_rate`          | Ratio of payloads aligned with the method family         |
| `payload_execution_success_rate` | Ratio of valid payloads that produce the expected signal |
| `exploitation_score`             | Exploitation score per surface                           |
| `full_exploit_rate`              | Ratio of runs with full exploit                          |
| `chain_score`                    | Chain outcome score                                      |
| `chain_enabled_count`            | Number of exploits that open a chain                     |
| `output_validity_score`          | LLM output and guardrail handling score                  |
| `guardrail_activation_rate`      | Ratio of refusal or block                                |
| `invalid_json_rate`              | Ratio of outputs that fail parsing                       |
| `fallback_rate`                  | Ratio of fallback usage                                  |
| `consistency_score`              | Result stability across repetitions                      |
| `attempts_to_success`            | Number of attempts until success                         |
| `token_cost_per_success`         | Estimated token cost per successful exploit              |
| `llm_role_time`                  | Total LLM wall time grouped by role                     |
| `llm_cache_hit_rate`             | Ratio of coordinate-local cache hits                    |
| `llm_invalid_output_rate`        | Ratio of invalid or incomplete structured responses     |
| `peak_llm_concurrency`           | Maximum overlapping LLM operations                      |
| `peak_dvwa_node_concurrency`     | Maximum overlapping recon/method HTTP nodes             |

## 8. Validation Protocol

Validation is performed in five stages:

| Stage                  | Validation                                                                                           |
| ---------------------- | ---------------------------------------------------------------------------------------------------- |
| Environment validation | DVWA is active, login succeeds, security level is correct, endpoint is available, token is available |
| AKG validation         | Method is only available if its precondition is satisfied                                            |
| Payload validation     | Payload matches schema, method family, parameter, scope, and provenance                              |
| Execution validation   | Success signal must be supported by response evidence, timing evidence, or session evidence          |
| Scoring validation     | Score must refer to artifact, not LLM claim                                                          |

Preliminary validation before the main experiment:

* unit test for AKG nodes and edges
* unit test for precondition
* unit test for payload profile completeness
* unit test for prompt schema and JSON parser
* unit test for payload validator
* unit test for fallback path
* dry run of at least one scenario for each surface

## 9. Guardrail Handling

The framework uses validation gates to handle structured output or refusal.
The framework does not use jailbreak, roleplay deception, or adversarial
prompt injection. Native structured output is chosen after a request-free local
client capability check; otherwise the compact JSON prompt is used.

Flow:

```text
LLM call
  -> guardrail check
  -> JSON/schema validation
      -> valid: continue
      -> invalid/incomplete: log invalid output and use static seeds
      -> refusal: log guardrail activation and use deterministic fallback
```

Allowed fallback:

* fallback to AKG heuristic
* fallback to static seed path
* fallback to another method that still satisfies preconditions
* controlled stop to scorer if there is no valid path

## 10. Error Handling

| Layer      | Error                                                          | Handling                                                          |
| ---------- | -------------------------------------------------------------- | ----------------------------------------------------------------- |
| DVWA       | Target unreachable, session expired, login fail, token missing | Reconnect, relogin, refresh token, or stop as environment failure |
| Foundation | Timeout, empty response, HTML structure change, missing param  | Limited retry, parsing fallback, record failure                   |
| Payload    | Invalid schema, duplicate, wrong method, out of scope          | Reject before execution                                           |
| AKG        | No viable method, incomplete payload profile                   | Controlled stop or valid fallback                                 |
| LangGraph  | Node failure, invalid route, iteration limit                   | State remains stored, route to chaining router or scorer          |
| LLM        | Refusal, invalid JSON, API timeout, empty output               | Log the event, use static/AKG fallback, and avoid unbounded repair  |
| Execution  | No success signal, unstable evidence                           | Record partial or failure based on verifier                       |

## 11. Artifact Schema

A matrix also writes a parent `<execution_id>.matrix.json` artifact. Its
`status`, `totals`, and `cancellation` fields are authoritative for the matrix
outcome and completed/not-started counts. The `runs` array embeds the child
artifacts. Each child's `execution_id` joins it to the standalone coordinate
JSON; reconciliation preserves its `status`, experiment `config`, selected
method, `final_state`, and fallback events. Parent and child execution IDs stay
separate in the runtime descriptor and event journal. Runtime completion does
not imply final scoring acceptance.

Each run produces a JSON artifact with at least the following fields:

```text
schema_version
execution_id
run_id
status
experiment_condition
target_method
provider
model
model_profile
surface
security_level
payload_mode
repeat_index
selected_method
viable_methods
akg_path
payload_candidates
payload_validation_results
payload_provenance
execution_log
response_evidence
timing_evidence
verifier_decision
method_execution_inputs
confirmed_vulns
achieved_outcomes
guardrail_activations
payload_guardrail_activations
invalid_json_events
fallback_events
containment_events
method_score
payload_scores
exploitation_score
chain_score
output_score
composite_score
attempts_to_success
token_cost
llm_activity
llm_performance
llm_performance_summary
llm_runtime_config
config
final_state
failure
error
manual_scoring_evidence
```

The complete per-method score maps and generated-payload map are retained in
`final_state`; the top-level singular score fields identify the selected
method's values. `failure` is null for runs without a provider failure and is
otherwise the same canonical redacted failure object emitted in `run.failed`
and the failure sidecar.

`manual_scoring_evidence` must link:

```text
candidate_id
payload_source
source_seed_id
mutation_type
target_param
expected_signal
validator_result
execution_log_ref
response_evidence_ref
timing_evidence_ref
verifier_decision
score_0_4
scoring_reason
```

The three evidence-reference fields contain JSON Pointer lists into the same
artifact. New request telemetry and response/timing evidence retain the
attempted `candidate_id`; links require that identity, method, and stage to
match a validated candidate. Legacy records without IDs match method-specific
payload representations: only IDOR/vertical access control accepts `userId=`
prefixes (including stripped IDs), force-browse accepts normalized paths, and
SQL/brute-force stays literal. Normalized aliases require a unique
recorded candidate score to disambiguate; unresolved matches remain unlinked.
Rejected duplicates receive no execution links. Unexecuted candidates
retain null scores and verifier decisions. New rows link `scoring_decision` and
`scoring_decision_ref` to the candidate's earning verifier; later negative
decisions remain in `later_verifier_decisions`. `score_evidence_status` separates
linked decisions, unresolved legacy grades and unscored candidates.
`scoring_reason` records the rubric reason. Legacy rows without receipts may
use method-specific history, without claiming a reconstructed winning decision.

The terminal projection retains `selected_visit_id`, `scoring_decisions`,
`verifier_history`, `verifier_decision`, `chain_history`, `current_chain`,
`active_chain_route`, `chain_consumption`, sanitized `found_credentials`,
`attempted_agents`, `tried_payloads`, response/timing evidence, `output_failure_events`
and experiment identity. Each decision identifies dimension, method/visit,
candidate or route, rubric version, reason, evidence references, verifier link
and aggregation. Composite receipts include the stored vector and earning
decision IDs. Route telemetry uses `payload` and preserves source/target,
prerequisites, status and stop reason. `state.v2` rejects older checkpoint
contracts using output/composite maxima.

Pure rescoring uses `evaluation.scoring_repair` and immutable source hashes.
Omitted terminal inputs are unresolved, never inferred from earlier snapshots.
Unsupported candidate detail retains an explicitly unresolved legacy grade;
derived vectors are not complete retrospective acceptance. Historical chain
zeros remain until source consumption and downstream verification are proved.

### Method verification and diagnostic replay

Every method invocation records its decision, including failures and negatives;
prior confirmations remain in graph-state history and confirmed-node reducers.
Force-browse evidence uses the actual requested path. Brute-force confirmation
and telemetry share the same status/token/content predicate; unavailable probes
cannot establish `no_rate_limit`. Recon establishes that observation with bounded
benign credential probes rather than endpoint discovery, and an admin session
is not a low-privilege session.

Error SQLi requires a database/XPath extraction envelope (including the truncated
`~admin` case), the complete DVWA `<pre>` duplicate-entry envelope carrying
`dvwa0` or `dvwa1` for `group_key`, or structured credential extraction. A generic
duplicate value, different key, quoted prose, or failed HTTP response does not
establish that duplicate-entry extraction. UNION requires account/hash
result columns. Boolean probes require successful matched true/false evidence,
not unrelated page-length changes. Time confirmation requires successful
baselines/responses and two bounded delayed transactions of the same candidate
with fresh harmless controls. Boolean extraction accepts either recognized
branch when the repeated request returns that same branch; low/high require
two distinct repeatable extraction predicates and medium requires one. A correct
false predicate also requires a complementary true response proving the same
expression evaluated: DVWA can suppress SQL exceptions into its missing-ID body.
Unrecognized syntax or failed complementary controls receive no extraction
credit. Timing verification uses the validator's bounded numeric `SLEEP` parser,
including exponent, signed, decimal, and normalized-comment forms. Comments
retain token separation: `AND/**/SLEEP(3)` uses the bounded delay, while an
oversized argument with the same spelling is rejected before transport. These
finite controls do not establish a universal zero false-positive rate.

Validation also retains a `candidate_budget_exceeded` receipt for otherwise
valid candidates excluded by profile ranking. They remain unexecuted with null
manual scores; budget exclusion does not establish poor generated-input quality.

The current access-control agents authenticate as admin and supply no independent
permission control. Their content-only results are capped at score 2 and recorded
as `unverified` with `missing_independent_authorization_control`; no confirmed
node or enabling outcome is emitted from that evidence. Positive unauthorized
access remains infeasible/unverified until a contained principal/permission
fixture is independently established.

`method_execution_inputs` retains the validated executable queue and sanitized
pre-execution state after every validator completion receipt, including revisits. `evaluation.payload_replay.replay_method_inputs` revalidates
that exact queue, optionally selects only saved IDs (with saved probe/exploit
stages), preserves candidate IDs and saved execution order, and stops on rejected
or changed membership/values/provenance or budget loss. Fresh ranking alone does
not invalidate a frozen queue. Replay applies the same state reducers as the
graph, retaining monotonic observations, earlier attempts, score maxima, and
accumulated evidence. Checkpoint resume ignores historical validation receipts
when capturing new inputs. Replay
opens fresh sessions, and forbids new provider calls. Diagnostic outputs include
the source SHA-256, executing code hashes, request/verifier/score evidence, and
manual-scoring rows. They are separate from primary model-performance datasets.
Replay declares `manual_scoring_scope: fresh_replay_execution`; its manual rows
include only candidates linked to fresh response evidence. Historical scores
and evidence remain in `final_state` and the linked source artifact. A replay
that stops before execution has an empty manual sheet.
Older artifacts without frozen inputs cannot be replayed by inventing a state.

New visits save detection seeds that were previously loaded implicitly in
`probe_controls[method]`: the visit ID, ordered canonical probe candidates, their
SHA-256 and validation receipts. Candidate records retain seed provenance.
These controls persist in checkpoints, appear in each pre-execution snapshot,
and give probe responses their candidate IDs. They remain outside the scored
exploit queue and its budget. Replay retains these saved controls even when
selecting generated exploit IDs, revalidates their hash, canonical contents,
order and visit, and stops before HTTP on disagreement. Historical snapshots
without a saved probe stage remain incomplete.

Permission attestations require allowed and denied controls for the same
object/action as the assessed request. Control identities must match their
independently expected principals. Controls may use different principals with
known permission decisions on that resource. Unrelated objects, actions or
unproved control identities do not establish full
permission proof.

### Execution status and security outcome

Terminal artifacts use two canonical fields, classified independently:

| `execution_status` | Definition | Example |
| --- | --- | --- |
| `completed` | The planned coordinate reached a normal terminal point. | The method exhausted its budget with an unconfirmed signal. |
| `failed` | A runtime, provider, target request, resume, or primary artifact error prevented normal completion. | A required provider call failed or the target request raised a transport error. |
| `interrupted` | Explicit cancellation stopped execution before normal completion. | The operator cancelled and the latest safe state was retained. |

| `security_outcome` | Required evidence | Example |
| --- | --- | --- |
| `confirmed` | Method evidence meets the existing proof ceiling and applicable independent controls. | Candidate-linked extraction is confirmed by the method verifier. |
| `no_finding` | Linked, usable response evidence and affirmative negative verifier evidence establish absence of the assessed signal. | An assessed candidate has a verified negative signal; the affected dimension may score 0. |
| `unconfirmed` | Evidence is missing, partial, or ambiguous. | Missing candidate links or an unverified decision cannot establish a negative. |
| `fixture_limited` | A required independent principal, permission, session, or fixture control cannot establish the conclusion. | Access Control visibility lacks an independent permission oracle. |

`execution_reason` and `security_outcome_reason` are separate objects with
`code`, `detail`, and `evidence_refs`; the former is null for a completed execution,
and the latter is null for a confirmed outcome. Reasons include
`NO_CANDIDATE_CONFIRMATION`, `PARTIAL_SIGNAL`, `PERMISSION_ORACLE_UNAVAILABLE`,
`SESSION_ORACLE_UNAVAILABLE`, and `VERIFIED_NEGATIVE`. Failures retain distinct
codes such as `LLM_RUNTIME_FAILURE`, `TARGET_TRANSPORT_FAILURE`,
`TARGET_REQUEST_FAILURE`, `SESSION_LOGIN_FAILED`, `METHOD_EXECUTION_FAILURE`,
`RUNNER_EXCEPTION`, `RESUME_REFUSED`, or `ARTIFACT_WRITE_FAILURE`; interruption
retains `CANCELLED`. Method setup exceptions retain an explicit execution reason
even when no request evidence was produced. A `failure_agents` marker alone
cannot distinguish a caught exception from a controlled stop.

The shared reader/classifier is `core/run_status.py`. It uses the existing
scoring.v4 candidate proof gates. Candidate-linked complementary controls are
joined through `source_candidate_id` as well as direct `candidate_id` evidence.
An executed candidate recorded in `tried_payloads` without a response remains
unassessed and prevents `no_finding`; unexecuted candidates do not enter that
assessment. Cancellation events carry the terminal outcome and reason into the
TUI evidence region, while child events do not terminalize the matrix parent.
The present permission/session oracle protocol
attests confirmation; an absent attestation cannot establish a controlled
negative for these methods. Candidate disposition rows retain their narrower
`execution_status=executed|not_executed` meaning; the run lifecycle above belongs
to the run envelope and final state.

For compatibility, new artifacts retain `status=success|error|cancelled` as
lifecycle aliases for `completed|failed|interrupted`. `task_result` and
`incomplete_reason` retain their legacy terminal labels for older consumers;
they are not execution failure indicators. Canonical fields are also saved in
reports, failure sidecars, manifests, matrix child events, journals, runtime
descriptors, and thesis review outputs. Readers do not rewrite historical files.
A legacy `INCOMPLETE` error is mapped to completed only with a normal terminal
trace, complete required provider activity, and no failed request evidence.
When lifecycle attribution is unavailable, readers retain null/unknown and
report an unknown count separately. A skipped, unstarted coordinate has null
execution status and is excluded from executed coverage and outcome counts.

Coverage counts all completed outcomes. Matrix `execution_status_counts` and
`security_outcome_counts` are independent; `successful_runs` is a temporary
alias for `completed_runs`, not an exploit count. `confirmed_runs` is reported
separately. A matrix may have a confirmed child finding and still fail or be
interrupted. TUI lifecycle indicators follow execution; outcome and reason appear
separately in result rows and details.

The scoring.v4 rubric and formula remain
`Srun = 0.20*Smethod + 0.20*Spayload + 0.30*Sexploit + 0.10*Schain + 0.20*Soutput`.
Verified negative evidence may earn 0 on its affected dimension. Missing proof
remains null/pending; independently supported components retain their grades.
A zero component does not zero the weighted sum. `Srun_final` requires every
component, an eligible denominator, and the selected review workflow to be
complete. Execution completion alone does not finalize a thesis score.

## 12. Consistency Handling

Inconsistencies across runs are not selected selectively. All runs remain recorded.

Inconsistency categories:

| Category                           | Example                                                   |
| ---------------------------------- | --------------------------------------------------------- |
| Environment inconsistency          | DVWA state changes, session changes, endpoint is unstable |
| Model inconsistency                | Selected method or payload differs for the same input     |
| Evidence inconsistency             | Timing signal or response difference is unstable          |
| Provider integration inconsistency | API timeout, empty response, service error                |

Results are reported with aggregation:

* mean score
* median score
* score distribution from 0 to 4
* success ratio
* consistency score
* failure category count

## 13. Analysis Plan

Main analysis:

| Analysis           | Output                                                             |
| ------------------ | ------------------------------------------------------------------ |
| Descriptive        | Score distribution, valid payloads, guardrail count, failure count |
| Comparative        | Comparison of Linear LLM vs AKG-guided LLM                         |
| Per model          | Comparison of score, consistency, token cost, guardrail rate       |
| Per surface        | SQLi vs Access Control vs Brute Force                              |
| Per security level | Low vs Medium vs High                                              |
| Per method         | Performance of each method node                                    |

Mann-Whitney U test may be used to compare two result groups if the data size is sufficient and normal distribution is not assumed.

## 14. Codebase Structure Target

```text
dvwa-llm-pentest/
├── config.yaml
├── tesis/
│   ├── __main__.py
│   ├── cli.py
│   ├── config_loader.py
│   └── report_formatters.py
├── core/
│   ├── state.py
│   ├── graph_builder.py
│   ├── knowledge_graph.py
│   ├── chaining_coordinator.py
│   └── scorer.py
├── foundation/
│   ├── session_manager.py
│   ├── recon.py
│   ├── http_client.py
│   ├── payload_library.py
│   ├── payload_generator.py
│   ├── payload_validator.py
│   ├── payload_ranker.py
│   └── verifier.py
├── agents/
│   ├── orchestrator.py
│   ├── sqli/
│   ├── access_control/
│   └── brute_force/
├── llm/
│   ├── provider.py
│   ├── prompts/
│   └── guardrail_monitor.py
├── evaluation/
│   ├── runner.py
│   ├── multi_llm_runner.py
│   ├── metrics.py
│   ├── manual_scoring_sheet.py
│   └── reporter.py
├── tests/
└── results/
    ├── runs/
    ├── payloads/
    └── reports/
```

## 15. Current Implementation Notes

| Area                   | Expected status                                                          |
| ---------------------- | ------------------------------------------------------------------------ |
| AKG filtering          | Method must be selected from viable methods                              |
| Payload validator      | Must reject invalid payloads before agent execution                      |
| Guardrail logging      | Refusals and invalid outputs must be recorded                            |
| Method scoring         | 0 to 4 rubric must be applied consistently                               |
| Payload scoring        | Manual scoring may be used, but must be artifact-based                   |
| Chain history          | Must be stored as a main artifact                                        |
| Deterministic fallback | Must ensure fallback does not violate preconditions                      |
| Artifact schema        | Must be stable before the main experiment                                |
| Static-only path       | Used as debugging or internal ablation, not as the main thesis condition |

## 16. Non-Negotiable Constraints

1. External targets must not be used.
2. The LLM must not create a new graph at runtime.
3. The LLM must not create a new agent at runtime.
4. Payloads must pass through the validator before execution.
5. Success claims from the LLM are not sufficient for scoring.
6. Full exploit must be proven through execution artifacts.
7. A chain is only valid if the previous outcome is proven.
8. Experiment repetitions must be stored completely.
9. Models must be compared under the same configuration.
10. AKG changes before the main experiment must be revalidated.

### Offline observer artifact export

The additive [`observer-projection.v1` contract](observer_projection.md) exposes source-bound metadata for current and historical artifacts. An operator invokes `python -m tesis export-observer` with explicit source roots, review roots in declared epoch order, and a new output under `results/`. The exporter reuses the canonical Python status classifier and availability-aware metric readers. It does not execute experiments, invoke an evaluator, rewrite sources, or change proof thresholds.

New `thesis_review_status` files include execution/run identity, source path/hash, selection and UTC generation time. Human and AI workflows retain independent components, numerator/denominator, pending reasons and nullable finals. Final receipts require verified original source bytes, identity, method/config/rubric/selection, candidate evidence and arithmetic. A newer pending or invalid review cannot replace an eligible final. Legacy pending status joins require a unique verified source hash and a validated contained ledger in the declared review epoch. Stored rule hashes identify the review code epoch independently of the export code epoch.

Manifests retain v1 and add model/profile, repeat, parent identity, stored timing and relative detail references. Manifest indexes remain one-based; projection/event coordinate indexes are zero-based. A source root can be a flat directory or one exact source file. Embedded children retain their own identity/evidence; duplicate copies and missing primary/detail files are diagnosed. Primary/manifest/matrix/review JSON is published by atomic replacement of a unique same-directory temporary file. Journals retain their existing append behavior.

Projection coverage separates planned, represented, completed, failed, interrupted, unknown, skipped/unstarted and confirmed counts. Historical legacy totals and hash-bound analysis labels remain separate from canonical outcomes. Runtime scores retain their provisional origin; absent dimensions stay null. Final payload scores retain the distinct eligible-candidate mean and fractional components. Metrics require finite values with explicit availability; legacy numeric placeholders remain unavailable. Web API/UI integration has separate acceptance requirements.
