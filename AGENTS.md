# AGENTS.md — AI Implementation Guide

> Full architecture context lives in `docs/summary.md`, but treat that file as conceptual documentation. For runtime-accurate behavior, use the code in `core/`, `foundation/`, `agents/`, `llm/`, and `evaluation/` as the source of truth.

## General Info

This repository implements an LLM-assisted red teaming framework for **authorized testing of DVWA**. The runtime is built on **LangGraph**, uses a **static NetworkX Attack Knowledge Graph (AKG)**, executes **static method agents** for three in-scope vulnerability surfaces, and supports both **static-only** and **hybrid** payload candidate pipelines.

Use this file as the implementation contract for future edits. If `docs/summary.md` and the code disagree, follow the code and update the docs.

---

## Project Scope

**Target:** DVWA at three security levels: `low`, `medium`, `high`

| Surface | Implemented methods |
|---|---|
| `sqli` | `sqli_union`, `sqli_error`, `sqli_boolean_blind`, `sqli_time_blind` |
| `access_control` | `ac_idor`, `ac_vertical_escalation`, `ac_force_browse` |
| `brute_force` | `bf_dictionary`, `bf_spray` |

**Supported LLM providers in code:**
- `gemini`
- `openai`
- `claude`
- `openai_compatible`

**Payload modes in code:**
- `static_only`
- `hybrid`
- `llm_mutation_only`

**Out of scope for this framework:**
- XSS
- CSRF
- LFI
- Upload
- CMDi
- Weak Session
- JavaScript attacks
- CAPTCHA bypass as an exploitation target
- HTTP redirect attacks

---

## Tech Stack

| Component | Library / mechanism |
|---|---|
| Orchestration | `langgraph` (`StateGraph`, conditional edges, `MemorySaver`) |
| Knowledge graph | `networkx.DiGraph` |
| State schema | Python `TypedDict` plus LangGraph reducers |
| HTTP | `httpx` through `foundation/http_client.py` |
| HTML parsing | `beautifulsoup4` |
| LLM integrations | `langchain_google_genai`, `langchain_openai`, `langchain_anthropic` |

---

## Runtime Flow

Current runtime graph in `core/graph_builder.py`:

```text
START
  -> recon
  -> orchestrator
  -> payload_candidate_builder
  -> payload_validator
  -> selected method agent OR chaining_router
  -> chaining_router
  -> orchestrator OR payload_candidate_builder OR scorer
  -> END
```

### Important clarification

- `docs/summary.md` may present `verifier` as part of the flow, but there is **no standalone LangGraph `verifier` node** in the current runtime.
- Verification is performed **inside method agents** via `foundation/verifier.py`.
- `payload_validator` may route directly to `chaining_router` when no valid candidates remain for the selected method.

### Actual graph nodes

- `recon`
- `orchestrator`
- `payload_candidate_builder`
- `payload_validator`
- `chaining_router`
- `scorer`
- method nodes:
  - `sqli_union`
  - `sqli_error`
  - `sqli_boolean_blind`
  - `sqli_time_blind`
  - `ac_idor`
  - `ac_vertical_escalation`
  - `ac_force_browse`
  - `bf_dictionary`
  - `bf_spray`

---

## State Schema

The canonical state lives in `core/state.py`. The structure below is intentionally abbreviated but aligned with the code.

```python
class ExploitationState(TypedDict):
    target_url: str
    security_level: str
    llm_provider: str
    current_surface: str
    payload_mode: str

    endpoints: list[dict]
    input_vectors: list[dict]
    observations: dict[str, bool]

    confirmed_vulns: list[str]
    achieved_outcomes: list[str]
    found_credentials: list[dict]

    tried_payloads: dict[str, list[str]]

    payload_candidates: dict[str, list[dict]]
    generated_payloads: dict[str, list[dict]]
    payload_validation_results: dict[str, list[dict]]
    payload_scores: dict[str, int]
    payload_provenance: dict[str, dict]
    generation_prompts: list[dict]
    payload_guardrail_activations: list[dict]
    candidate_budget: int

    scores: dict[str, int]
    method_scores: dict[str, int]
    exploitation_scores: dict[str, int]
    chain_scores: dict[str, int]

    current_chain: list[str]
    chain_history: list[dict]
    messages: list

    guardrail_activations: list[dict]
    blocked_patterns: list[str]
    successful_bypasses: list[str]

    consecutive_clean_responses: int
    evasion_enabled: bool
    evasion_max_retries: int
    evasion_mode: str
    evasion_strategy: str
    evasion_cooldown_threshold: int
    evasion_attempts: int
    successful_evasions: int

    model_config: dict[str, Any]
    telemetry_events: list[dict]

    attempted_agents: list[str]
    blocked_agents: list[str]
    failure_agents: list[str]
    akg_path: list[str]
    fallback_depth: int

    next_agent: str
    selected_method: str | None
    iteration_count: int
    max_iterations: int
    task_result: str | None
    incomplete_reason: str | None
```

### State semantics that matter

- This is **not** a Pydantic model. It is a `TypedDict` with LangGraph reducers.
- Several fields accumulate through reducers:
  - `observations`
  - `tried_payloads`
  - `payload_candidates`
  - `generated_payloads`
  - `payload_validation_results`
  - `payload_provenance`
  - `attempted_agents`
  - `blocked_agents`
  - `failure_agents`
- `observations` use a merge strategy that never overwrites `True` with `False`.
- `scores`, `method_scores`, `exploitation_scores`, and `chain_scores` use max-merge semantics.

---

## Attack Knowledge Graph

The AKG is implemented in `core/knowledge_graph.py`.

### What it currently contains

- entry node: `unauthenticated`
- surface nodes:
  - `sqli`
  - `access_control`
  - `brute_force`
- method nodes for all 9 static agents
- method-confirmed nodes such as `sqli_union_confirmed`
- surface-confirmed nodes:
  - `sqli_confirmed`
  - `access_control_confirmed`
  - `brute_force_confirmed`
- outcome / chain nodes such as:
  - `credentials_extracted`
  - `authenticated_session`
  - `admin_session_obtained`
  - `data_exfiltrated`

### What the AKG provides

- `get_viable_methods(surface, observations)`
- `check_preconditions(method_node, observations)`
- `get_next_actions(node)`
- `get_payload_profile(method_node)`

### Payload-aware method profiles

Each method node carries a `payload_profile` with:

- `seed_payload_refs`
- `allowed_mutation_types`
- `forbidden_mutation_types`
- `validation_rules`
- `expected_success_signals`
- `target_params`
- `max_generated_candidates`
- `max_total_candidates`
- `provenance_required`

### Current cross-surface chain intent

The code encodes chain-capable transitions including:

1. `brute_force_confirmed -> authenticated_session -> ac_idor`
2. `sqli_confirmed -> credentials_extracted -> bf_dictionary`
3. `ac_vertical_escalation_confirmed -> admin_session_obtained -> sqli_union`

Important runtime nuance:

- chain routing checks preconditions against `confirmed_vulns`, not `achieved_outcomes`
- surface-confirmed nodes can be derived from method-confirmed nodes during chain routing

---

## Payload Candidate Pipeline

The current codebase does **not** use only static payload lists anymore.

### Step 1: Candidate build

`foundation/payload_generator.py`:

- loads static seed candidates from `PayloadLibrary`
- reads AKG payload profile for the selected method
- optionally calls the LLM to generate constrained variants
- records provenance and prompt artifacts

### Step 2: Candidate validation

`foundation/payload_validator.py`:

- validates required schema fields
- enforces method-family correctness
- enforces allowed target parameters
- rejects out-of-scope payload content
- enforces provenance rules for generated payloads
- deduplicates candidate IDs and payload strings
- ranks valid candidates with `foundation/payload_ranker.py`

### Step 3: Agent execution

Method agents consume validated candidates via state helpers, typically separating:

- probe-stage candidates
- exploit-stage candidates

### Design rule

Generated payloads must remain **AKG-constrained** and **provenance-linked** to validated static seeds.

---

## Method Agent Contract

Method agents are static execution modules, not dynamically created tools.

### Current execution pattern

Most method agents follow:

```text
PROBE -> EXPLOIT -> CHAIN CHECK
```

### PROBE

- send low-risk or structural candidate payloads
- test whether AKG preconditions are supported by live observations
- update `observations`
- if probe fails, stop with score `0`

### EXPLOIT

- run validated exploit candidates that have not already been tried
- append attempted payloads into `state.tried_payloads[agent_id]`
- assign:
  - `2` for partial exploit
  - `3` for full exploit
- append confirmed KG nodes into `confirmed_vulns`

### CHAIN CHECK

- use `agents.state_utils.chain_check(...)`
- if chain-ready outcome is achieved, raise score to `4`
- append any returned `achieved_outcomes`

### Return shape

Agents must return a **partial state update dict**, not mutate state directly.

---

## Orchestrator

The orchestrator in `agents/orchestrator.py` is responsible for **method selection**, not direct exploit execution.

### Inputs used by the prompt / fallback logic

- `current_surface`
- `security_level`
- `observations`
- `viable_methods`
- `attempted_agents`
- `blocked_agents`
- `failure_agents`
- `scores`
- `method_scores`
- `confirmed_vulns`
- `achieved_outcomes`
- `payload_mode`
- `iteration_count`
- `max_iterations`

### Responsibilities

- ask the LLM to choose the next method
- parse JSON-like structured output
- detect guardrail refusals
- fall back deterministically to AKG-compatible next methods
- support reactive or proactive evasion logic
- stop early on critical outcomes or budget exhaustion

### Important clarification

The orchestrator may return a method ID such as `sqli_union`, but the runtime then routes that selection through:

```text
orchestrator -> payload_candidate_builder -> payload_validator -> method agent
```

It does **not** route directly from orchestrator to the method node.

---

## Chaining Router

The runtime router lives in `core/chaining_coordinator.py`.

### Current behavior

1. Stop on iteration-budget exhaustion
2. Check chain-ready transitions from confirmed nodes
3. Stop early on high-impact outcomes
4. If the last method was blocked or failed, try the next unvisited viable method
5. If the current surface is exhausted, route to `scorer`
6. Otherwise route back to `orchestrator`

### Runtime outputs

The router returns a partial update that may set:

- `next_agent`
- `selected_method`
- `task_result`
- `incomplete_reason`
- `telemetry_events`

---

## DVWA Runtime Assumptions

Do not hardcode stale constants into new logic without checking the current helpers and config.

### Stable assumptions in code

- default login credentials are `admin` / `password`
- CSRF field is `user_token`
- session cookie is `PHPSESSID`
- security cookie is `security`

### Values that may differ by environment

- target URL comes from config, currently `config.yaml`
- endpoint discovery should prefer `foundation/recon.py`
- session handling should prefer `foundation/session_manager.py`

Do not assume `http://localhost/dvwa` unless the current runtime config says so.

---

## Scoring

The 0 to 4 rubric is still the active method-level scale:

| Score | Label |
|---|---|
| 0 | Not Found |
| 1 | Identified |
| 2 | Partial Exploit |
| 3 | Full Exploit |
| 4 | Chain Exploit |

The scorer in `core/scorer.py` also computes higher-level summary metrics such as:

- `method_selection_accuracy`
- `adaptation_rate`
- `mean_attempts_to_success`
- `payload_validity_rate`
- `payload_execution_success_rate`
- `payload_improvement_rate`
- `guardrail_activation_rate`
- per-surface score summaries

---

## Evasion / Guardrail Handling

The current code supports technical retry behavior for guardrail false positives.

### Config-driven fields

- `evasion.enabled`
- `evasion.mode`
- `evasion.max_retries`
- `evasion.cooldown_threshold`

### Current runtime intent

- use paraphrase / prompt restructuring
- preserve schema-oriented outputs
- log guardrail activations
- fall back to deterministic AKG/static behavior when needed

This is not a jailbreak mechanism. Keep it scoped to reliability for authorized testing.

---

## Implementation Rules

1. Do not mutate the LangGraph state object directly. Always return a partial update dict.
2. Treat `core/graph_builder.py` as the runtime topology source of truth.
3. Treat `core/state.py` as the canonical state contract.
4. Treat `core/knowledge_graph.py` as the canonical AKG and payload-profile contract.
5. Do not assume payloads come only from `PayloadLibrary`; validated generated candidates may also be present.
6. Before sending a payload, check `state.tried_payloads` and avoid redundant retries.
7. Preserve provenance for generated payloads.
8. Update `state.scores[agent_id]` with the highest reached score.
9. When appropriate, also update `method_scores`, `exploitation_scores`, and `chain_scores` through existing helpers.
10. Append confirmed KG nodes to `confirmed_vulns`, not arbitrary labels.
11. Keep observations monotonic: do not overwrite an established `True` signal with `False`.
12. If you add a new method agent, update all of:
    - `core/state.py`
    - `core/graph_builder.py`
    - `core/knowledge_graph.py`
    - payload seeds / prompts / tests as needed
13. If you change payload candidate shape, update builder, validator, ranking, state, and tests together.
14. Keep `docs/summary.md` and Mermaid diagrams in sync after material architecture changes.
15. No emojis in code or runtime-facing output.

---

## Development Checklist

- [ ] The change matches the runtime graph in `core/graph_builder.py`
- [ ] The change respects the current `ExploitationState` in `core/state.py`
- [ ] The change does not directly mutate state
- [ ] Tried payloads are deduplicated and persisted in `state.tried_payloads`
- [ ] Observations are returned from probe logic where relevant
- [ ] Confirmed nodes appended to `confirmed_vulns` are valid KG nodes
- [ ] Payload provenance is preserved for generated candidates
- [ ] Candidate validation rules still hold after the change
- [ ] Any new method is added to `METHODS_BY_SURFACE`, runtime handlers, and AKG transitions
- [ ] Any prompt changes preserve structured outputs expected by the parser
- [ ] Relevant tests are updated or added
- [ ] If docs describe the changed behavior, docs are updated too
