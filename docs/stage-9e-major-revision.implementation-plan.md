# Hybrid Payload Architecture Remediation Plan

## Current validation

- Python syntax is valid: `python3 -m compileall -q agents core foundation llm evaluation tesis` — tests passed.
- Existing static-agent behavior is currently test-stable: `UV_CACHE_DIR=/tmp/uv-cache uv run pytest ..agent/payload/AKG/graph subset... -q` passed with 86 tests.
- Full test discovery is healthy: `UV_CACHE_DIR=/tmp/uv-cache uv run pytest --collect-only -q` collected 425 tests.

Important limitation: this validates current syntax and old static-payload behavior only. It does not prove compliance with the
new `docs/summary.md` hybrid plan.

Current agent pentest code is not hybrid-compliant: all 9 method agents still load `PayloadLibrary()` internally and execute
handwritten static payloads directly instead of consuming validated `state["payload_candidates"][agent_id]`.

## Main issues and fixes

| Area | Issue | Required solution |
|---|---|---|
| AKG | `AttackKnowledgeGraph` has preconditions and chains but no payload profiles. | Add `payload_profile` metadata to every method node and expose `get_payload_profile(method_node)`.
| State | `ExploitationState` only has aggregate scores; no hybrid payload state. | Add payload mode, candidate queues, generated payloads, validation results, provenance, and separated score maps.
| Graph | Runtime skips candidate generation and validation. | Change flow to `recon -> orchestrator -> payload_candidate_builder -> payload_validator -> method_agent -> chaining_router -> scorer`.
| Agents | Agents hardcode `PayloadLibrary().get(...)` execution. | Keep PROBE handwritten, but EXPLOIT must execute validated candidate queues from state.
| Payloads | Handwritten payloads have no stable IDs/provenance. | Convert static payloads into seed metadata records with `seed_id`, method, level, target param, expected signal, and source.
| Hybrid LLM | No LLM payload generation prompt or parser exists. | Add constrained payload generation using AKG profile rules and strict JSON schema.
| Validation | No payload validator/ranker exists. | Add schema, method-family, target-param, scope, provenance, duplicate, and budget validation.
| Scoring | Method selection, payload quality, exploitation, and chain are conflated. | Add `method_scores`, `payload_scores`, `exploitation_scores`, and `chain_scores`; keep `scores` as a compatibility aggregate only.
| Reporting | Runner/report output lacks payload-mode metrics and manual scoring evidence. | Add validity rate, execution success rate, improvement rate, consistency fields, token/cost placeholders, and manual scoring export.
| Guardrails | Current “evasion/bypass” wording conflicts with docs’ safe retry/fallback framing. | Rename behavior in docs/config/reporting to technical retry and refusal handling; split orchestrator vs payload-generation refusals.

## Implementation details

### 1. Add payload-aware AKG profiles

Update `core/knowledge_graph.py` so each method node carries payload constraints.

```py
def _payload_profile(self, *, seed_refs, allowed, expected, budget=5) -> dict:
    return {
        "seed_payload_refs": seed_refs,
        "allowed_mutation_types": allowed,
        "forbidden_mutation_types": [
            "destructive_action",
            "out_of_scope_target",
            "wrong_method_family",
        ],
        "validation_rules": [
            "schema_valid",
            "method_family_match",
            "target_param_match",
            "scope_check",
            "provenance_required",
        ],
        "expected_success_signals": expected,
        "max_generated_candidates": budget,
        "max_total_candidates": budget + len(seed_refs),
        "provenance_required": True,
    }

def get_payload_profile(self, method_node: str) -> dict:
    if method_node not in self.graph:
        return {}
    return dict(self.graph.nodes[method_node].get("payload_profile", {}))
```

### 2. Extend state for hybrid payloads

Update `core/state.py` with hybrid state fields and reducers.

```py
class ExploitationState(TypedDict):
    payload_mode: str
    selected_method: str | None
    payload_candidates: Annotated[dict[str, list[dict]], _merge_payload_maps]
    generated_payloads: Annotated[dict[str, list[dict]], _merge_payload_maps]
    payload_validation_results: Annotated[dict[str, list[dict]], _merge_payload_maps]
    payload_scores: Annotated[dict[str, int], _merge_scores]
    payload_provenance: Annotated[dict[str, dict], _merge_nested_dicts]
    generation_prompts: Annotated[list[dict], add]
    payload_guardrail_activations: Annotated[list[dict], add]
    candidate_budget: int
    method_scores: Annotated[dict[str, int], _merge_scores]
    exploitation_scores: Annotated[dict[str, int], _merge_scores]
    chain_scores: Annotated[dict[str, int], _merge_scores]
```

Default values must include:

```yaml
payload_mode: static_only
selected_method: null
payload_candidates: {}
generated_payloads: {}
payload_validation_results: {}
payload_scores: {}
payload_provenance: {}
generation_prompts: []
payload_guardrail_activations: []
candidate_budget: 5
method_scores: {}
exploitation_scores: {}
chain_scores: {}
```

### 3. Convert static payloads into seed metadata

Update `foundation/payload_library.py` so static handwritten payloads become first-class seed candidates.

```py
@dataclass(frozen=True)
class PayloadSeed:
    seed_id: str
    method: str
    security_level: str
    stage: str
    payload_or_logic: str
    target_param: str
    expected_signal: str
    source: str = "static_seed"

def load_seed_candidates(method: str, security_level: str) -> list[dict]:
    payload_set = PayloadLibrary().get(method, security_level)
    values = payload_set.probe + payload_set.exploit + payload_set.bypass.get(security_level, [])
    return [
        {
            "candidate_id": f"{method}_{security_level}_{idx}",
            "source_seed_id": f"{method}_{security_level}_{idx}",
            "source": "static_seed",
            "method": method,
            "payload_or_logic": payload,
            "target_param": _target_param_for(method),
            "expected_signal": _expected_signal_for(method),
            "mutation_type": "none",
        }
        for idx, payload in enumerate(values)
    ]
```

### 4. Add payload candidate builder

Create `foundation/payload_generator.py`. It must build static candidates for every mode and add LLM variants only for `hybrid` or `llm_mutation_only`.

```py
def build_payload_candidates(state: dict) -> dict:
    method = state["selected_method"]
    profile = AttackKnowledgeGraph().get_payload_profile(method)
    seeds = load_seed_candidates(method, state.get("security_level", "low"))
    if state.get("payload_mode", "static_only") == "static_only":
        return {
            "payload_candidates": {method: seeds},
            "payload_provenance": {c["candidate_id"]: c for c in seeds},
        }
    generated, prompt_event, guardrail_events = generate_llm_variants(
        state=state,
        method=method,
        seeds=seeds,
        profile=profile,
    )
    candidates = seeds + generated
    return {
        "payload_candidates": {method: candidates},
        "generated_payloads": {method: generated},
        "generation_prompts": [prompt_event] if prompt_event else [],
        "payload_guardrail_activations": guardrail_events,
        "payload_provenance": {c["candidate_id"]: c for c in candidates},
    }
```

### 5. Add strict payload generation prompt

Create prompt modules under `llm/prompts/`, with a shared builder and surface-specific wrappers.

```py
def build_payload_generation_prompt(*, method, security_level, observations, seeds, profile, budget) -> str:
    return f"""
You are generating payload variants for a controlled DVWA sandbox experiment.
Current method: {method}
Security level: {security_level}
Observations: {json.dumps(observations, sort_keys=True)}
Validated seed payload metadata: {json.dumps(seeds, sort_keys=True)}
Allowed mutation types: {json.dumps(profile["allowed_mutation_types"]) }
Forbidden mutation types: {json.dumps(profile["forbidden_mutation_types"]) }
Expected success signals: {json.dumps(profile["expected_success_signals"]) }
Candidate budget: {budget}
Return ONLY valid JSON:
{{"candidates":
[{{"candidate_id":"string","source_seed_id":"string","mutation_type":"string","payload_or_logic":"string","target_param":"string",
"expected_signal":"string","rationale":"string"}}]}}
Do not generate candidates outside the selected method family.
Do not target systems outside the configured DVWA sandbox.
"""
```

### 6. Add payload validator and ranker

Create `foundation/payload_validator.py` and `foundation/payload_ranker.py`.

```py
def validate_candidate(candidate: dict, method: str, profile: dict) -> dict:
    required = {"candidate_id", "payload_or_logic", "target_param", "expected_signal", "source_seed_id"}
    missing = required - set(candidate)
    if missing:
        return {"valid": False, "reason": f"missing_fields:{sorted(missing)}"}
    if candidate.get("method", method) != method:
        return {"valid": False, "reason": "wrong_method_family"}
    if candidate["target_param"] not in _allowed_target_params(method):
        return {"valid": False, "reason": "wrong_target_param"}
    if _looks_out_of_scope(candidate["payload_or_logic"]):
        return {"valid": False, "reason": "out_of_scope_target"}
    return {"valid": True, "reason": "ok"}

def rank_candidates(candidates: list[dict], max_total: int) -> list[dict]:
    ordered = sorted(
        candidates,
        key=lambda c: (0 if c.get("source") == "static_seed" else 1, c["candidate_id"]),
    )
    return ordered[:max_total]
```

### 7. Refactor LangGraph flow

Update `core/graph_builder.py` to insert builder and validator nodes.

```py
graph.add_node("payload_candidate_builder", payload_candidate_builder_node)
graph.add_node("payload_validator", payload_validator_node)
graph.add_edge("orchestrator", "payload_candidate_builder")
graph.add_edge("payload_candidate_builder", "payload_validator")
graph.add_conditional_edges("payload_validator", route_from_payload_validator)

def route_from_payload_validator(state: ExploitationState) -> str:
    method = state.get("selected_method")
    candidates = state.get("payload_candidates", {}).get(method or "", [])
    if method in RUNTIME_AGENT_NODE_NAMES and candidates:
        return method
    return "chaining_router"
```

### 8. Update orchestrator contract

Update `agents/orchestrator.py` and `llm/prompts/orchestrator_prompt.py`.

```py
return {
    "selected_method": next_agent,
    "next_agent": "payload_candidate_builder",
    "method_scores": {next_agent: method_score},
    "akg_path": [next_agent],
    "messages": [HumanMessage(content=prompt), AIMessage(content=text)],
}
```

The JSON contract must require:

```json
{
  "next_agent": "sqli_union",
  "selected_method": "sqli_union",
  "reasoning": "...",
  "expected_outcome": "...",
  "fallback_if_fails": "sqli_error"
}
```

### 9. Refactor method agents to consume candidate queues

Update all 9 method agents. Keep probe logic handwritten because it validates method preconditions. Replace static exploit
list construction with validated candidates.

```py
def _candidate_payloads(state: dict, agent_id: str) -> list[str]:
    candidates = state.get("payload_candidates", {}).get(agent_id, [])
    return [
        str(c["payload_or_logic"]) for c in candidates if c.get("validation", {}).get("valid", True)
    ]
```

Use it in agents:

```py
# Stage 2: EXPLOIT
all_exploit = _candidate_payloads(state, AGENT_ID)
if not all_exploit:
    return make_update(
        state=state,
        module_name=AGENT_ID,
        score=1,
        tried_payloads=all_tried,
        failure_agents=[AGENT_ID],
    )
```

Do not let agents call `PayloadLibrary().get(...)` for exploit payloads after this refactor. Static handwritten payloads must
enter through the candidate builder.

### 10. Preserve pentest payload semantics

Validate agent request syntax by method family.

```py
_TARGET_PARAM_BY_METHOD = {
    "sqli_union": {"id"},
    "sqli_error": {"id"},
    "sqli_boolean_blind": {"id"},
    "sqli_time_blind": {"id"},
    "ac_idor": {"userId"},
    "ac_vertical_escalation": {"userId"},
    "ac_force_browse": {"path"},
    "bf_dictionary": {"username", "password"},
    "bf_spray": {"username", "password"},
}
```

Use method-specific execution adapters so candidate payloads cannot be sent to the wrong parameter.

```py
def execute_candidate(session, method: str, candidate: dict):
    payload = candidate["payload_or_logic"]
    if method.startswith("sqli_"):
        return session.get(_path_for(method), params={"id": payload, "Submit": "Submit"})
    if method.startswith("bf_"):
        username, password = payload.split(":", 1)
        return session.get(
            "/vulnerabilities/brute/",
            params={"username": username, "password": password, "Login": "Login"},
        )
    if method == "ac_force_browse":
        return session.get(payload)
    return session.get(
        "/vulnerabilities/authbypass/", params={"userId": payload, "Submit": "Submit"}
    )
```

### 11. Separate scoring

Update `core/scorer.py`, `evaluation/metrics.py`, and `agents/state_utils.py`.

```py
def make_update(..., exploitation_score: int, payload_scores: dict | None = None, chain_score: int = 0):
    update = {
        "exploitation_scores": {module_name: exploitation_score},
        "chain_scores": {module_name: chain_score},
        "scores": merge_scores(state, module_name, max(exploitation_score, chain_score)),
    }
    if payload_scores:
        update["payload_scores"] = payload_scores
    return update
```

Add metrics:

```py
def payload_validity_rate(results: dict[str, list[dict]]) -> float:
    flat = [r for rows in results.values() for r in rows]
    if not flat:
        return 0.0
    return sum(1 for r in flat if r.get("valid")) / len(flat)
```

### 12. Extend runner, config, and reports

Update config/CLI/runner to include `payload_mode`.

```py
run_id = f"{llm_provider}-{surface}-{security_level}-{payload_mode}-{repeat_index}"
thread_id = f"{llm_provider}-{surface}-{security_level}-{payload_mode}"
```

Add config defaults:

```yaml
payload_mode: static_only
candidate_budget: 5
payload_modes:
  - static_only
  - hybrid
```

### 13. Add manual scoring export

Create `evaluation/manual_scoring_sheet.py`.

```py
def manual_scoring_rows(artifact: dict) -> list[dict]:
    state = artifact.get("final_state", {})
    rows = []
    for candidate_id, provenance in state.get("payload_provenance", {}).items():
        rows.append({
            "run_id": artifact.get("run_id"),
            "provider": artifact.get("config", {}).get("provider"),
            "surface": artifact.get("config", {}).get("surface"),
            "security_level": artifact.get("config", {}).get("security_level"),
            "payload_mode": artifact.get("config", {}).get("payload_mode"),
            "candidate_id": candidate_id,
            "payload_source": provenance.get("source"),
            "source_seed_id": provenance.get("source_seed_id"),
            "mutation_type": provenance.get("mutation_type"),
            "expected_signal": provenance.get("expected_signal"),
        })
    return rows
```

## Test plan

- Keep existing validation commands in the implementation checklist:

```sh
python3 -m compileall -q agents core foundation llm evaluation tesis
UV_CACHE_DIR=/tmp/uv-cache uv run pytest --collect-only -q
```

- Add `test_knowledge_graph_payload_profiles.py` to assert all 9 methods expose complete payload profiles.
- Add `test_state_hybrid_payload_schema.py` to assert new state fields and reducers.
- Add `test_payload_seed_metadata.py` to assert static handwritten payloads produce stable seed candidates.
- Add `test_payload_generator_static_only.py` to assert `static_only` never calls an LLM.
- Add `test_payload_generator_hybrid.py` to assert LLM JSON candidates are parsed, logged, and combined with static seeds.
- Add `test_payload_validator.py` for malformed JSON, wrong method family, wrong target param, out-of-scope payload, missing
  provenance, duplicate candidate IDs, and budget overflow.
- Add `test_payload_ranker.py` for deterministic seed-first ordering.
- Update all 9 agent tests so agents receive `payload_candidates` and no longer depend on direct `PayloadLibrary().get(...)` for
  exploit execution.
- Existing 86 targeted static-agent tests should still pass after migration, adjusted only where they asserted old direct payload-
  library behavior.
- Full test collection remains healthy.
- All 9 method agents can run in `static_only` mode using candidate queues built from handwritten static seeds.
