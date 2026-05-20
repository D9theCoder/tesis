# Implementation Spec: Add Python Docstrings Across the Codebase

## Objective

Add consistent Python docstrings across the codebase to improve maintainability, code readability, and thesis traceability.

The implementation must only document existing behavior. It must not change runtime logic, file structure, function signatures, state fields, routing behavior, payload behavior, AKG logic, scoring logic, or agent execution.

## Scope

Apply this specification to all Python files under:

```text
core/
foundation/
agents/
llm/
evaluation/
tesis/
tests/
```

Documentation must cover:

```text
module docstrings
class docstrings
public function docstrings
public method docstrings
LangGraph node docstrings
static method agent docstrings
non-trivial private helper docstrings
```

Private helpers may be left undocumented only when their behavior is trivial and does not affect state, scoring, routing, payload validation, AKG traversal, HTTP execution, or evaluation output.

## Docstring Style

Use PEP 257 conventions with Google-style sections.

Use triple double quotes:

```python
"""Docstring text."""
```

Use these sections only when relevant:

```text
Args:
Returns:
Raises:
Yields:
Attributes:
```

Do not repeat type hints unnecessarily. Type hints already describe data type. The docstring should explain semantic meaning, framework role, side effects, and return interpretation.

Preferred format:

```python
def function_name(arg: str, count: int = 1) -> dict[str, str]:
    """Summarizes the function behavior in one sentence.

    Add a second paragraph only when the function has non-obvious state
    behavior, routing behavior, side effects, or architectural relevance.

    Args:
        arg: Semantic meaning of the argument.
        count: How the value affects execution.

    Returns:
        Description of the returned value and how callers should interpret it.

    Raises:
        ValueError: When invalid input prevents execution.
    """
```

## Architectural Terms

Use these terms consistently:

```text
Foundation Layer
Static Payload-Aware AKG
LangGraph Execution Flow
Multi-LLM Layer
Static Method Agents
Evaluation Layer
CLI Layer
```

Do not invent new architectural layer names unless the code already uses them.

## General Rules

1. Add a module-level docstring to every `.py` file.
2. Add docstrings to all public classes, public functions, public methods, and LangGraph node functions.
3. Document non-trivial private helpers when they affect framework behavior.
4. Keep docstrings concise and technically precise.
5. Describe what the code currently does, not what it should do in the future.
6. Do not claim that behavior is safe, complete, optimal, or production-ready unless the code enforces it.
7. Do not add long thesis explanations inside code.
8. Do not add implementation walkthroughs line by line.
9. Use inline comments only for local implementation reasoning, not for API contracts.
10. Do not modify runtime behavior.

## Module Docstring Requirements

Every Python file must begin with a module docstring.

The module docstring should explain:

```text
architectural layer
main responsibility
whether it participates in LangGraph execution
whether it uses AKG, LLM, HTTP, payload validation, verification, or scoring
whether it reads or updates ExploitationState
```

Template:

```python
"""Short summary of this module.

This module belongs to the <Layer Name>. It implements <main responsibility>
for the DVWA-focused autonomous penetration testing framework.

If applicable, it participates in the LangGraph Execution Flow and reads or
updates shared `ExploitationState` fields.
"""
```

## LangGraph Node Docstrings

Any function registered as a LangGraph node must document:

```text
stage purpose
state fields read
state fields written
side effects
routing behavior
failure behavior
```

Template:

```python
def node_name(state: ExploitationState) -> dict[str, Any]:
    """Executes the <stage name> stage of the LangGraph workflow.

    Reads:
        Important state fields read by this node.

    Writes:
        Important state fields returned by this node.

    Routing:
        Expected next node or routing hint produced by this node.

    Side Effects:
        External effects such as HTTP requests, LLM calls, artifact writing, or
        telemetry recording.

    Args:
        state: Current shared LangGraph state.

    Returns:
        Partial state update merged into the LangGraph state.
    """
```

Use `Side Effects:` only when the function actually performs external effects.

## Core Directory Requirements

Target files:

```text
core/state.py
core/knowledge_graph.py
core/graph_builder.py
core/chaining_coordinator.py
core/scorer.py
```

### `core/state.py`

Document:

```text
ExploitationState
valid vulnerability surfaces
method mappings
score labels
payload modes
LLM providers
KG node mappings
state field purpose
```

Example:

```python
class ExploitationState(TypedDict, total=False):
    """Shared state passed across the LangGraph execution workflow.

    The state stores target configuration, reconnaissance results, selected
    attack method, payload candidates, execution evidence, scoring fields,
    guardrail events, and chaining history. Nodes exchange information by
    reading and returning partial updates to this state.
    """
```

### `core/knowledge_graph.py`

Document:

```text
static AKG construction
surface nodes
method nodes
method preconditions
payload profiles
expected success signals
outcome nodes
chain transitions
method viability checks
```

Example:

```python
class AttackKnowledgeGraph:
    """Represents the static payload-aware Attack Knowledge Graph.

    The graph encodes vulnerability surfaces, exploitation methods, method
    preconditions, payload profiles, expected success signals, and cross-surface
    chaining transitions. Runtime execution queries this graph but does not
    generate new graph structure dynamically.
    """
```

AKG function docstrings must explain graph semantics, not only data structure operations.

Example:

```python
def get_viable_methods(self, surface: str, observations: dict[str, bool]) -> list[str]:
    """Returns methods whose AKG preconditions are satisfied.

    Args:
        surface: Vulnerability surface identifier.
        observations: Reconnaissance-derived facts used to evaluate method
            preconditions.

    Returns:
        Ordered method identifiers that are viable for the current surface.
    """
```

### `core/graph_builder.py`

Document:

```text
LangGraph workflow assembly
node registration
conditional routing
terminal node behavior
relationship between Foundation services, agents, and core nodes
```

Example:

```python
def route_from_payload_validator(state: ExploitationState) -> str:
    """Routes execution from payload validation to the selected method agent.

    The router checks whether validated payload candidates exist for the
    selected method. If candidates are available, execution continues to the
    corresponding static method agent. Otherwise, execution falls back to the
    chaining router.

    Args:
        state: Current LangGraph state after payload validation.

    Returns:
        Name of the next LangGraph node.
    """
```

### `core/chaining_coordinator.py`

Document:

```text
cross-surface chain logic
fallback selection
termination conditions
critical outcome handling
how next_agent is selected
```

### `core/scorer.py`

Document both roles:

```text
pure score report builder
terminal LangGraph scoring node
```

Example:

```python
def scorer(state: dict) -> dict:
    """Builds the final scoring update as the terminal LangGraph node.

    The scorer reads accumulated method scores, payload scores, exploitation
    scores, chain scores, guardrail events, attempted agents, and payload
    validation results. It does not execute attacks or verify HTTP responses.

    Args:
        state: Final or near-final LangGraph state.

    Returns:
        Partial state update containing normalized scores, surface scores, and
        summary metrics.
    """
```

## Foundation Directory Requirements

Target files:

```text
foundation/http_client.py
foundation/session_manager.py
foundation/recon.py
foundation/payload_library.py
foundation/payload_generator.py
foundation/payload_validator.py
foundation/payload_ranker.py
foundation/verifier.py
```

### Required Focus

```text
http_client.py: HTTP wrapper, timeout handling, response abstraction
session_manager.py: DVWA login, CSRF token, cookies, security level
recon.py: DVWA crawling, endpoint discovery, input parsing, observations
payload_library.py: static payload seeds and payload metadata
payload_generator.py: static, hybrid, and LLM mutation payload construction
payload_validator.py: AKG-constrained validation, provenance, mutation checks
payload_ranker.py: deterministic payload ranking
verifier.py: response evidence extraction and success-signal matching
```

### Foundation Function Requirements

Each relevant function should clarify whether it performs:

```text
pure transformation
HTTP side effect
LangGraph state update
payload validation
payload ranking
evidence extraction
```

Example for verifier:

```python
def contains_any(self, body: str, signals: list[str]) -> VerificationResult:
    """Checks whether a response body contains any expected success signal.

    Args:
        body: HTTP response body returned by DVWA.
        signals: Case-insensitive text fragments that indicate relevant
            exploitation evidence.

    Returns:
        VerificationResult containing pass status, confidence, and matched
        evidence strings.
    """
```

Example for payload validation:

```python
def payload_validator_node(state: ExploitationState) -> dict[str, Any]:
    """Validates payload candidates against the selected AKG payload profile.

    The node removes malformed, duplicate, out-of-scope, or provenance-invalid
    candidates before a method agent executes them against DVWA.

    Args:
        state: Current LangGraph state containing selected method, payload
            candidates, payload profile constraints, and payload mode.

    Returns:
        Partial state update containing validated candidates, validation
        results, and payload provenance records.
    """
```

## Agents Directory Requirements

Target files:

```text
agents/orchestrator.py
agents/base_agent.py
agents/state_utils.py
agents/agent_telemetry.py
agents/sqli/*.py
agents/access_control/*.py
agents/brute_force/*.py
```

### Orchestrator Requirements

Document:

```text
constrained method selection
AKG viability use
LLM provider use
guardrail handling
fallback behavior
selected_method update
method score update
routing to payload builder
```

Example:

```python
def orchestrator(state: ExploitationState) -> dict[str, Any]:
    """Selects the next AKG-viable method using constrained LLM reasoning.

    The orchestrator reads reconnaissance observations, attempted methods,
    failed methods, confirmed vulnerabilities, and AKG viability results. It
    asks the configured LLM provider to choose among valid methods, then stores
    the selected method for payload construction.

    Args:
        state: Current LangGraph state after reconnaissance or chaining.

    Returns:
        Partial state update containing selected method, next node hint,
        method scores, guardrail events, and orchestration telemetry.
    """
```

### Static Method Agent Requirements

Every method agent must document:

```text
AKG method represented
DVWA module targeted
payload stages used
preconditions or observations used
verification evidence
state fields updated
payload score behavior
exploitation score behavior
chain score behavior
chaining behavior
failure behavior
```

Example:

```python
def sqli_union_agent(state: ExploitationState) -> dict[str, Any]:
    """Runs the UNION-based SQL injection method against DVWA.

    The agent consumes validated payload candidates for `sqli_union`, executes
    probe and exploit stages, verifies response evidence, updates payload and
    exploitation scores, and records confirmed vulnerabilities when success
    signals are observed.

    Args:
        state: Current LangGraph state containing target context, selected
            method, endpoints, payload candidates, observations, and scores.

    Returns:
        Partial state update containing attempted agent records, payload
        results, exploitation score, confirmed vulnerabilities, telemetry, and
        routing hints for chaining.
    """
```

### Shared Agent Utility Requirements

For `agents/state_utils.py`, document helpers that:

```text
select payload candidates
prepare DVWA session
merge scores
merge tried payloads
construct state updates
check chains
resolve endpoint fragments
```

For `agents/agent_telemetry.py`, document telemetry event structure and intended usage.

## LLM Directory Requirements

Target files:

```text
llm/provider.py
llm/guardrail_monitor.py
llm/prompts/orchestrator_prompt.py
llm/prompts/payload_generation_prompt.py
```

Document:

```text
supported provider abstraction
model configuration behavior
prompt input structure
expected JSON output
guardrail refusal detection
DVWA sandbox restriction
difference between method selection and payload mutation
```

Example:

```python
def get_llm(provider: str, model_config: dict[str, Any] | None = None):
    """Builds a chat model instance for the configured LLM provider.

    Args:
        provider: Provider identifier such as `gemini`, `openai`, `claude`,
            or `openai_compatible`.
        model_config: Optional provider configuration loaded from project
            configuration.

    Returns:
        LangChain-compatible chat model instance.

    Raises:
        ValueError: If the provider is unsupported or required configuration is
            missing.
    """
```

Prompt builder docstrings must specify:

```text
what decision the prompt asks for
what context is included
what schema is expected
what safety or scope constraints are included
```

## Evaluation Directory Requirements

Target files:

```text
evaluation/runner.py
evaluation/multi_llm_runner.py
evaluation/metrics.py
evaluation/contracts.py
evaluation/reporter.py
```

Document:

```text
single engagement execution
multi-provider matrix execution
score aggregation
metric semantics
report artifact generation
failure handling
```

Metric functions must define:

```text
input meaning
output range
interpretation
```

Example:

```python
def payload_validity_rate(validation_results: dict[str, list[dict]]) -> float:
    """Computes the fraction of payload candidates accepted by validation.

    Args:
        validation_results: Validation records grouped by method identifier.

    Returns:
        Float between 0.0 and 1.0 representing the proportion of candidates
        that passed structural, provenance, mutation, and scope checks.
    """
```

For runner functions, document:

```text
initial state construction
graph execution
configuration inputs
artifact writing
error handling
```

## CLI Directory Requirements

Target files:

```text
tesis/cli.py
tesis/config_loader.py
tesis/report_formatters.py
```

Document:

```text
CLI command behavior
configuration loading
configuration precedence
single run mode
matrix mode
dry-run behavior
report rendering
exit code meaning
```

Example:

```python
def handle_run(args: argparse.Namespace) -> int:
    """Runs a single or matrix engagement from CLI arguments.

    Args:
        args: Parsed command-line arguments containing target, provider,
            security level, surface, payload mode, iteration budget, and output
            settings.

    Returns:
        Process exit code. Zero indicates successful command execution.
    """
```

## Tests Directory Requirements

For tests:

```text
use descriptive test names
add module docstrings only for complex test modules
add function docstrings only when test intent is not obvious
do not add verbose docstrings to simple tests
```

Example:

```python
def test_payload_validator_rejects_out_of_scope_candidate():
    """Rejects payload candidates that violate AKG scope constraints."""
```

## Payload-Specific Documentation Rules

For payload-related functions, docstrings must distinguish:

```text
static seed payloads
LLM-generated variants
mutation constraints
validation rules
provenance requirements
candidate budget
payload mode
```

Example:

```python
def build_payload_candidates(state: ExploitationState) -> dict[str, list[dict]]:
    """Builds payload candidates for the selected AKG method.

    The function combines static payload seeds and optional LLM-generated
    variants according to the configured payload mode, AKG payload profile, and
    candidate budget.

    Args:
        state: Current LangGraph state containing selected method, security
            level, observations, payload mode, and candidate budget.

    Returns:
        Candidate payload records grouped by method identifier.
    """
```

## Verification vs Scoring Documentation Rule

Use this distinction consistently:

```text
Verifier:
    Foundation Layer component.
    Checks HTTP response evidence.
    Produces VerificationResult.
    Does not produce final experiment score.

Scorer:
    Evaluation component and terminal LangGraph node.
    Reads accumulated state.
    Produces final normalized scores and summaries.
    Does not execute payloads or inspect HTTP responses directly.
```

## Recon Documentation Rule

Use this distinction consistently:

```text
Recon as Foundation Layer:
    Provides target discovery and observation services.

Recon as LangGraph Execution Flow:
    Acts as the first runtime node before orchestration.
```

Do not treat this as duplicate architecture. It is the same component viewed from two perspectives: structural layer and runtime workflow.

## What Not to Do

Do not:

```text
change logic
change imports unless required for typing already present
change signatures
rename files
rename state fields
modify graph routing
modify payload content
modify AKG edges or metadata
modify scoring behavior
add new runtime dependencies
add new tests unless necessary
write speculative future behavior
write long thesis prose inside code
```

## Definition of Done

The task is complete when:

```text
1. Every Python file has a module docstring.
2. Every public class has a class docstring.
3. Every public function and method has a docstring.
4. Every LangGraph node documents state reads, state writes, routing, and side effects.
5. Every static method agent documents method purpose, payload use, verification, scoring, and chaining.
6. Every AKG function explains graph semantics.
7. Every payload function distinguishes seeds, variants, mutation constraints, validation, provenance, and budget.
8. Every metric function explains meaning and output range.
9. No docstring describes behavior that is not implemented.
10. No runtime behavior changes are introduced.
```
