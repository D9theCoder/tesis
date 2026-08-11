# AGENTS.md

# Running the Framework

Run these commands from the repository root. `uv sync` creates or updates the
project environment from `pyproject.toml` and `uv.lock`:

```bash
uv sync
source .venv/bin/activate
python -m tesis run --dry-run --config config.yaml
python -m tesis run --config config.yaml
```

If activation points to an old repository path after the checkout was moved,
open a fresh shell (or run `deactivate`) and recreate the environment before
activating it:

```bash
mv .venv .venv-relocated-backup
uv sync
source .venv/bin/activate
```

The framework entry point is `python -m tesis run`. `main.py` is a separate
sample LLM-query runner and does not load `config.yaml`.

# AI Implementation Guide

This repository implements an LLM-assisted autonomous penetration testing framework for authorized DVWA sandbox testing.

This file is intentionally concise. Detailed research design, experiment matrix, scoring rubrics, artifact schema, AKG semantics, and thesis alignment are documented in `summary_en.md`. If a topic is not specified here, follow `summary_en.md`.

## Source of Truth

Use the following priority:

1. Runtime topology: `core/graph_builder.py`
2. State schema: `core/state.py`
3. Attack Knowledge Graph: `core/knowledge_graph.py`
4. Runtime behavior: `foundation/`, `agents/`, `llm/`, `evaluation/`
5. Research design and methodology: `summary_en.md`
6. User-facing thesis draft: latest thesis document

## Research Scope

The framework is restricted to DVWA.

In-scope surfaces:

* SQL Injection
* Access Control
* Brute Force

In-scope methods:

```text
sqli_union
sqli_error
sqli_boolean_blind
sqli_time_blind
ac_idor
ac_vertical_escalation
ac_force_browse
bf_dictionary
bf_spray
```

Out of scope:

```text
XSS
CSRF
LFI
File Upload
Command Injection
Weak Session IDs
JavaScript attacks
CAPTCHA bypass
HTTP redirect attacks
Credential stuffing
Targets outside DVWA
```

Do not add new vulnerability surfaces unless the thesis scope is explicitly changed.

## Active Experiment Design

The main thesis experiment uses two conditions:

```text
linear_hybrid
akg_guided_hybrid
```

Both conditions use hybrid payloads.

`static_only` and `llm_mutation_only` may exist for debugging or optional ablation, but they are not the primary thesis conditions.

Required experiment fields:

```text
experiment_condition
target_method
payload_mode
repeat_index
```

The framework must support method-level evaluation. If `target_method` is set, the run evaluates that method explicitly. Do not silently replace it with another method unless the run is marked as fallback or infeasible.

## Runtime Flow

Canonical LangGraph flow:

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

Important rules:

* There is no standalone LangGraph verifier node.
* Verification is performed inside method agents using `foundation/verifier.py`.
* The orchestrator selects a method. It does not execute the method directly.
* Method execution must happen after payload candidate building and validation.
* Method agents are static modules. The LLM must not create agents dynamically.

## State Rules

Follow `core/state.py`.

Implementation rules:

* Return partial state updates.
* Do not mutate state directly.
* Keep observations monotonic.
* Preserve payload provenance.
* Store viable methods, selected method, and AKG path.
* Append confirmed KG nodes to `confirmed_vulns`.
* Append chain-enabling outcomes to `achieved_outcomes`.
* Keep individual score dimensions. Do not report only a composite score.

Required state concepts:

```text
experiment_condition
target_method
viable_methods
selected_method
akg_path
confirmed_vulns
achieved_outcomes
payload_candidates
payload_validation_results
payload_provenance
method_scores
payload_scores
exploitation_scores
chain_scores
output_scores
composite_scores
guardrail_activations
invalid_json_events
fallback_events
containment_events
```

## AKG Rules

Follow `core/knowledge_graph.py`.

The AKG must remain:

```text
static
predefined
prevalidated
payload-aware
```

The LLM must not modify the AKG at runtime.

Chain routing must evaluate both:

```python
known = set(confirmed_vulns) | set(achieved_outcomes)
```

Correct chain semantics are documented in `summary_en.md`. Do not treat an enabling outcome as a confirmed exploit. For example, `credentials_extracted` may enable credential validation or brute force workflow, but it is not the same as `brute_force_confirmed`.

## Payload Rules

Payload execution must follow this pipeline:

```text
static seed loading
-> optional constrained LLM candidate generation
-> payload validation
-> ranking and budgeting
-> method agent execution
-> verifier evidence
-> scoring
```

Payload validator must enforce:

```text
schema validity
method family alignment
target parameter alignment
allowed mutation types
forbidden mutation rejection
provenance requirement
deduplication
candidate budget
DVWA scope containment
```

Do not execute invalid payloads.

## Guardrail Handling

Use `guardrail_handling` and `guardrail_retry` naming in new code and docs.

Legacy `evasion` naming may be supported temporarily only for backward compatibility.

Allowed behavior:

```text
schema retry
structure-only clarification
authorized DVWA sandbox clarification
deterministic fallback
static seed fallback
controlled stop
```

Forbidden behavior:

```text
jailbreak
roleplay deception
adversarial prompt injection
policy bypass prompting
external target adaptation
```

## Containment

Containment is mandatory.

All HTTP requests must be restricted to the configured DVWA base URL or allowed same host.

Required behavior:

* Block external hosts.
* Block external redirects.
* Block payload candidates that introduce external targets.
* Log containment violations.
* Do not let LLM output override target scope.

Containment must be enforced at both the payload validation layer and the HTTP client layer.

## Scoring

Use the thesis scoring model documented in `summary_en.md`.

Required score dimensions:

```text
Smethod
Spayload
Sexploit
Schain
Soutput
Srun
```

Composite score:

```text
Srun = 0.20*Smethod + 0.20*Spayload + 0.30*Sexploit + 0.10*Schain + 0.20*Soutput
```

Preserve each individual dimension in artifacts.

## Artifact Rules

Each experiment run must produce enough evidence for reproducibility and manual audit.

At minimum, artifacts must include:

```text
run_id
experiment_condition
provider
model
surface
target_method
security_level
payload_mode
repeat_index
viable_methods
selected_method
akg_path
payload_candidates
payload_validation_results
payload_provenance
execution_log
response_evidence
timing_evidence
verifier_decision
confirmed_vulns
achieved_outcomes
guardrail_activations
invalid_json_events
fallback_events
containment_events
method_score
payload_scores
exploitation_score
chain_score
output_score
composite_score
final_state
```

Manual scoring must rely on artifacts, not intuition or model claims.

## Testing and Validation

Before main experiments:

* Validate AKG nodes, edges, preconditions, and payload profiles.
* Validate prompt schemas and JSON parsing.
* Validate payload validator behavior.
* Validate chain routing.
* Validate containment.
* Run at least one dry run per surface.
* Confirm artifact completeness.

Do not start main experiments if core validation fails.

## Development Checklist

Before finalizing a change:

* Runtime flow still matches `core/graph_builder.py`.
* State updates follow `core/state.py`.
* AKG changes are reflected in `core/knowledge_graph.py`.
* `summary_en.md` and `summary_id.md` are updated if methodology or architecture changes.
* Payload candidates preserve provenance.
* Invalid payloads cannot execute.
* Guardrail and invalid JSON events are logged.
* Containment is enforced.
* Method-level evaluation still works.
* Individual score dimensions are preserved.
* Tests or validation checks are updated.
