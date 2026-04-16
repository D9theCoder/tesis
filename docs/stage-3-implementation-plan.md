# Stage 3 Implementation Plan — Attack Knowledge Graph (Detailed, Contract-Aligned)

This document fully replaces the Stage 3 plan and is strictly scoped to **Attack Knowledge Graph (AKG)** work only.

It is aligned with:

- `/home/kevin/Coding (WSL)/tesis/core/state.py` (canonical contracts, especially `KG_NODES`)
- `/home/kevin/Coding (WSL)/tesis/AGENTS.md` (agent/chain semantics)
- `/home/kevin/Coding (WSL)/tesis/docs/summary.md` (architecture narrative + pseudocode aliases)

---

## 1) Stage objective and hard boundary

### Objective

Implement a deterministic `AttackKnowledgeGraph` in `core/knowledge_graph.py` that:

1. Uses `KG_NODES` from `core/state.py` as canonical node vocabulary.
2. Uses canonical edge metadata keys:
   - `is_chain`
   - `preconditions`
   - `target_agent`
3. Exposes deterministic APIs for Stage 4 consumers:
   - `get_next_actions(node: str) -> list[dict]`
   - `get_viable_chains(confirmed_vulns: list[str], achieved_outcomes: list[str] | None = None, max_paths: int = 5) -> list[list[str]]`
4. Validates graph integrity at initialization (fail-fast).

### Hard boundary (non-negotiable)

Stage 3 is **AKG only**. Do **not** implement Stage 4 runtime wiring:

- No LangGraph node wiring (`graph_builder`)
- No orchestrator runtime flow
- No chaining coordinator runtime routing implementation

Only integration **contracts/interfaces** are allowed.

---

## 2) Canonical naming and compatibility normalization

Canonical edge metadata:

- `is_chain: bool`
- `preconditions: list[str]`
- `target_agent: str | None`

Compatibility normalization is required because `summary.md` pseudocode uses aliases:

- `precondition` → `preconditions`
- `agent` → `target_agent`

Rule: aliases may be accepted internally at normalization boundaries, but public AKG outputs must always use canonical keys.

---

## 3) Determinism requirements (explicit)

Determinism is mandatory to avoid flaky behavior and hidden-test failures.

1. Nodes are inserted from `sorted(KG_NODES)`.
2. `get_next_actions()` ordering is stable by:
   1) `priority` ascending, 2) `target` lexical, 3) `target_agent` lexical (`""` when `None`).
3. `get_viable_chains()` ordering is stable by:
   1) path length ascending, 2) tuple lexical.
4. Unknown nodes are handled safely (`[]`) instead of exceptions.
5. `preconditions` are normalized (deduplicated + sorted).
6. Query methods are side-effect free (read-only).

---

## 4) Planned implementation blueprint (`core/knowledge_graph.py`)

### 4.1 Data models / transition types

```python
"""Attack Knowledge Graph built on NetworkX (Stage 3)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TypedDict

import networkx as nx

from core.state import KG_NODES


class RawTransition(TypedDict, total=False):
    source: str
    target: str
    is_chain: bool
    preconditions: list[str]          # canonical
    precondition: str | list[str]     # compatibility alias from summary.md pseudocode
    target_agent: str                 # canonical
    agent: str                        # compatibility alias from summary.md pseudocode
    priority: int


@dataclass(frozen=True, slots=True)
class Transition:
    source: str
    target: str
    is_chain: bool
    preconditions: tuple[str, ...]
    target_agent: str | None
    priority: int = 100
```

### 4.2 `AttackKnowledgeGraph` class skeleton

```python
class AttackKnowledgeGraph:
    """Deterministic attack-state graph for Stage 3 domain logic."""

    HIGH_IMPACT_OUTCOMES: tuple[str, ...] = (
        "admin_session_obtained",
        "rce_achieved",
        "user_compromised",
        "data_exfiltrated",
        "session_hijack",
    )

    def __init__(self) -> None:
        self.graph: nx.DiGraph = nx.DiGraph()
        self._build_graph()
        self._validate_graph()
```

### 4.3 Graph build method

```python
# inside AttackKnowledgeGraph
def _build_graph(self) -> None:
    self.graph.add_nodes_from(sorted(KG_NODES))  # canonical vocabulary only

    transitions: list[RawTransition] = [
        # Non-chain transitions
        {"source": "sqli_confirmed", "target": "credentials_extracted", "is_chain": False, "priority": 20},
        {"source": "brute_force_confirmed", "target": "credentials_extracted", "is_chain": False, "priority": 20},
        {"source": "blind_sqli_confirmed", "target": "data_exfiltrated", "is_chain": False, "priority": 30},
        {"source": "idor_confirmed", "target": "data_exfiltrated", "is_chain": False, "priority": 30},
        {"source": "csrf_confirmed", "target": "user_compromised", "is_chain": False, "priority": 30},
        {"source": "weak_session_confirmed", "target": "session_hijack", "is_chain": False, "priority": 30},
        {"source": "cmd_injection_confirmed", "target": "rce_achieved", "is_chain": False, "priority": 30},
        {"source": "file_upload_confirmed", "target": "rce_achieved", "is_chain": False, "priority": 30},
        {"source": "lfi_confirmed", "target": "log_access_confirmed", "is_chain": False, "priority": 20},

        # Chain transitions
        {
            "source": "credentials_extracted",
            "target": "admin_session_obtained",
            "is_chain": True,
            "preconditions": ["sqli_confirmed", "credentials_extracted"],
            "target_agent": "sqli_to_creds_chain",
            "priority": 10,
        },
        {
            "source": "admin_session_obtained",
            "target": "rce_achieved",
            "is_chain": True,
            "preconditions": ["admin_session_obtained"],
            "target_agent": "upload_to_rce_chain",
            "priority": 10,
        },
        {
            "source": "xss_stored_confirmed",
            "target": "user_compromised",
            "is_chain": True,
            "preconditions": ["xss_stored_confirmed"],
            "target_agent": "xss_to_csrf_chain",
            "priority": 10,
        },
        {
            "source": "log_access_confirmed",
            "target": "rce_achieved",
            "is_chain": True,
            "preconditions": ["lfi_confirmed", "log_access_confirmed"],
            "target_agent": "lfi_to_rce_chain",
            "priority": 10,
        },
    ]

    for raw in transitions:
        t = self._normalize_transition(raw)
        self.graph.add_edge(
            t.source,
            t.target,
            is_chain=t.is_chain,
            preconditions=list(t.preconditions),
            target_agent=t.target_agent,
            priority=t.priority,
        )
```

### 4.4 Metadata normalization helper

```python
# inside AttackKnowledgeGraph
@staticmethod
def _as_preconditions(value: str | list[str] | None) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return [item for item in value if isinstance(item, str)]


def _normalize_transition(self, raw: RawTransition) -> Transition:
    # Compatibility aliases (summary.md pseudocode)
    preconditions_raw = raw.get("preconditions", raw.get("precondition"))
    target_agent_raw = raw.get("target_agent", raw.get("agent"))

    preconditions = tuple(sorted(set(self._as_preconditions(preconditions_raw))))
    is_chain = bool(raw.get("is_chain", False))
    priority = int(raw.get("priority", 100))

    return Transition(
        source=str(raw["source"]),
        target=str(raw["target"]),
        is_chain=is_chain,
        preconditions=preconditions,
        target_agent=str(target_agent_raw) if target_agent_raw is not None else None,
        priority=priority,
    )
```

### 4.5 `get_next_actions`

```python
# inside AttackKnowledgeGraph
def get_next_actions(self, node: str) -> list[dict]:
    if node not in self.graph:
        return []

    actions: list[dict] = []
    for _, target, meta in self.graph.out_edges(node, data=True):
        normalized = self._normalize_transition(
            {
                "source": node,
                "target": target,
                "is_chain": bool(meta.get("is_chain", False)),
                "preconditions": list(meta.get("preconditions", [])),
                "target_agent": meta.get("target_agent"),
                "priority": int(meta.get("priority", 100)),
            }
        )
        actions.append(
            {
                "source": normalized.source,
                "target": normalized.target,
                "is_chain": normalized.is_chain,
                "preconditions": list(normalized.preconditions),
                "target_agent": normalized.target_agent,
                "priority": normalized.priority,
            }
        )

    return sorted(
        actions,
        key=lambda item: (
            item["priority"],
            item["target"],
            item["target_agent"] or "",
        ),
    )
```

### 4.6 `get_viable_chains`

```python
# inside AttackKnowledgeGraph
def _path_is_viable(self, path: list[str], known_nodes: set[str]) -> bool:
    for source, target in zip(path, path[1:]):
        edge = self.graph[source][target]
        if not bool(edge.get("is_chain", False)):
            continue
        required = set(edge.get("preconditions", []))
        if not required.issubset(known_nodes):
            return False
    return True


def get_viable_chains(
    self,
    confirmed_vulns: list[str],
    achieved_outcomes: list[str] | None = None,
    max_paths: int = 5,
) -> list[list[str]]:
    if max_paths <= 0:
        return []

    achieved = set(achieved_outcomes or [])
    known = set(confirmed_vulns) | achieved
    targets = [node for node in self.HIGH_IMPACT_OUTCOMES if node not in achieved]

    candidates: set[tuple[str, ...]] = set()
    for start in sorted(set(confirmed_vulns)):
        if start not in self.graph:
            continue
        for target in sorted(targets):
            if target not in self.graph or start == target:
                continue
            for path in nx.all_simple_paths(
                self.graph,
                source=start,
                target=target,
                cutoff=6,
            ):
                if self._path_is_viable(path, known):
                    candidates.add(tuple(path))

    ordered = sorted(candidates, key=lambda p: (len(p), p))
    return [list(path) for path in ordered[:max_paths]]
```

### 4.7 Validation helpers

```python
# inside AttackKnowledgeGraph
def _validate_graph(self) -> None:
    self._validate_nodes_in_kg_nodes()
    self._validate_chain_metadata()
    self._validate_preconditions_known()
    self._validate_high_impact_nodes_exist()


def _validate_nodes_in_kg_nodes(self) -> None:
    allowed = set(KG_NODES)
    unknown = sorted(node for node in self.graph.nodes if node not in allowed)
    if unknown:
        raise ValueError(f"Unknown graph nodes not in KG_NODES: {unknown}")


def _validate_chain_metadata(self) -> None:
    for source, target, meta in self.graph.edges(data=True):
        if not bool(meta.get("is_chain", False)):
            continue
        if "preconditions" not in meta:
            raise ValueError(f"Chain edge {source}->{target} missing preconditions")
        if not meta.get("target_agent"):
            raise ValueError(f"Chain edge {source}->{target} missing target_agent")


def _validate_preconditions_known(self) -> None:
    allowed = set(KG_NODES)
    for source, target, meta in self.graph.edges(data=True):
        for required in meta.get("preconditions", []):
            if required not in allowed:
                raise ValueError(
                    f"Edge {source}->{target} has unknown precondition: {required}"
                )


def _validate_high_impact_nodes_exist(self) -> None:
    missing = [n for n in self.HIGH_IMPACT_OUTCOMES if n not in self.graph]
    if missing:
        raise ValueError(f"Missing high-impact outcomes in graph: {missing}")
```

---

## 5) Stage 4 integration contracts (reference only, no runtime wiring)

These are **contracts only** that Stage 4 code will call.

```python
# /home/kevin/Coding (WSL)/tesis/agents/orchestrator.py (Stage 4 consumer contract)
kg = AttackKnowledgeGraph()
paths = kg.get_viable_chains(
    confirmed_vulns=state["confirmed_vulns"],
    achieved_outcomes=state.get("achieved_outcomes", []),
    max_paths=5,
)

# /home/kevin/Coding (WSL)/tesis/core/chaining_coordinator.py (Stage 4 consumer contract)
kg = AttackKnowledgeGraph()
for node in state["confirmed_vulns"]:
    for edge in kg.get_next_actions(node):
        if edge["is_chain"] and set(edge["preconditions"]).issubset(set(state["confirmed_vulns"])):
            return edge["target_agent"]
```

No Stage 4 control-flow implementation is included in Stage 3.

---

## 6) Representative pytest plan (`tests/test_knowledge_graph.py`)

```python
"""Representative tests for Stage 3 AKG behavior and contracts."""

import networkx as nx
import pytest

from core.knowledge_graph import AttackKnowledgeGraph
from core.state import KG_NODES


@pytest.fixture()
def kg() -> AttackKnowledgeGraph:
    return AttackKnowledgeGraph()


def test_graph_is_digraph_and_uses_canonical_nodes(kg: AttackKnowledgeGraph):
    assert isinstance(kg.graph, nx.DiGraph)
    assert set(KG_NODES).issubset(set(kg.graph.nodes))


def test_get_next_actions_unknown_node_returns_empty(kg: AttackKnowledgeGraph):
    assert kg.get_next_actions("unknown_node") == []


def test_get_next_actions_returns_canonical_metadata_keys(kg: AttackKnowledgeGraph):
    actions = kg.get_next_actions("credentials_extracted")
    assert actions
    for action in actions:
        assert "is_chain" in action
        assert "preconditions" in action
        assert "target_agent" in action
        assert "precondition" not in action
        assert "agent" not in action


def test_alias_normalization_works_for_summary_pseudocode_names(kg: AttackKnowledgeGraph):
    normalized = kg._normalize_transition(
        {
            "source": "credentials_extracted",
            "target": "admin_session_obtained",
            "is_chain": True,
            "precondition": "sqli_confirmed",
            "agent": "sqli_to_creds_chain",
        }
    )
    assert normalized.preconditions == ("sqli_confirmed",)
    assert normalized.target_agent == "sqli_to_creds_chain"


def test_get_viable_chains_is_deterministic(kg: AttackKnowledgeGraph):
    confirmed = ["sqli_confirmed", "credentials_extracted", "admin_session_obtained"]
    first = kg.get_viable_chains(confirmed_vulns=confirmed, achieved_outcomes=[])
    second = kg.get_viable_chains(confirmed_vulns=confirmed, achieved_outcomes=[])
    assert first == second


def test_chain_preconditions_are_enforced(kg: AttackKnowledgeGraph):
    # Missing sqli_confirmed should block credentials -> admin_session chain viability
    paths = kg.get_viable_chains(
        confirmed_vulns=["credentials_extracted"],
        achieved_outcomes=[],
        max_paths=10,
    )
    assert all("admin_session_obtained" not in path for path in paths)


def test_max_paths_and_achieved_outcome_filtering(kg: AttackKnowledgeGraph):
    paths = kg.get_viable_chains(
        confirmed_vulns=[
            "sqli_confirmed",
            "credentials_extracted",
            "admin_session_obtained",
            "lfi_confirmed",
            "log_access_confirmed",
        ],
        achieved_outcomes=["rce_achieved"],
        max_paths=1,
    )
    assert len(paths) <= 1
    assert all(path[-1] != "rce_achieved" for path in paths)
```

---

## 7) Migration / compatibility section

### Why migration is needed

`summary.md` pseudocode uses `precondition` and `agent`, but Stage 3 canonical metadata is `preconditions` and `target_agent`.

### Compatibility policy

1. Accept aliases at input/definition boundaries only.
2. Normalize immediately to canonical keys.
3. Return canonical keys only in public APIs.
4. Lock behavior with explicit tests.

### Alias mapping

| Legacy alias | Canonical key | Rule |
|---|---|---|
| `precondition` | `preconditions` | string → single-item list; list → dedupe + sort |
| `agent` | `target_agent` | direct rename |

---

## 8) Exact file paths: impacted vs non-impacted

### Impacted in Stage 3

1. `/home/kevin/Coding (WSL)/tesis/core/knowledge_graph.py`  
   Replace placeholder with deterministic AKG implementation.
2. `/home/kevin/Coding (WSL)/tesis/tests/test_knowledge_graph.py`  
   Add Stage 3 AKG tests (new file).
3. `/home/kevin/Coding (WSL)/tesis/docs/stage-3-implementation-plan.md`  
   Replace plan document with this detailed version.

### Explicitly non-impacted in Stage 3

1. `/home/kevin/Coding (WSL)/tesis/core/state.py` (read-only canonical contract)
2. `/home/kevin/Coding (WSL)/tesis/agents/orchestrator.py` (Stage 4 runtime)
3. `/home/kevin/Coding (WSL)/tesis/core/chaining_coordinator.py` (Stage 4 runtime)
4. `/home/kevin/Coding (WSL)/tesis/core/graph_builder.py` (Stage 4 runtime wiring)
5. `/home/kevin/Coding (WSL)/tesis/core/scorer.py` (Stage 6 domain)

---

## 9) Acceptance criteria

Stage 3 is accepted only if all conditions hold:

1. `AttackKnowledgeGraph` is implemented with `nx.DiGraph`.
2. Node vocabulary is sourced from `KG_NODES` only.
3. Canonical metadata keys are used (`is_chain`, `preconditions`, `target_agent`).
4. Alias normalization for `precondition`/`agent` is implemented and tested.
5. `get_next_actions()` is deterministic and canonical.
6. `get_viable_chains()` is deterministic, filtered, and respects `max_paths`.
7. Validation is fail-fast for invalid nodes/metadata/preconditions.
8. `tests/test_knowledge_graph.py` passes.
9. Stage boundary is respected (no Stage 4 runtime implementation work).

---

## 10) Definition of Done (DoD)

- [ ] Changes are limited to Stage 3 impacted files.
- [ ] `pytest tests/test_knowledge_graph.py -q` passes.
- [ ] `pytest tests/test_state.py -q` passes (contract compatibility retained).
- [ ] AKG query outputs are deterministic across repeated calls.
- [ ] Public outputs use canonical metadata keys only.
- [ ] Plan and snippets keep security levels within `low | medium | high` only.
- [ ] Documentation and tests are naming-consistent.

---

## 11) Risk / mitigation table

| Risk | Impact | Mitigation | Verification signal |
|---|---|---|---|
| Node naming drift from docs/examples | Broken graph lookups and hidden-test failures | Validate all nodes/edges against `KG_NODES` | Fail-fast validation tests |
| Alias drift (`precondition`/`agent`) | Stage 4 consumers parse wrong metadata | Normalize aliases and emit canonical keys only | Alias normalization unit tests |
| Nondeterministic ordering | Flaky routing and flaky tests | Stable sort policy in both APIs | Repeated-call equality tests |
| Missing chain metadata | Unsafe/invalid chain routing | Require `preconditions` + `target_agent` for chain edges | Validation tests for malformed edges |
| Scope creep into Stage 4 | Rework and stage overlap | Enforce impacted/non-impacted path boundary | Review checklist before merge |

---

## 12) Execution checklist (implementation sequence)

1. Add transition types and AKG class skeleton.
2. Implement `_build_graph()` with canonical transitions.
3. Implement alias normalization helper.
4. Implement fail-fast validation helpers.
5. Implement deterministic `get_next_actions()`.
6. Implement deterministic `get_viable_chains()`.
7. Add representative tests in `tests/test_knowledge_graph.py`.
8. Run AKG + state-contract tests.

This completes the Stage 3 plan for AKG only.