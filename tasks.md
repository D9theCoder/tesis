# Implementation Tasks (Concise)

Based on `summary.md` and `AGENTS.md`, this is the recommended build order for the framework.

| Stage | Time Period | Primary Deliverable |
|---|---|---|
| 1. Core state contract | Week 1 | Stable `ExploitationState` + folder boundaries |
| 2. Foundation layer | Week 2 | Session manager + recon + endpoint/input discovery |
| 3. Attack Knowledge Graph | Week 3 | NetworkX graph with chain preconditions |
| 4. Execution runtime | Weeks 4–5 | LangGraph workflow + conditional routing |
| 5. Vulnerability agents | Weeks 6–7 | Tier 1/2 agents + chain triggers + browser verification |
| 6. Evaluation and testing | Week 8 | Scorer (0–4), multi-LLM runner, regression tests |

## Stage 1 — Core state contract (Week 1)
**Goal:** Lock the shared state schema before writing agents.

**Sample code:**
```python
from typing import TypedDict

class ExploitationState(TypedDict):
    target_url: str
    security_level: str
    endpoints: list[dict]
    confirmed_vulns: list[str]
    scores: dict[str, int]
    tried_payloads: dict[str, list[str]]
    iteration_count: int
    max_iterations: int
```

**Why this stage:** All agents and graph nodes depend on one consistent state contract.

**Docs:**
- LangGraph state model / `StateGraph`

## Stage 2 — Foundation layer (Week 2)
**Goal:** Build HTTP session handling and recon crawler to discover forms, params, and CSRF tokens.

**Sample code:**
```python
import httpx
from bs4 import BeautifulSoup

with httpx.Client(follow_redirects=True, timeout=10.0, verify=False) as client:
    res = client.get(f"{base_url}/dvwa/index.php")

soup = BeautifulSoup(res.text, "html.parser")
forms = [
    {"action": f.get("action"), "method": f.get("method", "get")}
    for f in soup.select("form")
]
csrf = soup.select_one("input[name='user_token']")
```

**Why this stage:** Recon data (`endpoints`, `input_vectors`) is required before exploitation logic.

**Docs:**
- HTTPX `Client` usage
- BeautifulSoup selectors (`select`, `select_one`)

## Stage 3 — Attack Knowledge Graph (Week 3)
**Goal:** Encode exploit states and chain paths with preconditions.

**Sample code:**
```python
import networkx as nx

kg = nx.DiGraph()
kg.add_edge("sqli_confirmed", "credentials_extracted", is_chain=False)
kg.add_edge(
    "credentials_extracted",
    "admin_session_obtained",
    is_chain=True,
    preconditions=["sqli_confirmed"],
)
paths = list(nx.all_simple_paths(kg, "sqli_confirmed", "admin_session_obtained"))
```

**Why this stage:** The orchestrator and chaining coordinator need deterministic path knowledge.

**Docs:**
- NetworkX `DiGraph`
- NetworkX `all_simple_paths`

## Stage 4 — LangGraph runtime orchestration (Weeks 4–5)
**Goal:** Implement execution flow: `recon -> orchestrator -> agent -> chaining/scorer`.

**Sample code:**
```python
from langgraph.graph import StateGraph, END

graph = StateGraph(ExploitationState)
graph.add_node("recon", recon)
graph.add_node("orchestrator", orchestrator)
graph.add_node("scorer", scorer)

graph.add_conditional_edges("orchestrator", decide_next)
graph.add_conditional_edges("sqli_agent", route_after_agent)
graph.add_edge("scorer", END)
app = graph.compile()
```

**Why this stage:** This is the runtime backbone for iterative planning and chain execution.

**Docs:**
- LangGraph `add_node`, `add_conditional_edges`, `compile`, `END`

## Stage 5 — Vulnerability agents + verification (Weeks 6–7)
**Goal:** Implement Tier 1/2 agents and execution verification (HTTP + browser).

**Sample code:**
```python
from playwright.sync_api import sync_playwright

def verify_xss(url: str, cookies: list[dict]) -> bool:
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        ctx = browser.new_context()
        if cookies:
            ctx.add_cookies(cookies)
        page = ctx.new_page()
        fired = {"ok": False}
        page.on("dialog", lambda d: (fired.__setitem__("ok", True), d.dismiss()))
        page.goto(url, wait_until="networkidle")
        browser.close()
        return fired["ok"]
```

**Why this stage:** Agents need concrete exploit confirmation, not only string matching.

**Docs:**
- Playwright Python browser context and page events

## Stage 6 — Scoring, evaluation, and tests (Week 8)
**Goal:** Finalize 0–4 rubric scoring, multi-LLM comparison, and automated tests.

**Sample code:**
```python
import pytest

@pytest.mark.parametrize("level", ["low", "medium", "high"])
def test_route_after_agent(level):
    state = {
        "security_level": level,
        "confirmed_vulns": ["sqli_confirmed", "credentials_extracted"],
        "iteration_count": 2,
        "max_iterations": 30,
    }
    nxt = route_after_agent(state)
    assert nxt in {"sqli_to_creds_chain", "orchestrator", "scorer"}
```

**Why this stage:** Ensures reproducibility, scientific comparison, and stable chain behavior.

**Docs:**
- pytest `parametrize`

## Library Documentation References
- LangGraph: https://langchain-ai.github.io/langgraph/
- NetworkX DiGraph: https://networkx.org/documentation/stable/reference/classes/digraph.html
- NetworkX paths: https://networkx.org/documentation/stable/reference/algorithms/generated/networkx.algorithms.simple_paths.all_simple_paths.html
- HTTPX clients: https://www.python-httpx.org/advanced/clients/
- BeautifulSoup4 docs: https://www.crummy.com/software/BeautifulSoup/bs4/doc/
- Playwright Python: https://playwright.dev/python/docs/intro
- pytest: https://docs.pytest.org/en/stable/
