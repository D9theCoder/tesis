# Stage 2 Implementation Plan — Foundation Layer (Technical)

This plan is based on the current repository state and the updated architecture intent in `AGENTS.md`, `summary.md`, and `tasks.md`.

- `core/state.py` is already the canonical state contract.
- `foundation/session_manager.py`, `foundation/http_client.py`, and `foundation/recon.py` are currently placeholders and should be implemented in this stage.
- `foundation/payload_library.py` and `foundation/verifier.py` remain full implementation targets for Stage 5; Stage 2 should only freeze their interfaces/contracts to avoid downstream churn.

---

## 1) Scope and design constraints

### In scope

1. Session/authentication foundation for DVWA (`session_manager.py`)
2. Shared HTTP transport layer (`http_client.py`)
3. Recon pipeline to populate attack surface (`recon.py`)
4. Contract-only payload/verifier interfaces (`payload_library.py`, `verifier.py`) for Stage 5 handoff
5. Tests for deterministic behavior and schema compatibility

### Non-negotiable constraints

1. **Immutable LangGraph state flow**: agents/nodes return partial updates; no in-place global mutation semantics.
2. **State schema compatibility**: output fields must match `ExploitationState` in `core/state.py`.
3. **Deterministic recon output shape**: endpoint/input-vector records must be normalized and deduplicated.
4. **Separation of concerns**: transport/session/recon/parsing/verification remain decoupled for reuse by Tier 1/2 agents.

---

## 2) Canonical contracts

## 2.1 Exploitation state contract (already defined)

Use `core/state.py` as source of truth for Stage 2 outputs:

- `endpoints: list[dict]`
- `input_vectors: list[dict]`
- `security_level: str`
- `next_agent: str`

### Recon node return contract

```python
from core.state import ExploitationState

def recon(state: ExploitationState) -> dict:
    # ... discover endpoints and vectors ...
    return {
        "endpoints": endpoints,
        "input_vectors": input_vectors,
        "security_level": detected_level,
        "next_agent": "orchestrator",
    }
```

## 2.2 Data model normalization (recommended)

Prefer explicit typed structures for normalization before writing to state.

```python
from typing import TypedDict

class EndpointRecord(TypedDict):
    url: str
    method: str
    params: list[str]
    csrf_token: str | None
    module_name: str

class InputVectorRecord(TypedDict):
    param_name: str
    param_type: str  # e.g. "text" | "hidden" | "file" | "unknown"
    endpoint_url: str
```

---

## 3) Module-level implementation plan

## 3.1 `foundation/http_client.py`

### Responsibilities

- Provide a reusable, session-aware HTTP client wrapper.
- Standardize timeout, redirect, and connection pooling behavior.
- Centralize request logging and response metadata capture.

### Best-practice decisions

- Use a persistent `httpx.Client` (connection pooling + cookie persistence).
- Configure explicit `Timeout` and `Limits` objects.
- Use `urljoin` for safe URL composition.
- Avoid global client singleton; instantiate via dependency injection.

### Suggested API

```python
import httpx
from dataclasses import dataclass
from urllib.parse import urljoin

@dataclass
class RequestResult:
    response: httpx.Response
    elapsed_ms: float

class HTTPClient:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/") + "/"
        self.client = httpx.Client(
            follow_redirects=True,
            verify=False,
            timeout=httpx.Timeout(connect=5.0, read=12.0, write=12.0, pool=5.0),
            limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
        )

    def get(self, path: str, **kwargs) -> RequestResult:
        resp = self.client.get(urljoin(self.base_url, path.lstrip("/")), **kwargs)
        return RequestResult(response=resp, elapsed_ms=resp.elapsed.total_seconds() * 1000)

    def post(self, path: str, **kwargs) -> RequestResult:
        resp = self.client.post(urljoin(self.base_url, path.lstrip("/")), **kwargs)
        return RequestResult(response=resp, elapsed_ms=resp.elapsed.total_seconds() * 1000)
```

### Error handling

- Convert low-level network exceptions into typed domain exceptions (`TransportError`, `TimeoutError`) for cleaner retries upstream.
- Fail fast on non-recoverable URL/configuration errors.

---

## 3.2 `foundation/session_manager.py`

### Responsibilities

- Perform DVWA login lifecycle.
- Extract and include `user_token` where required.
- Set and confirm security level (`low|medium|high`).
- Expose authenticated session behavior to recon and agents.

### Login flow (technical)

1. `GET /login.php`
2. Parse `user_token` hidden input (if present)
3. `POST` credentials + token
4. Validate successful authentication via redirect/content signal
5. Persist cookies in the shared client

### Suggested API

```python
from bs4 import BeautifulSoup
from foundation.http_client import HTTPClient

class DVWASession:
    def __init__(self, base_url: str):
        self.http = HTTPClient(base_url)

    @staticmethod
    def _extract_user_token(html: str) -> str | None:
        soup = BeautifulSoup(html, "html.parser")
        token_el = soup.select_one("input[name='user_token']")
        return token_el.get("value") if token_el else None

    def login(self, username: str = "admin", password: str = "password") -> bool:
        login_page = self.http.get("login.php").response
        token = self._extract_user_token(login_page.text)

        payload = {"username": username, "password": password, "Login": "Login"}
        if token:
            payload["user_token"] = token

        resp = self.http.post("login.php", data=payload).response
        body = resp.text.lower()
        return ("logout" in body) or ("index.php" in str(resp.url))
```

### Security-level management

- Implement `set_security_level(level)` by updating DVWA security cookie and/or submitting security endpoint form.
- Implement `detect_security_level()` from cookie first, then page fallback parsing.
- Validate against allowed values (`low`, `medium`, `high`) and normalize case.

### State integration rule

Do **not** store raw session/client objects in `ExploitationState`; keep these as runtime dependencies injected into nodes.

---

## 3.3 `foundation/recon.py`

### Responsibilities

- Crawl module links from DVWA index/navigation.
- For each relevant page: parse forms, params, method, CSRF token.
- Build normalized `endpoints` and `input_vectors`.
- Infer `module_name` from path patterns.

### Recon pipeline (deterministic)

1. Start at `/index.php` (or configured entry)
2. Extract candidate links (`a[href]`) and normalize absolute URLs
3. Filter to DVWA-relevant module paths
4. Fetch each module page
5. Parse all forms and inputs
6. Build `EndpointRecord` and `InputVectorRecord`
7. Deduplicate records by canonical key
8. Return partial state update with `next_agent="orchestrator"`

### Suggested implementation skeleton

```python
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

DVWA_MODULE_HINTS = {
    "sqli": "sqli",
    "sqli_blind": "sqli_blind",
    "xss_r": "xss_r",
    "xss_s": "xss_s",
    "xss_d": "xss_d",
    "exec": "cmdi",
    "fi": "lfi",
    "upload": "upload",
    "csrf": "csrf",
    "brute": "brute",
    "weak_id": "weak_session",
}

def infer_module_name(url: str) -> str:
    path = urlparse(url).path.lower()
    for marker, module in DVWA_MODULE_HINTS.items():
        if marker in path:
            return module
    return "unknown"

def parse_forms(html: str, page_url: str) -> tuple[list[dict], list[dict]]:
    soup = BeautifulSoup(html, "html.parser")
    endpoints, vectors = [], []

    for form in soup.select("form"):
        method = (form.get("method") or "get").lower()
        action = form.get("action") or page_url
        endpoint_url = urljoin(page_url, action)

        params: list[str] = []
        csrf_token = None

        for inp in form.select("input, textarea, select"):
            name = inp.get("name")
            if not name:
                continue
            params.append(name)
            ptype = inp.get("type", "unknown").lower()
            if name == "user_token":
                csrf_token = inp.get("value")
            vectors.append({
                "param_name": name,
                "param_type": ptype,
                "endpoint_url": endpoint_url,
            })

        endpoints.append({
            "url": endpoint_url,
            "method": method,
            "params": sorted(set(params)),
            "csrf_token": csrf_token,
            "module_name": infer_module_name(endpoint_url),
        })

    return endpoints, vectors
```

### Quality gates for recon

- Never emit malformed endpoint objects (schema validate before return).
- Ensure deterministic ordering (sort by URL + method).
- Deduplicate vectors by `(param_name, endpoint_url)`.

---

## 3.4 `foundation/payload_library.py` (contract freeze in Stage 2; full implementation in Stage 5)

Stage 2 should freeze the interface now to avoid downstream churn. Keep implementation lightweight (stub/protocol/data-shape only), with full payload engine behavior deferred to Stage 5.

### Suggested API

```python
from dataclasses import dataclass

@dataclass(frozen=True)
class PayloadSet:
    probe: list[str]
    exploit: list[str]
    bypass: dict[str, list[str]]  # by security level

class PayloadLibrary:
    def get(self, vuln_class: str, security_level: str) -> PayloadSet: ...
    def record_tried(self, state: dict, module: str, payload: str) -> dict: ...
    def record_bypass(self, state: dict, technique: str, blocked_pattern: str | None = None) -> dict: ...
```

### Best-practice note

- Keep payload definitions data-driven (YAML/JSON or constants map), not scattered across agents.
- Make retrieval deterministic and side-effect free.

---

## 3.5 `foundation/verifier.py` (contract freeze in Stage 2; full implementation in Stage 5)

### Responsibilities

- Provide evidence-oriented checks that agents can call.
- Separate transport parsing from browser execution checks.

### Suggested API

```python
class VerificationResult(dict):
    # keys: ok (bool), confidence (float), evidence (list[str])
    pass

class Verifier:
    def contains_any(self, body: str, signals: list[str]) -> VerificationResult: ...
    def regex_match(self, body: str, patterns: list[str]) -> VerificationResult: ...
    def verify_xss_dialog(self, url: str, cookies: list[dict]) -> VerificationResult: ...
```

### Best-practice note

- Return structured evidence, not only booleans.
- Keep browser verification optional by marker/feature flag for CI portability.
- In Stage 2, prioritize API boundary stability; implement full verification behavior in Stage 5.

---

## 4) Integration into execution graph

Stage 2 output must fit cleanly into the LangGraph runtime contract:

- `recon` node executes first.
- It returns attack surface + security level confirmation.
- Control moves to `orchestrator` via `next_agent` and graph edge definitions.

```python
# expected runtime handoff shape from recon
{
    "endpoints": [...],
    "input_vectors": [...],
    "security_level": "medium",
    "next_agent": "orchestrator",
}
```

---

## 5) Testing strategy (technical DoD)

## 5.1 Unit tests

1. `test_session_manager.py`
   - token extraction edge cases (missing token, malformed HTML)
   - login success/failure detection
   - invalid security level handling

2. `test_http_client.py`
   - timeout/redirect behavior
   - URL join correctness
   - exception mapping

3. `test_recon.py`
   - form parsing into normalized endpoint/vector objects
   - deduplication correctness
   - module-name inference coverage

4. Contract tests for `payload_library` / `verifier` (optional in Stage 2)
    - API surface and return-shape checks only
    - full behavioral tests scheduled for Stage 5

## 5.2 Integration tests

- Authenticated recon smoke test against DVWA fixture target.
- Validate returned dict keys match `ExploitationState` expectations.

```python
def test_recon_returns_state_compatible_update():
    state = {"target_url": "http://localhost/dvwa", "security_level": "low"}
    update = recon(state)

    assert "endpoints" in update
    assert "input_vectors" in update
    assert "security_level" in update
    assert update.get("next_agent") == "orchestrator"
```

## 5.3 Determinism requirements

- Sort emitted endpoints/vectors to avoid flaky tests.
- Avoid nondeterministic timestamps/random IDs in primary recon outputs.

---

## 6) Operational best practices

1. Add module-level docstrings and explicit type hints in all foundation modules.
2. Use structured logging (`logger.info/debug`) with correlation IDs when available.
3. Mask sensitive fields (`password`, cookies, tokens) in logs.
4. Keep parsing logic pure where possible for isolated testing.
5. Prefer explicit exceptions over broad `except Exception`.

---

## 7) Acceptance criteria (without time mapping)

Stage 2 is complete when all of the following are true:

1. `session_manager.py`, `http_client.py`, `recon.py` are fully implemented (not placeholders).
2. Recon consistently emits normalized `endpoints` and `input_vectors` compatible with `core/state.py`.
3. Security level can be set and detected reliably.
4. Payload library and verifier expose stable, documented interfaces suitable for Stage 5 implementation handoff.
5. Foundation tests pass locally and in CI.
6. Recon handoff to `orchestrator` is validated by integration tests.

---

## 8) Official documentation and best-practice references

1. **LangGraph** (state graphs, nodes, conditional routing):
   - https://langchain-ai.github.io/langgraph/

2. **HTTPX Client usage and advanced configuration**:
   - https://www.python-httpx.org/advanced/clients/
   - https://www.python-httpx.org/advanced/timeouts/
   - https://www.python-httpx.org/advanced/resource-limits/

3. **BeautifulSoup parsing patterns**:
   - https://www.crummy.com/software/BeautifulSoup/bs4/doc/

4. **Playwright Python (browser verification path)**:
   - https://playwright.dev/python/docs/intro

5. **pytest testing practices**:
   - https://docs.pytest.org/en/stable/

---

## 9) Notes on repository-specific alignment

- This plan intentionally follows `core/state.py` as canonical for state schema and reducers.
- It aligns with `AGENTS.md` requirement that agents return **partial state updates**.
- It removes any day/week sequencing and focuses only on technical implementation depth and quality gates.
