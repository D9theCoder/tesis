# Implementation Tasks (Concise)

Based on `summary.md` and `AGENTS.md`, this is the recommended build order for the framework.

| Stage | Time Period | Primary Deliverable |
|---|---|---|
| 1. Core state contract | Week 1 | Stable `ExploitationState` + folder boundaries |
| 2. Foundation layer | Week 2 | Session manager + recon + endpoint/input discovery + contract freeze (`payload_library`/`verifier`) |
| 3. Attack Knowledge Graph | Week 3 | NetworkX graph with chain preconditions |
| 4. Execution runtime | Weeks 4–5 | LangGraph workflow + conditional routing |
| 5. Vulnerability agents | Weeks 6–7 | Tier 1/2 agents + chain triggers + full payload/verifier behavior + browser verification |
| 6. Evaluation and testing | Week 8 | Scorer (0–4), multi-LLM runner, regression tests |
| 7. CLI and config interface | Week 9 | Thesis-grade CLI (`python -m tesis run`), config-driven execution, structured output artifacts |
| 7.1. Rich experiment reporting & diagnostics | Week 10 | Prompt/response trace capture, AKG traversal logs, rejection/success messaging, failure artifacts, and low-coverage diagnostics |
| 8. Adversarial prompt evasion | Week 11 | Single-turn and multi-turn prompt injection/jailbreak pipelines to prevent AI rejection during execution |

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

**Catatan:** contoh di atas adalah subset minimal. Kontrak kanonik tetap mengikuti `core/state.py`.

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

**Scope boundary:** Pada Stage 2, `payload_library` dan `verifier` dibatasi pada stabilisasi interface/kontrak; implementasi perilaku penuh dilakukan di Stage 5.

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

## Stage 7 — CLI interface and config-driven execution (Week 9)
**Goal:** Provide a reproducible, thesis-grade execution interface via a documented CLI that reads `config.yaml`, supports single runs and matrix runs, and produces structured output artifacts.

**Scope:** This stage does NOT modify the core runtime, agents, or evaluation logic. It is purely a user-facing layer over the already-implemented `evaluation/runner.py`, `evaluation/multi_llm_runner.py`, and `evaluation/reporter.py`.

### 7.1 Design Principles

1. **Config-first**: `config.yaml` is the source of truth; CLI flags override it.
2. **Progressive disclosure**: `--help` must be usable by a non-expert. `--verbose` must satisfy a power user.
3. **Deterministic by default**: Every run produces a stable artifact with a reproducible run ID.
4. **No breaking changes**: The underlying `evaluation/runner` and `build_framework` APIs remain unchanged.

### 7.2 Proposed Command Structure

```bash
# Single engagement (one provider × one level)
python -m tesis run \
    --target http://localhost/dvwa \
    --level low \
    --provider gemini \
    --iterations 30

# Matrix engagement (all providers × all levels × N repeats)
python -m tesis run \
    --target http://localhost/dvwa \
    --matrix \
    --providers gemini claude \
    --levels low medium high \
    --repeats 3 \
    --iterations 30 \
    --output-dir ./results

# Config-driven run (CLI flags override config.yaml values)
python -m tesis run --config ./custom-config.yaml \
    --provider claude \
    --level high

# Dry-run: validate config without connecting to target
python -m tesis run --dry-run \
    --config ./config.yaml

# Show framework info (supported providers, modules, schema version)
python -m tesis info

# Set model config (API key, model name, etc.) — stored in config.yaml or env
python -m tesis config \
    --provider gemini \
    --api-key YOUR_API_KEY \
    --model gemini-2.0-flash \
    --temperature 0

# Show rejection rate analysis from a previous run
python -m tesis report ./results/runs/gemini-low-0.json \
    --show-rejections

# Show full evaluation results from a matrix run
python -m tesis report ./results/reports/matrix_latest.json \
    --show-scores \
    --show-chains

# Set up API keys interactively
python -m tesis config --interactive
```

### 7.3 CLI Tasks

**File:** `tesis/cli.py` (new, registered via `pyproject.toml` entry point as `tesis`)

```
[project.scripts]
tesis = "tesis.cli:main"
```

Tasks:
- [ ] Implement `main()` with argparse + subcommands (`run`, `info`, `config`, `report`)
- [ ] Implement `run` subcommand with all flags (target, level, provider, iterations, matrix, providers, levels, repeats, output-dir, config, verbose, quiet, dry-run)
- [ ] Implement `info` subcommand (version, supported providers, MODULE_NAMES, schema version)
- [ ] Implement `config` subcommand (set/get API keys, model names, temperature, timeout per provider; interactive mode)
- [ ] Implement `report` subcommand (load JSON artifact, print formatted rejection rate table, print formatted evaluation scores, print formatted chain summary)
- [ ] Load and merge config from `config.yaml` with env-var overrides (e.g., `TESIS_TARGET_URL`)
- [ ] Validate all config values before invoking the framework (fail fast on bad target URL, unknown provider, etc.)
- [ ] Wire single-run mode to `evaluation.runner.run_single_engagement()`
- [ ] Wire matrix-run mode to `evaluation.multi_llm_runner.run_provider_matrix()`
- [ ] Use `evaluation.reporter.write_json_report()` to persist every run artifact
- [ ] Use `evaluation.reporter.write_markdown_report()` to generate summary per matrix run
- [ ] Add `--format` flag (json, markdown, both — default both)
- [ ] Add `--dry-run` mode that validates config without executing `app.invoke()`
- [ ] Add structured logging with `--verbose` (DEBUG level) and `--quiet` (WARNING level)
- [ ] Add proper exit codes: 0 = success, 1 = runtime error, 2 = config/validation error, 3 = target unreachable
- [ ] Register `tesis` entry point in `pyproject.toml`

### 7.4 Config Loading Tasks

**Files:** `tesis/config_loader.py` (new)

Tasks:
- [ ] Load `config.yaml` using PyYAML
- [ ] Override with environment variables prefixed `TESIS_` (e.g., `TESIS_TARGET_URL`, `TESIS_DVWA_USERNAME`)
- [ ] Override with CLI flags (CLI takes highest precedence)
- [ ] Validate: target URL is a valid HTTP/HTTPS URL, provider is in `SUPPORTED_PROVIDERS`, level is in `SECURITY_LEVELS`
- [ ] Support `--config` flag to load a custom config file path
- [ ] Produce a merged, validated `EngagementConfig` TypedDict or dataclass

### 7.5 Output & Artifact Tasks

**Files:** `tesis/cli.py`, `evaluation/reporter.py` (extend)

Tasks:
- [ ] Run artifacts written to `{output_dir}/runs/{run_id}.json`
- [ ] Markdown summary written to `{output_dir}/reports/{run_id}_summary.md`
- [ ] Matrix runs produce an aggregate report: `{output_dir}/reports/matrix_{timestamp}.md`
- [ ] Each artifact includes `schema_version: "stage6.v1"` for reproducibility tracking
- [ ] CLI prints a human-readable summary table to stdout on completion

### 7.6 Test Tasks

**File:** `tests/test_cli.py` (new)

Tasks:
- [ ] Test config loading: yaml → dict → dataclass round-trip
- [ ] Test env-var override of config values
- [ ] Test CLI flag override of config values (priority order)
- [ ] Test `--dry-run` produces valid artifact without invoking `app.invoke()`
- [ ] Test `run` subcommand calls `run_single_engagement()` with correct arguments
- [ ] Test `run --matrix` calls `run_provider_matrix()` with correct arguments
- [ ] Test `info` subcommand returns MODULE_NAMES, SUPPORTED_PROVIDERS, schema version
- [ ] Test exit codes (validation failure → 2, runtime error → 1, success → 0)

### 7.7 Report Subcommand — Rejection Rate Table

**File:** `tesis/report_formatters.py` (new)

The `report` subcommand loads a run artifact (JSON) and renders formatted analysis tables. This directly supports the empirical contribution in `summary.md`: measuring guardrail activation rate as a secondary metric for comparing LLM providers.

Tasks:
- [ ] Parse a single run artifact JSON file or a matrix aggregate JSON
- [ ] Extract `guardrail_activations` list per run; each entry is `{provider, context, snippet}`
- [ ] Compute total LLM calls per provider (approximate from `messages` count in state, or infer from orchestrator invocation count)
- [ ] Compute rejection rate per provider per task context (e.g., "orchestrator planning", "payload generation")
- [ ] Render a formatted ASCII table:

```
Provider    Task                    Guardrails    Total Calls    Rejection Rate
---------   ---------------------  -----------  -------------  ---------------
gemini      orchestrator            2            12             16.7%
gemini      payload_generation      1            8              12.5%
gemini      total                  3            20             15.0%
claude      orchestrator           0            10              0.0%
claude      payload_generation      0            9               0.0%
claude      total                  0            19              0.0%
```

- [ ] `--show-rejections` flag on `report` subcommand triggers this output
- [ ] Handle missing `guardrail_activations` gracefully (print "No guardrail data" instead of crashing)
- [ ] Support multi-run/matrix aggregation: sum across all runs for the same provider, show per-run breakdown if `--verbose`
- [ ] Output to stdout by default; `--output FILE` flag to write to file
- [ ] Add unit tests: mock artifacts with known activation counts, verify table output

### 7.8 Report Subcommand — Evaluation Scores Table

**File:** `tesis/report_formatters.py` (extend)

Tasks:
- [ ] Parse `module_scores` from run artifact JSON
- [ ] Render a per-module score table with 0–4 rubric labels:

```
Module       Score    Label              Chain
----------   -----    ----------------  ----------------------------------
sqli            4      Chain Exploit     sqli→creds→admin→upload→rce
sqli_blind      3      Full Exploit
xss_r           3      Full Exploit
xss_s           4      Chain Exploit     xss_stored→csrf
xss_d           0      Not Found
cmdi            4      Chain Exploit     cmdi→rce
brute           0      Not Found
lfi             4      Chain Exploit     lfi→log_poison→rce
upload          0      Not Found         (requires admin_session)
csrf            2      Partial Exploit
weak_session    3      Full Exploit
idor            0      Not Found
```

- [ ] Show score distribution summary: `Score Distribution: {0: 4, 1: 0, 2: 1, 3: 3, 4: 4}`
- [ ] Highlight Level 4 rows differently (e.g., bold or green) to emphasize chain exploits
- [ ] Show `highest_impact_outcome` and `longest_chain` from the summary section
- [ ] For matrix runs: render a cross-provider comparison table (providers as columns, modules as rows, cells show score + label)

```
          gemini         claude         gpt-4o
        -----------  ------------  ------------
sqli      4 Chain       3 Full       4 Chain
sqli_blind  2 Partial    3 Full       2 Partial
xss_r     3 Full        4 Chain      3 Full
...
```

- [ ] `--show-scores` flag triggers this output
- [ ] `--show-chains` flag adds the chain column (otherwise omitted for brevity)
- [ ] Support `--module FILTER` to show only specific modules
- [ ] Support `--level FILTER` to show only specific security levels
- [ ] Add unit tests: mock artifacts with varied scores, verify table layout and formatting

### 7.9 Config Subcommand — Model Configuration Settings

**File:** `tesis/config_loader.py` (extend), `tesis/model_config.py` (new)

This supports the empirical contribution in `summary.md`: comparing LLM providers under equivalent conditions. Each provider needs its own model name, API key, temperature, and optional provider-specific settings.

Tasks:
- [ ] Define `ModelConfig` dataclass:

```python
@dataclass
class ModelConfig:
    provider: str
    api_key: str               # loaded from env or explicit config
    model_name: str            # e.g., "gemini-2.0-flash-preview"
    temperature: float = 0.0
    max_tokens: int | None = None
    timeout: int = 60         # seconds per LLM call
    extra: dict[str, Any]     # provider-specific options (e.g., top_p, top_k for Gemini)
```

- [ ] Config file structure (extends `config.yaml`):

```yaml
models:
  gemini:
    api_key: "${GEMINI_API_KEY}"   # reference env var
    model_name: "gemini-2.0-flash-preview"
    temperature: 0.0
    timeout: 60
  claude:
    api_key: "${ANTHROPIC_API_KEY}"
    model_name: "claude-sonnet-4-20250514"
    temperature: 0.0
    timeout: 60
    extra:
      top_p: 0.9

default_model: gemini
```

- [ ] Load model configs from `config.yaml` under the `models:` key
- [ ] Resolve `${ENV_VAR}` references in config values using `os.environ`
- [ ] `config` subcommand flags:
  - `--list` — print all configured providers and their model names
  - `--set-provider PROVIDER --api-key KEY --model MODEL` — update config.yaml
  - `--set-temperature PROVIDER TEMPERATURE`
  - `--interactive` — prompt for API key without echoing it to terminal
  - `--show-keys` — print configured keys (masked: `sk-****1234`) for security audit
- [ ] Validate model names against known provider model registries (e.g., reject unknown Claude model strings)
- [ ] `llm/provider.py` must be updated to accept a full `ModelConfig` instead of just a provider name string
- [ ] Secrets (API keys) are never printed in logs or stdout (even with `--verbose`)
- [ ] Config is persisted to `config.yaml` on `--set-*` commands (never stored in code)
- [ ] Add unit tests: mock config with env var references, verify resolution; test masked key display; test invalid model name rejection

### 7.10 Aggregate Report — Matrix Cross-Provider Summary

**File:** `tesis/report_formatters.py` (extend), `evaluation/multi_llm_runner.py` (extend)

The matrix run produces an aggregate report that consolidates all per-run artifacts. This is the primary artifact for the empirical comparison in the thesis.

Tasks:
- [ ] Extend `evaluation/multi_llm_runner.run_provider_matrix()` to return an additional aggregate dict with:
  - Per-provider score totals (sum of scores across all modules × levels)
  - Per-provider chain exploit count
  - Per-provider guardrail activation rate
  - Per-provider highest impact outcome achieved
  - Score distribution per provider
  - `by_provider_level[provider][level]` for drill-down
- [ ] Write aggregate report to `{output_dir}/reports/matrix_{run_id}.json`
- [ ] Render matrix markdown report with:
  - Header: target, date, schema version
  - Provider comparison table (scores, chains, guardrails, iterations)
  - Per-module breakdown per provider (heatmap-style: show score per module × level)
  - Chain summary: list all chains achieved per provider
  - Rejection rate table (from 7.7)
  - Iteration usage: avg/total iterations per provider
- [ ] Example matrix markdown output:

```markdown
# Stage 6 Matrix Evaluation Report
**Target:** http://localhost/dvwa
**Date:** 2025-07-15T10:30:00Z
**Schema:** stage6.v1

## Provider Comparison

| Provider | Total Score | Chain Exploits | Guardrail Rate | Highest Outcome | Avg Iterations |
|----------|-------------|---------------|---------------|----------------|----------------|
| gemini   | 31/48       | 4             | 15.0%         | rce_achieved   | 18.3           |
| claude   | 38/48       | 5             | 0.0%          | rce_achieved   | 14.7           |

## Per-Module Scores (Low Security)

| Module   | gemini | claude | gpt-4o |
|----------|--------|--------|--------|
| sqli     | 4      | 4      | 4      |
| sqli_blind | 3   | 4      | 3      |
| xss_r    | 3      | 4      | 3      |
| ...      | ...    | ...    | ...    |

## Chain Exploits Achieved

**gemini:**
- sqli→creds→admin→upload→rce (Score 4)
- cmdi→rce (Score 4)

**claude:**
- sqli→creds→admin→upload→rce (Score 4)
- cmdi→rce (Score 4)
- xss_stored→csrf (Score 4)
- lfi→log_poison→rce (Score 4)
- brute→creds→admin (Score 4)

## Guardrail Activation Summary

[Table from 7.7]
```

- [ ] Print human-readable summary to stdout on matrix run completion (tabular, colored if terminal supports it)
- [ ] Add `--no-summary` flag to suppress stdout output during batch runs
- [ ] Add unit tests: mock matrix artifacts, verify aggregate computation and markdown rendering

### 7.11 Docs Tasks

Tasks:
- [ ] Add Stage 7 entry to `docs/summary.md` Coverage Matrix (new column: "CLI supported")
- [ ] Add Stage 7 to `AGENTS.md` Agent Development Checklist (new item: has CLI flag mapping)
- [ ] Add `docs/stage-7-cli-interface.implementation-plan.md` with full file content specifications
- [ ] Document `python -m tesis report` usage in `README.md` (with example output for rejection rate and score tables)
- [ ] Document model configuration (`python -m tesis config --interactive`) in `README.md` with environment variable setup
- [ ] Add `config.yaml` section to `README.md` explaining all supported fields under `models:`
- [ ] Update `summary.md` Section 3 (Rubrik Penilaian) to reference the CLI's `--show-scores` output for reproducibility

## Stage 8 — Adversarial prompt evasion (Week 11)
**Goal:** Implement prompt injection and multi-turn jailbreak algorithms to rewrite offensive prompts, preventing LLM safety filters from rejecting the framework's own execution tasks.

**Sample code:**
```python
from llm.evasion import PromptInjectionPipeline

# Wrap the standard prompt in an adversarial enhancement
pipeline = PromptInjectionPipeline(simulator=simulator_llm, max_retries=3)
safe_evasion_prompt = pipeline.run(base_seed=unsafe_task_intent)

# Submit rewritten payload to target LLM to bypass refusal
llm_response = target_llm.invoke(safe_evasion_prompt)
```

**Why this stage:** To maximize evaluation coverage and exploit success rates against heavily-aligned target models by dynamically rewriting internal requests to evade rejection.

**Docs:**
- `docs/jailbreak-algorithm.md`
- DeepTeam adversarial attacks
- `docs/stage-8-adversarial-prompt-evasion.implementation-plan.md`

## Stage 8.1 — Jailbreak Integration to Main Program (Week 11, days 4–5)
**Goal:** Wire the existing adversarial evasion layer through the full execution pipeline: CLI flags → config loader → engagement runner → LangGraph initial state → orchestrator → reports.

**What is missing today:**
- `tesis/cli.py` does not expose `--evasion-enabled` or `--evasion-strategy`.
- `tesis/model_config.py` / `EngagementConfig` has no evasion fields.
- `tesis/config_loader.py` ignores `evasion_enabled` / `evasion_strategy` from YAML, env vars, and CLI overrides.
- `evaluation/runner.py` and `evaluation/multi_llm_runner.py` never pass evasion settings into `init_state`.
- `core/scorer.py` and `evaluation/contracts.py` do not surface evasion metrics in score reports.
- `tesis/report_formatters.py` has no evasion statistics table.

**Files to modify:**
- `tesis/model_config.py` — add `evasion_enabled` and `evasion_strategy` to `EngagementConfig`.
- `tesis/config_loader.py` — parse evasion settings from YAML / `TESIS_EVASION_ENABLED` / CLI overrides; validate strategy.
- `tesis/cli.py` — add `--evasion-enabled`, `--evasion-strategy` to `run`; add `--show-evasion` to `report`; wire values to runners.
- `evaluation/runner.py` — accept `evasion_enabled` / `evasion_strategy`; inject into `init_state`; persist in artifact.
- `evaluation/multi_llm_runner.py` — propagate evasion settings to every single engagement; aggregate `evasion_attempts` / `successful_evasions` per provider.
- `evaluation/contracts.py` — extend `ScoreSummary` with `evasion_attempts`, `successful_evasions`, `evasion_strategy`.
- `core/scorer.py` — read evasion fields from final state and include them in `ScoreSummary`.
- `tesis/report_formatters.py` — implement `format_evasion_table()`; wire it to `--show-evasion`.

**Files to create:**
- `tests/test_evasion_integration.py` — config loading, runner state propagation, report formatting.

**Acceptance criteria:**
- [ ] `python -m tesis run --dry-run --evasion-enabled --evasion-strategy prompt_injection` resolves without error.
- [ ] `EngagementConfig` carries evasion settings with correct defaults (`False`, `"pipeline"`).
- [ ] Evasion settings reach `init_state` and flow back into run artifacts.
- [ ] Matrix aggregate includes per-provider evasion attempt/success counts and `evasion_success_rate`.
- [ ] `python -m tesis report <artifact> --show-evasion` renders an evasion statistics table.
- [ ] All existing tests continue to pass.

**Docs:**
- `docs/stage-8.1-jailbreak-integration.implementation-plan.md`

---

## Stage 9 — Refactor Agent Layer + Infrastructure Hardening (Week 12)
**Goal:** Fix the single critical blocker identified in the compliance audit (all 9 method agents are non-functional stubs) and harden core infrastructure gaps.

**Context:** The audit (`docs/audit-codebase-compliance-report.md`) evaluated the codebase against `AGENTS.md` and `docs/summary.md`. The core infrastructure (orchestrator, state, AKG, graph builder, chaining, CLI, evasion) is solid. The **only critical blocker** is that all 9 method agents log payloads locally but never send real HTTP requests to DVWA. Additionally, several infrastructure gaps were identified.

**Stage 9 is split into two parallel workstreams:**

### Stage 9A — Real Method Agent Execution
**Goal:** Rewrite all 9 method agents with real PROBE → EXPLOIT → CHAIN CHECK pipelines using `DVWASession`.

**Critical violations to fix:**
- No HTTP requests (zero imports of `httpx`, `DVWASession`, or `http_client`)
- Fake PROBE stage (`observations[key] = True` set unconditionally)
- Fake EXPLOIT stage (`exploit_triggered = True` after local iteration; score 3 granted if `security_level == "low"`)
- Wrong AKG confirmed node IDs (e.g., `sqli_union_confirmed` instead of `sqli_confirmed`)
- Fake CHAIN CHECK (no AKG query; hardcoded outcome if `score >= 3`)
- No `BaseAgent` inheritance
- Fake `found_credentials` (splits payload string on `:` instead of parsing DVWA response)

**Files to modify:**
- `agents/sqli/sqli_union_agent.py`
- `agents/sqli/sqli_error_agent.py`
- `agents/sqli/sqli_boolean_blind_agent.py`
- `agents/sqli/sqli_time_blind_agent.py`
- `agents/access_control/ac_idor_agent.py`
- `agents/access_control/ac_vertical_escalation_agent.py`
- `agents/access_control/ac_force_browse_agent.py`
- `agents/brute_force/bf_dictionary_agent.py`
- `agents/brute_force/bf_spray_agent.py`
- `agents/state_utils.py` — add method-agent endpoint mappings
- `foundation/payload_library.py` — refine payloads for DVWA realism

**Files to create:**
- `tests/test_sqli_union_agent.py`
- `tests/test_sqli_error_agent.py`
- `tests/test_sqli_boolean_blind_agent.py`
- `tests/test_sqli_time_blind_agent.py`
- `tests/test_ac_idor_agent.py`
- `tests/test_ac_vertical_escalation_agent.py`
- `tests/test_ac_force_browse_agent.py`
- `tests/test_bf_dictionary_agent.py`
- `tests/test_bf_spray_agent.py`

**Implementation plan:** `docs/stage-9a-real-method-agents.implementation-plan.md`

### Stage 9B — Core Infrastructure Hardening
**Goal:** Fix AKG intermediate chain nodes, convert `GuardrailMonitor` to a class, remove legacy prompt stubs, align scorer output with spec, and tighten chain precondition checks.

**Files to modify:**
- `core/knowledge_graph.py` — add `unauthenticated`, `authenticated_session`, `admin_session_obtained` edges
- `core/chaining_coordinator.py` — check preconditions against `confirmed_vulns` only
- `core/scorer.py` — return nested `surface_scores` + `summary` per spec
- `llm/guardrail_monitor.py` — convert to `GuardrailMonitor` class
- `llm/prompts/__init__.py` — remove legacy stub exports
- `llm/prompts/sqli_prompt.py` — delete legacy stub
- `llm/prompts/idor_prompt.py` — delete legacy stub
- `llm/prompts/brute_prompt.py` — delete legacy stub
- `llm/prompts/sqli_blind_prompt.py` — delete legacy stub

**Files to create:**
- `tests/test_guardrail_monitor_class.py`
- `tests/test_scorer_output_shape.py`

**Implementation plan:** `docs/stage-9b-infrastructure-hardening.implementation-plan.md`

### Stage 9 Acceptance Criteria (combined)
- [ ] All 9 agents send real HTTP requests via `DVWASession`.
- [ ] All 9 agents parse HTTP responses for preconditions and exploitation evidence.
- [ ] All 9 agents append correct surface-level confirmed nodes.
- [ ] All 9 agents query `AttackKnowledgeGraph.get_next_actions()` during CHAIN CHECK.
- [ ] AKG contains `unauthenticated`, `authenticated_session`, `admin_session_obtained` with correct edges.
- [ ] `GuardrailMonitor` class exists with `check()`, `get_rate()`, `summary()`.
- [ ] Legacy prompt stubs deleted and no longer exported.
- [ ] `scorer()` returns nested `surface_scores` + `summary` per spec.
- [ ] Chain preconditions checked against `confirmed_vulns` only.
- [ ] All new and existing tests pass.

**Suggested branch names:**
- `feat/stage9a-real-method-agents`
- `feat/stage9b-infrastructure-hardening`
