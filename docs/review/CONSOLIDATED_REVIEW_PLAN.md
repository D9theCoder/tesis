# Consolidated Review Plan — Unfixed Issues (Post-Stage-9D)

**Generated:** 2026-05-02  
**Source reviews:** `CORE_LAYER_REVIEW.md`, `review_agent_layer.md`, `foundation_layer_review.md`  
**Canonical reference:** `docs/summary.md`  
**Purpose:** Central registry of all open findings. Each item is cross-checked against `summary.md` for architectural drift.

---

## Legend

| Tag | Meaning |
|-----|---------|
| **DRIFT** | Current code violates the canonical architecture documented in `docs/summary.md` |
| **NODRIFT** | Current code aligns with `docs/summary.md`; the finding is internal quality debt only |
| **DOCGAP** | `docs/summary.md` is silent or ambiguous on the topic; no drift can be asserted |

---

## Part A — Critical & High Severity (Must Fix Before Thesis Submission)

### A1. Evasion Pipeline Is a Functional No-Op
- **Source:** `review_agent_layer.md` (CRITICAL)
- **File:** `agents/orchestrator.py:107-122`
- **Issue:** `_run_evasion_pipeline` performs naive `str.replace` on phrases like `"exploit the vulnerability"` that **do not appear** in the actual prompt built by `llm/prompts/orchestrator_prompt.py`. Both proactive and reactive modes do nothing.
- **Drift from `summary.md`:** **DRIFT**. Section 7.1 documents a "semantic paraphrase" pipeline with "retry + paraphrase + validity gate." The current implementation is not semantic paraphrase — it is dead string replacement.
- **Fix direction:** Replace the tiered `str.replace` map with a real paraphrase layer (e.g., prompt restructuring that swaps role framing from "penetration tester" to "security auditor") or remove the feature and document it as not yet implemented.

### A2. SQLi Boolean Blind — Score 3 Awarded for a Single Bit
- **Source:** `review_agent_layer.md` (HIGH)
- **File:** `agents/sqli/sqli_boolean_blind_agent.py:106`
- **Issue:** The first `_TRUTHY_SIGNAL` match awards `score = 3`. A single boolean condition proves injection but does not constitute "full exploitation."
- **Drift from `summary.md`:** **DRIFT**. Rubrik Section 3 defines Score 3 as "Full Exploit — full exploitation via selected method" with the example "Seluruh tabel `users` ter-dump via `sqli_time_blind`." A single bit does not meet this threshold.
- **Fix direction:** Reserve score 3 for a multi-character extraction sequence (e.g., at least 3 confirmed bits reconstructing part of the database name). Score 2 for the first confirmed boolean condition.

### A3. SQLi Time Blind — Score 3 Awarded for a Single Delay
- **Source:** `review_agent_layer.md` (HIGH)
- **File:** `agents/sqli/sqli_time_blind_agent.py:119`
- **Issue:** The first measurable delay awards `score = 3`. A single `SLEEP(3)` proves time-based injection but is not "full exploitation."
- **Drift from `summary.md`:** **DRIFT**. Same rubrik as A2. The sample code in Section 6.2 only awards score 3 after `binary_search_extract` returns a `db_name`.
- **Fix direction:** Reserve score 3 for a binary-search extraction that reconstructs at least part of a secret. Score 2 for first confirmed delay.

### A4. SQLi Error — Exploit Signals Match Normal Page Content
- **Source:** `review_agent_layer.md` (HIGH)
- **File:** `agents/sqli/sqli_error_agent.py:30-35`
- **Issue:** `_EXPLOIT_SIGNALS` includes `admin:`, `gordonb:`, `pablo:`, `smithy:`. The normal DVWA response for `id=1` already contains `First name: admin` and `Surname: admin`. A payload that fails silently but returns the default page will falsely trigger score 3.
- **Drift from `summary.md`:** **DRIFT**. Rubrik Score 3 requires extracted data. The sample code in Section 6.2 requires `extractvalue()` output with `~dvwa~` or credential-hash patterns for score 3.
- **Fix direction:** Replace generic content signals with extraction-specific patterns: `~dvwa~`, `xpath error:`, `extractvalue`, `concat(`, or colon-delimited `username:hash` strings that do not appear in the benign response.

### A5. `get_viable_chains` vs `chaining_coordinator` Precondition Split
- **Source:** `CORE_LAYER_REVIEW.md` (HIGH)
- **Files:** `core/knowledge_graph.py:290` / `core/chaining_coordinator.py:76`
- **Issue:** `get_viable_chains` includes `achieved_outcomes` in `known_nodes`; `chaining_coordinator` uses `confirmed_vulns` only. This creates a runtime-vs-reporting mismatch.
- **Drift from `summary.md`:** **DRIFT**. Pseudocode Section 5.5 checks chain preconditions against `state.confirmed_vulns` only: `all(p IN state.confirmed_vulns FOR p IN edge.preconditions)`. The `get_viable_chains` function deviates from this contract.
- **Fix direction:** Align `get_viable_chains` with the pseudocode — exclude `achieved_outcomes` from chain precondition checks, or document and justify the divergence in a module-level docstring.

### A6. Multi-Step Chain Edges Are Dead Code
- **Source:** `CORE_LAYER_REVIEW.md` (MEDIUM, but architecturally significant)
- **File:** `core/knowledge_graph.py:138-174`
- **Issue:** Each cross-surface chain has two edges (e.g., `brute_force_confirmed → authenticated_session` and `authenticated_session → ac_idor`). Only the first edge is ever traversed because intermediates are appended to `achieved_outcomes`, not `confirmed_vulns`.
- **Drift from `summary.md`:** **DRIFT**. The Mermaid diagram in Section 2 shows chains as direct: `[brute_force_confirmed] ──► [ac_idor]`. The intermediate edges do not exist in the documented architecture.
- **Fix direction:** Collapse each chain to a single edge or append intermediate nodes to `confirmed_vulns` during `chain_check` so the second edge becomes traversable.

### A7. Login Success Detection Is Ambiguous
- **Source:** `foundation_layer_review.md` (HIGH)
- **File:** `foundation/session_manager.py:96-122`
- **Issue:** Success is inferred from `"index.php" in current_url` without checking for `"username and/or password incorrect"` in the body. A failed login can still redirect to `index.php` on some configurations.
- **Drift from `summary.md`:** **DOCGAP**. `summary.md` does not specify login detection logic in detail. However, pseudocode Section 5.1 assumes `session.login()` returns a reliable boolean.
- **Fix direction:** Add a negative check: if `"username and/or password incorrect"` is in the body, force `False`. Verify `"logout"` appears as an `<a>` tag, not just bare text.

---

## Part B — Medium Severity (Should Fix Before Final Evaluation)

### B1. `ac_vertical_escalation` Payloads Are Semantically Wrong
- **Source:** `foundation_layer_review.md` (HIGH downgraded to MEDIUM after payload_library fix)
- **File:** `foundation/payload_library.py:67-73`
- **Issue:** Probe/exploit payloads are `{"1", "2"}` — just numeric user IDs. Vertical escalation should test accessing admin-privileged resources, but the payload library treats sequential IDs as bypass attempts.
- **Drift from `summary.md`:** **DRIFT**. Section 7 documents the precondition as `role_based_access_present`. The payloads do not test role-based access; they test ID enumeration (which is the IDOR agent's job).
- **Fix direction:** Define payloads that test role escalation semantics (e.g., passing `role=admin` or `is_admin=1` to the authbypass endpoint). Document that DVWA authbypass conflates IDOR and role escalation.

### B2. Brute Force / Force-Browse Bypass Payloads Are Identical Across Levels
- **Source:** `foundation_layer_review.md` (MEDIUM)
- **Files:** `foundation/payload_library.py:83-103`
- **Issue:** `bf_dictionary`, `bf_spray`, and `ac_force_browse` have `bypass["medium"]` and `bypass["high"]` identical to low-level payloads.
- **Drift from `summary.md`:** **DRIFT**. Section 7 Security Level Adaptations table states High Brute Force has "CAPTCHA present — document as scope boundary." The payload library should encode this boundary (empty bypass list for high) instead of reusing low payloads.
- **Fix direction:** Set `bypass["high"] = []` for brute-force agents and add a comment documenting the CAPTCHA scope boundary. For `ac_force_browse`, document that high-level authentication may block setup.php access.

### B3. SQLi High Bypass Uses `/**/` (Irrelevant to DVWA High)
- **Source:** `foundation_layer_review.md` (MEDIUM)
- **Files:** `foundation/payload_library.py:56,63`
- **Issue:** `sqli_time_blind` and `sqli_boolean_blind` high bypasses use `/**/` comment-space tricks. DVWA High uses prepared statements + `LIMIT 1` + CSRF token — not space-based WAF filtering.
- **Drift from `summary.md`:** **DRIFT**. Section 7 Security Level Adaptations table states High SQLi = "Token-based, LIMIT clause." The `/**/` trick addresses a WAF defense that does not exist in DVWA.
- **Fix direction:** Replace with token-aware placeholders (e.g., append `user_token` parameter) or remove high bypasses and document that agents must inject CSRF tokens themselves.

### B4. SQLi Error Probe Includes Ineffective Payload
- **Source:** `foundation_layer_review.md` (MEDIUM)
- **File:** `foundation/payload_library.py:41`
- **Issue:** Probe `"1"` (double-quote) inside a single-quoted MySQL string does not cause a syntax error on DVWA Low.
- **Drift from `summary.md`:** **DOCGAP**. `summary.md` does not enumerate exact probe payloads.
- **Fix direction:** Replace `"1"` with `"1\\'"` (escaped single quote to test filtering) or `"1' OR '1'='1"`.

### B5. SQLi Agents Do Not Populate `found_credentials`
- **Source:** `review_agent_layer.md` (MEDIUM)
- **Files:** All 4 SQLi agents
- **Issue:** When SQLi agents extract credentials (e.g., `concat(user,0x3a,password)`), they append `credentials_extracted` to `achieved_outcomes` but do not populate `found_credentials`.
- **Drift from `summary.md`:** **DRIFT**. State schema in Section 5.1 includes `found_credentials: list[dict]`. The sample code in Section 6.2 (time-blind) and Section 6.4 (brute force) both populate `found_credentials`.
- **Fix direction:** Parse extracted credential strings in SQLi agents and append `{"username": u, "password": p}` to `found_credentials`.

### B6. `sqli_time_blind` Time Threshold Is Fragile
- **Source:** `review_agent_layer.md` (MEDIUM)
- **File:** `agents/sqli/sqli_time_blind_agent.py:29`
- **Issue:** `TIME_THRESHOLD = 2.5` absolute. If baseline takes >0.5s, `elapsed - baseline` may be <2.5s even with `SLEEP(3)`.
- **Drift from `summary.md`:** **DOCGAP**. `summary.md` does not specify threshold logic.
- **Fix direction:** Use relative threshold (`elapsed > baseline * 3`) or increase absolute threshold to 4s.

### B7. `module_endpoint` Hard-Coded Fragment Mapping
- **Source:** `review_agent_layer.md` (MEDIUM)
- **File:** `agents/state_utils.py:44-70`
- **Issue:** The 10-entry `_MODULE_ENDPOINT_FRAGMENTS` map must be kept in sync with `core/state.py` and `foundation/payload_library.py`.
- **Drift from `summary.md`:** **NODRIFT**. `summary.md` does not prescribe how endpoint resolution works.
- **Fix direction:** Derive mapping from a single source of truth (e.g., a dataclass in `core/state.py`).

### B8. `prepare_agent_session` Catches `TypeError`
- **Source:** `review_agent_layer.md` (MEDIUM)
- **File:** `agents/state_utils.py:88`
- **Issue:** `TypeError` from `login()` usually signals a programming error (wrong arity), not a transient network issue.
- **Drift from `summary.md`:** **NODRIFT**.
- **Fix direction:** Remove `TypeError` from the except tuple.

### B9. `ac_idor` Baseline Failure Handling
- **Source:** `review_agent_layer.md` (MEDIUM)
- **File:** `agents/access_control/ac_idor_agent.py:52-56`
- **Issue:** If `userId=1` baseline fails, the agent sets `baseline_text=""` and still probes, but the comparison logic is complex and may miss IDOR signals.
- **Drift from `summary.md`:** **NODRIFT**. Pseudocode Section 5.4 does not specify baseline failure behavior.
- **Fix direction:** If baseline fails, compare probe responses against each other instead of against a missing baseline.

### B10. `ac_vertical_escalation` Signals Overlap Heavily
- **Source:** `review_agent_layer.md` (MEDIUM)
- **File:** `agents/access_control/ac_vertical_escalation_agent.py`
- **Issue:** `_ADMIN_SIGNALS` and `_EXPLOIT_SIGNALS` share 4 of 6 entries, making probe/exploit distinction meaningless.
- **Drift from `summary.md`:** **NODRIFT**.
- **Fix direction:** For vertical escalation, exploit should confirm strictly higher privilege than current session user.

### B11. `detect_security_level` Relies on BS4 Boolean Parsing
- **Source:** `foundation_layer_review.md` (MEDIUM)
- **File:** `foundation/session_manager.py:160`
- **Issue:** `select.find("option", selected=True)` assumes BS4 interprets `selected="selected"` correctly.
- **Drift from `summary.md`:** **NODRIFT**.
- **Fix direction:** Use `option.get("selected") is not None`.

### B12. Security Cookie Set with Empty Domain
- **Source:** `foundation_layer_review.md` (MEDIUM)
- **File:** `foundation/session_manager.py:210`
- **Issue:** `_apply_security_level_cookie` uses empty domain. Non-localhost targets may not persist the cookie.
- **Drift from `summary.md`:** **NODRIFT**.
- **Fix direction:** Parse domain from `base_url` and pass it to `set_cookie`.

### B13. `_submit_security_form` Swallows All Exceptions
- **Source:** `foundation_layer_review.md` (MEDIUM)
- **File:** `foundation/session_manager.py:181-198`
- **Issue:** If POST to `security.php` fails, exception is caught and logged. Caller has no way to know the form submission failed.
- **Drift from `summary.md`:** **NODRIFT**.
- **Fix direction:** Return boolean from `_submit_security_form` and raise/log error if False.

### B14. `get_next_actions` Redundant Re-Normalization
- **Source:** `CORE_LAYER_REVIEW.md` (MEDIUM)
- **File:** `core/knowledge_graph.py:232-258`
- **Issue:** Edge metadata was already normalized in `_build_graph`. Re-wrapping into `RawTransition` and calling `_normalize_transition` again is unnecessary.
- **Drift from `summary.md`:** **NODRIFT**.
- **Fix direction:** Return stored metadata directly, or extract a lightweight formatter.

### B15. `get_viable_chains` Returns Non-Chain Paths
- **Source:** `CORE_LAYER_REVIEW.md` (MEDIUM)
- **File:** `core/knowledge_graph.py`
- **Issue:** `nx.all_simple_paths` traverses all edges. A path could include discovery edges mixed with chain edges.
- **Drift from `summary.md`:** **NODRIFT**.
- **Fix direction:** Filter paths to require at least one chain edge.

---

## Part C — Low Severity (Polish & Debt)

### C1. `NotRequired` Fields Always Present in `DEFAULT_STATE`
- **Source:** `CORE_LAYER_REVIEW.md` (MEDIUM, but low impact)
- **File:** `core/state.py:79-113`
- **Issue:** `evasion_enabled`, `evasion_max_retries` are `NotRequired` but populated in default template.
- **Drift from `summary.md`:** **NODRIFT**.
- **Fix direction:** Remove `NotRequired` if always expected, or remove from `DEFAULT_STATE`.

### C2. Unused Accumulation Fields
- **Source:** `CORE_LAYER_REVIEW.md` (LOW)
- **File:** `core/state.py:48-49,71-72`
- **Issue:** `blocked_patterns`, `successful_bypasses` declared with `add` reducers but never referenced.
- **Drift from `summary.md`:** **NODRIFT**. `summary.md` Section 5.1 includes them in the initial state template.
- **Fix direction:** Either use them in evasion telemetry or remove from schema.

### C3. `KG_NODES` Includes Legacy Nodes
- **Source:** `CORE_LAYER_REVIEW.md` (LOW)
- **File:** `core/state.py:154-181`
- **Issue:** `xss_reflected_confirmed`, `lfi_confirmed`, etc. listed for backward compatibility but not in AKG.
- **Drift from `summary.md`:** **DRIFT**. Section 7 scope table explicitly excludes XSS, LFI, etc. as out of scope.
- **Fix direction:** Remove legacy nodes from `KG_NODES` or add a comment block separating active vs legacy.

### C4. Lazy Import in `_validate_agent_kg_node_mappings`
- **Source:** `CORE_LAYER_REVIEW.md` (LOW)
- **File:** `core/knowledge_graph.py:214`
- **Issue:** Imports `MODULE_TO_KG_NODE` and `ALL_METHOD_AGENTS` inside the method despite top-level imports.
- **Drift from `summary.md`:** **NODRIFT**.
- **Fix direction:** Move imports to top of file.

### C5. Overlapping Sanitize/Evasion Layers
- **Source:** `review_agent_layer.md` (LOW)
- **File:** `agents/orchestrator.py`
- **Issue:** `_sanitize_prompt_seed` and `_run_evasion_pipeline` both replace `exploit`/`attack`.
- **Drift from `summary.md`:** **NODRIFT**.
- **Fix direction:** Consolidate into one sanitization layer.

### C6. Orchestrator Short-Circuit Comment Is a No-Op
- **Source:** `review_agent_layer.md` (LOW)
- **File:** `agents/orchestrator.py:166`
- **Issue:** Comment promises reactive short-circuit but code is `pass`.
- **Drift from `summary.md`:** **NODRIFT**.
- **Fix direction:** Remove misleading comment or implement keyword pre-check.

### C7. Recon Does Not Check Login Before Observations
- **Source:** `foundation_layer_review.md` (LOW)
- **File:** `foundation/recon.py`
- **Issue:** Crawl continues even if `login_success=False`. Observations derived from unauthenticated crawl may differ from authenticated state.
- **Drift from `summary.md`:** **NODRIFT**.
- **Fix direction:** If login fails, either abort recon or set `authenticated_crawl=False` observation.

### C8. `verify_xss_dialog` Resource Leak
- **Source:** `foundation_layer_review.md` (LOW)
- **File:** `foundation/verifier.py:94-117`
- **Issue:** `page` not explicitly closed before `context.close()`.
- **Drift from `summary.md`:** **NODRIFT**.
- **Fix direction:** Use nested context managers.

### C9. `contains_any` Confidence Formula Arbitrary
- **Source:** `foundation_layer_review.md` (LOW)
- **File:** `foundation/verifier.py:44-55`
- **Issue:** `confidence = min(1.0, 0.5 + 0.15 * len(matches))` has no statistical basis.
- **Drift from `summary.md`:** **NODRIFT**.
- **Fix direction:** Use binary confidence or calibrate against labeled data.

### C10. `verify_method_response` Disconnected from `Verifier` Class
- **Source:** `foundation_layer_review.md` (LOW)
- **File:** `foundation/verifier.py:139`
- **Issue:** Bare function outside `Verifier` class. Agents inconsistently use either.
- **Drift from `summary.md`:** **NODRIFT**.
- **Fix direction:** Deprecate or make `@staticmethod` on `Verifier`.

### C11. HTTP Client — SSL Disabled by Default
- **Source:** `foundation_layer_review.md` (LOW)
- **File:** `foundation/http_client.py:48`
- **Issue:** `verify_ssl` defaults to `False` via `DVWA_VERIFY_SSL` env var.
- **Drift from `summary.md`:** **NODRIFT**.
- **Fix direction:** Default to `True`; only disable when explicitly requested.

### C12. HTTP Client — No Error Status Code Handling
- **Source:** `foundation_layer_review.md` (LOW)
- **File:** `foundation/http_client.py:95-106`
- **Issue:** 403/500 returned verbatim without domain exception.
- **Drift from `summary.md`:** **NODRIFT**.
- **Fix direction:** Map common status codes to domain exceptions.

### C13. HTTP Client — `urljoin` Can Escape Base URL
- **Source:** `foundation_layer_review.md` (LOW)
- **File:** `foundation/http_client.py:78,88`
- **Issue:** `path="../security.php"` resolves outside `base_url`.
- **Drift from `summary.md`:** **NODRIFT**.
- **Fix direction:** Validate resolved URL still starts with `self.base_url`.

### C14. `MODULE_TO_KG_NODE` Inconsistency for `ac_vertical_escalation`
- **Source:** `CORE_LAYER_REVIEW.md` (MEDIUM, but architecturally trivial)
- **File:** `core/state.py:147-148`
- **Issue:** Maps to `ac_vertical_escalation_confirmed` (method-specific) while others map to surface-confirmed.
- **Drift from `summary.md`:** **NODRIFT** — actually **CORRECT PER SPEC**. Section 7 explicitly documents `ac_vertical_escalation_confirmed` as the chain output for this agent. The review finding was based on an assumption of uniform surface-level mapping, but `summary.md` overrides this.
- **Resolution:** **DISMISS**. No fix needed. Add a code comment referencing `summary.md` Section 7 to prevent future confusion.

---

## Priority Matrix

| Priority | ID | Issue | Drift? | Effort | Files |
|----------|----|-------|--------|--------|-------|
| P0 | A1 | Evasion pipeline no-op | **DRIFT** | 1-2h | `agents/orchestrator.py`, `llm/prompts/orchestrator_prompt.py` |
| P0 | A2 | Boolean blind score inflation | **DRIFT** | 30m | `agents/sqli/sqli_boolean_blind_agent.py` |
| P0 | A3 | Time blind score inflation | **DRIFT** | 30m | `agents/sqli/sqli_time_blind_agent.py` |
| P0 | A4 | SQLi error weak signals | **DRIFT** | 30m | `agents/sqli/sqli_error_agent.py` |
| P0 | A5 | `get_viable_chains` / coordinator split | **DRIFT** | 1h | `core/knowledge_graph.py`, `core/chaining_coordinator.py` |
| P0 | A6 | Dead multi-step chain edges | **DRIFT** | 1h | `core/knowledge_graph.py`, `agents/state_utils.py` |
| P1 | A7 | Login detection ambiguous | DOCGAP | 1h | `foundation/session_manager.py` |
| P1 | B1 | Vertical escalation payloads wrong | **DRIFT** | 1h | `foundation/payload_library.py`, `agents/access_control/ac_vertical_escalation_agent.py` |
| P1 | B2 | BF/FB bypass identical across levels | **DRIFT** | 30m | `foundation/payload_library.py` |
| P1 | B3 | SQLi high bypass uses `/**/` | **DRIFT** | 30m | `foundation/payload_library.py` |
| P1 | B4 | SQLi error probe ineffective | DOCGAP | 15m | `foundation/payload_library.py` |
| P1 | B5 | SQLi agents missing `found_credentials` | **DRIFT** | 1h | All 4 SQLi agents |
| P2 | B6-B15 | Medium issues (see list above) | Mixed | 15m-1h each | Various |
| P3 | C1-C14 | Low / polish / debt | Mixed | 5-30m each | Various |

---

## Drift Summary

Out of **27 open issues**, the drift analysis yields:

| Category | Count |
|----------|-------|
| **DRIFT** (code violates `summary.md`) | 10 |
| **NODRIFT** (code aligns with `summary.md`) | 7 |
| **DOCGAP** (`summary.md` silent/ambiguous) | 6 |
| **DISMISSED** (finding contradicted by `summary.md`) | 1 |
| **Pending classification** | 3 |

**Key drift areas:**
1. **Scoring rubric** — 3 SQLi agents award Score 3 for minimal signals that `summary.md` defines as Score 2 (partial).
2. **Evasion pipeline** — `summary.md` documents semantic paraphrase; code implements dead string replacement.
3. **AKG chain structure** — `summary.md` shows direct chain edges; code has unreachable intermediate edges.
4. **Security-level adaptations** — `summary.md` documents CAPTCHA (high brute force) and token-based (high SQLi); payload library ignores both.
5. **`found_credentials` tracking** — `summary.md` state schema expects it; SQLi agents don't populate it.

**Recommended thesis narrative:** The drift items above represent the gap between the *designed* architecture (documented in `summary.md`) and the *implemented* architecture. Fixing them before final evaluation ensures that the empirical results (method selection accuracy, adaptation rate, mean attempts-to-success) are computed against a framework that faithfully implements its own specification.
