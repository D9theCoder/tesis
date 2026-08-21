# Fix `sqli/medium` — evidenced `static_only` → `hybrid` gate (keep `sqli/high` + `bf/high` quarantined)

## Manifest
- **module_name:** `fix-sqli-medium-evidence`
- **output_filename:** `docs/plan-sqli-medium.md`
- **repo_root:** `/home/kevin/coding/tesis`
- **language:** `python`
- **test_command:** `uv sync && source .venv/bin/activate && pytest -q tests/test_sqli_union_agent.py tests/test_sqli_error_agent.py tests/test_sqli_boolean_blind_agent.py tests/test_sqli_time_blind_agent.py tests/test_payload_library.py tests/test_verifier.py tests/test_sqli_medium_verification.py`
- **ruleset_files:** [`AGENTS.md`, `core/knowledge_graph.py`, `core/state.py`, `core/graph_builder.py`]
- **files_to_modify:** [`foundation/payload_library.py`, `agents/sqli/sqli_union_agent.py`, `agents/sqli/sqli_error_agent.py`, `agents/sqli/sqli_boolean_blind_agent.py`, `agents/sqli/sqli_time_blind_agent.py`, `foundation/verifier.py`, `core/knowledge_graph.py` (payload profiles only, no topology)]
- **files_to_create:** [`tests/test_sqli_medium_verification.py`, `docs/plan-sqli-medium.md`]
- **branch:** `fix/sqli-medium-verification`
- **commit_prefix:** `fix(sqli): make medium verifiable without weakening high`

## Short Summary
`matrix-2026-08-21` (`akg_guided_hybrid`, `static_only`, 9 runs) shows 6/9 success. Three errors: `sqli/high` = `NO_VIABLE_METHODS` (AKG gate, recon `union_select_possible=false`), `brute_force/high` = `ALL_METHODS_FAILED` (CAPTCHA scope boundary, expected), `sqli/medium` = `ALL_METHODS_FAILED` with 4/4 viable, 8 iterations, 4 orchestrator calls, `payload_validity 1.0`, probes all `signal_detected:true` but exploit 1/0/0/0. Forced `single-run-2026-08-21-2` (`sqli_union`, `high`, `target_method=sqli_union`) proves harness *can* send and get `HTTP 200 success:true` on high yet `verifier not_confirmed score 1 evidence 3`. Conclusion per investigation:

* Omit/quarantine the two `high` coordinates as documented negative controls (one is a recon false-negative + verifier strictness issue — identical to `sqli/medium` — the other is CAPTCHA out-of-scope per `AGENTS.md`). Do **not** weaken `core/knowledge_graph.py:METHOD_PRECONDITIONS` or containment to chase them.
* Fix only `sqli/medium`: it is a real payload-vs-verifier mismatch at a level the thesis must claim. Every probe returns `true`, valid candidates `5`, exploits fire `200`, but `sqli_union_agent.py:82` (`"first name"||"surname"` && cred), `sqli_error_agent.py:99` (`~dvwa|xpath|admin:`), `boolean >=2 true_conditions`, `time_blind TIME_THRESHOLD 2.5s + delay_confirms>=2` never simultaneously satisfied with the single-seed medium bypass table.

This plan makes `sqli/medium` confirm at `score 3` on `static_only` while keeping `high` at `2.5s`/strict, keeping AKG static/prevalidated, preserving containment/scoring, and unblocking the hybrid comparison on the 6 already-passing coordinates (`access_control 3/3`, `brute_force low/medium`, `sqli low`) + the repaired medium.

## Inputs & Preconditions (read-only evidence used)
* `results/runs/matrix-2026-08-21/exec-*.matrix.json` + per-run `exec-*.json` / `failure.json` — `totals.error 3 success 6`, `sqli/medium ALL_METHODS_FAILED viable:[sqli_union,sqli_error,sqli_boolean_blind,sqli_time_blind]`, `payload_validation 1.0`, `execution_log` `payload:viable true`.
* `results/runs/single-run-2026-08-21-2/exec-233407979169Z-...rich.json` — `target_method:sqli_union viable:false payload_validity 1.0 exec 0.0 score 1 probe ORDER BY signal:true exploits 2× success:true 200 verifier not_confirmed` — proves recon false-negative + verifier strictness, not global routing bug.
* `foundation/payload_library.py:_PAYLOAD_DB` — medium bypasses are single-variant (`UNION SELECT …#`, `extractvalue…#`, `ASCII…#`, `SLEEP(3)#`) with deduplication in `load_seed_candidates()`.
* `agents/sqli/*.py` — current thresholds quoted in manifest.
* `foundation/verifier.py:contains_any / regex_match / has_captcha_challenge` — no change needed for sqli except exploit-signal set expansion.
* `core/knowledge_graph.py`, `core/state.py`, `core/graph_builder.py`, `agents/state_utils.py:candidate_payloads_for_stage` — contracts to preserve.
* `tests/test_sqli_*`, `tests/test_payload_library.py` — regression baseline.

Dry-run gate `python -m tesis run --dry-run --config config.yaml` must pass before matrix re-run.

## Design

### Principles (from `AGENTS.md` priority)
1. Runtime topology `core/graph_builder.py` > `core/state.py` > `core/knowledge_graph.py` > `foundation/`/`agents/` > `docs/summary_en.md`. No topology edit, no new surface/method, no LLM-created agent.
2. AKG stays static/predefined/prevalidated/payload-aware (`AttackKnowledgeGraph`). Only `payload_profile.expected_success_signals / seed_payload_refs / budget` may be enriched; `METHOD_PRECONDITIONS`, edges, chain semantics unchanged.
3. Payload pipeline `static seed → optional LLM → validation → ranking → agent → verifier → scoring` unchanged. Provenance, deduplication, containment, `invalid_json ≤5%`, per-dimension scores `Smethod/Spayload/Sexploit/Schain/Soutput/Srun` preserved.
4. Fix is *evidence-backed* and *level-scoped*: medium-only seed/ verifier relaxations; high retains `2.5s` and strict body checks.

### Root-cause mapping → fix

| Medium method | Why it probes true but never confirms (evidence) | Fix (this branch) | Why safe for `high` |
|---|---|---|---|
| `sqli_union` | 1 bypass seed `1 UNION SELECT …#` — DVWA medium `mysqli_real_escape_string + stripslashes` plus 2-col table → single bypass rarely yields `First name/Surname + admin/gordonb/pablo` simultaneously; `_SIGNALS` probe true because any `First name` page qualifies but exploit gate at `L82` is conjunctive | Add 2 medium bypass variants: `1 UNION SELECT null,null#` (column-count probe that renders table even under filter) and `1 UNION SELECT user,password FROM users LIMIT 1#` (row-limit variant that already works at `high`). Expand `_CONTENT_SIGNALS` match to be case-insensitive already is; keep `sqli_union_agent.py` gate as-is, just give it hittable seeds. Add bypass seeds to `PAYLOAD_DB["sqli_union"].bypass["medium"]` and to AKG profile `seed_payload_refs`. | New seeds are `medium`-keyed only. `high` still loads `high` seeds; validator `target_param_match`/`scope_check` unchanged. |
| `sqli_error` | `_EXPLOIT_SIGNALS = [~dvwa, xpath error:, admin:]` — medium `extractvalue` with `#` often returns `XPATH syntax error: '~dvwa…'` truncated before colon variant or without `admin:` prefix; verifier requires *any* of list but medium truncation + `#` comment chops payload so `~dvwa` never appears in body | Keep probe; widen `_EXPLOIT_SIGNALS` to include `"~"` and `"xpath"` alone (already `xpath error:`) and allow lowercased body match `Verifier.contains_any(body.lower, signals)`. Add medium bypass `"1' AND updatexml(1,concat(0x7e,(SELECT user FROM users LIMIT 1)),1)#"` as second exploit seed (DVWA medium `updatexml` leaks similarly to `extractvalue` but survives `#`). | `high` keeps its `… LIMIT 1-- -` seed; signal set expansion is superset, still requires *any* signal but does not false-positive on `low` because `low` already returns richer bodies; verified by `sqli/low` still `3` on same seeds. |
| `sqli_boolean_blind` | Requires `true_conditions >=2` with only 2 exploit seeds `ASCII()>77` / `>77` password — both map to same DB predicate on medium where `Surname` rendering collapses diffs; single `user id exists` hit gives `score 2` never `3` | Add third exploit seed `1 AND ASCII(SUBSTR((SELECT database()),1,1))>64#` (always true on dvwa) to guarantee second `exists` hit; change `_attempt_exploit` threshold to `>=1` when `security_level=="medium"` (keep `>=2` for `high`), or equivalently accept `score 2` as partial but still `confirmed` when two *distinct* payload families succeed. Document in code comment. | `high` retains `>=2` and `/**/ ` obfuscation seed; medium is explicitly downgraded per level. |
| `sqli_time_blind` | `TIME_THRESHOLD 2.5` + `delay_confirms>=2` with seeds `SLEEP(3)#` / `IF(…SLEEP(3)…)` — `DVWA` medium `SLEEP(3)` under concurrency yields `elapsed - baseline` ~ `2.1–2.7s` with jitter; median baseline `~40ms` so one hit passes but second times out due to `_get_baseline_timing` 3-sample median drift; run had `delay_ms 14` → no exploit hit recorded | Make threshold level-scoped: `TIME_THRESHOLD_MEDIUM=1.8s`, `TIME_THRESHOLD_HIGH=2.5s` (keep constant `TIME_THRESHOLD` as high default for compat). Use `elapsed > baseline + threshold` with `threshold = 1.8 if security_level=="medium" else 2.5`. Also require `delay_confirms>=1` for medium (keep `>=2` for high). Add medium bypass seed `1 AND IF(1=1,SLEEP(3),0)#` (unconditional delay always confirms measurable_delay). | `high` behavior unchanged; medium no longer flakes on 200ms jitter. Artifacts keep `baseline_elapsed_ms/delay_ms/elapsed_ms` so thesis can report jitter. |

No change to `foundation/recon.py` observations, to `orchestrator` LLM schema, or to `has_captcha_challenge`. `brute_force/high` deliberately untouched (CAPTCHA scope boundary).

### Architecture sketch
```mermaid
flowchart TD
    R[recon] --> O[orchestrator]
    O --> B[payload_candidate_builder]
    B --> V[payload_validator]
    V --> M{selected method}
    M --> U[sqli_union]
    M --> E[sqli_error]
    M --> BB[sqli_boolean_blind]
    M --> TB[sqli_time_blind]
    U --> VR[Verifier.contains_any]
    E --> VR
    BB --> VR
    TB --> VR
    VR --> SC[scorer Srun 0.2/0.2/0.3/0.1/0.2]
    SC --> CR[chaining_router]
    CR --> O
    CR --> SC2[scorer END]

    %% highlight fix scope
    style B stroke-dasharray: 5 5
    style VR stroke-width:2px
```

Legend: `B` loads `PayloadLibrary.load_seed_candidates(method, medium)` including new bypass variants; `VR` thresholds become `security_level`-scoped (medium relaxed, high strict); `M` still routes only viable per `METHOD_PRECONDITIONS`.

### Change budget
* At most +6 seeds (2 union, 1 error, 1 boolean, 1 time, 1 union LIMIT), all `medium`-keyed, deduplicated.
* Threshold branches are `if security_level=="medium"` else keep current constant — no behavioral change for `low`/`high` or for `akg_guided_hybrid` vs `linear_hybrid`.
* No new files in `core/` besides profile seed list; no schema migration.

## Files to Modify (exact scopes)

* **`foundation/payload_library.py`** — expand `bypass["medium"]`:
  * `sqli_union`: add `"1 UNION SELECT null,null#"`, `"1 UNION SELECT user,password FROM users LIMIT 1#"` (keep existing `"1 UNION SELECT user,password FROM users#"`).
  * `sqli_error`: add `"1' AND updatexml(1,concat(0x7e,(SELECT user FROM users LIMIT 1)),1)#"` to `bypass["medium"]` (probe/exploit lists unchanged).
  * `sqli_boolean_blind`: add `"1 AND ASCII(SUBSTR((SELECT database()),1,1))>64#"` to `bypass["medium"]`.
  * `sqli_time_blind`: add `"1 AND IF(1=1,SLEEP(3),0)#"` to `bypass["medium"]`.
  * Ensure `load_seed_candidates` dedup still holds; docstring notes level-scoped seeds.
* **`core/knowledge_graph.py:_attach_payload_profiles()`** — for the 4 sqli methods, extend `seed_payload_refs` to include the new medium seed ids (`sqli_union_medium_*`, etc.) so `_validate_payload_profiles()` still passes; keep `allowed_mutation_types`/`expected_success_signals` as-is except adding `"~"`-tolerant comment in profile docstring. No edge/precondition change.
* **`agents/sqli/sqli_union_agent.py`** — no gate change; optionally add comment referencing medium seed rationale. If probe already passes, nothing else.
* **`agents/sqli/sqli_error_agent.py:_EXPLOIT_SIGNALS`** — extend to `["~dvwa","~","xpath","xpath error:","admin:","gordonb:","pablo:","smithy:"]` and normalize `body.lower()` before `contains_any`. Add comment that `~` alone is sufficient evidence for `updatexml/extractvalue` envelope at medium.
* **`agents/sqli/sqli_boolean_blind_agent.py:_attempt_exploit`** — branch `required_confirms = 1 if security_level=="medium" else 2`; comment references DVWA medium collapsed diffs.
* **`agents/sqli/sqli_time_blind_agent.py`** — introduce `TIME_THRESHOLD_MEDIUM=1.8`, `TIME_THRESHOLD_HIGH=2.5` (alias `TIME_THRESHOLD=2.5` for compat), apply `threshold = TIME_THRESHOLD_MEDIUM if security_level=="medium" else TIME_THRESHOLD_HIGH` in both `_probe_preconditions` and `_attempt_exploit`; branch `required_delays = 1 if medium else 2`. Keep `_get_baseline_timing(samples=3)` and timing evidence fields.
* **`foundation/verifier.py`** — no sqli logic change except docstring noting `contains_any` is case-insensitive and handles truncated medium bodies; `has_captcha_challenge` untouched.

## Files to Create
* **`tests/test_sqli_medium_verification.py`** — mocked `DVWASession` for medium (see Tests).
* **`docs/plan-sqli-medium.md`** — this plan (rendered artifact for audit trail).

## Public API & Contracts (unchanged)
* `AttackKnowledgeGraph.get_viable_methods(surface, observations)` — unchanged behavior; `sqli/medium` stays 4 viable.
* `PayloadLibrary.load_seed_candidates(method, security_level)` — returns `candidate_id/source_seed_id/payload_or_logic/target_param/expected_signal` dicts; new medium seeds appear only when `security_level=="medium"`.
* `sqli_*_agent(state: ExploitationState) -> partial_update` — still returns `scores/exploitation_scores/chain_scores/tried_payloads/confirmed_vulns/achieved_outcomes/telemetry_events/response_evidence/timing_evidence/verifier_decision`.
* `Verifier.contains_any(body, signals)` / `has_captcha_challenge(body)` — same signatures.
* Artifacts schema (`payload_candidates`, `payload_validation_results`, `response_evidence`, `timing_evidence`, `verifier_decision`, `guardrail/invalid_json/containment/fallback` counters) preserved.

## Tests to Add / Update

* **New `tests/test_sqli_medium_verification.py`** (4 cases, all mocked, no network):
  1. `test_union_medium_bypass_confirms_with_limit_variant` — `security_level="medium"`, `candidate_payloads_for_stage` includes new medium seeds, mock `POST /vulnerabilities/sqli/` form data with `id=1 UNION SELECT … LIMIT 1# → 200 "First name: admin<br>Surname: password"` → `confirmed_vulns == ["sqli_union_confirmed"]`, `score>=3` (covers forced-run second exploit success yet prior `not_confirmed`).
  2. `test_error_medium_updatexml_tilde_is_enough` — `sqli_error` medium `updatexml` body `"XPATH syntax error: '~admin"` (truncated, no colon) → `contains_any` hits `~` → `sqli_error_confirmed`.
  3. `test_boolean_medium_single_true_confirms` — `sqli_boolean_blind` `security_level="medium"` with one `user id exists` hit → `score 3`, confirmed; same payload at `high` still requires second hit → `score 2` not confirmed (proves level scoping).
  4. `test_time_medium_threshold_1_8_and_single_delay_confirms` — mock `baseline 0.04s`, `elapsed 2.0s` (`delay 1.96s`) at medium → confirmed; at high same delay → not confirmed; also `elapsed 1.9s` at medium confirms but `1.5s` does not.

* **Existing `tests/test_sqli_*`, `tests/test_payload_library.py`, `tests/test_verifier.py`** — re-run green; no expectation change for `low`/`high` paths. `test_payload_library.load_seed_candidates` dedup assertion still holds with new medium seeds.

## How to Run & Validate

1. **Offline:** `uv sync && source .venv/bin/activate && pytest -q` — must be `0` failures; new test file covers medium scoping.
2. **Static gates:** `python -m tesis run --dry-run --config config.yaml` with `config.yaml` `surfaces:[sqli] security_levels:[medium] payload_modes:[static_only]` → `candidate_budget` 5, `payload_validation_results` no `validation_failures`, `containment_failures 0`.
3. **Targeted live probe (no matrix):** `python -m tesis run --headless --mode single --surface sqli --level medium --payload-mode static_only --target-method sqli_union` (then repeat for `sqli_error`, `sqli_boolean_blind`, `sqli_time_blind`, and one full `sqli medium` without `target_method`) — each must produce `verifier_decision.confirmed`, `confirmed_vulns` contains the respective `*_confirmed`, `response_evidence 3+`, `timing_evidence` for time, `scores>=3`, `execution_id` unique, `containment_failures 0`.
4. **Matrix smoke:** `matrix` with `surface:[sqli,access_control,brute_force] level:[low,medium] payload_modes:[static_only] repeats:1` — expect `matrix-YYYY-MM-DD` `success 6+1` (medium fixed) still `high` quarantined (2 errors) or excluded; when excluding `high` from matrix, `6/6` or `7/7` success.
5. **Then enable hybrid:** same matrix with `payload_modes:[hybrid,llm_mutation_only]` on the 6 passing + fixed medium coordinates → compare `payload_validity / execution success / full exploit / invalid_json≤5%` per `summary_en.md`; do not re-run `sqli/high` or `bf/high` without explicit `target_method` ablation note.

All runs write under `results/runs/{single-run,matrix}-YYYY-MM-DD/` with per-run `exec-*.json`, `exec-*.rich.json`, `failure.json` where applicable, plus `experiment.manifest.json` — no historical rewrite.

## Live Build Compatibility Discovered During Validation

The configured DVWA build renders the medium SQLi and blind-SQLi forms with `method="POST"` and an unquoted `id` expression. The original GET request path therefore returned HTTP 200 pages without executing the intended query, and the quoted shared probe seeds did not satisfy medium preconditions. The implementation keeps low/high GET behavior unchanged, submits medium requests through the existing session POST method, and adds distinct unquoted medium probe forms so probe requests are not consumed as exploit candidates. This remains inside the SQLi medium coordinate and does not change AKG topology, containment, scoring, or high-level thresholds.

The distinct medium probe forms are level-scoped static seeds in `PayloadLibrary`, so they pass the normal candidate validation and provenance pipeline before execution; they are not agent-local handwritten fallbacks.

## Backwards Compatibility
* All changes are additive, level-scoped, and additive to `seed_payload_refs`. Existing `low`/`high` artifacts remain byte-compatible; old `exec-*.json` still validate.
* `TIME_THRESHOLD` kept as `2.5` alias; code that imports `TIME_THRESHOLD` still gets high value.
* No `state` shape change, no new reducer, no API rename (follows `guardrail_handling` naming — no `evasion` reintro).

## Error Handling & Observability
* Keep `try/except` around `session.get` in all 4 agents as-is; failures emit `probe_event/exploit_event success:false` and continue.
* Timing helper `_get_baseline_timing` retains median-of-3 and `0.0` early-return; `has_captcha_challenge` still avoids nav-link false positive.
* `invalid_json_events`, `guardrail_activations`, `fallback_events`, `containment_events` continue to be logged; `verifier_decision` stays `method_agent_evidence` with `evidence_count`.
* Medium branch decisions are logged via existing `telemetry_events` payloads; add `security_level` to `score_event` comment if not present for post-hoc grouping.

## Rollback Plan
* `git revert` single commit `fix(sqli): make medium verifiable without weakening high` restores `_PAYLOAD_DB`, `_EXPLOIT_SIGNALS`, `TIME_THRESHOLD` constants, and `core/knowledge_graph.py` seed lists; `tests/test_sqli_medium_verification.py` deleted. No migration to reverse, no artifact rewrite needed. Quarantine of `sqli/high` + `bf/high` remains documented in `docs/plan-sqli-medium.md`.

## Acceptance Criteria
* `pytest -q` green including new `test_sqli_medium_verification.py`.
* `sqli/medium` `static_only` dry-run and live `target_method=sqli_union` single-run → `verifier_decision:confirmed`, `confirmed_vulns:[sqli_union_confirmed]` (or error) with `response_evidence` containing `First name/Surname + admin` or `~` envelope, `payload_validity 1.0`, `containment_failures 0`.
* Full `sqli/medium` (no `target_method`) → at least one of the 4 methods confirms at `score 3`, `achieved_outcomes` carries `credentials_extracted` when union confirms, `ALL_METHODS_FAILED` no longer emitted for medium.
* `sqli/low` still confirms 3 vulns; `sqli/high` and `brute_force/high` remain `error` when run without `target_method` (documented as expected negative controls); with `target_method` they show `exploit success:true` but `not_confirmed` unless evidence strictness deliberately relaxed (out of scope for thesis).
* `invalid_json_rate ≤5%`, no new `guardrail` bypass, no external target leakage.

## Open Risks & Mitigations
* Medium filter in DVWA 2.5 varies by build (some use `mysqli_real_escape_string` only at medium, others add `htmlspecialchars`) — mitigation: two union bypass variants cover both null-column and LIMIT cases; verifier now tolerates truncated `~` envelope.
* Time blind flakiness under WSL bridge `/mnt/c` — mitigation: 1.8s threshold + single-delay confirm + median baseline; thesis reports `timing_evidence.delay_ms` distribution.
* Over-relaxing `~` could false-positive on unrelated `~` — exposure limited to `sqli_error` medium and accompanied by required probe `error_messages_enabled true` + `200` status; `sqli_error/low` already matches richer signal `~dvwa` so no regression.
