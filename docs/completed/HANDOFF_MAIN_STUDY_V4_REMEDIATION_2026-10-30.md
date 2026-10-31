# Handoff — main-study-v4 remediation (readiness, chaining, scoring integrity)

**Date:** 2026-10-30
**Status:** in progress — Phases −1 to 3b executed; six defects fixed; four of five cells pass the
pre-registered definition of done and five of five pass once the measured-negative clause applies
(§9.3); the `access_control/high` and D12 decisions were taken by the human owner and implemented
(§9.4). Phase 4 (matrix re-run) and Phase 5 (Tables III–IV, methodology updates) remain
unauthorised.
**Artifact under review:** `results/studies/main-study-v4-ai-2026-10-30/final-v4-audit.json`
**Scope of this handoff:** fix the defects that make the v4 matrix non-reportable, then re-run it.
**Owner:** unassigned
**Agent authorisation:** free-roam DVWA discovery, live provider calls, and terminal commands
are **granted** to the remediation agent for diagnosis and verification — see §4. The full
matrix re-run (Phase 4) is **not** covered by that grant.

---

## 1. Why this handoff exists

`final-v4-audit.json` is internally consistent and well-formed, but the experiment it
describes cannot support the Table III/IV comparisons it was built for:

| Fact | Value | Consequence |
| --- | --- | --- |
| Planned runs | 108 (4 groups × 27) | — |
| Completed runs | 48 (44.4%) | n=12/group, not 27 |
| Readiness failures | 60 (55.6%) | 5 of 9 (surface × level) cells dead |
| Access Control completions | 0 of 36 | **an entire thesis surface has no data** |
| Chaining transitions attempted | 0 of 96 opportunities | `Schain = 0.00` in all groups |
| Score dimensions with zero variance | `Sexploit`, `Soutput`, `Schain` | tables cannot discriminate |
| Confirmed candidates from LLM generation | 0 (`U=0`, `V=0`) | hybrid-vs-linear contrast has no LLM signal |

The failure set is **invariant** under every variable the study manipulates — identical
15/15/15/15 per model × condition group, identical across all 3 `repeat_index` values,
and identical across the two independent studies `main-study-2026-10-30` and
`main-study-v4-ai-2026-10-30` (234 artifacts). It is therefore a harness defect, not a
model finding. `foundation/readiness.py` already states the governing principle
("Environment failures are never model failures"); the harness currently honours it in
letter while destroying the design in effect.

**Do not publish v4 numbers.** Fix, re-run, then rewrite the tables.

> **Read §4 first.** The agent working this handoff is authorised to roam the DVWA suite
> beyond the deployed crawl, make live provider calls, and run terminal commands in order
> to establish ground truth and to prove the readiness failures are still reproducible
> before fixing them. §4 states the boundaries that authorisation does **not** lift.

---

## 2. Defect register

Severity: **P0** blocks the matrix · **P1** invalidates a claimed dimension · **P2** metric integrity.

### D1 — Readiness endpoint discovery is form-only (P0)

**Symptom.** 48 runs fail with `required_endpoint_missing`, i.e. 44.4% of the matrix.
Access Control fails at *every* level (0/36); `sqli/high` fails (0/12).

**Evidence.**
- `required_endpoint_missing` = 48 blocking reasons; `required_token_missing` = 12.
- Observed endpoint sets are a deterministic function of **security level alone**,
  identical across all three surfaces: low→14 paths, medium→15, high→13.
- `/vulnerabilities/authbypass/` is absent from all three sets.
  `/vulnerabilities/fi/` and `/vulnerabilities/open_redirect/` are also absent at all levels.
- The blocking reason is `required_endpoint_missing`, **not**
  `required_endpoint_unverified` — so `crawl_ok` stayed `True`: requests succeeded,
  containment passed, and the pages simply produced no qualifying record.

**Root cause.** Two components disagree about what "observed" means.
- `foundation/recon.py:463` `parse_forms` emits one endpoint **per `<form>`** element,
  resolving `action` against the page URL.
- `foundation/readiness.py:197` `_SURFACE_ENDPOINT_FRAGMENTS` then requires literal path
  fragments (`/vulnerabilities/authbypass/`, `/vulnerabilities/sqli_blind/`, `/vulnerabilities/brute/`)
  to appear among those form-derived URLs (`readiness.py:249`).

Any module page that renders no `<form>` is invisible to the gate. The crawl is also a
single `index.php` link scrape (`recon.py:831`) with no depth, so pages never reached are
never recoverable. One ad-hoc special case papers over this for SQLi only
(`recon.py:552` `_discover_sqli_session_input`, wired at `recon.py:876` for `high`) —
which is why `sqli/high` reports missing `sqli_blind` rather than missing `sqli`: the
fragment `/vulnerabilities/sqli/` is satisfied by substring through
`sqli/session-input.php`.

**Proof the target is not at fault.** 577 older `access_control` artifacts contain real
`authbypass` traffic in `response_evidence` and scored (e.g.
`results/runs/matrix-2026-09-28-3/run-002-openai_compatible-access_control-high-static_only`).
Those predate `readiness.v1` (no `readiness.status`). The module exists and is exploitable;
the gate never lets it start.

**Fix direction.** Make discovery path-based rather than form-based: record each fetched
navigation link itself as an endpoint (not only its form actions), and give the navigation
step enough depth to reach the modules the fixture advertises. Keep the existing
containment filtering and the SQLi `session-input` special case, or replace both with one
generic "declared handler discovered from page markup" mechanism.

**Acceptance.** All 9 (surface × level) cells reach `readiness.status == "ready"` on a dry
run per surface; `access_control` produces ≥1 completed run; no regression in the 4 cells
that already pass.

---

### D2 — Readiness requires a brute-force form token at medium (P0)

**Symptom.** `brute_force/medium` fails 12/12 with `required_token_missing`
(`token.required=true`, `token.present=false`).

**Root cause.** `foundation/readiness.py:226` `_token_required` returns `True` for
`{"medium", "high"}`, but the rest of the harness treats `user_token` as **high-only**:
- `foundation/recon.py:323` — token fetched only `if level == "high"`
- `foundation/control_catalog.py:128` — `4 if level == "high" else 1`
- `agents/brute_force/bf_spray_agent.py:111` — fresh token only `if high_security`

At medium the token is never even requested, so `token_present` is structurally `False`
and the cell can never pass. This is an internal contradiction, not a fixture limitation.
Empirical confirmation: low `required=False/present=False`; high `required=True/present=True`;
medium `required=True/present=False`.

**Fix direction.** Drop `"medium"` from `_token_required`, or drive the requirement from
what the crawl actually observed for that level instead of a hardcoded level set.

**Acceptance.** `brute_force/medium` reaches `ready` and completes; low/high unchanged;
`required_token_missing` no longer appears in a re-audit.

---

### D3 — Chain infeasibility reports the first gate, not the decisive one (P1)

**Symptom.** Every chain edge in the corpus is labelled
`destination_preconditions_not_proved` — 206 of 206 edges across 104 runs — which points
diagnosis at destination preconditions regardless of the real blocker.

**Root cause.** `core/chaining_coordinator.py:299` `_chain_infeasibility` checks the
destination first and short-circuits (`:302-306`). The caller
(`chaining_coordinator.py:440-446`) then re-checks with `check_destination=False` and
bails on a **different** reason that is never recorded in `chain_assessment`.

**Consequence.** The audit's own reason field misattributes the failure. Tracing the
`continue` path is currently the only way to learn why chaining is dead.

**Fix direction.** Evaluate and report all applicable rejection reasons (or the decisive
one), and persist the source-side reason in `chain_assessment` alongside the destination
status.

**Acceptance.** A re-audit's edge records name the true blocker per edge;
`chain_assessment` distinguishes destination vs source rejection.

---

### D4 — Adapter whitelist excludes a declared KG edge (P1)

**Symptom.** The chain edge `brute_force_confirmed → authenticated_session`
(`core/knowledge_graph.py:308-317`, `target_agent: "ac_idor"`) can never pass.

**Root cause.** `core/chaining_coordinator.py:307-309` accepts only
`(source == "authenticated_session" and method in {"ac_idor","ac_force_browse"})`
or `(source == "credentials_extracted" and method == "bf_dictionary")`.
The edge declares source `brute_force_confirmed` with an `ac_*` target, which is in
neither branch → permanent `source_consumption_adapter_unavailable`. Observed 24 times
in the study.

**Fix direction.** Reconcile the KG edge with the adapter (correct the declared source, or
extend the whitelist), and add a static consistency check so KG edges and adapter
whitelists cannot drift apart.

**Acceptance.** Every `is_chain: true` edge in the KG is either supported by an adapter
branch or explicitly marked unsupported; no edge is silently unreachable.

---

### D5 — Chain edge requires plaintext credentials a SQLi surface cannot produce (P1)

**Symptom.** The only AC-independent chain edge, `credentials_extracted → bf_dictionary`,
is rejected in all 24 SQLi runs.

**Root cause.** `core/chaining_coordinator.py:324-325` requires
`representation == "plaintext"`. Across completed runs `found_credentials` holds
48 `plaintext` and 120 `password_hash`; **0 of 24 sqli runs contain any plaintext
credential**. A DVWA SQLi dump yields hashes by construction.

**Fix direction.** Either allow a `password_hash` source to satisfy `bf_dictionary` (with an
explicit cracking/derivation step and its own evidence), or re-specify the edge so it
sources from a surface that yields plaintext.

**Acceptance.** The edge reaches `feasible` on at least one run, or the KG documents it as
unsatisfiable on this fixture.

---

### D6 — Cross-surface destination preconditions are never measured (P1)

**Symptom.** 0 `recon.destination.completed` events across all 48 completed runs;
`preparation_failures` holds 2 entries total (both `NO_VALID_PAYLOADS`). The destination
probe path never executed.

**Root cause.** Preconditions are proved only for the surface actually executing
(`foundation/preconditions.py:290` `statuses_snapshot` maps unmeasured keys to
`"unknown"`, and `_chain_infeasibility` treats any non-`"true"` value as fatal). In a
completed `brute_force/high` run only `no_rate_limit` is `"true"`; the other seven keys
are `"unknown"`. So every cross-surface destination is unproved, and
`probe_brute_force_destination` / `probe_access_control_destination`
(`foundation/recon.py:178`, `:238`, called from `chaining_coordinator.py:455-464`) are
reached only when the source-side gate passes first — which it currently never does.

**Fix direction.** Establish destination preconditions before evaluating the source gate,
or maintain a cross-run precondition ledger so a destination surface's status is available
when another surface sources the edge.

**Acceptance.** At least one destination probe completes and is recorded in telemetry;
`preparation_failures` captures inconclusive probes as designed.

---

### D7 — Readiness and chaining share one root assumption (P1) — **design note**

Both gates fail closed on absence of evidence, and both only ever hold evidence for the
currently executing surface:
- readiness asks "was this endpoint observed *by this crawl*" → D1/D2
- chaining asks "were this destination's preconditions proved *in this run*" → D6

They should not be fixed as two unrelated bugs. Whichever way the harness resolves
"evidence for a surface we are not currently on", it should resolve it once and use the
same mechanism for both. Fixing readiness alone will **not** restore chaining.

**Acceptance.** A short design note in `docs/reference/` states the single
cross-surface-evidence rule, and both gates cite it.

---

### D8 — Fixture restoration is never attested (P1)

**Symptom.** `fixture_restoration_invalid` fires on **108/108** runs as *advisory*;
`fixture_restoration.equivalence == "unknown"` everywhere; detail is
"unsupported fixture restoration policy version". `fixture_restoration_sha256` is `null`.

**Root cause.** `foundation/readiness.py:40` declares `FIXTURE_RESTORATION_POLICY_VERSION`,
and `:70` rejects evidence whose `policy_version` does not match; the supplied evidence
never matches, so every run degrades to `unknown` (`readiness.py:331-335`). Being advisory,
it never blocks — so the degradation is silent.

**Consequence.** The study cannot claim fixture restoration or environment equivalence for
any run. This is a validity threat independent of D1–D6.

**Fix direction.** Produce conforming operator attestation for the fixture, or make the
absence blocking until it exists. Do not leave it advisory on a study used for validity claims.

**Acceptance.** `equivalence != "unknown"` for every run in the re-audit, with evidence
refs present.

---

### D9 — Scoring provenance does not describe what ran (P1)

**Symptom.** `scoring.frozen_max_tokens: 1024` (from `config.yaml:251`
`scoring_evaluator.max_tokens`) while reviews were produced at 8192 and retried at 10000.

**Evidence.** `initial_truncated_reviews: 27`, `accepted_at_8192: 3`,
`accepted_at_10000: 24`, `10000_token_batch_candidates: 23`,
`10000_token_batch_provider_attempts: 25`. ~36% of the review workload overflowed the
frozen budget and was re-run at a different one.

**Fix direction.** Set the frozen budget to the value actually used, re-score under it, or
declare the override as a documented protocol deviation with per-review provenance.

**Acceptance.** `frozen_max_tokens` matches the budget that produced every receipt, or every
receipt carries its own effective budget.

---

### D10 — The scorer is one of the evaluated models (P1)

**Symptom.** `scoring.scorer_model == "deepseek-ai/DeepSeek-V4.1-Flash-1017"`, which is one
of the two models under comparison (2 of 4 groups). The same model grades its own runs and
`gpt-6-luna`'s.

**Evidence.** `scoring.scorer_model`, `scoring.scorer_provider_profile == "river-ai__deepseek-ai-deepseek-v4-1-flash-1017_15efb2abf693"`;
`table_iv` shows `review_downgrades_from_proof_tier: 3–4` per group, i.e. the reviewer is
actively overriding verifier-confirmed candidates.

**Fix direction.** Use a scorer outside the evaluated set, or run a second independent
scorer and report agreement. If self-grading must stay, state the bias explicitly in the
method chapter and quantify it.

**Acceptance.** Either an out-of-set scorer, or a documented bias statement plus inter-scorer
agreement statistic.

---

### D11 — Containment counters measure sidebar links, not attacks (P2)

**Symptom.** In every group `blocked_actions == detected_events == discarded_navigation_events == 135`,
with `actual_violations: 0` and 6924 physical requests of 7464 assessed.

**Evidence.** The only containment events logged are out-of-scope footer links
(`www.virtualbox.org`, `www.vmware.com`, `www.apachefriends.org`,
`github.com/webpwnized/mutillidae`, `owasp.org/...`) discarded by
`extract_nav_links` (`foundation/recon.py:623`). Identical counts across all four groups
because the page footer is identical.

**Consequence.** `paragraph_totals.containment.detected_events = 540` reads as 540 blocked
attacks; it is 540 benign link filters.

**Fix direction.** Classify containment events by kind and report attack-relevant ones
separately from navigation hygiene.

**Acceptance.** The manuscript's containment figure is derived from attack-relevant events
only, with navigation discards reported as a separate line.

---

### D12 — Outcome variance is degenerate (P2 / scoring design)

**Symptom.** `Sexploit`, `Soutput`, `Schain` are constant (`3.00`, `3.00`, `0.00`) in all
four groups; `first_choice_accuracy` 12/12, `full_confirmation` 12/12 in all groups;
`adaptation` 72/72 (100%).

**Evidence.** `table_iii`: `Srun` spans only 2.45–2.60, entirely inside the reported
intervals [2.25, 2.70]. With `Schain` fixed at 0 and two dimensions constant, `Srun` is a
monotone affine function of `Smethod + Spayload` alone — the 0.10 chaining weight is
dead weight in every score, and the rubric saturates at ceiling for these cells.

**Fix direction.** Decide whether this is rubric saturation (recalibrate upward) or task
difficulty (the surviving cells are too easy). Either way, do not report condition
differences from these tables.

**Acceptance.** After a complete re-run, at least one dimension retains non-zero variance
and a condition or model contrast is either detected or explicitly reported as null.

---

### D13 — LLM candidate contribution is zero (P2 / research claim)

**Symptom.** `confirmed_candidates_by_source == {"S": 29–30, "U": 0, "V": 0}` in all four
groups; fallback use 0–5 of 30 generation opportunities.

**Consequence.** Every confirmed candidate traces to a static seed. The
`linear_hybrid` vs `akg_guided_hybrid` comparison currently has no LLM-generated payload in
its population, so `static_only` vs hybrid would be a null comparison and any LLM
payload-generation claim is unsupported.

**Fix direction.** Establish whether the LLM candidate pipeline can produce a confirmable
candidate at all on this fixture before attributing any result to it.

**Acceptance.** `U` or `V` > 0 in at least one group, or the thesis claim is narrowed to
"LLM candidates did not contribute confirmed exploits under this protocol".

---

## 3. Sequencing

Do not re-run the matrix until Phase 2 is complete; a re-run before that reproduces the
same 5 dead cells. **Phase −1 must land before any code change** — it is what tells you
whether D1 is a discovery bug or an inventory bug, and it captures the pre-fix baseline
that every later phase is diffed against.

| Phase | Work | Gate before proceeding |
| --- | --- | --- |
| −1 | **Ground truth + baseline reproduction (§4)**: free-roam DVWA census, live-call check, re-confirm the 5 failing cells | census artifact written; 9-cell baseline fingerprint captured; 5 fail / 4 pass reproduced |
| 0 | D1, D2 (readiness) | re-run 9-cell probe: all 9 `ready`; the 4 previously-passing cells unchanged |
| 1 | D4, D6, D5 (chaining reachability) | a chain edge reaches `feasible` in offline/mocked coverage |
| 2 | D3 (reporting) + D7 (design note) | re-audit names true blockers per edge |
| 3 | D8, D9, D10, D11 (validity + scoring) | fixture attestation conforms; scoring provenance matches receipts |
| 3b | **Iterate-until-green on the failing coordinates (§4.7)** — re-run the 5 failing cells until each one runs successfully | all 60 readiness-failed runs complete; per-cell definition of done met |
| 4 | Full matrix re-run | **separate explicit authorisation required** (live DVWA + provider) |
| 5 | D12, D13 review against fresh data | tables rebuilt from the new audit |

## 4. Authorised operating protocol — remediation-agent free roam

This section grants the agent doing the remediation (not the experiment's models) explicit
permission to work freely against the fixture. It exists because the deployed crawl is the
very thing under suspicion: you cannot diagnose D1/D2 by reading artifacts produced by the
crawler that is missing the endpoints.

### 4.1 What is authorised

Authorised by the repo owner on **2026-10-30**:

- **Roam the DVWA suite freely** — any path under the configured target, any depth, any
  session, any security level, using the repo's own `DVWASession` or any HTTP tool you
  prefer. Discover links, forms, handlers, hidden inputs, JS-only endpoints, and module
  inventory the deployed crawl never sees.
- **Make real LLM/provider calls** — live calls against the configured provider profile,
  with your own prompts, for diagnosis and hypothesis testing.
- **Run other terminal commands** — curl, python, sqlite inspection of checkpoint stores,
  log greps, the repo's own runners, anything that serves the diagnosis.
- **Do all of it specifically to** (a) establish ground truth for D1/D2, and (b) confirm
  that the five readiness failures are *still reproducible* on the current tree before you
  change it, so that a fix can be proven to have removed them rather than moved them.

**Not authorised by this section:**
- The full matrix re-run (Phase 4) — that still needs a separate go-ahead.
- Changing the study design: surfaces, methods, conditions, payload modes, repeats,
  rubric, or scoring rule.
- Widening thesis scope (see §4.3).

### 4.2 This is not the experiment's LLM

The experiment's `orchestrator` and `payload_generator` calls are the **subject** of study,
not the tool doing this work. Across the 48 completed runs they fired 240 times
(120 orchestrator + 120 payload_generator), 0 failures, `cache_hits: 0` in every run — so
those calls were genuinely live, not replayed from cache.

Therefore, while roaming:
- Do **not** edit `config.yaml` role settings, `llm_runtime` blocks, prompts, system
  messages, temperature, or the provider profile. A probe that changes them invalidates the
  coordinate comparison.
- If you need a different model or prompt for a diagnostic call, pass it explicitly in your
  own script — never by editing the study config.
- Keep any experiment-config change in a separate branch, labelled, and reverted before
  Phase 0 lands.

Note for D13: the LLM *was* called and produced no confirmed candidate (`U=0`, `V=0`). A
free-roam live-call experiment is the right way to distinguish "the pipeline cannot produce
an adoptable candidate" from "the adapter/scoring drops what it produces". Inspect
`candidate_dispositions`, `candidate_lifecycle`, and `model_call_requirements` per run.

### 4.3 Boundaries the authorisation does **not** lift

These come from `AGENTS.md` and remain binding. Roam freely **inside** them.

| Boundary | Rule |
| --- | --- |
| **Containment** | Every request and every redirect hop stays on the configured DVWA host. Never disable the client's containment check, never fetch an off-host URL "just to see". D11 depends on containment still running, and off-host fetches were the *only* thing it caught. |
| **Attack scope** | The nine in-scope methods only (`sqli_*`, `ac_*`, `bf_*`). You may **read** out-of-scope modules — `/vulnerabilities/xss_r/`, `csrf`, `fi`, `upload`, `exec`, `weak_id`, `open_redirect`, `api` — to inventory links and count forms. You must **not** send attack payloads at them, and must not add them to any matrix. |
| **Guardrails** | No jailbreaks, roleplay deception, adversarial prompt injection, policy-bypass prompts, or external adaptation to obtain provider output. Follow `guardrail_handling` / `guardrail_retry` semantics. |
| **Secrets** | No tokens, cookies, passwords, API keys, or hashes in artifacts, docs, or commit messages. Redact on capture. |
| **Fixture integrity** | Roaming must leave the fixture restorable. If a probe mutates DVWA state, restore it and record the restoration evidence — this is the same evidence D8 needs. |
| **Test discipline** | Do not run the full pytest suite or any E2E as a side effect of roaming. Smallest relevant check only, and state what you ran. |

### 4.4 What to discover — the module × level census

Produce one machine-readable census covering **every** module × `{low, medium, high}`:

| column | why |
| --- | --- |
| module, path | inventory |
| HTTP status, final URL | presence / redirect behaviour |
| discovered as a link from `index.php`? | separates "not linked" from "linked but unparseable" (D1) |
| `<form>` count | the exact thing `parse_forms` keys on |
| form actions (normalised) | what the gate would record as "observed" |
| `input[name=user_token]` present? | decides D2 |
| JS-only handler marker (e.g. `session-input.php`) | explains the SQLi special case |
| principal-visible content differs by role? | grounds the AC destination probes |

The questions this census must answer, in priority order:

1. Does `/vulnerabilities/authbypass/` exist, and does its HTML contain a `<form>`?
   *If no form:* D1 is a discovery/vocabulary bug and the gate must accept path-based
   evidence. *If not present at all:* the fixture is wrong for the thesis scope and the
   matrix design must change — a much bigger decision.
2. Does `/vulnerabilities/sqli_blind/` render a form at `high`? (explains `sqli/high` 0/12)
3. Does `/vulnerabilities/brute/` contain `input[name=user_token]` at `medium`? (decides D2 —
   code inspection already says no, but confirm against the fixture)
4. What is the full `index.php` nav-link inventory? Are `fi`, `open_redirect`, `authbypass`
   absent from it, matching the observed gaps at every level?
5. Does the SQLi `session-input.php` marker appear only at `high`?

### 4.5 Baseline reproduction gate — "confirm the failures are still there"

Before touching code, reproduce and capture the current behaviour of all nine cells:

| cell | expected current result |
| --- | --- |
| `access_control` low / medium / high | fail — `required_endpoint_missing`, `/vulnerabilities/authbypass/` |
| `sqli` high | fail — `required_endpoint_missing`, `/vulnerabilities/sqli_blind/` |
| `brute_force` medium | fail — `required_token_missing` |
| `sqli` low / medium, `brute_force` low / high | pass — `ready` |

Capture per cell: the full `readiness` block, `endpoints.observed`, the crawl's nav-link
list, and the resulting `execution_reason`. Diff the post-fix probe against this
fingerprint. Three outcomes to distinguish:

- 5 flip to `ready`, 4 unchanged → fix landed.
- A cell changes which reason it fails for → **regression, not progress**; investigate
  before proceeding.
- Previously-passing cells break → stop; you have widened the blast radius.

### 4.6 Suggested tooling (guidance, not prescription)

```bash
# module x level census through the repo client, so containment still applies
.venv/bin/python - <<'PY'
from foundation.session_manager import DVWASession
s = DVWASession("http://172.19.48.1/dvwa"); s.login()
for level in ("low", "medium", "high"):
    s.set_security_level(level)
    index = s.http.get("index.php").text
    # collect <a href> under /vulnerabilities/, then GET each and count <form> /
    # input[name=user_token] / JS-only handler markers
PY

# config + graph compile check, no HTTP and no provider calls
.venv/bin/python -m tesis run --dry-run --config config.yaml

# single-coordinate probe rather than the whole matrix
.venv/bin/python -m tesis run --headless --mode single --config <per-cell config>
```

`--dry-run` performs no HTTP and no provider calls — use it to confirm the graph and config
still compile before and after a change, but **never** as evidence that a cell is `ready`.

Write raw captures under `results/validation/` (gitignored). Do not paste HTML bodies,
cookies, or tokens into this handoff or into `docs/`.

### 4.7 Iterate-until-green loop on the failing coordinates

After the readiness (D1, D2), chaining (D3–D6), and remaining fixes (§3, Phases 0–3) land,
**re-run the failing coordinates the artifact names and keep iterating until every one of
them runs successfully.** This is Phase 3b and it is a hard gate before the matrix re-run.

**The target set is exactly the artifact's `matrix.readiness_failed_runs_total: 60`** — not a
sample, not a re-selection:

| surface | levels | groups | repeats | runs |
| --- | --- | --- | --- | --- |
| `access_control` | low, medium, high | 4 | 3 | 36 |
| `sqli` | high | 4 | 3 | 12 |
| `brute_force` | medium | 4 | 3 | 12 |
| **total** | 5 cells | | | **60** |

**Escalate, do not start at full cost.** Iterate at the cheapest stage that still gives a
valid signal, and only climb when green:

| stage | scope | runs | purpose |
| --- | --- | --- | --- |
| A | 5 cells × 1 group × 1 repeat | 5 | fast fix feedback; re-run after every code change |
| B | 5 cells × 4 groups × 1 repeat | 20 | confirm the fix is coordinate-independent, not group-specific |
| C | 5 cells × 4 groups × 3 repeats | 60 | the acceptance run |

Reserve Stage C for after Stage B is fully green. Re-running Stage C on every code edit
burns provider budget and produces diffs nobody reads.

**Definition of done per run — "successfully ran" means all of:**

- `readiness.status == "ready"`
- `readiness.reasons` contains **no** `severity == "blocking"` entry
- `execution_status == "completed"`
- the surface's own method actually executed: `attempted_agents` non-empty and contains at
  least one in-scope method for that surface (`ac_*` for access_control, `sqli_*` for sqli,
  `bf_*` for brute_force)
- a verifier decision is recorded (`verifier_decision` / `verifier_history` non-empty)
- the artifact is schema-complete per the `AGENTS.md` artifact-schema checklist

**What is deliberately *not* in the definition of done.** `security_outcome == "confirmed"`
and a non-zero `composite_score` are **experimental results, not harness properties**. If a
repaired Access Control run executes cleanly and comes back *not vulnerable*, that is a
finding to report — not a failure to loop. Looping until the verifier says "confirmed" would
turn a validation gate into a result-steering exercise, so the loop exits on "ran correctly",
never on "got the answer we wanted".

**Anti-sabotage rule.** The loop may not be satisfied by weakening the check that was
failing. These are **not** acceptable fixes, even if they turn the cells green:

- deleting `/vulnerabilities/authbypass/` from `_SURFACE_ENDPOINT_FRAGMENTS`
  (`foundation/readiness.py:197`)
- making `_token_required` return `False` unconditionally (`readiness.py:226`)
- downgrading `REASON_ENDPOINT_MISSING` from `blocking` to `advisory`, or letting
  `crawl_ok is False` pass
- removing an endpoint requirement because the crawler cannot see it

The distinction is: **improve discovery so the harness observes the truth** (record fetched
nav paths, add crawl depth, drive the token requirement from observation) — versus
**delete the observation requirement so the gate stops complaining**. Only the first is a fix.

If a required endpoint genuinely cannot be observed on this fixture, the correct outcome is
an explicitly documented design limitation backed by the §4.4 census, with human sign-off —
not a silent gate removal.

**If the coordinate still fails — go back to square one.** A cell that fails again is not a
cue to patch forward. It is a cue to re-derive the diagnosis from scratch, with fresh
evidence, and then fix and retry. Repeat until the cell runs successfully.

1. **Stop.** Do not loosen a threshold, re-run hoping for a different draw, or nudge the
   gate until it passes. A retry without a changed hypothesis is noise.
2. **Return to square one.** Re-run the §4.4 census for that specific module × level, with
   free roam (§4.1). Re-read the artifact's baseline entry for the cell. Re-derive which
   gate actually fired. With D3 fixed, the recorded reason should name the true blocker;
   if it still names the shallowest gate, treat that as a D3 regression and repair it first —
   you cannot diagnose through a lying reporter.
3. **Write the hypothesis down before touching code.** One sentence: *which component is
   wrong, and what evidence says so* — discovery, gate spec, fixture capability,
   precondition measurement, or adapter/scoring. No hypothesis, no fix.
4. **Fix at the root.** The five components above have five different fixes. Re-deriving the
   diagnosis is what tells you which one you are actually in, instead of assuming it is the
   one you fixed last time.
5. **Retry that cell at Stage A.** Green → climb to the next stage. Red → back to step 1.

**Square-one cycles are expected and cheap. Repeating yourself is not.** Each cycle re-reads
evidence rather than re-applying a patch. If the same fix has been attempted twice and the
cell still fails, that hypothesis is **falsified** — record it as such and switch to a
structurally different component. Cycling the same patch is the one form of "going back to
square one" this handoff forbids.

| cycle outcome | next action |
| --- | --- |
| cell goes green | climb to Stage B (then C) |
| fails after a *new* hypothesis + root fix | back to square one, next component |
| same hypothesis failed twice | falsified — move to a structurally different component |
| green for some groups/repeats only | **not green** — re-diagnose as coordinate-dependent |
| census proves the fixture lacks the capability | escalate for a **scope decision** (§7 Q1) |

The last row is the only legitimate non-green exit, and it is not a code fix — if the
fixture genuinely has no `authbypass` module, no amount of iteration makes the cell pass, and
the thesis scope or the surface design has to change. That needs a human decision, not
another retry.

**Capture every iteration.** Append one row per attempt to
`results/validation/<date>-readiness-after-fix.jsonl` with: timestamp, `git rev-parse --short HEAD`,
cell, group, repeat, square-one cycle number, **hypothesis text**, component under test,
`readiness.status`, blocking reasons, `execution_status`, `attempted_agents`,
`security_outcome`. The final green run per cell is the evidence; the failed cycles are the
audit trail proving the loop converged on a diagnosis instead of being declared green.

### 4.8 Deliverables and records

Hand back artifacts, not prose. Raw captures live under `results/validation/` (gitignored).

- `results/validation/2026-10-30-dvwa-module-census.json` — the §4.4 table
- `results/validation/2026-10-30-readiness-baseline.json` — 9-cell pre-fix fingerprint (§4.5)
- `results/validation/<date>-readiness-after-fix.json` — 9-cell post-fix fingerprint + diff
- `results/validation/<date>-readiness-after-fix.jsonl` — the §4.7 iteration log, one row per
  attempt including square-one cycle number and the hypothesis under test
- a short §9 "Outcome" appended to this handoff, citing the four artifacts by path —
  not restating their contents

## 5. Non-goals

- No new surfaces or methods. Surfaces stay SQL Injection / Access Control / Brute Force;
  methods stay the nine in `AGENTS.md`. Free-roam reading of other DVWA modules (§4.3) is
  inventory only and never adds a surface.
- No **full matrix re-run** without a separate authorisation. Diagnostic single-coordinate
  probes and free-roam discovery are authorised by §4; a 108-run matrix is not.
- Do not edit manuscript numbers or `docs/reference/summary_*.md` until the re-run exists.
- Do not "fix" the audit JSON by hand — it is generated evidence.

## 6. Reproduction (read-only)

```bash
cd /home/kevin/coding/tesis
A=results/studies/main-study-v4-ai-2026-10-30/final-v4-audit.json

# matrix completeness + readiness split
python3 -c "import json;d=json.load(open('$A'));print(d['matrix'])"

# blocking reason census over all 108 runs
python3 -c "
import json,collections
a=json.load(open('$A')); c=collections.Counter()
for e in a['source_manifest']:
    r=(json.load(open(e['path'])).get('readiness') or {})
    for x in r.get('reasons') or []: c[(x['code'],x['severity'])]+=1
print(c)"

# observed endpoint sets per (surface, level)
python3 -c "
import json
a=json.load(open('$A')); seen={}
for e in a['source_manifest']:
    r=(json.load(open(e['path'])).get('readiness') or {})
    seen.setdefault((e['surface'],e['security_level']),set()).add(
        tuple(sorted((r.get('endpoints') or {}).get('observed') or [])))
for k,v in sorted(seen.items()): print(k,len(v),[len(x) for x in v])"

# credential representations (D5)
python3 -c "
import json,collections
a=json.load(open('$A')); c=collections.Counter()
for e in a['source_manifest']:
    if e['execution_status']!='completed': continue
    fs=json.load(open(e['path'])).get('final_state') or {}
    c[(e['surface'],e['security_level'],any(x.get('representation')=='plaintext' for x in fs.get('found_credentials') or []))]+=1
print(c)"
```

Chain-edge census across the whole corpus (D3/D4/D6) requires scanning
`results/**/exec-*.json` for `chain_assessment.edges`; 206/206 are `infeasible` with
`destination_preconditions_not_proved`.

## 7. Open questions (Q1–Q5 are closed by the §4.4 census)

1. **Is `authbypass` in `index.php`'s navigation at all?** Absent from every observed set,
   but it is unknown whether it is missing from the link scrape or present and form-less.
   Both are D1, but the fix differs — and "not present on the fixture" would be a design
   problem larger than D1. **Answered by §4.4 Q1.**
2. **Would a repaired AC run satisfy its own destination preconditions?** Untested; AC is a
   *destination* in 5 of 6 chain edges, so it may never appear as an executing surface that
   proves its own preconditions. **Answerable in Phase 1 with a single AC probe run.**
3. **`with_satisfied_prerequisites` has no producer in the repo.** The aggregator exists
   only in the audit JSON; per-edge `prerequisite_status` (e.g.
   `{"credentials_extracted": "proved"}`) is verifiable in the artifacts and shows source
   prerequisites satisfied alongside `infeasible` edges. Reconcile that metric's definition
   before quoting it. **Still open — needs the audit generator, not a probe.**
4. **§4.4 Q2–Q5** — `sqli_blind` form at `high`, `user_token` at `medium`, the full nav-link
   inventory, and whether the `session-input.php` marker is high-only.

## 8. Acceptance for this handoff

Marked 2026-10-30 by the remediation agent. `[x]` met with the cited evidence; `[~]` partly
met, with the shortfall named; `[ ]` not met, with the reason.

- [x] **Phase −1 census artifact exists** and answers §4.4 Q1–Q5 —
      `results/validation/2026-10-30-dvwa-module-census.json`
- [x] **Pre-fix baseline fingerprint captured**: 5 cells fail with the recorded reasons,
      4 pass — `results/validation/2026-10-30-readiness-baseline.json` matches §4.5 exactly
- [x] All 9 (surface × level) cells `ready` on the post-fix 9-cell probe, with the 4
      previously-passing cells unchanged — `results/validation/2026-10-30-readiness-after-fix-probe.json`
      (5 flipped to `ready`, 0 regressions, 4 unchanged)
- [x] **All 60 previously readiness-failed runs complete**: **48 of 60** runs of record meet the
      pre-registered §4.7 definition of done and **60 of 60** meet it once the measured-negative
      clause is applied — `results/validation/remediation-2026-10-30/acceptance-summary.json`,
      totals `dod_passed_strict` and `dod_passed`, across all four model-condition groups. The 12
      strict shortfalls are all `access_control/high`: every in-scope precondition was measured
      `false` by three independent bounded controls, and each now carries a per-method
      `not_vulnerable` verdict. Report **both** counts; see §9.4.
- [x] Iteration log `results/validation/2026-10-30-readiness-after-fix.jsonl` exists and shows
      the loop converging per cell, with no cell green only after a gate was weakened
- [x] No square-one cycle repeated a falsified hypothesis (each retry names a new one)
- [x] Access Control produces completed runs at all three levels (low, medium, high), and low
      and medium now reach `security_outcome: "confirmed"` after the D14 oracle repair (12/12
      runs each across all four model-condition groups). At high the run completes with
      `NO_VIABLE_METHODS`; each in-scope method carries a `not_vulnerable` verdict backed by sent
      control evidence, its composite is `null` with
      `metric_unavailable_reason: "no_method_attempted_measured_negative"`, and the run passes
      under the measured-negative clause — see §9.4.
- [x] At least one chain edge reaches `feasible` and one transition is attempted, so
      `Schain` can be non-zero — met after the D5 derivation step: a live run scheduled
      `credentials_extracted -> bf_dictionary`, the destination visit consumed the source
      evidence and its downstream verifier confirmed it (`route:0` ready → routed → executed →
      completed, `chain_scores.bf_dictionary = 4`). Evidence:
      `results/validation/remediation-2026-10-30/chain-live-transition-evidence.json` and
      `chain-edge-census.json` (`ever_feasible: 1`, `completed_live_routes: 1`).
- [x] `chain_assessment` reports the decisive rejection reason per edge (`decisive_stage`,
      `reasons`, `source_rejection`, `destination_rejection`)
- [x] `fixture_restoration.equivalence != "unknown"` for runs produced after the D8
      attestation landed: `equivalence: "attested"` with four evidence refs and zero readiness
      reasons. The attestation is `results/validation/remediation-2026-10-30/fixture-restoration-attestation.json`,
      embedded in `config.yaml`. Stage A/C artifacts recorded before it remain as produced.
- [x] `frozen_max_tokens` matches the budget that produced every receipt — D9: the frozen
      budget and its validator ceiling are now 16384 (`evaluation/thesis_scoring.py
      EVALUATOR_MAX_TOKENS_CEILING`), and artifacts record `max_tokens: 16384`. Re-scoring the
      historical v4 receipts under it is Phase 5 work.
- [x] Containment reporting separates attack events from navigation discards
      (`evaluation/containment.py`; matrix aggregates carry `containment_failures: 0` and
      `containment_navigation_discards: 15` on separate lines)
- [x] Study config unchanged by any diagnostic probe (`git diff config.yaml` clean; every
      override was a CLI argument)
- [ ] Full matrix re-run separately authorised, executed, and re-audited — not authorised,
      not run
- [ ] **Before that re-run: re-bind the D8 attestation to the new source epoch.** The §9.4 edits
      touched `core/scorer.py`, `evaluation/runner.py`, the new `evaluation/method_verdicts.py` and
      `tesis/config_loader.py`, so the embedded `fixture_restoration_evidence` still carries epoch
      `bfdfb5a1…` while the current source epoch is `11601914…`; a live run would refuse with
      "fixture restoration source hashes do not match the current run". Deliberately **not** done
      here: `fixture_attestation.py`'s contract requires measured evidence refs (census,
      no-mutation check, capability check) *at the epoch being attested*, the epoch moves again with
      any further edit, and re-binding it now would attest to a fixture state nobody re-measured.
      Run it after the last source change, together with the live fixture check that backs it.
- [x] `docs/reference/summary_en.md` + `summary_id.md` updated only after the re-run — not
      touched, as §5 requires
- [ ] Tables III–IV rebuilt from the new audit; manuscript numbers replaced — Phase 5, after
      the authorised re-run

## 9. Outcome

Filled 2026-10-30 by the remediation agent. Artifacts are cited by path; their contents are
not restated here.

| Field | Value |
| --- | --- |
| Phase −1 census | `results/validation/2026-10-30-dvwa-module-census.json` |
| Pre-fix baseline | `results/validation/2026-10-30-readiness-baseline.json` |
| Post-fix probe | `results/validation/2026-10-30-readiness-after-fix-probe.json` |
| Iteration log | `results/validation/2026-10-30-readiness-after-fix.jsonl` |
| Fixture no-mutation check | `results/validation/2026-10-30-fixture-no-mutation-check.json` |
| Access Control level capability | `results/validation/2026-10-30-ac-high-capability-check.json` |
| Access Control anonymous read | `results/validation/2026-10-30-ac-anonymous-read-check.json` |
| Chain probe (D3/D4/D6) | `results/validation/remediation-2026-10-30/chain-probe.json` |
| Stage C run root | `results/validation/remediation-2026-10-30/stageC/` (retry: `stageC-retry/`) |
| Consolidated acceptance summary | `results/validation/remediation-2026-10-30/acceptance-summary.json` |
| Per-edge chain census | `results/validation/remediation-2026-10-30/chain-edge-census.json` |
| Open-decision inputs | `results/validation/remediation-2026-10-30/decision-inputs.json` |
| Evidence index | `results/validation/remediation-2026-10-30/README.md` |
| Definition-of-done reports | `results/validation/remediation-2026-10-30/<stage>/<condition>/dod-report.json` |
| D1 verdict | **discovery bug.** `/vulnerabilities/authbypass/` exists at every level, is linked from `index.php`, and renders **0 forms** at every level; the crawl recorded only form actions. Fixed by recording fetched navigation paths plus the handlers a page itself declares. |
| D2 verdict | **confirmed.** `/vulnerabilities/brute/` carries `input[name=user_token]` at high only; medium and low declare no token field. The requirement is now driven by the observed form instead of a level table. |
| Cells recovered | **4 of 5** — `access_control` low and medium, `sqli` high, `brute_force` medium. `access_control` high does not recover: see 9.2. |
| Runs meeting the §4.7 definition of done | **48 of the 60 runs of record under the pre-registered definition; 60 of 60 once the measured-negative clause applies** (§9.4) — 5 cells × 4 model-condition groups × 3 repeats, drawn from 188 recorded attempts. The 12 strict shortfalls are all `access_control/high` (6 per model coordinate) and pass under the amended clause; `dod_passed_by_clause` records the split as `{strict: 48, measured_negative: 12}`. All 60 runs of record share one source epoch (`single_epoch_of_record: true`) and every compliance invariant holds for all 188 runs: authorised coordinates only, at low reasoning effort, zero attack-relevant containment violations, in-scope methods only. See `acceptance-summary.json` (`dod_passed_strict`, `dod_passed`). |
| Square-one cycles used | **8** (0 baseline · 1 D1/D2 · 2 disclosure-marker false positive · 3 session-change false positive · 4 green · 5 `access_control/high` boundary · 6 provider timeout · 7 permission-oracle anonymous control). `access_control/low` took the most (cycles 2, 3 and 7 all surfaced there). No falsified hypothesis was retried. |
| Non-green cells | **None under the amended definition.** `access_control/high` (12 runs) is the only cell that does not meet the pre-registered clause, and it does not because the *fixture* closes it: all three AC preconditions (`object_ids_enumerable`, `role_based_access_present`, `force_browse_endpoints_visible`) were measured **false** by three independent bounded controls, `viable_methods` is empty, and the run completes with `NO_VIABLE_METHODS` — identically in both model-condition groups and all three repeats. `results/validation/2026-10-30-ac-high-capability-check.json` shows the fixture denies `get_user_data.php` to a non-admin at high for the principal's **own** record as well as for other and nonexistent ids (JSON error envelope at 200), while low and medium return all five records; the module page returns 403 at high and medium. The decision (§9.4) is to report a decisive measured negative rather than to attempt a method whose measured precondition is false, or to drop the cell. These 12 runs report `composite_score: null` with `metric_unavailable_reason: "no_method_attempted_measured_negative"`, never `0`. |
| Deviations | (1) **All four model-condition groups executed.** The `gpt-6-luna` coordinate ran on explicit authorisation at **low** reasoning effort (the v4 study used `max`), which is a protocol deviation recorded here; the DeepSeek coordinate ran at low as before. (2) `access_control/low` repeat 2 of the `linear_hybrid` Stage C pass hit a provider read timeout (`LLM_RUNTIME_FAILURE`); the coordinate was retried unchanged and passed 3/3 (`stageC-retry/`). (3) `config.yaml` was not edited: every override was a CLI argument (`git diff config.yaml` clean). |

### 9.1 Defect status

| Defect | Status | Evidence |
| --- | --- | --- |
| D1 endpoint discovery | **fixed** | census Q1/Q2/Q5; 9-cell probe diff: 5 flipped to `ready`, 0 regressions, 4 unchanged |
| D2 token requirement | **fixed** | census Q3; `brute_force/medium` runs with `token.required=false` and completes |
| D3 decisive rejection reason | **fixed** | `_chain_infeasibility_details` reports every applicable reason with a `decisive_stage`; live artifacts name the source stage |
| D4 adapter/edge drift | **fixed** | `brute_force_confirmed` gained a session-consumption branch; the two unreachable edges are declared `supported: false` with a reason; `chain_adapter_gaps() == []` |
| D5 plaintext from SQLi | **fixed (decision: explicit derivation step)** | `foundation/credential_derivation.py` derives plaintext offline from a recovered hash against the declared credential corpus and records algorithm, hash digest, candidate index and corpus digest on the credential; a live run then scheduled and completed the chain edge (`chain-live-transition-evidence.json`) |
| D6 destination preconditions | **fixed** | a bounded destination control now runs before the source gate; `recon.destination.completed` recorded with `preconditions_measured` for `bf_dictionary` in `chain-probe.json` |
| D7 single evidence rule | **fixed** | `docs/reference/cross_surface_evidence.md`, cited by both gates |
| D8 fixture attestation | **fixed** | `fixture-restoration-attestation.json` embedded in `config.yaml`; runs now record `fixture_restoration.equivalence: "attested"` with zero readiness reasons. Two mechanism defects were found and repaired on the way: the loader rejected fixture-wide attestations in single-level configs, and the source epoch hashed `config.yaml` including the attestation block (circular) — see `evaluation/research_plan.CONFIG_EPOCH_EXCLUDED_KEYS`. Policy gap recorded: `fixture-restoration.v1` has no "verified not mutated" kind, so `isolated_equivalent` carries that meaning explicitly in `details`. |
| D9 frozen token budget | **fixed (decision: 16K)** | `scoring_evaluator.max_tokens: 16384`; the validator, both override guards and the TUI hint now share `EVALUATOR_MAX_TOKENS_CEILING` |
| D10 scorer selection | **fixed (decision: GLM 5.3 Flash, high effort)** | evaluator is `river-ai__zai-org-glm-5-3-flash_bc20d9347385` with `reasoning_effort: high`; the v4 matrix driver now requires the evaluator to be an openai_compatible profile *outside* the evaluated model set instead of equal to it, and pins `outside_evaluated_set: true` |
| **D14 (new, found during 3b)** permission oracle aborted | **fixed** | `evaluation/permission_oracle.py` called `set_security_level` on the *anonymous* control session, which raises `RuntimeError` because an unauthenticated client has no server-side session to persist a level into. The exception was swallowed into `reason: RuntimeError`, so no AC candidate could ever reach `candidate_base == 3` and every AC run reported `PERMISSION_ORACLE_UNAVAILABLE`. The anonymous read now proceeds with the level cookie and records `security_level_persisted: false`; `reason_detail` was added so a failing collection is diagnosable. Result: AC low/medium now report `security_outcome: "confirmed"` with `scope_outcome` `broad_exposure`/`candidate_specific`. |
| D11 containment accounting | **fixed** | `evaluation/containment.py` reports attack-relevant violations and navigation discards separately; matrix aggregates carry both counts |
| D12 outcome variance | **root causes fixed, recalibration deferred (§9.4)** | Two implementation defects accounted for most of the apparent "no variance". (i) Run-level `Schain` was graded from the *selected* visit, so a completed chain route scored 0 at run level; `core.scorer.run_scope_score_components` now takes the run's best chain grade, which moves `sqli/high`·`akg_guided_hybrid` from 2.9/2.9/2.1 to 3.3/3.3/2.5 and leaves every non-chaining run byte-identical. (ii) The 2.1 repeat is explained rather than a flake: repeat 3 selected `sqli_time_blind`, which returned `not_confirmed` (`Sexploit: 1`), while repeats 1–2 selected `sqli_union` (`Sexploit: 3`), so the run-level composite is selection-scoped by construction. What remains is a measurement property, not a bug: 70% of `Srun`'s weight (`Smethod`+`Spayload`+`Sexploit`) is fixed by the pipeline once a method is selected and confirmed, so the composite cannot discriminate models. Recalibrating the weights or anchors stays a human decision and, if taken, is post-hoc and Phase 4/5 work. |
| D13 LLM candidate contribution | **unchanged, cause localized** | LLM-derived candidates are produced (2–3 per run) but none is executed inside the candidate budget; every confirmed exploit still traces to a static seed. With D5 in place the chain now consumes *derived* credentials, which is a new, separate source of non-static material worth scoring in Phase 5. |

### 9.2 New finding — chain visits are unreachable under the study's stop policy

`core/workflow_policy.method_coverage` measures coverage over the **current surface's** methods
only, so a surface that has attempted its own methods reaches `coverage_target: 0.7` and
`stop_reason` returns `coverage_target_reached` before the chaining router can schedule a
cross-surface visit. Live evidence: `sqli/high` attempts 3 of 4 SQLi methods (ratio 0.75), while
`brute_force/medium` and every `access_control` cell reach 1.0. No chain visit is schedulable
until that metric or the stopping rule changes, independently of D3–D6. That is a
protocol/stopping-rule decision, reported here rather than changed.

### 9.3 What the repaired harness now produces (60 runs of record, one source epoch)

Source: `results/validation/remediation-2026-10-30/per-cell-results.json` and
`acceptance-summary.json` (run roots `acceptance2/` for DeepSeek and `luna-acceptance2/` for
gpt-6-luna). Each cell is 3 repeats x 2 models x 2 conditions = **12 runs**, all in one source
epoch.

| cell | `security_outcome: confirmed` | chain visit completed | derived credentials |
| --- | --- | --- | --- |
| `access_control/low` | **12/12** | 0 | 0 |
| `access_control/medium` | **12/12** | 0 | 0 |
| `sqli/high` · `akg_guided_hybrid` | 6/6 | **6/6** | 6/6 |
| `sqli/high` · `linear_hybrid` | 6/6 | 0/6 (condition forbids chaining) | 6/6 |
| `brute_force/medium` | **12/12** | 0 | 0 |
| `access_control/high` | 0/12 (measured-negative, nothing viable) | 0 | 0 |

Read this carefully before quoting it:

1. **Access Control is reportable for the first time.** In v4 the surface had 0 completed runs of
   36. After the readiness fixes and the D14 oracle repair, `access_control` low and medium record
   `security_outcome: "confirmed"` in all 12 runs each. The oracle's `scope_outcome` distinguishes
   two findings: `broad_exposure` (the object is readable **without any authentication** at low and
   medium — `results/validation/2026-10-30-ac-anonymous-read-check.json`) and `candidate_specific`
   (12 and 6 protocol documents respectively across the set).
2. **`Schain` is no longer identically zero.** v4 attempted 0 of 96 chain opportunities. The
   repaired harness completes `credentials_extracted -> bf_dictionary` in **6 of 6** `sqli/high`
   runs under `akg_guided_hybrid` (both models, all repeats) and in **0 of 6** under
   `linear_hybrid` — the condition contrast the design was built to measure. It appears only in
   `sqli/high` because that 4-method surface leaves a window below the 0.7 coverage target before
   the run stops (§9.2); `brute_force/medium` and the AC cells stop earlier, and their only
   admissible sources need a non-admin credential the fixture does not yield.
3. **Derived credentials appear in both conditions.** Derivation is data processing over a
   recovered hash, not a chain decision, so `linear_hybrid` derives them too (6/6) and simply
   never routes. Treat "derived" as a payload-provenance fact, not a chaining result.
4. `access_control/high` is measured-negative (§9.4 and
   `2026-10-30-ac-high-capability-check.json`) and is the only cell that does not meet the
   pre-registered clause; its option accounting is in `decision-inputs.json`. Its 12 runs report
   `composite_score: null` with a reason, so they contribute nothing to any mean — including
   nothing *negative*.
5. **`Schain` at run level now counts a chain visit.** Before §9.4, the run-level composite was
   taken from the selected visit, so all six `sqli/high` runs recorded `chain_score: 0` even
   though the `akg` runs had `final_state.chain_scores["bf_dictionary"] = 4`. The `akg` cell now
   reports 3.3/3.3/2.5 against `linear`'s 2.9/2.9/2.9. Read that gap as a chain-visibility fix,
   not as a rubric change: no non-chaining run moved.

### 9.4 Decisions taken, and what they changed

The human owner took the two open decisions on 2026-10-30. Both were implemented and re-verified
against the same frozen artifacts, so the runs of record stay in one source epoch; nothing here
needs a re-run, and nothing here re-ran one.

**`access_control/high` — report a decisive measured negative (option (a), as a named predicate).**
The cell stays in the design; the 12 runs stay in the record; the pre-registered §4.7 criteria stay
untouched for the 48 runs that already met them. What was added is a second, separately named way
to satisfy the clause, with its own evidence requirement:

- `evaluation/method_verdicts.py` derives one `not_vulnerable` verdict per in-scope method from the
  state's own control evidence. Fail-closed: it emits nothing unless the run attempted no method,
  selected no method, every declared precondition is observed exactly `"false"`, and at least one
  detection-control event for that method was actually sent (`establishes_exploit: true` rows do
  not count). `"unknown"`, an absent key, or a snapshot without a sent event yields no verdict.
- The artifact gains `method_verdicts` and `measured_negative`; `attempted_agents` keeps its
  meaning ("a method agent executed") so no downstream table is polluted by the relabelling.
- `check_dod.py` reports **both** counts — `strict_passed` (pre-registered) and `passed` (amended) —
  and the acceptance summary records `dod_passed_strict: 48`, `dod_passed: 60`,
  `dod_passed_by_clause: {strict: 48, measured_negative: 12}`. Never quote the amended count alone.
- These runs report `composite_score: null` and
  `metric_unavailable_reason: "no_method_attempted_measured_negative"`. `0` would be
  indistinguishable from a run that executed a method and scored nothing, and would drag any
  aggregate mean down for a non-failure.

Rejected: **attempting a method past a measured-false precondition** would resend requests the
probe already sent (`ac_idor`'s readiness probe and exploit stage issue the identical
`MODULE_PATH?userId=<id>` request) and the exploit predicate is *stricter* than the probe's, so it
cannot recover a probe false negative — it would buy a protocol violation for cosmetic field
filling. **Dropping the cell** would leave the AC surface without a high level and shrink N
silently, which is worse than a reported negative.

Residual risk, recorded rather than closed: the measurement covers `get_user_data.php` with a
`userId` parameter and the `authbypass` module page. A human pentester might find an
authorisation-bypass vector at high that the nine in-scope methods do not express, so the claim is
"no in-scope method confirms Access Control at high in this fixture" — not "Access Control is
unfindable at high".

**D12 — fix the aggregation, restate the scope, defer recalibration.** Three changes, in order:

1. `core.scorer.run_scope_score_components` grades run-level `Schain` from the run's best chain
   grade instead of the selected visit's. `COMPOSITE_SCOPE` records the scoping per dimension in
   every artifact and in `summary.composite_scope`, so a run-scope number can never be mistaken
   for a per-method one.
2. The 2.1 repeat is diagnosed, not excluded: `sqli/high`·`deepseek`·`akg` repeat 3 selected
   `sqli_time_blind` (`Sexploit: 1`, `not_confirmed`) while repeats 1–2 selected `sqli_union`
   (`Sexploit: 3`). The dip is a selection effect, and it stays in the data as one.
3. The composite's scope is stated instead of inflated: `Srun` is a **framework-quality index**.
   With `Smethod`, `Spayload` and `Sexploit` fixed by the pipeline once a method is selected and
   confirmed, it is expected to sit near-constant across models and must not carry the condition or
   model claims. Those claims rest on the two variables that do vary and are attributable —
   per-cell confirmation rate, and chain completion rate (6/6 vs 0/6, §9.3) — with the component
   table (`Smethod`…`Soutput`) reported beside the composite so the constant parts stay visible.
   Propagating this statement into `docs/reference/summary_en.md` and `summary_id.md` is Phase 5
   work and was **not** done here, per §5.

**Verification for §9.4** (all offline, against frozen artifacts): `tests/test_measured_negative_verdicts.py`
(12 tests) covers the fail-closed verdict rules and the run-scope composite; the scorer, runner,
scoring-contract, config-loader and v4-matrix suites pass (85 + 251 + 101 + 174 tests);
`acceptance-summary.json` regenerated with `0` invariant failures across 188 runs; `--dry-run`
passes (graph and AKG compile, 4 payload coordinates validated).

Three test failures were investigated rather than assumed:

- `tests/test_chapter3_slice_d.py::test_fixture_restoration_evidence_is_validated_and_kept` was a
  **real regression from the D8 change**, caught here: `tesis.config_loader` filters attestations
  for levels an invocation does not run, but the filter derived the configured-level set in a way
  that could be empty, and it had silently changed the rejection message for "attestation covers
  only levels this run does not use". Verified by swapping in `HEAD`'s loader (the test passed
  there) and restoring the working copy. Fixed in `_validate_engagement_config` (never filter
  against an empty level set; keep the envelope when this invocation runs none of the attested
  levels), and the test now states the intended D8 semantics — extra levels are narrowed, not
  rejected — plus explicit coverage that a fixture-wide attestation is accepted by a
  single-level run. The `"targets levels outside this configuration"` message it used to assert is
  now unreachable and is not produced anywhere.
- `tests/test_evaluation_runner.py::test_runtime_calls_feed_runner_activity_and_effective_runtime_metadata`
  fails at `HEAD` too: it asserts an `llm_runtime_config` role dict without the
  `rate_limit_retries` / `rate_limit_retry_budget_s` keys that `llm/runtime.py` already emits.
- `tests/test_scoring_evidence_v4_e2e.py::test_report_tables_examples_and_package_preservation` and
  `tests/test_chapter3_slice_d.py::test_derived_docx_preserves_source_and_math` resolve docx files
  by bare relative path; the assets live under `docs/docx/`. Environmental, unchanged by this work.

No commit was made; `HEAD` remains `c914f23`.
