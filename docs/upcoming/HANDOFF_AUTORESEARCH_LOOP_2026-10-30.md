# Handoff — autoresearch loop: harness self-improvement without benchmaxing

**Date:** 2026-10-30
**Status:** proposed — not started. No code change, no run, and no authorisation is implied by
this document, **with one exception:** the single 60-run epoch recorded in §11 (Q4, 2026-10-31).
That authorisation covers that one epoch only, only once §11.1's preconditions hold, and is spent
when the epoch completes.
**Baseline artifacts:** `results/validation/remediation-2026-10-30/full-2026-10-30/` (60 runs,
one source epoch `b4909695…`, all `execution_status: completed`)
**Target set for the loop:** the **48 scored runs** — `access_control/{low,medium}`,
`brute_force/medium`, `sqli/high` × 2 models × 2 conditions × 3 repeats.
**Explicitly skipped:** `access_control/high` (12 runs). See §9.2.
**Deliverable:** a **new epoch** that is gradeable on all five dimensions. The 2026-10-30 epoch is the
**baseline**, reported as a four-dimension partial; no step in this document attempts to recover
`Smethod`/`Srun` for it. §0.1 restructures the workflow around that split so that every step in it has
a reachable end state.
**Owner:** unassigned
**Decisions answered 2026-10-31 (recorded in §11, not repeated as questions):** **Q0** — build the
`scoring_profile`; **Q0b** — publish a four-dimension partial and plan a new epoch; **T7** — all
four config blocks; **Q4** — one 60-run epoch authorised. Still open, and needed only before the
result tables: §11 Q1, Q2, Q3, Q5, Q6. **Parked ambiguity:** §11.2 A1 (what `Smethod` measures for the
2026-10-30 epoch) — contested, unresolved, and not blocking phases A or B.
**Re-prioritised 2026-10-31:** the loop's first deliverable is **score-artifact reporting**,
not the fidelity ledger — see *Priority 0* below. The reported score must come from the
graded thesis rubric (`Tabel 3.5–3.11`), not from the runtime `composite_score`.

---

## Priority 0 — the reported score comes from the wrong scorer

**Added 2026-10-31 after reading `docs/docx/bab-3-reconciled-2026-10-29.docx`.** This outranks
every phase below. The loop's first deliverable is not a ledger and not a code fix: it is making
the artifact report **the score the thesis actually defines**.

**The thesis rubric is graded, and it is thorough.** Tabel 3.5–3.11 specify five 5-level ladders
(0–4), each with a criterion, an evaluation mechanism (nearly all "otomatis"), and an example
condition — plus two explicit non-score statuses: *belum dapat dinilai* (required evidence
missing) and *tidak berlaku* (out of scope for that measurement). `Spayload` is an **arithmetic
mean over executed eligible candidates**, not a maximum.

| dim | 0 | 1 | 2 | 3 | 4 |
| --- | --- | --- | --- | --- | --- |
| **Smethod** | outside the surface | prerequisites known false | viable, but a higher-fit/cheaper method existed | top-ranked | top-ranked **and** reason + plan verified |
| **Spayload** | invalid, or executed + verified negative | early signal only | partial proof, no independent control | success confirmed with candidate + independent control | result **reused downstream** |
| **Sexploit** | verified negative with control | early indication | partial result | confirmed by verifier + independent reference | confirmed **and** used downstream |
| **Schain** | no AKG-consistent opportunity | source/prereqs incomplete | source + prereqs proven, destination unconfirmed | one verified hop | **two+ causally linked** hops |
| **Soutput** | unusable, no recovery / scope violation | **only a static fallback was usable** | usable after recorded retry/repair | valid, no repair, references incomplete | valid, references + provenance complete |

**That rubric is already implemented** — in `evaluation/scoring_evidence.py`, not in the run path:

| function | line | what it grades |
| --- | --- | --- |
| `selection_grade` | 350 | `0` outside surface · `1` prereq false · `None` unknown · `2` higher-ranked exists · `3` top · `4` when `reason_refs` + `plan` are valid (line 398) |
| `automatic_components` | 1069 | `Sexploit` = `max(base_proof)`, raised to `4` when a verified dependency consumed the source (line 1078) |
| `chain_grade` | 620 | `4` two linked hops · `3` one hop · `2` prereqs proven · `1` weak opportunity · `0` — identical to Tabel 3.10 |
| `output_grade` | 934 | `0` containment · **`1` static-fallback credit** · `2` retry/repair needed · `3` valid but references incomplete · `4` references + provenance complete |

**But the artifacts report a different implementation.** `composite_score` and
`composite_components` in every run are written during execution by `agents/state_utils.py` +
`core/scorer.py` from five capped state keys (§1.2). The graded path runs only in the post-hoc
thesis evaluation, which **has never been run for this matrix** — `thesis_scoring_status:
pending_review` in all 60 artifacts.

**Same artifacts, two answers** (`review_queue(<artifact>)`, offline, zero provider calls):

| run | runtime `composite_components` | graded v4 `components` |
| --- | --- | --- |
| `deepseek / akg / access_control-low` | Smethod `3`, Spayload `2`, Sexploit `3`, Schain `0`, Soutput `4` | Smethod **`None`**, Sexploit `3`, Schain `0`, Soutput **`3`** (four keys only — `review_queue` does not emit `Spayload`; it comes from review decisions) |
| `luna / akg / sqli-high` (chain run) | Smethod `3`, Spayload `3`, Sexploit `3`, Schain **`4`**, Soutput `4` | Smethod **`None`**, Sexploit `3`, Schain **`0`**, Soutput **`3`** |

Run over the whole ring: `python` + `review_queue` on all 60 artifacts, offline, zero provider
calls, result at `results/validation/2026-10-31-graded-thesis-components.json`:

| dimension | graded distribution (n=60) | what it means |
| --- | --- | --- |
| `Smethod` | **`None` × 60** (48 `ranking_unavailable`, 12 `missing_selection_snapshot`) | `scoring_profile` is empty, so selection is ungradeable and `Srun` does not exist |
| `Sexploit` | `3` × 48, `None` × 12 (`no_eligible_candidate`) | agrees with the runtime on the scored runs |
| `Schain` | **`0` × 60** | wrong — 6 runs have a verified chain (see below) |
| `Soutput` | **`1` × 4, `3` × 44, `None` × 12** | the runtime said `4` on 43 of those 44, and `3`/`2` on the four it now grades `1` |

Four consequences:

1. **`Soutput` is inflated across almost the whole matrix.** 43 runs graded `3` where the runtime
   said `4` (Tabel 3.11 level 4 needs `output_references_valid` on every call; the stored receipts
   do not satisfy it), and 4 runs graded `1` — "execution depended on a static fallback" — where
   the runtime said `3` or `2`. That is **0.20–0.40 of runtime inflation in 47 of 48 scored runs**.
2. **`Schain` is a real defect, and it is a scope mismatch.** All 6 chain runs
   (`akg × sqli/high`, both models) credit the chain to `bf_dictionary` while the selected method is
   `sqli_time_blind`. The graded receipt is built for **one** method (`thesis_scoring.py:336`), so a
   run-scoped dimension is being graded per method: measured on one chain run,
   `chain_grade(sqli_time_blind)=0`, `sqli_union=2`, `bf_dictionary=0`. The runtime grades `Schain`
   at run scope (`COMPOSITE_SCOPE`), so this is a **scope decision before it is a filter fix** (G5).
3. **`Smethod` is `None` on the graded path** because `config.scoring_profile: {}` →
   `ranking_unavailable`. By Tabel 3.5 (`Jika profil … belum tersedia, Smethod dan skor akhir
   Srun belum dapat ditetapkan`) that makes **`Srun` undefined — not `2.70`**.
4. **`Soutput = 1` is implemented and correct.** It comes from the per-group credit branch at
   `scoring_evidence.py:1012–1019` (`_fallback_credit` on a bound `payload_generation.static_seed_fallback`),
   *not* from `grades = [1] * len(fallback_only)` at `:1008` — that list was empty in all four runs.
   The four runs it applies to are `deepseek` runs where the model candidate was rejected by payload
   validation and only static seeds executed: Tabel 3.11 level 1, substantively right.

**The honest first step makes the headline number worse.** With an empty `scoring_profile`,
graded `Srun` is `null` for all 48 scored runs, each with a recorded reason. That is the rubric
working as specified, and it is the result to report. Sequence:

| step | work | authority |
| --- | --- | --- |
| **T1** | Report graded components + `component_pending_reasons` in every table instead of `composite_score`; keep the runtime vector only as an explicitly-labelled legacy field | **free** — reporting change, no run |
| **T2** | Decide what `Schain` is scoped to. The receipt grades one method while the rubric and the runtime grade the run. Measured: selected `sqli_time_blind` → `0`, source `sqli_union` → `2`, destination `bf_dictionary` → `0`; destination attribution alone yields `0`, and `3` needs G4a repaired. **This is a scope decision before it is a filter fix** | **free** to analyse; the change is a rubric reading (G5) |
| **T3** | `Soutput`: 47 of 48 scored runs disagree with the runtime. The cap is now known — 41/48 graded receipts have no `reason_refs`, 7/48 have unresolvable ones, and level 2's retry gate is dead (G18). Fix G18, decide G19 (only the last receipt is graded), then re-grade | **free** for G18; G19 is a rubric reading |
| ~~**T4**~~ | ~~Add `verified_permission_candidate: 3` to `PROOF_TIERS`~~ — **dropped**: AC already reaches `Sexploit 3` through the permission oracle, and the table tier is clamped at 2 regardless. The real AC issue is G21 (tier 2 self-granted by the agent's own boolean) | retracted by cross-check |
| **T5** | Freeze a `scoring_profile` per surface × level so `Smethod` — and therefore `Srun` — exists at all | **Q0 answered 2026-10-31: build it.** Authoring the 15 entries blind is the remaining work; reachability is proven offline by stages B1–B3 (§0.1) before any live run |
| **T6** | Decide who scores `Spayload` (frozen evaluator or human) and cost it | **Q4 answered: one 60-run epoch.** Scoring route still to pick |
| **T7** | Clear the four config blocks that stop a frozen plan: `repeats ≥ 3`, `payload_mode: hybrid`, a non-empty `scoring_profile`, a declared `scoring_policy_epoch`; then fix G16 (routed selections record AKG edge nodes as method prerequisites) | **T7 answered 2026-10-31: all four, no debate** — config + one code fix |
| **T8** | Repair `evaluation/dependency_oracle.py`'s negative control so the positive control is not discarded (mirror `permission_oracle.py:255–264`); then re-check the six chain runs' `dependency_ref` | **code, free** |
| **T9** | **Hard-pin the graded rubric to `scoring.v4`** and refuse an artifact whose `score_epoch.thesis_final` disagrees (G24). Nothing else in this list is trustworthy until this lands | **code — blocker** |

**Mapping to the gap register below (post cross-check):** T1 → G13 · T2 → G5 · T3 → G6/G18/G19 · T5 → G1/G1b/G17 · T6 → G10 · **T4 dropped** (the ablation refuted it) · **T7** = G3 (the four config blocks) + G16 (routed prerequisites) · **T8** = **G4a, a code fix in `dependency_oracle`**, not oracle authoring · **T9** (new, from the re-audit) = **G24**, hard-pin `scoring.v4` before any re-scoring is called honest.

T1 to T3 change **how the 60 recorded runs are described**, not the runs. T4 to T8 change what
a future score *can* be, which is why they are gated. And **G2 means no ordering of T1…T8 produces
a graded `Srun` for the 2026-10-30 epoch** — that number can only come from a new epoch. §0.1 splits the
work so that this is a boundary rather than a dead end: phases A and B reach their own end states without
it, and phase C is where all five dimensions first exist.

### Profile authoring work order — what "freeze a scoring profile" actually requires (T5)

The steps above name the work; this subsection is the specification, taken from
`validate_profile` (`evaluation/scoring_evidence.py:61–106`) and `freeze_ranking_profile`
(`evaluation/research_plan.py:339`). Q0 is now **answered — build it** (§11, 2026-10-31), so this
subsection is the work order for T5 rather than the preamble to a question.

**Required shape of a profile** (a malformed or tampered profile is a hard error, never a skip):

| element | requirement |
| --- | --- |
| top level | `profile_id`, `version`, `fixture_id`, `protocol_version`, `frozen_at` — non-empty strings; `candidate_budget` positive int (a bool is rejected); `sources` — hash-pinned, and for a current epoch every source must be `origin: operator_fixture`; `scenarios` — non-empty; `sha256` = `evidence_hash` of the profile with `sha256` removed |
| scenario key | `"<surface>:<level>"`, surface from the 9-method registry, level ∈ `{low, medium, high}` |
| every method of that surface | `preconditions` **identical to the static AKG**; `planned_request_count` positive int; `protocol_refs` non-empty and ⊆ `sources`; `fit_predicates` non-empty list of `{key: <AKG predicate key>, equals: bool}`; `allowed_plans` ⊆ `{stop_after_target, stop_at_budget, continue_same_surface, chain}` |
| calibration | `reference_status` ∈ `{confirmed, pending}` + non-empty `reference_reason`; `reference_fit` 1–3 when confirmed, `null` when pending |
| ranking rule | eligible = every precondition observed `True`; `fit_level` = `reference_fit` when **all** `fit_predicates` match, else 1; order = `(-fit_level, planned_request_count)`; exact ties stay tied |

**`pending` is not a neutral placeholder — it is a hard null.** One eligible competitor marked
`pending` makes the whole dimension ungradeable (`ranking_reference_pending` → `Smethod = None`).
So a profile that grades anything must resolve **every** eligible method to `confirmed` with a fit
level and a reason.

**Freezing it** (offline; re-runs nothing, does not touch the 60 recorded runs):

```bash
# the content is the research decision (Q0); the freeze only validates and pins it
.venv/bin/python -m evaluation.research_plan freeze-profile \
  --candidate-profile <path to candidate profile>.json \
  --output-epoch results/studies/<epoch-dir> --epoch-id <epoch-id>
```

The freezer writes `<output-epoch>/config.frozen.yaml` (`research_plan.py:420`) — **that file, not the
repo `config.yaml`, is what the next epoch must run with**; otherwise `scoring_profile` is `{}` again
and G1 repeats.

The freezer enforces: schema via `validate_profile`, `scoring_rubric_version` + `scoring_oracles`
present, matching `fixture_id` / `protocol_version` / `candidate_budget`, all sources
`operator_fixture`, ≥ 3 repeats, and an empty output epoch. Content (fit predicates, request
counts, protocol references) is preserved; identity and lineage hash change.

**The size of the research half:** 5 scenarios keyed by the *registry* surface name —
`access_control:low`, `access_control:medium`, `access_control:high`, `brute_force:medium`,
`sqli:high` (`ac:…` / `sql_injection:…` are rejected as "outside the registry") — and each scenario
must carry **every** method of its surface: 3 + 3 + 3 + 2 + 4 = **15 entries**, not "5 × 3". Each
entry needs a request-count anchor, fit predicates, and an independent protocol reference that
resolves inside `config/oracles/`.

**Done when** — in two stages, the first of which costs no run at all (§0.1):

| stage | check |
| --- | --- |
| **B1–B3 (offline)** | `validate_profile` accepts the frozen profile; `selection_grade` returns 2–4 for a post-freeze snapshot in a unit test; `review_queue` over an `offline_synthetic_fixture` artifact with `selected_at > profile.frozen_at` returns a numeric `Smethod` with no `ranking_unavailable` |
| **C (the authorised epoch)** | `review_queue` over a run **executed after the freeze** returns a numeric `Smethod` and `component_pending_reasons` no longer contains `ranking_unavailable` |

Stage C **cannot** be met by the 60 recorded runs: their `config.scoring_profile` is `{}` (G1), their
receipts carry `profile_sha256: null` (G1b) and the profile is frozen after their `selected_at` (G2).
After that, the last blocker is `Spayload`.

**T6, the `Spayload` procedure** (Tabel 3.6: arithmetic mean over executed eligible candidates):

```bash
# 1. export the pending review template for one artifact
.venv/bin/python -m evaluation.thesis_scoring <artifact>.json --template <template>.json
# 2. finalize with human/AI decisions (no DVWA, no payload execution)
.venv/bin/python -m evaluation.thesis_scoring <artifact>.json --decisions <decisions>.json --output-dir <dir>
#    or let the frozen evaluator decide (provider calls; bounded by the frozen budget)
.venv/bin/python -m evaluation.thesis_scoring <artifact>.json --evaluate
```

Probe requests, rejected candidates, unexecuted candidates and candidates from earlier methods are
excluded from the `Spayload` denominator by the rubric itself.

**A graded rubric is easier to game than a gate, not harder.** Every level is a judgement. Hence
B16 in §4.3: components may only be produced by `evaluation/scoring_evidence.py`; a `None` stays
`None` and is reported with its reason; no hand-filled grades, and no dimension may be scored by
reading the artifact directly.

## Rubric gap register — re-verified by five independent re-audits (2026-10-31)

Full scan of the evaluation path: every `return None, <reason>` in `evaluation/scoring_evidence.py`,
the oracle bundle, selection receipts, requirement rows and LLM receipts, each checked against the
60 recorded artifacts. Five read-only cross-checkers then re-derived the claims independently and
**retracted or downgraded five of them**; their reports are in
`results/validation/2026-10-31-crosscheck-{selection,chain,output,oracle,handoff}.md`. Everything below is
post-cross-check.

### A. Confirmed blockers

| id | gap | evidence (measured) | blocks | class |
| --- | --- | --- | --- | --- |
| **G1** | `scoring_profile` is empty | `config.yaml:257`; artifact `config.scoring_profile == {}` in 60/60; gate `scoring_evidence.py:298–300` → `ranking_unavailable` in 48/48 scored runs | `Smethod`, so all of `Srun` | research + freeze |
| **G1b** | selection receipts carry `profile_sha256: null` | 126/126 Smethod decisions (and 12/12 rejection receipts) | *for these artifacts only*: even a frozen profile cannot grade them. **No code fix needed for future runs** — `agents/state_utils.py:245-246` stamps `state['scoring_profile']['sha256']`, seeded from config at `evaluation/runner.py:1194`; it is null *because* the profile is empty | config prerequisite |
| **G2** | a profile cannot grade earlier selections | gate `scoring_evidence.py:320–322`; freezer stamps wall clock (`research_plan.py:373,378`) | `Smethod` for the 2026-10-30 matrix, permanently. **But the gate is evidence-integrity, not physics**: a back-dated `frozen_at` passes `validate_profile` (`:67–70`) and would grade 3 — doing that is forgery under B12/B16 | structural; new epoch |
| **G3** | the frozen-plan path is blocked by four config values, not one | `research_plan.py` raises on `repeats: 1 < 3` (`:470`), `payload_mode: static_only` (`:472`), empty profile (`:477–481`), and *then* a missing `scoring_policy_epoch` (`:490`). `scoring_policy_epoch` is absent from `config.yaml`; `{}` is a loader default (`tesis/config_loader.py:1147`) | any `plan`/`run`, i.e. the whole next-epoch pipeline | config + decision |
| **G4a** | **the dependency collector's negative control is structurally unsatisfiable** | `evaluation/dependency_oracle.py:66–71` calls `set_security_level` on a deliberately anonymous session → `RuntimeError` (`session_manager.py:310–313`) → the `except` at `evaluation/dependency_oracle.py:202–204` **discards the successful positive control too** → `reason: dependency_controls_not_confirmed`, 6/6 chain runs. `evaluation/permission_oracle.py:255–264` documents and catches this same limitation; the dependency collector does not | every `dependency_ref`, therefore all dependency evidence, in **every live run** | **code** (N8: the test double `FakeSession.set_security_level` is a no-op, so the suite cannot see it) |
| **G4b** | independent dependency proof is the only accepted form | `scoring_evidence.py:565–567` requires `consumption['dependency_ref']` to resolve to `#/config/scoring_oracles/…` | `Schain` 3–4 and the "downstream reuse" level 4 of `Sexploit`/`Spayload` | code (gate) + G4a |
| **G5** | `Schain` is a **run-scope** dimension graded **per method** | the receipt is built for one method (`thesis_scoring.py:336`), `chain_grade:622` then filters dependencies by that method. Measured on a chain run: `chain_grade(sqli_time_blind)=0` (selected), `sqli_union=2` (source), `bf_dictionary=0` (destination) | `Schain` above 0 whenever the chain's source/destination is not the selected method — and note the runtime grades `Schain` at run scope (`COMPOSITE_SCOPE`), so this is a **scope mismatch**, not just a bad filter | code + possibly a rubric reading |
| **G15** | **`Smethod = 4` is unreachable in this matrix** | `selection_grade:388–389` needs every `reason_refs` entry to be an observation key that is `True`; the orchestrator schema types `reason_refs` as free strings (`agents/orchestrator.py:48`), 15/126 decisions are non-empty, 8/126 carry a `plan.kind`, and **0/48 graded decisions qualify**. Counterfactual with a perfect profile: `3` in 48/48, `4` in 0/48 | Tabel 3.5 level 4 | **prompt/schema (§4.2)** — or report it as a model finding |
| **G16** | routed AKG selections record **edge** nodes as method prerequisites | `chaining_coordinator.py:663–665` → `state_utils.py:190`; 6 decisions carry `['credentials_extracted']` where AKG says `['no_rate_limit']`, and were runtime-graded `score=1` "prerequisites_not_proved" while their own `precondition_status` says `no_rate_limit: true`. The same records carry `surface: brute_force` inside a `sqli/high` artifact, so a 5-scenario profile would look up `brute_force:high` and return `ranking_scenario_unavailable` | `Smethod` for the 6 chain-routed visits + a latent profile-coverage trap | **code, free** |
| **G17** | `brute_force:medium` cannot discriminate its two methods | both have the single AKG precondition `no_rate_limit`; the cell exposes 3 bools and `fit_predicates` may only use AKG predicates, so eligibility and fit always tie → `Smethod = 3` either way. Only a hand-authored `planned_request_count` can separate them | Tabel 3.5 level 2 for 12 scored runs | profile authoring (Q0) |
| **G11** | observation keys are cell-limited, and only AKG predicates are usable | bool observations per cell: `brute_force/medium` 3 (`authenticated_crawl`, `low_priv_session_available`, `no_rate_limit`), `access_control/*` 5, `sqli/high` 9 in 12/42 decisions but 6 in 24/42; `fit_predicates` may only use the **8 AKG predicate keys**, which excludes `authenticated_crawl` — so `brute_force/medium` can only predicate on `no_rate_limit` | G17; any profile using another key returns `ranking_observation_unknown` | constraint on the Q0 author |
| **G18** | the "recorded retry ⇒ level 2" gate can never fire | `scoring_evidence.py:1037` tests `attempt != 1`, but `attempt` is `1` in 258/258 while **20 receipts carry `attempts: 2` / `provider_dispatches: 2`** — **5** of them in graded scope, so 3 runs would drop `3 → 2` on a correct implementation | `Soutput` level 2 (over-credit) | **code, free** |
| **G19** | only the **final-selection** receipt is graded | `:939–941` keeps receipts whose `method == selected_method`; runs have 2–3 orchestrator calls. This hides 4 `reason_refs`-valid receipts and **14 luna receipts with `structured_output_fallback: true`** (the other level-2 signal) | `Soutput` degenerates to "did the last selection cite observations" | code / rubric reading |
| **G20** | `measured_negative` is never read by the graded path | 0 occurrences of `measured_negative`/`method_verdicts` in `scoring_evidence.py` and `thesis_scoring.py`; the 12 AC/high runs have `measured_negative.complete: true` + 3 `not_vulnerable` verdicts yet grade `Sexploit: None` via `no_eligible_candidate` | Tabel 3.7–3.9 level 0 for measured negatives | **rubric decision** (run-level vs candidate-level negative) — **and note the trap: resolving it by awarding `0` to the 12 runs is B12 / §4.4, so the decision must be taken as a rubric reading, not as a fill** |
| **G21** | level 2 for `ac_`/`bf_` can be granted by the agent's own boolean | `candidate_base:493–494`: `elif tier is not None or row.get('signal_detected') is True: tier = min(…, 2)` — no proof class required | integrity of the AC/bf tiers 0–2 | **code (tighten)** — the mirror of the retracted G9 |
| **G22** | the AC permission oracle is authored **inside the run it grades** | `runner.py:1994–2002` appends collected sources; 90 `oracle_ref` rows across 42/60 runs, each attestation carrying that run's own ids. Genuine independent HTTP, but it cannot be pre-registered or hash-frozen for a new epoch | `Sexploit 3` reproducibility for AC | design — needs a pre-registered oracle |
| **G23** | **a graded, executed candidate outside the selected method is discarded** | `best_payload_score` filters `payload_scores` by `payload_candidates[selected_method]`; `sqli_time_blind_llm_0_82fb8c1a` holds `payload_scores: 3` with two exploit-stage evidence rows (grades 2 and 3) yet the run selected `sqli_boolean_blind`, so its grade is invisible | model contribution looks like zero when it is not; same scope issue as G5 | rubric reading (method-scoped vs run-scoped attribution) |
| **G24** | **the artifact selects its own rubric version** | `thesis_scoring.py:331` reads `config['scoring_rubric_version']` and falls back to `RUBRIC_VERSION = 'scoring.v3'` (`:28`); nothing cross-checks `score_epoch.thesis_final` (`scoring.v4` in 60/60) or `scoring_rule_sha256`. On the v3 branch `_automatic_components:455-456` derives `Smethod` from the **legacy runtime viable flag**, so deleting one key yields `Smethod 3` with no frozen profile — measured: 54/60 vectors change and 46/60 get `Smethod 3` | the entire *Priority 0* premise; a one-key escape from G1/G2/T5 that looks like a graded score | **code (hard-pin v4) — blocker before any re-scoring** |
| **G13** | runtime vector still written and read | **confirmed** but demoted in importance: the runtime caps are runtime-only (see §1.2 scope banner) |
| **G14** | `token_cost` / `consistency_score` not computed | **confirmed** |

### B. Retracted, downgraded, or restated by the cross-check

| id | was | now |
| --- | --- | --- |
| **G9** | "`PROOF_TIERS` lacks `verified_permission_candidate`, so AC cannot pass level 2 — add it (T4)" | **RETRACTED for `scoring.v4`, with a caveat that matters.** On v4 every AC run grades `Sexploit 3` because 24/24 counted candidates carry `oracle_ref`; the table tier is clamped to 2 either way, and inserting the key changes nothing (ablation). **But on the v3 fallback path (G24) the same 24 runs grade `Sexploit: None`, and the missing key is exactly what moves them to 2** — so the omission is real, it is just invisible on the rubric we report. **T4 stays dropped**; the live defect is the unmapped reason (N2 below), not the clamp |
| **G12** | "dependency evidence needs base tier 3 on both ends — that is the blocker" | **RETRACTED as a cause.** The gate exists (`:556`). Exactly one route per chain run reaches it, and there both ends are 3 — 6/6 runs. It never fired. The actual first failing gate is `:565` (`dependency_ref`), i.e. G4a+G4b |
| **G10** | "`manual_scoring_evidence` is always empty" | **HALF WRONG, and my own wording was the ambiguous part.** There are two fields: the artifact's **top-level** `manual_scoring_evidence` is non-empty in **48/60** runs (0–22 rows per run), while `final_state.manual_scoring_evidence` **does not exist in 60/60**, and **no code path reads either copy** (writers only: `runner.py:2062`, `scoring_repair.py:173`, `payload_replay.py:460`, `multi_llm_runner.py:1074`) — my row named the second and implied the first. The real `Spayload` blocker is that `payload_score_0_4` is copied from the runtime `payload_scores` (`manual_scoring_sheet.py:108,175`) and `review_queue` never emits `Spayload`, so `finalize_reviews` returns `pending_candidate_grades` until reviewed decisions exist. **Worse: the sheet pre-fills that column with the runtime grade, so a reviewer is anchored to the legacy score** — T6 must produce fresh grades, not confirm the pre-fill |
| **G7** | "role receipts go missing (`required_role_receipt_missing`) — code fix" | **DOWNGRADED.** The surplus is duplication, not loss: **390 requirement rows over 259 `call_id` values including a 6-row null bucket → 258 distinct real call ids, 126 of which appear twice** (252 payload rows over 126 ids). `_requirement_plan` covers all 144 rows for the 48 scored runs. The 6 failing runs are all AC/high, where the receipt *exists* but is dropped by the `method` filter because `selected_method` is null. **Touches zero scored runs** |
| **G8** | "no `negative_attestations` ⇒ level 0 unreachable" | **RESTATED.** Level 0 *is* reachable with no oracle: `no_verified_exploit_signal` / `timing_not_verified` / `login_not_confirmed` map to tier 0 and 4 sqli candidates already sit at `base_proof: 0`. The bundle is 3 protocol documents in `config.yaml`, growing to 3–6 in artifacts after collection. The 12 AC/high runs have an **empty `payload_candidates`** (0 exploit/bypass rows), which is why `Sexploit` is `None`; level 0 is in fact already awarded to them as `Schain 0`. Nothing sets `negative_oracle_ref` except `attach_oracle_evidence`, whose only callers are `evaluation/runner.py:1998` and `:2002` — `review_queue` never calls it, so offline re-scoring cannot bind a negative |
| **G6** | "the orchestrator rarely cites observations (16/132)" | **RESTATED, sharper.** The graded scope is the final-selection receipt only, so the right statistic is **41/48 no `reason_refs`, 7/48 unresolvable** (prose or invented keys). The payload side is fine (123/126 pass). `inputs.precondition_status` is absent in 258/258, so half of `output_references_valid`'s orchestrator branch is dead |

### C. What this changes about the plan

1. **`Srun` for this matrix is unreachable on `Smethod` (G2), and that is final for this epoch.**
   The deliverable is a **three-dimension partial** (`Sexploit`, `Schain`, `Soutput`): `review_queue` emits only those four
keys and never `Spayload`, and `Smethod` is unreachable by construction.
2. **The chain dimension needs both halves:** repair the collector (G4a) *and* resolve the
   run-scope/per-method mismatch (G5). After G4a, `Schain 3` becomes reachable on the existing
   six runs' evidence; `4` still needs a second linked hop. `chain_grade` level 1 is also
   unreachable today: it demands `candidate_base ∈ (1,2)`, and **all 60 weak opportunities have a
   source base of 3** (24 of them method-matching) — measured, not inferred.
3. **AC is in better shape than the runtime ceiling suggested** — 3 is already awarded via the
   oracle. What AC actually needs is a *pre-registered* oracle (G22) and a tightened tier-2 rule
   (G21).
4. **`Soutput` is capped by prompt behaviour and receipt selection, not by missing fields**
   (G15/G18/G19): level 4 needs the orchestrator to cite observations, level 2's gate is dead, and
   only the last selection is graded.

### D. Cross-check log — what the five verifiers overturned

Recorded so nobody re-adopts a refuted claim. Each verifier worked read-only, re-derived the corpus
itself (60 runs, `_superseded_*` and `.rich.json` excluded) and used in-memory ablations on real
artifacts where an inference needed testing.

| claim (as I first wrote it) | verdict | the evidence that decided it | report |
| --- | --- | --- | --- |
| AC cannot pass level 2; add a `PROOF_TIERS` key | **refuted** | graded `Sexploit 3` on 24/24 AC runs via the permission oracle; ablation: strip `oracle_ref` → 2, add the tier key → **still 2** | `crosscheck-oracle.md` |
| dependency evidence blocked by the `candidate_base == 3` gate | **refuted** | that gate is satisfied 3/3 on both ends in 6/6 chain runs; first failing gate is `:565` (`dependency_ref`) | `crosscheck-chain.md` |
| the dependency oracle is missing content | **refuted** | `config.yaml` points at 3 protocol templates by design; the empty `dependencies` is a **collector crash**, not missing authoring | `crosscheck-chain.md` |
| `manual_scoring_evidence` always empty | **refuted for one field, confirmed for the other** | top-level sheet non-empty in 48/60 (0–22 rows); the `final_state` copy is empty in 60/60 | `crosscheck-output.md` |
| role receipts go missing on scored runs | **wrong causality** | surplus is duplicated requirement rows (252 rows / 126 call ids); all 144 rows for scored runs are covered; the 6 failures are AC/high where the receipt exists but `selected_method` is null | `crosscheck-output.md` |
| `reason_refs` presence explains the `Soutput` cap | **imprecise** | of the 16 ref-bearing calls only 4 resolve at all; the graded scope is one receipt per run, where 41/48 carry no refs and the 7 that do are all unresolvable | `crosscheck-output.md` |
| the receipt never records the profile hash → needs a code fix | **wrong class** | `state_utils.py:245-246` stamps it from `state['scoring_profile']`; it is null because the config profile is empty | `crosscheck-selection.md` |
| `Srun` is blocked "structurally, no fix" | **qualified** | a back-dated `frozen_at` passes `validate_profile` and would grade — so the block is evidence integrity (B12/B16), not impossibility | `crosscheck-selection.md` |
| `scoring_policy_epoch` is the blocker for the plan path | **imprecise** | three earlier raises fire first: `repeats: 1`, `payload_mode: static_only`, empty profile | `crosscheck-selection.md` |
| 5 scenarios × 3 methods = 15 entries | **arithmetic wrong, total right** | surfaces have 4/3/2 methods; 3+3+3+2+4 = 15 | `crosscheck-selection.md` |
| `Soutput = 1` comes from `fallback_only` | **mechanism wrong** | it comes from the per-group `_fallback_credit` branch (`:1012–1019`); `fallback_only` was empty in all four runs | `crosscheck-output.md` |

**Standing rule from this exercise:** a defect in this register is not "confirmed" until a second
party reproduces it from the artifacts or by ablation. Five of my first-pass rows failed that test.

### E. Frontier findings — the surrounding pipeline (surface sweep, 2026-10-31)

Modules no earlier audit touched, 22 findings. Three are blockers, and they matter because they sit
*around* the score rather than in it: the epoch cannot produce a receipt, cannot produce a plan, and
cannot report a request count.

| id | finding | measured | severity |
| --- | --- | --- | --- |
| **F1** | **neither plan pipeline accepts the shipped `config.yaml`** | `research_plan.build_research_plan` fails on `payload_mode: static_only`, empty `scoring_profile`, missing `scoring_policy_epoch`; `scoring_v4_matrix._validate_config` fails four *different* pre-checks (provider ≠ `openai_compatible`, `payload_modes` set mismatch, `matrix: false`, empty profile) and `create_plan` additionally needs a live DVWA `security.php` and hardcodes `repeat_indices [0]` | **blocker** |
| **F2** | **no run can finalize an `Srun` — zero receipts** | every queue has `components.Smethod is None`, so `finalize_reviews` yields 12 `no_assessable_candidates`, 6 `output_not_applicable` (**misattributed** — the real gap is ranking) and 42 `missing_component_evidence`. The partial-review guard itself works | **blocker** |
| **F3** | **physical request metrics are never reportable** | 4290/8045 dispatches are `role=other`, so `http_client.py:163` sets `capture_status=partial` in 60/60 → `physical_requests_total`, `request_retries`, `redirect_hops`, `failed_requests` unavailable, although the counter already holds 58–201 requests per run | **blocker** |
| **F4** | `compute_run_metrics(artifact)` ignores the artifact's own components | it never reads `composite_components` (present in 48/60) → `full_exploit_flag` 0/60 available though `Sexploit ≥ 3` in 48; `chain_enabled_exploit_flag` 0/60 though `Schain ≥ 3` in 6 | degrades |
| **F5** | the metrics entry point hardcodes ignorance | `_candidate_view(rows=None)` fixes `assessed=False, proof=None`; with real rows the same metrics become available in 11 / 2 / 1 runs | degrades |
| **F6** | the catalogue pools superseded epochs | `ArtifactCatalog.paths` globs `*.json` and re-indexes `_superseded_*` → observer projection reports **90 runs / 30 matrices** instead of 60/20, and one provider reads 60 runs / 27 failed instead of 30/0 | degrades |
| **F7** | the frozen price schedule may be empty | `token_price_schedule` is a declared required input but only hash-compared; `{}` freezes and verifies → `token_cost` / `token_cost_per_success` unavailable 60/60 | degrades |
| **F8** | the runner's default rubric is v3 | `multi_llm_runner` defaults `scoring_rubric_version="scoring.v3"`; omitting the argument silently downgrades the whole review path — **the same escape as G24, one layer up** | degrades (**reinforces G24**) |
| **F9** | three different digests are all called "scoring rule" | `597bcb93…` (receipts/queue, includes `verifier.py`), `c5649338…` (recorded in every `score_epoch`, includes `research_metrics.py`), `591e858a…` (`scoring_rule_hash`) — a `verifier.py` change does **not** move the artifact-side digest, so §8's "same `scoring_rule_sha256`" criterion is ambiguous | degrades |
| **F10** | the projection republishes a zero as a score | `empty_artifact`'s `composite_score: 0` becomes `components.Srun = 0` with status `runtime_provisional_scoring.v2` for never-run coordinates, while `aggregate_metric` reads the same record as `not_computed` | misleads |
| **F12** | `report.summary` publishes bare zeros | `payload_validity_rate 0.0` ×12, `payload_execution_success_rate 0.0` ×36, `mean_attempts_to_success 0.0` + `attempts_to_success 0` ×12 — literally "success on attempt 0". `metric_reading` relabels them `legacy_numeric` and excludes them, so aggregates stay honest while artifacts do not | misleads |
| **F14/F15** | the human-facing artefacts carry the wrong epoch | `manual_scoring_sheet` emits v2 `*_score_0_4` columns with no epoch label; `rubric_document` hardcodes "profile and oracles not available" although the pinned DWVA oracle validates in all 60 queues | misleads |
| **F16/F17/F18** | the matrix and comparison tables publish the legacy vector | `provisional_avg_score` is a mean of **summed** module scores (values 6.0/9.0/13.0/0.0) next to `score_epoch: runtime_provisional_scoring.v2`; the provider table keeps max-over-runs (best-of-N) as "the provider's score"; the module table's header is literally "Score" | misleads |
| **F19** | a diagnostic prints hardcoded counts | `remaining_evidence.main()` prints `retry_rows 46` / `scoring_rows 108` literally, and its coverage audit no longer reproduces (join key is a hash of current sources) | misleads |

**Checked and clean:** `reporter.py` (no composite in the markdown at all), `observer_reviews.py` (receipt
arithmetic re-derived; no path publishes a score the runtime did not have), the `finalize_reviews`
partial-review guard, `rubric_tables` (3.5–3.11 present), `aggregate_metric`/`metric_reading` (no zero
filling), `tui_drawers._score_text` (never synthesises).

**False positive, recorded so it is not re-raised:** the sweep reported a live provider key in
`config.yaml`. There is **no** `api_key` under `scoring_evaluator`; the only one in the tracked config is
an env reference, and artifacts store `[REDACTED]`.

**Fix order for this group:** (0) **T9/G24**, (1) **F2 + F7 + F1** — the epoch can neither produce a
receipt nor a plan, and the price schedule needs a non-empty guard in the same pass; (2) **F3** —
request accounting is missing scope tags the counter already holds; (3) **F4 + F5** — make
`compute_run_metrics` use the artifact's own components and rows instead of declaring evidence absent.

---

## 0. One-page version

The loop is allowed to raise the score **only as a consequence of measuring the harness more
truthfully**. It is never allowed to raise the score by changing what counts.

That distinction is not a slogan here — §1.2 shows the current composite is quantised by
five hard-coded caps in `agents/state_utils.py` and `core/chaining_coordinator.py`. The
cheapest possible way to move the number is a one-line `min()` edit. Therefore the loop's
objective function is a **fidelity ledger** (§3), the rubric is a **frozen guard** (§4), and
every score change must be explainable as "the harness previously mis-measured, now it
measures". An improvement that cannot be explained that way is rejected even if it looks
better.

Six rules bind the whole loop:

| # | Rule |
| --- | --- |
| **R0** | The reported score is the **graded thesis rubric** (`Tabel 3.5–3.11`, implemented in `evaluation/scoring_evidence.py`). The runtime `composite_score` is a legacy field and is never reported as *the* score. See *Priority 0*. |
| **R1** | The loop optimises **fidelity metrics** (§3.1), never `composite_score`. Score movement is an observation, reported after the fact. |
| **R2** | The scoring rubric, the five dimension caps, the weights, `COMPOSITE_SCOPE`, and the DoD are **frozen** (§4.1). The loop cannot edit them, and cannot import a change into them. |
| **R3** | Any change that alters the **experiment** (candidate budget/order, stop policy, prompt, model, condition, repeats) is a **design amendment**, needs human sign-off *before* seeing the resulting score, and is re-reported on the whole epoch (§4.2). |
| **R4** | Every deduction and every `null` must end with a **named cause** from a closed list (§3.2). `unknown` is a loop failure, not an acceptable answer. |
| **R5** | The only accepted evidence of improvement is a **fresh-epoch matrix** showing the fidelity gain with all §4 invariants verified unchanged. Never a re-scored old epoch presented as new, never a subset of repeats. |

### 0.1 The workflow, repositioned so that no step is unreachable

G2 makes exactly one thing impossible: a graded `Smethod` **for the 2026-10-30 epoch**. Read as a single
unbroken chain — "repair the rubric, then re-score the 60 runs, then report `Srun`" — that one impossible
step poisons the whole document, because the chain has no reachable end. The workflow below is the same
work in three phases, each with its own reachable end state, and the impossible step is a labelled
boundary rather than a step.

| phase | work | provider calls | ends when | reachable today |
| --- | --- | --- | --- | --- |
| **A — report and repair** | T9 (pin `scoring.v4`), T1 (report the graded vector + `component_pending_reasons`), T3 (G18 retry gate), T8 (G4a dependency oracle), F1 (validators accept a frozen config), F3/F4/F5 readers, F6, F7, T6 (`Spayload` reviews) | 0 | the 60 saved artifacts are restated under the frozen v4 path, and **four** dimensions — `Spayload`, `Sexploit`, `Schain`, `Soutput` — each carry a keep/deduct decision with a closed-list cause | **yes** |
| **B — author, freeze, prove** | T5 (the 15-entry profile, authored blind), T7 (the four config blocks), `freeze_ranking_profile` → `<epoch>/config.frozen.yaml`, then stages **B1–B3** below | 0 | `Smethod` is **proven working end-to-end offline** — before a single provider call is spent on it | **yes** |
| **C — one authorised epoch** | the 60-run matrix from §11 Q4, launched with `config.frozen.yaml` | yes (§11.1) | all five dimensions exist for a real epoch: the first and only honest 0–4 `Srun` this study can produce | gated |

**Phase A's output is a complete deliverable, not a shortfall.** A four-dimension partial with every
`None` carrying its reason is a legitimate thesis result; what is not legitimate is calling it an
`Srun`.

**Phase B is where the unfixable problem dissolves.** T5 previously read as "done when a run executed
after the freeze returns a numeric `Smethod`", which deferred the first evidence of success to a paid,
irreversible epoch. Stages **B1–B3** move that evidence earlier:

| stage | check | needs |
| --- | --- | --- |
| **B1** | `validate_profile` accepts the frozen profile: schema, all 15 entries, `reference_status: confirmed`, hash-pinned `operator_fixture` sources, `sha256` = `evidence_hash` | nothing — pure function |
| **B2** | `selection_grade` returns 2–4 for a **post-freeze** selection snapshot, in a unit test | nothing — a constructed snapshot |
| **B3** | `review_queue` over a synthetic artifact labelled `offline_synthetic_fixture`, with `selected_at > profile.frozen_at`, returns a numeric `Smethod` and no `ranking_unavailable` | nothing — a labelled fixture artifact |

B1 and B2 are pure-function checks over a constructed snapshot. B3 depends on `review_queue` accepting a
fixture artifact — confirm at implementation; if that path is closed, B2 plus an explicit assertion that
`component_pending_reasons` no longer contains `ranking_unavailable` carries the identical claim. **A B3
fixture is never counted as a run and never enters a table.** Establish reachability with it, then let
stage C produce the graded number.

### 0.2 The one step that is not in this workflow

Grading `Smethod` for the 2026-10-30 epoch is not "not yet". It is not at all, and the reason is not
missing data:

- the profile must be frozen **before** the selection it judges, and all 60 runs were selected with
  `scoring_profile: {}` — every selection receipt carries `profile_sha256: null` (126/126);
- back-dating `frozen_at` passes `validate_profile` and is a forged timestamp (B12/B16);
- a profile authored *now* would be tuned with knowledge of which method each run picked and how it went,
  which grades the system against a preference fitted to its own output — the §4.3 pattern, not a fix;
- 12 of the 60 runs (`missing_selection_snapshot`) have no selection record to grade even then.

**What the old epoch gets instead**, all of it honestly derivable from the saved artifacts:

| substitute | what it is | what it is not |
| --- | --- | --- |
| `Spayload` (T6) | Tabel 3.6 over executed eligible candidates, from reviewed per-candidate decisions | not `Smethod` |
| `Sexploit`, `Schain`, `Soutput` | graded from the frozen v4 path, with causes | not `Smethod` |
| **FD1 `selection_precondition_consistency`** (§3.1) | did the selected method satisfy its own static-AKG preconditions, per the recorded snapshot? | **not a rubric dimension**; no preference list, no outcome knowledge, excluded from `Srun`, and a high value means "no self-contradiction", not "good choice" |

The only other way to put a number in that column is a §4.2 rubric amendment that drops the
pre-freeze requirement. That would produce a number-shaped object and no measurement, and it would put
Tables III–IV beyond defence. It is named here so it is a decision, not a discovery.

**This claim is contested, and the contest is parked rather than settled** — the owner's position is
that the object being measured is the model's *selection*, which is recorded in full, so the date of
the ranking should not decide gradeability. That disagreement is written up as **§11.2 A1**, with a
cheap two-key test that resolves it either way. While A1 is open, the behaviour above stands.

### 0.3 Triage — what can be done now, and what cannot

Written 2026-10-31 so that no later session has to re-derive the boundary. "Now" means: no provider
call, no DVWA run, no authorisation, no rubric amendment.

**1. Can be done now — offline, verifiable against the 60 saved artifacts**

| work | why it is safe to do today |
| --- | --- |
| **T9** pin the graded rubric to `scoring.v4` | nothing else is trustworthy until an artifact cannot pick its own rulebook (G24) |
| **T1** report the graded vector + `component_pending_reasons` | reporting only; changes no number |
| **T3** fix the dead retry gate (`scoring_evidence.py:1037`) | code defect; `attempt` is 1 in 258/258 receipts |
| **T8** repair `dependency_oracle`'s negative control (G4a) | code defect — **and** the only route to `Sexploit 4` (§1.2b) |
| **F1** make both plan validators accept `config.frozen.yaml` | today they reject it, so no frozen plan can be produced |
| **F3/F4/F5** metric readers; **F6** label consistency; **F7** price-schedule guard | measurement only |
| **T6** `Spayload` reviews over the 48 scored runs | offline, from saved candidates; costs reviewer time, not providers |
| **FD1** selection-precondition diagnostic | artifact + static AKG only (§3.1) |
| **A1** the two-key test | fully offline (§11.2) |
| **§3.3** resolution reporting | already measured; needs writing into the report |
| author the 15-entry profile + freeze it; prove B1–B3 | offline; the *content* is the owner's judgement, the mechanics are not |

**2. Needs one thing from the owner — not code**

- the **15 profile entries** (fit levels, request-count anchors, protocol references), authored blind;
- the **four config values** entered into `config.frozen.yaml` (decided 2026-10-31, not yet typed);
- an **A1 decision**, if the two-key test comes out "keys disagree";
- Q1, Q2, Q3, Q5, Q6 before the result tables are written.

**3. Cannot be done — ever, for the 2026-10-30 epoch**

- a graded `Smethod` or `Srun` (G2, §0.2) — the profile had to exist before 19:01:00 WIB on 30 Oct;
- the 12 missing selection snapshots — they were never written;
- `Sexploit 4` — the promotion needs a verified dependency, and dependencies were never collected for
  these runs. **T8 fixes collection for future runs; it cannot manufacture evidence for past ones**;
- `Smethod 4` — the receipts have no resolvable `reason_refs` (G15), and they cannot be re-authored
  without rewriting the artifact history (B-rule).

**4. Cannot be done yet — waiting on something named**

| blocked on | item |
| --- | --- |
| §11.1 precondition 6 (cost metering) | the one authorised 60-run epoch (§11 Q4) |
| §11.1 precondition 7 (DVWA + provider scope confirmation) | same |
| the profile being frozen | any graded `Smethod` at all, even for a new epoch |
| T8 landing | `Sexploit 4` / `Schain 4` in the next epoch |

**5. May not be done — regardless of who asks**

Reweight the dimensions, delete a dimension, cap or uncap a level, back-date a profile, re-score a
reported epoch after seeing its result, or narrow the §8 acceptance checklist. Each of these changes
*what counts*, which is the one move §4 exists to forbid — and §1.2b shows the ceiling argument is
exactly the one that would pay off most.

---

## 1. Why this handoff exists

### 1.1 The **runtime** vector is already at its structural ceiling

Measured over the 48 scored runs of the 2026-10-30 matrix (all numbers re-derived from the
artifacts; reproduction in §10):

| Dimension | Observed values | Count |
| --- | --- | --- |
| `Smethod` | `3` | 48 |
| `Spayload` | `2` (all `ac_*`), `3` (all `bf_*`, `sqli_*`) | 24 / 24 |
| `Sexploit` | `3` | 48 |
| `Schain` | `0` / `4` | 42 / 6 |
| `Soutput` | `4` / `3` / `2` | 43 / 3 / 2 |

The agents themselves are barely more expressive than that: across all 60 runs the raw
per-method agent score (`final_state.scores`) only ever takes **`0` (414), `3` (120), `4` (6)** —
never `1` or `2`.

Only **eight distinct component vectors** exist across 48 runs, and **43 of 48 sit exactly at
the per-cell ceiling**:

| cell family | ceiling vector | ceiling `composite_score` (legacy) | runs at ceiling |
| --- | --- | ---: | ---: |
| `access_control/*` | `3 / 2 / 3 / 0 / 4` | **2.70** | 22 of 24 |
| `brute_force/medium`, `sqli/high` (linear) | `3 / 3 / 3 / 0 / 4` | **2.90** | 16 of 18 |
| `sqli/high` (akg, with a completed chain) | `3 / 3 / 3 / 4 / 4` | **3.30** | 5 of 6 |

The remaining five runs lose `0.20` (three runs, `Soutput 3`) or `0.40` (two runs,
`Soutput 2`) to `Soutput` only. So "raise the composite" has a maximum remaining headroom of
**0.40, in 2 of 48 runs** *without* changing a cap — and all five of those deductions trace to
a provider/schema artefact or a harness budget decision, not to a finding about method or
payload quality (§2, §6 S2).

**A loop that targets `composite_score` therefore has almost nothing legitimate left to do,
and one very cheap illegitimate move available.** That is the whole reason this handoff is
framed as it is — and *Priority 0* shows the target itself is wrong: this section describes the
legacy vector, whose 2.70/2.90/3.30 ceilings are not the rubric's.

### 1.2 The ceilings are code caps — **of the runtime vector only**

> **Scope correction (2026-10-31 cross-check).** `verified_grade`, `payload_scores`,
> `exploitation_scores`, `method_scores` and `output_scores` appear **0 times** in
> `evaluation/scoring_evidence.py` and `evaluation/thesis_scoring.py`. Every cap below therefore
> governs only the legacy runtime `composite_score` that *Priority 0* demotes. **None of them
> limits the graded thesis score**, and the graded path is *kinder* to Access Control (it reaches
> `Sexploit 3` via a permission oracle) than the runtime ceiling of 2 suggests.
>
> **The graded path has ceilings of its own — different in cause, and partly repairable: see
> §1.2b.** The graded top is 3.7 of 4.0 today (3.3 in `ac_*` cells), not because of any `min()` here
> but because `Sexploit 4` needs dependency evidence that T8 repairs.

| Dimension | Producer | Code | Effect |
| --- | --- | --- | --- |
| `Spayload` | `agents/state_utils.py:1474` | `grade = min(int(grade), 2 if module_name.startswith("ac_") else 3)` | **no method can reach 4** (0 code paths emit `verified_grade=4`); `ac_*` additionally **loses a proven 3 → 2** |
| `Sexploit` | `agents/state_utils.py:1382`, `:1486` | `min(score, 3)` | **no method can reach 4** — 6 runs proved 4 and were recorded as 3 (S12) |
| `Smethod` | `agents/state_utils.py:217` | `grade = 3 if is_viable else 1` | binary `{1,3}`; `0`, `2`, `4` unreachable |
| `Schain` | `core/chaining_coordinator.py:494` | `grade = 4 if completed else 0` | binary; partial credit impossible |
| `Soutput` | `core/scorer.py:114` | `0` violation / `2` rejected / `3` fallback / `4` clean | `1` unreachable; a **method-linked** `fallback_events` entry caps at 3 (19 runs carry fallback events that do not bind, so the cap is not universal) |

Consequence: `Spayload = 2` for every Access Control run is **not** a statement about payload
quality. It is a constant in the source. Any table, chart, or claim that reads it as a model
measurement is wrong — and the fastest way to make the table look better is to delete that
`min()`. §4 forbids exactly that.

### 1.2b Graded-path reachability — the ceilings above are **not** the graded ceilings

Added 2026-10-31 because §1.2's scope note ("none of them limits the graded thesis score") is easy to
misread as "the graded rubric has no ceiling". It has one — different in cause, and partly repairable.

| dimension | top level the rubric defines | how the graded path reaches it | what gates it today | reached in 2026-10-30 |
| --- | --- | --- | --- | --- |
| `Smethod` | 4 | `selection_grade:398` — `4 if reason_ok and plan_ok else 3` | every `reason_refs` entry must be an observation key: non-empty in 15/126 receipts, **0/48** graded decisions qualify (G15) | `null` — no profile at all (G1/G2) |
| `Spayload` | 4 | arithmetic mean over executed eligible candidates | **`review_queue` never emits it** — the graded receipt carries four keys, not five (T6) | **absent** |
| `Sexploit` | 4 | `automatic_components:1073` takes `max(base_proof)`; `:1078-1079` promotes **3 → 4** only when a verified dependency names the method | `verified_dependencies` is empty in **60/60** (G4a); `ac_*` / `bf_*` are clamped to 2 without an independent oracle (`:492-494`) | 3 |
| `Schain` | 4 | `chain_grade` | the weak-opportunity branch needs `candidate_base ∈ (1,2)`; **all 60** weak opportunities have 3 | 0 |
| `Soutput` | 4 | `output_grade:1040` — `4 if all(output_references_valid(c))` | orchestrator receipts must carry resolvable `reason_refs`: absent 41/48, unresolvable 7/48 (G6) | 3 (44 runs), 1 (4 runs) |

Two consequences that matter for how results are worded:

1. **Tier 4 never comes from the tier table.** `PROOF_TIERS` holds 17 evidence classes with values
   `{0, 1, 2, 3}` — there is no tier-4 class. `Sexploit 4` exists **only** through the promotion at
   `:1078-1079`. So **T8 is not only about chain crediting: it is the single route to `Sexploit 4`
   for every method.**
2. **The reachable ceiling today is 3.7, not 4.0.** With `Sexploit` pinned at 3:
   `0.2·4 + 0.2·4 + 0.3·3 + 0.1·4 + 0.2·4 = 3.7`. For an `ac_*` cell the `Spayload ≤ 2` clamp
   (`:492-494`) pulls it to **3.3**. After T8, 4.0 becomes reachable. Any sentence of the form "the
   score is out of 4" should carry the reachable ceiling beside it.

### 1.3 The study's independent variable was never delivered

The thesis contrast is hybrid (static seeds **+** LLM candidates) versus linear. Measured:

| Fact | Value |
| --- | --- |
| Budget receipts carrying an LLM candidate | **123** |
| …where an LLM candidate was **executed** | **1** |
| …`stopped_before_execution` | **92** |
| …`budget_excluded` | 15 |
| …`rejected` (validator refused the model's payload) | 15 |
| Receipts with `(configured, profile, effective)` budget | **all 123 = `(10, 5, 5)`** |
| Position of the LLM candidate in the queue | **always last in every receipt where it is queued** (0-based `3/4` ×41, `4/5` ×29, `1/2` ×23 = 93); **30 of 123 receipts never queue it**; across all 123 it is last in 117 |
| Scored runs whose counted `Spayload` came from an LLM candidate | **0 of 48** — but see the line below; this is not the same as "the model never earned a grade" |
| LLM candidates that executed, were graded, and were then discarded | **1** — `sqli_time_blind_llm_0_82fb8c1a` (deepseek·linear·sqli/high run-001) executed at exploit stage, earned `verified_grade 3` and a `Spayload` decision of 3, but belongs to `sqli_time_blind` while the run selected `sqli_boolean_blind`, so it never reached the run score (G23) |

The mechanism is ordering plus stop policy, not the budget level: the LLM candidate is
appended after the static seeds, the queue is consumed front-to-back, and the workflow stops
(`coverage_target_reached` 36, `selection_rejected_precondition_false` 12, `no_viable_methods`
6, `confirmed_success` 6) before reaching the tail. This is the single most consequential
defect in the current tree, and fixing it is a **design amendment** (it changes which payload
executes first), not a bug fix — see §4.2 and §11 Q1.

---

## 2. Verified baseline

> The numbers below are the **runtime** vector. *Priority 0* shows that this is not the
> thesis score; read §2 as the shape of the recorded artifacts, not as the result.

Re-derived on 2026-10-30 from the accepted trees (`deepseek/**/matrix-2026-10-30`,
`luna/**/matrix-2026-10-30-2`; `_superseded_*` trees excluded). Every number below is
reproducible with §10.

| Property | Value |
| --- | --- |
| Runs | 60 (all `completed`) |
| Distinct `source_hashes_sha256` | **1** (`b4909695…`) |
| `security_outcome` | `confirmed` 48, `unconfirmed` 12 |
| `composite_score` | non-null 48, `null` 12 (all `no_method_attempted_measured_negative`) |
| `measured_negative.complete` | `true` 12 / `false` 48 |
| `method_verdicts` non-empty | 12 runs × 3 verdicts |
| `composite_score_status` | `runtime_provisional_scoring.v2` — **all 60** |
| `score_epoch.runtime_provisional` | `scoring.v2` — all 60 |
| `scoring_policy.rubric_version` | `scoring.v4` — all 60 |
| Arithmetic check, v4 weights | **48/48 exact**, 0 mismatches |

Per-cell composites (`null` = AC/high, out of the loop's target set):

| model | condition | cell | composites | mean |
| --- | --- | --- | --- | ---: |
| deepseek | akg | ac/high | `null, null, null` | — |
| deepseek | akg | ac/low | `2.7, 2.7, 2.7` | 2.700 |
| deepseek | akg | ac/medium | `2.5, 2.7, 2.7` | 2.633 |
| deepseek | akg | bf/medium | `2.9, 2.7, 2.9` | 2.833 |
| deepseek | akg | sqli/high | `3.3, 3.1, 3.3` | 3.233 |
| deepseek | linear | ac/low | `2.7, 2.7, 2.7` | 2.700 |
| deepseek | linear | ac/medium | `2.7, 2.3, 2.7` | 2.567 |
| deepseek | linear | bf/medium | `2.5, 2.9, 2.9` | 2.767 |
| deepseek | linear | sqli/high | `2.9, 2.9, 2.9` | 2.900 |
| luna | akg | ac/low | `2.7, 2.7, 2.7` | 2.700 |
| luna | akg | ac/medium | `2.7, 2.7, 2.7` | 2.700 |
| luna | akg | bf/medium | `2.9, 2.9, 2.9` | 2.900 |
| luna | akg | sqli/high | `3.3, 3.3, 3.3` | 3.300 |
| luna | linear | ac/low | `2.7, 2.7, 2.7` | 2.700 |
| luna | linear | ac/medium | `2.7, 2.7, 2.7` | 2.700 |
| luna | linear | bf/medium | `2.9, 2.9, 2.9` | 2.900 |
| luna | linear | sqli/high | `2.9, 2.9, 2.9` | 2.900 |

`Soutput < 4` — all five are deepseek; **luna is 24/24 clean**:

| cell | selected method | `Soutput` | linked event |
| --- | --- | ---: | --- |
| deepseek akg ac/medium | `ac_idor` | 3 | `fallback_events: budget_excluded_model_candidate` |
| deepseek akg bf/medium | `bf_spray` | 3 | `fallback_events: no_valid_generated_candidates` ×2 |
| deepseek akg sqli/high | `sqli_time_blind` | 3 | `no_valid_generated_candidates` ×2 + `budget_excluded_model_candidate` |
| deepseek linear ac/medium | `ac_vertical_escalation` | 2 | `fallback_events: schema_violation` + `output_failure_events` |
| deepseek linear bf/medium | `bf_spray` | 2 | `fallback_events: schema_violation` + `output_failure_events` |

---

## 3. The objective function

### 3.1 Fidelity ledger — the only thing the loop maximises

F1–F8 are computed **from the artifacts**, with no new scoring code and no provider calls. **FD1** is
the one diagnostic in the table and is excluded from `Srun` (see the note below it).
Baseline column is the 2026-10-30 value.

| id | metric | definition | baseline | target |
| --- | --- | --- | --- | --- |
| **F1** | `model_candidate_execution_rate` | receipts with an `_llm_` candidate executed ÷ receipts with an `_llm_` candidate | **1/123 = 0.008** | > 0, and *pre-registered* per §4.2 |
| **F2** | `generated_grade_share` | scored runs whose counted `Spayload` came from an `_llm_` candidate ÷ 48 | **0/48** | > 0, same pre-registration |
| **F3** | `attribution_completeness` | deductions + nulls with a closed-list cause ÷ all deductions + nulls | not measured | **1.00**, `unknown` = 0 |
| **F4** | `null_discipline` | nulls with `metric_unavailable_reason` **and** a complete measurement ÷ nulls | **12/12** | stay 1.00 |
| **F5** | `arithmetic_consistency` | scored runs whose `composite_components` reproduce `composite_score` under v4 weights | **48/48** | stay 1.00 |
| **F6** | `label_consistency` | artifact internal disagreements (epoch string vs rubric, `attempts` vs executed candidates, `stop_reason` vs `attempted_agents`) | **≥3 known** (§6 S3, S5, S6) | **0** |
| **F7** | `repeat_stability` | distinct composite vectors within one cell's 3 repeats (16 target cells) | **11 cells at 1, 5 cells at 2** (all variance is deepseek) | reported, not optimised |
| **F8** | `thesis_rubric_coverage` | runs whose reported components come from the graded path ÷ runs reported; and, within them, components that are `None` with a recorded reason ÷ components | **0/48 reported** (never evaluated) | 48/48, with every `None` carrying a reason |
| **FD1** | `selection_precondition_consistency` (diagnostic) | graded runs whose **selected** method had every static-AKG precondition observed `True` in the selection snapshot ÷ graded runs that have a snapshot — computed from the artifact + the static AKG only | not measured (48 runs carry a snapshot) | measured for 2026-10-30, with G16's six exceptions each resolved or explained |

F8 is the only one that starts at zero for a reporting reason rather than a harness reason; it
is bound by *Priority 0*, and it is the first metric the loop is allowed to move.

**FD1 exists because the 2026-10-30 epoch can never carry `Smethod`** (§0.2). It is a **diagnostic, not a
rubric dimension**: it uses no preference list and no knowledge of any outcome, it never enters `Srun`,
and it must be labelled as a diagnostic wherever it is reported. It answers "did the orchestrator respect
its own rules?" — not "was the choice the best one?" — and its inputs are mostly link-existence flags
(G11), so FD1 = 1.00 means no self-contradiction, not good selection.

F1 and F2 are the ones that would rise from the §1.3 repair. They are also the ones most
easily faked (drop the seeds, raise the budget, promote provenance). Hence §4.2: F1/F2 may
only move through a pre-registered design amendment, and the report must show the *seed*
results of the same epoch alongside, so a reader can see whether the harness improved or the
comparison baseline was dismantled.

### 3.2 Closed cause list

Every deduction (`grade < cap` for that dimension) and every `null` gets exactly one:

| cause | meaning | typical evidence |
| --- | --- | --- |
| `model_output_quality` | the provider returned unusable/invalid payload candidates | `candidate_lifecycle.status: rejected`, `fallback_events: schema_violation`, `invalid_json_events` |
| `harness_ordering` | a valid candidate existed but never got a request | `candidate_budget_receipts.*.stopped_before_execution`, queue position |
| `harness_budget` | a valid candidate was excluded by the effective budget | `budget_excluded` entries + `effective_candidate_budget` |
| `harness_scoring` | the grade does not follow from the recorded evidence | `scoring_decisions` vs `manual_scoring_evidence` vs `response_evidence` |
| `provider_failure` | transport/quota/storage failure independent of the payload | `fallback_events`, `failure`, `SIWCError`-class errors |
| `fixture_infeasible` | the fixture cannot exhibit the signal (measured, not assumed) | `method_verdicts`, `probe_controls`, census |
| `rubric_ceiling` | the cap made the deduction unavoidable | §1.2 table |
| `label` | the number is right but its description is wrong (epoch, attempt count, surface, outcome code) | `score_epoch`, `surface_scores`, `security_outcome_reason` |

Only `harness_*` rows are actionable as fixes. `model_output_quality`, `provider_failure`,
`fixture_infeasible`, and `rubric_ceiling` are **results to report**, and converting them into
fixes is the definition of benchmaxing.

### 3.3 What the graded rubric actually discriminates in this matrix

Measured 2026-10-31 over `results/validation/2026-10-31-graded-thesis-components.json` (60 records,
graded block present in 60/60, `Sexploit` non-null in 48):

| dimension | values across the 48 scored runs |
| --- | --- |
| `Smethod` | `null` × 48 |
| `Spayload` | **absent from the receipt** × 48 |
| `Sexploit` | `3` × 48 — constant |
| `Schain` | `0` × 48 — constant |
| `Soutput` | `3` × 44, `1` × 4 |

**Distinct graded vectors: 3 across all 60, and 2 across the 48 scored runs** — 44 × `(null, —, 3,
0, 3)` and 4 × `(null, —, 3, 0, 1)`. The five-dimension 0–4 rubric is currently resolving this epoch
into a single bit. Three separate causes, usually conflated:

1. **Overlap / double counting.** An orchestrator receipt's `reason_refs` is consumed **twice** —
   by `selection_grade:388` (level 4) and by `output_references_valid:732` inside `output_grade:1040`
   (level 4). One missing field therefore costs 0.20 of `Soutput` *and* blocks 0.20 of `Smethod`. In
   the same direction, `Spayload`, `Sexploit` and `Schain` all read the executed-candidate evidence,
   so "the exploit worked" carries ≈0.60 of the weight rather than the 0.30 the formula advertises.
2. **Unreachable top levels** (§1.2b): `Sexploit` cannot exceed 3 until T8, `Smethod` cannot exceed 3
   on these receipts, and `Spayload` is not emitted at all.
3. **Identifiability** (§11.2 A1): selection cannot be graded without a key committed in advance.

**What may not be done about it.** Reweighting, deleting a dimension, or re-scoring after the fact are
all changes to *what counts* (§4.1), and would need a §4.2 amendment signed before any result was
seen. The benchmax tell is exact: §1.2b shows that pinning `Sexploit` at 3 costs 0.30 of `Srun`, so
"the ceiling is unfair" is precisely the argument that would raise the number most cheaply.

**What may be done.** Report the resolution and its causes as a result; use the rubric as what it
demonstrably is in this epoch — a **structured evidence template** that names which artefacts must
exist — and, for a future pre-registered epoch, give each dimension its own evidence class so the
overlap disappears by construction (selection inputs / validation-stage / response / cross-method /
report-only).

---

## 4. Forbidden interventions (the anti-benchmax register)

This section is the operative content of the handoff. It is modelled on
§4.7 "Anti-sabotage rule" of
[HANDOFF_MAIN_STUDY_V4_REMEDIATION_2026-10-30](../active/HANDOFF_MAIN_STUDY_V4_REMEDIATION_2026-10-30.md),
which governs *validation* gates; this one governs *score* gates, where the incentive is
stronger because the number is the deliverable.

### 4.1 Frozen surfaces

The loop **must not** modify, and must verify unmodified before claiming any improvement:

| frozen thing | where | check |
| --- | --- | --- |
| **the graded score producer** | `evaluation/scoring_evidence.py`, `evaluation/thesis_scoring.py`, `evaluation/manual_scoring_sheet.py` | **frozen**: these now produce the reported score, and R2 cannot cover only the runtime caps |
| dimension caps | `agents/state_utils.py:1474`, `:1382`, `:1486`, `:217`; `core/chaining_coordinator.py:494` | `git diff` must not touch these lines |
| `Soutput` ladder | `core/scorer.py:114`–`133` | same |
| weights + `COMPOSITE_SCOPE` | `core/scorer.py` `SCORE_WEIGHTS`, `COMPOSITE_SCOPE` | constant hash |
| rubric identity | `scoring_policy.rubric_version`, `scoring_rule_sha256`, `score_epoch` | must be identical across the before/after epochs |
| readiness gates | `foundation/readiness.py` `REASON_ENDPOINT_MISSING`, `_token_required`, `crawl_ok`, `_SURFACE_ENDPOINT_FRAGMENTS` | already binding per `AGENTS.md` |
| verifier thresholds | `foundation/verifier.py` | same |
| model coordinates | `config.yaml` roles `provider`/`model`/`temperature`, `llm_runtime` | same |
| experiment identity | `experiment_condition`, `target_method`, `payload_mode`, `repeat_index`, condition definitions | same |
| measured-negative rule | `evaluation/method_verdicts.py`, `measured-negative-verdicts.v1` | same |

### 4.2 Design amendments (allowed only with human sign-off, before the score is seen)

| amendment | why it is a design change, not a fix |
| --- | --- |
| candidate queue **ordering** (LLM candidate before static seeds) | changes which payload executes first ⇒ changes the measured treatment |
| `effective_candidate_budget` 5 → higher | changes the candidate set the model is evaluated on |
| stop policy / `max_iterations` / `coverage_target` | changes how many candidates can ever run |
| prompt or schema for `payload_generator` | changes the model's task |
| any seed-library change | changes the static baseline the contrast is measured against |

Protocol for an amendment: (1) write it down with the mechanistic evidence that motivates it;
(2) state the predicted effect on F1–F7 **and** on each dimension, before running; (3) get
sign-off; (4) run the full target set on a new epoch; (5) report both epochs, both conditions,
and the *seed-only* baseline of the new epoch. An amendment whose justification is "the score
went up" is void.

### 4.3 The sixteen named benchmax patterns

| id | pattern | concrete form in this repo | why it is benchmaxing |
| --- | --- | --- | --- |
| B1 | raise the payload cap | edit `min(grade, 2 if ac_ else 3)` → `4` | score rises with no new evidence; it is a rubric change disguised as a fix |
| B2 | raise the exploit cap | `min(score, 3)` → `4` | same |
| B3 | reward `Smethod` 4 | `grade = 3 if is_viable else 1` → `4` when a plan string exists | grade 4 requires *verified references and plan* (methodology §7.1); an LLM-authored plan is not verification |
| B4 | partial `Schain` credit | `4 if completed else 0` → graded partial | §16 constraint 7: a chain is valid only if the previous outcome is proven |
| B5 | soften `Soutput` | drop `fallback_events` from the 3-class, or zero `fallback_events` | erases the only per-run signal of provider/output quality |
| B6 | provenance promotion | rewrite `origin_kind` `static_seed`→`seed_mutation`, or stamp `model` provenance onto a seed | fabricates the independent variable |
| B7 | confirmation relaxation | accept `unverified` as confirmed, or relax evidence thresholds | violates §16 constraints 5–6 |
| B8 | gate removal | any §4.1 readiness/verifier edit | turns a failing measurement into a silence |
| B9 | model shopping | swap `provider`/`model` to whatever scores higher | the model is the subject, not a knob |
| B10 | repeat cherry-picking | report best-of-3, drop a failed repeat, re-run “until a better draw” | destroys the repetition rule (§6.3) and the variance finding |
| B11 | weight/search tuning | change `SCORE_WEIGHTS` or `COMPOSITE_SCOPE` | frozen research invariant (`AGENTS.md`) |
| B12 | null → number | fill AC/high with 0, or with the cell mean, or a "conservative estimate" | §4.4 |
| B13 | fixture-fitted prompts | add DVWA-specific strings (`admin`/`password`, `1' OR '1'='1`, `/vulnerabilities/sqli/`) to prompts or seeds to lift execution | fits the model to the benchmark's answer key; destroys external validity |
| B14 | surface/cell selection | improve only the cells with headroom, drop AC/bf from the report | the matrix is pre-registered (methodology §6.2) |
| B15 | metric substitution | report a friendlier metric in place of `Srun` (e.g. "success rate", "grade share") as *the* score | a different question answered confidently |
| B16 | scoring outside the frozen implementation | hand-assigning a graded component, filling a `None` (belum dapat dinilai) with a value, or reading the artifact "by eye" to award a level | the graded rubric is a judgement per level; only `evaluation/scoring_evidence.py` may produce it, and a missing-evidence `None` is a result |

**B15 needs care**: §3.1's fidelity metrics are legitimate *harness* metrics, but they are not
the thesis score and must never be presented as an improvement in it.

### 4.4 The `null` rule

A `null` composite backed by a complete measured negative is a **result**. The loop may never
turn it into a number. It may fix the *labels* around it (§6 S5, S6) — `surface_scores` and
`security_outcome_reason` — because those are mis-descriptions of a correct measurement, but
the number stays `null` and `metric_availability.composite_score` stays `false`.

---

## 5. The loop

### 5.1 Phases

| phase | instrument | provider calls | output |
| --- | --- | --- | --- |
| **P−1 score reporting** | `evaluation/thesis_scoring.review_queue` over saved artifacts; report graded components + pending reasons (*Priority 0*, steps T1…T3) | 0 | the artifact tree restated under the thesis rubric; runtime vector kept as a labelled legacy field |
| **P0 ledger** | read artifacts only (§10) | 0 | `fidelity-ledger.json`: every run × every dimension × closed-list cause, with evidence pointers |
| **P1 queue** | rank ledger rows by (evidence strength × affected runs × actionability) | 0 | ordered hypothesis list; each row names one component and one discriminating control |
| **P2 proof** | `evaluation/scoring_repair.py` (hash-pinned rescore) is free; `evaluation/payload_replay.py` re-executes saved candidates against **fresh DVWA sessions** (`:257`, `:404`) — zero provider calls but a **live target run needing its own E2E authorisation** | 0 provider / live target | does the change alter the *grade* of inputs that already exist? |
| **P3 single coordinate** | `python -m tesis run --headless --mode matrix --config <epoch>/config.frozen.yaml --providers <p> --surfaces <s> --levels <l> --payload-modes hybrid --condition <c> --repeats 1 --iterations 10 --output-dir <dir>` — a cell is five flags, not a path (`run_full_matrix.sh`) | yes | one run, one coordinate, hypothesis under test |
| **P4 cell** | 3 repeats of one cell | yes | stability + repeat variance |
| **P5 matrix** | full target set, fresh epoch (§10 launcher) | yes | acceptance evidence |

P2 is the workhorse and the reason this loop is affordable — but only the `scoring_repair` half is free: most candidate fixes
(ordering, budget, label, provenance, attribution) are **decidable on the saved artifacts**.
No hypothesis advances to P3 without a P2 prediction that is either confirmed or refuted by
replay/rescore. **P3–P5 are authorised for exactly one epoch** (§11 Q4, 2026-10-31: one 60-run run
of the full target set, once §11.1's preconditions hold); every further cycle needs new
authorisation. The authorisation of that epoch does not extend to a second one, and `AGENTS.md`
E2E rules otherwise apply unchanged.

### 5.2 Cycle rules

1. **One hypothesis, one change.** No bundled edits; a cycle that changes two components
   cannot attribute its result.
2. **Write the prediction first.** Which runs change, which dimension, which direction, and
   what the replay should show. No prediction, no change.
3. **Falsify loudly.** Two failures of the same hypothesis ⇒ it is falsified; record it in
   the ledger as `falsified` with the evidence refs, and move to a structurally different
   component. Never re-run hoping for a different draw (§4 B10).
4. **Never widen the fix.** If a fix requires touching a §4.1 frozen surface, it is not a fix;
   it is a §4.2 amendment request.
5. **Keep the failing evidence.** Superseded artifacts are moved, never deleted, and the
   ledger cites the pre-fix artifact for every repaired defect (the 2026-10-30 tree already
   keeps `_superseded_*`; keep that convention).

### 5.3 Ranking rule for P1

P−1 is not ranked: it is unconditional and comes before any hypothesis, because reporting the
wrong score invalidates every ranking made under it.

Sort on three ordinals, lexicographically — do not multiply (these are categories, not numbers):
1. **risk of benchmax**, ascending (`none` → `needs §4.2` → `needs §4.3`);
2. **evidence strength**, descending (`artifact-only` > `artifact+replay` > `needs-live`);
3. **runs affected**, descending.
The effect is that label/attribution/measurement defects (zero benchmax risk, artifact-only)
displace score-adjacent work — which is the intended bias.

---

## 6. Discovery agenda — seeded from the 2026-10-30 baseline

Each row is already measured. The loop's job is to confirm the verdict class, find the
discriminating control, and either fix or document. **None of these are pre-approved.** They
are the starting queue, and P0 must re-derive them from the artifacts before acting.

### 6.1 Seed findings

| id | finding | evidence | hypothesis / next control | verdict class |
| --- | --- | --- | --- | --- |
| **S0** | **the reported score is produced by the wrong scorer** — `composite_score` comes from the capped runtime path, while the graded rubric lives in `evaluation/scoring_evidence.py` and has never been evaluated for this matrix | 60/60 artifacts evaluated (`2026-10-31-graded-thesis-components.json`): `Soutput` graded `3` where runtime said `4` in **43** runs and `1` where runtime said `3`/`2` in **4**; `Schain` graded `0` in **all 60** despite 6 verified chains; `Smethod` is `None` in **all 60**; `thesis_scoring_status: pending_review` everywhere | publish the graded vector with `component_pending_reasons` as the reported score, then work T2, T3, T5, T6 in order (T4 is dropped) | label + harness_scoring (**Priority 0**) |
| **S1** | LLM candidates are appended last and the run stops before reaching them | §1.3: 92 `stopped_before_execution`, LLM candidate last in 92/92 queues, 1 executed | ordering/stop interaction; control = replay the saved queue with the LLM candidate first, no provider call | harness_ordering (**§4.2 amendment**) |
| **S2** | a harness budget decision is scored as model output failure — **careful: two functions share the name `output_grade`** (`core/scorer.py:114` runtime, `scoring_evidence.py:934` graded). The run named here grades **3**, not 1, on the graded path; the four graded-1 runs are `akg/bf-medium r2`, `akg/sqli-high r2` (runtime 3) and `linear/ac-medium r2`, `linear/bf-medium r1` (runtime 2) | `Soutput 3` on **1** run whose only fallback reason is `budget_excluded_model_candidate` | `output_grade` treats any `fallback_events` as `deterministic_fallback`; the model's output was valid, the queue excluded it | harness_scoring |
| ~~**S3**~~ | ~~the artifact disagrees with itself about which rubric produced the composite~~ — **RETRACTED**: `score_epoch` is byte-identical in 60/60 and declares both layers explicitly (`runtime_provisional: scoring.v2`, `thesis_final: scoring.v4`, `final_status: pending_review`). `composite_score_status` names the *layer*, not the arithmetic. The live issue is G24, not a stale constant | `composite_score_status: runtime_provisional_scoring.v2` and `score_epoch.runtime_provisional: scoring.v2` vs `scoring_policy.rubric_version: scoring.v4`, in all 60; arithmetic matches **v4** | status constant is stale (`evaluation/runner.py:2035`, `evaluation/multi_llm_runner.py:1034`); control = recompute under both rubrics | label |
| **S4** | the proposed "gate correctness" signal does not exist | `gate_correctness` appears nowhere in `results/` or `docs/` | no producer, no consumer; if wanted it must be specified, not assumed | label / absent metric |
| **S5** | `attempts: 0` on a run that sent 5 controls | AC/high run: `report.surface_scores` all `{score 0, label "Not Found", attempts 0}` while `http_request_counters.by_role.detection_control = 5`, `probe_controls = 3`, `method_verdicts` = 3 | `surface_scores` counts executed *attacks*, not *measurements*; label defect, stays out of the loop's target set (§9.2) but must not be cited as "no activity" | label |
| **S6** | measured negative described as missing proof | AC/high: `security_outcome: unconfirmed`, reason `NO_CANDIDATE_CONFIRMATION` ("Missing or ambiguous candidate proof cannot establish presence or absence") while `measured_negative.complete: true` and 3 `not_vulnerable` verdicts | the reason code describes the *absence of an exploit*, not the presence of a measurement; decide whether the code should distinguish "measured negative" | label |
| **S7** | chain credit is binary and only reachable in one cell family — **but the cause is not the fixture**: G4a shows the collector's negative control always raises, so no dependency evidence can exist. Report the reach, attribute it to G4a, not to fixture infeasibility | `Schain 4` in 6 runs, all `deepseek/luna × akg × sqli/high`; 0 in linear, 0 in AC/bf | KG edge + adapter reachability; control = per-route eligibility census, offline | fixture_infeasible / rubric_ceiling (report as scope limit) |
| ~~**S8**~~ | ~~AC proof is floored twice~~ — **RETRACTED**, twin of the dropped T4: AC reaches `Sexploit 3` through the permission oracle on every run, and the tier clamp changes nothing (ablation). What survives is (b) only — no `PROOF_TIERS` anchor — which matters solely on the v3 path (G9, G24). Original wording: AC proof is floored twice, and the runtime artifact contradicts its own reason string | AC runs record `Spayload: 2` with `reason: verified_permission_candidate`, while the same run's `response_evidence` carries `verified_grade: 3` for that candidate (3 of 3 AC methods); separately `verified_permission_candidate` has **no `PROOF_TIERS` entry** in `evaluation/thesis_scoring.py`, and `evaluation/scoring_evidence.py:494` clamps to ≤2 ("Session/permission labels cannot replace an independent oracle") | two distinct floors: (a) runtime `min(..., 2 if ac_ else 3)` discards an emitted 3; (b) thesis tier map has no anchor for the reason. Decide whether (a) is a recorder defect or a deliberate non-crediting rule — **(a) changes AC scores, so it is a §4.2 decision, not a free fix** | harness_scoring (**§4.2**) / rubric_ceiling (b) |
| **S9** | AC/high stops without ever selecting a method — in two different ways | `akg`: `no_viable_methods`, `iteration_count: 0` (6 runs); `linear`: `selection_rejected_precondition_false`, `iteration_count: 1` (6 runs); all 12 have `attempted_agents: []` plus 5 sent controls and 3 verdicts | correct-by-design for a measured negative, but `iteration_count 0` may be read as "never tried"; needs a label decision | label |
| **S10** | iteration budget is never the binding constraint | `coverage_target_reached` 36, `selection_rejected_precondition_false` 12, `no_viable_methods` 6, `confirmed_success` 6; `max_iterations` never reached | confirms the stop policy, not the iteration cap, governs candidate spend — relevant to any §4.2 amendment | harness_ordering |
| **S11** | the `Spayload` review is never completed, and the sheet is pre-filled with the runtime grade | the artifact's **top-level** `manual_scoring_evidence` is non-empty in 48/60 (0–22 rows) but the **`final_state` copy is empty in 60/60**; `payload_score_0_4` is copied from the runtime `payload_scores` (`manual_scoring_sheet.py:108,175`), so `finalize_reviews` stays at `pending_candidate_grades` (see G10) | grades exist without the review rows that document them; `AGENTS.md` requires manual scoring to rely on artifacts | harness_scoring |
| **S12** | an agent-proven exploit grade of 4 is silently truncated | 6 runs (all `akg·sqli/high`, method `bf_dictionary`) have `final_state.scores = 4` while `exploitation_scores = 3`; the chain credit appears instead as `Schain 4` | `min(score, 3)` at `state_utils.py:1382`/`:1486`. Either the deduplication into `Schain` is intended, or `Sexploit` cannot express a completed chain — the artifact does not say which | harness_scoring (**§4.2**) |

### 6.2 What the loop must also check every cycle

- `source_hashes_sha256` identical across all runs of the new epoch (one epoch, or a documented
  epoch boundary).
- `scoring_rule_sha256` identical to the baseline, unless a §4.2 rubric amendment was signed.
- Denominator unchanged: 48 scored runs, 12 `null`.
- `containment_failures` and `fixture_restoration_evidence` unchanged.
- No run re-scored and presented as a new run.

---

## 7. Reporting rules

0. **The reported score is the graded vector** (§Priority 0). Never publish `composite_score`
   as *the* score; if it appears at all, label it `runtime_provisional_scoring.v2 (legacy)`.
1. **Never quote a `Srun` that does not exist.** For the 2026-10-30 epoch, `Smethod` is
   unreachable (G2), so the honest headline is a **three-dimension partial over 48 runs** (`Spayload` needs reviews, `Smethod` is unreachable), with
   `Smethod` reported as unavailable-by-construction and its reason quoted. AC/high is its own row
   (`not_vulnerable`, 3 methods, 5 controls, no `Srun`).
2. **Never pool conditions.** `akg` and `linear` differ by construction; pooling them hides
   exactly the treatment effect this study measures.
3. **Report the ceiling only for the vector it belongs to.** `2.70` / `2.90` / `3.30` are the
   **runtime** ceilings (§1.1); the graded rubric has different reachable maxima per cell and none of
   those three numbers is a rubric ceiling. Never place them side by side with graded components
   without saying which is which.
4. **Report `null` separate from `0`.** A `null` is a measurement; a `0` would be a fabrication.
5. **Fidelity metrics go in a separate table** from the rubric `Srun`, and never replace it.
6. **Every claimed fix carries its pre-fix artifact path.**

---

## 8. Stop conditions and acceptance

The loop stops on the **first** of:

| exit | condition | what gets written |
| --- | --- | --- |
| **converged** | F3 = 1.00, F4 = 1.00, F5 = 1.00, F6 = 0, and no open `harness_*` ledger row; every remaining deduction sits in `model_output_quality` / `provider_failure` / `fixture_infeasible` / `rubric_ceiling` | final ledger + one fresh-epoch matrix + Tables III–IV |
| **ceiling-bound** | every remaining deduction is `rubric_ceiling`, and the report says so | ledger + scope-limitation paragraph |
| **needs human** | next step is a §4.2 amendment or a §11 question | a written request, no code change |
| **falsified out** | all ranked hypotheses falsified | ledger with falsification records (a legitimate result) |

**Acceptance checklist** (all must hold before any "the harness improved" claim):

- [ ] **phase A closed** (§0.1): the 60 saved artifacts restated under the frozen `scoring.v4` path, with `Spayload`, `Sexploit`, `Schain`, `Soutput` each decided and caused; every `None` carries its reason
- [ ] **phase B closed**: T5 stages B1–B3 pass, so `Smethod` is proven reachable **before** the authorised epoch spends any provider budget
- [ ] **FD1 reported** for 2026-10-30 alongside the partial, labelled a diagnostic, absent from `Srun`
- [ ] P0 ledger complete: every deduction and null has a closed-list cause and evidence pointers
- [ ] `unknown` count = 0
- [ ] fresh-epoch matrix on the full 48-run target set; one `source_hashes_sha256`
- [ ] all §4.1 frozen surfaces byte-identical to a **named git commit** recorded at the top of the run (there is none today: `b4909695…` is a source-tree hash, not a commit), or a signed §4.2 amendment
- [ ] denominators stated exactly: a 48-run epoch cannot evidence AC/high; the 12 `null` runs are cited from the 2026-10-30 record, not re-observed
- [ ] F4/F5 = 1.00; arithmetic exact under v4 weights
- [ ] `containment_failures` and fixture restoration unchanged
- [ ] every prior "improvement" retired if its evidence was a re-scored old epoch
- [ ] tables report ceiling + denominator + `null` discipline (§7)
- [ ] the reported score is the **graded** vector; every `None` carries its `component_pending_reasons`; no component hand-assigned (B16)
- [ ] no graded `Srun` is claimed for the 2026-10-30 epoch (G2, §0.2); the partial is reported as a partial, with `Smethod` marked unreachable by construction

**A loop that cannot meet this checklist must report the gap, not narrow the checklist.**
That is the one failure mode this handoff is written to prevent.

---

## 9. Scope

### 9.1 In scope

- Offline analysis of the existing artifacts; new analysis code under `evaluation/` that reads
  artifacts and writes ledgers (no new scoring, no new runner, no new CLI unless asked).
- **Score-artifact reporting** (*Priority 0*): publishing the graded thesis vector instead of
  `composite_score`, including the `None`/pending statuses.
- Label/attribution/measurement repairs that make the harness describe what it did.
- Documentation of rubric ceilings and scope limits in `docs/reference/summary_{en,id}.md`,
  with human sign-off on wording that touches the rubric.

### 9.2 `access_control/high` — skipped (owner decision, 2026-10-30)

The 12 AC/high runs are **out of the loop's target set**. Their `Srun` is `null`
(`no_method_attempted_measured_negative`), they satisfy the DoD only through the
measured-negative clause, and they cost provider budget without producing a comparable number.

What the loop may do with them: read them (they are evidence for S5/S6/S9), keep them in the
denominator of the *record* (60 runs), and report them as a separate `not_vulnerable` row.

What it may not do: re-run them to manufacture a score, change readiness/scoring so they
produce a number, exclude them from the record, or present the 48-run mean as if it covered
the matrix.

### 9.3 Out of scope

- New surfaces, methods, models, or conditions (`AGENTS.md`).
- Deployment, target reset, fixture mutation.
- Push or commit without authorization; the loop's outputs are artifacts and docs.
- Any change to the weights, caps, `COMPOSITE_SCOPE`, or DoD (that is a human decision).
- Filling the 12 `null`s.

---

## 10. Reproduction (read-only, no provider calls)

```bash
cd /home/kevin/coding/tesis

# full matrix launcher used for the baseline (2 models x 2 conditions x 5 cells x 3 repeats)
cat results/validation/remediation-2026-10-30/run_full_matrix.sh

# offline ledger pass: reads artifacts only. Accepted trees are
#   deepseek/**/runs/matrix-2026-10-30  and  luna/**/runs/matrix-2026-10-30-2
#   (_superseded_* excluded: those are the SIWC-storage failures, kept for audit)
.venv/bin/python - <<'PY'
import json, pathlib
ROOT = pathlib.Path("results/validation/remediation-2026-10-30/full-2026-10-30")
runs = []
for model in ("deepseek", "luna"):
    for cond in sorted(p.name for p in (ROOT/model).iterdir() if p.is_dir()):
        for cell in sorted(p.name for p in (ROOT/model/cond).iterdir() if p.is_dir()):
            accept = "matrix-2026-10-30-2" if model == "luna" else "matrix-2026-10-30"
            for rd in sorted((ROOT/model/cond/cell/"runs"/accept).iterdir()):
                if not rd.is_dir():
                    continue
                f = [x for x in rd.glob("exec-*.json")
                     if not x.name.endswith((".jsonl", ".rich.json"))][0]
                d = json.loads(f.read_text()); d["_cell"] = (model, cond, cell); runs.append(d)
print("runs:", len(runs))
print("epochs:", len({json.dumps(r["source_hashes_sha256"], sort_keys=True) for r in runs}))
print("nulls:", sum(1 for r in runs if r.get("composite_score") is None))
W = dict(Smethod=.2, Spayload=.2, Sexploit=.3, Schain=.1, Soutput=.2)
bad = [r["_cell"] for r in runs if r.get("composite_score") is not None
       and abs(round(sum(W[k]*r["composite_components"][k] for k in W), 10)
               - r["composite_score"]) > 1e-9]
print("arithmetic mismatches:", len(bad))
rec = [x for r in runs for x in (r.get("candidate_budget_receipts") or [])]
llm = [x for x in rec if any("_llm_" in c for c in x.get("generated") or [])]
print("receipts:", len(rec), "with LLM candidate:", len(llm),
      "executed:", sum(1 for x in llm if any("_llm_" in c for c in x.get("executed") or [])))
PY

# Priority 0 / T1: the graded thesis vector, offline, over saved artifacts
.venv/bin/python - <<'PY2'
import json, pathlib
from evaluation.thesis_scoring import review_queue
ROOT = pathlib.Path("results/validation/remediation-2026-10-30/full-2026-10-30")
for model in ("deepseek", "luna"):
    accept = "matrix-2026-10-30-2" if model == "luna" else "matrix-2026-10-30"
    for cond in sorted(p.name for p in (ROOT/model).iterdir() if p.is_dir()):
        for cell in sorted(p.name for p in (ROOT/model/cond).iterdir() if p.is_dir()):
            for rd in sorted((ROOT/model/cond/cell/"runs"/accept).iterdir()):
                if not rd.is_dir():
                    continue
                f = next(x for x in rd.glob("exec-*.json")
                         if not x.name.endswith((".jsonl", ".rich.json")))
                q = review_queue(f)
                print(f"{model}/{cond}/{cell}", rd.name[:7], q["components"], q["component_pending_reasons"])
PY2

# Rubric gap register (G1-G24) evidence, offline
.venv/bin/python - <<'PY3'
import json, pathlib, collections
from evaluation.scoring_evidence import verified_dependencies
ROOT = pathlib.Path("results/validation/remediation-2026-10-30/full-2026-10-30")
deps, refs, hashes, obs = collections.Counter(), collections.Counter(), collections.Counter(), collections.defaultdict(set)
for model in ("deepseek", "luna"):
    accept = "matrix-2026-10-30-2" if model == "luna" else "matrix-2026-10-30"
    for cond in sorted(p.name for p in (ROOT/model).iterdir() if p.is_dir()):
        for cell in sorted(p.name for p in (ROOT/model/cond).iterdir() if p.is_dir()):
            for rd in sorted((ROOT/model/cond/cell/"runs"/accept).iterdir()):
                if not rd.is_dir():
                    continue
                f = next(x for x in rd.glob("exec-*.json")
                         if not x.name.endswith((".jsonl", ".rich.json")))
                d = json.loads(f.read_text())
                deps[len(verified_dependencies(d))] += 1
                for r in d.get("llm_performance") or []:
                    if r.get("role") == "orchestrator":
                        refs[bool((r.get("output") or {}).get("reason_refs"))] += 1
                for dec in (d.get("final_state") or {}).get("scoring_decisions") or []:
                    if dec.get("dimension") == "Smethod":
                        hashes[dec.get("profile_sha256")] += 1
                        for k, v in (dec.get("observations") or {}).items():
                            obs[cell].add((k, type(v).__name__))
print("G4a/G4b verified_dependencies per run (expect all zero):", dict(deps))
print("G6 raw call-level reason_refs (all calls, not the graded-scope 41/48):", dict(refs))
print("G1b profile_sha256 values in selection receipts:", dict(hashes))
for cell in sorted(obs):
    print("G11 bool observations", cell, sorted(k for k, t in obs[cell] if t == "bool"))
PY3

# existing offline instruments the loop must use before any live run
grep -n "no provider calls\|without making provider calls\|hash-pinned" \
  evaluation/payload_replay.py evaluation/scoring_repair.py
```

Cost notes (measured): the matrix runs a 10-iteration, low-reasoning-effort configuration.
Summed `matrix_wall_time_ms` over the 20 cells is **1,061,822 ms ≈ 17.7 min** for all 60 runs
(≈53 s per cell), so wall time is not the constraint — provider calls are. The artifacts
record **no usable spend figure** (`metric_availability.token_cost: false`,
`token_cost_per_success: false`, reason `not_computed`), so the authorised epoch's spend has to be
metered outside the artifact tree (§11.1 precondition 6).

The `luna` group failed once with `SIWCError: Unable to access private SIWC storage`
(`~/.config/tesis/siwc` outside the sandbox). That is a provider-storage failure, **not** a
harness or model finding; those artifacts are retained under
`_superseded_matrix-2026-10-30-siwc-failure` and are excluded from every number above.

---

## 11. Decisions taken, and open questions

**Decided by the owner:**

| date | decision | effect |
| --- | --- | --- |
| 2026-10-30 | `access_control/high` is skipped by the loop | §9.2 — `null` stays `null`, 60 runs stay in the record |
| 2026-10-31 | **the reported score is the graded thesis rubric** (Tabel 3.5–3.11), not the runtime `composite_score` | *Priority 0* — steps T1…T3 are unblocked; R0 and B16 added |
| 2026-10-31 | the loop does not benchmax: no cap, rubric, weight, model, repeat, or provenance change without pre-registration | §4 |
| 2026-10-31 | **Q0 — build the `scoring_profile`.** `Smethod` is *not* declared unavailable: all 15 entries are authored and frozen `confirmed` before the next epoch's first selection | T5 unblocked; the *Profile authoring work order* under Priority 0 is the spec; G1/G1b/G17 addressed |
| 2026-10-31 | **Q0b — a four-dimension partial now, a scored epoch next.** 2026-10-30 is published with `Smethod: null` + `component_pending_reasons`; the graded claim comes from a new epoch planned with a frozen profile and a declared `scoring_policy_epoch` | scope of every table; G2 accepted as **structural and not repaired**; workflow split into reachable phases in §0.1 |
| 2026-10-31 | **T7 — all four config blocks, no debate:** `repeats: 3`, `payload_mode: hybrid`, the frozen `scoring_profile`, a declared `scoring_policy_epoch`; plus G16 | G3 closed. `static_only` is a *debugging* mode (`AGENTS.md`), so this is a correctness fix, not a preference |
| 2026-10-31 | **Q4 — one provider-backed epoch** of the 60-run matrix (48 scored; the 12 `access_control/high` runs execute and stay unscored, §9.2). The authorisation is spent when that epoch completes; every further cycle needs new authorisation | P3–P5 unblocked once §11.1 holds |

**What the four mean together.** The offline repairs — T1, T3, T8, T9 — are unblocked immediately and
need no further decision. Q0 and T7 build the inputs the 2026-10-30 epoch never had; Q4 authorises
exactly one epoch in which those inputs are live. The profile is the load-bearing one: it is the only
graded input that must **pre-date** what it grades, so it has to be authored blind — from Tabel 3.5,
the static AKG and the DVWA fixture, never from the 60 recorded selections or their outcomes. A
profile fitted to observed behaviour grades the system against its own output, which is precisely what
§4 B16 forbids. If the loop ever catches itself editing a fit level or a request-count anchor after
seeing a result, that is a benchmax, not a fix.

### 11.1 Preconditions for the authorised epoch

All of these hold **before** the single authorised run, in this order:

| # | precondition | gate |
| --- | --- | --- |
| 1 | **T9** — graded rubric hard-pinned to `scoring.v4`; an artifact whose `score_epoch.thesis_final` disagrees is refused (G24) | nothing in this document is honest until this lands |
| 2 | **T1** — tables report the graded vector + `component_pending_reasons`, never `composite_score` | report shape of both epochs |
| 3 | **T8** — `dependency_oracle` negative control repaired (G4a), if `Schain` claims are in scope | chain crediting (T2 / G5) |
| 4 | **Q0** — the 15-entry profile authored, every entry `confirmed`, frozen with `freeze_ranking_profile` into `<epoch>/config.frozen.yaml` | `Smethod` exists at all |
| 5 | **T7 + F1** — the four config blocks set **in that frozen file**, and both plan validators accepting it; today they reject it (F1) | a frozen plan can be produced at all |
| 6 | cost metering available outside the artifact tree — `token_cost` and `token_cost_per_success` are `not_computed` in 60/60 (§10) | the authorisation can be spent knowingly |
| 7 | DVWA target and provider scope confirmed for that epoch — `AGENTS.md` E2E rules apply unchanged | the run itself |

**Open — none of these block the offline half; they block the result tables and the live epoch:**

| id | question | blocks |
| --- | --- | --- |
| **Q1** | Candidate ordering (§1.3): is `LLM candidate before static seeds` an acceptable pre-registered amendment? It is the only path to a non-zero F1/F2, and it changes the measured treatment. | S1, F1, F2 |
| **Q2** | Rubric caps (§1.2 for the runtime caps, §1.2b for the graded ones — the graded ceiling is 3.7, and `Sexploit 4` is gated by T8, not by a cap): do the `ac_*` `Spayload ≤ 2` and global `Sexploit ≤ 3` caps get documented as scope limits, or is a rubric amendment on the table? Document-only is the cheap, honest option. | S8, the thesis result tables (III–IV = the score/comparison tables) |
| **Q3** | Is the `surface_scores` / `security_outcome_reason` label repair (S5, S6, S9) in scope for this loop, given it touches AC/high? It changes no number. | S5, S6, S9 |
| **Q5** | Chain claim scope: is `Schain` reached only in `akg × sqli/high` a reportable scope limit, or a routing defect to investigate? | S7 |
| **Q6** | D12 (outcome variance is degenerate): the active handoff records it as *root causes fixed, recalibration deferred*, i.e. **already decided** — the open part is only whether this loop performs the recalibration. Confirm, or drop the question | report shape |

### 11.2 Ambiguity register — parked, to be resolved later

Written 2026-10-31 because the owner and this document disagree about one thing and neither side
should be silently overruled in prose. **An entry here is not decided.** Nothing in the loop changes
while an entry is open; the default behaviour recorded in §0.2 stands until the entry is closed.

| id | ambiguity | status | closes when |
| --- | --- | --- | --- |
| **A1** | **What `Smethod` is a measurement *of*.** §0.2 treats it as "agreement with a ranking committed before the run", which makes a post-hoc profile worthless. The owner's position: the object being measured is *the model's method selection*, which is recorded in full — so why should the date of the ranking change whether the selection can be graded? | **open — needs an owner decision** | the resolution test below is run, *or* the owner simply decides |
| **A2** | **FD1's reference has no stamped freeze date.** The static AKG is the yardstick FD1 checks against, and it is older than the runs — but the artifact's `akg.snapshot.json` carries no `frozen_at` (keys: `nodes`, `edges`, `method_preconditions`, `schema_version`, …), so its "before the run" status rests on the repo file's last commit (`core/knowledge_graph.py`, 2026-10-30 17:40 WIB, ≈1 h 20 m before the first selection) plus the recorded source-tree hash | **open — cheap to close** | either the AKG's provenance is added to the snapshot, or FD1 is reported with that caveat attached |

#### A1 in detail

**What is not in dispute** — both readings accept all of this:

- the selections are recorded: 1,032 `selected_at` stamps, each with the chosen method, the candidate set, and the observations visible at that moment;
- at run time `config.scoring_profile` was `{}`, and every selection receipt carries `profile_sha256: null` (126/126);
- `validate_profile` rejects any profile whose `frozen_at` is later than the `selected_at` it grades, and back-dating is forgery (B12/B16);
- 12 of the 60 runs carry no selection snapshot at all.

**Reading 1 — the document's current position (§0.2).** `Smethod` grades a choice against a
commitment made before the choice. A ranking authored afterwards is a restatement of the results,
so the number would measure agreement with its author rather than the model. A rerun is a new exam
with a new key, which is legitimate; a back-fill of this exam is not.

**Reading 2 — the owner's position.** The thing worth measuring is the selection, and the selection
is fully in hand. A ranking built from the protocol documents, Tabel 3.5 and the static AKG is a
defensible yardstick regardless of when it was typed; the hindsight risk is real but declarable, and
that is what `reference_reason` fields are for.

**Why the date matters — the arithmetic, stated so it can be argued with.** Five cells, 12 graded
runs each, and only 2–4 candidate methods per cell. The profile has 15 entries, so one ordering
decision in `brute_force/medium` (2 methods) determines how 12 of the 48 graded runs score. A
yardstick with that much leverage, chosen by someone who has seen the results, can be chosen to
score well — and if any defensible key is acceptable, then a flattering key is always available.

**The resolution test — cheap, offline, and it settles the question without anyone having to win.**
Write **two** profiles independently, both defensible from protocol material alone, deliberately
differing where the protocol is silent (e.g. `bf_dictionary` vs `bf_spray` in `brute_force:medium`).
Grade the epoch with both.

| outcome | conclusion |
| --- | --- |
| the two keys produce **materially different** vectors | the quantity is not identifiable from the material available — Reading 1 holds, the null stands |
| the two keys produce **the same** vector | the epoch is gradeable in a way that survives the choice of key — Reading 2 is vindicated, and the graded vector may be reported **labelled** "post-hoc agreement, keys agree" |

Either way the epoch's `Smethod` must never be reported as if a profile had been frozen in advance,
and the result is recorded here with both vectors attached.

**Why this cannot stay in prose.** Resolving A1 in favour of Reading 2 is a §4.2 rubric amendment
(it changes what counts as a valid grading input). It is therefore an owner decision, taken on the
record, not something the loop may adopt by editing a document. Until it is taken, the reported
result is the four-dimension partial of §0.1 phase A.

---

## 12. References

- [HANDOFF_MAIN_STUDY_V4_REMEDIATION_2026-10-30](../active/HANDOFF_MAIN_STUDY_V4_REMEDIATION_2026-10-30.md) — defect register D1–D13, the validation-gate analogue of §4, and the matrix that produced this baseline.
- [summary_en.md §7.1](../reference/summary_en.md) — `Srun` weights, `scoring.v4`, `Spayload_final` definition, `Smethod` grade semantics.
- [summary_en.md §16](../reference/summary_en.md) — non-negotiable constraints (esp. 5, 6, 7, 8, 9).
- [AGENTS.md](../../AGENTS.md) — runtime invariants, containment, E2E authorisation rules, artifact schema.
- `docs/docx/bab-3-reconciled-2026-10-29.docx` — Tabel 3.5–3.11, the graded 0–4 rubric this handoff is now ordered around. Text extract used for the audit: `results/validation/bab3-reconciled-2026-10-29.extract.txt` (gitignored).
- `evaluation/scoring_evidence.py` — the implementation of that rubric (`selection_grade`, `automatic_components`, `chain_grade`, `output_grade`).
- `results/validation/2026-10-31-graded-thesis-components.json` — the graded vector for all 60 runs (gitignored); produced by `review_queue` over saved artifacts, no provider calls.
- `evaluation/payload_replay.py` — revalidate + execute saved candidates, no provider calls.
- `evaluation/scoring_repair.py` — hash-pinned rescore of frozen inputs.
- `evaluation/research_analysis.py` — availability-aware aggregation; never fills nulls, never pools epochs. The loop must consume this rather than compute its own score.
