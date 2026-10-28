# Handoff: Chapter 3 experiment-flow drift and probe-control policy

Status: **completed implementation; archived by owner direction on 2026-10-29;
research acceptance remains pending**. The owner approved the bounded-control
policy on 2026-10-28. Runtime, configuration and payload-mode corrections were
implemented in the same workstream as the
[payload-modes handoff](HANDOFF_LLM_PAYLOAD_MODES_2026-10-28.md). The derived
revision is [Chapter 3 revised](CHAPTER_3_REVISED_2026-10-28.md); the source
`bab 3 only.docx` is preserved unchanged. The owner moved this handoff to
`docs/completed/` after implementation; section 8 retains the passing checks
and outstanding scientific prerequisites. This lifecycle closure does not
establish full research acceptance. The source DOCX remains in `docs/active/`
for the [document reconciliation](HANDOFF_COMBINED_THESIS_DOCX_RECONCILIATION_2026-10-29.md).
No live experiment result is claimed here.

The original sections below record the investigation and proposed remediation.
Where they say "upcoming" or "recommendation", read them as pre-implementation
wording; the current policy is the approved bounded-control policy described in
section 4.

## 1. Purpose and source precedence

Compare the complete [Chapter 3 thesis document](../../bab%203%20only.docx),
including Figures 3.1–3.4, with the current runtime. The objective is a
credible comparison of `linear_hybrid` and `akg_guided_hybrid`, not just a
workflow that finishes. Address the related
[payload-modes handoff](HANDOFF_LLM_PAYLOAD_MODES_2026-10-28.md) as part of the
same research protocol.

For evaluation tables, the owner explicitly chose the repository's **v4**
contract over the older tables in the DOCX. The normative replacement for
Tables 3.5–3.11 is [thesis scoring v4](../reference/thesis_scoring.md#report-rubric-and-illustrative-conditions),
implemented by [thesis_scoring.py](../../evaluation/thesis_scoring.py) and
[scoring_evidence.py](../../evaluation/scoring_evidence.py). Do not implement
older DOCX rubric wording or silently change the v4 formula, proof ceilings,
final-method scope, or historical rubric versions. Table 3.4 and surrounding
prose must also be reconciled with the actual availability of v4 evidence.

The frozen [scoring-v4 fresh matrix](../../evaluation/scoring_v4_matrix.py) is a
separate 108-coordinate scoring/remediation design: one provider, both
conditions, nine forced methods, three levels, `hybrid` and the historical
`llm_mutation_only`, and one repeat. It is **not** the Chapter 3 primary study
of model method selection with three repeats. Preserve that design, its pinned
inputs, and existing artifacts. A changed policy requires a new declared
code/config epoch; do not overwrite or relabel historical runs.

Preserve DVWA-only containment, the three surfaces and nine methods, static
agents and AKG, verifier-in-agent topology, observation history, candidate
provenance, all experiment identity fields, and all five score dimensions.
The primary comparison remains the two hybrid conditions. `static_only`, strict
mutation-only, and Template are separate controls or ablations, not replacements
for the primary study.

## 2. Drift inventory

The entries distinguish **current code**, **Chapter 3's claim**, and the
required treatment. They are not claims that a live DVWA experiment has been
performed or that every existing result is invalid.

### D1 — Forced method coordinates cannot measure model method selection

Chapter 3 describes both a model-selected method and a matrix over each of the
nine methods, with three repeats; Figure 3.1 also treats method-selection quality
as a dependent variable. However, a method-level matrix assigns every method as
`target_method` ([matrix expansion](../../evaluation/multi_llm_runner.py#L514-L538)).
The [orchestrator](../../agents/orchestrator.py#L287-L330) selects that target
directly, before its normal model call, and
[stop_reason](../../core/workflow_policy.py#L37-L53) stops after that method is
attempted. This is suitable for forced-method/payload coverage, not for claiming
that the model chose, adapted, or chained through the target. V4 records
`forced` separately and explicitly says it cannot establish model selection
ability ([v4 evidence rules](../reference/thesis_scoring.md#evidence-and-final-method-rules)).

**Remedy:** retain forced-method coverage, but add a separately identified
surface-level selection block with `target_method=None`, both primary
conditions, and at least three repeats. Compare model-origin first choices and
actual subsequent decisions only in selection opportunities with call evidence;
report deterministic fallback, forced selection, and AKG route selection as
separate sources. Keep v4 `Smethod` on its documented final-selection snapshot;
any first-choice metric is an additional, explicitly defined metric.

### D2 — Endpoint discovery is being treated as measured precondition evidence

Chapter 3, Table 3.2, and its AKG discussion describe observations such as
`error_messages_enabled`, `union_select_possible`, `response_diff_detectable`,
and `response_delay_measurable` as conditions supported by observed signals.
In [recon](../../foundation/recon.py#L770-L793), presence of an SQLi endpoint
sets the first two to true, and discovery of the blind endpoint sets the latter
two to true. Discovery alone does not demonstrate an error, UNION feasibility,
a response difference, or a measurable delay. The AKG then accepts those
booleans as satisfied ([viability check](../../core/knowledge_graph.py#L510-L518)).
The [observation reducer](../../core/state.py#L11-L25) never changes an earlier
true to false, so a later failed probe does not correct that earlier assertion.

**Remedy:** distinguish endpoint discovery from evidence-backed preconditions.
Store source, fixture/principal/session scope, method, observation time, and
control/evidence references as immutable facts; derive current precondition
status as true, false, or unknown without erasing history. Use a bounded,
method-appropriate control or independently attested fixture evidence, not the
endpoint name, to establish each claimed signal. Unknown, transport failure,
and missing control are not false. Apply the section 4 control policy rather
than running arbitrary invasive probes. Update ranking snapshots and readers so
v4 receives evidence-supported inputs without changing its rubric.

### D3 — A fixed target can proceed despite an unproved prerequisite

The same [forced-target branch](../../agents/orchestrator.py#L296-L330) checks
that the target belongs to the surface, but selects it even when it is absent
from `viable_methods`. For example, the error agent also permits a validated
exploit after clean HTTP responses without an observed error signal
([agent behavior](../../agents/sqli/sqli_error_agent.py#L63-L75)). Chapter 3
says a method is viable only when its precondition is established.

**Remedy:** assess target viability using D2's trustworthy evidence before
exploitation. For an explicit target, retain its identity and report the
specific false, unknown, fixture, or environment reason; never silently switch
methods. For automatic selection, keep the baseline's canonical choices
visible to the Linear model, but enforce the common scope and evidence gate
after selection and record a rejected choice. AKG-guided selection may filter
using the proved viable set before the call. Do not give the baseline model the
AKG viable set under another name. If a necessary precondition cannot be
measured safely, classify the coordinate as infeasible or incomplete, not a
model failure.

### D4 — Readiness and fixture equivalence are not established by a run label

Chapter 3's validation protocol requires the intended DVWA state, successful
session, security level, required endpoint, and token before a run; environment
failures are not model failures. [Recon](../../foundation/recon.py#L614-L640)
logs a failed login and continues an unauthenticated crawl, and can replace the
requested level with a detected level. [Session setup](../../foundation/session_manager.py#L265-L332)
logs an unsuccessful security-form submission and detection can fall back to a
cookie or local value. These paths alone do not prove the requested fixture and
level were established. Some downstream failures are already classified; do not
claim every failure is currently unclassified.

**Remedy:** introduce a documented readiness decision before selection and
candidate execution, with separate requested and observed level, authentication
and endpoint/token evidence, fixture/protocol identity, and a specific failed or
unknown reason. Fail closed on a required readiness failure. Preserve the
requested matrix coordinate rather than relabeling it as a different level.
For each comparison/repeat, establish the same fixture state or a documented
reset/isolated equivalent; HTTP serialization alone does not prove fixture
restoration. Do not invoke reset endpoints or change fixture data without the
operator's authorized protocol.

### D5 — Configured candidate budget is not the enforced exploit-queue budget

Chapter 3 describes the same candidate/attempt budget across models. The
[builder](../../foundation/payload_generator.py#L321-L350) uses the configured
budget for generation, while the [validator](../../foundation/payload_validator.py#L311-L315)
ranks against the profile's `max_total_candidates`; the queue may also contain
probe seeds. The [ranker](../../foundation/payload_ranker.py#L6-L17) puts
chain-derived candidates first, then static seeds, then model candidates. Agent
loops can stop after an earlier success, so even a generated and validated
candidate need not be executed.

An offline call using `bf_dictionary`, `static_only`, low, and
`candidate_budget=1` produced a validated queue of six: two probes and four
exploit candidates. This demonstrates a configuration/queue mismatch; it is
not a measurement of live HTTP attempts.

**Remedy:** define and enforce one versioned per-visit budget for distinct
validated exploit/bypass candidate IDs across all origins. Define separate,
fixed budgets for detection and candidate-verification control requests, and
record actual HTTP request/retry counts separately from candidate counts.
Apply the same policy to both primary conditions. Record generated, valid,
queued, executed, stopped-before-execution, and budget-excluded candidates with
reasons. Do not award or impute an LLM outcome for an unexecuted candidate.
Do not silently reserve a model slot or change hybrid ordering in historical
runs; any revised scheduling is a newly declared policy and scoring-profile
epoch.

### D6 — Hybrid success is not automatically LLM payload success

Chapter 3 asks to compare static and LLM payload quality. Hybrid combines
seeds and model variants, but a seed may confirm before a model candidate runs;
seed-first ranking and the stop-on-success behavior make that possible.
`Spayload_final` in v4 averages **all distinct executed validated exploit/bypass
candidates of the final method**, not just model candidates
([v4 rules](../reference/thesis_scoring.md#evidence-and-final-method-rules)).
The historical mutation-only name also currently permits static fallback at
[generation](../../foundation/payload_generator.py#L352-L378) and
[validation](../../foundation/payload_validator.py#L293-L309).

**Remedy:** preserve the v4 composite and add separately named, visit- and
candidate-attributed LLM outcomes, as specified in section 5. Implement strict
mutation and Template through the companion handoff; do not present a
seed-backed or unexecuted result as model payload correctness. A hybrid result
still measures the combined workflow, not an isolated model's generative skill.

### D7 — Existing detection controls can affect and leak into the experiment

Chapter 3 permits seeds as controls, but a stage label alone does not make a
request scientifically neutral. [Initial recon](../../foundation/recon.py#L714-L725)
uses brute-force seed probes; [destination recon](../../foundation/recon.py#L178-L287)
uses brute-force and Access Control controls; all nine method agents have probe
stages. The [IDOR probe](../../agents/access_control/ac_idor_agent.py#L51-L87)
can read object responses, and the [time probe](../../agents/sqli/sqli_time_blind_agent.py#L72-L117)
sends a delay request. Brute-force probing can affect rate-limit state; its
[helper](../../agents/brute_force/bf_dictionary_agent.py#L190-L192) even inserts
dedicated credentials when passed an empty probe list. These are potential
contamination and inference risks, not proof that any particular run leaked or
changed state. Frozen method `probe_controls` and v4 probe exclusion already
exist, but not all recon and destination controls use that same visit-bound
contract ([freezing](../../foundation/payload_validator.py#L410-L418)).

There is also an identity collision. The
[force-browse agent](../../agents/access_control/ac_force_browse_agent.py#L186-L209)
passes already-tried probe values into exploit execution, which skips a
matching normalized path. The v4
[review queue](../../evaluation/thesis_scoring.py#L329-L340) can nevertheless
mark an exploit candidate `eligible` merely because its payload string is in
the combined `tried_payloads` list. An offline synthetic example with a
candidate equal to an earlier probe sent no candidate request but produced
`eligible=True`, `status=not_assessable`, and a null proof ceiling. This is
misclassification and can leave review pending; the example did **not** grant
full-success credit.

**Remedy:** adopt the explicit, bounded detection-control recommendation in
section 4, subject to owner confirmation. Ensure the implementation covers
recon, destination probing, method probes, hard-coded empty-list fallbacks,
independent verifier controls, replay, and artifact consumers—not only the
payload builder.

### D8 — The two conditions differ in more than the label “AKG absent”

Chapter 3 Table 3.3 describes Linear as not using AKG. In code,
[eligibility](../../core/workflow_policy.py#L15-L25) gives the Linear selector
the surface's canonical list and the AKG selector the observation-based viable
list, but both use the shared AKG payload profile and validator. Cross-surface
AKG chaining is also enabled only for the AKG condition
([router](../../core/chaining_coordinator.py#L68-L80)). Therefore the overall
outcome contrast combines selection guidance and chain-routing differences; it
is not a pure isolated effect of the selection prompt, nor a completely
AKG-free safety implementation.

**Remedy:** describe Linear as **not AKG-guided for method selection or chain
routing**, while accurately disclosing common scope, payload-profile,
validation, and scoring constraints. Predeclare the overall comparison as the
combined workflow effect. Analyze model-origin selection decisions separately;
if an isolated selection-only effect is desired, predeclare a matched common
stop/chain policy as a separate analysis, not an unnoticed change to the main
conditions.

### D9 — Graph edges are not proof that every chain is executable

Chapter 3 and Figure 3.4 describe possible edges, including
`admin_session_obtained -> sqli_union`. The static graph contains routes, but
[the current destination adapter gate](../../core/chaining_coordinator.py#L204-L232)
only supports `credentials_extracted -> bf_dictionary` and
`authenticated_session -> ac_idor|ac_force_browse` with additional bound source
material. Other routes are explicitly infeasible. An edge, route selection, or
model plan alone is not a completed causal chain; forced-target runs stop before
continuation.

**Remedy:** keep the static topology and report each edge as available,
actually executed, independently confirmed, or infeasible with its reason.
Implement a missing source-consumption adapter only where the authorized DVWA
fixture and real source-to-destination evidence support it; otherwise preserve
the explicit limitation. V4 tier 3/4 chain claims require the documented
source/use/destination controls, not merely an AKG path. Correct Figure 3.4's
caption/prose to distinguish conceptual edges from available runtime adapters.

### D10 — Some requested metrics and final scores are not presently assessable

Chapter 3 requests first-choice accuracy, method alignment, AKG path validity,
token cost per success, consistency, and comparative results. The v4
[metrics builder](../../evaluation/thesis_scoring.py#L451-L482) explicitly
returns the first four as null with reasons under its current contract. V4
finalization also stays pending when candidate grades, component evidence, or
the executed-candidate denominator are missing
([finalization](../../evaluation/thesis_scoring.py#L669-L705)). Human and AI
payload reviews are separate options; the evaluator does not alter graph state
or replace independent oracles. Runtime `scoring.v2` composites are provisional,
not interchangeable with final v4 receipts.

**Remedy:** retain nulls and coverage, and report precisely which evidence is
missing. Add separately versioned, evidence-backed metrics only when their
inputs exist: initial model selection against a frozen ranking; a distinct
method-alignment verdict; a complete edge-by-edge trace; and token cost from a
frozen timestamped price schedule and actual usage. Do not infer full Access
Control/Brute Force success from response visibility or a login marker: v4
requires its independent permission/session controls. Do not change the seven
v4 rubric tables to make missing evidence score as zero or success.

The subsequent scoring audit identified concrete v4 evidence, score-level, and
metric defects beyond simple unavailability. Section 5.1–5.3 makes their
remediation and acceptance part of this handoff; they are prerequisites for
thesis evidence, not a separate optional cleanup.

### D11 — Matrix aggregation and statistics can pool incomparable evidence

The Chapter 3 design promises identical conditions and complete repeated
artifacts. The general matrix aggregate groups by provider, surface, level,
and payload mode, not condition or target method
([aggregate](../../evaluation/multi_llm_runner.py#L184-L203)); its averages use
lifecycle-successful rows and include provisional runtime summaries. The
[existing exploratory notebook](../../evaluation/mann_whitney_u.ipynb) explicitly
uses a historical forced-target mutation-only archive, warns about matching and
historical score problems, and does not establish the primary hybrid result.

**Remedy:** construct research summaries from uniquely identified source runs
and matching final v4 review receipts, grouped by model/provider, condition,
surface, level, target or selection block, mode/policy epoch, fixture/protocol,
and repeat. Preserve all planned, failed, incomplete, unassessable, and
fallback counts and their reasons; do not replace missing scores with zero or
silently pool v2/v3/v4. Pair Linear/AKG runs only when the declared coordinates,
fixture controls, and evidence are comparable. Predeclare a paired analysis for
matched runs; Mann–Whitney remains exploratory/supplementary when its
independence assumption is not met. Report sample sizes, exclusions, effect
size, uncertainty, and multiple-comparison policy. No conclusion follows from
three repeats alone.

### D12 — Figures and preflight need an explicit freeze/epoch boundary

Figure 3.2 starts with AKG design but omits the preliminary-validation stage
specified in the text; its loop from an incomplete matrix back to configuration
changes can be read as changing budget/fallback inside one experiment. Figure
3.3 accurately sketches the graph's main nodes but does not show forced-target
selection, no-candidate direct stopping, or the distinction between runtime
scores and later v4 review. The repository dry run is an **offline** graph,
configuration, and static-contract check; it is not a live DVWA test.

**Remedy:** revise the figures and prose after implementation: validate the
preflight gates, freeze inputs, collect immutable runs, review, then analyze.
If configuration, code, fixture, prompts, controls, or budgets change, start a
new identified epoch and retain prior attempts and reasons; do not selectively
replace unfavorable runs. State the limits of the offline dry run and separately
identify any authorized live DVWA/provider validation.

## 3. Proposed experiment design

Use two complementary blocks rather than presenting one as evidence for both
questions. Both keep `linear_hybrid` and `akg_guided_hybrid` with `hybrid`.

| Block | Coordinate | What it can assess |
| --- | --- | --- |
| **Selection/workflow** | model × condition × level × surface × repeat; `target_method=None` | Model-origin method choice, bounded adaptation, workflow/chain behavior, and combined-condition outcomes. |
| **Forced-method coverage** | model × condition × level × registered method × repeat; surface derived from method | Per-method agent and payload evidence; not LLM method-selection ability or automatically an end-to-end chain. |

Declare at least three repetitions per coordinate, as Chapter 3 requires, and
record planned versus completed counts. The forced-method block has
`Nmodel × 2 × 3 × 9 × 3` runs at that minimum; the additional selection block
has `Nmodel × 2 × 3 × 3 × 3`. These are distinct planned blocks, not a command
to run a matrix. Compare conditions within the same block, model, fixture,
level, surface, repeat policy, candidate/control budgets, prompt/schema epoch,
provider settings, and scoring profile. Matching is not established merely by
matching labels: verify or document equivalent fixture state and control
results, and mark a pair unmatched if that evidence is missing. Do not merge
ablation-mode runs with the hybrid primary comparison.

For future Chapter 3 prose, the following is a proposed replacement, not a
claim about the current implementation:

> Perbandingan utama dilakukan pada dua kondisi `linear_hybrid` dan
> `akg_guided_hybrid` dengan payload hybrid. Pada blok pemilihan metode,
> `target_method` tidak ditetapkan sehingga keputusan model dan adaptasi dapat
> diamati. Pada blok cakupan metode, setiap metode ditetapkan secara eksplisit
> untuk menilai agen dan payload; pemilihan paksa tidak dianggap sebagai
> keputusan model. Kedua blok menggunakan kondisi fixture, batas kandidat,
> kontrol, dan rubrik v4 yang dibekukan serta minimal tiga repetisi. Hasil yang
> tidak dapat dinilai tetap dicatat bersama alasannya.

## 4. Approved solution to payload-mode handoff section 4

**Approved policy (owner, 2026-10-28):** allow explicitly predeclared, isolated, bounded detection
controls in all modes, including strict mutation and Template, but keep them
outside the exploit queue and model-attributed success. Describe strict modes
as “LLM-generated exploit/bypass candidates with fixed detection and independent
verification controls,” not as “no static HTTP requests” or a fully autonomous
seed-free penetration test. This preserves measurable method preconditions and
v4's independent verification; prohibiting every static request would prevent
some methods from being fairly or safely assessed. It does mean that these
ablations measure generation under shared framework assistance, not an unaided
model. If a suitable control cannot be isolated or verified, mark the coordinate
infeasible/incomplete rather than inventing a result.

### 4.1 Control classes and boundaries

1. **Fixture/setup:** authentication, security-level setup, and known fixture
   checks use only authorized, contained requests and do not establish exploit
   success. Record the requested/observed state and failure reasons.
2. **Detection/precondition controls:** use only a frozen, versioned,
   method/level/fixture-specific allowlist. Validate before HTTP and record true
   library origin, control ID and hash, phase, purpose, method, visit or recon
   scope, principal/session identity, request/response or timing evidence,
   outcome, and per-control request budget. Separate their queue and budget from
   exploit candidates. Apply an equivalent policy to paired conditions; any
   unavoidable difference is explicit and makes an unmatched comparison
   ineligible for a paired claim.
3. **Candidate verification controls:** permit method-specific baselines,
   repeated candidate requests, and candidate-derived controls when required to
   assess a candidate, such as a boolean complement or timing baseline. Bind
   each to that candidate, visit, purpose, and response; they are controls, not
   independent model-generated candidates. Keep the independent oracle
   requirements and evidence ceilings of v4. Verification controls must not
   become alternate exploit candidates.
4. **Independent fixture/oracle controls:** preserve v4's separate permission,
   session, and causal-dependency controls. Their role, budgets, session
   isolation, and provenance differ from detection controls; they cannot
   silently alter graph decisions or give a model credit for their own result.

Controls must not enter the LLM-candidate denominator, consume an exploit
candidate slot, stand in for a missing/rejected model output, or independently
write method-confirmed nodes, achieved outcomes, recovered credentials, or
chain-credit claims. Positive model outcomes require the model candidate's own
validated execution and linked verifier evidence, with any independent control
used only in its declared evidentiary role. Do not stop using necessary
controls merely to produce a higher or more complete score.

Isolation is an actual fixture property, not a label. Prefer read-only,
non-sensitive controls and distinct fresh sessions; enforce the request/delay
limits and verify known-invalid brute-force controls against the fixture. If a
probe unexpectedly authenticates, returns sensitive data, mutates a session,
changes rate-limit state, or proves the assessed exploit, retain a redacted
control event, quarantine the visit, and reset/re-establish the fixture under
the authorized protocol before any comparable continuation. If restoration
cannot be established, mark the run incomplete. Do not reuse the control's
credentials or result as a model-created outcome. A control may establish an
observable precondition only to the extent its evidence actually supports it.

Freeze and validate controls consistently for initial recon, method visits,
chain-destination probes, replay, and any helper-level fallback. In particular,
remove implicit fallback from an empty brute-force control list: empty means no
request, not permission to insert static credentials. The current method-stage
freezing is useful but is not proof that every other control already meets this
contract. Retain request role and source separately from `stage`; a `probe` label
or a hash alone does not prove isolation or independent truth.

The current [frozen-control validator](../../foundation/payload_validator.py#L359-L376)
requires the complete ordered canonical probe set for the visit. A revised
allowlist therefore needs a versioned control-catalog and replay contract, not
an in-place redefinition of historical canonical records. Preserve old
snapshots and hashes, and make readers interpret each recorded policy version
without rewriting old artifacts.

### 4.2 Template confidentiality and the numbered item 4

The companion handoff's **section 2, item 4** also identifies a distinct
provenance problem: the current generator and validator require a canonical
`source_seed_id` ([generator](../../foundation/payload_generator.py#L78-L110),
[validator](../../foundation/payload_validator.py#L166-L187)). Queue-local
payload deduplication cannot by itself say whether a model copied a seed that
is not in the queue. This is not solved by the probe-policy choice.

Use a versioned discriminated origin contract: seed-origin mutation binds a
real supplied seed and model call; Template binds a real neutral template ID,
version/hash, model call, candidate, method, and visit, with no fabricated seed
ID. The runtime—not an LLM-supplied `source`—assigns the trusted origin. Keep
method/parameter/scope/resource validation, independent v4 evidence, and
historical seed-based readers intact. Capture exact equality to a **supplied**
seed separately from equality to another local canonical seed; neither proves
novelty. A changed string is not proof of a new technique.

Template prompts require a closed allowlist of task context and sanitized,
typed observations; do not pass working seed payloads, solved credentials,
raw probe responses, histories, profile helper fields, or prior successful
outputs indirectly. The [existing mutation prompt](../../llm/prompts/payload_generation_prompt.py#L22-L68)
is seed-backed and filters observations by key name, so it must not simply be
reused as the Template contract. A template is inert and never itself queued
or executable. If a method/level cannot be supported without disclosing the
answer or bypassing a precondition, record an explicit feasibility limitation.
In particular, do not assume Template brute-force generation can succeed
without the fixture credentials, or feed chain-derived credentials to the
model and then call the task seed-free. A chain requiring unavailable source
material remains infeasible rather than receiving substituted static credit.

## 5. Evidence and metrics contract

For each planned generation opportunity and method visit, retain a versioned
policy, run/execution/visit/method identity, prompt and schema identity,
provider/model and logical/physical call receipts, status and failure reason,
trusted candidate origin, seed/template or control reference, validation,
queue/budget decision, execution/response or timing evidence, and matching
verifier decision. Keep secret-bearing fixture material out of public artifacts
and prompts; use existing redaction and evidence-reference patterns.

Report separately, by mode and origin:

- planned visits and generator opportunities, actual calls/cache hits,
  refusals, invalid outputs, provider failures, and no-call reasons;
- parsed model candidates, validated model candidates, queued and executed
  model candidates, and unexecuted/budget-excluded candidates;
- candidate-linked confirmed positives, independently verified negatives,
  partial signals, and missing/ambiguous evidence; report evidence coverage;
- static, chain-derived, detection-control, and verifier-control activity,
  explicitly excluded from model-candidate success.

For a model-confirmation rate, use confirmed model candidates divided by
**assessable executed model candidates** only when the denominator is nonzero;
report the assessable/total-executed coverage alongside it. Declare whether
partial evidence is assessable for the specific binary question; never convert
missing or partial proof into a verified negative. A separate validity rate can
use validated model candidates over parsed model candidates, while malformed
responses are reported at the call level. Preserve numerator, denominator,
reason, and `null` where unavailable. These additional model-attributed metrics
do not redefine v4 `Spayload_final`, `Sexploit`, or `Srun`.

### 5.1 Scoring audit: scope and version boundary

Implement the following v4 corrections together with the experiment-flow and
payload-mode work. This handoff is **active**: implementation is in progress and
the observations below still require authorized acceptance evidence before they
can be treated as complete. Use the published v4 tables,
proof ceilings, independent oracles, final-method candidate denominator, and
the existing weighted formula. Runtime `scoring.v2` values are provisional and
must not be presented as final v4 grades. Correct v4 implementation defects in
a new code/config/policy epoch with a recorded scoring-rule hash; retain
historical artifacts and receipts unchanged. If a proposed change would alter
a published rubric or an established metric's meaning rather than correct its
implementation, obtain an explicit research decision and version that contract;
do not silently redefine v4.

At the time of this audit, [config.yaml](../../config.yaml#L233-L236) selected
v4 with an empty `scoring_profile`. For an in-scope method, the
[v4 selection scorer](../../evaluation/scoring_evidence.py#L104-L125) returns
`ranking_unavailable` without that profile, so a complete final composite
cannot be established. The same config also selected `static_only` and one
repeat. Recheck effective config before implementation or experiment; do not
silently overwrite the owner's defaults. Before the primary study, freeze an
evidence-backed ranking profile and experiment settings that match the actual
fixture, protocol, candidate budget, and code epoch. Historical pilot profiles
are not automatically valid for a changed experiment.

The provisional [runtime output scorer](../../core/scorer.py#L34-L55) emits
0, 2, 3, or 4, not 1; its 3 means deterministic fallback. The
[v4 output scorer](../../evaluation/scoring_evidence.py#L410-L477) has branches
for all five grades and uses 1 for validated fallback. A missing grade in one
real experiment is not by itself a defect. In the historical
[108-coordinate review](../../results/validation/scoring-v4-live-acceptance-2026-10-10/acceptance-summary.json#L144-L174),
v4 `Soutput` had four 1s, 33 2s, and 71 4s, with no 0s or 3s; all targets were
forced and some reviews were pending. This distribution is historical, not
proof of current model performance or a reason to manufacture missing grades.

### 5.2 Required v4 evidence and score corrections

1. **Required model calls and `Soutput`.** Derive the required roles and visits
   from the actual frozen workflow and selection source, including legitimate
   early stops and zero-call controls. A valid generator receipt must not hide a
   missing required orchestrator receipt, or vice versa. Bind every call,
   recovery, and output event to its role, method, visit, and call identity.
   A missing required receipt is pending, not a clean 4. Distinguish a real
   provider/transport failure from a returned refusal or malformed model
   output; preserve operational failure status and do not describe a provider
   failure as a model refusal. Permit v4 0–4 and `null` according to the
   established rubric, rather than copying the provisional v2 mapping.

2. **Fallback credit.** Award v4 fallback score 1 only when the fallback was
   actually used and validated for that same role and visit. A static probe,
   an unrelated method, or a valid seed from another visit cannot satisfy the
   check. For an orchestrator fallback, validate and bind the deterministic
   method decision; do not require an unrelated static payload as proof. A
   strict payload-generation failure cannot receive static-seed credit merely
   because a control or hybrid seed exists elsewhere. Preserve the evidence
   for valid repair, failed repair, refusal, provider failure, and no-call
   cases without letting one role's recovery erase another's failure.

3. **Candidate execution and provenance.** Replace string-only execution
   inference in [review_queue](../../evaluation/thesis_scoring.py#L318-L340)
   with an actual exploit/bypass request bound to the candidate, method, visit,
   and request/response evidence. The same-value probe collision in D7 must
   remain unexecuted unless the candidate has its own request. Apply the
   boundary consistently to manual/AI evidence, v4 review, replay, metrics,
   and exported artifacts. Derived verification controls are linked controls,
   not extra model candidates. Ambiguous historical evidence stays unavailable;
   do not rewrite it.

4. **`Sexploit` and candidate evidence.** A verified positive candidate can
   establish its supported outcome, but one verified negative plus an
   unassessable executed candidate must not establish a run-level verified
   negative. No executed candidate is not an exploit failure. Preserve partial,
   unknown, and independently verified negative outcomes separately. Implement
   candidate-bound, method-appropriate evidence for v4's level-1 early signal:
   the current [proof mapping](../../evaluation/thesis_scoring.py#L33-L45) uses
   level-1 probe labels, while candidate proof filters for exploit/bypass
   stages. For example, a relevant SQL error produced by an actual candidate
   needs a method-appropriate baseline and candidate-bound evidence to support
   an initial signal; do not simply credit every SQL error or promote a probe.
   Retain the v4 permission, session, timing, and causal-use proof ceilings.

5. **`Schain`.** Record whether the chain-opportunity assessment actually ran
   and had enough evidence. The default empty
   `weak_chain_opportunities` list must not by itself prove a scored zero for a
   run that never reached an assessable chain decision. A genuinely assessed
   absence can earn 0; missing evidence stays unavailable. Preserve v4's
   distinct 1/2/3/4 criteria and the causal controls required for completed
   routes. The current weak-opportunity producer recognizes only a partial
   UNION result ([source](../../evaluation/scoring_evidence.py#L524-L551));
   support other existing methods only where their candidate-linked evidence
   actually satisfies the v4 criterion. Never invent a chain or change AKG
   topology merely to reach a score.

6. **`Smethod` and `Srun`.** Keep v4 final-method selection grading and the
   published formula. Validate the ranking profile against the frozen
   fixture/protocol/budget and preserve explicit `forced`, model, fallback,
   and route origins. Record a supported, determinable out-of-surface or
   unmet-prerequisite decision under the v4 0/1 rules even if ranking is
   unavailable; missing observations or missing proof must not be represented
   as a measured negative. A forced method does not establish model selection
   skill. Do not emit `Srun_final` when any required component or review is
   pending; do not substitute a provisional v2 component or a zero.

### 5.3 Research metrics, denominators, and acceptance

Implement or explicitly account for every Chapter 3 metric, not only
`Soutput`. Persist numerator, denominator, population, origin, method/visit,
availability, and a reason for `null`. Separate method-selection and
forced-method blocks, static/model/control sources, provider failures, and
fixture limitations. Retain the documented v4 final score contract; add
separately named/versioned metrics when a different denominator is needed.

| Metric family | Required behavior |
| --- | --- |
| First choice and method selection | Compute first-choice accuracy only from an actual model-origin first decision against the frozen ranking snapshot. The current v4 field is hard-coded null. Keep final-selection `Smethod` distinct; forced or deterministic choices are not model accuracy. |
| Adaptation | Count genuine opportunities to select again after a supported failure; distinguish model decisions from deterministic routing. No opportunity is unavailable, not 0% model adaptation. |
| AKG path validity | Validate the recorded edge-by-edge trace, prerequisites, and decision source. A missing trace or a non-AKG baseline is unavailable/not applicable rather than an invented valid path. |
| Payload validity and method alignment | Keep the existing combined candidate-validation rate distinct from model-only validity. Record a separate evidence-backed method-alignment verdict; do not infer it from an unrelated acceptance or a probe. |
| Payload execution and improvement | Preserve the documented v4 valid-exploit-candidate denominator for its existing metric, but return unavailable when no eligible candidate was executed. Report valid, executed, assessed, and confirmed counts separately; expose a separately named assessable-executed rate where needed. Compare model improvement only against a genuinely executed, comparable static baseline for the same method/fixture; `chain_derived` is not model output, and a missing baseline is not score zero. |
| Full exploit and chain-enabled count | Base a negative on sufficient candidate/route evidence; a positive needs its own verifier and independent controls. Label v4's current 0/1 chain-enabled indicator as a flag; report an actual route count separately if required. |
| Attempts to success | Preserve v4's distinct-candidate ordering and separately report physical requests, probes, repeats, and verifier controls. Missing ordering or no assessable success remains unavailable; do not present the provisional count of all tried strings as the exact first-success request. |
| Guardrail, invalid JSON, and fallback rates | Retain raw events and distinguish returned model output from provider errors and cache hits. Define the relevant unique-call/opportunity denominator, avoid treating multiple events for one call as multiple calls or silently hiding them by clipping, and make a zero denominator unavailable. Version any new rate rather than silently changing historical definitions. |
| Consistency, mean, median, and comparisons | Compare compatible final receipts while also reporting planned, pending, failed, and unassessable runs. Compute first-choice consistency across comparable input coordinates without grouping away differing chosen methods; keep final-method and grader groupings separate. One repeat cannot establish stability. Use a predeclared paired analysis for matched conditions; label Mann–Whitney exploratory when independence is not satisfied. |
| Token usage and cost | Calculate cost only from retained actual usage and a frozen, timestamped price schedule applicable to the provider/model and token categories. Report missing usage/pricing and zero confirmed successes as unavailable, with counts; never infer a price or a success. |
| Runtime summaries and operational telemetry | Label provisional v2 and v4 final values distinctly. Count methods actually attempted rather than the entire registry as tested; unattempted methods must not become zero-score failures. Distinguish summed role-call durations from elapsed wall time, provider token-cache rates from response-cache rates, and matrix-wide from per-run concurrency. A rate with no calls is not measured 0%. |

Acceptance of the scoring work requires all of the following, when verification
is authorized:

- V4 `Soutput` produces the documented 0, 1, 2, 3, 4, and unavailable outcomes
  from their own evidence. Missing one required role receipt cannot yield 4;
  a previous-visit seed or probe cannot earn fallback 1; a legitimate zero-call
  control remains not applicable. Test mixed roles, revisits, invalid output,
  recovery, provider error, and containment separately.
- A validated model candidate matching a probe is not executed or scored unless
  its own visit-bound exploit request exists. A model refusal, no candidate,
  transport failure, or stale candidate never becomes a static-seed model
  success in either strict mode.
- A candidate-linked early positive signal can receive the appropriate v4
  level-1 evidence without crediting probes or weakening any independent
  oracle. A verified negative plus unassessable candidate does not produce a
  run-level verified negative; an all-negative assessed set can produce 0.
- `Schain` remains unavailable when no assessable opportunity/route evaluation
  occurred, gives 0 for a proved absence, and preserves supported 1–4 evidence.
  Forced-target runs do not acquire fabricated chain credit.
- A valid but unexecuted candidate is not reported as a 0% execution result
  when no candidate executed. Improvement without a comparable static
  execution is unavailable. Guardrail and fallback rate denominators and
  no-opportunity cases remain explicit; unattempted methods are not counted as
  tested failures.
- All Chapter 3 metrics above either have their declared, evidence-backed
  computation and coverage or remain explicitly unavailable with reasons.
  First-choice accuracy is calculated only for model-origin choices; costs need
  usage and prices; repeat stability needs comparable repeats. No missing value
  is filled from another mode, model, visit, reviewer, or experiment epoch.
- With a matching, frozen v4 ranking profile and all other required evidence,
  `Smethod` and `Srun_final` are assessable; with a missing/mismatched profile
  or missing component they remain pending where v4 requires it. Scope and
  prerequisite decisions that v4 can independently assess do not rely on an
  unrelated ranking profile.
- Existing v4 weights, v4 rubric/proof ceilings, final-method payload averaging,
  separate human/AI receipts, source hashes, historical v2/v3 records, and the
  frozen 108-coordinate matrix remain intact. New metrics or changed scoring
  behavior identify their code/policy epoch and cannot relabel prior evidence.

## 6. Implementation order and acceptance

1. **Freeze the study contract:** choose the proposed control policy with the
   owner, document selection versus forced blocks, fixture protocol, comparison
   estimands, policy/schema epoch, and v4 inputs. Coordinate with the companion
   payload-mode handoff; do not independently implement competing contracts.
2. **Readiness and preconditions:** implement D2–D4 in recon, state/observation
   provenance, workflow eligibility, orchestrator, method agents, and runner
   status/artifacts. Preserve monotonic fact history; never turn a discovered
   endpoint into a proven signal. Distinguish false, unknown, and unavailable.
3. **Candidate/control boundaries:** implement D5–D7 across generator,
   validator, ranker, all method-stage helpers, both brute-force probe helpers,
   destination recon, verifier controls, replay, and evidence consumers. Keep
   controls and candidate budgets separate and apply fixed scope checks to both.
4. **Correct shared v4 scoring:** implement sections 5.1–5.3 together with the
   candidate/control boundaries. Bind required calls and fallback to their
   visits, retain unknown evidence, implement candidate-linked early signals,
   correct or explicitly version affected research metrics, and validate the
   frozen ranking inputs. This can proceed alongside the other implementation
   work once the shared identity/control contracts are frozen.
5. **Research blocks and analysis:** add or configure a genuinely automatic
   selection matrix without changing the frozen v4 matrix, retain the forced
   coverage block, and group comparable source runs and final receipts without
   losing statuses or original evidence. Preserve explicit target identity and
   the main two hybrid conditions.
6. **Complete payload modes:** implement strict no-static-fallback mutation,
   seed-free Template provenance, safe prompt context, and model-only outcome
   attribution according to the companion handoff. Validate every existing
   generator, validator, chain-derived, and agent fallback path.
7. **Documentation after implementation:** update both
   [English](../reference/summary_en.md) and
   [Indonesian](../reference/summary_id.md) methodology, affected
   [architecture](../reference/architecture.md) and artifact guidance, and a
   derived Chapter 3 document/figures. Use the repository's v4 Tables 3.5–3.11;
   preserve the source DOCX and clearly record which document is revised.

Acceptance, when verification is authorized, requires observable evidence that:

- a forced or deterministic selection cannot be counted as a model choice;
  automatic Linear and AKG calls receive the intended distinct eligible input;
  a fixed infeasible target never silently executes a substitute;
- an endpoint alone does not prove an error, UNION, boolean, or timing signal;
  negative and unknown evidence remain distinguishable, scoped, and auditable;
- failed login, missing required token/endpoint, and mismatched/unknown DVWA
  level yield specific environment/incomplete outcomes without model or
  exploit-failure credit;
- a configured one-candidate exploit budget admits at most one distinct
  exploit/bypass candidate, independently of detection and verification
  controls, including all origins and both primary conditions;
- strict-mode generation refusal, malformed response, provider failure,
  validation failure, revisit, or missing candidate never executes or credits
  a static or chain-derived substitute; an empty control list sends no hidden
  brute-force probes;
- a model candidate with the same content as an earlier detection control is
  counted as executed only if its own visit-bound exploit request is recorded;
  a skipped duplicate is explicitly unexecuted, not inferred from
  `tried_payloads` or a probe response. Ambiguous legacy evidence stays
  unavailable and is not rewritten;
- an unexpectedly successful or state-changing control is recorded and cannot
  supply model success, confirmed nodes, credentials, or chain credit; a
  contaminated fixture is not reused without evidenced restoration;
- Template call inputs contain no working seed, solved credential, raw control
  result, or prior successful payload; real template origin and model-call
  identity survive validation, execution, replay, and review;
- positive model evidence joins the same candidate and visit to its response,
  method verifier, and required independent controls; missing or unexecuted
  evidence remains null/incomplete, not a verified negative or success;
- a conceptual edge with no destination adapter stays infeasible; completed
  chains meet v4 causal source/use/destination requirements;
- final v4 scores and historical records retain their documented rubric,
  arithmetic, final-method denominator, proof ceilings, and separate review
  receipts; research summaries never mix unlabelled conditions or score epochs.
- all scoring and research-metric acceptance cases in section 5.3 pass before
  either handoff is treated as complete or the primary thesis experiment begins.

This documentation request does **not** authorize tests, E2E, a matrix, live
DVWA HTTP, or provider calls. Use the smallest relevant existing non-E2E checks
only when the owner requests verification; add a behavior test only for a
concrete uncovered risk. Major implementation requires asking the owner about
E2E coverage and waiting for the answer, including for mocked/offline E2E.
Before any main experiment, obtain current-epoch evidence for AKG,
preconditions, prompt/schema parsing, payload validation, chain routing,
containment, artifacts, and one offline dry run per surface. Live validation
also requires explicit target/provider scope. Move this handoff to
`docs/completed/` only after implementation and the required authorized
acceptance evidence are complete.

## 7. Evidence collected for this handoff

- Read the complete DOCX text and all four embedded Chapter 3 figures, plus the
  linked current runtime, v4 review, and matrix sources. The DOCX was not edited.
- Ran an offline, in-memory Python inspection using repository functions and no
  target/provider calls: a forced `sqli_error` with a false prerequisite was
  selected while only `sqli_union` was viable; merging an earlier true and
  later false observation preserved true; a one-candidate low-security
  `bf_dictionary` configuration yielded two probe and four exploit candidates;
  and a simulated empty model response in `llm_mutation_only` produced static
  seeds and a `payload_generation.static_seed_fallback` event. The simulated
  response is not a provider observation.
- A second offline synthetic example passed a force-browse candidate identical
  to an earlier probe: the agent made zero candidate requests, while the v4
  review queue marked the candidate eligible but not assessable, with no proof
  ceiling or evidence references. The temporary synthetic artifact was removed.
  This was a review-queue inspection, not a review of a real run or a final
  score receipt.
- A subsequent offline scoring audit exercised provisional `Soutput` values
  0/2/3/4 and all v4 output branches. Synthetic missing-role and prior-visit
  probe-only fallback cases returned v4 4 and 1, respectively. Other synthetic
  cases returned `Sexploit=0` for one negative plus one unassessable candidate,
  `Schain=0` for an empty state, and a 0% execution rate for one valid but
  unexecuted candidate. A SQL-error response was recorded as candidate grade
  0. The provisional improvement metric returned 100% without a model or
  static baseline. These are controlled code-path observations, not claims
  about live experiments or the number of historical runs affected.
- No tests, E2E, matrix, live DVWA, provider call, or real-run thesis scoring
  review was performed for this documentation-only audit. Runtime behavior not
  directly exercised is identified through the linked source, not claimed as
  live experimental evidence.

## 8. Implementation verification and remaining prerequisites

The original documentation-only observations in section 7 precede the following
authorized implementation checks:

| Check | Observed result | Evidence |
| --- | --- | --- |
| Full TESIS offline suite | 2,879 passed, no failures | [`junit-final-full.xml`](../../results/validation/chapter3-payload-v2-20261028/junit-final-full.xml) |
| Mutation-only method/level/condition replay controls | 54 passed; no fresh replay provider calls | [`junit-continued-replay-matrix.xml`](../../results/validation/chapter3-payload-v2-20261028/junit-continued-replay-matrix.xml) |
| Repository-root CLI dry run | 4 configured payload coordinates passed; graph compiled | `.venv/bin/python -m tesis run --dry-run --config config.yaml` |
| Offline preflight per surface | SQLi 4, Access Control 3, Brute Force 2 coordinates passed | [`dry-run-surfaces.json`](../../results/validation/chapter3-payload-v2-20261028/dry-run-surfaces.json) |
| Template runner/export/replay smoke | Current template/call/candidate evidence retained; replay made no provider calls | [`validation.json`](../../results/validation/chapter3-payload-v2-20261028/template-smoke-ddff539fb4f440a8bfcb9062a260ab72/validation.json) |
| Actual Textual Template launcher | Review reached; normal exit; no run started or configuration change | [`tui-template-review.json`](../../results/validation/chapter3-payload-v2-20261028/tui-template-review.json) |
| Benign live Doctor | 17 passed, no failures or skips; configured DVWA and River provider | [`doctor-live-current.json`](../../results/validation/chapter3-payload-v2-20261028/doctor-live-current.json) |
| Companion TESIS Web suite | 490 passed; 2 existing opt-in checks skipped | [`web-junit-final.xml`](../../results/validation/chapter3-payload-v2-20261028/web-junit-final.xml) |
| Companion web production and browser checks | Production build/TypeScript passed; 2 focused browser checks passed | `npm run build`; `tests/browser/remediation.spec.ts` against the production server |

The final test pass includes corrected independent/derived control evidence
links, preserved replay order, exact selection-call receipt attribution,
unknown rather than negative failed-control transport, verified security-level
fixtures, and caption-bound DOCX rubric updates that preserve appended tables.
The Template smoke uses synthetic HTTP/model fixtures; it is not live DVWA or
provider evidence. Live Doctor checks are benign readiness checks, not a
technique-success test or a research matrix.

Two renewed DeepSeek web workers independently reviewed receipt binding and
presentation, then cross-checked the corrections. The web now accepts the current
metric records, displays Template consistently, honors frozen review selection,
and compares persisted configs exactly rather than through display redaction.
A saved source with stale top-level `human` but frozen config `both` displayed
its existing AI final of 2.7000, and overview counted both saved workflows as
final. This is read-only interpretation of saved evidence, not fresh scoring.

Main-study acceptance still requires operator-supplied, current-epoch fixture
restoration/equivalence evidence and the frozen research ranking profile.
Token-cost claims additionally require an applicable timestamped price schedule
and actual retained usage. These inputs have not been fabricated or inferred
from successful connectivity or offline controls. Required final scores, cost
and paired comparisons remain unavailable where their evidence is missing.
No primary experiment or frozen 108-coordinate scoring matrix was rerun, and no
historical score was rewritten. The derived DOCX's visual layout remains
unverified. These limitations remain open after the owner-directed archival of
both implementation handoffs on 2026-10-29; their completed-folder location is
not evidence that the scientific prerequisites or visual acceptance have passed.
