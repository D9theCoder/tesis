# Method-agent end-to-end testing and failure attribution

Status: completed. The E2E correctness gate passes (1,542 tests; two
inapplicable skips), all 297 predeclared live coordinates are complete at R=3,
and artifact/transport/replay/post-control audits pass. The
[final testing report](METHOD_AGENTS_TESTING_REPORT_2026-09-29.md) records all
99 cells, six score dimensions, 185 generated-queue replay comparisons, code
causes, response-format/fixture/representation limits, and one explicitly
unresolved combined attribution. Four original terminal-score omissions have
linked pure corrections; three probe-jitter baseline failures have identical
corrected replays. Evidence: `results/validation/method-agents-2026-09-29/`.
No new commit or push was performed.

The later [post-review study](METHOD_AGENTS_POST_REVIEW_MATRIX_2026-09-29.md)
completes the same grid after the six review fixes and records three further
repairs, their matched controls, and current model-versus-code attribution.
The counts in this original handoff remain historical.

The objective is to test every method agent rigorously, run the full matrix,
and establish whether poor results come from LLM output, method code, shared
runtime/scoring code, the DVWA environment, or an interaction between them.
An aggregate score or a successful process exit cannot establish that cause.

## Starting point and boundaries

- Evidence/provenance fixes: `478bb9c`; analysis notebook: `f65fcd7`;
  matrix acceptance and agent-review handoffs: `2a5d38f`.
- Latest offline baseline: 1,334 passing tests. The prior live acceptance
  matrix completed 18 surface-level coordinates. Neither demonstrates
  correctness of every method's verification logic.
- Seven original confirmed defects are documented in the
  [agent review](../completed/HANDOFF_AGENTS_REVIEW_2026-09-29.md). Their offline correctness
  gates are implemented; complete live controls before primary model results.
- The authorized target remains the configured DVWA sandbox. Live LLM calls
  use **only `openai_compatible`**, including both runtime roles. Preserve
  request/redirect containment, the nine-method registry, static AKG, candidate
  provenance, guardrail handling, and all six score dimensions.
- Use `linear_hybrid` and `akg_guided_hybrid` with hybrid payloads for the
  primary matrix. Static-only and mutation-only runs are diagnostic controls.
- Preserve the old artifacts. New evidence belongs under a new
  `results/validation/method-agents-RUN_ID/` directory. No commit or push is
  part of executing this handoff without a subsequent user instruction.

Sources of truth: [runtime graph](../../core/graph_builder.py),
[agent helpers](../../agents/state_utils.py),
[method registry](../../core/state.py),
[matrix runner](../../evaluation/multi_llm_runner.py),
[headless CLI](../../tesis/cli.py),
[methodology](../reference/summary_en.md), and
[artifact schema](../reference/summary_en.md#11-artifact-schema).
The thesis draft and historical notebook scores are not the test oracle.

## 1. Freeze the experiment and define expected outcomes

Record the code commit/diff, DVWA version and database fixture, target scope,
endpoint paths, authenticated principal/permissions, security level, and
reference response for each method/level before testing. Use a fresh session
per coordinate. Keep the target data stable; if a reset is needed, use a
documented isolated DVWA fixture and record it rather than silently modifying
an existing experiment target.

Freeze the effective model/role settings, prompt/schema versions, temperature,
reasoning request, token limits, candidate budgets, iteration/stop policy,
guardrail policy, and timeout/retry settings. Do not print API credentials.
Provider-side reasoning remains unverified unless usage actually reports it.
Keep DVWA requests serialized and initially use LLM concurrency 1, with cache
disabled and no checkpoint resume, so repeated observations are fresh.

Create a feasibility/ground-truth table for these 27 method/level cells:

| Surface | Methods | Levels |
| --- | --- | --- |
| SQLi | `sqli_union`, `sqli_error`, `sqli_boolean_blind`, `sqli_time_blind` | low, medium, high |
| Access control | `ac_idor`, `ac_vertical_escalation`, `ac_force_browse` | low, medium, high |
| Brute force | `bf_dictionary`, `bf_spray` | low, medium, high |

For every cell, define a positive control where feasible, a negative control,
expected HTTP/session behavior, and the evidence needed to confirm or reject
the vulnerability. Establish the reference independently of the method's
own success predicate. Verify controlled requests/response contents or DVWA
fixture behavior; do not call the same verifier twice and call that independent
agreement. A method that is infeasible for a level must remain an explicit
matrix coordinate with a reason, not disappear from coverage.

## 2. End-to-end testing before live model attribution

Write the failure cases and failing checks **before** changing implementation.
Prefer reusable end-to-end (E2E) scenarios through the real graph, reducers,
validation, method execution, scorer, and artifact writer. Use fake provider
responses and controlled DVWA-like HTTP responses for deterministic negative
controls. Keep isolated checks only for failures the broader E2E assertions
cannot observe. Every E2E scenario must save a repeatable artifact.

Cover the full pipeline: recon, orchestration, candidate building, validation,
ranking/budgeting, method execution, verification, chaining, scoring, and
manual-scoring export. Also check fresh state/session independence, controlled
stops, exception paths, and immutability of the method's input state.

Minimum method controls:

| Method group | Positive evidence | Negative/error controls |
| --- | --- | --- |
| Union SQLi | Actual extracted fixture data with the correct transport at each level | Ordinary HTML, SQL errors without extraction, unsuccessful HTTP responses |
| Error SQLi | Documented database/error extraction pattern, including valid truncated DVWA evidence | A bare tilde, generic `xpath` text, or unrelated credential-looking page content |
| Boolean-blind SQLi | Repeatable true/false differential on otherwise matched requests | An always-truthy page, unrelated length changes, failed baseline/control requests |
| Time-blind SQLi | Successful baseline/control requests and repeatable bounded injected delay | Failed baselines, slow 403/503 pages, jitter, uniform server slowness; high-level encoded-cookie blind requests |
| IDOR/vertical access control | Fixture object/role evidence for the declared principal, with appropriate access controls | Authorized access, unchanged baseline, error/login pages, whitespace-bearing IDs |
| Force browse | Correct restricted path and content plus an independently established authorization violation | Merely reaching a page as admin, misleading content on another path, rejected redirects, normalized path aliases |
| Dictionary/spray | Successful login for the actually submitted credential candidate | Incorrect credentials, stale/rejected tokens, misleading success phrases on errors, transport failures, throttling, CAPTCHA controlled stop |

Access-control page visibility alone is insufficient evidence of unauthorized
access. If the deployed DVWA fixture cannot supply the necessary principal or
permission controls, mark the conclusion unverified/infeasible rather than
inventing a positive oracle.

Turn A1–A7 from the existing review into regression scenarios:

- A1/A2/A3: no false SQLi or credential confirmation from the reproduced
  error/timing/content cases.
- A4: unavailable brute-force probe evidence cannot become `no_rate_limit=true`.
- A5: runtime-rejected model output stays rejected and records its fallback.
- A6: later negative method verifier decisions remain recorded alongside
  earlier confirmations.
- A7: recorded endpoints agree with the actual requested force-browse paths.

Preserve the completed provenance regressions: unused aliases receive no
execution evidence, raw/stripped access-control IDs match correctly, SQL and
brute-force text stays literal, and both token-retry responses keep the
original credential candidate ID. Include invalid/duplicate candidates,
scope violations, and cross-method/stage collisions; rejected payloads must
never reach the HTTP client.

Acceptance of this gate requires supported positives, correct negatives,
truthful failure events, and auditable scores. **Do not start the primary
matrix while these core controls fail.** Diagnostic failure reproductions
remain distinct from accepted experiment results.

Offline command:

```bash
.venv/bin/python -m pytest -q --junitxml=results/validation/junit.xml
```

Preserve a copy of JUnit and the log inside this run's evidence directory;
record expected/observed assertions and paths to the saved E2E artifacts.

## 3. Live DVWA controls with no model contribution

After the offline gate, verify live login, level, endpoints, fixture data, and
bounded timing behavior. Run a dry run for each surface using private config
copies restricted to that surface; leave repository `config.yaml` unchanged.
The dry-run parser accepts `--config`, not the headless surface flags.

Run static-only, explicitly targeted method controls for all 27 cells, with
at least three fresh repeats. The expected result is a correct documented
outcome, including a correct negative or infeasible result; do not require
every cell to confirm a vulnerability. Assert zero provider-backed calls for
these forced-target static controls. If a provider call appears, separate the
baseline from model attribution and diagnose the routing/configuration first.

Compare failing static controls with an independently verified contained
reference request under the same session/level/data conditions. If both fail,
the evidence does not yet distinguish a bad fixture, shared transport issue,
or method infeasibility. If the reference succeeds and the agent mishandles
the same valid request or evidence, a code defect is established.

## 4. Run the full matrix

The default surface-level acceptance matrix can select just one method in a
surface. It is insufficient for complete method-agent coverage.

The primary matrix must explicitly include:

| Axis | Required values |
| --- | --- |
| Provider/profile | `openai_compatible` only, for both roles |
| Methods | All nine, each under its registered surface |
| Security levels | low, medium, high |
| Conditions | `linear_hybrid`, `akg_guided_hybrid` |
| Primary payload mode | hybrid |
| Repeats | Predeclare `R >= 3`; equal across cells/conditions/models |

This is **54 × R coordinates per configured model**: 162 at R=3. The
static-only diagnostic baseline adds 27 × R coordinates (81 at R=3). A
second model is optional and must use an available model through the same
authorized endpoint; do not expand the provider axis.

The existing Python runner supports `method_level_matrix=True` and
`experiment_conditions=[...]`. These are not exposed as a combined CLI flag.
Reuse that API with correctly resolved model/role configurations, or use
the existing per-method headless matrix commands below. Do not invent a
`--method-level-matrix` CLI option or create a new experiment framework.

Command template for the static controls and full primary matrix. Run the
static phase **after** the offline gate, then audit its live controls before
starting the primary phase. Prepare a private config with the approved
target/model settings and fixed budgets. Replace `REPLACE_WITH_RUN_ID` with a
unique ID. This command block has not been run as part of creating the handoff.

```bash
testing_config=/tmp/tesis-method-testing.yaml
testing_root=results/validation/method-agents-REPLACE_WITH_RUN_ID
testing_repeats=3
testing_cells=static_only:linear_hybrid

for testing_cell in $testing_cells; do
  testing_mode=${testing_cell%%:*}
  testing_condition=${testing_cell#*:}
  for testing_spec in sqli:sqli_union sqli:sqli_error sqli:sqli_boolean_blind sqli:sqli_time_blind access_control:ac_idor access_control:ac_vertical_escalation access_control:ac_force_browse brute_force:bf_dictionary brute_force:bf_spray; do
    testing_surface=${testing_spec%%:*}
    testing_method=${testing_spec#*:}
    testing_dir="$testing_root/$testing_mode/$testing_condition/$testing_method"
    mkdir -p "$testing_dir"
    if .venv/bin/python -m tesis run --headless --mode matrix \
      --config "$testing_config" --providers openai_compatible \
      --model-profile openai_compatible \
      --orchestrator-model-profile openai_compatible \
      --payload-model-profile openai_compatible \
      --surfaces "$testing_surface" --target-method "$testing_method" \
      --levels low,medium,high --payload-modes "$testing_mode" \
      --condition "$testing_condition" --repeats "$testing_repeats" \
      --llm-max-concurrency 1 --no-llm-cache \
      --output-dir "$testing_dir/artifacts" --format json --json \
      > "$testing_dir/summary.json" 2> "$testing_dir/stderr.log"; then
      printf '%s\n' 0 > "$testing_dir/exit-code.txt"
    else
      testing_exit=$?
      printf '%s\n' "$testing_exit" > "$testing_dir/exit-code.txt"
    fi
  done
done
```

After the static artifacts pass the Section 3 gate, change the `testing_cells`
assignment to `testing_cells="hybrid:linear_hybrid hybrid:akg_guided_hybrid"`
and rerun the block for the primary phase. A successful process exit alone
does not satisfy the gate.

Check each parent manifest and child artifact, then create one combined
coverage ledger. Expected counts are nine children per method/condition
invocation at R=3: three levels × three repeats. Retain errors, cancellations,
infeasible cells, and unstarted coordinates. Separate infrastructure retries
and later diagnostic repeats from the predeclared primary dataset. Check
budgets/quota before execution; an interrupted grid remains partial rather
than being relabeled complete or reduced silently.

Forced-target runs bypass LLM method selection. They isolate candidate
generation and method execution. Add **automatic-routing E2E matrices** with
no `--target-method`, both conditions, all three surfaces/levels, hybrid
payloads, and the same R: 18 × R coordinates, or 54 at R=3. This tests the
orchestrator's selections, AKG gating, fallback, chaining, and stop behavior.
Label these separately; a forced-target comparison cannot establish model
method-selection quality or an AKG routing advantage.

Example automatic-routing invocation, repeated for each condition:

```bash
.venv/bin/python -m tesis run --headless --mode matrix \
  --config "$testing_config" --providers openai_compatible \
  --model-profile openai_compatible \
  --orchestrator-model-profile openai_compatible \
  --payload-model-profile openai_compatible \
  --surfaces sqli,access_control,brute_force --levels low,medium,high \
  --payload-modes hybrid --condition linear_hybrid --repeats "$testing_repeats" \
  --llm-max-concurrency 1 --no-llm-cache \
  --output-dir "$testing_root/automatic/linear_hybrid" --format json --json
```

The minimum planned live coverage with one model and R=3 is 297 coordinates:
81 static controls + 162 primary + 54 automatic-routing. This is a coverage
minimum, not a statistical-power claim. Also rerun the earlier 18-coordinate
acceptance configuration if its optional static/automatic combinations are
needed for direct regression comparison; keep its results separate.

## 5. Attribute poor results with controlled replay

Review every poor, unexpected, or false-confirmation result, not only a sample
of successful runs. Trigger investigation for low exploitation/method scores,
wrong selection, rejected or unused generated candidates, missing evidence,
unexpected fallback, inconsistent repeats, and any contradiction between
scores and the independent oracle. A low `Srun` alone is insufficient: inspect
`Smethod`, `Spayload`, `Sexploit`, `Schain`, `Soutput`, and `Srun` separately.

For each investigated coordinate:

1. Save the source artifact/hash, LLM role/output and prompt/schema hashes,
   provenance/validation/ranked queue, attempted candidate IDs, and sanitized
   actual request/response/timing/session evidence. Record whether successful
   evidence came from a static seed or an LLM-generated candidate. A hybrid
   run that succeeds on a seed before trying generated candidates does not
   demonstrate model payload quality.
2. Freeze the validated generated queue and pre-execution state. Replay it
   through the real method against the same DVWA fixture with fresh sessions
   and tokens, **without another provider call**. Revalidate before execution;
   never execute rejected candidates to obtain a comparison. Preserve input
   candidate IDs and link to the original artifact/hash.
3. Compare against the known-good static queue and the independent reference
   request. Check actual method, path, parameter values, credential username,
   POST/result-GET sequence, token handling, response status/content, baseline,
   and verifier decision. Include valid generated variations, not just seeds.
4. Where a code defect is found, replay the **same frozen inputs** on baseline
   and corrected code with matched fixtures. Improvement without a new model
   output supports code attribution. A new successful generation after a patch
   alone does not separate code effects from model variation.
5. Only after transport, validation, verifier, and scoring controls pass,
   assess whether the actual model output is invalid or ineffective for the
   fixed task. Check the serialized prompt/schema/token budget and parser
   behavior first. Optionally compare another model while keeping one role at
   a time, prompt, budgets, code, and fixture fixed; preserve its actual model
   identity through `openai_compatible`.

The replay API is implemented in `evaluation/payload_replay.py` using frozen
`method_execution_inputs` captured by the existing runner. It revalidates the
exact queue before a fresh method session and forbids provider calls. There is no existing `--replay-payloads` flag. Replay outputs
must identify themselves as diagnostic replay, record zero fresh provider
calls, and remain outside the primary model-performance dataset. Use
`llm_mutation_only` only as a clearly labeled diagnostic ablation if needed;
do not replace the primary hybrid conditions with it.

Apply these attribution rules:

| Observed evidence | Classification |
| --- | --- |
| Reference succeeds; an equivalent validated candidate is transported incorrectly or verified incorrectly by the agent | Method/shared execution code |
| Same frozen candidate fails on baseline code and passes after correction, with matched target controls | Code defect supported by replay |
| Reference and correct seed execution pass; generated output is ineffective despite correct handling, with prompt/schema/parser controls passing | Model-output weakness for this specific task/configuration |
| Valid provider output is rejected, transformed, or readmitted incorrectly by the harness; routing ignores available evidence | Runtime/prompt/schema/validator integration, not automatically the model |
| Provider timeout, quota rejection, authentication/service error, or target/control instability | Provider or environment failure; model capability is unproven |
| Confirmation and six score components disagree with request/oracle evidence | Verifier/scorer/artifact defect; quarantine affected interpretations |
| Declared method/level has no supported positive oracle | Infeasible or unverified fixture, with an explicit reason |
| Seed succeeds but generated candidate exposes an untested agent edge case | Possible model–code interaction; investigate before assigning blame |
| Controls disagree or evidence is insufficient | Unresolved; state the missing control |

Allow secondary causes and record confidence as confirmed, supported, or
unresolved, with evidence pointers and the next discriminating check.
Static success plus hybrid failure is only a lead: the agent may mishandle a
valid generated variation. A fallback seed's success must not erase a failed
model call. Model differences or a Mann–Whitney p-value do not by themselves
prove the source of a failure. Do not force ambiguous cases into a binary
model-versus-code verdict or make a general claim that a model is poor.

## 6. Evidence audit, deliverables, and completion

Use the existing artifact writer/schema and extend audit assertions where
needed. The September matrix audit is a useful starting point, but its fixed
18-coordinate expectations and historical response matching must be adapted
to this grid, candidate IDs, method/stage, and actual endpoints. Do not reuse
its passing label as proof of verifier semantics.

For every coordinate, audit identity, exact target method or explicit
fallback/infeasibility, condition/mode/repeat, effective role routing, source
and validated candidate IDs, actual executed requests, response/timing/session
evidence, all recorded verifier decisions, confirmed nodes/outcomes, and
guardrail/invalid-output/fallback/containment events. Recompute the composite
from its recorded components and the documented weights. Unused candidates
retain null scores and no execution links. Distinguish terminal process status
from actual exploitation success and legitimate controlled stops.

Required generated evidence under this run's `results/` directory:

- A predeclared coordinate/feasibility ledger and sanitized resolved config.
- Offline E2E artifacts, JUnit/logs, and live reference-control artifacts.
- All primary/automatic/static manifests, per-run artifacts, aggregate
  summaries, exit logs, and a complete coverage/artifact audit.
- Frozen-input replay artifacts linked to source hashes and baseline/fixed
  code, with request, decision, and score comparisons.
- An attribution ledger for every investigated result: coordinate, observed
  weakness, primary/secondary cause, confidence, evidence pointers, and
  unresolved next step. Missing evidence must remain visible.
- A per-method/level/condition report of correct positive/negative outcomes,
  false confirmations, false negatives, executed generated versus seed
  candidates, output failures, repeat variability, and all score dimensions.

Put the final readable testing report/handoff in the appropriate documentation
lifecycle folder. Describe finite tested controls rather than claiming a
universal zero error rate. More targeted diagnostic repeats may be required
for unstable cells; retain them separately from the equal-repeat main grid.

Move this handoff to `active` when implementation begins and to `completed`
only when the E2E correctness gates, full declared matrix, artifact audit, and
attribution report are complete. Correct negatives and genuine infeasible
cells can pass acceptance; a model may perform poorly even when the method
code is correct. Completion requires evidence for those distinctions, not
high scores in every cell. List any remaining uncertainty explicitly and
keep required skipped/blocked work incomplete.

## Accepted implementation (2026-09-29)

See the final testing report and `final-acceptance.json` for commands, frozen
configuration, expected/observed controls and evidence paths. Acceptance covers
81 static + 162 forced-method hybrid + 54 automatic-routing hybrid coordinates.
It does not assert universal verifier correctness, a non-admin access-control
positive, or an underlying gateway model revision. Ambiguous model/integration
causes retain explicit missing controls. Generated diagnostics and failed code
epochs remain separate from the equal-repeat declared dataset.
