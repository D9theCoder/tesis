# Handoff: strict LLM mutation and template payload modes

Status: **upcoming**. This document specifies unstarted implementation work; it
does not establish that any runtime behavior, validation, or experiment has
changed. The owner asked to discuss the probe-control policy after this handoff;
that decision remains open in section 4.

## 1. Goal and scope

Make `llm_mutation_only` a genuine model-candidate mode: **never fall back to a
static seed** when the model or validator fails. Add a separate `llm_template`
payload mode, displayed as **Template**, that asks the model to construct a
payload from a neutral, non-executable template rather than from a working seed.
Attribute model payload correctness only to a generated candidate with its own
execution and verifier evidence.

Retain `static_only` and `hybrid` as the existing static and mixed baselines.
The primary thesis conditions remain `linear_hybrid` and
`akg_guided_hybrid` with hybrid payloads. Mutation-only and Template are
separate ablations unless the research design is explicitly changed. Do not
change the AKG's topology or claim that the orchestrator LLM plans a complete
AKG path as part of this work.

This remains an authorized DVWA-only system. Preserve the three supported
surfaces, nine registered methods, containment at payload and HTTP boundaries,
static method agents, verifier evidence, research identity, and all score
dimensions. Respect `experiment_condition`, `target_method`, `payload_mode`,
and `repeat_index`; an explicit target is not silently replaced.
Use `guardrail_handling` and `guardrail_retry` terminology for new behavior;
retries remain limited to schema repair or authorized-sandbox clarification.

## 2. Current behavior to change

The following are observations from the current implementation, not acceptance
evidence for the proposed behavior:

1. [`build_payload_candidates`](../../foundation/payload_generator.py) asks for
   up to one LLM variant and uses `generated or seed_candidates` in
   `llm_mutation_only`. Refusal, invalid output, or provider failure can thus
   enqueue static seeds and emit `payload_generation.static_seed_fallback`.
2. [`validate_payload_candidates`](../../foundation/payload_validator.py) can
   reload canonical seeds after generated candidates fail validation and emit
   `payload_validation.static_seed_fallback`.
3. The builder can append a `chain_derived` brute-force candidate independently
   of model generation. The method-stage helper in
   [`agents/state_utils.py`](../../agents/state_utils.py) also has probe-control
   and legacy library paths. These paths need explicit mode-aware handling; an
   empty or rejected model queue must not revive a seed or substitute a
   non-model exploit candidate.
4. Current prompts request a variant of an execution-ready seed and the
   validator and scoring evidence require `source_seed_id`. They cannot express
   a seed-free template candidate without a distinct prompt and provenance
   contract. The current validator checks duplicate payloads within the supplied
   queue, so a generated response can match a supplied seed when that seed is
   absent from the queue; record copies honestly instead of calling them novel.
5. [`evaluation/runner.py`](../../evaluation/runner.py) recognizes payload
   provider failure through a static-fallback event and decides whether a model
   call is required from the known mode list. Doctor and dry run currently
   validate static candidates under every mode. These assumptions must be
   updated for strict modes.

## 3. Required payload behavior

| Mode | Model input | Executable exploit/bypass candidates |
| --- | --- | --- |
| `static_only` | No payload-generation call | Validated static seeds. |
| `hybrid` | Execution-ready seeds and the selected method profile | Validated static seeds and any valid model variant, subject to ranking and budget. |
| `llm_mutation_only` | Execution-ready seeds and the selected method profile | Validated model-generated variants only. Seeds are inputs, never a fallback candidate. |
| `llm_template` | Neutral template and scoped task context, with no working seed payload | Validated model-generated candidates only. The template is never executable. |

The table describes exploit and bypass candidates. Reconnaissance and detection
controls are the separate, deferred decision in section 4.

### Strict mutation-only

- Keep seed-based generation as the task: the model may inspect execution-ready
  seeds, allowed mutation types, method, security level, target parameters,
  expected signals, and permitted observations. It does not modify agent code.
- On refusal, empty response, malformed JSON, schema violation, provider error,
  rejected candidate, exhausted budget, or any other no-usable-candidate case,
  do not enqueue any static seed, stale candidate from an earlier visit, or
  chain-derived substitute. Apply the same rule at both generation and
  validation and in all agent/stage fallback paths.
- Mark the visit and run outcome accurately, with a reason linked to the
  originating call or validation event. An explicit target with no usable
  candidate must not execute another method. Automatic selection may continue
  only under the existing policy, recording each failed visit separately and
  never turning a failed visit into a seed-backed model success.
- Preserve the reason for a refusal, invalid output, scope rejection, or
  transport failure. Do not represent a missing candidate as an executed
  negative result. A provider or target infrastructure failure must remain
  distinguishable from a model-produced but ineffective payload.
- Attribute model origin from the actual provider call and trusted runtime
  normalization, not an LLM-supplied `source` label. Record whether its output
  exactly matches a supplied seed; an emitted copy can be evaluated as an
  output, but is not evidence of a novel mutation.

### Template mode

- Add the canonical config value `llm_template`, with the TUI label `Template`.
  Support normal single-run, headless, CLI, and matrix selection paths. Do not
  add it to default or frozen historical matrices automatically.
- Define versioned, method-specific neutral templates for the registered
  methods and applicable DVWA levels. A template supplies the task, parameter,
  format, and any necessary inert structure; it is not a working exploit,
  probe, bypass, candidate, or executable fallback. Do not invent a working
  result or claim feasibility for an unsupported fixture.
- Use a dedicated prompt and response schema that request a candidate from the
  template. Supply only the selected method, level, allowed parameter and
  expected outcome, authorized bounds, neutral template, and explicitly
  permitted sanitized observations. Do not include working seed payloads,
  seed examples, prior successful payloads, or solved credentials in the model
  prompt through profiles, history, observations, or helper fields.
- Apply method, parameter, provenance, schema, scope, resource, and budget
  validation before execution. Adapt the construction rules to this new task;
  do not require a skeleton to be an existing execution-ready seed or weaken
  containment to make a generated candidate pass.
- Record a real `source_template_id` and template version/hash, plus the call,
  method, visit, candidate, prompt/schema version, and model identity. Extend
  the candidate/provenance contract for template-origin outputs instead of
  inventing a `source_seed_id` or describing a template as a static seed.
  Preserve existing seed-based artifact readers and historical records.
- Use only validated model-generated exploit/bypass candidates. A missing or
  rejected response has the same no-static-fallback behavior as strict
  mutation-only. A template, probe, old visit, or chain-derived candidate must
  not substitute for a generated exploit candidate.

Template mode measures generation under the supplied DVWA context, constraints,
and model's prior knowledge. It does not establish that an LLM invented a
technique or had no prior exposure to similar examples.

## 4. Deferred decision: reconnaissance and probe controls

The owner requested further discussion of whether these modes may use static
seed-library probes as **explicit detection controls**. The current recon and
method precondition paths do use such probes, including frozen
`probe_controls`. This decision is not settled by the handoff.

- If allowed, predeclare their use as controls, retain their true source and
  evidence, and keep them separate from generated exploit candidates and the
  LLM-candidate correctness denominator. A control must not be used as a
  substitute when generation or validation fails. Do not disguise a seed as a
  model output or relabel implicit fallback as a control.
- If disallowed, do not execute static seed-library probes in these modes,
  including recon, chain destination probing, or method preconditions. Design
  an evidence-preserving alternative; where that is not possible, report the
  relevant method/fixture as infeasible or incomplete. Do not bypass a
  precondition or verifier merely to obtain a model score.
- In both cases, the model-only exploit queue never falls back to static seeds
  or other non-model candidates. Do not silently choose a probe policy during
  implementation; resolve it with the owner before completing behavior that
  depends on the decision.

## 5. Evidence and scoring

Keep the existing `Smethod`, `Spayload`, `Sexploit`, `Schain`, `Soutput`, and
`Srun` dimensions and formula:

`Srun = 0.20*Smethod + 0.20*Spayload + 0.30*Sexploit + 0.10*Schain + 0.20*Soutput`

Add a separately named, candidate-attributed LLM outcome rather than silently
redefining the composite.

For each method visit, retain the model call receipt and prompt/schema identity,
generation status, candidate ID and trusted origin, seed or template reference,
validation result, execution/response evidence, and matching verifier decision.
Credit a generated candidate only when its own executed exploit/bypass evidence
supports the claimed outcome. Probe controls, seed fallback, chain-derived
outputs, a route selection, and unrelated verifier results cannot earn LLM
payload success.

Report at least: generation opportunities/calls, refusals and invalid outputs,
provider failures, valid model candidates, executed model candidates, and
verifier-confirmed model candidates. Define denominators and retain `null` with
a reason when a rate is not assessable. Report fixture/precondition and
transport limitations separately; do not turn unexecuted candidates or missing
evidence into verified failures or successes. Distinguish a model's exact copy
of a supplied seed from a changed output when interpreting mutation results.

Update the candidate/provenance joins and manual/AI evidence consumers, notably
[`evaluation/scoring_evidence.py`](../../evaluation/scoring_evidence.py),
[`evaluation/manual_scoring_sheet.py`](../../evaluation/manual_scoring_sheet.py),
and artifact exports, so template references and per-visit identity remain
auditable. Bind any positive or negative research conclusion to independent,
method-appropriate controls; a generic response or model explanation is not a
substitute for verifier evidence.

Because the behavior of the existing `llm_mutation_only` name changes, record a
payload-policy/schema version in new run and matrix artifacts. Preserve old
artifacts unchanged, and do not infer strict semantics for a historical record
without source-epoch evidence. Do not expand or rewrite the historically frozen
two-mode [`scoring_v4_matrix.py`](../../evaluation/scoring_v4_matrix.py) design.
A new research matrix needs its own declared coordinates and code/config epoch.

## 6. Implementation map and order

1. **Freeze the contract.** Resolve section 4 with the owner; define mode and
   prompt/schema versions, origin fields, outcome statuses, and control
   boundaries. Review existing artifact consumers before adding fields.
2. **Remove fallback paths.** Update the builder, validator, stage helper,
   chain-derived candidate handling, and graph routing so empty, invalid, or
   failed generation never becomes a static candidate in either strict mode.
   Keep static/hybrid behavior and target-method identity intact.
3. **Introduce templates.** Add a neutral template registry and dedicated
   generator prompt/schema; update AKG profile compatibility, provenance,
   model-call receipts, visit ownership, and validation. Register template
   prompt/schema versions in [`llm/prompts/manifests.py`](../../llm/prompts/manifests.py).
4. **Integrate configuration.** Update mode registries in
   [`tesis/model_config.py`](../../tesis/model_config.py) and
   [`core/state.py`](../../core/state.py), config and CLI validation, TUI
   single/matrix selectors, headless execution, and model-required checks.
   Make Doctor and dry run check the appropriate seed/template contracts
   without making HTTP or provider calls or treating a static seed as a strict
   mode's generated output.
5. **Integrate evidence.** Update scoring evidence, reporting, manual review,
   observer/artifact metadata, failure classification, and legacy reads. Record
   model-attributed outcomes separately from the unchanged `Srun` formula.
6. **Update durable documentation after implementation.** Update both
   [`summary_en.md`](../reference/summary_en.md) and
   [`summary_id.md`](../reference/summary_id.md), plus affected architecture
   and artifact guidance. Describe actual probe policy, fallback semantics,
   template visibility, and measured-versus-unmeasured outcomes.

## 7. Acceptance criteria and verification boundaries

Acceptance requires evidence for all of the following when verification is
authorized:

- For every generator and validator failure category, neither strict mode
  executes or scores a static seed or chain-derived exploit in place of the
  absent/invalid model candidate. Include fixed-target and automatic-selection
  visits, repeats, and stale-queue/revisit cases.
- Successful strict mutation uses a model-origin candidate bound to its seed
  and visit; successful Template uses a model-origin candidate bound to its
  template and visit. An exact copied seed is identifiable, and neither a
  template nor a model's claimed success alone earns verifier credit.
- Candidate evidence links generated output, validation, executed request or
  response, and the method verifier. A probe or fallback cannot earn model
  credit. Retain nulls and explicit incomplete or infeasible outcomes.
- Template prompts contain no working seed payloads or solved credentials,
  and each registered method/level has either a suitable neutral template or
  an explicit, evidence-backed limitation. The chosen precondition-control
  policy is visible and consistently enforced.
- Static and hybrid runs retain their intended semantics; configuration, TUI,
  CLI, Doctor, dry run, matrix coordinates, reports, artifacts, and scoring
  readers handle the new mode without rewriting historical evidence. The
  configured role/model and the existing DVWA containment remain effective.

Use existing focused checks and add a behavior test only where coverage is
missing, if the user authorizes verification. Existing cases in
[`tests/test_hybrid_payload_pipeline.py`](../../tests/test_hybrid_payload_pipeline.py)
encode the old fallback and will need revision when this behavior changes.
A documentation handoff does not
authorize tests, E2E runs, a research matrix, live DVWA requests, or provider
calls. E2E is opt-in, including mocked/offline E2E; for a major implementation,
ask the owner whether E2E coverage is wanted and wait for their answer. Live
experiments also require explicit target and provider scope. Move this handoff
through the documented lifecycle only when implementation and its required,
authorized acceptance checks are complete.
