# LLM Runtime Acceleration Acceptance

This record compares the authorized 18-coordinate `akg_guided_hybrid` matrix
before and after the runtime acceleration changes. The coordinate axes were
unchanged: provider `openai_compatible`, surfaces `sqli`, `access_control`,
and `brute_force`, security levels `low`, `medium`, and `high`, payload modes
`hybrid` and `llm_mutation_only`, repeat index `0`, and automatic method
selection.

## Baseline

Source artifact:
`results/runs/exec-20260819T141221964120Z-1260de40ccc24a61ab293103e1b232c2.matrix.json`

- 18 coordinates; 12 successful and 6 incomplete/error.
- 83 model calls.
- 41 invalid JSON responses (49.4%).
- 0 guardrail activations.
- 838.14 seconds summed model-call time.

## Accelerated rerun

Source artifact:
`results/runs/matrix-2026-08-20/exec-20260819T170257425324Z-9e297ab4e99b4424a223cee346bee633.matrix.json`

- 18 coordinates with unchanged axes and repeat count.
- 9 successful and 9 incomplete/error; method-level failures remain explicit
  in artifacts rather than being presented as success.
- 123 recorded role calls, including 24 same-coordinate cache hits (99 provider
  calls).
- 332.08 seconds summed model-call time: 60.4% below the baseline.
- Invalid/incomplete structured outputs: 2/123 records (1.63%), or 2/99 actual
  provider calls (2.02%); both are below the 5% gate.
- Guardrail activations: 0, unchanged from baseline.
- Peak LLM concurrency: 2; peak DVWA-node concurrency: 1.
- Actual request/redirect containment failures: 0.

Recon also records 90 blocked discovery links (five filtered external links per
coordinate). These were discarded before any HTTP request and are reported as
scope-discovery evidence; they are not containment failures.

The two invalid records were semantic method-selection failures: the native
tool call was decoded, but `next_agent` was outside the coordinate's viable
method set. They were not malformed JSON or provider refusals. A subsequent
two-coordinate SQLi smoke run after adding a per-call `next_agent` enum had
zero invalid or incomplete LLM outputs; both runs stopped as
`Experiment incomplete: UNSPECIFIED` because reconnaissance exposed no viable
SQLi method. That terminal experiment result is kept separate from LLM output
validity and is not silently converted to success.

Every coordinate artifact includes role/cache configuration, LLM performance
records, lifecycle activity, fallback/invalid-output records, containment
evidence, and the normal experiment evidence fields. The full-coordinate HTTP
concurrency feasibility report remains separate and HTTP serialization stays
enabled for thesis evidence.
