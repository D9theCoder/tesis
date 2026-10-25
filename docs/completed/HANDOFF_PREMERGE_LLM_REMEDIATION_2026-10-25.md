# Handoff: pre-merge LLM configuration and Doctor remediation

Status: completed for the authorized offline scope. Branch:
`breaking/major-tui-revamp`. Starting commit: `23c01ab`.

The user authorized implementation of all seven pre-merge findings and an
investigation of unexpected Gemini runs, then authorized a local commit.
Do not merge or push. Validation is offline only; focused offline E2E coverage
is authorized.

## Findings and acceptance

| ID | Required behavior | Status |
| --- | --- | --- |
| F01 | CLI LLM controls override environment values, which override YAML. | Passed |
| F02 | Untouched launch controls preserve different role reasoning settings. | Passed |
| F03 | The independent evaluator preserves its frozen profile's effective reasoning and API mode. | Passed |
| F04 | Token defaults follow the effective coordinate profile; explicit role limits win. | Passed |
| F05 | Doctor and runtime session setup use the configured DVWA credentials without exporting secrets. | Passed |
| F06 | Artifacts distinguish logical calls, cache hits, and provider dispatch attempts. | Passed |
| F07 | Doctor rejects a missing config path even when environment values otherwise resolve. | Passed |
| F08 | Explain recent Gemini entries, isolate synthetic test output, and restrict launcher choices to configured providers. | Passed for inspected sources |

The initial review and reproductions are saved under
`results/validation/premerge-llm-review/`. The baseline had 159 focused LLM
checks and 139 broader contract checks passing. Those receipts describe the
starting code, not acceptance of these fixes.

## Gemini investigation

The current config resolves to `openai_compatible`, with configured `openai`
and `openai_compatible` profiles. No provider-selection environment override
was present during inspection. The recently inspected Gemini manifests use
`test-model`, have no primary execution artifact, and contain no demonstrated
provider-call evidence. Tests that default their output to repository
`results/` can expose synthetic runs in the real results browser. Preserve
existing artifacts; record attribution separately rather than rewriting them.

Five inspected manifests under `results/runs/single-run-2026-10-12-*` name
`gemini/test-model`, have no child execution identity or primary artifact, and
contain zero `llm.*` events. Their bytes and source hashes are retained in
`results/validation/premerge-llm-remediation/gemini-attribution.json`. These
entries match mocked tests; their metadata does not demonstrate a Gemini API
call. This attribution does not cover every historical Gemini record.

The headless configuration test now supplies a temporary output root, and UI
tests run in temporary working directories. Under the current config, launcher
choices are `openai` and `openai_compatible`. The synthetic `test-execution`
directory created by the preceding review was preserved outside the operator
index at
`results/validation/premerge-llm-review/synthetic-runs/single-run-2026-10-25`.

## Implementation and verification

Flat runtime aliases are normalized before precedence merging. The launch
reasoning selector defaults to preserving role values and can explicitly clear
both overrides. Loader token defaults carry `max_tokens_default`; runtime
resolution honors an explicit role limit, then the effective profile limit,
then the reasoning or historical role default. The evaluator freezes effective
profile options and preserves the source-binding rejection for changed judging
configuration. Historical reviews are not silently migrated to new settings.

`foundation.session_manager.dvwa_credentials` scopes login defaults to a runner
coordinate and later oracle collection. It does not add credentials to graph
state or checkpoints; explicit fixture principal credentials still win.

Runtime records retain a ledger for native and fallback dispatches. Logical
call counts remain separate from dispatch/request counts, and cache hits make
zero requests. Gemini and Claude SDK retry defaults were also found to be 6
and 2 in the installed SDKs; the shared adapter now applies its registered
default of zero to every provider. Explicit SDK retries remain supported,
with exact request counts marked unknown rather than guessed.

Final offline acceptance evidence is under
`results/validation/premerge-llm-remediation/`:

- `unit-contract-acceptance-junit.xml`: 311 passed, zero failures/errors/skips.
- `launch-regressions-junit.xml`: five passed, including four focused UI
  checks and one runner metadata check also included in the 311-check suite.
- `e2e-junit.xml`: two passed, one single run and one matrix flow.
- `offline-e2e/test_configured_roles_and_cred0/acceptance.json` and the sibling
  `test_configured_roles_and_cred1/acceptance.json`: saved E2E receipts, with
  configs, manifests, primary artifacts, and runtime journals in each fixture
  directory. The existing JSON artifact writer produced the receipts.
- `doctor.json`: 11 passed, zero failed, five live checks skipped.
- `static-checks.json`: all 23 changed Python files parsed; diff check passed.
- `acceptance.json`: consolidated commands, source hashes, and evidence links.

The E2E flow uses real mounted launch forms, headless execution, single/matrix
runners, runtime services, and session login behavior. Graph progression,
provider clients, and HTTP transport are local substitutes. Both flows preserve
`high`/`low` efforts, use configured credentials, reject Gemini selection, and
save four dispatches across two logical calls. They do not establish exploit
correctness, model-side reasoning, or live provider/DVWA acceptance.

Both methodology languages, architecture guidance, and the scoring reference
now describe the implemented controls. No method, AKG, scoring formula, or
containment rule changed. No live requests, merge, or push occurred.

Commands for the final required checks:

```bash
.venv/bin/python -m pytest -q tests/test_provider.py tests/test_reasoning_config.py tests/test_doctor.py tests/test_diagnostics.py tests/test_llm_runtime.py tests/test_llm_runtime_config_cli.py tests/test_config_loader.py tests/test_config_fields.py tests/test_session_manager.py tests/test_evaluator_profile_config.py tests/test_runtime_interfaces.py tests/test_evaluation_runner.py tests/test_evaluation_multi_llm_runner.py tests/test_headless.py tests/test_execution_status_review_regressions.py --junitxml=results/validation/premerge-llm-remediation/unit-contract-acceptance-junit.xml
.venv/bin/python -m pytest -q tests/test_evaluation_runner.py::test_runtime_calls_feed_runner_activity_and_effective_runtime_metadata tests/test_tui.py::test_launch_start_freezes_request_until_terminal tests/test_tui.py::test_launch_inputs_resolve_into_the_review tests/test_tui.py::test_single_runner_receives_serialized_model_config tests/test_tui.py::test_ctrl_c_cancels_and_second_ctrl_c_exits --junitxml=results/validation/premerge-llm-remediation/launch-regressions-junit.xml
.venv/bin/python -m pytest -q tests/test_premerge_llm_e2e.py --basetemp=results/validation/premerge-llm-remediation/offline-e2e --junitxml=results/validation/premerge-llm-remediation/e2e-junit.xml
.venv/bin/python -m tesis doctor --config config.yaml --json
git diff --check
```

## Follow-up: shared test model

The shared UI and headless launch fixtures now select `openai_compatible`
with `base_url: http://localhost:9999/v1`. The headless layout and cancellation
fixtures reuse the same model configuration, and the UI serialization check
asserts that the compatible endpoint reaches the runner. Test transports remain
mocked and output remains isolated. Historical Gemini attribution above is
unchanged.

Seven focused headless/UI checks passed. The follow-up receipt is
`results/validation/premerge-llm-remediation/compatible-test-model-acceptance.json`,
with JUnit evidence in `compatible-test-model-junit.xml`. This receipt hashes
the two changed test files; it supplements the earlier acceptance epoch.
