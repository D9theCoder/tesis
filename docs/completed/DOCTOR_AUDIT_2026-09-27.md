# Doctor correctness audit — 2026-09-27

Status: completed. Focused, full offline, and requested live acceptance checks passed.
Scope: all 11 offline checks, both configured live model roles, all three live
DVWA checks, and the TUI report lifecycle. No experiment or attack was executed.
User configuration and earlier staged cleanup changes were preserved.

## Results by check

| Check | Finding and final behavior | Verification / limits |
| --- | --- | --- |
| `coverage.scope` | Flattening the method set missed methods assigned to the wrong surface. Now checks each surface mapping. | Swapped-method fault rejected; current fixed axes pass. |
| `akg.integrity` | Missing method preconditions could pass and make methods viable without observations. Now requires a nonempty precondition list for every method. | Missing-precondition regression and existing AKG failure tests; this is static validation. |
| `graph.compilation` | No additional misclassification found within its compilation-only claim. | Current graph compiles; no node executes. Compilation does not prove method behavior. |
| `payload.static_seeds` | Nonempty candidates without validation records could pass. Now requires a record per seed. | Missing-evidence and rejected-seed faults fail; all 81 current coordinates pass. Generated LLM payloads are not probed. |
| `containment.http` | A guard rejecting every URL could pass the external-target checks. Now also requires the configured target to be accepted. | Deny-all/permissive guard faults and HTTP-mocked redirect containment; offline checks transmit no request. |
| `config.profiles_roles` | No further fault found in configured profile/role resolution. | Current profiles resolve; missing profiles are reported. All configured profiles are checked locally, but only selected roles receive live probes. |
| `config.credentials` | Ignored effective `extra.api_key` and SDK environment fallback, producing false failures. | Effective credentials now resolve and are included in secret redaction; remote acceptance is tested separately. |
| `config.endpoints` | Invalid ports, whitespace hosts, and invalid `extra.base_url` overrides could pass. | Those cases now fail. URL syntax does not establish reachability. |
| `environment.dependencies` | Required SQLite checkpoint dependency was omitted. | Missing `langgraph.checkpoint.sqlite` now fails. This checks importability, not all version compatibility; a missing bootstrap import can prevent Doctor from starting. |
| `output.writability` | Parent permission checks missed a file at `output_dir/runs`, dangling links, and failed writes. | Checks the actual layout path and performs/removes a temporary write with flush/fsync; all three faults fail. Does not reserve space or guarantee future capacity. |
| `reasoning.controls` | Wording overstated provider/model validity. | Now explicitly checks adapter forwarding and states model support is unverified offline. Invalid efforts/unsupported adapters still fail. |
| `live.model.orchestrator`, `live.model.payload_generator` | Probe could override a profile budget with 32 tokens, use the wrong default profile, accept extra schema keys, or mark valid output skipped solely because usage was absent. | Now probes the resolved profile/budget and exact schema. Valid output passes with missing telemetry explicitly unverified. SDK-simulated cases cover rejection, truncation, schema mismatch, and absent usage; both actual configured roles pass live. |
| `live.dvwa.authentication` | Earlier weak login signals were already tightened. | Actual running DVWA passes; one deliberately incorrect password fails with dependent checks skipped. Earlier stopped-server probe timed out and failed correctly. |
| `live.dvwa.levels` | Earlier cookie-fallback false positives were already removed. | Live low/medium/high each confirmed by server-rendered selected settings; missing/unreachable-page regressions fail. |
| `live.dvwa.surfaces` | Strict path comparison rejected valid redirects from a directory to its `index.php`. | Equivalent index URLs now pass; login redirects/navigation-only pages fail. Current SQLi, access-control, and brute-force pages pass. Surface probes are at requested high level, not a 3×3 execution matrix. |
| TUI lifecycle | An older worker could pass its generation check, queue a callback, then overwrite a newer result. | Generation checked again when rendering. Reversed callback delivery preserves the newest result. Errors remain visible/redacted; reruns clear old results. |

Nineteen additional regression cases failed before their corresponding repairs.
Existing stopped-service, rejected-provider, and healthy-service cases were
retained. Test fixtures explicitly isolate real environment credentials.

## Repeatable validation

Run from the repository root with the current `config.yaml`:

```bash
.venv/bin/python -m tesis doctor --config config.yaml --json
.venv/bin/python -m tesis doctor --config config.yaml --live --json
.venv/bin/python -m pytest -q tests/test_doctor.py tests/test_tui.py -k doctor --junitxml=results/validation/doctor-audit/focused.xml
.venv/bin/python -m pytest -q --junitxml=results/validation/junit.xml
PYTHONPATH=. .venv/bin/python results/validation/doctor-audit/probe_rejected_login.py
```

Live commands require network access and model probes may consume credits.
The negative-login script submits one deliberately wrong password only to the
configured DVWA target. Synthetic HTTP/SDK cases make no external requests.

Evidence directory: `results/validation/doctor-audit/`.

- `live-before.json`, `live-after.json`: both actual full probes passed 16 checks;
  two model roles returned structured output and usage; reasoning-token evidence
  was absent and remains unverified.
- `offline-after.json`: 11 local passes, 5 explicitly skipped service checks.
- `live-rejected-login.json`: authentication rejected, 1 failed and 2 skipped;
  the reproduction script exits zero only when this expected negative result occurs.
- `before.log`, `before-ui.log`, `before-effective.log`, `before-akg.log`: faults
  reproduced before implementation.
- `focused.log`, `focused.xml`: 64 focused Doctor/UI checks passed.
- `suite.log`, `results/validation/junit.xml`: 1,314 tests passed in 93.63 seconds.
- Individual synthetic fault reports are adjacent JSON files. Prior HTTP service
  scenarios and the redacted TUI error capture remain in `results/validation/doctor/`.

These checks establish behavior for the recorded configuration and fault cases.
They do not prove that every future service response, provider/model, filesystem
state, or experiment coordinate is correct. No remaining misclassification was
observed in the tested cases; actual attack execution was intentionally outside
this diagnostic audit.
