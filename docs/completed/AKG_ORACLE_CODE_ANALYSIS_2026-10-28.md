# AKG routing and oracle code analysis

Status: code remediation and full offline acceptance complete. The final suite
passed 2,457 tests with no failures; one DOCX check was excluded at the owner's
request. Research evidence retains the fixture limits described below.

## Findings and repairs

| Finding | Repair |
| --- | --- |
| Truthy strings and integers could satisfy method preconditions. | Require the observed boolean `True`. |
| Unknown or mismatched static chain agents passed graph validation; absent confirmed-node mappings were skipped. | Validate every registered destination and method mapping before routing. |
| Session collection treated its own generated sources as additional protocols. Dependency idempotency was checked after HTTP. | Identify frozen protocols and check generated IDs before issuing controls. |
| Collectors parsed credential strategy text differently from agents. | Use the executor's credential-prefix parser. |
| Session controls overwrote the original response's identity fingerprint. | Preserve response bindings; retain independent replay identity separately. |
| Missing bindings and failed dependency controls disappeared. | Persist pending records with reasons, and `not_dependent` when the destination works without the source. |
| Confirmed-only oracles left controlled negatives indistinguishable from missing evidence. | Add separately bound negative permission/session attestations and retain their evidence in scoring review. |
| Replaying a negative candidate successfully could upgrade the original execution. | Require agreement between original outcome and independent control. |
| Generated attestations could resolve without their frozen parent; conflicts and malformed pointers were insufficiently constrained. | Validate the parent hash and exact pointer shape; reject conflicting verdicts. |
| An admin-only recovered source could schedule an AC attempt requiring a non-admin. | Record explicit route infeasibility before scheduling. |
| Credential validation could bind material outside the active route. | Match route evidence, source candidate and source visit before binding. |
| Path recording could conflate separate branches; destination completion accepted evidence outside its verifier references. | Preserve a connected traversal, record separate branches in route history, and require verifier-linked candidate consumption. |
| Permission collection hard-coded fixture admin credentials. | Verify the configured fixture account from the existing scoped credential context. |
| SQLi plaintext to dictionary login lacked independent dependency collection. | Control the recovered credential at the fresh login destination; retain hash-only infeasibility. |
| An unsuccessful execution omitted the explicit negative signal required by the collector. | Retain the agent's boolean result in request evidence. |
| A JSON denial was treated as evidence that role data was enumerable. | Require an actual record identifier during the vertical-escalation probe. |
| A recovered non-admin source could be blocked by observations collected under an earlier admin session. | Measure destination prerequisites once per source in the recovered principal's session, without bypassing higher-priority ready routes. |
| A saved-input replay selecting an exploit discarded its saved queue probes. | Retain saved probe candidates while narrowing the exploit subset. |
| Existing dependency attestations lost their reference when the artifact was extended. | Reattach the existing source-bound reference without repeating HTTP and revalidate it before scoring. |
| HTTPX dot-segment aliases were counted as different targets, and the oracle could not bind the original alias to the normalized response endpoint. | Normalize literal dot segments consistently, avoid duplicate requests and bind both the original object and actual wire resource. |
| Permission collection only covered user ID 1 even when the frozen fixture policy covered other known user records. | Support an explicit list of operator-verified user IDs; unknown IDs remain outside the frozen protocol. |

## Review and suite follow-up

The owner expanded the task to resolve both review comments and all 43 suite
failures, including failures reproduced on the starting commit.

- Session negatives now require DVWA's explicit credential-rejection response
  from the original execution. CSRF-token errors, CAPTCHA and unevaluated forms
  remain without a negative attestation, and do not trigger fresh controls.
  Saved session attestations must meet the same original-response requirement.
- SQLi dependency controls parse the consumed destination credential and match
  it against the source-bound recovered records. Multiple extracted pairs no
  longer cause the collector to select the first pair regardless of consumption.
- Budget exhaustion retains the incomplete result and iteration-limit reason
  in the orchestrator's immediate update.
- Activity observers receive event batches while their drawer covers the
  mission screen. Narrow pipeline rows use the concise stage labels.
- Tests now exercise the current reasoning control, category settings, modal
  sizes, modifier shortcuts, command composer, responsive columns and focus
  indicators. Batched rendering is flushed before UI assertions. Doctor tests
  create their own evidence directory instead of depending on another test.
- Graph tests patch the accessor used by both selection and workflow policy.
  Normal automatic selection excludes visited methods; explicit saved-graph
  revisit coverage still verifies both visits and retained scoring decisions.
  Failed-chain fixtures supply consumable plaintext; hash-only fixtures assert
  that dictionary chaining receives no causal credit.

## Route limits

The static graph declares six chain edges. Runtime consumption supports extracted
plaintext to dictionary login and authenticated non-admin material to IDOR or
force browsing. The two edges leading into intermediate outcome nodes and the
admin-session to SQLi edge do not currently have a supported consumption adapter.
They remain explicitly infeasible; reading an admin record cannot establish an
admin session. The fixture's extracted password hashes cannot be used as plaintext.

The user-manager read API exposes records anonymously at some levels. A matched
permission oracle may establish broad exposure, while a causal dependency must
fail if its negative source control can access the same destination. Do not
convert that result into successful chaining.

The local [protocol configuration](../../config/oracles/dvwa-source-fee264766667580e5352.json)
is pinned to the verified fixture and known user IDs 1–5. `config.yaml` enables
its three protocols for that fixture. The path, fixture identity and protocol
must be reconsidered if the target or fixture changes. The normal configuration
still has an empty ranking profile, so a final v4 method score can remain
pending until an appropriate frozen ranking profile is supplied.

## Validation

The live measurements listed below predate the final review fixes. Their
recorded outcomes are historical evidence, not a new live acceptance run for
this code epoch. Final review validation uses offline checks and mocked E2E;
no fresh live DVWA or model requests were made for this follow-up.

Final follow-up evidence: `results/validation/code-repair-2026-10-28/`.
The final full-suite command is:

```bash
.venv/bin/python -m pytest -q -k 'not report_tables_examples_and_package_preservation' --junitxml=results/validation/junit.xml
```

The final result is **2,457 passed, zero failed, one DOCX check deselected**
in 403.98 seconds. It is recorded in `final-full-suite.log`, with code hashes
and scope in `validation-scope.json`. `original-43-resolution.json` maps every
original failure to a passing counterpart; none was removed or skipped. All three surface dry runs passed using inert
credential placeholders for static compilation, without HTTP or model calls.
The final saved-oracle and scoring checks passed 109 tests; their JUnit report
is `final-oracle-read-check.xml`. DOCX preservation remains deliberately excluded.


Evidence root: `results/validation/akg-oracle-2026-10-28/`.

- Nine new regression failures were captured before repairs. The final focused
  oracle and routing checks passed: 328 in the acceptance run, 45 after the
  last alias fix, 72 after the branch-path fix, and an additional containment
  check. These overlapping test sets should not be added together.
- The first full code suite produced 2,395 passes and 42 failures, with the DOCX
  preservation test excluded. All 42 failures were reproduced on unchanged
  commit `ad53a15da98fe66b6d919b4bf2dfb68050450d92`; see
  [baseline comparison](../../results/validation/akg-oracle-2026-10-28/baseline-comparison.json).
  A later full run produced 2,408 passes and 43 failures. The extra settings UI
  assertion passed in isolation and in a four-test context on both the current
  checkout and that unchanged commit; it is not established as an introduced
  regression. The later full run preceded the final alias-binding and branch-path
  changes, which passed the focused checks above. The subsequent follow-up
  described above resolves these code-suite failures.
- All three surface dry runs pass without target or provider calls.
- Nine live principal/level fixture controls completed on the configured DVWA.
  The mounted fixture hashes match the previous pins; the prior frozen ranking
  profile is reused without claiming a new ranking calibration.
- The [live matrix](../../results/validation/akg-oracle-2026-10-28/final-evidence-audit.json)
  contains both main conditions, nine target methods, three levels, hybrid
  payloads and one repeat: 54 distinct coordinates. There were 53 completed
  executions and one River AI account-rate failure. The latter completed in a
  [separate retry](../../results/validation/akg-oracle-2026-10-28/rate-limit-retry-epoch1/retry-summary.json);
  the original failure remains in the primary cohort. Outcomes in the primary
  cohort were 46 confirmed, four fixture-limited and four unconfirmed.
  The configured experiment roles and evaluator used River AI. All 54 recorded
  experiment model calls were payload-generator calls to River AI DeepSeek;
  explicitly targeted methods did not require an orchestrator model call.
- All 54 original artifacts were reviewed using the frozen River AI evaluator:
  56 candidate decisions in 57 requests produced 46 final receipts and eight
  pending reviews. Four separately derived, source-hashed alias controls and
  their River AI reviews provide final receipts for four of the pending cases;
  four coordinates remain without assessable executed exploit candidates. These
  derived receipts are not additional experiment repeats. Their review required
  four additional AI decisions and four requests.
- The original matrix's assessable candidates came from static seeds. Four
  generated dot-segment aliases received controlled negative assessments in
  the derived artifacts. This does not measure model payload quality or support
  a model ranking. Other unsupported resource paths and nonexistent user IDs
  remain outside the frozen permission protocol rather than receiving invented
  oracle outcomes.
- The [live chain controls](../../results/validation/akg-oracle-2026-10-28/live-chain-controls-epoch4/summary.json)
  used a saved non-admin source and zero fresh provider calls. Force browsing
  earned `Schain=3` from an independently verified one-hop dependency; IDOR
  earned `Schain=0` because the destination was also available anonymously. Both
  recorded branch paths were checked against the directed AKG edges.
  A [saved-input live replay](../../results/validation/akg-oracle-2026-10-28/live-force-browse-dedup-summary.json)
  verified that equivalent aliases caused one request, with zero provider calls.
- The main matrix used its frozen source epoch. Source-bound destination probes,
  dependency-reference recovery and path normalization were fixed after that
  epoch and verified separately. The four alias reviews are linked to their
  derived artifact hashes; original matrix artifacts and receipts remain intact.
