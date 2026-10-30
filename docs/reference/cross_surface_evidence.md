# Cross-surface evidence rule (D7)

**Status:** reference — governing rule for the readiness gate and the chaining router.
**Introduced:** 2026-10-30, main-study v4 remediation.
**Consumers:** `foundation/readiness.py` (readiness gate), `core/chaining_coordinator.py`
(chain reachability), `foundation/recon.py` (discovery and bounded destination controls).

## The rule

> **Evidence for a surface is produced by observing that surface in this run. It is never
> inherited, inferred, or assumed — and its absence is recorded as a limitation of the run,
> not as a property of the fixture or the model.**

Two gates asked the same underlying question in the v4 study — "what do we know about a
surface we are not currently on?" — and each answered it separately with a fail-closed
default that produced a silent, permanent rejection:

| Gate | Question it asks | v4 failure | Resolution under this rule |
| --- | --- | --- | --- |
| Readiness (`foundation/readiness.py`) | Was this surface's handler **observed** by this run's crawl? | Form-only discovery never recorded form-less module pages, so Access Control and `sqli/high` were permanently unobservable (D1); a hardcoded level set demanded a token the fixture does not render (D2). | Observe harder: record the fetched navigation link and the handlers the page itself declares, and drive the token requirement from the form the crawl actually saw. The requirement is unchanged; the observation became complete. |
| Chaining (`core/chaining_coordinator.py`) | Were this **destination's** preconditions proved **in this run**? | Destination preconditions were only measured after the source gate passed, so a cross-surface destination was never measured and every edge reported `destination_preconditions_not_proved` (D6). | Measure first: run the bounded destination control before the source gate decides, record `recon.destination.completed` in telemetry, and record an inconclusive probe in `preparation_failures`. The visit still requires source material that is bound to this run's evidence. |

## What "observed" means for each gate

- **Readiness evidence** is a per-run observation of the configured fixture at the requested
  security level: authenticated principal, observed security level, and the surface's module
  handler — either a form action, a handler the page declares in its own markup (inline
  JavaScript, an inline event attribute, or a same-host script the page loads), or the
  navigation path of a successfully fetched module page that declared nothing more specific.
  A redirect away from the requested path, an error status, or a missing handler is not
  observation. Nothing about a previous run is reused.
- **Chaining evidence** is either a verifier-confirmed source outcome bound to candidate and
  response evidence in this run, or a bounded detection control executed in this run. A
  destination status is `true` only when a control measured it; `unknown` never authorises a
  visit and is recorded in `preparation_failures`.

## Explicitly rejected alternatives

- **Cross-run inheritance.** Reusing a previous run's precondition fact as this run's evidence
  would let an unattested fixture epoch (see the D8 validity threat) stand in for a
  measurement. It is not used.
- **Fail-open by absence.** Treating an unobserved endpoint or an unmeasured precondition as
  satisfied is the opposite failure and equally disqualifying; it would report a harness
  property that was never established.
- **Gate removal.** Dropping a required endpoint from `_SURFACE_ENDPOINT_FRAGMENTS`, making the
  token requirement unconditional-off, or downgrading a blocking readiness reason removes the
  observation requirement instead of completing it.

## Consequences recorded for the study

1. A surface whose destination prerequisites are measured `false` on this fixture is rejected
   with that measured negative — a finding, not a defect.
2. A chain edge whose source material cannot exist on this fixture (for example plaintext
   credentials from a SQL injection dump) is rejected on the **source** stage, and the
   rejection now names the source stage explicitly (`decisive_stage` in `chain_assessment`),
   rather than blaming destination preconditions.
3. A destination measurement costs one bounded control set per (method, source evidence) pair
   per run and is skipped when the destination is already proved or already measured `false`.
