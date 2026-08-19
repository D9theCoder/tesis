# Full-Coordinate Concurrency Feasibility

## Decision

Full matrix-coordinate concurrency is not enabled for thesis experiments. The
implemented scheduler overlaps LLM work only and holds a matrix-wide semaphore
around complete reconnaissance and method-agent nodes. This preserves a single
DVWA request/evidence stream while removing avoidable model idle time.

No `matrix_max_concurrency` option is exposed. The repository currently has one
configured DVWA base URL and no isolated replica endpoints for timing-sensitive
or brute-force trials, so the empirical gates below cannot be satisfied without
changing the test environment.

## Verified locally

Blocking fake-model and fake-node tests verify that:

- model calls overlap when LLM concurrency is two;
- peak model concurrency never exceeds the configured bound;
- recon and method-node HTTP regions never overlap;
- coordinate artifacts retain canonical matrix order after out-of-order worker
  completion;
- coordinate caches and telemetry do not cross coordinate boundaries;
- cancellation stops further submission and retains completed or safely
  cancelled child artifacts.

These are implementation-safety checks, not evidence that concurrent DVWA
requests preserve experimental validity.

## Required empirical study

Before adding full-coordinate concurrency, run serial and two-worker schedules
with identical seeds, conditions, methods, levels, payload modes, and repeat
indexes.

1. Use the existing DVWA instance only for non-timing methods.
2. Use separate, freshly initialized DVWA replicas for SQLi timing and
   brute-force coordinates. Never submit simultaneous timing-sensitive requests
   to one instance as thesis evidence.
3. Run three repeats per schedule and retain complete response, timing,
   containment, cookie, and security-level evidence.
4. Compare each concurrent coordinate with its serial counterpart.

Full concurrency is acceptable only if every comparison shows:

- zero cookie or DVWA security-level leakage;
- identical confirmed findings and terminal statuses across all three repeats;
- identical timing classifications;
- less than 10 percent non-delay P95 latency drift;
- no new rate-limit, containment, or redirect events.

## Recommendation

Retain HTTP serialization until isolated replicas are provisioned and every
gate passes. If higher throughput is required before then, schedule one
coordinate per isolated DVWA replica and keep request serialization within each
replica. A future `matrix_max_concurrency` setting should be added only after
the resulting evidence is archived and reviewed.
