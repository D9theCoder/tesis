# LLM rate-limit retries

The shared LLM runtime retries transient rate limits for orchestrator and
payload-generator calls automatically. Defaults are three retries after the
initial dispatch, with waits of 10, 20, and 40 seconds plus up to one second of
jitter. Provider `Retry-After` (seconds or HTTP date) and `retry-after-ms` headers
can extend a wait. A requested wait that exceeds the remaining retry window
ends the call rather than sending an early request.

The retry window defaults to 120 seconds, measured from admission to the LLM
concurrency slot. No further retry starts after that window. An admitted
request still uses its own configured timeout and can complete after the
window. The runtime retains its concurrency slot during waits.

## Configuration

Configure these provider-agnostic defaults once for all runtime model calls:

```yaml
llm_runtime:
  rate_limit_retries: 3
  rate_limit_retry_budget_s: 120
```

The config loader validates and forwards these settings to single runs, matrix
runs, research-plan execution, and runtime Doctor probes. No provider-specific
configuration is needed. Optional model overrides under `models.<profile>.extra`
or `api_providers.<id>.extra` take precedence over the global defaults.
`rate_limit_retries` accepts integers from 0 through 10; zero disables runtime retries.
`rate_limit_retry_budget_s` accepts finite numbers from 0 through 3600; zero
also prevents retries. These fields never enter the provider HTTP body.

An explicit positive SDK `max_retries` retains retry ownership and disables
the runtime loop, avoiding multiplied retry counts. SDK defaults remain zero.
SIWC continues to reject hidden SDK retries; its runtime calls use the same
observable rate-limit policy as other adapters.

## Errors and evidence

HTTP 429 and structured rate-limit error codes qualify. Billing, insufficient
quota, credit exhaustion, and subscription usage exhaustion codes are terminal.
Authentication failures, other HTTP errors, invalid JSON, schema validation
failures, and incomplete outputs do not trigger this policy. Prompts, model
selection, and experiment identity remain identical across retries.

Each dispatch has its own `attempt_records` entry, diagnostic, and elapsed time.
The throttled attempt records `retry_reason: rate_limit` and `retry_delay_s`;
activity emits `llm.retrying`. Final records include the effective
`rate_limit_retries`, `rate_limit_retry_budget_s`, and `retry_owner`.
`provider_dispatches`, `attempts`, and known physical request counts include
retries. Local cache hits create no dispatch. SDK retries continue to make
physical request counts unknown.

This policy applies to calls through `LLMRuntime`, including runtime Doctor
model probes. Direct evaluator requests, model discovery, and reasoning-support
checks retain their existing behavior. It does not rerun an experiment or repair target-readiness
failures. Exhausted retries preserve the final provider error and preceding
attempts for review.

Tests and live provider/DVWA validation were left unrun at the user's request.
