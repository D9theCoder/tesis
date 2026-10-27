# LLM caching and input-token metrics

TESIS distinguishes provider prompt caching from its coordinate-local response
cache. The provider may reuse computation for a matching input prefix while
generating a fresh response. TESIS never shares saved model answers between
coordinates, repeats, or runs. Independent calls can naturally return identical
text; caching does not force different answers.

## Scope and request layout

`llm_runtime.cache_scope: run` enables saved-response reuse only inside one
`CoordinateCallContext`. There is no matrix-wide or persistent response cache.
Provider client factories disable LangChain's response cache, including any
process-global cache, so it cannot bypass coordinate isolation. The configuration
switch controls TESIS response reuse, not the provider's prompt cache.

Exact-request keys include coordinate ID, role, model/configuration fingerprint,
actual output schema, schema version, system/user messages, token limit, and
decoding settings. Same-key calls in one context wait on a context-owned lock
before taking an LLM slot. Only successfully parsed and validated responses are
saved. Hits are revalidated against the current caller's constraints and returned
as independent copies. Failed validation evicts the entry and dispatches again.
None of these locks or entries are shared with another coordinate.

Both role prompts put stable task instructions first. Their compact JSON context
places reusable surface/method constraints and seeds before changing observations
and progress. Nested mappings retain deterministic ordering. This changes input
layout, not the allowed methods, mutation rules, containment, or output schemas.
Prompt manifests use version `2.0.0` and hash the instruction prefix and context
placement. Full history and other-coordinate data remain excluded.

Provider caching remains best-effort and depends on the serving service, model,
prefix boundaries, token threshold, residency, and request timing. The runtime
does not pad prompts, perform hidden warm-up requests, or share generated answers
to manufacture a higher hit rate. Parallel coordinates still dispatch independently.

## Metric contract

New coordinate, per-role, and matrix summaries carry
`cache_metrics_version: provider-input-tokens.v1`. Rates are fractions from 0 to 1;
multiply by 100 for display as a percentage.

| Field | Meaning |
| --- | --- |
| `cache_hit_rate` | Sum of provider cache-read input tokens divided by sum of total provider input tokens |
| `provider_input_tokens` | Total input, including cache reads and cache writes, when accounting is complete |
| `provider_cached_input_tokens` | Cache-read input tokens when accounting is complete |
| `provider_cache_usage_attempts` | Physical dispatch attempts requiring usage evidence |
| `provider_cache_usage_reported_attempts` | Attempts with valid total-input and cache-read counters |
| `provider_cache_usage_unknown_attempts` | Attempts missing complete cache usage |
| `provider_cache_usage_coverage` | Reported attempts divided by observed dispatch attempts; null with no dispatches |
| `provider_cache_usage_status` | `complete`, `partial`, `unavailable`, `no_provider_calls`, `zero_input_tokens`, or `sdk_retries_unknown` |
| `observed_provider_input_tokens` | Input-token sum from attempts with complete counters |
| `observed_provider_cached_input_tokens` | Cache-read sum from those same attempts |
| `observed_provider_cache_hit_rate` | Ratio for that observed subset only |
| `response_cache_hits` | Logical calls reusing a coordinate-local saved response |
| `response_cache_hit_rate` | Saved-response hits divided by logical calls |
| `cache_hits` | Compatibility name for the local `response_cache_hits` count |

For example, attempts reporting 800/1,000 and 0/9,000 cached/total input tokens
produce `cache_hit_rate: 0.08` (8%), not the mean of their individual rates.
Generated output and reasoning-output tokens are excluded from the denominator.
Local response hits add no provider tokens or attempts.

`cache_hit_rate`, `provider_input_tokens`, and `provider_cached_input_tokens`
are null if any dispatch lacks complete counters or configured SDK retries hide
the actual requests. The observed subset and its coverage remain explicit.
With no provider calls or zero total input, the provider rate is null. Explicit
zero cache reads with positive total input produce a measured rate of zero.
Missing cache counters are never interpreted as zero. Coverage describes visible
attempts; it does not resolve hidden SDK retries.

Physical `attempt_records` are authoritative, including native-schema fallback
attempts and responses rejected by JSON/schema validation. Parent call usage is
not added again. Older records without attempt rows use parent usage once and
retain incomplete accounting when multiple dispatches cannot be reconstructed.
Matrix rates are recomputed from child attempt totals, never by averaging rates.

Each returned attempt and parent call retains normalized `provider_usage` and
redacted `provider_usage_raw`. Cache extraction supports LangChain
`input_token_details.cache_read`, Chat Completions
`prompt_tokens_details.cached_tokens`, Responses
`input_tokens_details.cached_tokens`, and DeepSeek
`prompt_cache_hit_tokens` / `prompt_cache_miss_tokens`. Native Anthropic input
counts exclude cached tokens, so reads and cache-creation tokens are added once
to obtain total input; normalized LangChain input totals already include them.

## Historical artifacts and provider evidence

Artifacts without `cache_metrics_version: provider-input-tokens.v1` used
`cache_hit_rate` for local saved-response hits. Do not relabel that historical
number as a provider token rate. Original artifacts remain unchanged; recompute
from their usage evidence only when it is available.

Provider references:

- [River usage and billing](https://docs.river.ai/guides/inference-models/)
- [River prefix reuse](https://docs.river.ai/guides/inference/)
- [DeepSeek context caching](https://api-docs.deepseek.com/guides/kv_cache/)
- [OpenAI prompt caching](https://developers.openai.com/api/docs/guides/prompt-caching)

Offline checks and live cache measurements are separate evidence. Unit or mocked
E2E success does not establish provider cache residency or a guaranteed hit rate.

### River diagnostic on 2026-10-28

The authorized live check used the configured River profile
`deepseek-ai/DeepSeek-V4.1-Flash-1017`, seven synthetic requests, at most 512
output tokens per call, no SDK retries, and no DVWA requests. Every request used
a fresh coordinate context with local response reuse enabled. The long-prefix
input was a fictional inventory; no production prompts or repository documents
were sent. Production prompt cache performance remains unmeasured.

| Request group | Cached / total input tokens | Provider rate |
| --- | --- | --- |
| Four compact synthetic requests, sequential and parallel | 0 / 100 | 0% |
| First long-prefix synthetic request | 0 / 4,372 | 0% |
| Parallel request with marker `left` | 4,352 / 4,371 | 99.57% |
| Parallel request with marker `right` | 4,352 / 4,371 | 99.57% |
| All seven requests | 8,704 / 13,214 | 65.87% |

All seven responses passed validation. Peak LLM concurrency was two. The
parallel long-prefix responses preserved their distinct input markers, and
all seven coordinates recorded zero local response hits. This demonstrates
provider prefix reuse with independent output generation for this diagnostic;
it does not establish a guaranteed rate or a production-workload speedup.

The initial sandbox attempt could not connect. Automatic approval review then
rejected a probe containing repository content. That probe was replaced with
the synthetic inputs above before network access was approved.

Evidence and reproducible scripts are under
`results/validation/llm-cache-2026-10-28/`: `live_probe.py`,
`live/manifest.json`, `live/transport.json`, individual coordinate artifacts,
and `live/summary.json`. The failed sandbox attempt is retained separately in
`live-sandbox-network-blocked/`; it is excluded from the live measurement.
