"""Provider input-token cache accounting, separate from saved response reuse."""

from __future__ import annotations

from typing import Any, Mapping


def _tokens(usage: Mapping[str, Any], *path: str) -> int | None:
    value: Any = usage
    for key in path:
        if not isinstance(value, Mapping):
            return None
        value = value.get(key)
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def provider_cache_tokens(
    usage: Mapping[str, Any], raw_usage: Mapping[str, Any] | None = None,
) -> tuple[int | None, int | None]:
    """Read total input and cached reads without turning missing counters into zero.

    LangChain input totals already include cached tokens. Native Anthropic input
    totals exclude cache reads and writes, so those must be added exactly once.
    DeepSeek can report its total as the sum of cache hits and misses.
    """
    input_tokens = _tokens(usage, "input_tokens")
    cached_tokens = _tokens(usage, "input_token_details", "cache_read")
    if cached_tokens is None:
        for tier in ("priority", "flex"):
            cached_tokens = _tokens(usage, "input_token_details", f"{tier}_cache_read")
            if cached_tokens is not None:
                break
    if input_tokens is not None and cached_tokens is not None:
        return (input_tokens, cached_tokens) if cached_tokens <= input_tokens else (None, None)

    native = raw_usage if raw_usage else usage
    if "cache_read_input_tokens" in native:
        uncached = _tokens(native, "input_tokens")
        reads = _tokens(native, "cache_read_input_tokens")
        writes = _tokens(native, "cache_creation_input_tokens")
        total = None if uncached is None or reads is None or writes is None else uncached + reads + writes
        return total, reads

    total = _tokens(native, "prompt_tokens")
    if total is None:
        total = _tokens(native, "input_tokens")
    reads = _tokens(native, "prompt_tokens_details", "cached_tokens")
    if reads is None:
        reads = _tokens(native, "input_tokens_details", "cached_tokens")
    if reads is None:
        reads = _tokens(native, "prompt_cache_hit_tokens")
    misses = _tokens(native, "prompt_cache_miss_tokens")
    if total is None and reads is not None and misses is not None:
        total = reads + misses
    if total is None:
        total = input_tokens
    if reads is None:
        reads = cached_tokens
    if total is not None and reads is not None and reads > total:
        return None, None
    return total, reads


def cache_performance_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate physical attempts once and use token-weighted provider rates.

    ``cache_hit_rate`` is null when any dispatch lacks complete usage, when SDK
    retries hide requests, or when no input tokens were sent. The observed rate
    and coverage describe partial evidence without claiming a complete rate.
    Older records without attempts use their parent usage once; parent and
    physical-attempt usage are never both counted.
    """
    response_hits = sum(bool(row.get("cache_hit")) for row in rows)
    attempts = reported = total_input = cached_input = 0
    requests_unknown = False
    for row in rows:
        if row.get("cache_hit"):
            continue
        records = row.get("attempt_records")
        records = records if isinstance(records, list) else []
        dispatches = row.get("provider_dispatches", row.get("attempts", len(records) or 1))
        dispatches = dispatches if isinstance(dispatches, int) and dispatches >= 0 else len(records)
        if not dispatches and not records:
            continue
        requests_unknown |= bool(row.get("max_retries")) and row.get("provider_requests") is None
        sources = records or [row]
        attempts += max(dispatches, len(sources))
        for source in sources:
            if not isinstance(source, Mapping):
                continue
            usage = source.get("provider_usage")
            raw_usage = source.get("provider_usage_raw")
            total, cached = provider_cache_tokens(
                usage if isinstance(usage, Mapping) else {},
                raw_usage if isinstance(raw_usage, Mapping) else None,
            )
            if total is None or cached is None:
                continue
            reported += 1
            total_input += total
            cached_input += cached
    complete = bool(attempts) and reported == attempts and not requests_unknown
    observed_rate = round(cached_input / total_input, 4) if total_input else None
    if not attempts:
        status = "no_provider_calls"
    elif requests_unknown:
        status = "sdk_retries_unknown"
    elif reported != attempts:
        status = "partial" if reported else "unavailable"
    else:
        status = "complete" if total_input else "zero_input_tokens"
    return {
        "cache_metrics_version": "provider-input-tokens.v1",
        "cache_hit_rate": observed_rate if complete else None,
        "provider_input_tokens": total_input if complete else None,
        "provider_cached_input_tokens": cached_input if complete else None,
        "observed_provider_input_tokens": total_input,
        "observed_provider_cached_input_tokens": cached_input,
        "observed_provider_cache_hit_rate": observed_rate,
        "provider_cache_usage_status": status,
        "provider_cache_usage_attempts": attempts,
        "provider_cache_usage_reported_attempts": reported,
        "provider_cache_usage_unknown_attempts": attempts - reported,
        "provider_cache_usage_coverage": round(reported / attempts, 4) if attempts else None,
        "cache_hits": response_hits,
        "response_cache_hits": response_hits,
        "response_cache_hit_rate": round(response_hits / len(rows), 4) if rows else 0.0,
    }
