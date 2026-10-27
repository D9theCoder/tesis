"""Token-weighted provider cache rates and explicit incomplete usage evidence."""

import pytest

from evaluation.multi_llm_runner import _build_matrix_aggregate
from llm.cache_metrics import cache_performance_summary, provider_cache_tokens


@pytest.mark.parametrize(("usage", "expected"), [
    ({"input_tokens": 1000, "input_token_details": {"cache_read": 800}}, (1000, 800)),
    ({"input_tokens": 1000, "input_token_details": {"priority_cache_read": 800}}, (1000, 800)),
    ({"prompt_tokens": 1000, "prompt_tokens_details": {"cached_tokens": 800}}, (1000, 800)),
    ({"input_tokens": 1000, "input_tokens_details": {"cached_tokens": 800}}, (1000, 800)),
    ({"prompt_tokens": 1000, "prompt_cache_hit_tokens": 800, "prompt_cache_miss_tokens": 200}, (1000, 800)),
    ({"prompt_cache_hit_tokens": 800, "prompt_cache_miss_tokens": 200}, (1000, 800)),
    ({"input_tokens": 100, "cache_read_input_tokens": 800, "cache_creation_input_tokens": 100}, (1000, 800)),
    ({"input_tokens": 1000, "input_token_details": {"cache_read": 0}}, (1000, 0)),
    ({"input_tokens": 1000}, (1000, None)),
    ({"input_tokens": 1000, "input_token_details": {"cache_read": True}}, (1000, None)),
    ({"input_tokens": 1000, "input_token_details": {"cache_read": 1001}}, (None, None)),
    ({}, (None, None)),
])
def test_provider_cache_usage_formats(usage, expected):
    assert provider_cache_tokens(usage) == expected


def _attempt(total, cached):
    return {"provider_usage": {"input_tokens": total, "input_token_details": {"cache_read": cached}}}


def _row(*attempts, **overrides):
    return {"cache_hit": False, "provider_dispatches": len(attempts),
            "attempt_records": list(attempts), **overrides}


def test_fallback_attempts_are_counted_once_and_local_hits_add_no_tokens():
    rows = [
        _row(_attempt(1000, 800), _attempt(9000, 0), provider_usage=_attempt(9000, 0)["provider_usage"]),
        {"cache_hit": True, "provider_usage": _attempt(1000, 800)["provider_usage"]},
    ]
    summary = cache_performance_summary(rows)
    assert summary["cache_hit_rate"] == 0.08
    assert summary["provider_input_tokens"] == 10000
    assert summary["provider_cached_input_tokens"] == 800
    assert summary["provider_cache_usage_attempts"] == 2
    assert summary["response_cache_hit_rate"] == 0.5
    assert summary["cache_hits"] == summary["response_cache_hits"] == 1


def test_native_deepseek_counters_survive_missing_sdk_cache_details():
    usage = {"input_tokens": 1000, "output_tokens": 50}
    raw = {"prompt_tokens": 1000, "prompt_cache_hit_tokens": 800, "prompt_cache_miss_tokens": 200}
    summary = cache_performance_summary([_row({"provider_usage": usage, "provider_usage_raw": raw})])
    assert summary["cache_hit_rate"] == 0.8


def test_missing_attempt_usage_keeps_complete_rate_unknown():
    summary = cache_performance_summary([_row({}, _attempt(1000, 800))])
    assert summary["cache_hit_rate"] is None
    assert summary["provider_input_tokens"] is None
    assert summary["observed_provider_input_tokens"] == 1000
    assert summary["observed_provider_cache_hit_rate"] == 0.8
    assert summary["provider_cache_usage_coverage"] == 0.5
    assert summary["provider_cache_usage_status"] == "partial"


def test_hidden_sdk_retries_prevent_claiming_an_exact_token_rate():
    summary = cache_performance_summary([
        _row(_attempt(1000, 800), max_retries=2, provider_requests=None),
    ])
    assert summary["cache_hit_rate"] is None
    assert summary["observed_provider_cache_hit_rate"] == 0.8
    assert summary["provider_cache_usage_status"] == "sdk_retries_unknown"


@pytest.mark.parametrize("rows", [[], [{"cache_hit": True}], [_row(_attempt(0, 0))]])
def test_no_provider_input_tokens_has_no_rate(rows):
    assert cache_performance_summary(rows)["cache_hit_rate"] is None


def test_legacy_parent_usage_is_used_once_without_attempts():
    summary = cache_performance_summary([{
        "provider_usage": {"prompt_tokens": 1000, "prompt_tokens_details": {"cached_tokens": 800}},
    }])
    assert summary["cache_hit_rate"] == 0.8
    assert summary["provider_cache_usage_attempts"] == 1


def test_matrix_rate_uses_combined_token_totals_not_mean_coordinate_rates():
    artifacts = [{
        "status": "success", "config": {"provider": "openai_compatible", "surface": "sqli",
        "security_level": "low"}, "llm_performance": [_row(_attempt(total, cached))],
    } for total, cached in ((1000, 800), (9000, 0))]
    summary = _build_matrix_aggregate(artifacts)["llm_performance_summary"]
    assert summary["cache_hit_rate"] == 0.08
    assert summary["provider_input_tokens"] == 10000
    assert summary["response_cache_hit_rate"] == 0.0
