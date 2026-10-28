"""Bounded, observable rate-limit retry policy for runtime model dispatches."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import math
import random
from typing import Any, Mapping


@dataclass(frozen=True)
class RateLimitPolicy:
    retries: int = 3
    budget_s: float = 120.0

    @classmethod
    def from_config(cls, config: Mapping[str, Any]) -> RateLimitPolicy:
        retries = config.get("rate_limit_retries", 3)
        budget = config.get("rate_limit_retry_budget_s", 120.0)
        if type(retries) is not int or not 0 <= retries <= 10:
            raise ValueError("rate_limit_retries must be an integer between 0 and 10")
        if isinstance(budget, bool) or not isinstance(budget, (int, float)) or not math.isfinite(budget) or not 0 <= budget <= 3600:
            raise ValueError("rate_limit_retry_budget_s must be finite and between 0 and 3600")
        # An explicitly enabled SDK retry policy retains ownership. Never
        # multiply SDK retries by another application-level retry loop.
        return cls(0 if config.get("max_retries") else retries, float(budget))

    def delay(self, exc: Exception, *, status_code: int | None, retry_index: int,
              elapsed_s: float) -> float | None:
        chain: list[BaseException] = []
        current: BaseException | None = exc
        while current is not None and all(current is not item for item in chain):
            chain.append(current)
            current = current.__cause__ or current.__context__
        codes = []
        for item in chain:
            codes.extend(_error_codes(getattr(item, "body", None)))
            codes.append(str(getattr(item, "code", "")).lower())
        # A billing/usage exhaustion can also be HTTP 429, but waiting briefly
        # does not repair it. Do not treat it as a transient throttle.
        if any(marker in code for code in codes for marker in (
            "insufficient_quota", "quota_exceeded", "billing", "credit", "usage_limit_exceeded",
        )):
            return None
        throttled = status_code == 429 or any(code in {
            "rate_limit_exceeded", "rate_limit_error", "too_many_requests", "resource_exhausted",
        } for code in codes)
        if not throttled or (status_code is not None and status_code != 429) or retry_index >= self.retries:
            return None
        delay = min(60.0, 10.0 * 2.0 ** retry_index) + random.uniform(0, 1)
        for item in chain:
            headers = getattr(getattr(item, "response", None), "headers", None)
            if not isinstance(headers, Mapping):
                headers = getattr(item, "retry_headers", {})
            if isinstance(headers, Mapping):
                delay = max(delay, _retry_after(headers))
        # Never shorten a provider's requested delay to fit the budget.
        return delay if elapsed_s + delay < self.budget_s else None


def _error_codes(body: Any) -> list[str]:
    if not isinstance(body, Mapping):
        return []
    return [str(body.get(key, "")).lower() for key in ("code", "type")] + _error_codes(body.get("error"))


def _retry_after(headers: Mapping[str, Any]) -> float:
    normalized = {str(key).lower(): value for key, value in headers.items()}
    delays = [0.0]
    for key, scale in (("retry-after-ms", 0.001), ("retry-after", 1.0)):
        value = normalized.get(key)
        if value is None:
            continue
        try:
            delay = float(value) * scale
        except (TypeError, ValueError):
            if key != "retry-after":
                continue
            try:
                date = parsedate_to_datetime(str(value))
                delay = (date - datetime.now(timezone.utc)).total_seconds()
            except (TypeError, ValueError, OverflowError):
                continue
        if math.isfinite(delay):
            delays.append(max(0.0, delay))
    return max(delays)
