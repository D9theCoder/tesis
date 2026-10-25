"""Extract only provider-returned reasoning text and summaries, never infer it."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def _field(value: Any, key: str) -> Any:
    return value.get(key) if isinstance(value, Mapping) else getattr(value, key, None)


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _summary(value: Any) -> str | None:
    if isinstance(value, str):
        return _text(value)
    if isinstance(value, list):
        parts = [item["text"] for item in value if isinstance(item, Mapping)
                 and item.get("type") in ("summary_text", "reasoning.summary") and _text(item.get("text"))]
        return "\n".join(parts) or None
    return None


def reasoning_evidence(response: Any) -> dict[str, str | None]:
    """Return nullable trace/summary fields and the native source of each.

    Trace and summary are independent. Encrypted/redacted reasoning and visible
    answer text are excluded. Prefer a native field over a duplicate content
    representation; combine multiple blocks within that one representation.
    """
    result: dict[str, str | None] = {
        "reasoning_trace": None, "reasoning_trace_source": None,
        "reasoning_summary": None, "reasoning_summary_source": None,
    }
    raw = _field(response, "raw")
    if raw is not None:
        response = raw
    additional = _field(response, "additional_kwargs") or {}
    if not isinstance(additional, Mapping):
        additional = {}
    for source, prefix in ((additional, "additional_kwargs."), (response, "")):
        trace = _text(_field(source, "reasoning_content"))
        if trace and result["reasoning_trace"] is None:
            result.update(reasoning_trace=trace, reasoning_trace_source=prefix + "reasoning_content")
        summary = _summary(_field(source, "reasoning_summary"))
        if summary and result["reasoning_summary"] is None:
            result.update(reasoning_summary=summary, reasoning_summary_source=prefix + "reasoning_summary")

    representations = [(additional.get("reasoning_details"), "additional_kwargs.reasoning_details"),
                       (additional.get("reasoning"), "additional_kwargs.reasoning"),
                       (_field(response, "content"), "content"),
                       (_field(response, "output"), "output")]
    for blocks, source in representations:
        if isinstance(blocks, Mapping):
            blocks = [blocks]
        if not isinstance(blocks, list):
            continue
        traces, summaries = [], []
        for block in blocks:
            if not isinstance(block, Mapping):
                continue
            kind = block.get("type")
            if not isinstance(kind, str):
                continue
            if kind in {"thinking", "reasoning_content", "reasoning.text"}:
                text = _text(block.get("thinking")) or _text(block.get("text"))
                if text:
                    traces.append(text)
            elif kind == "reasoning":
                text = _text(block.get("reasoning"))
                if text:
                    traces.append(text)
                summary = _summary(block.get("summary"))
                if summary:
                    summaries.append(summary)
            elif kind == "reasoning.summary":
                summary = _text(block.get("summary")) or _text(block.get("text"))
                if summary:
                    summaries.append(summary)
        if traces and result["reasoning_trace"] is None:
            result.update(reasoning_trace="\n".join(traces), reasoning_trace_source=source)
        if summaries and result["reasoning_summary"] is None:
            result.update(reasoning_summary="\n".join(summaries), reasoning_summary_source=source)
    return result
