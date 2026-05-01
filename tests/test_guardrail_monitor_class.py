import pytest

from llm.guardrail_monitor import GuardrailMonitor, is_guardrail_refusal


def test_is_guardrail_refusal_detects_known_patterns():
    assert is_guardrail_refusal("I can't assist with that") is True
    assert is_guardrail_refusal("Here is the payload") is False


def test_guardrail_monitor_check_increments_counters():
    monitor = GuardrailMonitor()
    assert monitor.check("I can't assist") is True
    assert monitor.check("Normal response") is False
    assert monitor._total_checks == 2
    assert monitor._activations == 1
    assert monitor.get_rate() == 0.5


def test_guardrail_monitor_summary():
    monitor = GuardrailMonitor()
    monitor.check("I can't assist")
    monitor.make_event("claude", "orchestrator", "I can't assist")
    summary = monitor.summary()
    assert summary["total_checks"] == 1
    assert summary["activations"] == 1
    assert summary["by_provider"]["claude"] == 1
