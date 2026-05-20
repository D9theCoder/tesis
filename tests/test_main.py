"""Regression tests for the DVWA LangGraph framework.

This module verifies current behavior for state handling, routing, payloads,
LLM adapters, agents, evaluation, or CLI integration without changing runtime
code."""
import main as main_module


def test_main_returns_success_payloads(monkeypatch):
    """Verifies main returns success payloads behavior."""
    def fake_invoke_sample_query(provider_name: str):
        """Supports regression tests for test main."""
        return {
            "provider": provider_name,
            "model": f"{provider_name}-model",
            "query": main_module.SAMPLE_QUERY,
            "response": f"{provider_name}-response",
        }

    monkeypatch.setattr(main_module, "invoke_sample_query", fake_invoke_sample_query)

    results = main_module.main()

    assert set(results.keys()) == set(main_module.SUPPORTED_PROVIDERS)
    for provider in main_module.SUPPORTED_PROVIDERS:
        assert results[provider]["status"] == "success"
        assert results[provider]["response"] == f"{provider}-response"


def test_main_returns_error_payloads(monkeypatch):
    """Verifies main returns error payloads behavior."""
    def fake_invoke_sample_query(provider_name: str):
        """Supports regression tests for test main."""
        if provider_name == "gemini":
            raise RuntimeError("provider unavailable")
        return {
            "provider": provider_name,
            "model": f"{provider_name}-model",
            "query": main_module.SAMPLE_QUERY,
            "response": f"{provider_name}-response",
        }

    monkeypatch.setattr(main_module, "invoke_sample_query", fake_invoke_sample_query)

    results = main_module.main()

    assert results["gemini"]["status"] == "error"
    assert "provider unavailable" in results["gemini"]["error"]
