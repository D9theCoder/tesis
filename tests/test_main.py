import main as main_module


def test_main_returns_success_payloads(monkeypatch):
    def fake_invoke_sample_query(provider_name: str):
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
    def fake_invoke_sample_query(provider_name: str):
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
