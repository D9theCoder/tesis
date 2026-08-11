"""Regression tests for the DVWA LangGraph framework.

This module verifies current behavior for state handling, routing, payloads,
LLM adapters, agents, evaluation, or CLI integration without changing runtime
code."""
import pytest
import llm.provider as provider_module
from langchain_core.messages import HumanMessage
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_openai import ChatOpenAI
from llm.provider import (
    SAMPLE_QUERY,
    SUPPORTED_PROVIDERS,
    get_llm,
    get_llm_from_model_config,
    invoke_sample_query,
)
from tesis.model_config import ModelConfig


def test_get_llm_gemini(monkeypatch):
    """Verifies get llm gemini behavior."""
    monkeypatch.setenv("GOOGLE_API_KEY", "test-key")
    llm = get_llm("gemini")
    assert isinstance(llm, ChatGoogleGenerativeAI)
    assert llm.model == "gemini-3-flash-preview"


def test_get_llm_openai(monkeypatch):
    """Verifies get llm openai behavior."""
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    llm = get_llm("openai")
    assert isinstance(llm, ChatOpenAI)
    assert llm.model_name == "gpt-4o-mini"
    assert llm.max_retries == 0


def test_get_llm_openai_compatible_base_url(monkeypatch):
    """Verifies get llm openai compatible base url behavior."""
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    llm = get_llm("openai", model_name="meta-llama/llama-3.1-8b-instruct", base_url="https://openrouter.ai/api/v1")
    assert isinstance(llm, ChatOpenAI)
    assert llm.model_name == "meta-llama/llama-3.1-8b-instruct"
    assert llm.openai_api_base == "https://openrouter.ai/api/v1"


def test_get_llm_openai_compatible_with_base_url(monkeypatch):
    """Verifies get llm openai compatible with base url behavior."""
    monkeypatch.setenv("OPENAI_COMPATIBLE_API_KEY", "test-key")
    llm = get_llm(
        "openai_compatible",
        model_name="llama3.2",
        base_url="http://localhost:11434/v1",
    )
    assert isinstance(llm, ChatOpenAI)
    assert llm.model_name == "llama3.2"
    assert llm.openai_api_base == "http://localhost:11434/v1"
    assert llm.max_retries == 0


def test_typed_model_config_preserves_provider_timeout():
    """Typed configuration must preserve ChatOpenAI's request timeout field."""
    llm = get_llm_from_model_config(ModelConfig(
        provider="openai_compatible",
        api_key="test-key",
        model_name="llama3.2",
        base_url="http://localhost:11434/v1",
        timeout=7,
    ))

    assert llm.request_timeout == 7
    assert llm.max_retries == 0


def test_explicit_provider_retries_are_preserved():
    """Callers can opt into retries when a provider requires them."""
    llm = get_llm(
        "openai_compatible",
        api_key="test-key",
        model_name="llama3.2",
        base_url="http://localhost:11434/v1",
        max_retries=2,
    )

    assert llm.max_retries == 2


def test_get_llm_openai_compatible_missing_base_url():
    """Verifies get llm openai compatible missing base url behavior."""
    with pytest.raises(ValueError, match="openai_compatible provider requires base_url"):
        get_llm("openai_compatible", model_name="llama3.2")


def test_get_llm_openai_compatible_base_url_from_env(monkeypatch):
    """Verifies get llm openai compatible base url from env behavior."""
    monkeypatch.setenv("OPENAI_COMPATIBLE_API_KEY", "test-key")
    monkeypatch.setenv("OPENAI_COMPATIBLE_BASE_URL", "http://localhost:8080/v1")
    llm = get_llm("openai_compatible", model_name="llama3.2")
    assert isinstance(llm, ChatOpenAI)
    assert llm.openai_api_base == "http://localhost:8080/v1"


def test_openai_compatible_in_supported_providers():
    """Verifies openai compatible in supported providers behavior."""
    assert "openai_compatible" in SUPPORTED_PROVIDERS


def test_get_llm_invalid():
    """Verifies get llm invalid behavior."""
    with pytest.raises(ValueError, match="Unsupported LLM provider: unknown"):
        get_llm("unknown")


def test_invoke_sample_query_uses_hardcoded_prompt(monkeypatch):
    """Verifies invoke sample query uses hardcoded prompt behavior."""
    class FakeResponse:
        """Groups regression tests for FakeResponse behavior."""
        def __init__(self, content):
            self.content = content

    class FakeLLM:
        """Groups regression tests for FakeLLM behavior."""
        model_name = "fake-model"

        def __init__(self):
            self.received_messages = []

        def invoke(self, messages):
            """Supports regression tests for test provider."""
            self.received_messages = messages
            return FakeResponse("I am fake-model")

    fake_llm = FakeLLM()

    def fake_get_llm(provider_name: str, **kwargs):
        """Supports regression tests for test provider."""
        assert provider_name == "gemini"
        return fake_llm

    monkeypatch.setattr(provider_module, "get_llm", fake_get_llm)

    result = invoke_sample_query("gemini")

    assert result == {
        "provider": "gemini",
        "model": "fake-model",
        "query": SAMPLE_QUERY,
        "response": "I am fake-model",
    }
    assert len(fake_llm.received_messages) == 1
    assert isinstance(fake_llm.received_messages[0], HumanMessage)
    assert fake_llm.received_messages[0].content == SAMPLE_QUERY
