import pytest
import llm.provider as provider_module
from langchain_core.messages import HumanMessage
from langchain_google_genai import ChatGoogleGenerativeAI
from llm.provider import SAMPLE_QUERY, get_llm, invoke_sample_query


def test_get_llm_gemini(monkeypatch):
    monkeypatch.setenv("GOOGLE_API_KEY", "test-key")
    llm = get_llm("gemini")
    assert isinstance(llm, ChatGoogleGenerativeAI)
    assert llm.model == "gemini-3-flash-preview"


def test_get_llm_invalid():
    with pytest.raises(ValueError, match="Unsupported LLM provider: unknown"):
        get_llm("unknown")


def test_invoke_sample_query_uses_hardcoded_prompt(monkeypatch):
    class FakeResponse:
        def __init__(self, content):
            self.content = content

    class FakeLLM:
        model_name = "fake-model"

        def __init__(self):
            self.received_messages = []

        def invoke(self, messages):
            self.received_messages = messages
            return FakeResponse("I am fake-model")

    fake_llm = FakeLLM()

    def fake_get_llm(provider_name: str, **kwargs):
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
