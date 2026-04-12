import os
import pytest
from llm.provider import get_llm
from langchain_openai import ChatOpenAI
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_anthropic import ChatAnthropic

def test_get_llm_openai(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    llm = get_llm("gpt4o")
    assert isinstance(llm, ChatOpenAI)
    assert llm.model_name == "gpt-4o"

def test_get_llm_gemini(monkeypatch):
    monkeypatch.setenv("GOOGLE_API_KEY", "test-key")
    llm = get_llm("gemini")
    assert isinstance(llm, ChatGoogleGenerativeAI)
    assert llm.model == "gemini-1.5-pro"

def test_get_llm_claude(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    llm = get_llm("claude")
    assert isinstance(llm, ChatAnthropic)
    assert llm.model == "claude-3-5-sonnet-20241022"

def test_get_llm_llama(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("OPENAI_API_BASE", "http://localhost:11434/v1")
    llm = get_llm("llama")
    assert isinstance(llm, ChatOpenAI)
    assert llm.openai_api_base == "http://localhost:11434/v1"

def test_get_llm_invalid():
    with pytest.raises(ValueError, match="Unsupported LLM provider: unknown"):
        get_llm("unknown")
