"""Preserve provider reasoning fields while retaining ChatOpenAI behavior."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from langchain_openai import ChatOpenAI


class ReasoningChatOpenAI(ChatOpenAI):
    """Keep gateway reasoning separately from answer content and tool arguments.

    The upstream wrapper deliberately drops these nonstandard fields. Its sync
    and async Chat Completions paths both use the two conversion hooks below.
    LangChain merges string deltas and indexed detail blocks while accumulating
    an AIMessage, so no mutable trace buffer is shared between calls.
    """

    @staticmethod
    def _reasoning_fields(message: dict[str, Any]) -> dict[str, Any]:
        return {name: deepcopy(message[name]) for name in ("reasoning_content", "reasoning_details")
                if isinstance(message.get(name), (str, list)) and message[name]}

    def _create_chat_result(self, response: Any, generation_info: dict | None = None):
        result = super()._create_chat_result(response, generation_info)
        raw = response if isinstance(response, dict) else response.model_dump()
        for generation, choice in zip(result.generations, raw.get("choices") or []):
            message = choice.get("message") or {}
            generation.message.additional_kwargs.update(self._reasoning_fields(message))
        return result

    def _convert_chunk_to_generation_chunk(self, chunk: dict, default_chunk_class: type,
                                         base_generation_info: dict | None):
        result = super()._convert_chunk_to_generation_chunk(chunk, default_chunk_class, base_generation_info)
        choices = chunk.get("choices") or []
        if result is not None and choices:
            result.message.additional_kwargs.update(self._reasoning_fields(choices[0].get("delta") or {}))
        return result
