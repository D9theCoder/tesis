"""Offline request serialization for the independently frozen evaluator."""


import pytest

from evaluation.thesis_scoring import evaluate_queue


def test_evaluator_cannot_silently_change_a_historical_frozen_configuration():
    evaluator = {"provider": "openai", "model": "test", "max_attempts": 1,
                 "max_tokens": 1024, "timeout": 20, "reasoning_effort": "high"}
    historical = {key: value for key, value in evaluator.items() if key != "reasoning_effort"}
    queue = {"selection": "ai", "source_sha256": "0" * 64,
             "evaluator": historical, "candidates": []}
    with pytest.raises(ValueError, match="frozen experiment configuration"):
        evaluate_queue(queue, evaluator)
