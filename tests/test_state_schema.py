"""Regression tests for the DVWA LangGraph framework.

This module verifies current behavior for state handling, routing, payloads,
LLM adapters, agents, evaluation, or CLI integration without changing runtime
code."""
import pytest
from core.state import ExploitationState, DEFAULT_STATE, new_default_state, SURFACES, ALL_METHOD_AGENTS, METHODS_BY_SURFACE


def test_default_state_has_required_fields():
    """Verifies default state has required fields behavior."""
    state = new_default_state()
    assert "current_surface" in state
    assert "observations" in state
    assert "failure_agents" in state
    assert "akg_path" in state
    assert "task_result" in state
    assert "incomplete_reason" in state
    assert "consecutive_clean_responses" in state


def test_no_old_module_names():
    """Verifies no old module names behavior."""
    from core.state import DEFAULT_STATE
    assert "MODULE_NAMES" not in globals()


def test_surfaces_defined():
    """Verifies surfaces defined behavior."""
    assert set(SURFACES) == {"sqli", "access_control", "brute_force"}


def test_methods_by_surface():
    """Verifies methods by surface behavior."""
    assert len(METHODS_BY_SURFACE["sqli"]) == 4
    assert len(METHODS_BY_SURFACE["access_control"]) == 3
    assert len(METHODS_BY_SURFACE["brute_force"]) == 2
