from copy import deepcopy

import agents.orchestrator as orchestrator_module
from core.chaining_coordinator import route_after_agent
from core.graph_builder import RUNTIME_AGENT_HANDLERS, build_framework
from core.state import DEFAULT_STATE


def test_graph_builder_uses_real_stage5_handlers():
    expected = {
        "sqli_agent",
        "sqli_blind_agent",
        "xss_reflected_agent",
        "xss_stored_agent",
        "xss_dom_agent",
        "cmdi_agent",
        "brute_agent",
        "lfi_agent",
        "upload_agent",
        "csrf_agent",
        "weak_session_agent",
        "idor_agent",
        "sqli_to_creds_chain",
        "upload_to_rce_chain",
        "xss_to_csrf_chain",
        "lfi_to_rce_chain",
    }
    assert expected.issubset(set(RUNTIME_AGENT_HANDLERS.keys()))
    for handler in RUNTIME_AGENT_HANDLERS.values():
        assert callable(handler)
        assert "placeholder" not in handler.__name__


def test_route_after_agent_dispatches_chain_nodes():
    state = {
        "confirmed_vulns": ["lfi_confirmed", "log_access_confirmed"],
        "achieved_outcomes": [],
        "iteration_count": 1,
        "max_iterations": 30,
    }
    assert route_after_agent(state) == "lfi_to_rce_chain"


def test_runtime_round_trip_recon_to_orchestrator_to_agent(monkeypatch):
    def fail_get_llm(*args, **kwargs):
        raise RuntimeError("offline test")

    monkeypatch.setattr(orchestrator_module, "get_llm", fail_get_llm)

    app = build_framework(llm_provider="gemini")
    state = deepcopy(DEFAULT_STATE)
    state["max_iterations"] = 1

    result = app.invoke(state)

    assert "next_agent" in result
    assert result.get("iteration_count", 0) <= state["max_iterations"]


def test_agent_score_merge_preserves_existing_module_scores():
    from agents.tier1.cmdi_agent import cmdi_agent

    state = {
        "target_url": "",
        "security_level": "low",
        "scores": {"sqli": 2},
        "tried_payloads": {},
        "iteration_count": 0,
    }
    update = cmdi_agent(state)

    assert update["scores"]["sqli"] == 2
    assert "cmdi" in update["scores"]


def test_agent_tried_payloads_merge_preserves_other_modules():
    from agents.tier1.sqli_agent import sqli_agent

    state = {
        "target_url": "",
        "security_level": "low",
        "scores": {},
        "tried_payloads": {"cmdi": ["127.0.0.1; id"]},
        "iteration_count": 0,
    }
    update = sqli_agent(state)

    assert "cmdi" in update["tried_payloads"]
    assert update["tried_payloads"]["cmdi"] == ["127.0.0.1; id"]
