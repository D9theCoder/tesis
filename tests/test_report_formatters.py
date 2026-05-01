from tesis.report_formatters import (
    format_module_scores_table,
    format_provider_comparison_table,
    format_rejection_table,
)


def _single_artifact() -> dict:
    return {
        "run_id": "gemini-low-0",
        "status": "success",
        "config": {"provider": "gemini", "security_level": "low"},
        "final_state": {
            "iteration_count": 10,
            "guardrail_activations": [
                {"provider": "gemini", "context": "orchestrator", "snippet": "..."},
                {"provider": "gemini", "context": "payload_generation", "snippet": "..."},
            ],
        },
        "report": {
            "module_scores": {
                "sqli": {"score": 4, "label": "Chain Exploit", "chain": "sqli→creds→admin→upload→rce"},
                "xss_r": {"score": 3, "label": "Full Exploit", "chain": None},
            },
            "summary": {
                "score_distribution": {0: 0, 1: 0, 2: 0, 3: 1, 4: 1},
                "highest_impact_outcome": "admin_session_obtained",
                "longest_chain": "sqli→creds→admin→upload→rce",
                "total_iterations_used": 10,
                "guardrail_activations": 2,
            },
        },
    }


def test_show_rejections_no_guardrail_data_message():
    artifact = _single_artifact()
    artifact["final_state"]["guardrail_activations"] = []
    artifact["report"]["summary"]["guardrail_activations"] = 0

    rendered = format_rejection_table(artifact)
    assert "No guardrail data available" in rendered


def test_rejection_rate_aggregation_by_provider_and_context():
    runs = {"runs": [_single_artifact(), _single_artifact()]}
    rendered = format_rejection_table(runs)

    assert "Provider" in rendered
    assert "orchestrator" in rendered
    assert "payload_generation" in rendered
    assert "total" in rendered


def test_score_table_renders_module_label_and_chain():
    rendered = format_module_scores_table(_single_artifact(), show_chains=True)

    assert "Module" in rendered
    assert "sqli" in rendered
    assert "Chain Exploit" in rendered
    assert "sqli→creds→admin→upload→rce" in rendered


def test_score_table_distribution_summary():
    rendered = format_module_scores_table(_single_artifact(), show_chains=False)

    assert "Score Distribution" in rendered
    assert "Highest Outcome" in rendered
    assert "Longest Chain" in rendered


def test_matrix_cross_provider_table_layout():
    first = _single_artifact()
    second = _single_artifact()
    second["config"]["provider"] = "claude"
    second["report"]["module_scores"]["sqli"]["score"] = 3
    second["report"]["module_scores"]["sqli"]["label"] = "Full Exploit"

    rendered = format_provider_comparison_table({"runs": [first, second]})

    assert "Module" in rendered
    assert "gemini" in rendered
    assert "claude" in rendered
    assert "sqli" in rendered
