"""P0 opt-in checkpoint regression (handoff 2026-09-20).

Default single/matrix runs must not create SQLite checkpoint databases and
must forward checkpoint flags unchanged; explicit runs must. ``--resume``
without metadata must fail closed before the graph runs, and the default
path must work without the sqlite-saver package installed.
"""


def test_resume_without_metadata_fails_closed_pre_execution(tmp_path, monkeypatch):
    from evaluation.runner import run_single_engagement

    class MustNotRun:
        def stream(self, *a, **k):
            raise AssertionError("graph must not run on failed resume")

        def invoke(self, *a, **k):
            raise AssertionError("graph must not run on failed resume")

    monkeypatch.setattr("evaluation.runner.build_framework", lambda **_kw: MustNotRun())
    missing = run_single_engagement(
        target_url="http://localhost/dvwa",
        security_level="low",
        llm_provider="openai_compatible",
        target_method="sqli_union",
        output_dir=str(tmp_path),
        checkpoint_dir=str(tmp_path / "empty"),
        experiment_id="nope",
        resume=True,
    )
    assert missing["status"] == "error"
    assert missing["resumed_from_checkpoint"] is False
    assert missing["resumed"] is False
    assert "refus" in missing["error"]

def test_corrupt_metadata_db_fails_closed_pre_execution(tmp_path, monkeypatch):
    from evaluation.runner import run_single_engagement

    ckpt_dir = tmp_path / "ckpt"
    ckpt_dir.mkdir()
    (ckpt_dir / "checkpoints.sqlite3").write_bytes(b"not a sqlite db\x00\x01\x02")

    class MustNotRun:
        def stream(self, *a, **k):
            raise AssertionError("graph must not run on corrupt metadata")

        def invoke(self, *a, **k):
            raise AssertionError("graph must not run on corrupt metadata")

    monkeypatch.setattr("evaluation.runner.build_framework", lambda **_kw: MustNotRun())
    bad = run_single_engagement(
        target_url="http://localhost/dvwa",
        security_level="low",
        llm_provider="openai_compatible",
        target_method="sqli_union",
        output_dir=str(tmp_path),
        checkpoint_dir=str(ckpt_dir),
        experiment_id="corrupt-exp",
        resume=True,
    )
    assert bad["status"] == "error"
    assert bad["resumed_from_checkpoint"] is False
    assert bad["resumed"] is False
    assert "refus" in bad["error"]
