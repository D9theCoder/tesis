"""Offline regression tests for fixture census equivalence attestations.

No census subprocess runs and no provider/DVWA request is made: ``_run_census``
returns synthetic documents and ``source_identity`` is replaced by a synthetic
hash.  These tests cover only the local equivalence decision.
"""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from evaluation import fixture_epoch

_DIGESTS = {"low": "1" * 64, "medium": "2" * 64, "high": "3" * 64}


def _complete_census() -> dict[str, Any]:
    levels: dict[str, Any] = {}
    for level in fixture_epoch.LEVELS:
        levels[level] = {
            "observed_level": level,
            "index_nav_link_count": 2,
            "index_nav_paths": ["index.php", "vulnerabilities/sqli/"],
            "index_all_hrefs": ["index.php", "vulnerabilities/sqli/"],
            "nonadmin_principal": "gordonb",
            "rows": [
                {
                    "requested_path": "index.php",
                    "status": 200,
                    "module": "index",
                    "content_sha256": _DIGESTS[level],
                },
                {
                    "requested_path": "vulnerabilities/sqli/",
                    "status": 200,
                    "module": "sqli",
                    "content_sha256": _DIGESTS[level],
                },
            ],
        }
    return {"artifact": "dvwa-module-census", "levels": levels}


def _install_censuses(
    monkeypatch: pytest.MonkeyPatch,
    before: dict[str, Any],
    after: dict[str, Any],
) -> list[str]:
    calls: list[str] = []

    def fake_run_census(output: Path) -> dict[str, Any]:
        calls.append(Path(output).name)
        return deepcopy(before if Path(output).name == "census-before.json" else after)

    monkeypatch.setattr(fixture_epoch, "_run_census", fake_run_census)
    monkeypatch.setattr(
        fixture_epoch,
        "source_identity",
        lambda **_kwargs: {"source_hashes_sha256": "f" * 64},
    )
    return calls


def _build(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    before: dict[str, Any],
    after: dict[str, Any],
) -> dict[str, Any]:
    _install_censuses(monkeypatch, before, after)
    return fixture_epoch.build_attestations(
        epoch_id="offline-epoch",
        repo_root=tmp_path,
        output_dir=tmp_path / "evidence",
        config_path=tmp_path / "config.yaml",
    )


def _no_mutation(tmp_path: Path) -> dict[str, Any]:
    return json.loads(
        (tmp_path / "evidence" / "no-mutation-check.json").read_text(encoding="utf-8")
    )


def _assert_no_attestations(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    for level in fixture_epoch.LEVELS:
        assert not (evidence / f"fixture-restoration-{level}.json").exists()
    assert not (evidence / "fixture-restoration-evidence.json").exists()


def test_complete_stable_census_emits_isolated_equivalent(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    result = _build(monkeypatch, tmp_path, _complete_census(), _complete_census())

    assert result["identical"] is True
    check = _no_mutation(tmp_path)
    assert check["identical"] is True
    assert check["coverage_ok"] is True
    assert check["coverage_issues"] == {"before": [], "after": []}
    assert all(count == 2 for count in check["successful_response_rows"].values())
    for level in fixture_epoch.LEVELS:
        document = json.loads(
            (tmp_path / "evidence" / f"fixture-restoration-{level}.json").read_text(
                encoding="utf-8"
            )
        )
        assert document["restoration"] == "isolated_equivalent"
        assert document["security_level"] == level
    envelope = json.loads(
        (tmp_path / "evidence" / "fixture-restoration-evidence.json").read_text(
            encoding="utf-8"
        )
    )
    assert envelope["levels"] == list(fixture_epoch.LEVELS)


def test_equally_empty_censuses_refuse_equivalence(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    empty = _complete_census()
    for level in fixture_epoch.LEVELS:
        empty["levels"][level]["rows"] = []

    with pytest.raises(RuntimeError, match="coverage is incomplete"):
        _build(monkeypatch, tmp_path, empty, deepcopy(empty))

    check = _no_mutation(tmp_path)
    assert check["identical"] is False
    assert check["coverage_ok"] is False
    for census_side in ("before", "after"):
        reasons = {issue["reason"] for issue in check["coverage_issues"][census_side]}
        assert "empty_census" in reasons
    _assert_no_attestations(tmp_path)


def test_missing_level_cannot_establish_equivalence(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    partial = _complete_census()
    del partial["levels"]["high"]

    with pytest.raises(RuntimeError, match="coverage is incomplete"):
        _build(monkeypatch, tmp_path, partial, deepcopy(partial))

    check = _no_mutation(tmp_path)
    assert check["identical"] is False
    for census_side in ("before", "after"):
        issues = check["coverage_issues"][census_side]
        assert {"level": "high", "reason": "level_missing"} in issues
    _assert_no_attestations(tmp_path)


def test_failed_rows_cannot_establish_equivalence(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    failed = _complete_census()
    for level in fixture_epoch.LEVELS:
        failed["levels"][level]["rows"].append(
            {
                "requested_path": "vulnerabilities/exec/",
                "status": None,
                "module": "exec",
                "error": "ConnectTimeout: probe failed",
            }
        )

    with pytest.raises(RuntimeError, match="coverage is incomplete"):
        _build(monkeypatch, tmp_path, failed, deepcopy(failed))

    check = _no_mutation(tmp_path)
    assert check["identical"] is False
    for census_side in ("before", "after"):
        issues = [
            issue for issue in check["coverage_issues"][census_side]
            if issue["reason"] == "observation_unavailable"
        ]
        assert {issue["level"] for issue in issues} == set(fixture_epoch.LEVELS)
        assert all("ConnectTimeout" in issue["detail"] for issue in issues)
    _assert_no_attestations(tmp_path)


def test_row_error_with_digest_cannot_establish_equivalence(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    failed = _complete_census()
    for level in fixture_epoch.LEVELS:
        failed["levels"][level]["rows"].append(
            {
                "requested_path": "vulnerabilities/exec/",
                "status": 200,
                "module": "exec",
                "content_sha256": "d" * 64,
                "error": "parser failed after response",
            }
        )

    with pytest.raises(RuntimeError, match="coverage is incomplete"):
        _build(monkeypatch, tmp_path, failed, deepcopy(failed))

    check = _no_mutation(tmp_path)
    assert check["identical"] is False
    for census_side in ("before", "after"):
        issues = [
            issue for issue in check["coverage_issues"][census_side]
            if issue["reason"] == "observation_unavailable"
        ]
        assert len(issues) == len(fixture_epoch.LEVELS)
        assert all("row_error: parser failed" in issue["detail"] for issue in issues)
    _assert_no_attestations(tmp_path)


def test_missing_http_status_with_digest_cannot_establish_equivalence(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    partial = _complete_census()
    for level in fixture_epoch.LEVELS:
        partial["levels"][level]["rows"][0]["status"] = None

    with pytest.raises(RuntimeError, match="coverage is incomplete"):
        _build(monkeypatch, tmp_path, partial, deepcopy(partial))

    check = _no_mutation(tmp_path)
    assert check["identical"] is False
    for census_side in ("before", "after"):
        issues = [
            issue for issue in check["coverage_issues"][census_side]
            if issue["reason"] == "observation_unavailable"
        ]
        assert len(issues) == len(fixture_epoch.LEVELS)
        assert all("http_status_unavailable" in issue["detail"] for issue in issues)
    _assert_no_attestations(tmp_path)


def test_valid_non_2xx_observations_can_establish_equivalence(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    observed = _complete_census()
    for level in fixture_epoch.LEVELS:
        rows = observed["levels"][level]["rows"]
        rows[0]["status"] = 404
        rows[1]["status"] = 403

    result = _build(monkeypatch, tmp_path, observed, deepcopy(observed))

    assert result["identical"] is True
    check = _no_mutation(tmp_path)
    assert check["coverage_ok"] is True
    assert check["coverage_issues"] == {"before": [], "after": []}
    for level in fixture_epoch.LEVELS:
        document = json.loads(
            (tmp_path / "evidence" / f"fixture-restoration-{level}.json").read_text(
                encoding="utf-8"
            )
        )
        assert document["restoration"] == "isolated_equivalent"


def test_duplicate_rows_cannot_establish_equivalence(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    ambiguous = _complete_census()
    for level in fixture_epoch.LEVELS:
        rows = ambiguous["levels"][level]["rows"]
        rows.append(deepcopy(rows[0]))

    with pytest.raises(RuntimeError, match="coverage is incomplete"):
        _build(monkeypatch, tmp_path, ambiguous, deepcopy(ambiguous))

    check = _no_mutation(tmp_path)
    assert check["identical"] is False
    for census_side in ("before", "after"):
        reasons = {issue["reason"] for issue in check["coverage_issues"][census_side]}
        assert "duplicate_row" in reasons
    _assert_no_attestations(tmp_path)


def test_changed_complete_census_refuses_equivalence(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    after = _complete_census()
    after["levels"]["medium"]["rows"][0]["content_sha256"] = "e" * 64

    with pytest.raises(RuntimeError, match="responses changed"):
        _build(monkeypatch, tmp_path, _complete_census(), after)

    check = _no_mutation(tmp_path)
    assert check["identical"] is False
    assert check["coverage_ok"] is True
    assert check["differences"]["medium"]["changed"] == ["index.php"]
    _assert_no_attestations(tmp_path)


def test_observed_preserves_failed_rows() -> None:
    census = _complete_census()
    census["levels"]["low"]["rows"] = [
        {
            "requested_path": "vulnerabilities/exec/",
            "status": None,
            "module": "exec",
            "error": "ConnectTimeout: probe failed",
        }
    ]

    observed = fixture_epoch._observed(census)

    assert len(observed["low"]) == 1
    assert observed["low"][0]["path"] == "vulnerabilities/exec/"
    assert observed["low"][0]["available"] is False
    assert "ConnectTimeout" in observed["low"][0]["unavailable_reason"]
    assert len(observed["high"]) == 2


def test_observed_marks_errors_and_missing_status_unavailable_with_digest() -> None:
    census = _complete_census()
    census["levels"]["low"]["rows"] = [
        {
            "requested_path": "index.php",
            "status": 200,
            "module": "index",
            "content_sha256": "a" * 64,
            "error": "parser failed after response",
        },
        {
            "requested_path": "vulnerabilities/sqli/",
            "status": None,
            "module": "sqli",
            "content_sha256": "b" * 64,
        },
        {
            "requested_path": "vulnerabilities/brute/",
            "status": "unavailable",
            "module": "brute",
            "content_sha256": "c" * 64,
        },
    ]

    observed = fixture_epoch._observed(census)["low"]

    assert [row["available"] for row in observed] == [False, False, False]
    assert observed[0]["content_sha256"] == "a" * 64
    assert "row_error: parser failed after response" in observed[0]["unavailable_reason"]
    assert observed[1]["content_sha256"] == "b" * 64
    assert "http_status_unavailable: None" in observed[1]["unavailable_reason"]
    assert observed[2]["content_sha256"] == "c" * 64
    assert "http_status_unavailable: 'unavailable'" in observed[2]["unavailable_reason"]
