"""Offline controls for maintained census plumbing; no real HTTP/provider calls."""
from contextlib import contextmanager
import json
from types import SimpleNamespace

from evaluation import fixture_census, fixture_epoch


def test_census_uses_resolved_credentials_and_exports_no_secret_values(tmp_path, monkeypatch):
    password = "unit-census-password-never-export"
    monkeypatch.setenv("UNIT_CENSUS_PASSWORD", password)
    monkeypatch.setenv("TESIS_DVWA_PASSWORD", password)
    monkeypatch.setenv("TESIS_DVWA_USERNAME", "unit_admin")
    monkeypatch.setenv("TESIS_TARGET_URL", "http://fixture.invalid/dvwa")
    config = tmp_path / "config.yaml"
    config.write_text('target_url: http://fixture.invalid/dvwa\ndvwa_username: unit_admin\ndvwa_password: ${UNIT_CENSUS_PASSWORD}\n')
    captured = []

    @contextmanager
    def credentials(username, secret):
        captured.append((username, secret))
        yield

    class Session:
        def __init__(self, principal, level):
            self.principal, self.level, self.http = principal, level, self
            self.closed = False

        def get(self, path):
            if path == "security.php":
                text = f'<select name="security"><option selected value="{self.level}">level</option></select>'
            elif path == "index.php":
                text = ''.join(f'<a href="{p}">module</a>' for p in fixture_census.MODULE_PATHS)
            else:
                assert path in fixture_census.MODULE_PATHS
                text = f'<p>{self.principal}</p><form><input name="user_token" value="unit-csrf-never-export"><input name="password" value="{password}"></form>'
            return SimpleNamespace(text=text, status_code=200, url="http://fixture.invalid/dvwa/" + path.lstrip('/'))

        def close(self):
            self.closed = True

    sessions = []

    def opened(principal):
        def make(base, level):
            assert base == "http://fixture.invalid/dvwa"
            session = Session(principal, level)
            sessions.append(session)
            return session, principal, "unit-initial-session"
        return make

    monkeypatch.setattr(fixture_census, "dvwa_credentials", credentials)
    monkeypatch.setattr(fixture_census, "open_configured_principal_session", opened("unit_admin"))
    monkeypatch.setattr(fixture_census, "open_documented_nonadmin_session", opened("unit_reader"))
    report = fixture_census.collect_census(config)
    assert captured == [("unit_admin", password)]
    assert all(session.closed for session in sessions)
    assert all(report["levels"][level]["observed_level"] == level for level in fixture_census.LEVELS)
    assert all(len(report["levels"][level]["rows"]) == 4 for level in fixture_census.LEVELS)
    assert password not in json.dumps(report)
    assert "unit-csrf-never-export" not in json.dumps(report)
    assert report["executed_exploit_candidates"] == 0
    assert report["thesis_scores"] is None


def test_epoch_collector_invokes_maintained_module_with_the_explicit_config(tmp_path, monkeypatch):
    output, config = tmp_path / "census.json", tmp_path / "chosen-config.yaml"
    seen = []

    def run(arguments, **kwargs):
        seen.append(arguments)
        output.write_text('{"validation_scope": "offline_subprocess_stub"}')
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(fixture_epoch.subprocess, "run", run)
    result = fixture_epoch._run_census(output, config)
    assert seen == [[fixture_epoch.sys.executable, "-m", "evaluation.fixture_census",
                     str(output.resolve()), "--config", str(config.resolve())]]
    assert result["validation_scope"] == "offline_subprocess_stub"
