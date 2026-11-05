"""Bounded, read-only census of the configured thesis DVWA surfaces.

This is operator fixture evidence, never an exploit run or score. It replaces a
removed validation-directory script. Authentication and level setup are normal
DVWA session operations; only the four declared module pages are inventoried.
Bodies, cookies, CSRF values and fixture credentials are never exported.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
from urllib.parse import urlsplit

from bs4 import BeautifulSoup
from tesis.config_loader import load_runtime_inputs

from evaluation.reporter import write_json_report
from foundation.http_client import request_scope, http_request_accounting, snapshot_http_request_counters
from foundation.session_manager import (
    dvwa_credentials, open_configured_principal_session,
    open_documented_nonadmin_session, parse_security_level_page,
)

LEVELS = ("low", "medium", "high")
MODULE_PATHS = (
    "/vulnerabilities/sqli/", "/vulnerabilities/sqli_blind/",
    "/vulnerabilities/brute/", "/vulnerabilities/authbypass/",
)
POLICY_MARKER = "This page should only be accessible by the admin user"
ROOT = Path(__file__).resolve().parents[1]


def page_observation(response, path: str) -> dict:
    """Retain actual response identity and secret-free structural observations."""
    text = response.text
    soup = BeautifulSoup(text, "html.parser")
    forms = soup.find_all("form")
    names = sorted({str(node.get("name")) for node in soup.select("input[name]")})
    policy = POLICY_MARKER.lower() in soup.get_text(" ", strip=True).lower()
    kind = ("admin_user_manager" if policy else "credential_form" if "password" in names
            else "object_form" if "id" in names else "module_page")
    return {
        "requested_path": path, "status": response.status_code,
        "final_path": urlsplit(response.url).path,
        "content_sha256": sha256(text.encode()).hexdigest(),
        "content_length": len(text.encode()), "form_count": len(forms),
        "form_actions": [str(form.get("action") or "") for form in forms],
        "form_methods": [str(form.get("method") or "get").lower() for form in forms],
        "form_inputs": names, "handler_kind": kind,
        "user_token_inputs": len(soup.select("input[name='user_token']")),
        "policy_text_present": policy,
    }


def collect_census(config_path: str | Path = "config.yaml") -> dict:
    """Observe all requested cells once, retaining every unavailable outcome."""
    config_path = Path(config_path).resolve()
    config = load_runtime_inputs(config_path=str(config_path), cli_args={})
    base = str(config["target_url"])
    parsed = urlsplit(base)
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("DVWA target must be a root URL without embedded secrets/query")
    bindings = [Path(__file__), ROOT / "foundation/session_manager.py",
                ROOT / "foundation/http_client.py", ROOT / "tesis/config_loader.py", config_path]
    original = {str(path): sha256(path.read_bytes()).hexdigest() for path in bindings}
    levels = {"nonadmin_session_errors": {}}
    with http_request_accounting() as counter, request_scope(phase="verification", role="independent_control"), dvwa_credentials(
        str(config.get("dvwa_username") or "admin"), str(config.get("dvwa_password") or "password")
    ):
        for level in LEVELS:
            document = {"requested_level": level, "observed_level": None,
                        "nonadmin_principal": None, "index_nav_paths": [], "rows": []}
            levels[level] = document
            admin = alternate = None
            try:
                admin, principal, _ = open_configured_principal_session(base, level)
                document["admin_principal"] = principal
                document["observed_level"] = parse_security_level_page(admin.http.get("security.php").text)
                # Closed scope: do not follow arbitrary navigation or inspect
                # out-of-scope DVWA attack modules.
                index = admin.http.get("index.php")
                links = [urlsplit(str(a.get("href") or "")).path
                         for a in BeautifulSoup(index.text, "html.parser").select("a[href]")]
                document["index_nav_paths"] = [path for path in MODULE_PATHS
                    if any(link.rstrip("/").endswith(path.rstrip("/")) for link in links)]
                try:
                    alternate, identity, _ = open_documented_nonadmin_session(base, level)
                    document["nonadmin_principal"] = identity
                    document["nonadmin_observed_level"] = parse_security_level_page(alternate.http.get("security.php").text)
                except Exception as exc:
                    levels["nonadmin_session_errors"][level] = f"{type(exc).__name__}: {exc}"
                for path in MODULE_PATHS:
                    row = {"requested_path": path}
                    document["rows"].append(row)
                    try:
                        row.update(page_observation(admin.http.get(path), path))
                        if alternate is not None:
                            view = page_observation(alternate.http.get(path), path)
                            view["principal"] = document["nonadmin_principal"]
                            view["differs_from_admin"] = view["content_sha256"] != row["content_sha256"]
                            row["nonadmin_view"] = view
                    except Exception as exc:
                        row["error"] = f"{type(exc).__name__}: {exc}"
            except Exception as exc:
                document["error"] = f"{type(exc).__name__}: {exc}"
            finally:
                if alternate is not None:
                    alternate.close()
                if admin is not None:
                    admin.close()
        accounting = snapshot_http_request_counters(counter)
    if any(sha256(Path(path).read_bytes()).hexdigest() != digest for path, digest in original.items()):
        raise RuntimeError("Census source/config changed during collection; do not use these observations")
    return {
        "schema_version": "fixture-census", "validation_scope": "live_configured_dvwa_readonly_census",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target_url": base, "declared_module_paths": list(MODULE_PATHS),
        "source_bindings": original, "levels": levels,
        "http_request_counters": accounting, "fresh_provider_calls": 0,
        "executed_exploit_candidates": 0, "thesis_scores": None,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--config", default="config.yaml", type=Path)
    args = parser.parse_args(argv)
    output = args.output.resolve()
    if not output.is_relative_to(ROOT / "results") or output.exists():
        raise ValueError("Census output must be a new file under results/")
    report = collect_census(args.config)
    write_json_report(output, report)
    print(json.dumps({"output": str(output), "levels": {level: {
        "observed": report["levels"][level]["observed_level"],
        "rows": len(report["levels"][level]["rows"]),
        "error": report["levels"][level].get("error"),
    } for level in LEVELS}, "physical_requests": report["http_request_counters"]["total_requests"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
