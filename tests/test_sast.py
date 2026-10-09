"""Offline tests for the Semgrep layer.

These do NOT require Semgrep to be installed: they exercise the JSON parsing,
the file:line -> endpoint glue (against the real target app), the vuln-class
mapping, and the static-vs-dynamic cross-check, using a fabricated Semgrep JSON.
The live scan path is covered separately when a runner is available.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from engine import sast  # noqa: E402
from engine.findings import Finding  # noqa: E402

APP = Path(__file__).resolve().parents[1] / "target_app" / "app.py"


def _finding(vuln_class, endpoint, confirmed=True):
    return Finding(vuln_class=vuln_class, name=vuln_class, endpoint=endpoint,
                   method="GET", severity="high", confirmed=confirmed, detail="")


def test_map_vuln_class():
    assert sast.map_vuln_class("python.lang.security.audit.formatted-sql-query", "") == "sqli"
    assert sast.map_vuln_class("rule", "hardcoded password detected") == "data_exposure"
    assert sast.map_vuln_class("x.missing.login_required", "") == "missing_auth"
    # Generic rules don't describe IDOR -> no class (this is the point of the demo).
    assert sast.map_vuln_class("python.lang.correctness.foo", "unused variable") is None


def test_parse_results_maps_line_to_endpoint_and_class():
    src = APP.read_text(encoding="utf-8")
    # Find the real line of the SQLi sink in the demo app.
    sqli_line = next(i + 1 for i, ln in enumerate(src.splitlines())
                     if "owner_id = %d" in ln)
    data = {"results": [{
        "check_id": "python.lang.security.audit.formatted-sql-query",
        "path": str(APP),
        "start": {"line": sqli_line}, "end": {"line": sqli_line},
        "extra": {"severity": "ERROR", "message": "Detected SQL string formatting",
                  "metadata": {"cwe": ["CWE-89: SQL Injection"],
                               "owasp": ["A03:2021 - Injection"]}},
    }]}
    findings = sast.parse_results(data)
    assert len(findings) == 1
    f = findings[0]
    assert f.vuln_class == "sqli"
    assert f.endpoint == "/invoices/search"       # mapped via AST from the line
    assert f.cwe == ["CWE-89: SQL Injection"]
    assert f.severity == "ERROR"


def test_cross_check_three_buckets():
    static = [
        sast.StaticFinding("sql-rule", str(APP), 1, 1, "ERROR", "sql", vuln_class="sqli",
                           endpoint="/invoices/search"),
        sast.StaticFinding("secret-rule", str(APP), 1, 1, "WARNING", "secret",
                           vuln_class="data_exposure", endpoint="/me"),
    ]
    dynamic = [
        _finding("sqli", "/invoices/search", confirmed=True),
        _finding("idor", "/invoices/101", confirmed=True),
        _finding("data_exposure", "/me", confirmed=False),   # not confirmed by attack
    ]
    cc = sast.cross_check(static, dynamic)
    both = {r.vuln_class for r in cc.both}
    static_only = {r.vuln_class for r in cc.static_only}
    dynamic_only = {r.vuln_class for r in cc.dynamic_only}
    assert both == {"sqli"}                 # flagged AND confirmed -> real bug
    assert static_only == {"data_exposure"} # flagged, attack failed -> likely FP
    assert dynamic_only == {"idor"}         # confirmed, Semgrep silent -> SAST missed


def test_run_semgrep_raises_when_runner_missing():
    bogus = sast.Runner("local", ["__no_such_semgrep_binary__"])
    with pytest.raises(sast.SastUnavailable):
        sast.run_semgrep(str(APP), runner=bogus)


def test_detect_runner_does_not_crash():
    # Returns a Runner or None depending on the machine; must not raise.
    r = sast.detect_runner(str(APP.parent))
    assert r is None or isinstance(r, sast.Runner)
