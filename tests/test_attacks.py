"""Attack-engine tests: every attack must confirm its bug on the demo app.

Runs the attacks against the Flask app in-process via httpx's WSGI transport,
so no live server is required.
"""

import sys
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from target_app.app import app as flask_app, init_db  # noqa: E402
from engine.attacks import (  # noqa: E402
    DEMO_PROFILE,
    attack_data_exposure,
    attack_idor,
    attack_missing_auth,
    attack_sqli,
    run_all_attacks,
)


@pytest.fixture()
def client():
    init_db()
    transport = httpx.WSGITransport(app=flask_app)
    with httpx.Client(transport=transport, base_url="http://testserver") as c:
        yield c


def test_idor_confirmed(client):
    f = attack_idor(client, DEMO_PROFILE)
    assert f.confirmed
    assert f.vuln_class == "idor"
    assert "owned by user_id=1" in f.detail
    assert f.curl.startswith("curl")


def test_sqli_confirmed(client):
    f = attack_sqli(client, DEMO_PROFILE)
    assert f.confirmed
    assert "other users" in f.detail or "database error" in f.detail


def test_data_exposure_confirmed(client):
    f = attack_data_exposure(client, DEMO_PROFILE)
    assert f.confirmed
    assert "password_hash" in f.detail


def test_missing_auth_confirmed(client):
    f = attack_missing_auth(client, DEMO_PROFILE)
    assert f.confirmed
    assert f.response["status"] == 200


def test_run_all_returns_four_confirmed_findings(client):
    findings = run_all_attacks(client)
    assert len(findings) == 4
    assert all(f.confirmed for f in findings)
    assert {f.vuln_class for f in findings} == {"idor", "sqli", "data_exposure", "missing_auth"}
