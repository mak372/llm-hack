"""Good-path tests: the legitimate behaviour each endpoint must keep.

These run against a fresh seeded database via the Flask test client. They are
the baseline the verifier reuses so a proposed fix cannot "pass" by breaking
or deleting a route -- e.g. Alice must still be able to read her own invoice.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from target_app.app import app as flask_app, init_db  # noqa: E402


@pytest.fixture()
def client():
    init_db()
    flask_app.config.update(TESTING=True)
    with flask_app.test_client() as c:
        yield c


def _login(client, username, password):
    resp = client.post("/login", json={"username": username, "password": password})
    assert resp.status_code == 200, resp.get_data(as_text=True)
    return resp.get_json()["token"]


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def test_login_succeeds_with_valid_credentials(client):
    token = _login(client, "alice", "alice-pw")
    assert token == "alice-token"


def test_login_rejects_bad_password(client):
    resp = client.post("/login", json={"username": "alice", "password": "wrong"})
    assert resp.status_code == 401


def test_alice_can_read_her_own_invoice(client):
    token = _login(client, "alice", "alice-pw")
    resp = client.get("/invoices/101", headers=_auth(token))
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["id"] == 101
    assert body["owner_id"] == 1
    assert body["amount"] == 42.00


def test_invoice_requires_authentication(client):
    resp = client.get("/invoices/101")
    assert resp.status_code == 401


def test_alice_can_search_her_own_invoices(client):
    token = _login(client, "alice", "alice-pw")
    resp = client.get("/invoices/search?q=coffee", headers=_auth(token))
    assert resp.status_code == 200
    rows = resp.get_json()
    assert len(rows) == 1
    assert rows[0]["id"] == 101


def test_me_returns_identity_for_authenticated_user(client):
    token = _login(client, "alice", "alice-pw")
    resp = client.get("/me", headers=_auth(token))
    assert resp.status_code == 200
    assert resp.get_json()["username"] == "alice"


def test_admin_can_list_users(client):
    token = _login(client, "admin", "admin-pw")
    resp = client.get("/admin/users", headers=_auth(token))
    assert resp.status_code == 200
    assert len(resp.get_json()) == 3
