"""Good-path checks: the legitimate behaviour every endpoint must keep.

These mirror tests/test_good_path.py but as pure functions of (client, profile)
so the verifier can run them against a *patched* app in-process. A fix that
blocks the attack but also breaks one of these (e.g. Alice can no longer read
her own invoice, or the route was deleted) must NOT count as verified.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import httpx


@dataclass
class CheckResult:
    name: str
    passed: bool
    detail: str


@dataclass
class GoodPathReport:
    results: list[CheckResult] = field(default_factory=list)

    @property
    def all_passed(self) -> bool:
        return all(r.passed for r in self.results)

    @property
    def failures(self) -> list[CheckResult]:
        return [r for r in self.results if not r.passed]


def _login(client: httpx.Client, profile: dict, who: str):
    creds = profile["users"][who]
    return client.post("/login", json=creds)


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def run_checks(client: httpx.Client, profile: dict) -> GoodPathReport:
    """Run all good-path checks and return a structured report."""
    report = GoodPathReport()

    def check(name: str, cond: bool, detail: str = ""):
        report.results.append(CheckResult(name, bool(cond), detail))

    # 1. Valid login issues a token.
    r = _login(client, profile, "alice")
    token = r.json().get("token") if r.status_code == 200 else None
    check("alice_login_succeeds", r.status_code == 200 and bool(token),
          f"status={r.status_code}")

    # 2. Bad password is rejected.
    bad = client.post("/login", json={"username": "alice", "password": "wrong"})
    check("bad_password_rejected", bad.status_code == 401, f"status={bad.status_code}")

    if not token:
        # Without a token the authed checks can't run; report them as failed.
        for n in ("alice_reads_own_invoice", "invoice_requires_auth",
                  "alice_searches_own_invoices", "me_returns_identity",
                  "admin_lists_users"):
            check(n, False, "no alice token")
        return report

    h = _auth(token)

    # 3. Alice can read her OWN invoice (the fix must not block this).
    inv = client.get("/invoices/101", headers=h)
    body = _safe_json(inv)
    check("alice_reads_own_invoice",
          inv.status_code == 200 and isinstance(body, dict)
          and body.get("owner_id") == 1 and body.get("amount") == 42.0,
          f"status={inv.status_code} body={body}")

    # 4. Reading an invoice still requires authentication.
    noauth = client.get("/invoices/101")
    check("invoice_requires_auth", noauth.status_code == 401, f"status={noauth.status_code}")

    # 5. Alice can search her own invoices.
    search = client.get("/invoices/search", params={"q": "coffee"}, headers=h)
    rows = _safe_json(search)
    check("alice_searches_own_invoices",
          search.status_code == 200 and isinstance(rows, list) and len(rows) == 1
          and rows[0].get("id") == 101,
          f"status={search.status_code} rows={rows}")

    # 6. /me still returns the caller's identity.
    me = client.get("/me", headers=h)
    me_body = _safe_json(me)
    check("me_returns_identity",
          me.status_code == 200 and isinstance(me_body, dict)
          and me_body.get("username") == "alice",
          f"status={me.status_code}")

    # 7. An admin can still list users.
    admin_login = _login(client, profile, "admin")
    admin_token = admin_login.json().get("token") if admin_login.status_code == 200 else None
    if admin_token:
        au = client.get("/admin/users", headers=_auth(admin_token))
        au_body = _safe_json(au)
        check("admin_lists_users",
              au.status_code == 200 and isinstance(au_body, list) and len(au_body) == 3,
              f"status={au.status_code}")
    else:
        check("admin_lists_users", False, "no admin token")

    return report


def _safe_json(resp: httpx.Response) -> Any:
    try:
        return resp.json()
    except Exception:
        return None
