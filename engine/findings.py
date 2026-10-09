"""Structured finding model shared by the attack, fix and verify stages.

A Finding records one attempted exploit: what was sent, what came back, and
-- deterministically -- whether the vulnerability was *confirmed*. The same
object is replayed by the verifier, so it carries the full request needed to
reproduce the attack, plus a copy-pasteable curl command for the report.
"""

from __future__ import annotations

import json
import shlex
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Finding:
    vuln_class: str          # idor | sqli | data_exposure | missing_auth
    name: str                # human-readable title
    endpoint: str            # path, e.g. "/invoices/101"
    method: str              # HTTP method of the attack request
    severity: str            # high | medium | low
    confirmed: bool          # deterministically decided by the attack module
    detail: str              # why it is (or is not) confirmed
    request: dict[str, Any] = field(default_factory=dict)   # method/url/headers/params/json
    response: dict[str, Any] = field(default_factory=dict)  # status/body
    curl: str = ""           # reproduction command

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def truncate(text: str, limit: int = 600) -> str:
    text = text if isinstance(text, str) else str(text)
    return text if len(text) <= limit else text[:limit] + "...[truncated]"


def build_curl(method: str, url: str, headers: dict[str, str] | None = None,
               params: dict[str, str] | None = None, json_body: Any = None) -> str:
    """Build a curl command that reproduces an attack request.

    Query params are appended to the URL (urlencoded) so the command is a
    single faithful line the reader can paste into a terminal.
    """
    from urllib.parse import urlencode

    if params:
        sep = "&" if "?" in url else "?"
        url = url + sep + urlencode(params)
    parts = ["curl", "-s"]
    if method.upper() != "GET":
        parts += ["-X", method.upper()]
    for key, value in (headers or {}).items():
        parts += ["-H", f"{key}: {value}"]
    if json_body is not None:
        parts += ["-H", "Content-Type: application/json",
                  "-d", json.dumps(json_body)]
    parts.append(url)
    return " ".join(shlex.quote(p) for p in parts)
