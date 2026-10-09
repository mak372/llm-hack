"""Patch proposers.

A proposer takes narrow context about ONE vulnerable handler and returns a
replacement for that handler only. The LLM is just one implementation -- it only
*proposes*; nothing here decides whether a fix worked (that is the verifier).

- LLMProposer: asks Claude for a minimal handler rewrite, given the failing
  attack and a per-class fix template, with strict output rules.
- TemplateProposer: returns a known-good handler per class. Used for offline
  tests and as a deterministic fallback so the loop is demonstrable without an
  API key.

Fix templates (one per class) follow the project's remediation rules:
  IDOR          -> add an ownership/authorization check
  SQLi          -> use a parameterized query
  data_exposure -> return an explicit allowlist of fields
  missing_auth  -> require authentication (and admin where relevant)
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from engine.codemod import strip_code_fences
from engine.findings import Finding

# vuln_class -> the handler function name in target_app/app.py
HANDLER_BY_CLASS = {
    "idor": "get_invoice",
    "sqli": "search_invoices",
    "data_exposure": "me",
    "missing_auth": "admin_users",
}

FIX_TEMPLATES = {
    "idor": ("Add an ownership check: after loading the resource, return 403 if it "
             "does not belong to the authenticated user (allow admins). The owner "
             "must still receive 200."),
    "sqli": ("Replace the string-built SQL with a parameterized query using '?' "
             "placeholders and a parameter tuple. Preserve the behaviour that a "
             "user only searches their own rows."),
    "data_exposure": ("Return only an explicit allowlist of safe fields "
                      "(id, username, is_admin). Never return password_hash, token, "
                      "reset_token or ssn."),
    "missing_auth": ("Require authentication: reject callers with no/invalid token "
                     "(401), and require admin for this endpoint (403 otherwise). "
                     "A valid admin token must still receive 200."),
}


@dataclass
class FixContext:
    vuln_class: str
    handler_name: str
    handler_source: str
    route: str
    finding: Finding
    template: str
    sast_hint: str | None = None     # optional Semgrep rule/line/message grounding


def build_context(finding: Finding, handler_source: str, route: str,
                  sast_hint: str | None = None) -> FixContext:
    return FixContext(
        vuln_class=finding.vuln_class,
        handler_name=HANDLER_BY_CLASS[finding.vuln_class],
        handler_source=handler_source,
        route=route,
        finding=finding,
        template=FIX_TEMPLATES[finding.vuln_class],
        sast_hint=sast_hint,
    )


# --------------------------------------------------------------------------
# Template (offline / deterministic) proposer
# --------------------------------------------------------------------------
_TEMPLATE_PATCHES = {
    "get_invoice": '''@app.get("/invoices/<int:invoice_id>")
def get_invoice(invoice_id: int):
    user = current_user()
    if user is None:
        return jsonify({"error": "unauthorized"}), 401
    db = get_db()
    row = db.execute("SELECT * FROM invoices WHERE id = ?", (invoice_id,)).fetchone()
    if row is None:
        return jsonify({"error": "not found"}), 404
    if row["owner_id"] != user["id"] and not user["is_admin"]:
        return jsonify({"error": "forbidden"}), 403
    return jsonify(dict(row))
''',
    "search_invoices": '''@app.get("/invoices/search")
def search_invoices():
    user = current_user()
    if user is None:
        return jsonify({"error": "unauthorized"}), 401
    q = request.args.get("q", "")
    db = get_db()
    rows = db.execute(
        "SELECT * FROM invoices WHERE owner_id = ? AND description LIKE ?",
        (user["id"], f"%{q}%"),
    ).fetchall()
    return jsonify([dict(r) for r in rows])
''',
    "me": '''@app.get("/me")
def me():
    user = current_user()
    if user is None:
        return jsonify({"error": "unauthorized"}), 401
    allowed = ("id", "username", "is_admin")
    return jsonify({k: user[k] for k in allowed})
''',
    "admin_users": '''@app.get("/admin/users")
def admin_users():
    user = current_user()
    if user is None:
        return jsonify({"error": "unauthorized"}), 401
    if not user["is_admin"]:
        return jsonify({"error": "forbidden"}), 403
    db = get_db()
    rows = db.execute("SELECT id, username, is_admin FROM users").fetchall()
    return jsonify([dict(r) for r in rows])
''',
}


class TemplateProposer:
    """Deterministic known-good patches; no network. Used for tests and fallback."""

    def propose(self, ctx: FixContext, feedback: str | None = None) -> str:
        return _TEMPLATE_PATCHES[ctx.handler_name]


# --------------------------------------------------------------------------
# LLM proposer (Anthropic)
# --------------------------------------------------------------------------
_SYSTEM = (
    "You are a secure-coding assistant that fixes exactly one vulnerability in "
    "exactly one Flask route handler. You will be given the handler's current "
    "source and a failing attack. Return ONLY the corrected handler function, "
    "including its route decorator(s), as plain Python.\n"
    "Hard rules:\n"
    "- Change only this handler. Do not touch any other code.\n"
    "- Do NOT add import statements. Reuse the existing helpers current_user() "
    "and get_db(), and flask's jsonify/request which are already imported.\n"
    "- Keep the same function name and the same route path.\n"
    "- Make the minimal change that fixes the vulnerability.\n"
    "- Preserve legitimate behaviour: authorized callers must still succeed.\n"
    "- Output only the code. No prose, no markdown fences, no explanation."
)


def build_user_message(ctx: FixContext, feedback: str | None) -> str:
    """The narrow-context fix request, shared by every LLM proposer."""
    f = ctx.finding
    parts = [
        f"Vulnerability class: {ctx.vuln_class}",
        f"Route: {ctx.route}",
        f"How to fix this class: {ctx.template}",
    ]
    if ctx.sast_hint:
        parts.append(f"Static analysis (Semgrep) flagged: {ctx.sast_hint}")
    parts += [
        "",
        "Confirmed exploit (deterministically verified against the running app):",
        f"  {f.detail}",
        f"  attack request: {f.request}",
        f"  attack response: status {f.response.get('status')} "
        f"body {f.response.get('body')}",
        "",
        "Current handler source:",
        ctx.handler_source,
    ]
    if feedback:
        parts += [
            "",
            "Your previous attempt did not pass verification. Fix this and try "
            "again. Verification feedback:",
            f"  {feedback}",
        ]
    parts.append("\nReturn the corrected handler now.")
    return "\n".join(parts)


class LLMProposer:
    """Proposes a patch via the Anthropic API. Only proposes -- never verifies."""

    def __init__(self, model: str | None = None, max_tokens: int = 4000):
        self.model = model or os.environ.get("FIXER_MODEL", "claude-opus-5-5")
        self.max_tokens = max_tokens
        self._client = None

    def _client_lazy(self):
        if self._client is None:
            import anthropic  # imported lazily so offline use needs no SDK key
            self._client = anthropic.Anthropic()
        return self._client

    def propose(self, ctx: FixContext, feedback: str | None = None) -> str:
        client = self._client_lazy()
        resp = client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            output_config={"effort": "high"},
            system=_SYSTEM,
            messages=[{"role": "user", "content": build_user_message(ctx, feedback)}],
        )
        text = "".join(b.text for b in resp.content if b.type == "text")
        return strip_code_fences(text)


class GeminiProposer:
    """Proposes a patch via Google's Gemini API (google-genai). Only proposes.

    Reads the API key from GEMINI_API_KEY (or GOOGLE_API_KEY) automatically, and
    the model from GEMINI_MODEL (default gemini-3.6-flash -- override if your
    account exposes a different id).
    """

    def __init__(self, model: str | None = None, max_tokens: int = 4000):
        self.model = model or os.environ.get("GEMINI_MODEL", "gemini-3.6-flash")
        self.max_tokens = max_tokens
        self._client = None

    def _client_lazy(self):
        if self._client is None:
            from google import genai  # lazy: offline/other providers need no SDK
            self._client = genai.Client()
        return self._client

    def propose(self, ctx: FixContext, feedback: str | None = None) -> str:
        from google.genai import types
        client = self._client_lazy()
        resp = client.models.generate_content(
            model=self.model,
            contents=build_user_message(ctx, feedback),
            config=types.GenerateContentConfig(
                system_instruction=_SYSTEM,
                max_output_tokens=self.max_tokens,
                temperature=0,
            ),
        )
        return strip_code_fences(resp.text or "")


class FallbackProposer:
    """Wrap an LLM proposer and fall back to deterministic template patches if it
    fails (missing key, unknown model, network error, SDK not installed, empty
    response). The workflow keeps running instead of stopping.

    Once the primary trips it is not retried for the rest of the run (avoids
    repeated slow failures). `used_fallback`/`reason` record what happened so the
    caller can report honestly that a patch came from the template, not the LLM.
    """

    def __init__(self, primary, fallback=None, on_fallback=None):
        self.primary = primary
        self.fallback = fallback or TemplateProposer()
        self.on_fallback = on_fallback
        self.used_fallback = False
        self.reason = ""

    def propose(self, ctx: FixContext, feedback: str | None = None) -> str:
        if not self.used_fallback:
            try:
                out = self.primary.propose(ctx, feedback)
                if out and out.strip():
                    return out
                raise RuntimeError("empty response from LLM")
            except Exception as exc:  # noqa: BLE001 - any failure must degrade, not stop
                self.used_fallback = True
                self.reason = f"{type(exc).__name__}: {exc}"
                if self.on_fallback:
                    self.on_fallback(self.reason)
        return self.fallback.propose(ctx, feedback)
