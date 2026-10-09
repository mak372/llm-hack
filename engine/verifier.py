"""Deterministic verification of a proposed fix.

This is the arbiter of the whole tool, and it contains NO LLM calls and no LLM
judgement. A fix is "verified" only if ALL of the following hold against the
patched app:

  1. app_starts        -- the patched app imports and /health returns 200
  2. attack_blocked    -- re-running the *exact* original attack no longer confirms
  3. good_path_ok      -- every legitimate request still works (nothing broken/deleted)

It also re-runs ALL attacks (not just the patched one) so the report can show
sibling vulnerabilities and catch a patch that introduces a new one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import ModuleType

import httpx

from engine import goodpath
from engine.attacks import ATTACKS, run_all_attacks
from engine.findings import Finding


@dataclass
class VerifyResult:
    verified: bool
    app_starts: bool
    attack_blocked: bool
    good_path_ok: bool
    target_class: str
    good_path: goodpath.GoodPathReport
    reattack: list[Finding] = field(default_factory=list)
    notes: str = ""

    def summary(self) -> str:
        """One-line-per-check feedback, used both for reports and LLM retry context."""
        gp = "pass" if self.good_path_ok else (
            "FAIL: " + ", ".join(f"{c.name}({c.detail})" for c in self.good_path.failures))
        still = [f.vuln_class for f in self.reattack if f.confirmed]
        return (f"app_starts={self.app_starts} "
                f"attack_blocked={self.attack_blocked} "
                f"good_path={gp} "
                f"still_vulnerable={still}")


def _client(app_module: ModuleType) -> httpx.Client:
    transport = httpx.WSGITransport(app=app_module.app)
    return httpx.Client(transport=transport, base_url="http://verify.local")


def verify_fix(app_module: ModuleType, finding: Finding, profile: dict) -> VerifyResult:
    """Run every verification check against an already-loaded patched app module."""
    # Fresh, deterministic database for the patched app.
    app_module.init_db()

    with _client(app_module) as client:
        # 1. App starts / responds.
        try:
            app_starts = client.get("/health").status_code == 200
        except Exception as exc:  # noqa: BLE001 - any failure means it didn't start
            return VerifyResult(False, False, False, False, finding.vuln_class,
                                goodpath.GoodPathReport(), notes=f"health check error: {exc}")

        # 2. Re-run the EXACT original attack; it must no longer confirm.
        target = ATTACKS[finding.vuln_class](client, profile)
        attack_blocked = not target.confirmed

        # 3. Good-path checks: legitimate behaviour preserved.
        gp = goodpath.run_checks(client, profile)
        good_path_ok = gp.all_passed

        # Extra layer: re-attack everything to surface siblings / regressions.
        reattack = run_all_attacks(client, profile)

    verified = app_starts and attack_blocked and good_path_ok
    return VerifyResult(
        verified=verified,
        app_starts=app_starts,
        attack_blocked=attack_blocked,
        good_path_ok=good_path_ok,
        target_class=finding.vuln_class,
        good_path=gp,
        reattack=reattack,
    )
