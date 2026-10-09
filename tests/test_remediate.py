"""End-to-end fix->verify tests, offline (TemplateProposer, no API key needed).

The central claim of the tool is "we trust the re-attack, not the AI". These
tests exercise that: a correct patch verifies, a patch that blocks the attack
but breaks the good path is REJECTED, and the retry loop recovers from a bad
first proposal.
"""

import sys
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from engine import remediate  # noqa: E402
from engine.attacks import ATTACKS, DEMO_PROFILE  # noqa: E402
from engine.fixer import FixContext, TemplateProposer  # noqa: E402

APP = str(Path(__file__).resolve().parents[1] / "target_app" / "app.py")


def _finding(vuln_class: str):
    """Run the real attack to get a genuine confirmed finding to remediate."""
    from target_app.app import app, init_db
    init_db()
    with httpx.Client(transport=httpx.WSGITransport(app=app), base_url="http://t") as c:
        f = ATTACKS[vuln_class](c, DEMO_PROFILE)
    assert f.confirmed, f"{vuln_class} should be confirmed before fixing"
    return f


@pytest.mark.parametrize("vuln_class", ["idor", "sqli", "data_exposure", "missing_auth"])
def test_template_fix_verifies_each_class(vuln_class):
    result = remediate.remediate_finding(_finding(vuln_class), APP, proposer=TemplateProposer())
    assert result.verified, result.attempts[-1].verify.summary()
    vr = result.attempts[-1].verify
    assert vr.attack_blocked
    assert vr.good_path_ok
    assert vr.app_starts
    assert result.diff and result.patched_source


class _BreaksGoodPathProposer:
    """A patch that blocks the attack by forbidding EVERYONE -- Alice too.

    This must be rejected: the attack is blocked, but Alice can no longer read
    her own invoice. Only the deterministic good-path check catches this.
    """

    def propose(self, ctx: FixContext, feedback=None) -> str:
        return ('@app.get("/invoices/<int:invoice_id>")\n'
                'def get_invoice(invoice_id: int):\n'
                '    return jsonify({"error": "forbidden"}), 403\n')


def test_fix_that_breaks_good_path_is_rejected():
    result = remediate.remediate_finding(
        _finding("idor"), APP, proposer=_BreaksGoodPathProposer(), max_attempts=2)
    assert not result.verified
    assert result.status == "needs_human_review"
    last = result.attempts[-1].verify
    assert last.attack_blocked is True          # the attack WAS blocked...
    assert last.good_path_ok is False           # ...but legit access broke -> rejected
    broken = {c.name for c in last.good_path.failures}
    assert "alice_reads_own_invoice" in broken


class _BadThenGoodProposer:
    """Returns an invalid patch first, then the known-good template patch."""

    def __init__(self):
        self.calls = 0
        self._template = TemplateProposer()

    def propose(self, ctx: FixContext, feedback=None) -> str:
        self.calls += 1
        if self.calls == 1:
            # Invalid: changes the route, so validation rejects it pre-verify.
            return '@app.get("/invoices/all")\ndef get_invoice(invoice_id: int):\n    return jsonify({})\n'
        return self._template.propose(ctx, feedback)


def test_retry_recovers_from_bad_first_proposal():
    proposer = _BadThenGoodProposer()
    result = remediate.remediate_finding(_finding("idor"), APP, proposer=proposer, max_attempts=3)
    assert result.verified
    assert len(result.attempts) == 2
    assert result.attempts[0].valid is False    # first was rejected by validation
    assert result.attempts[1].verified is True


def test_original_file_is_never_modified():
    before = Path(APP).read_text(encoding="utf-8")
    remediate.remediate_finding(_finding("idor"), APP, proposer=TemplateProposer())
    after = Path(APP).read_text(encoding="utf-8")
    assert before == after                       # the real target file is untouched
