"""Tests for the fixer proposers, focused on the fallback behaviour."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from engine.fixer import FallbackProposer, TemplateProposer, build_context  # noqa: E402
from engine.findings import Finding  # noqa: E402


def _ctx():
    f = Finding("idor", "n", "/invoices/101", "GET", "high", True, "detail")
    return build_context(f, "@app.get('/invoices/<int:invoice_id>')\ndef get_invoice(): ...\n",
                         "/invoices/<int:invoice_id>")


class _Boom:
    """A primary proposer that always fails (simulates no key / bad model)."""
    def propose(self, ctx, feedback=None):
        raise RuntimeError("model unavailable")


class _Empty:
    def propose(self, ctx, feedback=None):
        return "   "   # empty/whitespace -> treated as failure


class _Ok:
    def propose(self, ctx, feedback=None):
        return "@app.get('/invoices/<int:invoice_id>')\ndef get_invoice(invoice_id):\n    return 1\n"


def test_fallback_engages_when_primary_raises():
    fp = FallbackProposer(_Boom(), TemplateProposer())
    out = fp.propose(_ctx())
    assert "def get_invoice" in out          # came from the template patch
    assert "owner_id" in out                 # the real template fix content
    assert fp.used_fallback and "model unavailable" in fp.reason


def test_fallback_engages_on_empty_response():
    fp = FallbackProposer(_Empty(), TemplateProposer())
    out = fp.propose(_ctx())
    assert fp.used_fallback
    assert "def get_invoice" in out


def test_primary_used_when_it_succeeds():
    fp = FallbackProposer(_Ok(), TemplateProposer())
    out = fp.propose(_ctx())
    assert "return 1" in out
    assert not fp.used_fallback


def test_on_fallback_callback_fires_once():
    calls = []
    fp = FallbackProposer(_Boom(), TemplateProposer(), on_fallback=calls.append)
    fp.propose(_ctx())
    fp.propose(_ctx())                        # second call: already tripped
    assert len(calls) == 1                    # callback fired only once
