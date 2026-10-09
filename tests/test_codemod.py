"""Tests for the source-surgery and patch-validation layer."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from engine import codemod  # noqa: E402

APP = Path(__file__).resolve().parents[1] / "target_app" / "app.py"


def test_extract_handler_includes_decorator_and_route():
    src = APP.read_text(encoding="utf-8")
    block = codemod.extract_handler(src, "get_invoice")
    assert block.name == "get_invoice"
    assert block.routes == ("/invoices/<int:invoice_id>",)
    assert block.text.startswith("@app.get")
    assert "def get_invoice" in block.text


def test_replace_handler_only_changes_that_block():
    src = APP.read_text(encoding="utf-8")
    block = codemod.extract_handler(src, "me")
    new = '@app.get("/me")\ndef me():\n    return jsonify({"ok": True})\n'
    patched = codemod.replace_handler(src, block, new)
    assert 'return jsonify({"ok": True})' in patched
    # Other handlers are untouched.
    assert "def admin_users" in patched
    assert "def search_invoices" in patched


def test_validate_patch_accepts_same_shape():
    good = ('@app.get("/me")\ndef me():\n    user = current_user()\n'
            '    return jsonify({"id": user["id"]})\n')
    ok, detail = codemod.validate_patch(good, "me", ("/me",))
    assert ok, detail


def test_validate_patch_rejects_route_change():
    bad = '@app.get("/users/me")\ndef me():\n    return jsonify({})\n'
    ok, detail = codemod.validate_patch(bad, "me", ("/me",))
    assert not ok and "route" in detail


def test_validate_patch_rejects_added_import():
    bad = 'import os\n@app.get("/me")\ndef me():\n    return jsonify({})\n'
    ok, detail = codemod.validate_patch(bad, "me", ("/me",))
    assert not ok and "import" in detail


def test_validate_patch_rejects_rename():
    bad = '@app.get("/me")\ndef profile():\n    return jsonify({})\n'
    ok, detail = codemod.validate_patch(bad, "me", ("/me",))
    assert not ok and "renamed" in detail


def test_strip_code_fences():
    fenced = "```python\n@app.get('/me')\ndef me():\n    return 1\n```"
    out = codemod.strip_code_fences(fenced)
    assert out.startswith("@app.get")
    assert "```" not in out
