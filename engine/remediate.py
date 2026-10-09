"""The fix->verify loop for a single confirmed finding.

For one Finding it: extracts the vulnerable handler, asks the proposer for a
replacement, validates the replacement is minimal/same-shape, applies it to a
*working copy* (the original is backed up and never touched), loads the patched
app and runs the deterministic verifier. On failure it feeds the verifier's
reasons back to the proposer and retries, up to `max_attempts`, then gives up
with status "needs_human_review". It never reports success it did not verify.
"""

from __future__ import annotations

import difflib
import os
import shutil
import tempfile
from dataclasses import dataclass, field

from engine import codemod, verifier
from engine.attacks import DEMO_PROFILE
from engine.fixer import HANDLER_BY_CLASS, FixContext, TemplateProposer, build_context
from engine.findings import Finding


@dataclass
class Attempt:
    number: int
    proposed_patch: str
    valid: bool
    validation_detail: str
    verify: verifier.VerifyResult | None = None
    error: str = ""

    @property
    def verified(self) -> bool:
        return self.verify is not None and self.verify.verified


@dataclass
class RemediationResult:
    finding: Finding
    status: str                      # "verified" | "needs_human_review"
    attempts: list[Attempt] = field(default_factory=list)
    diff: str = ""                   # unified diff of the handler (when verified)
    patched_source: str = ""         # full patched app.py (when verified)
    working_dir: str = ""
    working_app_path: str = ""
    backup_path: str = ""

    @property
    def verified(self) -> bool:
        return self.status == "verified"


def _make_working_copy(src_app_path: str, work_root: str | None) -> tuple[str, str, str]:
    """Copy the target_app dir to a sandbox. Returns (work_dir, app_path, backup_path)."""
    src_dir = os.path.dirname(os.path.abspath(src_app_path))
    work_dir = tempfile.mkdtemp(prefix="afv_work_", dir=work_root)
    dst_dir = os.path.join(work_dir, os.path.basename(src_dir))
    shutil.copytree(src_dir, dst_dir)
    app_path = os.path.join(dst_dir, os.path.basename(src_app_path))
    backup_path = app_path + ".bak"
    shutil.copyfile(app_path, backup_path)   # keep a backup of the original
    return work_dir, app_path, backup_path


def remediate_finding(
    finding: Finding,
    src_app_path: str,
    proposer=None,
    profile: dict | None = None,
    max_attempts: int = 3,
    work_root: str | None = None,
    sast_hint: str | None = None,
) -> RemediationResult:
    profile = profile or DEMO_PROFILE
    proposer = proposer or TemplateProposer()

    with open(src_app_path, "r", encoding="utf-8") as fh:
        original_source = fh.read()

    handler_name = HANDLER_BY_CLASS[finding.vuln_class]
    block = codemod.extract_handler(original_source, handler_name)
    route = block.routes[0] if block.routes else finding.endpoint
    ctx: FixContext = build_context(finding, block.text, route, sast_hint=sast_hint)

    work_dir, app_path, backup_path = _make_working_copy(src_app_path, work_root)
    result = RemediationResult(finding=finding, status="needs_human_review",
                               working_dir=work_dir, working_app_path=app_path,
                               backup_path=backup_path)

    feedback: str | None = None
    for n in range(1, max_attempts + 1):
        proposed = codemod.strip_code_fences(proposer.propose(ctx, feedback))
        ok, detail = codemod.validate_patch(proposed, handler_name, block.routes)
        attempt = Attempt(number=n, proposed_patch=proposed, valid=ok, validation_detail=detail)

        if not ok:
            attempt.error = f"rejected: {detail}"
            result.attempts.append(attempt)
            feedback = f"Patch rejected before running: {detail}"
            continue

        # Apply to the working copy (original stays untouched, backup kept).
        patched_source = codemod.replace_handler(original_source, block, proposed)
        with open(app_path, "w", encoding="utf-8") as fh:
            fh.write(patched_source)

        try:
            module = codemod.load_app_module(app_path)
        except Exception as exc:  # noqa: BLE001 - patched app failed to import
            attempt.error = f"app failed to start: {exc}"
            result.attempts.append(attempt)
            feedback = f"The patched app did not start (import/syntax error): {exc}"
            continue

        vr = verifier.verify_fix(module, finding, profile)
        attempt.verify = vr
        result.attempts.append(attempt)

        if vr.verified:
            result.status = "verified"
            result.patched_source = patched_source
            result.diff = _handler_diff(block.text, proposed, route)
            return result

        feedback = vr.summary()

    # All attempts failed: restore the working copy to the backed-up original.
    shutil.copyfile(backup_path, app_path)
    return result


def _handler_diff(old_block: str, new_block: str, route: str) -> str:
    old = old_block.splitlines(keepends=True)
    new = (new_block if new_block.endswith("\n") else new_block + "\n").splitlines(keepends=True)
    return "".join(difflib.unified_diff(
        old, new, fromfile=f"a: handler {route}", tofile=f"b: handler {route}"))
