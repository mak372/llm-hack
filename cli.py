"""Attack-Fix-Verify CLI.

Runs the full loop against an API: ATTACK (active exploits) -> FLAG -> FIX (LLM
or offline template proposes a patch) -> VERIFY (deterministic re-attack +
good-path + app-start). Writes a terminal summary and an HTML/Markdown report,
and can emit pytest regression tests for every verified fix.

Examples:
  # Offline (no API key): attack the in-process app, fix with templates, report.
  python cli.py --code target_app/app.py --offline

  # Attack a running server, fix with the LLM, apply verified patches, emit tests.
  python cli.py --base-url http://localhost:5000 --code target_app/app.py --apply --gen-tests

  # Attack only, no fixing.
  python cli.py --code target_app/app.py --no-fix
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys

import httpx

from engine import regression, report
from engine import sast as sastmod
from engine.attacks import DEMO_PROFILE, run_all_attacks
from engine.codemod import load_app_module
from engine.fixer import FallbackProposer, GeminiProposer, LLMProposer, TemplateProposer
from engine.remediate import remediate_finding
from engine.report import Outcome


def _attack_client(args):
    """Return (client, closer). Live server if --base-url, else in-process WSGI."""
    if args.base_url:
        client = httpx.Client(base_url=args.base_url, timeout=10.0)
        return client, client.close
    module = load_app_module(os.path.abspath(args.code))
    module.init_db()
    transport = httpx.WSGITransport(app=module.app)
    client = httpx.Client(transport=transport, base_url="http://in-process")
    return client, client.close


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Attack-Fix-Verify for AI-generated APIs")
    p.add_argument("--code", required=True, help="path to the app source to patch")
    p.add_argument("--base-url", help="run attacks against this live server "
                                      "(default: load --code in-process)")
    p.add_argument("--offline", action="store_true",
                   help="use the template proposer (no API key needed)")
    p.add_argument("--provider", choices=["gemini", "anthropic"], default="gemini",
                   help="LLM provider for the fixer (ignored with --offline)")
    p.add_argument("--no-fix", action="store_true", help="only attack and flag")
    p.add_argument("--only", help="comma-separated classes to run "
                                  "(idor,sqli,data_exposure,missing_auth)")
    p.add_argument("--max-attempts", type=int, default=3)
    p.add_argument("--apply", action="store_true",
                   help="write verified patches back to --code (keeps a .bak)")
    p.add_argument("--gen-tests", action="store_true",
                   help="generate pytest regression files for verified fixes")
    p.add_argument("--tests-dir", default="generated_tests")
    p.add_argument("--report", default="report.html", help="report output path")
    p.add_argument("--format", choices=["html", "md"], default="html")
    p.add_argument("--open-pr", action="store_true",
                   help="apply verified fixes, add tests+report, and open a GitHub PR")
    p.add_argument("--push", action="store_true",
                   help="with --open-pr: push the branch and create the PR "
                        "(needs an 'origin' remote and GITHUB_TOKEN)")
    p.add_argument("--base-branch", default="main", help="base branch for the PR")
    p.add_argument("--sast", action="store_true",
                   help="run Semgrep as a static layer (pre-scan, cross-check, rescan)")
    p.add_argument("--sast-config", action="append",
                   help="Semgrep config (repeatable); default: p/python p/flask p/owasp-top-ten")
    p.add_argument("--restore", action="store_true",
                   help="restore --code from its .bak and exit")
    args = p.parse_args(argv)

    if args.restore:
        bak = args.code + ".bak"
        if os.path.exists(bak):
            shutil.copyfile(bak, args.code)
            print(f"Restored {args.code} from {bak}")
            return 0
        print(f"No backup found at {bak}", file=sys.stderr)
        return 1

    # ----- ATTACK -----
    client, close = _attack_client(args)
    try:
        findings = run_all_attacks(client, DEMO_PROFILE)
    finally:
        close()

    if args.only:
        wanted = {s.strip() for s in args.only.split(",")}
        findings = [f for f in findings if f.vuln_class in wanted]

    # ----- SCAN (Semgrep static pre-scan + cross-check) -----
    sast_data = None
    static_findings = []
    if args.sast:
        code_dir = os.path.dirname(os.path.abspath(args.code))
        runner = sastmod.detect_runner(code_dir)
        if runner is None:
            sast_data = sastmod.SastData(
                ran=False, note="no Semgrep runner found (PATH, python -m, Docker, WSL)")
            print(f"note: Semgrep skipped - {sast_data.note}", file=sys.stderr)
        else:
            try:
                static_findings = sastmod.run_semgrep(
                    args.code, configs=args.sast_config, runner=runner)
                sast_data = sastmod.SastData(ran=True, runner=runner.kind,
                                             findings=static_findings)
                sast_data.cross = sastmod.cross_check(static_findings, findings)
            except sastmod.SastUnavailable as exc:
                sast_data = sastmod.SastData(ran=False, note=str(exc))
                print(f"note: Semgrep skipped - {exc}", file=sys.stderr)

    # ----- FIX + VERIFY -----
    if args.offline:
        proposer = TemplateProposer()
    else:
        primary = LLMProposer() if args.provider == "anthropic" else GeminiProposer()
        # Wrap the LLM so a missing key / unknown model / network error degrades
        # to deterministic template patches instead of stopping the workflow.
        proposer = FallbackProposer(
            primary, TemplateProposer(),
            on_fallback=lambda reason: print(
                f"warning: {args.provider} proposer unavailable ({reason}); "
                f"falling back to deterministic template patches.", file=sys.stderr))

    apply_patches = args.apply or args.open_pr
    do_gen_tests = args.gen_tests or args.open_pr

    outcomes: list[Outcome] = []
    verified_results = []
    for f in findings:
        if not f.confirmed or args.no_fix:
            outcomes.append(Outcome(f, None))
            continue
        hint = sastmod.semgrep_context_for(f, static_findings) if static_findings else None
        result = remediate_finding(f, args.code, proposer=proposer,
                                   profile=DEMO_PROFILE, max_attempts=args.max_attempts,
                                   sast_hint=hint)
        outcomes.append(Outcome(f, result))
        if result.verified:
            verified_results.append(result)
            if apply_patches:
                _apply(args.code, result.patched_source)

    # ----- RE-VERIFY (Semgrep rescan of patched code) -----
    # Only re-scan classes Semgrep actually flagged in the pre-scan; claiming a
    # finding "cleared" for a class it never saw would be misleading.
    if sast_data is not None and sast_data.ran and verified_results:
        flagged = {s.vuln_class for s in static_findings if s.vuln_class}
        for r in verified_results:
            if r.finding.vuln_class not in flagged:
                continue
            try:
                post = sastmod.run_semgrep(r.working_app_path, configs=args.sast_config)
            except sastmod.SastUnavailable:
                continue
            still = any(s.vuln_class == r.finding.vuln_class for s in post)
            sast_data.cleared[r.finding.vuln_class] = not still

    # ----- REPORT -----
    print()
    print(report.terminal_summary(outcomes, sast=sast_data))
    if isinstance(proposer, FallbackProposer) and proposer.used_fallback:
        print(f"\n[!] LLM was unavailable ({proposer.reason}); patches above came "
              f"from the deterministic template fallback, not {args.provider}.")

    if args.format == "md":
        text = report.render_markdown(outcomes, args.base_url or args.code, args.offline,
                                      sast=sast_data)
    else:
        text = report.render_html(outcomes, args.base_url or args.code, args.offline,
                                   sast=sast_data)
    with open(args.report, "w", encoding="utf-8") as fh:
        fh.write(text)
    print(f"\nReport written to {args.report}")

    if do_gen_tests and verified_results:
        paths = regression.generate_regression_tests(verified_results, args.tests_dir)
        print(f"Generated {len(paths)} regression test file(s) in {args.tests_dir}")

    # ----- PUBLISH (open a PR for the verified fixes) -----
    if args.open_pr:
        if not verified_results:
            print("No verified fixes; nothing to publish as a PR.")
        else:
            from engine import publisher
            body = publisher.build_pr_body(verified_results, args.base_url or args.code)
            n = len(verified_results)
            title = f"Security: fix {n} vulnerabilit{'y' if n == 1 else 'ies'} (verified by re-attack)"
            files = [args.code, args.tests_dir, args.report]
            try:
                pr = publisher.open_pull_request(
                    os.getcwd(), verified_results, files, title, body,
                    base_branch=args.base_branch, push=args.push,
                    token=os.environ.get("GITHUB_TOKEN"))
            except publisher.PublishError as exc:
                print(f"PR step failed: {exc}", file=sys.stderr)
                return 1
            if pr.pushed:
                print(f"\nOpened pull request: {pr.pr_url}")
            else:
                print(f"\nCreated local branch '{pr.branch}' with the fix + tests + report.")
                print(f"PR body written to {pr.body_path}.")
                print("To publish: add a GitHub 'origin' remote and set GITHUB_TOKEN, "
                      "then re-run with --open-pr --push (or push the branch and open a PR by hand).")

    # Exit non-zero if any confirmed vuln is not verified (useful for CI).
    unresolved = [o for o in outcomes
                  if o.finding.confirmed and o.status != "verified"]
    return 1 if (unresolved and not args.no_fix) else 0


def _apply(code_path: str, patched_source: str):
    """Write a verified patch back to the real source, backing up the original once."""
    bak = code_path + ".bak"
    if not os.path.exists(bak):
        shutil.copyfile(code_path, bak)
    with open(code_path, "w", encoding="utf-8") as fh:
        fh.write(patched_source)


if __name__ == "__main__":
    raise SystemExit(main())
