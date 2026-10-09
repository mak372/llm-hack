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
from engine.attacks import ATTACKS, DEMO_PROFILE, run_all_attacks
from engine.codemod import load_app_module
from engine.fixer import LLMProposer, TemplateProposer
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

    # ----- FIX + VERIFY -----
    proposer = TemplateProposer() if args.offline else LLMProposer()
    if not args.offline and not args.no_fix and not os.environ.get("ANTHROPIC_API_KEY"):
        print("note: ANTHROPIC_API_KEY not set; the LLM proposer will rely on an "
              "`ant auth login` profile, or use --offline for template patches.",
              file=sys.stderr)

    outcomes: list[Outcome] = []
    verified_results = []
    for f in findings:
        if not f.confirmed or args.no_fix:
            outcomes.append(Outcome(f, None))
            continue
        result = remediate_finding(f, args.code, proposer=proposer,
                                   profile=DEMO_PROFILE, max_attempts=args.max_attempts)
        outcomes.append(Outcome(f, result))
        if result.verified:
            verified_results.append(result)
            if args.apply:
                _apply(args.code, result.patched_source)

    # ----- REPORT -----
    print()
    print(report.terminal_summary(outcomes))

    if args.format == "md":
        text = report.render_markdown(outcomes, args.base_url or args.code, args.offline)
    else:
        text = report.render_html(outcomes, args.base_url or args.code, args.offline)
    with open(args.report, "w", encoding="utf-8") as fh:
        fh.write(text)
    print(f"\nReport written to {args.report}")

    if args.gen_tests and verified_results:
        paths = regression.generate_regression_tests(verified_results, args.tests_dir)
        print(f"Generated {len(paths)} regression test file(s) in {args.tests_dir}")

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
