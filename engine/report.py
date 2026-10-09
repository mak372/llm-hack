"""Reporting: a terminal summary and a standalone HTML / Markdown report.

Consumes the findings from the attack phase plus the RemediationResult per
confirmed finding, and renders the full attack -> fix -> verify story with
evidence, curl reproductions, the fix diff, and the deterministic verify checks.
"""

from __future__ import annotations

import datetime
import html
from dataclasses import dataclass

from engine.findings import Finding
from engine.remediate import RemediationResult

CLASS_TITLES = {
    "idor": "Broken Access Control (IDOR)",
    "sqli": "SQL Injection",
    "data_exposure": "Sensitive Data Exposure",
    "missing_auth": "Missing Authentication",
}


@dataclass
class Outcome:
    """A finding paired with its remediation result (None if fixing was skipped)."""
    finding: Finding
    result: RemediationResult | None

    @property
    def status(self) -> str:
        if not self.finding.confirmed:
            return "safe"
        if self.result is None:
            return "vulnerable"
        return "verified" if self.result.verified else "needs_review"


STATUS_LABEL = {
    "safe": "SAFE",
    "vulnerable": "VULNERABLE",
    "verified": "FIXED & VERIFIED",
    "needs_review": "NEEDS HUMAN REVIEW",
}


def _counts(outcomes: list[Outcome]) -> dict[str, int]:
    c = {"total": len(outcomes), "confirmed": 0, "verified": 0, "needs_review": 0}
    for o in outcomes:
        if o.finding.confirmed:
            c["confirmed"] += 1
        if o.status == "verified":
            c["verified"] += 1
        if o.status == "needs_review":
            c["needs_review"] += 1
    return c


# --------------------------------------------------------------------------
# Terminal
# --------------------------------------------------------------------------
def terminal_summary(outcomes: list[Outcome], sast=None) -> str:
    lines = []
    for o in outcomes:
        f = o.finding
        label = STATUS_LABEL[o.status]
        lines.append(f"  [{label:>18}]  {f.vuln_class:<14} {f.method} {f.endpoint}")
        lines.append(f"      {f.detail}")
        if o.result is not None and o.finding.confirmed:
            r = o.result
            last = r.attempts[-1].verify if r.attempts and r.attempts[-1].verify else None
            if last:
                lines.append(f"      verify: app_starts={last.app_starts} "
                             f"attack_blocked={last.attack_blocked} "
                             f"good_path_ok={last.good_path_ok} "
                             f"(attempts={len(r.attempts)})")
            if r.verified is False:
                bad = last.good_path.failures if last else []
                if bad:
                    lines.append("      broken good-path checks: "
                                 + ", ".join(c.name for c in bad))
        lines.append("")
    c = _counts(outcomes)
    header = (f"Attack-Fix-Verify summary: {c['confirmed']} vulnerabilities confirmed, "
              f"{c['verified']} fixed & verified, {c['needs_review']} need human review")
    body = header + "\n" + "-" * len(header) + "\n" + "\n".join(lines)
    if sast is not None:
        body += "\n" + _sast_terminal(sast)
    return body


def _sast_terminal(sast) -> str:
    if not sast.ran:
        return f"Semgrep (SAST): skipped - {sast.note}"
    lines = [f"Semgrep (SAST) via {sast.runner}: {len(sast.findings)} static suspect(s)"]
    if sast.cross is not None:
        lines.append(f"  cross-check: {len(sast.cross.both)} confirmed by both, "
                     f"{len(sast.cross.static_only)} static-only (likely FP), "
                     f"{len(sast.cross.dynamic_only)} dynamic-only (SAST missed)")
        for r in sast.cross.dynamic_only:
            lines.append(f"    SAST MISSED: {r.vuln_class} {r.endpoint} "
                         f"(found only by active attack)")
    if sast.cleared:
        done = ", ".join(f"{k}:{'cleared' if v else 'still-flagged'}"
                         for k, v in sast.cleared.items())
        lines.append(f"  post-fix rescan: {done}")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Markdown
# --------------------------------------------------------------------------
def render_markdown(outcomes: list[Outcome], base_url: str, offline: bool, sast=None) -> str:
    c = _counts(outcomes)
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    out = [
        "# Attack-Fix-Verify Report",
        "",
        f"- Target: `{base_url}`",
        f"- Generated: {now}",
        f"- Patch source: {'template (offline)' if offline else 'LLM (claude)'}",
        f"- **{c['confirmed']} confirmed · {c['verified']} verified · "
        f"{c['needs_review']} need review**",
        "",
    ]
    if sast is not None:
        out += _sast_markdown(sast)
    for o in outcomes:
        f = o.finding
        out.append(f"## {CLASS_TITLES.get(f.vuln_class, f.vuln_class)} — {STATUS_LABEL[o.status]}")
        out.append("")
        out.append(f"- Endpoint: `{f.method} {f.endpoint}` (severity: {f.severity})")
        out.append(f"- Evidence: {f.detail}")
        out.append(f"- Reproduce: `{f.curl}`")
        out.append("")
        if o.result and f.confirmed:
            r = o.result
            last = r.attempts[-1].verify if r.attempts and r.attempts[-1].verify else None
            if last:
                out.append(f"**Verify:** app_starts={last.app_starts}, "
                           f"attack_blocked={last.attack_blocked}, "
                           f"good_path_ok={last.good_path_ok}, attempts={len(r.attempts)}")
                out.append("")
            if r.diff:
                out.append("```diff")
                out.append(r.diff.rstrip())
                out.append("```")
                out.append("")
    return "\n".join(out)


# --------------------------------------------------------------------------
# HTML
# --------------------------------------------------------------------------
_CSS = """
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 0;
  background: #0f1420; color: #e6e9ef; line-height: 1.5; }
.wrap { max-width: 900px; margin: 0 auto; padding: 32px 20px 64px; }
h1 { font-size: 26px; margin: 0 0 4px; }
.meta { color: #9aa4b2; font-size: 14px; margin-bottom: 20px; }
.tiles { display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 28px; }
.tile { flex: 1 1 140px; background: #1a2130; border: 1px solid #2a3344;
  border-radius: 10px; padding: 14px 16px; }
.tile .n { font-size: 28px; font-weight: 700; }
.tile .l { color: #9aa4b2; font-size: 13px; }
.card { background: #1a2130; border: 1px solid #2a3344; border-radius: 12px;
  padding: 18px 20px; margin-bottom: 18px; }
.card h2 { font-size: 18px; margin: 0 0 10px; display: flex; align-items: center;
  justify-content: space-between; gap: 12px; }
.badge { font-size: 12px; font-weight: 700; padding: 4px 10px; border-radius: 999px;
  white-space: nowrap; }
.b-safe { background: #16351f; color: #8ff0a4; }
.b-vulnerable { background: #3a1620; color: #ff8ba0; }
.b-verified { background: #16351f; color: #8ff0a4; }
.b-needs_review { background: #3a2f12; color: #ffd480; }
.row { font-size: 14px; margin: 4px 0; }
.k { color: #9aa4b2; }
pre { background: #0c111b; border: 1px solid #2a3344; border-radius: 8px;
  padding: 12px; overflow-x: auto; font-size: 12.5px; margin: 10px 0 0; }
.diff .add { color: #8ff0a4; } .diff .del { color: #ff8ba0; }
.checks span { display: inline-block; margin-right: 14px; font-size: 13px; }
.ok { color: #8ff0a4; } .no { color: #ff8ba0; }
"""


def _check(label: str, val: bool) -> str:
    cls = "ok" if val else "no"
    mark = "✓" if val else "✗"
    return f'<span class="{cls}">{mark} {html.escape(label)}</span>'


def _diff_html(diff: str) -> str:
    rows = []
    for ln in diff.splitlines():
        esc = html.escape(ln)
        if ln.startswith("+") and not ln.startswith("+++"):
            rows.append(f'<span class="add">{esc}</span>')
        elif ln.startswith("-") and not ln.startswith("---"):
            rows.append(f'<span class="del">{esc}</span>')
        else:
            rows.append(esc)
    return "\n".join(rows)


def _sast_markdown(sast) -> list[str]:
    if not sast.ran:
        return [f"> **Semgrep (SAST):** skipped — {sast.note}", ""]
    out = [f"## Semgrep (SAST) — {len(sast.findings)} static suspect(s) via {sast.runner}", ""]
    if sast.cross is not None:
        out += ["| Vulnerability | Endpoint | Semgrep | Attack | Verdict |",
                "|---|---|:--:|:--:|---|"]
        for r in sast.cross.rows:
            verdict = {"confirmed-by-both": "real bug (both agree)",
                       "static-only": "likely false positive",
                       "dynamic-only": "**SAST missed — caught only by active attack**"}[r.verdict]
            out.append(f"| {r.vuln_class} | `{r.endpoint}` | "
                       f"{'✅' if r.static else '—'} | {'✅' if r.dynamic else '—'} | {verdict} |")
        out.append("")
    return out


def render_html(outcomes: list[Outcome], base_url: str, offline: bool, sast=None) -> str:
    c = _counts(outcomes)
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    cards = []
    for o in outcomes:
        f = o.finding
        status = o.status
        title = CLASS_TITLES.get(f.vuln_class, f.vuln_class)
        parts = [
            '<div class="card">',
            f'<h2>{html.escape(title)}'
            f'<span class="badge b-{status}">{STATUS_LABEL[status]}</span></h2>',
            f'<div class="row"><span class="k">Endpoint:</span> '
            f'<code>{html.escape(f.method)} {html.escape(f.endpoint)}</code> '
            f'<span class="k">severity</span> {html.escape(f.severity)}</div>',
            f'<div class="row"><span class="k">Evidence:</span> {html.escape(f.detail)}</div>',
            f'<div class="row"><span class="k">Response:</span> '
            f'status {f.response.get("status")}</div>',
            f'<div class="row k">Reproduce:</div><pre>{html.escape(f.curl)}</pre>',
        ]
        if o.result and f.confirmed:
            r = o.result
            last = r.attempts[-1].verify if r.attempts and r.attempts[-1].verify else None
            if last:
                parts.append(
                    '<div class="row checks" style="margin-top:12px">'
                    + _check("app starts", last.app_starts)
                    + _check("attack blocked", last.attack_blocked)
                    + _check("good path preserved", last.good_path_ok)
                    + f'<span class="k">attempts: {len(r.attempts)}</span></div>')
                if not last.good_path_ok and last.good_path.failures:
                    broken = ", ".join(x.name for x in last.good_path.failures)
                    parts.append(f'<div class="row no">Broken good-path checks: '
                                 f'{html.escape(broken)}</div>')
            if sast is not None and f.vuln_class in sast.cleared:
                parts.append('<div class="row checks">'
                             + _check("Semgrep finding cleared", sast.cleared[f.vuln_class])
                             + '</div>')
            if r.diff:
                parts.append('<div class="row k" style="margin-top:12px">Applied fix (diff):</div>')
                parts.append(f'<pre class="diff">{_diff_html(r.diff)}</pre>')
        parts.append('</div>')
        cards.append("\n".join(parts))

    tiles = (
        f'<div class="tile"><div class="n">{c["confirmed"]}</div>'
        '<div class="l">vulnerabilities confirmed</div></div>'
        f'<div class="tile"><div class="n ok">{c["verified"]}</div>'
        '<div class="l">fixed &amp; verified</div></div>'
        f'<div class="tile"><div class="n">{c["needs_review"]}</div>'
        '<div class="l">need human review</div></div>'
    )
    src = "template (offline)" if offline else "LLM (claude)"
    sast_html = _sast_html(sast) if sast is not None else ""
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Attack-Fix-Verify Report</title><style>{_CSS}</style></head>
<body><div class="wrap">
<h1>Attack-Fix-Verify Report</h1>
<div class="meta">Target <code>{html.escape(base_url)}</code> · {now} · patches from {src}</div>
<div class="tiles">{tiles}</div>
{sast_html}
{''.join(cards)}
</div></body></html>"""


def _sast_html(sast) -> str:
    if not sast.ran:
        return (f'<div class="card"><h2>Semgrep (SAST)</h2>'
                f'<div class="row k">Skipped — {html.escape(sast.note)}</div></div>')
    rows = ""
    if sast.cross is not None:
        trs = []
        for r in sast.cross.rows:
            verdict, cls = {
                "confirmed-by-both": ("real bug (both agree)", "ok"),
                "static-only": ("likely false positive", "k"),
                "dynamic-only": ("SAST missed — caught only by active attack", "no"),
            }[r.verdict]
            trs.append(
                f'<tr><td>{html.escape(r.vuln_class)}</td>'
                f'<td><code>{html.escape(r.endpoint)}</code></td>'
                f'<td style="text-align:center">{"✓" if r.static else "—"}</td>'
                f'<td style="text-align:center">{"✓" if r.dynamic else "—"}</td>'
                f'<td class="{cls}">{html.escape(verdict)}</td></tr>')
        rows = ("<table style='width:100%;border-collapse:collapse;font-size:13.5px'>"
                "<tr style='color:#9aa4b2;text-align:left'>"
                "<th>Vulnerability</th><th>Endpoint</th><th>Semgrep</th>"
                "<th>Attack</th><th>Verdict</th></tr>" + "".join(trs) + "</table>")
    return (f'<div class="card"><h2>Semgrep (SAST) '
            f'<span class="badge b-safe">{len(sast.findings)} suspects · {html.escape(sast.runner)}</span></h2>'
            f'<div class="row k">Static analysis vs. active attacks:</div>{rows}</div>')
