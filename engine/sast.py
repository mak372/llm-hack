"""Semgrep (SAST) layer: static evidence that complements the dynamic attacks.

Four roles (all optional -- the core loop runs fine without Semgrep):
  1. Pre-scan: list static "suspects" (file, line, rule, CWE/OWASP) before attacking.
  2. Cross-check: compare static findings with what the attacks actually confirmed
     -- the "attack confirmed, Semgrep silent" row is the pitch for needing DAST.
  3. Fix context: hand the rule id/line/message to the LLM advisor as grounding.
  4. Re-verify: after a fix, the static finding should also be gone.

Semgrep has no native Windows CLI, so a runner is auto-detected in this order:
local `semgrep` on PATH, `python -m semgrep`, Docker, then WSL. If none is
available, run_semgrep raises SastUnavailable and callers skip gracefully.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field

from engine import codemod
from engine.findings import Finding

DEFAULT_CONFIGS = ["p/python", "p/flask", "p/owasp-top-ten"]

# Keyword -> our vuln_class, used to line Semgrep rules up with our attacks.
_CLASS_KEYWORDS = {
    "sqli": ("sql", "injection", "sqli", "formatted-sql", "tainted-sql"),
    "data_exposure": ("password", "secret", "sensitive", "pii", "token", "hardcoded"),
    "missing_auth": ("auth", "login_required", "unauthenticated", "access-control",
                     "authorization"),
    # idor (broken object-level authorization) is intentionally absent: generic
    # static rules almost never catch it -- that gap is the demo's point.
}


class SastUnavailable(RuntimeError):
    """Raised when no Semgrep runner is available on this machine."""


@dataclass
class SastData:
    """Everything the report needs about the Semgrep run (or its absence)."""
    ran: bool = False
    runner: str = ""
    note: str = ""
    findings: list = field(default_factory=list)      # list[StaticFinding] (pre-scan)
    cross: "CrossCheck | None" = None
    cleared: dict = field(default_factory=dict)       # vuln_class -> bool (post-fix rescan)


@dataclass
class StaticFinding:
    check_id: str
    path: str
    start_line: int
    end_line: int
    severity: str
    message: str
    cwe: list[str] = field(default_factory=list)
    owasp: list[str] = field(default_factory=list)
    vuln_class: str | None = None     # mapped from the rule, or None
    endpoint: str | None = None       # mapped from file:line via AST, or None

    def to_dict(self) -> dict:
        from dataclasses import asdict
        return asdict(self)


# --------------------------------------------------------------------------
# Runner detection
# --------------------------------------------------------------------------
@dataclass
class Runner:
    kind: str                         # "local" | "module" | "docker" | "wsl"
    argv_prefix: list[str]            # command that accepts `scan --json ...`
    mount_dir: str | None = None      # for docker: host dir mounted at /src


def _has(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def _to_wsl_path(win_path: str) -> str:
    """Translate a Windows path (C:\\a\\b) to its WSL mount path (/mnt/c/a/b)."""
    p = os.path.abspath(win_path)
    drive, rest = os.path.splitdrive(p)
    if drive:
        return "/mnt/" + drive[0].lower() + rest.replace("\\", "/")
    return p.replace("\\", "/")


def _ok(argv: list[str], timeout: int = 15) -> bool:
    """True if the command runs and exits 0 (used to confirm a runner is usable)."""
    try:
        return subprocess.run(argv, capture_output=True, timeout=timeout).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def detect_runner(target_dir: str | None = None) -> Runner | None:
    """Find a way to run Semgrep that actually works, or None.

    Only returns a runner that passed a liveness check, so a dead Docker daemon
    or a WSL without Semgrep falls through instead of failing mid-scan.
    """
    if _has("semgrep"):
        return Runner("local", ["semgrep"])
    try:
        import importlib.util
        if importlib.util.find_spec("semgrep") is not None:
            return Runner("module", [sys.executable, "-m", "semgrep"])
    except Exception:
        pass
    if _has("docker") and target_dir and _ok(["docker", "info"]):
        mount = os.path.abspath(target_dir)
        return Runner(
            "docker",
            ["docker", "run", "--rm", "-v", f"{mount}:/src", "semgrep/semgrep", "semgrep"],
            mount_dir=mount,
        )
    if _has("wsl") and _ok(["wsl", "-e", "sh", "-c", "command -v semgrep"]):
        return Runner("wsl", ["wsl", "semgrep"])
    return None


# --------------------------------------------------------------------------
# Running + parsing
# --------------------------------------------------------------------------
def run_semgrep(target: str, configs: list[str] | None = None,
                runner: Runner | None = None, timeout: int = 180) -> list[StaticFinding]:
    """Scan `target` (a file or dir) and return parsed static findings.

    Raises SastUnavailable if no runner exists or Semgrep fails to execute.
    """
    configs = configs or DEFAULT_CONFIGS
    target = os.path.abspath(target)
    target_dir = target if os.path.isdir(target) else os.path.dirname(target)
    runner = runner or detect_runner(target_dir)
    if runner is None:
        raise SastUnavailable(
            "no Semgrep runner found (tried PATH, python -m, Docker, WSL)")

    scan_target = target
    if runner.kind == "docker":
        # Translate host path to the mounted /src path.
        rel = os.path.relpath(target, runner.mount_dir).replace(os.sep, "/")
        scan_target = "/src/" + rel
    elif runner.kind == "wsl":
        scan_target = _to_wsl_path(target)

    argv = list(runner.argv_prefix) + ["scan", "--json", "--error", "--quiet"]
    for c in configs:
        argv += ["--config", c]
    argv.append(scan_target)

    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SastUnavailable(f"Semgrep failed to run: {exc}") from exc

    # Semgrep exits non-zero when findings exist (with --error); that's fine as
    # long as we got JSON. A hard failure yields no parseable stdout.
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise SastUnavailable(
            f"Semgrep produced no JSON (exit {proc.returncode}): "
            f"{proc.stderr.strip()[:300]}") from exc

    # Semgrep (in Docker/WSL) reports container/Linux paths, but we need the real
    # local source to map a line to an endpoint. For a single-file scan we know
    # that file, so read it directly regardless of the reported path.
    if os.path.isfile(target):
        local_src = _file_source_lookup(target)
        lookup = lambda _path: local_src  # noqa: E731
    else:
        lookup = _file_source_lookup
    return parse_results(data, lookup)


def map_vuln_class(check_id: str, message: str) -> str | None:
    hay = f"{check_id} {message}".lower()
    for vuln_class, keywords in _CLASS_KEYWORDS.items():
        if any(k in hay for k in keywords):
            return vuln_class
    return None


def _as_list(v) -> list[str]:
    if v is None:
        return []
    return [str(x) for x in v] if isinstance(v, (list, tuple)) else [str(v)]


def _file_source_lookup(path: str) -> str | None:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return None


def parse_results(data: dict, source_lookup=_file_source_lookup) -> list[StaticFinding]:
    """Turn Semgrep JSON into StaticFindings, mapping each to a vuln class and,
    via the AST glue, to the endpoint whose handler contains the flagged line."""
    out: list[StaticFinding] = []
    for r in data.get("results", []):
        extra = r.get("extra", {})
        meta = extra.get("metadata", {})
        check_id = r.get("check_id", "")
        message = extra.get("message", "")
        sf = StaticFinding(
            check_id=check_id,
            path=r.get("path", ""),
            start_line=r.get("start", {}).get("line", 0),
            end_line=r.get("end", {}).get("line", 0),
            severity=extra.get("severity", ""),
            message=message,
            cwe=_as_list(meta.get("cwe")),
            owasp=_as_list(meta.get("owasp")),
            vuln_class=map_vuln_class(check_id, message),
        )
        src = source_lookup(sf.path) if source_lookup else None
        if src and sf.start_line:
            try:
                handler = codemod.find_handler_containing_line(src, sf.start_line)
                if handler and handler.routes:
                    sf.endpoint = handler.routes[0]
            except SyntaxError:
                pass
        out.append(sf)
    return out


# --------------------------------------------------------------------------
# Cross-check (static vs dynamic)
# --------------------------------------------------------------------------
@dataclass
class CrossRow:
    vuln_class: str
    endpoint: str
    static: bool
    dynamic: bool

    @property
    def verdict(self) -> str:
        if self.static and self.dynamic:
            return "confirmed-by-both"          # high confidence, real bug
        if self.static and not self.dynamic:
            return "static-only"                # likely false positive
        return "dynamic-only"                   # SAST missed it (the pitch)


@dataclass
class CrossCheck:
    rows: list[CrossRow] = field(default_factory=list)

    @property
    def both(self):
        return [r for r in self.rows if r.verdict == "confirmed-by-both"]

    @property
    def static_only(self):
        return [r for r in self.rows if r.verdict == "static-only"]

    @property
    def dynamic_only(self):
        return [r for r in self.rows if r.verdict == "dynamic-only"]


def cross_check(static: list[StaticFinding], dynamic: list[Finding]) -> CrossCheck:
    """Compare static findings with the attacks that actually confirmed.

    Keyed by vuln_class. Produces one row per class seen by either side:
    both -> real bug; static-only -> likely FP; dynamic-only -> static missed.
    """
    confirmed = {f.vuln_class: f for f in dynamic if f.confirmed}
    static_by_class: dict[str, StaticFinding] = {}
    for s in static:
        if s.vuln_class and s.vuln_class not in static_by_class:
            static_by_class[s.vuln_class] = s

    cc = CrossCheck()
    for vc in sorted(set(confirmed) | set(static_by_class)):
        dyn = confirmed.get(vc)
        sta = static_by_class.get(vc)
        endpoint = (dyn.endpoint if dyn else None) or (sta.endpoint if sta else "") or ""
        cc.rows.append(CrossRow(vuln_class=vc, endpoint=endpoint,
                                static=sta is not None, dynamic=dyn is not None))
    return cc


def semgrep_context_for(finding: Finding, static: list[StaticFinding]) -> str | None:
    """A short grounding string for the fix prompt, if Semgrep flagged this class."""
    for s in static:
        if s.vuln_class == finding.vuln_class:
            cwe = f" ({', '.join(s.cwe)})" if s.cwe else ""
            return f"Semgrep {s.check_id} at {s.path}:{s.start_line}{cwe}: {s.message}"
    return None
