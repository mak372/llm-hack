# Attack-Fix-Verify — an autonomous security agent for AI-generated APIs

AI now writes API code faster than anyone can security-test it. The usual loop is a human finds a bug, another human fixes it, someone re-tests this can't keep up.

This project is an **autonomous agent that closes that loop by itself**: it
attacks a running API, confirms real vulnerabilities with evidence, uses an LLM
to propose a fix, **proves the fix by re-running the exact attack**, and then
opens a GitHub pull request with the patch, regression tests, and the evidence.

> ### The core idea:
> The LLM only **proposes** a patch. Whether a fix actually works is decided by
> plain, deterministic code that re-runs the original exploit. An LLM's opinion
> can never mark something "fixed." If the re-attack still succeeds, the fix is
> rejected — no matter how confident the model was.

---

## How it works — the loop

```
         ┌───────────────────────────────────────────────────────────────┐
         │                     running API (target app)                   │
         └───────────────────────────────────────────────────────────────┘
                 ▲                                            │
   (1) ATTACK    │ real HTTP exploits                 responses + evidence
   deterministic │                                            ▼
         ┌───────┴───────┐   (2) FLAG        ┌─────────────────────────────┐
         │ attack engine │ ───────────────▶  │ confirmed findings + curl    │
         └───────────────┘                   └─────────────────────────────┘
                                                           │
                              (3) FIX  (the only LLM step) │ narrow context:
                                                           ▼ one handler + evidence
         ┌─────────────────────────────────────────────────────────────┐
         │ LLM proposes a minimal patch  →  applied to a *working copy*  │
         └─────────────────────────────────────────────────────────────┘
                                                           │
   (4) VERIFY     deterministic - the authority            ▼
         ┌─────────────────────────────────────────────────────────────┐
         │ re-run the EXACT attack  +  good-path still works  +  app runs│
         │   all three pass → "verified"   |   else → retry (max 3)      │
         └─────────────────────────────────────────────────────────────┘
                                                           │ verified
   (5) PUBLISH                                             ▼
         ┌─────────────────────────────────────────────────────────────┐
         │ open a GitHub PR: patch + regression tests + evidence report  │
         └─────────────────────────────────────────────────────────────┘
```

**Only step 3 uses an LLM.** Steps 1, 2, 4 are ordinary Python. Attacking is
dynamic testing (DAST) it probes the running app's behavior, not its source.

### Step by step

1. **ATTACK** (`engine/attacks.py`) - behaves like a real attacker over HTTP:
   logs in as one user to read another's data, injects SQL, calls protected
   endpoints with no token, etc. It decides "vulnerable" by **comparing the
   actual response** (e.g. "did Bob get back a record he doesn't own?").
2. **FLAG** — each confirmed exploit becomes a structured finding: the request,
   the response, and a copy-pasteable `curl` to reproduce it.
3. **FIX** (`engine/fixer.py`) - the tool extracts **only the one vulnerable
   handler** (via the AST) and asks an LLM for a minimal rewrite of *that
   function only*. The proposal is validated (same function, same route, no new
   imports) and applied to a **working copy** the original file is backed up
   and never touched directly.
4. **VERIFY** (`engine/verifier.py`) - **no LLM here.** A fix counts as verified
   only if all three hold on the patched app:
   - the **exact original attack now fails**,
   - the **good path still works** (e.g. the real owner can still read their own
     record, this stops the LLM from "fixing" by breaking the endpoint), and
   - the **app still starts**.

   If verification fails, the reason is fed back to the LLM and it retries, up to
   3 times, then the finding is marked **"needs human review."**
5. **PUBLISH** (`engine/publisher.py`) - for verified fixes, the agent opens a
   **GitHub pull request** (via the REST API) carrying the patch, generated
   pytest regression tests, and an evidence report. The PR body states that every
   claim was confirmed by re-attack, not by an LLM.

---

## The four vulnerability classes

The bundled demo app has one deliberate bug per class:

| Class | Demo endpoint | How it's attacked | Verified fixed when |
|-------|---------------|-------------------|---------------------|
| Broken access control (IDOR) | `GET /invoices/<id>` | Bob requests Alice's invoice | non-owner gets 403/404, owner still 200 |
| SQL injection | `GET /invoices/search?q=` | `' OR 1=1 --` | injection returns no other users' rows |
| Sensitive data exposure | `GET /me` | inspect response for forbidden fields | `password_hash`/`token`/`ssn` no longer returned |
| Missing authentication | `GET /admin/users` | call with no token | unauthenticated caller gets 401/403 |

Every vulnerable endpoint also has a legitimate "good path," so a fix can't pass
by breaking or deleting the route.

---

## Semgrep: static analysis as a second opinion (`--sast`)

With `--sast`, the agent also runs **Semgrep** (SAST - it reads the code) and
**cross-checks** it against what the attacks actually confirmed (DAST - it probes
behavior):

| Result | Meaning |
|--------|---------|
| Semgrep flagged **and** attack confirmed | high-confidence, real bug |
| Semgrep flagged, attack failed | likely false positive |
| **Attack confirmed, Semgrep silent** | a bug static analysis missed |

On this demo, Semgrep catches the **SQL injection** (a code-pattern bug) but
**misses the IDOR, data exposure, and missing-auth bugs** - authorization/logic
flaws that static rules can't see. That's the point: **static analysis finds
*where the code looks wrong*; the active attacker proves *what's actually
exploitable*.** Semgrep's findings also feed the fix prompt (rule, line, CWE),
and after a fix the code is re-scanned as an extra verification signal.

Semgrep has no native Windows build, so the tool runs it through **Docker**
(auto-detected: local CLI → `python -m semgrep` → Docker → WSL). If no runner is
available it **skips gracefully** - the core loop is never blocked.

---

## Who writes the fix (providers + fallback)

The patch "proposer" is pluggable, so the loop doesn't care who writes the fix:

- **Gemini** (default) — Google `google-genai`; reads `GEMINI_API_KEY`, model via
  `GEMINI_MODEL` (default `gemini-3.6-flash`).
- **Anthropic** - `--provider anthropic`; `claude-opus-5-5`, reads `ANTHROPIC_API_KEY`.
- **Template** - `--offline`; deterministic known-good patches, no API key, no network.

If the chosen LLM is unavailable (missing key, unknown model, 503, network
error), the agent **automatically falls back to the deterministic template
patches** and prints a clear note — so the workflow never stops, and you always
know whether a patch came from the LLM or the fallback.

---

## Repository layout

```
target_app/app.py      deliberately vulnerable Flask + SQLite app (staging/test ONLY)
engine/attacks.py      the 4 attack modules → structured findings + curl
engine/fixer.py        proposers: Gemini / Anthropic / Template + FallbackProposer
engine/codemod.py      extract/replace one handler, validate patch, load patched app
engine/verifier.py     deterministic verdict: app-starts + attack-blocked + good-path
engine/remediate.py    propose → validate → apply(working copy) → verify, 3 retries
engine/sast.py         Semgrep runner, line→endpoint mapping, static-vs-dynamic cross-check
engine/report.py       terminal + HTML/Markdown report
engine/regression.py   emit pytest regression tests from verified fixes
engine/publisher.py    open a GitHub PR (via API) for verified fixes
cli.py                 entry point
tests/                 project test suite (good-path + attacks + engine, 35 tests)
```

---

## Setup

```bash
pip install -r requirements.txt
```

Optional, depending on what you use:
- **Gemini fixer:** a key from https://aistudio.google.com/apikey → set `GEMINI_API_KEY`.
- **Anthropic fixer:** set `ANTHROPIC_API_KEY`.
- **Semgrep (`--sast`):** Docker Desktop running.
- **PR publishing (`--open-pr --push`):** a GitHub repo set as `origin`, and a
  fine-grained token in `GITHUB_TOKEN` (Contents + Pull requests: read/write).

Nothing above is needed to run `--offline` or the test suite.

---

## Usage

```powershell
# Core loop, offline (no key, no Docker): attack → fix (template) → verify → report
python cli.py --code target_app/app.py --offline

# Full loop with Gemini + Semgrep (needs GEMINI_API_KEY and Docker running)
python cli.py --code target_app/app.py --sast

# The finale: also open a GitHub PR with the verified fix (needs GITHUB_TOKEN)
python cli.py --code target_app/app.py --sast --open-pr --push

# Attack a separately running server instead of loading the code in-process
python target_app/app.py            # terminal 1 (serves http://127.0.0.1:5000)
python cli.py --base-url http://localhost:5000 --code target_app/app.py --sast

# Attack only, no fixing
python cli.py --code target_app/app.py --no-fix
```

### Flags

| Flag | Meaning |
|------|---------|
| `--code PATH` | **(required)** the app source to attack/patch |
| `--base-url URL` | attack a live server; default loads `--code` in-process |
| `--provider {gemini,anthropic}` | LLM provider for the fixer (default `gemini`) |
| `--offline` | use deterministic template patches (no key) |
| `--sast` | run Semgrep: pre-scan, cross-check, post-fix rescan |
| `--open-pr` / `--push` | create a fix branch + PR / actually push & open it |
| `--apply` | write verified patches back to `--code` (keeps a `.bak`) |
| `--gen-tests` | emit pytest regression files (`generated_tests/`) |
| `--no-fix` | attack and flag only |
| `--only idor,sqli` | run a subset of classes |
| `--restore` | restore `--code` from its `.bak` |
| `--report PATH` / `--format {html,md}` | report output |

Exit code is non-zero if any confirmed vulnerability wasn't verified-fixed
(useful for CI).

---

## Demo

The demo app lives on `main` in its **vulnerable** state. Each run finds all 4
bugs, as long as you start from the vulnerable app.

```powershell
git checkout -f main                               # ensure the vulnerable app
python cli.py --code target_app/app.py --sast      # attack → fix → verify (+ Semgrep)
# finale — open a real PR:
python cli.py --code target_app/app.py --sast --open-pr --push
git checkout -f main                               # reset before the next run
```

`--open-pr`/`--apply` modify `app.py` and leave you on a fix branch, so run
`git checkout -f main` before demoing again. The plain `--sast` command changes
nothing and is freely repeatable.

---

## Tests

```bash
python -m pytest tests/ -q
```

The suite proves the parts that matter including that a fix which blocks the
attack **but breaks the good path is rejected**, and that the retry loop recovers
from a bad first proposal.

---

```
