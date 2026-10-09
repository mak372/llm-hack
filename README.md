# Attack-Fix-Verify for AI-generated APIs

AI writes API code faster than teams can security-test it. This tool automates
the whole loop against a **running** API:

1. **ATTACK** — actively exploit the app for 4 vulnerability classes.
2. **FLAG** — report confirmed vulnerabilities with evidence + a curl repro.
3. **FIX** — an LLM proposes a minimal patch for the one vulnerable handler.
4. **VERIFY** — re-run the *exact* attack against the patched app to prove it.

> **We don't trust the AI's fix. We trust the re-attack.** The LLM only
> *proposes* patches. Plain deterministic code decides pass/fail — an LLM
> judgement can never mark something "fixed".

## The four vulnerability classes

| Class | Demo endpoint | Attacked by | Verified fixed when |
|-------|---------------|-------------|---------------------|
| Broken access control (IDOR) | `GET /invoices/<id>` | Bob requests Alice's invoice | non-owner gets 403/404, owner still 200 |
| SQL injection | `GET /invoices/search?q=` | `' OR 1=1 --` | injection returns no other users' rows |
| Sensitive data exposure | `GET /me` | inspect response fields | `password_hash`/`token`/`ssn` gone |
| Missing authentication | `GET /admin/users` | call with no token | unauthenticated gets 401/403 |

Only the **FIX** step uses an LLM. ATTACK and VERIFY are ordinary Python (DAST).

## Layout

```
target_app/app.py     deliberately vulnerable Flask + SQLite app (staging/test only)
engine/attacks.py     the 4 attack modules -> structured findings + curl
engine/fixer.py       LLM / template patch proposers + per-class fix templates
engine/codemod.py     extract/replace one handler, validate patch, load patched app
engine/verifier.py    deterministic verdict: app-starts + attack-blocked + good-path
engine/remediate.py   propose -> validate -> apply(working copy) -> verify, 3 retries
engine/report.py      terminal + HTML/Markdown report
engine/regression.py  emit pytest regression tests from verified fixes
cli.py                entry point
tests/                project test suite (good-path + attack + engine)
```

## Setup

```bash
pip install -r requirements.txt
```

The LLM fixer uses `claude-opus-5-5` via the Anthropic API; set `ANTHROPIC_API_KEY`.
Everything also runs **offline** with `--offline` (deterministic template patches, no key).

## Run

```bash
# Offline: attack the app in-process, fix with templates, write report.html
python cli.py --code target_app/app.py --offline

# Attack a running server, fix with the LLM, apply verified patches, emit tests
python target_app/app.py            # in one terminal (serves :5000)
python cli.py --base-url http://localhost:5000 --code target_app/app.py --apply --gen-tests

# Attack only (no fixing)
python cli.py --code target_app/app.py --no-fix

# Undo applied patches
python cli.py --code target_app/app.py --restore
```

Key flags: `--offline` (no API key), `--only idor,sqli`, `--apply` (write verified
patches back, keeps a `.bak`), `--gen-tests` (pytest regression files in
`generated_tests/`), `--format html|md`. Exit code is non-zero if any confirmed
vulnerability was not verified-fixed (useful for CI).

## Tests

```bash
python -m pytest tests/ -q
```

## Scope & honesty

Only these 4 classes, REST APIs with token auth, for **staging/test** environments
— never production. "Verified" means the attacks we tried no longer work, not that
the code is provably secure.
