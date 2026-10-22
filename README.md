# Secure Web Application

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-green.svg)](app.py)
[![CI](https://github.com/SayedAbdou/secure-web-application/actions/workflows/ci.yml/badge.svg)](https://github.com/SayedAbdou/secure-web-application/actions)

A reference Flask application demonstrating how to build web apps that resist the most common attack classes — with an automated test suite that **proves each protection works**.

## Control → code → test mapping

| Vulnerability | Control in this app | Code | Test |
|---|---|---|---|
| SQL Injection | Parameterized queries only (`?` placeholders) | `app.py: register/search/dashboard` | `test_sqli_in_search_is_parameterized` |
| XSS | Jinja auto-escaping + CSP without `'unsafe-inline'` | `templates/`, `add_security_headers` | `test_xss_escaped_on_dashboard` |
| CSRF | Per-session token, validated on every POST (constant-time compare) | `validate_csrf` | `test_post_without_csrf_rejected`, `test_post_with_wrong_csrf_rejected` |
| Broken auth | PBKDF2 password hashing (werkzeug, salted) | `generate_password_hash` | `test_password_stored_hashed` |
| Session fixation | Session regeneration on login | `session.clear()` in `login` | covered in flow tests |
| User enumeration | Identical error for unknown user / wrong password | `login` | `test_login_wrong_password_same_error_as_unknown_user` |
| Brute force | Per-IP rate limiting + lockout (429) | `rate_limited` | `test_login_rate_limited_after_five_failures` |
| Weak passwords | Minimum length policy, client + server side | `register` | `test_weak_password_rejected` |
| Session hijacking | `HttpOnly` + `SameSite=Lax` + `Secure` cookies | `app.config` | `test_session_cookie_flags` |
| Missing authZ | `@login_required` on protected views | `login_required` | `test_profile_requires_authentication` |
| Clickjacking | `X-Frame-Options: DENY` + CSP `frame-ancestors` | `add_security_headers` | `test_security_headers_present` |

## Run it

```bash
pip install -r requirements.txt
python app.py            # http://127.0.0.1:5000
```

Set `SECRET_KEY` in the environment for anything beyond local use.

## Run the security tests

```bash
pytest -v
```

Every test is a security assertion — if a control breaks, its test fails.

## Intentionally not included

This repo deliberately does **not** implement: password reset flows, file uploads, payment logic, or admin panels. Each of those deserves its own hardened design (and its own tests) — this reference stays focused on the core patterns that fix the most common vulnerabilities.

## License

MIT — see [LICENSE](LICENSE).
