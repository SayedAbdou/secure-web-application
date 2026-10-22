# Security Policy

## About this project

This repository is a **reference implementation** of secure coding patterns. It is intended as educational material and a starting point — not as a production-ready service.

## If you find a vulnerability in this code

Email: work@sayedabdou.com — subject `[secure-web-application] Security Issue`.

Include the affected file, a reproduction, and suggested fix. No public issues for security findings; I respond within 72 hours.

## If you deploy this code

- Set a strong `SECRET_KEY` from the environment (never hardcoded, never in git).
- Serve behind a TLS-terminating proxy.
- Review the "Intentionally not included" section of the README — password reset, file uploads, and admin panels need their own hardened designs.
