# HTTP Security Headers & TLS Auditor

A defensive web security auditing CLI built with Python's standard library (`urllib`, `ssl`, `socket`) that inspects HTTP response security headers and evaluates TLS/X.509 certificate posture.

## Features

- **HTTP Security Header Checks**: Audits `Strict-Transport-Security`, `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, and `Permissions-Policy`.
- **Weighted Security Scoring**: Computes a `0–100` score and assigns an `A–F` hardening grade with actionable remediation advice for missing headers.
- **TLS & Certificate Inspection**: Verifies negotiated TLS protocol version, cipher suite, bit strength, certificate issuer/subject Common Name, and days remaining until expiration.
- **JSON Reporting**: Exports structured findings via `--json-out`.

## Quick Start

```bash
# Run an audit
python -m tls_header_auditor.auditor https://example.com

# Export JSON report
python -m tls_header_auditor.auditor https://example.com --json-out audit_report.json

# Run unit tests
python -m unittest discover -s tests
```

## Push to GitHub

This repository is pre-configured with `.gitignore`, `LICENSE`, `README.md`, and GitHub Actions CI. To publish to GitHub:

```bash
cd http-tls-security-auditor
git init -b main
git add .
git commit -m "feat: initial HTTP security headers and TLS auditor"
git remote add origin https://github.com/<your-username>/http-tls-security-auditor.git
git push -u origin main
```
