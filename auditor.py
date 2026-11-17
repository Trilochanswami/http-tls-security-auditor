import argparse
import json
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional


SECURITY_HEADERS: Dict[str, dict] = {
    "Strict-Transport-Security": {
        "weight": 20,
        "recommendation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'.",
    },
    "Content-Security-Policy": {
        "weight": 25,
        "recommendation": "Define a strict Content-Security-Policy to mitigate XSS and data injection.",
    },
    "X-Content-Type-Options": {
        "weight": 15,
        "recommendation": "Set 'X-Content-Type-Options: nosniff' to block MIME-type sniffing.",
    },
    "X-Frame-Options": {
        "weight": 15,
        "recommendation": "Set 'X-Frame-Options: DENY' or 'SAMEORIGIN' to prevent clickjacking.",
    },
    "Referrer-Policy": {
        "weight": 15,
        "recommendation": "Set 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'.",
    },
    "Permissions-Policy": {
        "weight": 10,
        "recommendation": "Restrict sensitive browser APIs via Permissions-Policy.",
    },
}


@dataclass
class HeaderFinding:
    header: str
    present: bool
    value: Optional[str]
    weight: int
    recommendation: str


@dataclass
class TLSProfile:
    enabled: bool
    protocol_version: Optional[str]
    cipher_suite: Optional[str]
    cipher_bits: Optional[int]
    subject_cn: Optional[str]
    issuer_cn: Optional[str]
    not_after: Optional[str]
    days_remaining: Optional[int]
    error: Optional[str] = None


@dataclass
class AuditReport:
    target_url: str
    status_code: int
    security_score: int
    grade: str
    headers: List[HeaderFinding]
    tls: TLSProfile


def normalize_url(raw_url: str) -> str:
    cleaned = raw_url.strip()
    if not cleaned.startswith(("http://", "https://")):
        cleaned = "https://" + cleaned
    parsed = urllib.parse.urlparse(cleaned)
    if not parsed.hostname:
        raise ValueError(f"Invalid target URL: {raw_url}")
    return cleaned


def _extract_cn(rdn_tuple: tuple) -> Optional[str]:
    for group in rdn_tuple:
        for key, val in group:
            if key == "commonName":
                return val
    return None


def inspect_tls(hostname: str, port: int = 443, timeout: float = 6.0) -> TLSProfile:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=hostname) as tls_sock:
                cert = tls_sock.getpeercert() or {}
                cipher_info = tls_sock.cipher() or (None, None, None)
                not_after_str = cert.get("notAfter")
                days_left = None
                if not_after_str:
                    expiry = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(
                        tzinfo=timezone.utc
                    )
                    days_left = (expiry - datetime.now(timezone.utc)).days

                return TLSProfile(
                    enabled=True,
                    protocol_version=tls_sock.version(),
                    cipher_suite=cipher_info[0],
                    cipher_bits=cipher_info[2],
                    subject_cn=_extract_cn(cert.get("subject", ())),
                    issuer_cn=_extract_cn(cert.get("issuer", ())),
                    not_after=not_after_str,
                    days_remaining=days_left,
                )
    except Exception as exc:
        return TLSProfile(
            enabled=False,
            protocol_version=None,
            cipher_suite=None,
            cipher_bits=None,
            subject_cn=None,
            issuer_cn=None,
            not_after=None,
            days_remaining=None,
            error=str(exc),
        )


def compute_grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def run_audit(url: str, timeout: float = 8.0) -> AuditReport:
    target = normalize_url(url)
    parsed = urllib.parse.urlparse(target)
    hostname = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    req = urllib.request.Request(
        target,
        method="GET",
        headers={"User-Agent": "TLS-Header-Auditor/1.0 (Defensive Security Check)"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status_code = resp.getcode()
            raw_headers = {k.lower(): v for k, v in resp.headers.items()}
    except urllib.error.HTTPError as http_err:
        status_code = http_err.code
        raw_headers = {k.lower(): v for k, v in http_err.headers.items()}

    findings: List[HeaderFinding] = []
    earned_score = 0
    for header_name, meta in SECURITY_HEADERS.items():
        val = raw_headers.get(header_name.lower())
        present = val is not None
        if present:
            earned_score += meta["weight"]
        findings.append(
            HeaderFinding(
                header=header_name,
                present=present,
                value=val,
                weight=meta["weight"],
                recommendation="Configured" if present else meta["recommendation"],
            )
        )

    if parsed.scheme == "https":
        tls_profile = inspect_tls(hostname, port=port, timeout=timeout)
    else:
        tls_profile = TLSProfile(
            enabled=False,
            protocol_version=None,
            cipher_suite=None,
            cipher_bits=None,
            subject_cn=None,
            issuer_cn=None,
            not_after=None,
            days_remaining=None,
            error="Target uses plain HTTP without TLS.",
        )

    return AuditReport(
        target_url=target,
        status_code=status_code,
        security_score=earned_score,
        grade=compute_grade(earned_score),
        headers=findings,
        tls=tls_profile,
    )


def render_report(report: AuditReport) -> None:
    print("=" * 72)
    print(f"Target URL     : {report.target_url}")
    print(f"HTTP Status    : {report.status_code}")
    print(f"Security Score : {report.security_score}/100 (Grade: {report.grade})")
    print("=" * 72)

    print("\n[1] HTTP Response Security Headers")
    print("-" * 72)
    for item in report.headers:
        badge = "[PASS]" if item.present else "[MISS]"
        detail = item.value if item.present else item.recommendation
        print(f"{badge} {item.header:<28} | {detail}")

    print("\n[2] TLS / X.509 Certificate Inspection")
    print("-" * 72)
    if report.tls.enabled:
        print(f"TLS Version    : {report.tls.protocol_version}")
        print(f"Cipher Suite   : {report.tls.cipher_suite} ({report.tls.cipher_bits} bits)")
        print(f"Subject CN     : {report.tls.subject_cn}")
        print(f"Issuer CN      : {report.tls.issuer_cn}")
        print(f"Expires On     : {report.tls.not_after} ({report.tls.days_remaining} days left)")
    else:
        print(f"TLS Status     : Inactive / Error ({report.tls.error})")
    print("=" * 72)


def build_cli() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Inspect HTTP security headers and TLS configuration of a target URL."
    )
    parser.add_argument("url", help="Target URL or domain (e.g., https://example.com)")
    parser.add_argument("--timeout", type=float, default=8.0, help="Request timeout in seconds")
    parser.add_argument("--json-out", type=Path, default=None, help="Optional JSON report path")
    return parser


def main() -> None:
    args = build_cli().parse_args()
    report = run_audit(args.url, timeout=args.timeout)
    render_report(report)

    if args.json_out:
        args.json_out.write_text(json.dumps(asdict(report), indent=2), encoding="utf-8")
        print(f"Saved JSON report to {args.json_out}")


if __name__ == "__main__":
    main()
