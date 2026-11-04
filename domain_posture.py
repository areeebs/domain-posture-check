#!/usr/bin/env python3
"""Read-only HTTPS and DNS posture checks for one explicitly named public domain."""

from __future__ import annotations

import argparse
import datetime as dt
import http.client
import ipaddress
import json
import math
import re
import socket
import ssl
import sys
from dataclasses import asdict, dataclass
from typing import Callable


VERSION = "0.1.0"
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    title: str
    detail: str
    recommendation: str


@dataclass(frozen=True)
class AuditResult:
    hostname: str
    addresses: list[str]
    http_status: int
    tls_version: str
    certificate_expires: str
    certificate_days_remaining: int
    findings: list[Finding]


class ScanError(ValueError):
    """Input, DNS, or connection error that prevents a meaningful report."""


def normalize_domain(value: str) -> str:
    candidate = value.strip()
    if not candidate or any(char in candidate for char in ":/@?#\\"):
        raise ScanError("Enter a hostname only, such as example.com; URLs, paths, and ports are not accepted.")
    if candidate.endswith(".."):
        raise ScanError("A fully qualified hostname may have at most one trailing dot.")
    candidate = candidate.rstrip(".")
    try:
        hostname = candidate.encode("idna").decode("ascii").lower()
    except UnicodeError as error:
        raise ScanError("The hostname is not valid IDNA text.") from error
    if len(hostname) > 253 or "." not in hostname:
        raise ScanError("Enter a fully qualified public domain name.")
    labels = hostname.split(".")
    if any(not label or len(label) > 63 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) for label in labels):
        raise ScanError("The hostname contains an invalid DNS label.")
    if hostname == "localhost" or hostname.endswith((".localhost", ".local", ".internal", ".test", ".invalid")):
        raise ScanError("Local and reserved hostnames are not accepted.")
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        return hostname
    raise ScanError("Enter a DNS hostname, not an IP address.")


def resolve_public_addresses(hostname: str) -> list[str]:
    try:
        answers = socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
    except OSError as error:
        raise ScanError(f"DNS lookup failed: {error}") from error
    addresses = sorted({answer[4][0] for answer in answers})
    if not addresses:
        raise ScanError("DNS returned no IPv4 or IPv6 address for this hostname.")
    for address in addresses:
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError as error:
            raise ScanError("DNS returned an invalid address.") from error
        if not parsed.is_global:
            raise ScanError(f"DNS for {hostname} includes a non-public address; refusing to connect.")
    return addresses


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connect to a previously validated IP while preserving TLS SNI and hostname checks."""

    def __init__(self, hostname: str, address: str, timeout: float, context: ssl.SSLContext):
        super().__init__(hostname, 443, timeout=timeout, context=context)
        self._pinned_address = address

    def connect(self) -> None:
        raw = socket.create_connection((self._pinned_address, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


def fetch_https(hostname: str, address: str, timeout: float) -> tuple[int, dict[str, str], str, dt.datetime]:
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    connection = _PinnedHTTPSConnection(hostname, address, timeout, context)
    try:
        connection.request("GET", "/", headers={"User-Agent": f"DomainPosture/{VERSION}", "Accept": "text/html,*/*;q=0.2", "Connection": "close"})
        if connection.sock is None:
            raise ScanError("TLS connection ended before its certificate could be inspected.")
        # Capture TLS metadata immediately after the handshake; servers may close
        # the socket as soon as the HTTP response is delivered.
        certificate = connection.sock.getpeercert()
        expiry_text = certificate.get("notAfter")
        if not expiry_text:
            raise ScanError("The TLS certificate did not include an expiry time.")
        expiry = dt.datetime.fromtimestamp(ssl.cert_time_to_seconds(expiry_text), tz=dt.timezone.utc)
        tls_version = connection.sock.version()
        response = connection.getresponse()
        headers: dict[str, str] = {}
        for key, value in response.getheaders():
            lowered = key.lower()
            headers[lowered] = f"{headers[lowered]}, {value}" if lowered in headers else value
        status = response.status
        response.close()
        return status, headers, tls_version or "unknown", expiry
    except ScanError:
        raise
    except (OSError, ssl.SSLError, http.client.HTTPException, ValueError) as error:
        raise ScanError(f"HTTPS check failed: {error}") from error
    finally:
        connection.close()


def _header_findings(headers: dict[str, str]) -> list[Finding]:
    findings: list[Finding] = []
    hsts = headers.get("strict-transport-security", "")
    max_age_match = re.search(r"(?:^|;)\s*max-age\s*=\s*(\d+)", hsts, re.I)
    if not max_age_match:
        findings.append(Finding("HDR001", "medium", "Strict-Transport-Security is missing or invalid", "Browsers are not instructed to require HTTPS for future visits.", "For HTTPS sites, add a reviewed HSTS policy with an appropriate max-age; add includeSubDomains only when every subdomain supports HTTPS."))
    elif int(max_age_match.group(1)) < 15_552_000:
        findings.append(Finding("HDR001", "low", "Strict-Transport-Security has a short max-age", "The policy expires sooner than the six-month baseline this tool checks.", "Consider a longer max-age after confirming that HTTPS works on all relevant hosts."))

    if not headers.get("content-security-policy"):
        findings.append(Finding("HDR002", "low", "Content-Security-Policy is missing", "A browser content policy can reduce the impact of some injected-content flaws.", "Define a policy that fits the site and test it in report-only mode before enforcing it."))
    if headers.get("x-content-type-options", "").strip().lower() != "nosniff":
        findings.append(Finding("HDR003", "low", "X-Content-Type-Options is not set to nosniff", "Browsers may infer content types instead of honoring the declared type.", "Send `X-Content-Type-Options: nosniff`."))
    csp_directives = {
        directive.strip().split(None, 1)[0]
        for directive in headers.get("content-security-policy", "").lower().split(";")
        if directive.strip()
    }
    x_frame_options = headers.get("x-frame-options", "").strip().lower()
    if x_frame_options not in {"deny", "sameorigin"} and "frame-ancestors" not in csp_directives:
        findings.append(Finding("HDR004", "low", "No framing restriction was detected", "Neither X-Frame-Options nor a CSP frame-ancestors directive was present.", "Set a framing policy if the site should not be embedded by other origins."))
    if not headers.get("referrer-policy"):
        findings.append(Finding("HDR005", "low", "Referrer-Policy is missing", "The browser's default referrer behavior may share more URL context than intended.", "Choose a policy such as strict-origin-when-cross-origin if it fits the application."))
    if not headers.get("permissions-policy"):
        findings.append(Finding("HDR006", "info", "Permissions-Policy is missing", "No explicit browser feature policy was detected.", "Consider disabling browser features the site does not use."))
    return findings


def inspect_result(hostname: str, addresses: list[str], response: tuple[int, dict[str, str], str, dt.datetime], now: dt.datetime | None = None) -> AuditResult:
    status, headers, tls_version, expiry = response
    now = now or dt.datetime.now(dt.timezone.utc)
    remaining = (expiry - now).days
    findings = _header_findings(headers)
    if remaining < 0:
        findings.append(Finding("TLS001", "high", "TLS certificate is expired", f"The verified certificate expired on {expiry.isoformat()}.", "Renew and deploy the certificate, then verify the full certificate chain."))
    elif remaining < 14:
        findings.append(Finding("TLS001", "high", "TLS certificate expires soon", f"The verified certificate expires in {remaining} day(s), on {expiry.isoformat()}.", "Renew the certificate and confirm automated renewal is working."))
    elif remaining < 30:
        findings.append(Finding("TLS001", "medium", "TLS certificate expires within 30 days", f"The verified certificate expires in {remaining} day(s), on {expiry.isoformat()}.", "Confirm renewal is scheduled and will deploy before expiry."))
    if 300 <= status < 400:
        location = headers.get("location", "").strip()
        downgrade = location.lower().startswith("http://")
        findings.append(Finding(
            "HTTP001",
            "medium" if downgrade else "info",
            "HTTPS endpoint redirects to HTTP" if downgrade else "HTTPS endpoint returned a redirect",
            f"Status {status}; target: {location or '(no Location header)'}. This tool does not follow redirects.",
            "Change the redirect to HTTPS and verify the canonical host." if downgrade else "Review the redirect target and run the check again against the intended canonical hostname.",
        ))
    elif status >= 400:
        findings.append(Finding("HTTP002", "low", "HTTPS root returned an error status", f"The root request returned HTTP {status}; header checks may reflect an error page.", "Confirm the intended public route and repeat the check when the site is available."))
    findings.sort(key=lambda item: (SEVERITY_ORDER[item.severity], item.rule))
    return AuditResult(hostname, addresses, status, tls_version, expiry.isoformat(), remaining, findings)


def audit_domain(value: str, timeout: float = 5.0, resolver: Callable[[str], list[str]] | None = None, fetcher: Callable[[str, str, float], tuple[int, dict[str, str], str, dt.datetime]] | None = None, now: dt.datetime | None = None) -> AuditResult:
    if not math.isfinite(timeout) or timeout <= 0 or timeout > 30:
        raise ScanError("Timeout must be greater than 0 and no more than 30 seconds.")
    hostname = normalize_domain(value)
    addresses = (resolver or resolve_public_addresses)(hostname)
    if not addresses:
        raise ScanError("DNS returned no globally routable address for this hostname.")
    # Pin the connection to a validated public address to avoid a second DNS lookup
    # between the public-address check and the TLS connection. Try at most three
    # already-validated addresses in case one published endpoint is unavailable.
    connect = fetcher or fetch_https
    errors: list[str] = []
    response = None
    for address in addresses[:3]:
        try:
            response = connect(hostname, address, timeout)
            break
        except ScanError as error:
            errors.append(str(error))
    if response is None:
        reason = errors[-1] if errors else "no HTTPS endpoint responded"
        raise ScanError(f"HTTPS check failed for {min(len(addresses), 3)} validated address(es): {reason}")
    return inspect_result(hostname, addresses, response, now)


def render_text(report: AuditResult) -> str:
    lines = [f"Domain Posture {VERSION}", f"Host: {report.hostname}", f"Resolved public IPs: {', '.join(report.addresses)}", f"HTTPS: {report.http_status} · {report.tls_version}", f"Certificate expiry: {report.certificate_expires} ({report.certificate_days_remaining} days)", ""]
    if not report.findings:
        lines.append("No findings from the current checks.")
    for item in report.findings:
        lines.extend([f"[{item.severity.upper()}] {item.rule} · {item.title}", f"  {item.detail}", f"  Recommendation: {item.recommendation}"])
    lines.extend(["", "Limited, read-only checks of one hostname and its HTTPS root. Not a penetration test or a security certification."])
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only TLS and HTTP security-header checks for one public domain.")
    parser.add_argument("domain", help="Hostname only, for example example.com; no URL, port, or path")
    parser.add_argument("--timeout", type=float, default=5.0, help="Connection timeout in seconds (default: 5; maximum: 30)")
    parser.add_argument("--json", action="store_true", help="Print machine-readable output")
    parser.add_argument("--version", action="version", version=f"Domain Posture {VERSION}")
    args = parser.parse_args(argv)
    try:
        report = audit_domain(args.domain, args.timeout)
    except ScanError as error:
        if args.json:
            print(json.dumps({"error": str(error)}))
        else:
            print(f"Error: {error}", file=sys.stderr)
        return 2
    print(json.dumps(asdict(report), indent=2) if args.json else render_text(report))
    return 1 if any(item.severity in {"high", "medium"} for item in report.findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
