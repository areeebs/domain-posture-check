import datetime as dt
import socket
import unittest
from unittest.mock import patch

import domain_posture


UTC = dt.timezone.utc


class DomainPostureTests(unittest.TestCase):
    def test_normalizes_idna_hostname(self):
        self.assertEqual(domain_posture.normalize_domain("  Exämple.com. "), "xn--exmple-cua.com")

    def test_rejects_urls_ips_and_local_names(self):
        for value in ("https://example.com", "example.com/path", "127.0.0.1", "service.local", "example.com.."):
            with self.subTest(value=value), self.assertRaises(domain_posture.ScanError):
                domain_posture.normalize_domain(value)

    def test_refuses_private_dns_answers(self):
        records = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]
        with patch.object(domain_posture.socket, "getaddrinfo", return_value=records):
            with self.assertRaisesRegex(domain_posture.ScanError, "non-public address"):
                domain_posture.resolve_public_addresses("example.com")

    def test_pins_https_request_to_validated_address(self):
        now = dt.datetime(2026, 11, 4, tzinfo=UTC)
        expiry = now + dt.timedelta(days=90)
        calls = []

        def fake_fetch(hostname, address, timeout):
            calls.append((hostname, address, timeout))
            return 200, {"strict-transport-security": "max-age=31536000", "content-security-policy": "default-src 'self'; frame-ancestors 'none'", "x-content-type-options": "nosniff", "referrer-policy": "strict-origin"}, "TLSv1.3", expiry

        report = domain_posture.audit_domain("example.com", resolver=lambda _: ["93.184.216.34"], fetcher=fake_fetch, now=now)
        self.assertEqual(calls, [("example.com", "93.184.216.34", 5.0)])
        self.assertEqual(report.certificate_days_remaining, 90)
        self.assertNotIn("HDR001", {finding.rule for finding in report.findings})
        self.assertNotIn("HDR004", {finding.rule for finding in report.findings})

    def test_tries_another_validated_address_if_one_endpoint_fails(self):
        now = dt.datetime(2026, 11, 4, tzinfo=UTC)
        expiry = now + dt.timedelta(days=90)
        attempts = []

        def fake_fetch(hostname, address, timeout):
            attempts.append(address)
            if address == "2606:4700:4700::1111":
                raise domain_posture.ScanError("first endpoint is unavailable")
            return 200, {}, "TLSv1.3", expiry

        report = domain_posture.audit_domain(
            "example.com",
            resolver=lambda _: ["2606:4700:4700::1111", "93.184.216.34"],
            fetcher=fake_fetch,
            now=now,
        )
        self.assertEqual(attempts, ["2606:4700:4700::1111", "93.184.216.34"])
        self.assertEqual(report.http_status, 200)

    def test_expired_certificate_is_high_severity(self):
        now = dt.datetime(2026, 11, 4, tzinfo=UTC)
        response = (200, {}, "TLSv1.3", now - dt.timedelta(days=1))
        report = domain_posture.inspect_result("example.com", ["93.184.216.34"], response, now)
        expiry = next(item for item in report.findings if item.rule == "TLS001")
        self.assertEqual(expiry.severity, "high")

    def test_redirect_is_reported_without_following_it(self):
        now = dt.datetime(2026, 11, 4, tzinfo=UTC)
        response = (302, {"location": "https://other.example/"}, "TLSv1.3", now + dt.timedelta(days=90))
        report = domain_posture.inspect_result("example.com", ["93.184.216.34"], response, now)
        redirect = next(item for item in report.findings if item.rule == "HTTP001")
        self.assertIn("does not follow", redirect.detail)

    def test_http_redirect_from_https_is_flagged_as_downgrade(self):
        now = dt.datetime(2026, 11, 4, tzinfo=UTC)
        response = (301, {"location": "http://example.com/"}, "TLSv1.3", now + dt.timedelta(days=90))
        report = domain_posture.inspect_result("example.com", ["93.184.216.34"], response, now)
        redirect = next(item for item in report.findings if item.rule == "HTTP001")
        self.assertEqual(redirect.severity, "medium")
        self.assertIn("redirects to HTTP", redirect.title)

    def test_frame_ancestor_directive_is_recognized_as_a_directive(self):
        findings = domain_posture._header_findings({
            "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
            "x-content-type-options": "nosniff",
        })
        self.assertNotIn("HDR004", {item.rule for item in findings})

    def test_fetch_requires_modern_tls_and_requests_only_root(self):
        expiry_text = "Nov  3 12:00:00 2027 GMT"
        created = []

        class FakeSocket:
            def version(self):
                return "TLSv1.3"

            def getpeercert(self):
                return {"notAfter": expiry_text}

        class FakeResponse:
            status = 200

            def getheaders(self):
                return [("X-Content-Type-Options", "nosniff")]

            def close(self):
                pass

        class FakeConnection:
            def __init__(self, hostname, address, timeout, context):
                self.hostname, self.address, self.timeout = hostname, address, timeout
                self.context = context
                self.sock = FakeSocket()
                self.request_args = None
                created.append(self)

            def request(self, *args, **kwargs):
                self.request_args = (args, kwargs)

            def getresponse(self):
                response = FakeResponse()
                self.sock = None
                return response

            def close(self):
                pass

        with patch.object(domain_posture, "_PinnedHTTPSConnection", FakeConnection):
            status, headers, version, expiry = domain_posture.fetch_https("example.com", "93.184.216.34", 3)
        self.assertEqual(status, 200)
        self.assertEqual(headers["x-content-type-options"], "nosniff")
        self.assertEqual(version, "TLSv1.3")
        self.assertEqual(expiry.tzinfo, UTC)
        connection = created[0]
        self.assertEqual(connection.address, "93.184.216.34")
        self.assertGreaterEqual(connection.context.minimum_version, domain_posture.ssl.TLSVersion.TLSv1_2)
        self.assertEqual(connection.request_args[0], ("GET", "/"))


if __name__ == "__main__":
    unittest.main()
