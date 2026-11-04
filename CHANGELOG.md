# Changelog

## 0.1.0

- Add read-only DNS, TLS certificate, HTTPS status, and security-header checks for one explicit hostname.
- Refuse non-public DNS answers and pin the connection to a validated public IP.
- Report redirects without following them; flag HTTPS-to-HTTP downgrade redirects.
- Do not scan ports, enumerate subdomains, or read response bodies.
- Add JSON output and offline regression coverage.
