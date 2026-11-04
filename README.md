# Domain Posture Check

A small, local-first checker for the public HTTPS posture of one domain you own or are authorized to assess. It looks at DNS resolution, the TLS certificate used by the HTTPS root, the negotiated TLS version, the root response status, and a short list of browser security headers.

> **Status:** Early intermediate learning project. Findings are review prompts, not a security score, penetration test, compliance result, or proof that a site is secure.

## Why this scope

Widely used projects show that maintainers value focused, inspectable security workflows: [Nuclei](https://github.com/projectdiscovery/nuclei) for template-based checks, [OWASP Amass](https://github.com/owasp-amass/amass) for attack-surface discovery, [testssl.sh](https://github.com/testssl/testssl.sh) for TLS testing, and [DNSViz](https://github.com/dnsviz/dnsviz) for DNSSEC analysis. Their GitHub pages showed roughly 32.6k, 15.2k, 9.2k, and 1.3k stars respectively when checked on 2026-11-04; counts change over time. Domain Posture Check takes a narrower, non-invasive path: a single hostname, a single HTTPS root request, and practical findings that are easy to reproduce.

## Requirements

- Python 3.10 or newer
- Network access to resolve the hostname and connect to its HTTPS endpoint on port 443
- No third-party Python packages

## Run

```sh
python3 domain_posture.py example.com
```

Machine-readable JSON is available with `--json`; control the connection timeout with `--timeout` (1–30 seconds):

```sh
python3 domain_posture.py example.com --json
python3 domain_posture.py example.com --timeout 8
```

Exit codes: `0` means no medium or high findings, `1` means one or more medium/high findings, and `2` means the hostname could not be safely checked.

## Checks

- Resolves the supplied hostname and refuses to connect if any answer is not a globally routable address.
- Connects to one of up to three resolved addresses while retaining TLS SNI and certificate hostname verification. It tries the next validated address if a published endpoint fails, and pins each connection to avoid a second DNS lookup before connecting.
- Requires TLS 1.2 or newer for the check. The negotiated version is reported; the tool does not probe obsolete TLS versions.
- Makes one `GET /` request over HTTPS. It does not read the response body, follow redirects, or try other paths.
- Reports the HTTP status, negotiated TLS version, and verified certificate expiry.
- Reports redirects without following them and flags an HTTPS-to-HTTP downgrade.
- Reviews HSTS, Content-Security-Policy, X-Content-Type-Options, framing restrictions, Referrer-Policy, and Permissions-Policy.

The findings intentionally avoid an overall grade. Missing headers can be acceptable for some applications; choose policies based on the site's behavior and threat model.

## Safety and privacy

- Only check domains you own or have explicit permission to assess.
- The tool does not scan ports, enumerate subdomains, brute-force names, exploit vulnerabilities, submit forms, authenticate, or change server settings.
- It checks only the supplied hostname on TCP port 443. Redirect targets are shown but never fetched.
- DNS uses the computer's configured resolver. The target server will see one HTTPS request to `/` from your network.
- The tool refuses URL syntax, IP literals, local-only hostnames, and DNS answers that are not globally routable. It connects to a validated IP while using the hostname for TLS verification.
- Output includes the resolved public IP addresses. Review JSON or terminal output before sharing it.

These limits reduce risk but do not replace an authorization process or a professional assessment. Reverse proxies, CDNs, and WAFs may serve different headers or certificates from the origin.

## Development and tests

The test suite is offline and uses stubbed DNS/HTTPS responses:

```sh
python3 -m unittest discover -s tests -v
```

The offline suite passed during development. A live request to the reserved `example.com` test domain could not be completed in this development environment because its system DNS lookup failed; use a domain you control to exercise the network path from your machine.

## Related projects

This is an independent learning tool. It does not copy or bundle the projects linked above and is not a substitute for them. Each has a broader or different purpose; use maintained specialist tools when you need deeper coverage.

## License

MIT. See [LICENSE](LICENSE).
