# Contributing

Thanks for helping improve Domain Posture Check.

## Development

- Use Python 3.10 or newer.
- Keep unit tests offline. Stub DNS and HTTPS; never make a test depend on a third-party domain.
- Run `python3 -m unittest discover -s tests -v` before opening a change.
- Keep network behavior narrow: one named hostname, public DNS answers only, TCP 443 only, and no redirect following.
- Add a regression test when fixing a false positive, false negative, or unsafe input case.
- Use synthetic hostnames and certificates in examples. Do not commit customer domains, scan outputs, or credentials.

## Reporting a finding

Include the rule ID, a synthetic input or sanitized response shape, what you expected, and what the tool returned. Avoid publishing real hostnames or configuration details if they would expose an organization's infrastructure.
