# Security Policy

## Confirmed amount disclosure

The current proof backend is **not zero knowledge**. Public proof bytes can reveal
witness amounts and salts. Read the [security advisory](docs/SECURITY_ADVISORY_AMOUNT_DISCLOSURE.md)
before using any proof or language binding with confidential data. Commerce APIs
fail closed for confidentiality requirements; legacy low-level APIs remain
integrity-only. No independent end-to-end audit or confidential release is claimed.

## Supported Versions

Security fixes are provided for the `main` branch.

## Reporting a Vulnerability

Please do not open a public issue for security-sensitive reports.

Preferred:
- Use GitHub Security Advisories ("Report a vulnerability" in the repository's Security tab).

Alternative:
- Email: `engineering@stateset.io`

Include as much of the following as you can:
- Description and impact
- Steps to reproduce / proof of concept
- Affected versions / commit
- Any suggested fix or mitigation
