# Security Policy

## Supported versions

PAJIN is pre-release software. Security fixes target the current `main` branch and the latest
published release, when one exists. Older commits and unreleased forks are not supported unless a
maintainer states otherwise.

## Reporting a vulnerability

Do not disclose a suspected vulnerability, exploit details, credentials, personal data, or
production coordinates in a public issue.

Use GitHub's private vulnerability reporting form:

<https://github.com/HYEXE/PAJIN/security/advisories/new>

If the private form is unavailable, open a public issue containing only a request for a private
contact channel. Do not include technical details in that issue.

Include, when available:

- the affected commit or release;
- the affected component and trust boundary;
- reproduction prerequisites and minimal steps;
- observed and expected behavior;
- security impact and required attacker capabilities;
- logs or artifacts with credentials and personal data removed.

Maintainers aim to acknowledge a complete report within five business days. Validation, remediation,
release, and disclosure timing depend on severity and reproducibility. Reporters should allow a
reasonable remediation window before public disclosure and coordinate publication with the
maintainers.

## Scope

Reports are most useful when they demonstrate a concrete violation of a documented PAJIN security
boundary. Missing product features, benchmark score disagreements, unsupported environments, and
the intentionally absent authorities documented in the contracts are not vulnerabilities by
themselves.
