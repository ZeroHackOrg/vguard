# Security Policy

## Reporting a Vulnerability

We take the security of VectorGuard and the RAG pipelines it protects seriously.

- **Do not** open a public issue for security vulnerabilities.
- Email **solutions@zerohack.org** with:
  - A description of the vulnerability.
  - Steps to reproduce.
  - Impact assessment (if known).

You should receive a response within 72 hours. Public disclosure is coordinated
after a fix is released.

## Supported Versions

| Version | Supported |
| --- | --- |
| latest (main) | yes |
| released tags | yes |

## Security Baseline

- All audit records are chained with SHA-256 hashes to detect tampering.
- Secrets are never embedded in the repository; CI uses GitHub Actions
  encrypted secrets only.
- Coordinate payloads are validated for NaN/Inf and dimensional conformance
  before spatial auditing.