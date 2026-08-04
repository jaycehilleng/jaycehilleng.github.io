# Security Policy

## Reporting Security Issues
If you discover a potential security vulnerability within this repository or associated architecture blueprints, please report it privately out-of-band rather than opening a public issue.

- **Email:** security@hillsecadvisors.com
- **Response SLA:** Acknowledgment within 24 hours; preliminary assessment within 72 hours.

## Security Controls & Verification
This repository enforces automated continuous security testing via GitHub Actions on every commit and pull request:
- Unit test coverage across out-of-band proxy inspection engines (`pytest`).
- Cryptographic Proof-of-Possession (PoP) token validation testing.
- SAST CodeQL analysis for automated vulnerability detection.