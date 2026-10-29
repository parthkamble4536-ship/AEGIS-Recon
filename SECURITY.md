# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest on `main` | ✅ |
| Older branches | ❌ (upgrade to main) |

## Purpose and Scope

AEGIS-Recon is a **defensive authorized-security-assessment tool**.
It is designed exclusively for use on systems and networks that you own or have
explicit written authorization to test. It is not designed for, and must not be
used for, unauthorized access, offensive operations, credential attacks, evasion,
or any other illegal activity.

## Reporting a Vulnerability

If you discover a security vulnerability in AEGIS-Recon itself (e.g., a bypass
of its safety controls, an injection flaw, an unintended data exposure):

1. **Do not open a public GitHub issue.**
2. Email the maintainer directly (see the GitHub profile or `pyproject.toml`).
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)
4. You will receive an acknowledgment within **5 business days**.
5. We aim to release a fix within **30 days** of a confirmed report.

## Safe-Use Requirements

- **Allowlist enforcement**: AEGIS-Recon only scans targets explicitly listed in `config/allowlist.yaml`.
- **Shell safety**: All subprocess calls use `shell=False`.
- **No auto-exploitation**: The system never exploits vulnerabilities — it identifies and prioritizes them.
- **No credential attacks**: AEGIS-Recon performs no authentication attempts against targets.
- **AI guardrails**: AI analysis is grounded in evidence; dangerous commands are blocked.

## AI Safety

The AI analysis module (`app/ai/`) includes:
- CVE allow-listing (only discusses CVEs present in scan data)
- Dangerous-command blocking
- JSON output validation
- Deterministic fallback when AI is unavailable

**IMPORTANT**: AI-generated text is always labeled. It must never be treated as
authoritative without analyst review.

## Dependency Policy

- All dependencies are pinned in `requirements.txt`.
- `pip-audit` runs in CI to detect known vulnerable dependencies.
- Dependency updates are reviewed before merging.
