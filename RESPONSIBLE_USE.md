# Responsible Use Policy

## Purpose

AEGIS-Recon is a **defensive security assessment tool** built for authorized penetration testing,
vulnerability research, and security education. It exists to help security professionals
identify and remediate vulnerabilities in systems they are authorized to test.

## Requirements Before Use

### 1. Authorization

You **must** have explicit, written authorization before scanning any system. This includes:

- A signed scope-of-work or penetration testing agreement
- Written permission from the system owner
- A lab environment you own and control

**"I didn't know I needed permission" is not a defense.**

### 2. Scope Enforcement

- Configure `config/allowlist.yaml` with **only** your authorized targets.
- AEGIS-Recon will refuse to scan targets not on the allowlist.
- Do not disable or bypass the allowlist enforcement.

### 3. Understand the Output

AEGIS-Recon findings include an **evidence type** for every result:

| Evidence Type | Meaning |
|---------------|---------|
| **Observed** | Directly seen in scan output (e.g., open port, banner) |
| **External Intelligence** | Correlated from an external source (e.g., NVD CVE match) |
| **Hypothesis** | Inferred but not confirmed (e.g., version range overlap) |
| **Recommendation** | Suggested action, not a finding |

A version match is **never** presented as a confirmed vulnerability. Always verify findings
manually before including them in a report or taking remediation action.

### 4. Data Handling

- Scan results may contain sensitive information about target systems.
- Store reports securely and share only with authorized parties.
- Do not commit real scan data to version control.
- Delete scan data when it is no longer needed.

## What This Tool Does NOT Do

- **No exploitation**: AEGIS-Recon does not attempt to exploit any vulnerability.
- **No credential attacks**: No brute-forcing, password spraying, or credential stuffing.
- **No destructive actions**: Scanning is passive information gathering only.
- **No unauthorized access**: The tool never attempts to log in to or access target systems.

## Legal Notice

Unauthorized computer access is a criminal offense in most jurisdictions, including but
not limited to:

- **United States**: Computer Fraud and Abuse Act (CFAA)
- **European Union**: Directive 2013/40/EU on attacks against information systems
- **United Kingdom**: Computer Misuse Act 1990
- **India**: Information Technology Act 2000

The authors of AEGIS-Recon accept **no responsibility** for misuse of this tool.
You are solely responsible for ensuring your use complies with all applicable laws
and regulations.

## Reporting Security Issues

If you discover a security vulnerability in AEGIS-Recon itself, please report it
responsibly by opening a private security advisory on the GitHub repository.
Do not file public issues for security vulnerabilities.
