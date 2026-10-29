# AEGIS-Recon Architecture Overview

## System Flow

```
Authorized Scope (allowlist.yaml)
    ↓
Asset Inventory (app/assets/)
    ↓
Safe Nmap Scan (app/scanner/ — shell=False, timeout)
    ↓
XML Parsing (app/parser/)
    ↓
Service Normalization (app/intel/models.py — NormalizedService)
    ↓
Vulnerability Correlation (app/intel/matcher.py — 5-level CPE hierarchy)
    ↓
NVD / CISA KEV / EPSS Intelligence (app/intel/)
    ↓
Evidence & Provenance (app/evidence/)
    ↓
Confidence Calculation (MatchConfidence: HIGH/MEDIUM/LOW)
    ↓
Asset Context (app/assets/service.py)
    ↓
Risk/Priority Engine V2 (app/risk/engine.py — 8 factors, configurable)
    ↓
AI Grounded Analysis (app/ai/ — optional, grounded, validated)
    ↓
Analyst Review (PATCH /api/findings/{id}/decision)
    ↓
Remediation / Risk Acceptance / False Positive
    ↓
Rescan → Scan Diff (app/diff/engine.py)
    ↓
Measurable Evaluation (tests/evaluation/)
```

## Module Map

| Module | Path | Purpose |
|--------|------|---------|
| Scanner | `app/scanner/` | Safe Nmap execution, profile selection |
| Parser | `app/parser/` | Nmap XML → structured host/service/port data |
| Intel — Matcher | `app/intel/matcher.py` | CPE-based CVE correlation, 5-level hierarchy |
| Intel — NVD | `app/intel/nvd.py` | NVD API 2.0 client |
| Intel — KEV | `app/intel/kev.py` | CISA KEV catalog |
| Intel — EPSS | `app/intel/epss/` | FIRST EPSS probability scores |
| Intel — Cache | `app/intel/cache.py` | SQLite TTL cache (shared by NVD/KEV/EPSS) |
| Assets | `app/assets/` | Asset inventory with criticality/environment/exposure |
| Risk V1 | `app/risk/scoring.py` | Original 6-factor risk engine (preserved) |
| Risk V2 | `app/risk/engine.py` | 8-factor configurable engine + policy YAML |
| Evidence | `app/evidence/` | Evidence chain, provenance, SHA-256 integrity |
| Diff | `app/diff/` | Scan-to-scan comparison, lifecycle, remediation |
| AI | `app/ai/` | Grounded Gemini analysis, hallucination guard |
| Reports | `app/reports/` | JSON + HTML report generation |
| API | `app/api/` | FastAPI routers |
| DB | `app/db/` | SQLite schema, migrations, repository |

## Evidence Model

| Type | Meaning | Example Sources |
|------|---------|-----------------|
| `observed` | Directly seen on the wire | Nmap banner, open port |
| `external_intelligence` | Trusted external data | NVD CVE record, CISA KEV, EPSS |
| `hypothesis` | Inferred, not confirmed | Version range match |
| `recommendation` | Suggested action | Analyst note |

> **CRITICAL**: A version match NEVER automatically becomes `observed` evidence.  
> Version presence ≠ confirmed vulnerability.

## Risk Score Factors (V2)

| Factor | Max Points | Condition |
|--------|-----------|-----------|
| CVSS Base Score | 40 | CVSS × 4.08 |
| CISA KEV | +20 | In KEV catalog |
| EPSS | +15 | Scaled by probability |
| Match Confidence | +10 | HIGH=10, MEDIUM=6, LOW=2 |
| Evidence Strength | +5 | observed > external > hypothesis |
| Public Exploit Ref | +5 | External exploit reference present |
| Service Exposure | +5 | Externally exposed service |
| Asset Criticality | +10 | CRITICAL=10, HIGH=7, MEDIUM=4, LOW=1 |

All weights are configurable via `configs/risk_policy.yaml`.

## Safety Invariants

1. All subprocess calls use `shell=False` (enforced by Bandit)
2. AI cannot execute commands
3. Missing EPSS = `None` (not `0.0`) — absence ≠ low risk
4. Remediation guidance must come from trusted sources only
5. All targets must be in `config/allowlist.yaml`

## Database Schema

Key tables:
- `scans` — scan metadata (target, profile, status, timestamps)
- `hosts` — discovered hosts per scan
- `services` — discovered services (port, protocol, CPE, version)
- `findings` — CVE findings with lifecycle fields (analyst_status, analyst_decision, remediation_*)
- `evidence` — evidence provenance records (SHA-256 hashed)
- `assets` — asset inventory (criticality, environment, exposure)
- `intel_cache` — SQLite TTL cache for NVD/KEV/EPSS
- `audit_log` — immutable audit trail for analyst actions

