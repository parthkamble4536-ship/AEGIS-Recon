# Changelog

All notable changes to AEGIS-Recon are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased] — Industry Standard Upgrade

### Branch: `feature/industry-upgrade`
### Base: `v0.2.0-baseline` (289 tests)

---

### Phase 0 — Baseline Checkpoint (`68628f8`)
- Tagged `v0.2.0-baseline` on `master`
- Created `feature/industry-upgrade` branch
- Documented baseline: 289 tests, Python 3.13.3, Nmap 7.80
- Fixed `test_no_results_on_intel_unavailable` pre-existing test bug

### Phase 1 — Correlation Engine V2 (`b4e0e11`)
**311 tests**
#### Added
- `app/intel/models.py` — `NormalizedService` dataclass
- `app/intel/match_result.py` — `MatchResult`, `MatchConfidence`, `MatchMethod` enums
- `app/intel/matcher.py` — `correlate_service()` with 5-level deterministic hierarchy:
  1. Exact CPE → HIGH confidence
  2. CPE version range → HIGH confidence
  3. Vendor + Product + Version → MEDIUM confidence
  4. Product + Version → MEDIUM confidence
  5. Product only → LOW confidence
- Each match includes: `match_method`, `confidence`, `reason`, `verification_required`
- `tests/unit/test_correlation_v2.py` — 22 new tests

### Phase 2 — EPSS Intelligence (`70a98da`)
**327 tests**
#### Added
- `app/intel/epss/` — EPSS client module
- `EPSSScore` dataclass: `cve_id, probability, percentile, source, retrieved_at, expires_at`
- SQLite TTL cache (reuses existing architecture)
- Stale-cache fallback on API failure
- **CRITICAL**: unavailable EPSS = `None`, NOT `0.0`
- `tests/unit/test_epss.py` — 16 new tests

### Phase 3+4 — Asset Inventory + Risk Engine V2 (`22eae4f`)
**384 tests**
#### Added
- `app/assets/` — Asset inventory module (CRUD, REST API)
  - `AssetCriticality`: LOW / MEDIUM / HIGH / CRITICAL
  - `AssetEnvironment`: LAB / DEV / TEST / STAGING / PRODUCTION
  - `AssetExposure`: INTERNAL / EXTERNALLY_EXPOSED / UNKNOWN
  - REST endpoints: `GET/POST /api/assets`, `GET/PUT/DELETE /api/assets/{id}`
- `app/risk/` — Risk Engine V2 (additive — original `scoring.py` preserved)
  - 8 configurable scoring factors: CVSS, KEV, EPSS, Match Confidence, Evidence Strength, Exploit Ref, Service Exposure, Asset Criticality
  - Environment multiplier
  - `configs/risk_policy.yaml` — configurable weights
  - Stores: `scoring_policy_version`, `scoring_factors` per finding
- `tests/unit/test_assets.py` — 21 new tests
- `tests/unit/test_risk_v2.py` — 36 new tests

### Phase 5 — Scan Diff + Vulnerability Lifecycle (`7c5cef5`)
**418 tests**
#### Added
- `app/diff/` — Scan diff and lifecycle module
  - `FindingState`: NEW / PERSISTENT / RESOLVED / CHANGED
  - `FindingStatus`: new / triaged / verified / remediation_planned / remediated / closed / false_positive / accepted_risk
  - `AnalystDecision`: pending / verify / false_positive / accept_risk / remediate / snooze
  - `FalsePositiveReason`: incorrect_version / backported_patch / not_applicable / compensating_control / duplicate / other
  - Diff engine: `compare_scans()` — compares findings and services across two scans
- New API endpoints:
  - `GET /api/scans/{id}/diff?baseline={id}` — scan diff
  - `PATCH /api/findings/{id}/status` — update analyst status
  - `PATCH /api/findings/{id}/decision` — record formal decision
  - `GET /api/findings/{id}/history` — audit trail
- DB: lifecycle columns added to `findings` table
- `tests/unit/test_diff.py` — 34 new tests

### Phase 6 — Evidence and Provenance Engine (`9f25bb3`)
**441 tests**
#### Added
- `app/evidence/` — Evidence tracking module
  - `EvidenceSource`: nmap / nvd / cisa_kev / epss / vendor_advisory / aegis_rule / ai / analyst
  - `EvidenceType`: observed / external_intelligence / hypothesis / recommendation
  - `EvidenceChain.strongest_type` — priority ordering for evidence quality
  - SHA-256 content hash for evidence integrity
- Evidence record functions:
  - `record_nmap_evidence()` → OBSERVED
  - `record_nvd_evidence()` → EXTERNAL_INTELLIGENCE
  - `record_kev_evidence()` → EXTERNAL_INTELLIGENCE
  - `record_epss_evidence()` → EXTERNAL_INTELLIGENCE
  - `record_version_match_hypothesis()` → HYPOTHESIS (NEVER OBSERVED)
- New API endpoints:
  - `GET /api/findings/{id}/evidence` — all evidence for a finding
  - `POST /api/findings/{id}/evidence` — analyst-added evidence
  - `GET /api/findings/{id}/why` — "Why did AEGIS flag this?"
- DB: `evidence` table added
- `tests/unit/test_evidence.py` — 23 new tests

### Phase 7 — Analyst Workflow (`01a387d`)
**462 tests**
#### Added
- `app/diff/remediation.py` — Remediation guidance update (trusted sources only)
- Remediation fields added to `findings` table:
  - `remediation_vendor`, `remediation_fixed_version`, `remediation_advisory_url`, `remediation_recommended_action`
- Decision auto-maps to status: VERIFY→triaged, FALSE_POSITIVE→false_positive, ACCEPT_RISK→accepted_risk, REMEDIATE→remediation_planned
- New API endpoint:
  - `PATCH /api/findings/{id}/remediation` — set remediation guidance
- `tests/unit/test_analyst_workflow.py` — 21 new tests

### Phase 8 — CI/CD and Repository Hardening (this commit)
#### Added
- `.github/workflows/ci.yml` — GitHub Actions CI: Ruff → Bandit → pip-audit → pytest + coverage
- `SECURITY.md` — vulnerability reporting policy, safe-use requirements
- `CONTRIBUTING.md` — development setup, safety rules, PR checklist
- `CHANGELOG.md` — this file
- `.env.example` — environment variable documentation

---

## [0.2.0] — Academic MVP Baseline
### Tag: `v0.2.0-baseline` (289 tests)

The baseline version before the industry upgrade. Includes:
- Nmap-based scanning (Quick/Standard/Thorough profiles)
- YAML allowlist enforcement
- NVD API 2.0 + CISA KEV integration
- SQLite TTL caching
- FastAPI + dashboard
- Evidence model (observed/external_intelligence/hypothesis/recommendation)
- Explainable 0–100 risk scoring
- AI grounded analysis with dangerous-command blocking
- JSON + HTML reporting
