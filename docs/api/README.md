# AEGIS-Recon API Reference

Base URL: `http://127.0.0.1:8000/api`  
Interactive docs: `http://127.0.0.1:8000/api/docs`

---

## Scans

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/scans` | List all scans |
| `POST` | `/scans` | Start a new scan |
| `GET` | `/scans/{id}` | Get scan details |
| `GET` | `/scans/{id}/diff?baseline={id}` | Compare two scans |

### POST /scans
```json
{
  "target": "192.168.1.1",
  "profile": "standard"
}
```
Profiles: `quick`, `standard`, `thorough`

### GET /scans/{id}/diff
Query params: `baseline` (required) — ID of the baseline scan to compare against.

Returns: `{ summary, new_findings, resolved_findings, persistent_findings, changed_findings, new_services, removed_services }`

---

## Findings

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/findings/{scan_id}` | Get findings for a scan |
| `POST` | `/findings/{scan_id}/enrich` | Trigger CVE enrichment |
| `GET` | `/findings/detail/{id}` | Get single finding detail |
| `PATCH` | `/findings/{id}/status` | Update analyst status |
| `PATCH` | `/findings/{id}/decision` | Record analyst decision |
| `PATCH` | `/findings/{id}/remediation` | Set remediation guidance |
| `GET` | `/findings/{id}/history` | Get status/decision audit trail |
| `GET` | `/findings/{id}/evidence` | Get all evidence for finding |
| `POST` | `/findings/{id}/evidence` | Add analyst evidence |
| `GET` | `/findings/{id}/why` | "Why did AEGIS flag this?" |

### PATCH /findings/{id}/status
```json
{
  "status": "triaged",
  "changed_by": "analyst",
  "reason": "Reviewed — in scope"
}
```
Valid statuses: `new` | `triaged` | `verified` | `remediation_planned` | `remediated` | `closed` | `false_positive` | `accepted_risk`

### PATCH /findings/{id}/decision
```json
{
  "decision": "false_positive",
  "decision_reason": "Debian backports fix",
  "decided_by": "alice",
  "false_positive_reason": "backported_patch"
}
```
Valid decisions: `pending` | `verify` | `false_positive` | `accept_risk` | `remediate` | `snooze`

Valid false_positive_reason: `incorrect_version` | `backported_patch` | `not_applicable` | `compensating_control` | `duplicate` | `other`

### PATCH /findings/{id}/remediation
```json
{
  "vendor": "Apache Software Foundation",
  "fixed_version": "2.15.0",
  "advisory_url": "https://logging.apache.org/log4j/2.x/security.html",
  "recommended_action": "Upgrade log4j to 2.15.0 or later"
}
```
All fields optional. Data must come from trusted sources — not AI.

---

## Assets

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/assets` | List all assets |
| `POST` | `/assets` | Create asset |
| `GET` | `/assets/{id}` | Get asset |
| `PUT` | `/assets/{id}` | Update asset |
| `DELETE` | `/assets/{id}` | Delete asset |

### POST /assets
```json
{
  "hostname": "web-prod-01",
  "ip": "10.0.1.50",
  "environment": "PRODUCTION",
  "criticality": "CRITICAL",
  "owner": "Platform Team",
  "business_service": "Customer Portal",
  "internet_exposed": true,
  "notes": "Primary public-facing web server"
}
```
Environments: `LAB` | `DEV` | `TEST` | `STAGING` | `PRODUCTION`  
Criticality: `LOW` | `MEDIUM` | `HIGH` | `CRITICAL`

---

## Reports

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/reports/{scan_id}/json` | Download JSON report |
| `GET` | `/reports/{scan_id}/html` | Download HTML report |
| `GET` | `/reports/{scan_id}/analysis` | AI analysis for scan |

---

## Health

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | System health check |

