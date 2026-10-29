# AEGIS-Recon — Baseline Checkpoint (v0.2.0-baseline)

Recorded at the start of the industry-standard upgrade (Phase 0).

## Git

| Item | Value |
|------|-------|
| Baseline tag | `v0.2.0-baseline` |
| Development branch | `feature/industry-upgrade` |
| Last master commit | `68a7201` |

## Runtime

| Item | Value |
|------|-------|
| Python | 3.13.3 (Windows) |
| Nmap | 7.80 (`C:\Program Files (x86)\Nmap\nmap.exe`) |
| Shell | PowerShell (Windows) |

## Key Dependencies

| Package | Version |
|---------|---------|
| fastapi | 0.143.0 |
| uvicorn | 0.54.0 |
| pydantic | 2.14.1 |
| pydantic-settings | 2.15.0 |
| httpx | 0.28.1 |
| requests | 2.34.2 |
| structlog | 26.1.0 |
| pytest | 9.1.1 |
| pytest-asyncio | 1.4.0 |
| pytest-cov | 7.1.0 |

## Test Suite Baseline

| Metric | Count |
|--------|-------|
| Total collected | 305 |
| Deselected (integration mark) | 16 |
| **Passing** | **289** |
| Failing | 0 |
| Skipped | 0 |

## Existing Feature Inventory

### Safe Reconnaissance
- Nmap-based scanning with Quick / Standard / Thorough profiles
- YAML-based target allowlisting (`config/allowlist.yaml`)
- Input validation, Windows Nmap auto-detection, `shell=False`
- Subprocess safety, timeout handling, temporary XML handling

### Parsing
- Nmap XML parser (`app/parser/nmap_xml.py`)
- Host / service / port / CPE / NSE script / OS extraction

### Vulnerability Intelligence
- NVD API 2.0 (`app/intel/nvd.py`) — CPE-based matching
- CISA KEV catalog (`app/intel/kev.py`)
- SQLite TTL caching (`app/intel/cache.py`)
- Offline / stale-cache fallback

### Evidence Model
Four categories: `observed`, `external_intelligence`, `hypothesis`, `recommendation`.
**CRITICAL:** version match is NEVER presented as confirmed vulnerability.

### Risk Engine
Explainable 0–100 priority scoring (`app/risk/scoring.py`).

### AI
- Grounded AI architecture (`app/ai/provider.py`)
- CVE allowlisting + dangerous-command blocking (`app/ai/validator.py`)
- JSON validation + deterministic fallback (`app/ai/fallback.py`)

### UI / API
- FastAPI REST API (`app/api/`)
- Web dashboard (`web/index.html`, `web/app.js`, `web/style.css`)
- Scan history, finding views, AI Analysis tab, JSON/HTML reports

### Evaluation Corpus
- `tests/fixtures/metasploitable2_scan.xml`
- `tests/fixtures/metasploitable3_win_scan.xml`
- `tests/fixtures/metasploitable3_linux_scan.xml`
- `tests/fixtures/kioptrix_scan.xml`

## Intelligence Retrieval Timestamps

> **Note:** NVD and KEV are fetched live; timestamps reflect data at time of scan, not baseline snapshot.
> Cached data stored in `data/aegis_recon.db` (gitignored).

## No Features Intentionally Removed

This baseline represents the complete working system before the industry-standard upgrade begins.
All features listed above must remain intact throughout the upgrade.

