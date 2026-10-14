# AEGIS-Recon

> Evidence-based, AI-assisted reconnaissance and vulnerability intelligence for authorized security assessments.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/Python-3.12+-green.svg)](https://python.org)

---

## ⚠️ Responsible Use

AEGIS-Recon is designed **exclusively** for authorized security assessments. Before using this tool:

1. **Obtain written authorization** for every target you scan.
2. **Configure your allowlist** (`config/allowlist.yaml`) to include only authorized targets.
3. **Read [RESPONSIBLE_USE.md](RESPONSIBLE_USE.md)** in full.

Unauthorized scanning of systems you do not own or have explicit permission to test is **illegal** in most jurisdictions.

---

## What Makes AEGIS-Recon Different

| Feature | Traditional Tools | AEGIS-Recon |
|---------|------------------|-------------|
| **Evidence Model** | Findings presented as facts | Every finding labeled: *observed*, *external intelligence*, *hypothesis*, or *recommendation* |
| **Scoring Transparency** | Single severity number | CVSS shown separately from contextual priority; each factor listed |
| **Version Matching** | "Vulnerable!" | "Potential match (confidence: medium) — version overlap with CPE range" |
| **Reproducibility** | Scan results only | Scan config, tool versions, and intel snapshot timestamps stored per report |
| **AI Safety** | LLM can run commands | LLM can never execute actions; output is schema-validated; deterministic fallback always available |

---

## Quick Start

### Prerequisites

- Python 3.12+
- Nmap installed and on PATH
- A target you are **authorized** to scan

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/aegis-recon.git
cd aegis-recon

# Create virtual environment
python -m venv venv
# Windows
venv\Scripts\activate
# Linux/macOS
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Configure
cp .env.example .env
# Edit .env with your settings
# Edit config/allowlist.yaml with your authorized targets
```

### Run

```bash
# Start the API server
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000

# Open dashboard
# Navigate to http://127.0.0.1:8000 in your browser
```

---

## Architecture

```
User → Dashboard/CLI → FastAPI → Validator+Allowlist → Nmap Runner
    → XML Parser → SQLite → NVD+KEV Intel → Risk Engine
    → AI Analysis (optional) → Report Generator → Dashboard
```

See [docs/architecture.md](docs/architecture.md) for the full design.

---

## Project Structure

```
aegis-recon/
├── app/                    # Application source
│   ├── main.py             # FastAPI app factory
│   ├── config.py           # Settings from environment
│   ├── api/                # API routers
│   ├── core/               # Validation, logging, errors
│   ├── scanner/            # Nmap runner + profiles
│   ├── parser/             # XML parsing
│   ├── intel/              # NVD, KEV, cache, matcher
│   ├── risk/               # Explainable scoring
│   ├── ai/                 # Optional LLM analysis
│   ├── reports/            # JSON/HTML report generation
│   └── db/                 # Database models + repository
├── web/                    # Dashboard (HTML/CSS/JS)
├── tests/                  # Test suite
├── config/                 # Allowlist and profiles
├── docs/                   # Documentation
└── scripts/                # Setup and demo scripts
```

---

## Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=app --cov-report=html

# Run specific test suite
pytest tests/unit/
pytest tests/integration/
```

---

## License

[MIT](LICENSE)

---

## Documentation

- [System & Architecture Overview](docs/SYSTEM_OVERVIEW.md) — Comprehensive technical guide, schema definitions, and module breakdowns.
- [Responsible Use Policy](RESPONSIBLE_USE.md) — Legal boundaries and scope guidelines.

---

## Status

✅ **Week 1 & Week 2 Complete (v0.2.0)**:
- Target validation, allowlist enforcement, and injection resistance
- Safe Nmap scanning pipeline and XML parser
- SQLite database persistence with WAL mode
- NVD API 2.0 client & CISA KEV catalog integration with TTL cache
- 6-factor explainable risk scoring engine
- AI prompt templates, schema validator, hallucination guard & deterministic fallback
- JSON & HTML report builders (XSS-safe)
- Glassmorphism dark-theme web dashboard
- 146 tests passing in 6.4s (100% pass rate)

