"""
Database models and schema for AEGIS-Recon.

Uses plain sqlite3 for Week 1-2 (zero-dependency setup).
SQLAlchemy + Alembic migrations will be added in Week 5 when the schema stabilizes.

Tables:
- scans: Scan metadata (target, profile, status, timestamps)
- hosts: Discovered hosts per scan
- services: Discovered services/ports per host
- findings: CVE findings per service (Week 2)
- intel_cache: Cached NVD/KEV responses (Week 2)
- audit_log: Who did what (Week 4)

All IDs are UUIDs stored as TEXT for portability.
Timestamps are ISO 8601 strings in UTC.
"""

from __future__ import annotations

# SQL statements for schema creation
SCHEMA_SQL = """
-- Scans table: one row per scan execution
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    profile TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    -- status: pending, running, completed, failed, timeout
    ports TEXT,
    start_time TEXT NOT NULL,
    end_time TEXT,
    nmap_version TEXT,
    command_args TEXT,
    -- JSON array of nmap args (for reproducibility)
    error_message TEXT,
    hosts_up INTEGER DEFAULT 0,
    hosts_down INTEGER DEFAULT 0,
    hosts_total INTEGER DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

-- Hosts table: discovered hosts per scan
CREATE TABLE IF NOT EXISTS hosts (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    ip TEXT NOT NULL,
    hostnames TEXT,
    -- JSON array of hostnames
    status TEXT NOT NULL DEFAULT 'unknown',
    os_matches TEXT,
    -- JSON array of OS match objects
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

-- Services table: discovered services per host
CREATE TABLE IF NOT EXISTS services (
    id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL DEFAULT 'tcp',
    state TEXT NOT NULL DEFAULT 'unknown',
    service_name TEXT,
    product TEXT,
    version TEXT,
    extra_info TEXT,
    cpe TEXT,
    -- JSON array of CPE URIs
    banner TEXT,
    scripts TEXT,
    -- JSON object of script_id: output
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

-- Findings table: CVE/vulnerability findings per service (populated in Week 2)
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    service_id TEXT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    cve_id TEXT,
    -- e.g., CVE-2021-44228
    title TEXT,
    description TEXT,
    cvss_score REAL,
    cvss_vector TEXT,
    severity TEXT,
    -- critical, high, medium, low, informational
    confidence TEXT NOT NULL DEFAULT 'low',
    -- high, medium, low — how confident is the version match
    evidence_type TEXT NOT NULL DEFAULT 'hypothesis',
    -- observed, external_intelligence, hypothesis, recommendation
    evidence_detail TEXT,
    -- Why this evidence type was assigned
    source TEXT,
    -- e.g., "NVD", "CISA KEV"
    source_url TEXT,
    is_kev INTEGER DEFAULT 0,
    -- 1 if in CISA Known Exploited Vulnerabilities
    kev_due_date TEXT,
    -- KEV remediation due date
    priority_score REAL,
    priority_factors TEXT,
    -- JSON: list of factors that contributed to the score
    match_detail TEXT,
    -- How the CVE was matched (CPE, version range, etc.)
    intel_timestamp TEXT,
    -- When the intelligence data was retrieved
    -- Analyst lifecycle fields (Phase 5)
    analyst_status TEXT NOT NULL DEFAULT 'new',
    -- FindingStatus: new, triaged, verified, remediation_planned, remediated, closed, false_positive, accepted_risk
    analyst_decision TEXT NOT NULL DEFAULT 'pending',
    -- AnalystDecision: pending, verify, false_positive, accept_risk, remediate, snooze
    decision_reason TEXT NOT NULL DEFAULT '',
    false_positive_reason TEXT,
    decided_by TEXT,
    decided_at TEXT,
    status_changed_at TEXT,
    status_changed_by TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

-- Intelligence cache: stores NVD/KEV API responses
CREATE TABLE IF NOT EXISTS intel_cache (
    cache_key TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    -- "nvd", "kev"
    response_data TEXT NOT NULL,
    -- JSON response body
    fetched_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

-- Audit log (populated in Week 4)
CREATE TABLE IF NOT EXISTS audit_log (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    user_id TEXT,
    action TEXT NOT NULL,
    -- e.g., "scan_started", "report_exported", "target_rejected"
    target TEXT,
    detail TEXT,
    ip_address TEXT
);

-- Reports table: generated reports
CREATE TABLE IF NOT EXISTS reports (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    format TEXT NOT NULL DEFAULT 'json',
    -- json, html
    content TEXT,
    -- Report content or file path
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

-- Indexes for query performance
CREATE INDEX IF NOT EXISTS idx_hosts_scan_id ON hosts(scan_id);
CREATE INDEX IF NOT EXISTS idx_services_host_id ON services(host_id);
CREATE INDEX IF NOT EXISTS idx_services_scan_id ON services(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_service_id ON findings(service_id);
CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_cve_id ON findings(cve_id);
CREATE INDEX IF NOT EXISTS idx_intel_cache_expires ON intel_cache(expires_at);
CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_reports_scan_id ON reports(scan_id);

-- Assets table: inventory of known hosts with business context (Phase 3)
CREATE TABLE IF NOT EXISTS assets (
    asset_id TEXT PRIMARY KEY,
    hostname TEXT NOT NULL DEFAULT '',
    ip TEXT NOT NULL DEFAULT '',
    environment TEXT NOT NULL DEFAULT 'LAB',
    -- LAB, DEV, TEST, STAGING, PRODUCTION
    criticality TEXT NOT NULL DEFAULT 'LOW',
    -- LOW, MEDIUM, HIGH, CRITICAL
    owner TEXT NOT NULL DEFAULT '',
    business_service TEXT NOT NULL DEFAULT '',
    internet_exposed INTEGER NOT NULL DEFAULT 0,
    -- 1 = externally exposed, 0 = internal
    notes TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_assets_ip ON assets(ip);

-- Evidence table: provenance and evidence chain for findings (Phase 6)
CREATE TABLE IF NOT EXISTS evidence (
    evidence_id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    evidence_type TEXT NOT NULL,
    -- observed, external_intelligence, hypothesis, recommendation
    source TEXT NOT NULL,
    -- nmap, nvd, cisa_kev, epss, vendor_advisory, aegis_rule, ai, analyst
    source_reference TEXT NOT NULL DEFAULT '',
    -- URL, API endpoint, rule ID, or other reference
    collected_at TEXT NOT NULL,
    content_hash TEXT NOT NULL DEFAULT '',
    -- SHA-256 of evidence content for integrity
    description TEXT NOT NULL DEFAULT '',
    raw_data TEXT,
    -- Optional raw payload (may be omitted for large data)
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_evidence_finding_id ON evidence(finding_id);
"""
