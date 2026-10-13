/* ═══════════════════════════════════════════════════════
   AEGIS-Recon Dashboard — Application Logic
   ═══════════════════════════════════════════════════════ */

const API_BASE = '/api';
let currentScanId = null;
let severityChart = null;
let evidenceChart = null;

// ─── Initialization ────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
    setupNavigation();
    setupScanForm();
    checkHealth();
    loadDashboard();
});

// ─── Navigation ────────────────────────────────────────

function setupNavigation() {
    document.querySelectorAll('.nav-link').forEach(link => {
        link.addEventListener('click', () => {
            navigateTo(link.dataset.view);
        });
    });
}

function navigateTo(viewName) {
    // Hide all views
    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
    document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));

    // Show target view
    const view = document.getElementById(`view-${viewName}`);
    if (view) view.classList.add('active');

    const navLink = document.querySelector(`.nav-link[data-view="${viewName}"]`);
    if (navLink) navLink.classList.add('active');

    // Load data for the view
    if (viewName === 'dashboard') loadDashboard();
    if (viewName === 'history') loadHistory();
}

// ─── Health Check ──────────────────────────────────────

async function checkHealth() {
    try {
        const res = await fetch(`${API_BASE}/health`);
        const data = await res.json();
        const dot = document.getElementById('api-status-dot');
        const text = document.getElementById('api-status-text');

        if (data.status === 'healthy') {
            dot.className = 'status-dot online';
            text.textContent = 'Connected';
        } else {
            dot.className = 'status-dot';
            text.textContent = 'Degraded';
        }
    } catch (e) {
        document.getElementById('api-status-dot').className = 'status-dot offline';
        document.getElementById('api-status-text').textContent = 'Disconnected';
    }
}

// ─── Dashboard ─────────────────────────────────────────

async function loadDashboard() {
    try {
        const res = await fetch(`${API_BASE}/scans?limit=10`);
        const data = await res.json();
        const scans = data.scans || [];

        // Stats
        document.getElementById('stat-total-scans').textContent = scans.length;

        let totalServices = 0;
        let totalFindings = 0;
        let criticalCount = 0;

        // Load findings for each scan to compute stats
        for (const scan of scans.slice(0, 5)) {
            totalServices += scan.hosts_up || 0;
            try {
                const fRes = await fetch(`${API_BASE}/findings/${scan.id}`);
                const fData = await fRes.json();
                const findings = fData.findings || [];
                totalFindings += findings.length;
                criticalCount += findings.filter(f => f.severity === 'critical').length;
            } catch (e) { /* ignore */ }
        }

        document.getElementById('stat-total-services').textContent = totalServices;
        document.getElementById('stat-total-findings').textContent = totalFindings;
        document.getElementById('stat-critical').textContent = criticalCount;

        // Recent scans table
        renderRecentScans(scans.slice(0, 5));

        // Charts (using aggregated data)
        updateCharts(scans);

    } catch (e) {
        console.error('Dashboard load error:', e);
    }
}

function renderRecentScans(scans) {
    const tbody = document.getElementById('recent-scans-body');
    const emptyMsg = document.getElementById('no-scans-msg');

    if (!scans.length) {
        tbody.innerHTML = '';
        emptyMsg.classList.remove('hidden');
        return;
    }

    emptyMsg.classList.add('hidden');
    tbody.innerHTML = scans.map(s => `
        <tr>
            <td><strong>${escapeHtml(s.target)}</strong></td>
            <td>${escapeHtml(s.profile)}</td>
            <td><span class="badge badge-${s.status === 'completed' ? 'success' : 'failed'}">${s.status}</span></td>
            <td>${s.hosts_up || 0}</td>
            <td>${formatTime(s.start_time)}</td>
            <td>
                <button class="btn btn-sm" onclick="viewScanDetail('${s.id}')">View</button>
            </td>
        </tr>
    `).join('');
}

async function updateCharts(scans) {
    // Aggregate severity data from all scans
    const sevCounts = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
    const evCounts = { observed: 0, external_intelligence: 0, hypothesis: 0, recommendation: 0 };

    for (const scan of scans.slice(0, 10)) {
        try {
            const res = await fetch(`${API_BASE}/findings/${scan.id}`);
            const data = await res.json();
            for (const f of (data.findings || [])) {
                const sev = f.severity || 'informational';
                if (sev in sevCounts) sevCounts[sev]++;
                const ev = f.evidence_type || 'hypothesis';
                if (ev in evCounts) evCounts[ev]++;
            }
        } catch (e) { /* ignore */ }
    }

    renderSeverityChart(sevCounts);
    renderEvidenceChart(evCounts);
}

function renderSeverityChart(counts) {
    const ctx = document.getElementById('severity-chart');
    if (!ctx) return;

    if (severityChart) severityChart.destroy();

    severityChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
            datasets: [{
                data: [counts.critical, counts.high, counts.medium, counts.low, counts.informational],
                backgroundColor: ['#ff3b5c', '#ff6d3a', '#ffb133', '#33ddb5', '#6e8eff'],
                borderColor: '#131829',
                borderWidth: 2,
            }],
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: '#a0a8c8', font: { family: 'Inter', size: 11 }, padding: 12 },
                },
            },
        },
    });
}

function renderEvidenceChart(counts) {
    const ctx = document.getElementById('evidence-chart');
    if (!ctx) return;

    if (evidenceChart) evidenceChart.destroy();

    evidenceChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['Observed', 'External Intel', 'Hypothesis', 'Recommendation'],
            datasets: [{
                label: 'Count',
                data: [counts.observed, counts.external_intelligence, counts.hypothesis, counts.recommendation],
                backgroundColor: ['#34d399', '#6e8eff', '#ffb133', '#a0a8c8'],
                borderRadius: 4,
            }],
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: { display: false },
            },
            scales: {
                x: { ticks: { color: '#6b7499', font: { family: 'Inter', size: 10 } }, grid: { display: false } },
                y: { ticks: { color: '#6b7499', stepSize: 1 }, grid: { color: 'rgba(42,49,85,0.3)' } },
            },
        },
    });
}

// ─── Scan Form ─────────────────────────────────────────

function setupScanForm() {
    const form = document.getElementById('scan-form');
    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        await startScan();
    });
}

async function startScan() {
    const target = document.getElementById('scan-target').value.trim();
    const profile = document.getElementById('scan-profile').value;
    const ports = document.getElementById('scan-ports').value.trim() || null;

    if (!target) { showToast('Please enter a target.', 'error'); return; }

    // Disable form
    const submitBtn = document.getElementById('scan-submit');
    submitBtn.disabled = true;
    submitBtn.querySelector('.btn-text').textContent = 'Scanning...';
    submitBtn.querySelector('.btn-spinner').classList.remove('hidden');

    // Show progress
    const progress = document.getElementById('scan-progress');
    progress.classList.remove('hidden');
    const progressFill = document.getElementById('scan-progress-fill');
    progressFill.style.width = '30%';
    document.getElementById('scan-progress-text').textContent = 'Validating target and starting Nmap...';

    try {
        progressFill.style.width = '50%';
        document.getElementById('scan-progress-text').textContent = 'Scan in progress...';

        const res = await fetch(`${API_BASE}/scans`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target, profile, ports }),
        });

        const data = await res.json();

        progressFill.style.width = '100%';
        progress.classList.add('hidden');

        if (res.ok) {
            currentScanId = data.scan_id;
            const result = document.getElementById('scan-result');
            result.classList.remove('hidden');
            document.getElementById('scan-result-title').textContent =
                data.status === 'completed' ? '✅ Scan Complete' : `⚠️ Scan ${data.status}`;
            document.getElementById('scan-result-message').textContent = data.message;
            showToast(`Scan ${data.status}: ${data.target}`, data.status === 'completed' ? 'success' : 'error');
        } else {
            showToast(data.message || data.detail || 'Scan failed.', 'error');
        }
    } catch (e) {
        showToast(`Error: ${e.message}`, 'error');
        progress.classList.add('hidden');
    }

    // Re-enable form
    submitBtn.disabled = false;
    submitBtn.querySelector('.btn-text').textContent = 'Launch Scan';
    submitBtn.querySelector('.btn-spinner').classList.add('hidden');
}

async function enrichScan() {
    if (!currentScanId) return;

    const btn = document.getElementById('btn-enrich');
    btn.disabled = true;
    btn.textContent = 'Enriching...';
    showToast('Starting CVE enrichment...', 'info');

    try {
        const res = await fetch(`${API_BASE}/findings/${currentScanId}/enrich`, { method: 'POST' });
        const data = await res.json();

        if (res.ok) {
            showToast(`Enrichment complete: ${data.findings_created} findings.`, 'success');
            btn.textContent = `✅ ${data.findings_created} Findings`;
        } else {
            showToast(data.detail || 'Enrichment failed.', 'error');
            btn.textContent = 'Retry Enrichment';
            btn.disabled = false;
        }
    } catch (e) {
        showToast(`Enrichment error: ${e.message}`, 'error');
        btn.textContent = 'Retry Enrichment';
        btn.disabled = false;
    }
}

function viewScanResults() {
    if (currentScanId) viewScanDetail(currentScanId);
}

// ─── History ───────────────────────────────────────────

async function loadHistory() {
    try {
        const res = await fetch(`${API_BASE}/scans?limit=100`);
        const data = await res.json();
        const scans = data.scans || [];

        const tbody = document.getElementById('history-table-body');
        tbody.innerHTML = scans.map(s => `
            <tr>
                <td><strong>${escapeHtml(s.target)}</strong></td>
                <td>${escapeHtml(s.profile)}</td>
                <td><span class="badge badge-${s.status === 'completed' ? 'success' : 'failed'}">${s.status}</span></td>
                <td>${s.hosts_up || 0}</td>
                <td>${formatTime(s.start_time)}</td>
                <td>
                    <button class="btn btn-sm" onclick="viewScanDetail('${s.id}')">Details</button>
                </td>
            </tr>
        `).join('');
    } catch (e) {
        showToast('Failed to load history.', 'error');
    }
}

// ─── Scan Detail ───────────────────────────────────────

async function viewScanDetail(scanId) {
    currentScanId = scanId;
    navigateTo('detail');

    try {
        // Load scan data
        const scanRes = await fetch(`${API_BASE}/scans/${scanId}`);
        const scanData = await scanRes.json();

        document.getElementById('detail-title').textContent =
            `Scan: ${scanData.scan.target} (${scanData.scan.profile})`;

        // Services table
        const svcBody = document.getElementById('detail-services-body');
        svcBody.innerHTML = (scanData.services || []).map(s => `
            <tr>
                <td>${escapeHtml(s.ip || '')}</td>
                <td><strong>${s.port}</strong>/${s.protocol}</td>
                <td>${escapeHtml(s.service_name || '')}</td>
                <td>${escapeHtml(s.product || '')}</td>
                <td>${escapeHtml(s.version || '')}</td>
                <td style="font-size:0.75rem;color:var(--text-muted)">${escapeHtml(truncate(s.cpe || '[]', 60))}</td>
            </tr>
        `).join('');

        // Load findings
        const findRes = await fetch(`${API_BASE}/findings/${scanId}`);
        const findData = await findRes.json();
        renderFindings(findData.findings || []);

        // Load analysis
        const analysisRes = await fetch(`${API_BASE}/reports/${scanId}/analysis`);
        const analysisData = await analysisRes.json();
        renderAnalysis(analysisData.analysis || {});

    } catch (e) {
        showToast(`Error loading scan: ${e.message}`, 'error');
    }
}

function renderFindings(findings) {
    const container = document.getElementById('findings-container');
    const emptyMsg = document.getElementById('no-findings-msg');

    if (!findings.length) {
        container.innerHTML = '';
        emptyMsg.classList.remove('hidden');
        return;
    }

    emptyMsg.classList.add('hidden');
    container.innerHTML = findings.map(f => `
        <div class="finding-card ${f.severity || 'informational'}">
            <div class="finding-header">
                <span class="badge badge-${f.severity || 'informational'}">${f.severity || 'info'}</span>
                ${f.is_kev ? '<span class="badge badge-kev">⚡ KEV</span>' : ''}
                <span class="badge badge-confidence">Confidence: ${f.confidence || '?'}</span>
                <span class="finding-title">${escapeHtml(f.cve_id || 'Unknown')}</span>
            </div>
            <div class="finding-meta">
                ${escapeHtml(f.product || '')} ${escapeHtml(f.version || '')} on
                ${escapeHtml(f.ip || '')}:${f.port || '?'} (${escapeHtml(f.service_name || '')})
                ${f.cvss_score ? ` • CVSS: ${f.cvss_score}` : ''}
                ${f.priority_score ? ` • Priority: ${f.priority_score}` : ''}
            </div>
            <div class="finding-meta" style="margin-top: 0.2rem;">
                Evidence: <span class="badge badge-${f.evidence_type === 'external_intelligence' ? 'confidence' : 'informational'}">${f.evidence_type || '?'}</span>
            </div>
            ${f.evidence_detail ? `<div class="finding-evidence">${escapeHtml(truncate(f.evidence_detail, 200))}</div>` : ''}
        </div>
    `).join('');
}

function renderAnalysis(analysis) {
    const container = document.getElementById('analysis-container');
    if (!analysis || !analysis.summary) {
        container.innerHTML = '<p style="color:var(--text-muted)">No analysis available. Enrich the scan first.</p>';
        return;
    }

    container.innerHTML = `
        <div class="analysis-section">
            <h4>Summary</h4>
            <p>${escapeHtml(analysis.summary)}</p>
        </div>
        ${analysis.risk_overview ? `
        <div class="analysis-section">
            <h4>Risk Overview</h4>
            <p>${escapeHtml(analysis.risk_overview)}</p>
        </div>` : ''}
        ${analysis.recommendations && analysis.recommendations.length ? `
        <div class="analysis-section">
            <h4>Recommendations</h4>
            <ol>${analysis.recommendations.map(r => `<li>${escapeHtml(r)}</li>`).join('')}</ol>
        </div>` : ''}
        ${analysis.confidence_notes ? `
        <div class="analysis-section">
            <h4>Confidence Notes</h4>
            <p>${escapeHtml(analysis.confidence_notes)}</p>
        </div>` : ''}
        ${analysis.limitations ? `
        <div class="analysis-section">
            <h4>Limitations</h4>
            <p>${escapeHtml(analysis.limitations)}</p>
        </div>` : ''}
        <div style="font-size: 0.75rem; color: var(--text-muted); margin-top: 0.5rem;">
            Analysis method: ${analysis.analysis_method || 'unknown'}
        </div>
    `;
}

// ─── Report Downloads ──────────────────────────────────

async function enrichCurrentScan() {
    if (!currentScanId) return;
    const btn = event.target;
    btn.disabled = true;
    btn.textContent = '⏳ Enriching...';

    try {
        const res = await fetch(`${API_BASE}/findings/${currentScanId}/enrich`, { method: 'POST' });
        const data = await res.json();
        showToast(`${data.findings_created} findings created.`, 'success');
        btn.textContent = '✅ Done';
        // Reload detail view
        setTimeout(() => viewScanDetail(currentScanId), 500);
    } catch (e) {
        showToast(`Enrichment error: ${e.message}`, 'error');
        btn.textContent = '🔍 Enrich CVEs';
        btn.disabled = false;
    }
}

async function downloadJSON() {
    if (!currentScanId) return;
    window.open(`${API_BASE}/reports/${currentScanId}/json`, '_blank');
}

async function downloadHTML() {
    if (!currentScanId) return;
    window.open(`${API_BASE}/reports/${currentScanId}/html`, '_blank');
}

// ─── Toast Notifications ───────────────────────────────

function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    container.appendChild(toast);
    setTimeout(() => toast.remove(), 4000);
}

// ─── Utilities ─────────────────────────────────────────

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = String(text);
    return div.innerHTML;
}

function truncate(text, len) {
    if (!text) return '';
    text = String(text);
    return text.length > len ? text.slice(0, len) + '…' : text;
}

function formatTime(isoString) {
    if (!isoString) return '—';
    try {
        const d = new Date(isoString);
        return d.toLocaleString();
    } catch (e) {
        return isoString;
    }
}
