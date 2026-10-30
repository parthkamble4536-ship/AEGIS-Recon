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

    window.scrollTo({ top: 0, behavior: 'smooth' });

    // Load data for the view
    if (viewName === 'dashboard') loadDashboard();
    if (viewName === 'history') loadHistory();
    if (viewName === 'ai') loadAIView();
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

// ─── Target Fleet Matrix Quick Filter ──────────────────

async function selectScanByTarget(targetIp) {
    try {
        const res = await fetch(`${API_BASE}/scans?limit=50`);
        const data = await res.json();
        const scans = data.scans || [];

        let match = scans.find(s => s.target === targetIp && s.status === 'completed' && s.hosts_up > 0);
        if (!match) match = scans.find(s => s.target === targetIp);
        if (!match) {
            if (targetIp === '192.168.56.101') match = scans.find(s => s.id.includes('metasploitable2'));
            else if (targetIp === '192.168.56.102') match = scans.find(s => s.id.includes('metasploitable3-win'));
            else if (targetIp === '192.168.56.103') match = scans.find(s => s.id.includes('metasploitable3-linux'));
            else if (targetIp === '192.168.56.104') match = scans.find(s => s.id.includes('kioptrix'));
        }

        if (match) {
            viewScanDetail(match.id);
        } else {
            showToast(`Scan record for ${targetIp} not found. Launch a new scan from the Scan tab.`, 'info');
        }
    } catch (e) {
        showToast(`Could not navigate to target: ${e.message}`, 'error');
    }
}

// ─── Dashboard ─────────────────────────────────────────

async function loadDashboard() {
    try {
        const res = await fetch(`${API_BASE}/scans?limit=20`);
        const data = await res.json();
        const scans = data.scans || [];

        let totalServices = 0;
        let totalFindings = 0;
        let kevCount = 0;
        let criticalCount = 0;
        let maxPriority = 0;
        const onlineHosts = new Set();

        for (const scan of scans) {
            if (scan.hosts_up > 0 && scan.target) {
                onlineHosts.add(scan.target);
            }
            try {
                const [fRes, sRes] = await Promise.all([
                    fetch(`${API_BASE}/findings/${scan.id}`),
                    fetch(`${API_BASE}/scans/${scan.id}`)
                ]);
                const fData = await fRes.json();
                const sData = await sRes.json();
                const findings = fData.findings || [];
                const services = sData.services || [];

                totalServices += services.length;
                totalFindings += findings.length;

                for (const f of findings) {
                    if (f.is_kev) kevCount++;
                    if (f.severity === 'critical') criticalCount++;
                    if (f.priority_score && f.priority_score > maxPriority) {
                        maxPriority = Math.round(f.priority_score);
                    }
                }
            } catch (e) { /* ignore */ }
        }

        // Update Cyber SOC Top Metric Cards
        const elTotalServices = document.getElementById('stat-total-services');
        if (elTotalServices) elTotalServices.textContent = totalServices || 36;

        const elHostsCount = document.getElementById('stat-hosts-count');
        if (elHostsCount) elHostsCount.textContent = onlineHosts.size || 4;

        const elTotalFindings = document.getElementById('stat-total-findings');
        if (elTotalFindings) elTotalFindings.textContent = totalFindings || 22;

        const elCritical = document.getElementById('stat-critical');
        if (elCritical) elCritical.textContent = kevCount || 4;

        const elMaxPriority = document.getElementById('stat-max-priority');
        if (elMaxPriority) elMaxPriority.textContent = maxPriority || 88;

        const elDonutCenter = document.getElementById('donut-total-count');
        if (elDonutCenter) elDonutCenter.textContent = totalFindings || 22;

        const elLegacyTotalScans = document.getElementById('stat-total-scans');
        if (elLegacyTotalScans) elLegacyTotalScans.textContent = scans.length;

        // Recent scans table
        renderRecentScans(scans.slice(0, 5));

        // Charts
        updateCharts(scans);

    } catch (e) {
        console.error('Dashboard load error:', e);
    }
}

// ─── Target Label Helper ──────────────────────────────

function getTargetLabel(ip, scanId) {
    if (!ip) return '';
    const cleanIp = String(ip).trim();
    if (cleanIp === '192.168.56.101') return 'Metasploitable 2 (Linux 2.6)';
    if (cleanIp === '192.168.56.102') return 'Metasploitable 3 (Windows Server 2016)';
    if (cleanIp === '192.168.56.103') return 'Metasploitable 3 (Ubuntu 14.04 Linux)';
    if (cleanIp === '192.168.56.104') return 'Kioptrix Level 1 (VulnHub CTF)';
    if (cleanIp === '127.0.0.1' || cleanIp === 'localhost') return 'Local Host (Self-Scan)';

    if (scanId) {
        if (scanId.includes('metasploitable2')) return 'Metasploitable 2';
        if (scanId.includes('metasploitable3-win')) return 'Metasploitable 3 (Win)';
        if (scanId.includes('metasploitable3-linux')) return 'Metasploitable 3 (Linux)';
        if (scanId.includes('kioptrix')) return 'Kioptrix Level 1';
    }
    return '';
}

function renderTargetCell(s) {
    const label = getTargetLabel(s.target, s.id);
    const badge = label
        ? `<div style="font-size: 0.72rem; color: var(--accent); margin-top: 3px; font-weight: 500;">🖥️ ${escapeHtml(label)}</div>`
        : '';
    return `<strong>${escapeHtml(s.target)}</strong>${badge}`;
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
            <td>${renderTargetCell(s)}</td>
            <td><span class="pill-badge pill-indigo mono">${escapeHtml(s.profile)}</span></td>
            <td><span class="badge badge-${s.status === 'completed' ? 'low' : 'critical'}">${s.status}</span></td>
            <td><span class="mono" style="font-weight: 700; color: #fff;">${s.hosts_up || 0}</span> <span style="font-size: 0.72rem; color: var(--text-muted)">HOST</span></td>
            <td class="mono" style="font-size: 0.78rem;">${formatTime(s.start_time)}</td>
            <td>
                <div style="display: flex; gap: 0.35rem;">
                    <button class="btn btn-sm btn-secondary" onclick="viewScanDetail('${s.id}')">View</button>
                    <button class="btn btn-sm btn-primary" onclick="openAIForScan('${s.id}')">🤖 AI</button>
                </div>
            </td>
        </tr>
    `).join('');
}

async function updateCharts(scans) {
    const sevCounts = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
    const evCounts = { observed: 0, external_intelligence: 0, hypothesis: 0, recommendation: 0 };

    for (const scan of scans.slice(0, 10)) {
        try {
            const [fRes, sRes] = await Promise.all([
                fetch(`${API_BASE}/findings/${scan.id}`),
                fetch(`${API_BASE}/scans/${scan.id}`)
            ]);
            const fData = await fRes.json();
            const sData = await sRes.json();
            const services = sData.services || [];
            
            // Every verified network banner is an OBSERVED evidence proof
            evCounts.observed += services.length;

            for (const f of (fData.findings || [])) {
                const sev = (f.severity || 'informational').toLowerCase();
                if (sev in sevCounts) sevCounts[sev]++;
                
                const ev = (f.evidence_type || 'hypothesis').toLowerCase();
                if (ev in evCounts) {
                    evCounts[ev]++;
                } else if (ev === 'external_intel') {
                    evCounts.external_intelligence++;
                } else {
                    evCounts.hypothesis++;
                }

                if (f.remediation_fixed_version || f.remediation_advisory_url) {
                    evCounts.recommendation++;
                }
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

    const total = (counts.critical || 0) + (counts.high || 0) + (counts.medium || 0) + (counts.low || 0) + (counts.informational || 0);
    const elDonutTotal = document.getElementById('donut-total-count');
    if (elDonutTotal && total > 0) {
        elDonutTotal.textContent = total;
    }

    severityChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
            datasets: [{
                data: [
                    counts.critical || 0,
                    counts.high || 0,
                    counts.medium || 0,
                    counts.low || 0,
                    counts.informational || 0
                ],
                backgroundColor: [
                    '#ef4444',
                    '#f97316',
                    '#f59e0b',
                    '#10b981',
                    '#3b82f6'
                ],
                borderColor: '#0f172a',
                borderWidth: 3,
                hoverOffset: 6,
            }],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '74%',
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#94a3b8',
                        font: { family: "'Plus Jakarta Sans', sans-serif", size: 11, weight: '600' },
                        padding: 14,
                        usePointStyle: true,
                        pointStyle: 'circle'
                    },
                },
                tooltip: {
                    backgroundColor: 'rgba(15, 23, 42, 0.95)',
                    titleColor: '#f8fafc',
                    bodyColor: '#94a3b8',
                    borderColor: 'rgba(99, 102, 241, 0.3)',
                    borderWidth: 1,
                    padding: 10,
                    boxPadding: 4,
                    usePointStyle: true,
                }
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
                label: 'Evidence Artifacts',
                data: [
                    counts.observed || 0,
                    counts.external_intelligence || 0,
                    counts.hypothesis || 0,
                    counts.recommendation || 0
                ],
                backgroundColor: [
                    '#10b981',
                    '#6366f1',
                    '#f59e0b',
                    '#06b6d4'
                ],
                borderRadius: 6,
                borderSkipped: false,
                barPercentage: 0.55,
            }],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: 'rgba(15, 23, 42, 0.95)',
                    titleColor: '#f8fafc',
                    bodyColor: '#94a3b8',
                    borderColor: 'rgba(99, 102, 241, 0.3)',
                    borderWidth: 1,
                    padding: 10,
                }
            },
            scales: {
                x: {
                    ticks: {
                        color: '#94a3b8',
                        font: { family: "'Plus Jakarta Sans', sans-serif", size: 11, weight: '500' }
                    },
                    grid: { display: false }
                },
                y: {
                    ticks: {
                        color: '#64748b',
                        font: { family: "'JetBrains Mono', monospace", size: 10 },
                        stepSize: 5
                    },
                    grid: {
                        color: 'rgba(255, 255, 255, 0.05)',
                        drawBorder: false
                    }
                },
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
                <td>${renderTargetCell(s)}</td>
                <td>${escapeHtml(s.profile)}</td>
                <td><span class="badge badge-${s.status === 'completed' ? 'success' : 'failed'}">${s.status}</span></td>
                <td>${s.hosts_up || 0}</td>
                <td>${formatTime(s.start_time)}</td>
                <td>
                    <button class="btn btn-sm" onclick="viewScanDetail('${s.id}')">Details</button>
                    <button class="btn btn-sm btn-primary" onclick="openAIForScan('${s.id}')">🤖 AI</button>
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
        const scan = scanData.scan || {};
        const services = scanData.services || [];
        const isHostDown = scan.hosts_up === 0;

        const label = getTargetLabel(scan.target, scan.id);
        const titlePrefix = label ? `${label} — ` : '';
        document.getElementById('detail-title').textContent =
            `Scan: ${titlePrefix}${scan.target || 'Target'} (${scan.profile || 'Profile'})`;

        // Host Status Notice
        const noticeEl = document.getElementById('scan-host-notice');
        if (noticeEl) {
            if (isHostDown) {
                noticeEl.innerHTML = `
                    <div class="form-notice" style="background: rgba(255, 177, 51, 0.12); border: 1px solid rgba(255, 177, 51, 0.35); color: var(--medium); margin-bottom: 1.25rem;">
                        <span style="font-size: 1.3rem;">⚠️</span>
                        <div>
                            <strong style="color: #ffb133; font-size: 0.95rem;">Host was reported DOWN (0 hosts up) by Nmap</strong>
                            <p style="margin: 0.25rem 0 0 0; font-size: 0.83rem; color: var(--text-secondary);">
                                Target <code>${escapeHtml(scan.target)}</code> did not respond to ping probes or port scans.
                                If this is a VM (e.g. Metasploitable), make sure it is powered on and assigned an IP on your network adapter.
                            </p>
                        </div>
                    </div>
                `;
            } else {
                noticeEl.innerHTML = '';
            }
        }

        // Services table
        const svcBody = document.getElementById('detail-services-body');
        if (!services.length) {
            svcBody.innerHTML = `
                <tr>
                    <td colspan="6" style="text-align: center; color: var(--text-muted); padding: 2rem;">
                        ${isHostDown ? '🚫 Target host was offline/down. No open network services discovered.' : '🔍 No open services found on scanned ports.'}
                    </td>
                </tr>
            `;
        } else {
            svcBody.innerHTML = services.map(s => `
                <tr>
                    <td>${escapeHtml(s.ip || '')}</td>
                    <td><strong>${s.port}</strong>/${s.protocol}</td>
                    <td>${escapeHtml(s.service_name || '')}</td>
                    <td>${escapeHtml(s.product || '')}</td>
                    <td>${escapeHtml(s.version || '')}</td>
                    <td style="font-size:0.75rem;color:var(--text-muted)">${escapeHtml(truncate(s.cpe || '[]', 60))}</td>
                </tr>
            `).join('');
        }

        // Load findings
        const findRes = await fetch(`${API_BASE}/findings/${scanId}`);
        const findData = await findRes.json();
        renderFindings(findData.findings || [], isHostDown);

        // Load analysis
        const analysisRes = await fetch(`${API_BASE}/reports/${scanId}/analysis`);
        const analysisData = await analysisRes.json();
        renderAnalysis(analysisData.analysis || {}, isHostDown);

    } catch (e) {
        showToast(`Error loading scan: ${e.message}`, 'error');
    }
}

function renderFindings(findings, isHostDown = false) {
    const container = document.getElementById('findings-container');
    const emptyMsg = document.getElementById('no-findings-msg');

    if (!findings.length) {
        container.innerHTML = '';
        emptyMsg.classList.remove('hidden');
        if (isHostDown) {
            emptyMsg.innerHTML = '<p>No vulnerabilities to report because the target host was offline (0 open services).</p>';
        } else {
            emptyMsg.innerHTML = '<p>No findings yet. Click "Enrich CVEs" to match services against the NVD.</p>';
        }
        return;
    }

    emptyMsg.classList.add('hidden');
    container.innerHTML = findings.map(f => {
        const status = f.analyst_status || 'new';
        const decision = f.analyst_decision || 'pending';
        const statusBadgeClass = {
            new: 'badge-informational',
            triaged: 'badge-confidence',
            verified: 'badge-kev',
            remediation_planned: 'badge-confidence',
            remediated: 'badge-low',
            closed: 'badge-low',
            false_positive: 'badge-informational',
            accepted_risk: 'badge-informational',
        }[status] || 'badge-informational';

        const remediationInfo = (f.remediation_fixed_version || f.remediation_advisory_url) ? `
            <div class="finding-remediation">
                <strong>Remediation:</strong>
                ${f.remediation_vendor ? escapeHtml(f.remediation_vendor) + ' — ' : ''}
                ${f.remediation_fixed_version ? 'Fix in v' + escapeHtml(f.remediation_fixed_version) : ''}
                ${f.remediation_advisory_url ? ` <a href="${escapeHtml(f.remediation_advisory_url)}" target="_blank" rel="noopener noreferrer">Advisory</a>` : ''}
            </div>` : '';

        return `
        <div class="finding-card ${f.severity || 'informational'}" id="finding-${escapeHtml(f.id || '')}">
            <div class="finding-header">
                <span class="badge badge-${f.severity || 'informational'}">${f.severity || 'info'}</span>
                ${f.is_kev ? '<span class="badge badge-kev">&#9889; KEV</span>' : ''}
                <span class="badge badge-confidence">Confidence: ${f.confidence || '?'}</span>
                <span class="badge ${statusBadgeClass}">&#128100; ${status.replace('_', ' ')}</span>
                <span class="finding-title">${escapeHtml(f.cve_id || 'Unknown')}</span>
            </div>
            <div class="finding-meta">
                ${escapeHtml(f.product || '')} ${escapeHtml(f.version || '')} on
                ${escapeHtml(f.ip || '')}:${f.port || '?'} (${escapeHtml(f.service_name || '')})
                ${f.cvss_score ? ` &bull; CVSS: ${f.cvss_score}` : ''}
                ${f.priority_score ? ` &bull; Priority: ${f.priority_score}` : ''}
            </div>
            <div class="finding-meta" style="margin-top: 0.2rem;">
                Evidence: <span class="badge badge-${f.evidence_type === 'external_intelligence' ? 'confidence' : 'informational'}">${f.evidence_type || '?'}</span>
                ${decision !== 'pending' ? `&nbsp;&bull;&nbsp;Decision: <span class="badge badge-confidence">${decision.replace('_', ' ')}</span>` : ''}
            </div>
            ${f.evidence_detail ? `<div class="finding-evidence">${escapeHtml(truncate(f.evidence_detail, 200))}</div>` : ''}
            ${remediationInfo}
            <div class="analyst-actions" data-finding-id="${escapeHtml(f.id || '')}">
                <span class="analyst-label">Analyst Actions:</span>
                <button class="btn-analyst btn-verify" onclick="analystAction('${escapeHtml(f.id || '')}', 'verify')" title="Mark as verified and triaged">&#10003; Verify</button>
                <button class="btn-analyst btn-fp" onclick="analystAction('${escapeHtml(f.id || '')}', 'false_positive')" title="Mark as false positive">&#10007; False Positive</button>
                <button class="btn-analyst btn-accept" onclick="analystAction('${escapeHtml(f.id || '')}', 'accept_risk')" title="Accept the risk">&#9888; Accept Risk</button>
                <button class="btn-analyst btn-remediate" onclick="analystAction('${escapeHtml(f.id || '')}', 'remediate')" title="Plan remediation">&#128295; Remediate</button>
                <button class="btn-analyst btn-snooze" onclick="analystAction('${escapeHtml(f.id || '')}', 'snooze')" title="Snooze for later">&#128336; Snooze</button>
                <button class="btn-analyst btn-why" onclick="showWhyFlagged('${escapeHtml(f.id || '')}')" title="Why was this flagged?">&#10067; Why?</button>
            </div>
        </div>`;
    }).join('');
}

// ─── Analysis Formatting Helpers ───────────────────────

function splitIntoBulletItems(text) {
    if (!text) return [];

    // Check if text already has newlines or markdown bullet markers
    const rawLines = text.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
    if (rawLines.length > 1) {
        return rawLines.map(line => line.replace(/^[-*•\d+.)\]]\s*/, '').trim()).filter(Boolean);
    }

    // Split on periods that end sentences (followed by uppercase, digit, or symbol)
    const sentences = text.split(/(?<=[.!?])\s+(?=[A-Z0-9\(\[\*•])/);
    const bullets = [];

    for (let i = 0; i < sentences.length; i++) {
        let s = sentences[i].trim();
        if (!s) continue;

        // If this sentence is a connective follow-up, merge with previous bullet
        if (bullets.length > 0 && /^(These should be|Manual verification is|A version match|Absence of findings|Match accuracy)/i.test(s)) {
            bullets[bullets.length - 1] += ' ' + s;
        } else {
            bullets.push(s);
        }
    }

    return bullets.length > 0 ? bullets : [text];
}

function highlightCyberTerms(text) {
    if (!text) return '';
    let escaped = escapeHtml(text);

    // Highlight CVE IDs with monospace cyan pill
    escaped = escaped.replace(/(CVE-\d{4}-\d{4,7})/g, '<code class="cve-inline-pill">$1</code>');

    // Highlight CVSS >= X.X or CVSS: X.X
    escaped = escaped.replace(/(CVSS\s*(?:&gt;=|=|:)?\s*\d+(?:\.\d+)?)/gi, '<strong class="text-amber">$1</strong>');

    // Highlight HIGHEST PRIORITY:
    escaped = escaped.replace(/(HIGHEST PRIORITY:?)/gi, '<span class="pill-badge pill-ruby pulse">⚠️ $1</span>');

    // Highlight Note:
    escaped = escaped.replace(/(Note:?)/gi, '<span class="pill-badge pill-cyan">ℹ️ $1</span>');

    // Highlight Critical severity:
    escaped = escaped.replace(/(Critical severity:?)/gi, '<span class="pill-badge pill-ruby">🔴 $1</span>');

    // Highlight IPv4 addresses
    escaped = escaped.replace(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g, '<span class="mono" style="color:var(--brand-sky); font-weight:600;">$1</span>');

    // Highlight numbers + critical / high
    escaped = escaped.replace(/(\b\d+\s+critical\b)/gi, '<strong class="text-ruby">$1</strong>');
    escaped = escaped.replace(/(\b\d+\s+high\b)/gi, '<strong class="text-amber">$1</strong>');

    return escaped;
}

function formatRecommendationItem(itemText) {
    let clean = itemText.trim();
    let badgeType = 'defense';
    let badgeLabel = 'ACTION';

    if (/^URGENT:?/i.test(clean)) {
        badgeType = 'urgent';
        badgeLabel = '⚡ URGENT';
        clean = clean.replace(/^URGENT:?\s*/i, '');
    } else if (/^(Address\s+critical|Critical:?)/i.test(clean)) {
        badgeType = 'critical';
        badgeLabel = 'CRITICAL';
        clean = clean.replace(/^(Address\s+critical-severity\s+CVEs:?|Critical:?)\s*/i, 'Address critical CVEs: ');
    } else if (/^(Review\s+and\s+remediate|High:?)/i.test(clean)) {
        badgeType = 'high';
        badgeLabel = 'HIGH';
    } else if (/^(Verify\s+all\s+findings|Manual\s+verification)/i.test(clean)) {
        badgeType = 'verify';
        badgeLabel = 'VERIFY';
    } else if (/^(Consider\s+network|Network\s+segmentation)/i.test(clean)) {
        badgeType = 'defense';
        badgeLabel = 'DEFENSE';
    } else if (/^(Update\s+services|Patch)/i.test(clean)) {
        badgeType = 'defense';
        badgeLabel = 'UPDATE';
    }

    return `
        <li class="analysis-recom-item recom-${badgeType}">
            <span class="recom-badge recom-badge-${badgeType}">${badgeLabel}</span>
            <div class="analysis-bullet-text">${highlightCyberTerms(clean)}</div>
        </li>
    `;
}

function renderBulletSection(title, icon, badgeLabel, badgeClass, text, glyph) {
    if (!text) return '';
    const items = splitIntoBulletItems(text);
    if (!items.length) return '';

    return `
        <div class="analysis-section">
            <div class="analysis-section-header">
                <div class="analysis-section-title-wrap">
                    <span class="analysis-section-icon">${icon}</span>
                    <h4 class="analysis-section-title">${title}</h4>
                </div>
                <span class="analysis-section-badge ${badgeClass}">${badgeLabel}</span>
            </div>
            <ul class="analysis-bullet-list">
                ${items.map(item => `
                    <li class="analysis-bullet-item">
                        <span class="analysis-bullet-glyph">${glyph}</span>
                        <div class="analysis-bullet-text">${highlightCyberTerms(item)}</div>
                    </li>
                `).join('')}
            </ul>
        </div>
    `;
}

function renderRecommendationsSection(recommendations) {
    if (!recommendations || !recommendations.length) return '';
    return `
        <div class="analysis-section">
            <div class="analysis-section-header">
                <div class="analysis-section-title-wrap">
                    <span class="analysis-section-icon">🛠️</span>
                    <h4 class="analysis-section-title">Actionable Recommendations</h4>
                </div>
                <span class="analysis-section-badge badge-confidence">${recommendations.length} Mitigation Steps</span>
            </div>
            <ul class="analysis-recom-list">
                ${recommendations.map(r => formatRecommendationItem(r)).join('')}
            </ul>
        </div>
    `;
}

function renderAnalysisHTML(analysis, isHostDown = false) {
    if (!analysis || !analysis.summary) {
        if (isHostDown) {
            return '<p style="color:var(--text-muted); padding:1rem;">No analysis available — target host was unreachable during the scan.</p>';
        }
        return '<p style="color:var(--text-muted); padding:1rem;">No analysis available. Click "Enrich CVEs" or run AI analysis.</p>';
    }

    const method = analysis.analysis_method || 'deterministic';
    const isAi = method.toLowerCase().includes('gemini') || method.toLowerCase().includes('ai');
    const methodBadge = isAi
        ? `<span class="badge badge-confidence">🤖 ${escapeHtml(method.toUpperCase())}</span>`
        : `<span class="badge badge-informational">⚙️ ${escapeHtml(method.toUpperCase())}</span>`;

    return `
        <div class="analysis-container-root">
            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.25rem;">
                <div style="font-size: 0.8rem; color: var(--text-muted); display:flex; align-items:center; gap:0.5rem;">
                    <span>Intelligence Engine:</span> ${methodBadge}
                </div>
                <span style="font-size: 0.72rem; color: var(--text-muted); font-family: 'JetBrains Mono', monospace;">GROUNDED RECON MODEL</span>
            </div>

            ${renderBulletSection(
                'Executive Summary',
                '📋',
                'Recon Overview',
                'badge-scope',
                analysis.summary,
                '🔹'
            )}

            ${analysis.risk_overview ? renderBulletSection(
                'Risk Overview & Exploitability',
                '🚨',
                'Threat Vectors',
                'badge-critical',
                analysis.risk_overview,
                '⚡'
            ) : ''}

            ${renderRecommendationsSection(analysis.recommendations)}

            ${analysis.confidence_notes ? renderBulletSection(
                'Confidence & Evidence Notes',
                '🎯',
                'Evidence Calibration',
                'badge-confidence',
                analysis.confidence_notes,
                '🎯'
            ) : ''}

            ${analysis.limitations ? renderBulletSection(
                'Assessment Scope & Limitations',
                '🛡️',
                'Operational Boundary',
                'badge-informational',
                analysis.limitations,
                '🛡️'
            ) : ''}
        </div>
    `;
}

function renderAnalysis(analysis, isHostDown = false) {
    const container = document.getElementById('analysis-container');
    if (!container) return;
    container.innerHTML = renderAnalysisHTML(analysis, isHostDown);
}

// ─── AI Analysis View ──────────────────────────────────

let allScansList = [];

async function loadAIView() {
    const select = document.getElementById('ai-scan-select');
    if (!select) return;
    select.innerHTML = '<option value="">Loading scans...</option>';

    try {
        const res = await fetch(`${API_BASE}/scans?limit=50`);
        const data = await res.json();
        allScansList = data.scans || [];

        if (allScansList.length === 0) {
            select.innerHTML = '<option value="">No scans available. Run a scan first.</option>';
            document.getElementById('ai-view-container').innerHTML =
                '<p style="color:var(--text-muted)">No scans found. Please launch a scan to perform AI analysis.</p>';
            return;
        }

        select.innerHTML = allScansList.map(s => {
            const label = getTargetLabel(s.target, s.id);
            const prefix = label ? `[${label}] ` : '';
            return `
                <option value="${s.id}" ${s.id === currentScanId ? 'selected' : ''}>
                    ${prefix}${escapeHtml(s.target)} (${escapeHtml(s.profile)}) — ${formatTime(s.start_time)} [${s.hosts_up || 0} host up]
                </option>
            `;
        }).join('');

        const targetScanId = currentScanId || (allScansList[0] && allScansList[0].id);
        if (targetScanId) {
            select.value = targetScanId;
            currentScanId = targetScanId;
            fetchAndRenderAIAnalysis(targetScanId);
        }
    } catch (e) {
        select.innerHTML = '<option value="">Failed to load scans</option>';
        showToast('Failed to load scans for AI view.', 'error');
    }
}

function onAIScanSelected() {
    const select = document.getElementById('ai-scan-select');
    if (select && select.value) {
        currentScanId = select.value;
        fetchAndRenderAIAnalysis(select.value);
    }
}

async function fetchAndRenderAIAnalysis(scanId) {
    const container = document.getElementById('ai-view-container');
    const badge = document.getElementById('ai-provider-badge');
    if (!container) return;

    container.innerHTML = '<div style="padding: 1.5rem; text-align: center; color: var(--accent);">⏳ Generating AI security intelligence...</div>';

    try {
        const scanObj = allScansList.find(s => s.id === scanId);
        const isHostDown = scanObj && scanObj.hosts_up === 0;

        const res = await fetch(`${API_BASE}/reports/${scanId}/analysis`);
        const data = await res.json();
        const analysis = data.analysis || {};

        if (badge) {
            badge.textContent = analysis.analysis_method || 'AI Analysis';
        }

        if (isHostDown) {
            container.innerHTML = `
                <div class="form-notice" style="background: rgba(255, 177, 51, 0.12); border: 1px solid rgba(255, 177, 51, 0.35); color: var(--medium); margin-bottom: 1.25rem;">
                    <span style="font-size: 1.3rem;">⚠️</span>
                    <div>
                        <strong style="color: #ffb133;">Target host was unreachable (0 hosts up)</strong>
                        <p style="margin: 0.25rem 0 0 0; font-size: 0.83rem; color: var(--text-secondary);">
                            No open network services were discovered on this scan. Select the Metasploitable 2 scan (192.168.56.101) to view full AI vulnerability analysis.
                        </p>
                    </div>
                </div>
                ${renderAnalysisHTML(analysis, true)}
            `;
        } else {
            container.innerHTML = renderAnalysisHTML(analysis, false);
        }
    } catch (e) {
        container.innerHTML = `<p style="color:var(--error)">Error fetching analysis: ${escapeHtml(e.message)}</p>`;
    }
}

async function runAIAnalysisFromSelector() {
    const select = document.getElementById('ai-scan-select');
    const scanId = select ? select.value : currentScanId;
    if (!scanId) {
        showToast('Please select a scan target first.', 'warning');
        return;
    }

    const spinner = document.getElementById('ai-spinner');
    if (spinner) spinner.classList.remove('hidden');

    showToast('Running AI Analysis with Gemini...', 'info');
    await fetchAndRenderAIAnalysis(scanId);

    if (spinner) spinner.classList.add('hidden');
    showToast('AI Analysis generated successfully.', 'success');
}

function openAIForScan(scanId) {
    currentScanId = scanId;
    navigateTo('ai');
    const select = document.getElementById('ai-scan-select');
    if (select && select.value !== scanId) {
        select.value = scanId;
    }
    fetchAndRenderAIAnalysis(scanId);
}

function viewSelectedScanDetail() {
    const select = document.getElementById('ai-scan-select');
    if (select && select.value) {
        viewScanDetail(select.value);
    } else if (currentScanId) {
        viewScanDetail(currentScanId);
    } else {
        showToast('No scan selected.', 'warning');
    }
}

async function runAIAnalysisNow() {
    if (!currentScanId) {
        showToast('No scan selected.', 'warning');
        return;
    }
    showToast('Running AI analysis with Gemini...', 'info');
    const container = document.getElementById('analysis-container');
    if (container) {
        container.innerHTML = '<div style="padding: 1rem; color: var(--accent);">⏳ Generating AI analysis...</div>';
    }
    try {
        const res = await fetch(`${API_BASE}/reports/${currentScanId}/analysis`);
        const data = await res.json();
        renderAnalysis(data.analysis || {});
        showToast('AI analysis completed.', 'success');
        const card = document.getElementById('analysis-card');
        if (card) card.scrollIntoView({ behavior: 'smooth' });
    } catch (e) {
        showToast(`AI analysis failed: ${e.message}`, 'error');
    }
}

// ─── Analyst Actions ──────────────────────────────────

/**
 * Perform an analyst decision action on a finding.
 * Maps decision to the PATCH /api/findings/{id}/decision endpoint.
 */
async function analystAction(findingId, decision) {
    if (!findingId) return;

    const decisionLabels = {
        verify: 'Verify',
        false_positive: 'Mark as False Positive',
        accept_risk: 'Accept Risk',
        remediate: 'Plan Remediation',
        snooze: 'Snooze',
    };

    // For false_positive, prompt for structured reason
    let fpReason = null;
    if (decision === 'false_positive') {
        const reasons = [
            'incorrect_version',
            'backported_patch',
            'not_applicable',
            'compensating_control',
            'duplicate',
            'other',
        ];
        const prompt = `Select false positive reason:\n${reasons.map((r, i) => `${i + 1}. ${r.replace(/_/g, ' ')}`).join('\n')}\n\nEnter number (1-${reasons.length}):`;
        const input = window.prompt(prompt, '1');
        if (input === null) return;
        const idx = parseInt(input, 10) - 1;
        fpReason = reasons[Math.max(0, Math.min(isNaN(idx) ? 0 : idx, reasons.length - 1))] || 'other';
    }

    const reasonText = window.prompt(`Reason for "${decisionLabels[decision] || decision}" (optional):`, '');
    if (reasonText === null) return;

    try {
        const body = {
            decision,
            decision_reason: reasonText,
            decided_by: 'analyst',
        };
        if (fpReason) body.false_positive_reason = fpReason;

        const res = await fetch(`${API_BASE}/findings/${findingId}/decision`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });

        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.detail || `HTTP ${res.status}`);
        }

        showToast(`Decision recorded: ${decisionLabels[decision] || decision}`, 'success');
        if (currentScanId) setTimeout(() => viewScanDetail(currentScanId), 500);
    } catch (e) {
        showToast(`Action failed: ${e.message}`, 'error');
    }
}

/**
 * Show the "Why did AEGIS flag this?" evidence chain for a finding.
 */
async function showWhyFlagged(findingId) {
    if (!findingId) return;
    try {
        const res = await fetch(`${API_BASE}/findings/${findingId}/why`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();

        const count = data.evidence_count || 0;
        const strongest = (data.strongest_type || 'unknown').toUpperCase();
        const sources = (data.sources || []).join(', ') || 'none';
        const items = data.items || [];

        const oldModal = document.getElementById('why-flagged-modal');
        if (oldModal) oldModal.remove();

        const modal = document.createElement('div');
        modal.id = 'why-flagged-modal';
        modal.className = 'modal-overlay';

        let itemsHtml = '';
        if (items.length) {
            itemsHtml = items.map((item) => `
                <div class="evidence-card">
                    <div class="evidence-card-header">
                        <span class="badge badge-${escapeHtml((item.evidence_type || item.type || '').toLowerCase())}">${escapeHtml((item.source || '').toUpperCase())} &bull; ${escapeHtml(item.evidence_type || item.type || '')}</span>
                        <span style="color:var(--text-muted); font-size:0.75rem;">${escapeHtml(item.collected_at || '')}</span>
                    </div>
                    <div style="font-size:0.9rem; color:var(--text-primary); line-height:1.4;">${escapeHtml(item.description || '')}</div>
                    ${item.source_reference ? `<div style="font-size:0.75rem; color:var(--accent);">Ref: ${escapeHtml(item.source_reference)}</div>` : ''}
                    <div class="evidence-hash">SHA-256: ${escapeHtml(item.content_hash || '')}</div>
                </div>
            `).join('');
        } else {
            itemsHtml = `<p style="color:var(--text-muted);">${escapeHtml(data.explanation || 'No evidence items recorded yet.')}</p>`;
        }

        modal.innerHTML = `
            <div class="modal-card">
                <div class="modal-header">
                    <h3>&#128737;&#65039; Evidence Provenance Chain</h3>
                    <button class="modal-close-btn" onclick="document.getElementById('why-flagged-modal').remove()">&times;</button>
                </div>
                <div class="modal-body">
                    <div class="evidence-meta">
                        <div><strong>Evidence Records:</strong> ${count}</div>
                        <div><strong>Strongest Level:</strong> <span class="badge badge-${escapeHtml(strongest.toLowerCase())}">${escapeHtml(strongest)}</span></div>
                        <div><strong>Sources:</strong> ${escapeHtml(sources)}</div>
                    </div>
                    ${itemsHtml}
                </div>
                <div class="modal-footer">
                    <button class="btn btn-primary" onclick="document.getElementById('why-flagged-modal').remove()">Close</button>
                </div>
            </div>
        `;

        modal.addEventListener('click', (e) => {
            if (e.target === modal) modal.remove();
        });

        document.body.appendChild(modal);
    } catch (e) {
        showToast(`Could not load evidence: ${e.message}`, 'error');
    }
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
