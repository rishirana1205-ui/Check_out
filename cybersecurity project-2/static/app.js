/* ==========================================================================
   Vulnerability Scanner — Frontend Logic
   ========================================================================== */

// --- State ---
let currentScanId = null;
let pollInterval = null;
let scanResults = null;

// --- DOM Refs ---
const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

// --- Initialization ---
document.addEventListener('DOMContentLoaded', () => {
    initEventListeners();
    loadPresets();
});

function initEventListeners() {
    // Scan form
    $('#scan-form').addEventListener('submit', (e) => {
        e.preventDefault();
        startScan();
    });

    // Port preset change
    $('#port-preset').addEventListener('change', (e) => {
        const custom = $('#custom-ports-group');
        custom.style.display = e.target.value === 'custom' ? 'block' : 'none';
    });

    // Tabs
    $$('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => switchTab(btn.dataset.tab));
    });

    // Export button
    $('#export-btn')?.addEventListener('click', exportResults);
}

async function loadPresets() {
    try {
        const res = await fetch('/api/presets');
        const data = await res.json();
        // Presets loaded for reference
    } catch (e) {
        console.warn('Could not load presets:', e);
    }
}

// --- Scan Management ---
async function startScan() {
    const target = $('#target-input').value.trim();
    if (!target) {
        showToast('Please enter a target host', 'error');
        return;
    }

    const preset = $('#port-preset').value;
    const customPorts = $('#custom-ports')?.value || '';
    const timeout = parseFloat($('#timeout-input')?.value || '1.5');

    // Disable form
    $('#scan-btn').disabled = true;
    $('#scan-btn').innerHTML = '<span class="animate-pulse">⏳</span> Scanning...';

    // Show progress
    $('.progress-section').classList.add('active');
    $('.results-section').classList.remove('active');
    resetStats();

    try {
        const body = {
            target: target,
            port_preset: preset === 'custom' ? 'quick' : preset,
            custom_ports: preset === 'custom' ? customPorts : '',
            timeout: timeout
        };

        const res = await fetch('/api/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });

        const data = await res.json();
        if (data.error) {
            showToast(data.error, 'error');
            resetScanBtn();
            return;
        }

        currentScanId = data.scan_id;
        startPolling();
    } catch (e) {
        showToast('Failed to start scan: ' + e.message, 'error');
        resetScanBtn();
    }
}

function startPolling() {
    if (pollInterval) clearInterval(pollInterval);
    pollInterval = setInterval(pollStatus, 800);
}

async function pollStatus() {
    if (!currentScanId) return;

    try {
        const res = await fetch(`/api/scan/${currentScanId}/status`);
        const data = await res.json();

        updateProgress(data.progress, data.phase);

        if (data.status === 'completed') {
            clearInterval(pollInterval);
            pollInterval = null;
            await loadResults();
        } else if (data.status === 'error') {
            clearInterval(pollInterval);
            pollInterval = null;
            showToast('Scan error: ' + data.phase, 'error');
            resetScanBtn();
        }
    } catch (e) {
        console.error('Poll error:', e);
    }
}

async function loadResults() {
    try {
        const res = await fetch(`/api/scan/${currentScanId}/results`);
        scanResults = await res.json();
        renderResults(scanResults);
        resetScanBtn();
        showToast('Scan completed successfully!', 'success');
    } catch (e) {
        showToast('Failed to load results: ' + e.message, 'error');
        resetScanBtn();
    }
}

// --- UI Updates ---
function updateProgress(pct, phase) {
    $('.progress-fill').style.width = pct + '%';
    $('.progress-pct').textContent = pct + '%';
    $('.progress-phase').textContent = phase;
}

function resetScanBtn() {
    const btn = $('#scan-btn');
    btn.disabled = false;
    btn.innerHTML = '🚀 Launch Scan';
}

function resetStats() {
    $$('.stat-value').forEach(el => el.textContent = '—');
}

function renderResults(report) {
    const summary = report.executive_summary || {};
    const findings = report.detailed_findings || {};
    const services = report.service_inventory || [];
    const remediation = report.remediation_plan || [];
    const raw = report.raw_data || {};

    // Show results section
    $('.results-section').classList.add('active');

    // Update stat cards
    $('#stat-ports').textContent = summary.open_ports_found || 0;
    $('#stat-vulns').textContent = summary.total_findings || 0;
    $('#stat-critical').textContent = summary.critical_count || 0;
    $('#stat-risk').textContent = summary.risk_score || 0;

    // Render risk gauge
    renderRiskGauge(summary.risk_score || 0, summary.risk_level || 'NONE');

    // Render severity chart
    renderSeverityChart(summary);

    // Render open ports table
    renderPortsTable(services);

    // Render vulnerabilities
    renderVulnerabilities(raw.vulnerabilities || []);

    // Render weak configs
    renderWeakConfigs(findings);

    // Render remediation plan
    renderRemediation(remediation);

    // Update tab badges
    updateTabBadges(summary, findings);
}

function renderRiskGauge(score, level) {
    const el = $('#risk-gauge');
    if (!el) return;

    const colors = {
        'CRITICAL': 'var(--severity-critical)',
        'HIGH': 'var(--severity-high)',
        'MEDIUM': 'var(--severity-medium)',
        'LOW': 'var(--severity-low)',
        'NONE': 'var(--severity-none)'
    };
    const color = colors[level] || colors['NONE'];

    el.innerHTML = `
        <div class="risk-circle" style="--pct:${score};--color:${color};color:${color}">
            ${score}
        </div>
        <div class="risk-label" style="color:${color}">${level} RISK</div>
    `;
}

function renderSeverityChart(summary) {
    const canvas = $('#severity-chart');
    if (!canvas || typeof Chart === 'undefined') return;

    const ctx = canvas.getContext('2d');

    // Destroy existing chart
    if (window._sevChart) window._sevChart.destroy();

    const counts = [
        summary.critical_count || 0,
        summary.high_count || 0,
        summary.medium_count || 0,
        summary.low_count || 0
    ];

    if (counts.every(c => c === 0)) {
        canvas.parentElement.innerHTML = '<div class="empty-state"><div class="icon">🛡️</div><h3>No Vulnerabilities Found</h3><p>Target appears secure</p></div>';
        return;
    }

    window._sevChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low'],
            datasets: [{
                data: counts,
                backgroundColor: ['#ef4444', '#f97316', '#eab308', '#22c55e'],
                borderColor: 'transparent',
                borderWidth: 0,
                hoverOffset: 8
            }]
        },
        options: {
            responsive: true,
            cutout: '70%',
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#94a3b8',
                        font: { family: 'Inter', size: 11 },
                        padding: 12,
                        usePointStyle: true,
                        pointStyleWidth: 8
                    }
                }
            }
        }
    });
}

function renderPortsTable(services) {
    const tbody = $('#ports-tbody');
    if (!tbody) return;

    if (services.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="empty-state"><div class="icon">🔒</div><p>No open ports found</p></td></tr>';
        return;
    }

    tbody.innerHTML = services.map(svc => `
        <tr>
            <td class="mono">${svc.port}</td>
            <td><span class="severity-badge severity-INFO">${svc.service}</span></td>
            <td>${svc.software || '<span style="color:var(--text-muted)">—</span>'}</td>
            <td>${svc.version || '<span style="color:var(--text-muted)">—</span>'}</td>
            <td>${svc.has_ssl ? '🔒 Yes' : '<span style="color:var(--text-muted)">No</span>'}</td>
        </tr>
    `).join('');
}

function renderVulnerabilities(vulns) {
    const container = $('#vulns-list');
    if (!container) return;

    if (vulns.length === 0) {
        container.innerHTML = '<div class="empty-state"><div class="icon">🛡️</div><h3>No Vulnerabilities Detected</h3><p>No known vulnerabilities matched the discovered services</p></div>';
        return;
    }

    container.innerHTML = vulns.map(v => {
        const sev = v.severity || 'INFO';
        const sevDot = { CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', LOW: '🟢', INFO: '🔵' };
        return `
        <div class="vuln-card sev-${sev}">
            <div class="vuln-header">
                <span class="vuln-title">${v.cve || v.type || 'Finding'}</span>
                <span class="severity-badge severity-${sev}">${sevDot[sev] || ''} ${sev}</span>
            </div>
            <div class="vuln-meta">
                <span>📡 Port ${v.port}</span>
                <span>🔧 ${v.service || 'unknown'}</span>
                ${v.software ? `<span>📦 ${v.software}</span>` : ''}
                ${v.cvss ? `<span>📊 CVSS ${v.cvss}</span>` : ''}
            </div>
            <div class="vuln-desc">${v.description || ''}</div>
            ${v.remediation ? `<div class="vuln-remediation">${v.remediation}</div>` : ''}
        </div>`;
    }).join('');
}

function renderWeakConfigs(findings) {
    const container = $('#configs-list');
    if (!container) return;

    const headers = findings.missing_header || [];
    const ssl = findings.ssl_issue || [];
    const risky = findings.risky_port || [];
    const all = [...headers, ...ssl, ...risky];

    if (all.length === 0) {
        container.innerHTML = '<div class="empty-state"><div class="icon">✅</div><h3>No Weak Configurations</h3><p>No configuration issues detected</p></div>';
        return;
    }

    container.innerHTML = all.map(item => {
        const sev = item.severity || 'INFO';
        const icon = item.type === 'missing_header' ? '📋' : item.type === 'ssl_issue' ? '🔓' : '⚠️';
        return `
        <div class="vuln-card sev-${sev}">
            <div class="vuln-header">
                <span class="vuln-title">${icon} ${item.header || item.type || 'Config Issue'}</span>
                <span class="severity-badge severity-${sev}">${sev}</span>
            </div>
            <div class="vuln-meta"><span>📡 Port ${item.port}</span></div>
            <div class="vuln-desc">${item.description || ''}</div>
            ${item.remediation ? `<div class="vuln-remediation">${item.remediation}</div>` : ''}
        </div>`;
    }).join('');
}

function renderRemediation(plan) {
    const container = $('#remediation-list');
    if (!container) return;

    if (plan.length === 0) {
        container.innerHTML = '<div class="empty-state"><div class="icon">🎯</div><h3>No Actions Required</h3><p>No remediation steps needed</p></div>';
        return;
    }

    container.innerHTML = plan.map((item, i) => {
        const sev = item.severity || 'INFO';
        return `
        <div class="vuln-card sev-${sev}">
            <div class="vuln-header">
                <span class="vuln-title">#${i + 1} — Priority: ${sev}</span>
                <span class="severity-badge severity-${sev}">${sev}</span>
            </div>
            <div class="vuln-meta">
                ${item.related_port ? `<span>📡 Port ${item.related_port}</span>` : ''}
                ${item.related_cve ? `<span>🔗 ${item.related_cve}</span>` : ''}
            </div>
            <div class="vuln-desc" style="color:var(--accent-green)">${item.action}</div>
        </div>`;
    }).join('');
}

function updateTabBadges(summary, findings) {
    const portsBadge = $('#tab-badge-ports');
    const vulnsBadge = $('#tab-badge-vulns');
    const configBadge = $('#tab-badge-configs');

    if (portsBadge) portsBadge.textContent = summary.open_ports_found || 0;
    if (vulnsBadge) vulnsBadge.textContent = summary.total_findings || 0;

    const cfgCount = (findings.missing_header?.length || 0) + (findings.ssl_issue?.length || 0) + (findings.risky_port?.length || 0);
    if (configBadge) configBadge.textContent = cfgCount;
}

// --- Tab Switching ---
function switchTab(tabId) {
    $$('.tab-btn').forEach(btn => btn.classList.toggle('active', btn.dataset.tab === tabId));
    $$('.tab-content').forEach(el => el.classList.toggle('active', el.id === tabId));
}

// --- Export ---
function exportResults() {
    if (!scanResults) {
        showToast('No scan results to export', 'error');
        return;
    }
    const blob = new Blob([JSON.stringify(scanResults, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `vuln_scan_${scanResults.executive_summary?.target || 'report'}_${new Date().toISOString().slice(0,10)}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showToast('Report exported as JSON', 'success');
}

// --- Toast Notifications ---
function showToast(message, type = 'info') {
    const existing = $('.toast');
    if (existing) existing.remove();

    const colors = {
        success: 'var(--accent-green)',
        error: 'var(--severity-critical)',
        info: 'var(--accent-cyan)'
    };
    const icons = { success: '✅', error: '❌', info: 'ℹ️' };

    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.style.cssText = `
        position:fixed;bottom:24px;right:24px;z-index:9999;
        padding:14px 24px;border-radius:12px;font-size:14px;font-weight:500;
        background:var(--bg-secondary);color:${colors[type]};
        border:1px solid ${colors[type]}30;
        box-shadow:0 8px 30px rgba(0,0,0,0.4);
        animation:fadeIn 0.3s ease;display:flex;align-items:center;gap:10px;
        font-family:'Inter',sans-serif;
    `;
    toast.innerHTML = `<span>${icons[type]}</span><span>${message}</span>`;
    document.body.appendChild(toast);
    setTimeout(() => { toast.style.opacity = '0'; setTimeout(() => toast.remove(), 300); }, 4000);
}
