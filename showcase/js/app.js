/**
 * CyberShield Showcase Website - Frontend JavaScript
 * Handles URL scanning, API calls, and result rendering
 */

// API Configuration
const API_BASE = '/api';

// State
let scanResults = [];
let isScanning = false;

// DOM Elements
const urlInput = document.getElementById('url-input');
const scanBtn = document.getElementById('scan-btn');
const clearBtn = document.getElementById('clear-btn');
const resultsPanel = document.getElementById('results-panel');
const resultsList = document.getElementById('results-list');
const resultsSummary = document.getElementById('results-summary');
const downloadBtn = document.getElementById('download-btn');

// Event Listeners
scanBtn.addEventListener('click', startScan);
clearBtn.addEventListener('click', clearAll);
downloadBtn.addEventListener('click', downloadReport);

// Keyboard shortcut (Ctrl+Enter to scan)
urlInput.addEventListener('keydown', (e) => {
    if (e.ctrlKey && e.key === 'Enter') {
        startScan();
    }
});

/**
 * Parse URL input and extract domains
 */
function parseUrls(input) {
    const urls = [];
    const lines = input.split(/[\n,]+/);

    for (let line of lines) {
        let url = line.trim();
        if (!url) continue;

        // Smart URL parsing
        let domain = url;
        let port = 443;
        let service = 'https';

        // Remove scheme
        if (url.startsWith('https://')) {
            domain = url.slice(8);
            port = 443;
            service = 'https';
        } else if (url.startsWith('http://')) {
            domain = url.slice(7);
            port = 80;
            service = 'http';
        } else if (url.startsWith('ftp://')) {
            domain = url.slice(6);
            port = 21;
            service = 'ftp';
        }

        // Remove path
        if (domain.includes('/')) {
            domain = domain.split('/')[0];
        }

        // Extract port
        if (domain.includes(':')) {
            const parts = domain.split(':');
            domain = parts[0];
            port = parseInt(parts[1]) || 443;
        }

        if (domain) {
            urls.push({
                original: url,
                domain: domain.toLowerCase(),
                port: port,
                service: service
            });
        }
    }

    return urls;
}

/**
 * Start scanning URLs
 */
async function startScan() {
    const input = urlInput.value.trim();
    if (!input) {
        showError('Please enter at least one URL to scan');
        return;
    }

    const urls = parseUrls(input);
    if (urls.length === 0) {
        showError('No valid URLs found');
        return;
    }

    // Update UI
    setScanning(true);
    resultsPanel.style.display = 'block';
    resultsList.innerHTML = '<div class="scanning-msg">Scanning URLs...</div>';

    // Scan each URL
    scanResults = [];

    for (let i = 0; i < urls.length; i++) {
        const url = urls[i];
        updateProgress(i + 1, urls.length, url.domain);

        try {
            const result = await scanUrl(url);
            scanResults.push(result);
            renderResults();
        } catch (error) {
            scanResults.push({
                domain: url.domain,
                risk_score: 0,
                risk_level: 'ERROR',
                evidence: [`Error: ${error.message}`],
                error: true
            });
            renderResults();
        }
    }

    setScanning(false);
    updateSummary();
}

/**
 * Scan a single URL via API
 */
async function scanUrl(urlData) {
    try {
        const response = await fetch(`${API_BASE}/scan`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(urlData)
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        return await response.json();
    } catch (error) {
        // Fallback: Use client-side heuristic scanning
        return clientSideScan(urlData);
    }
}

/**
 * Client-side fallback scanning (when API is unavailable)
 */
function clientSideScan(urlData) {
    const domain = urlData.domain;
    const port = urlData.port;

    let risk_score = 15;  // Baseline
    const evidence = [];

    // Known vulnerable domains
    const knownVulnerable = {
        'testphp.vulnweb.com': { score: 95, reason: 'Known intentionally vulnerable test site (Acunetix)' },
        'demo.testfire.net': { score: 90, reason: 'Known vulnerable demo site (IBM AppScan)' },
        'juice-shop.herokuapp.com': { score: 90, reason: 'OWASP Juice Shop (intentionally vulnerable)' },
        'dvwa.co.uk': { score: 95, reason: 'Damn Vulnerable Web Application' },
        'xss-game.appspot.com': { score: 85, reason: 'XSS vulnerable game' },
    };

    for (const [vuln, info] of Object.entries(knownVulnerable)) {
        if (domain.includes(vuln) || domain.endsWith(vuln)) {
            risk_score = info.score;
            evidence.push(`KNOWN VULNERABILITY: ${info.reason}`);
            break;
        }
    }

    // Suspicious TLDs
    const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq'];
    for (const tld of suspiciousTLDs) {
        if (domain.endsWith(tld)) {
            risk_score = Math.max(risk_score, 55);
            evidence.push(`Suspicious TLD: ${tld} (often used for phishing)`);
        }
    }

    // Suspicious patterns
    const patterns = [
        { regex: /admin/i, score: 30, reason: 'Admin panel detected' },
        { regex: /login.*paypal/i, score: 75, reason: 'PayPal phishing pattern' },
        { regex: /login.*bank/i, score: 75, reason: 'Banking phishing pattern' },
        { regex: /phpmyadmin/i, score: 60, reason: 'phpMyAdmin detected' },
        { regex: /wp-admin/i, score: 35, reason: 'WordPress admin detected' },
        { regex: /\.ru$/i, score: 25, reason: 'Russian TLD' },
        { regex: /\.cn$/i, score: 25, reason: 'Chinese TLD' },
    ];

    for (const p of patterns) {
        if (p.regex.test(domain)) {
            risk_score = Math.max(risk_score, p.score);
            evidence.push(p.reason);
        }
    }

    // High-risk ports
    const highRiskPorts = {
        21: { score: 70, reason: 'FTP port exposed' },
        22: { score: 40, reason: 'SSH port' },
        23: { score: 85, reason: 'Telnet port (insecure)' },
        3306: { score: 75, reason: 'MySQL port exposed' },
        3389: { score: 65, reason: 'RDP port exposed' },
        5432: { score: 75, reason: 'PostgreSQL port exposed' },
        27017: { score: 80, reason: 'MongoDB port exposed' },
    };

    if (highRiskPorts[port]) {
        const portInfo = highRiskPorts[port];
        risk_score = Math.max(risk_score, portInfo.score);
        evidence.push(`Port Risk: ${portInfo.reason}`);
    }

    // Default evidence
    if (evidence.length === 0) {
        evidence.push('Baseline risk: Domain requires further analysis');
    }

    // Determine risk level
    let risk_level = 'LOW';
    if (risk_score >= 75) risk_level = 'CRITICAL';
    else if (risk_score >= 50) risk_level = 'HIGH';
    else if (risk_score >= 30) risk_level = 'MEDIUM';

    return {
        domain: domain,
        port: port,
        risk_score: risk_score,
        risk_level: risk_level,
        evidence: evidence,
        scan_type: 'heuristic'
    };
}

/**
 * Render scan results
 */
function renderResults() {
    resultsList.innerHTML = '';

    for (const result of scanResults) {
        const level = result.risk_level.toLowerCase();
        const item = document.createElement('div');
        item.className = `result-item ${level}`;

        item.innerHTML = `
            <div class="result-header">
                <div>
                    <span class="result-domain">${escapeHtml(result.domain)}</span>
                    <span class="result-level ${level}">${result.risk_level}</span>
                </div>
                <span class="result-score ${level}">${result.risk_score}</span>
            </div>
            <ul class="result-evidence">
                ${result.evidence.slice(0, 3).map(e => `<li>${escapeHtml(e)}</li>`).join('')}
            </ul>
        `;

        resultsList.appendChild(item);
    }
}

/**
 * Update progress message
 */
function updateProgress(current, total, domain) {
    resultsSummary.textContent = `Scanning ${current}/${total}: ${domain}`;
}

/**
 * Update summary after scan completes
 */
function updateSummary() {
    const total = scanResults.length;
    const critical = scanResults.filter(r => r.risk_level === 'CRITICAL').length;
    const high = scanResults.filter(r => r.risk_level === 'HIGH').length;

    resultsSummary.innerHTML = `
        <strong>${total}</strong> scanned • 
        <span style="color:var(--critical)">${critical} Critical</span> • 
        <span style="color:var(--high)">${high} High</span>
    `;
}

/**
 * Set scanning state
 */
function setScanning(scanning) {
    isScanning = scanning;
    scanBtn.disabled = scanning;

    const btnText = scanBtn.querySelector('.btn-text');
    const btnLoader = scanBtn.querySelector('.btn-loader');

    if (scanning) {
        btnText.style.display = 'none';
        btnLoader.style.display = 'block';
    } else {
        btnText.style.display = 'inline';
        btnLoader.style.display = 'none';
    }
}

/**
 * Clear all inputs and results
 */
function clearAll() {
    urlInput.value = '';
    scanResults = [];
    resultsPanel.style.display = 'none';
    resultsList.innerHTML = '';
}

/**
 * Download results as JSON
 */
function downloadReport() {
    const report = {
        scan_date: new Date().toISOString(),
        total_urls: scanResults.length,
        results: scanResults,
        summary: {
            critical: scanResults.filter(r => r.risk_level === 'CRITICAL').length,
            high: scanResults.filter(r => r.risk_level === 'HIGH').length,
            medium: scanResults.filter(r => r.risk_level === 'MEDIUM').length,
            low: scanResults.filter(r => r.risk_level === 'LOW').length,
        }
    };

    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cybershield_scan_${Date.now()}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

/**
 * Show error message
 */
function showError(message) {
    alert(message);
}

/**
 * Escape HTML to prevent XSS
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Initialize
console.log('CyberShield Scanner initialized');
