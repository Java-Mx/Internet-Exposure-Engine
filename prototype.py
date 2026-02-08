#!/usr/bin/env python
"""
Internet Exposure Risk Scoring System - Formal Prototype Interface

Single-command execution that:
1. Starts the application
2. Launches local web server
3. Opens default browser automatically
4. Navigates to local interface

Professional interface for academic and industry demonstration.
"""

import sys
import os
import webbrowser
import threading
import time
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

import uvicorn
from fastapi import FastAPI, Request, UploadFile, File, Form
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
import json
import csv
import io
from datetime import datetime
from typing import Optional

from risk_scanner import AutomatedPipeline, parse_input_list
from reporting.pdf_generator import PDFReportGenerator, generate_pdf_report

# Application Configuration
APP_HOST = "127.0.0.1"
APP_PORT = 8080
APP_TITLE = "Internet Exposure Risk Scoring System"

app = FastAPI(title=APP_TITLE, version="1.0.0")


# Sample Real Domains for AI-Assisted Input
SAMPLE_DOMAINS = [
    {"domain": "github.com", "description": "Software development platform", "category": "Technology"},
    {"domain": "stackoverflow.com", "description": "Developer Q&A community", "category": "Technology"},
    {"domain": "cloudflare.com", "description": "Web infrastructure provider", "category": "Infrastructure"},
    {"domain": "digitalocean.com", "description": "Cloud hosting provider", "category": "Infrastructure"},
    {"domain": "heroku.com", "description": "Platform as a Service", "category": "Infrastructure"},
    {"domain": "mongodb.com", "description": "Database platform", "category": "Database"},
    {"domain": "redis.io", "description": "In-memory data store", "category": "Database"},
    {"domain": "nginx.org", "description": "Web server software", "category": "Infrastructure"},
    {"domain": "apache.org", "description": "Open source foundation", "category": "Technology"},
    {"domain": "elastic.co", "description": "Search and analytics", "category": "Technology"},
]


# Professional HTML Template
INTERFACE_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Internet Exposure Risk Scoring System</title>
    <style>
        :root {
            --primary: #1a365d;
            --secondary: #2c5282;
            --accent: #3182ce;
            --bg-light: #f7fafc;
            --bg-dark: #edf2f7;
            --text-primary: #1a202c;
            --text-secondary: #4a5568;
            --border: #e2e8f0;
            --success: #38a169;
            --warning: #d69e2e;
            --danger: #e53e3e;
            --critical: #742a2a;
        }
        
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        
        body {
            font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--bg-light);
            color: var(--text-primary);
            line-height: 1.6;
        }
        
        .header {
            background: var(--primary);
            color: white;
            padding: 20px 40px;
            border-bottom: 3px solid var(--accent);
        }
        
        .header h1 {
            font-size: 24px;
            font-weight: 600;
            margin-bottom: 4px;
        }
        
        .header p {
            font-size: 14px;
            opacity: 0.9;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 30px 40px;
        }
        
        .card {
            background: white;
            border: 1px solid var(--border);
            border-radius: 8px;
            margin-bottom: 24px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        
        .card-header {
            background: var(--bg-dark);
            padding: 16px 20px;
            border-bottom: 1px solid var(--border);
            font-weight: 600;
            font-size: 16px;
            color: var(--primary);
        }
        
        .card-body {
            padding: 20px;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-group label {
            display: block;
            font-weight: 500;
            margin-bottom: 8px;
            color: var(--text-secondary);
        }
        
        textarea {
            width: 100%;
            height: 120px;
            padding: 12px;
            border: 1px solid var(--border);
            border-radius: 6px;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 14px;
            resize: vertical;
        }
        
        textarea:focus {
            outline: none;
            border-color: var(--accent);
            box-shadow: 0 0 0 3px rgba(49, 130, 206, 0.1);
        }
        
        .btn {
            display: inline-block;
            padding: 12px 24px;
            font-size: 14px;
            font-weight: 600;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            transition: all 0.2s;
        }
        
        .btn-primary {
            background: var(--accent);
            color: white;
        }
        
        .btn-primary:hover {
            background: var(--secondary);
        }
        
        .btn-secondary {
            background: var(--bg-dark);
            color: var(--text-primary);
            border: 1px solid var(--border);
        }
        
        .btn-secondary:hover {
            background: var(--border);
        }
        
        .file-upload {
            display: flex;
            align-items: center;
            gap: 12px;
        }
        
        .file-upload input[type="file"] {
            flex: 1;
        }
        
        .suggestion-list {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 12px;
            margin-top: 12px;
        }
        
        .suggestion-item {
            background: var(--bg-light);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 12px;
            cursor: pointer;
            transition: all 0.2s;
        }
        
        .suggestion-item:hover {
            border-color: var(--accent);
            background: white;
        }
        
        .suggestion-item.selected {
            border-color: var(--accent);
            background: rgba(49, 130, 206, 0.05);
        }
        
        .suggestion-item strong {
            display: block;
            color: var(--primary);
        }
        
        .suggestion-item span {
            font-size: 13px;
            color: var(--text-secondary);
        }
        
        .loading {
            display: none;
            text-align: center;
            padding: 40px;
        }
        
        .spinner {
            width: 40px;
            height: 40px;
            border: 3px solid var(--border);
            border-top-color: var(--accent);
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin: 0 auto 16px;
        }
        
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        
        .results {
            display: none;
        }
        
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin-bottom: 24px;
        }
        
        .summary-card {
            text-align: center;
            padding: 20px;
            border-radius: 8px;
            border: 1px solid var(--border);
        }
        
        .summary-card.critical { background: #fff5f5; border-color: var(--critical); }
        .summary-card.high { background: #fffaf0; border-color: var(--danger); }
        .summary-card.medium { background: #fffff0; border-color: var(--warning); }
        .summary-card.low { background: #f0fff4; border-color: var(--success); }
        
        .summary-card .count {
            font-size: 36px;
            font-weight: 700;
        }
        
        .summary-card.critical .count { color: var(--critical); }
        .summary-card.high .count { color: var(--danger); }
        .summary-card.medium .count { color: var(--warning); }
        .summary-card.low .count { color: var(--success); }
        
        .summary-card .label {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--text-secondary);
            margin-top: 4px;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        th, td {
            padding: 12px 16px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }
        
        th {
            background: var(--bg-dark);
            font-weight: 600;
            color: var(--primary);
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        tr:hover {
            background: var(--bg-light);
        }
        
        .badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
        }
        
        .badge-critical { background: #fed7d7; color: var(--critical); }
        .badge-high { background: #feebc8; color: #c05621; }
        .badge-medium { background: #fefcbf; color: #975a16; }
        .badge-low { background: #c6f6d5; color: #276749; }
        
        .evidence-list {
            margin: 0;
            padding-left: 20px;
            font-size: 13px;
        }
        
        .evidence-list li {
            margin-bottom: 4px;
        }
        
        .json-output {
            background: #1a202c;
            color: #a0aec0;
            padding: 16px;
            border-radius: 6px;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 13px;
            overflow-x: auto;
            max-height: 400px;
            overflow-y: auto;
        }
        
        .section-title {
            font-size: 18px;
            font-weight: 600;
            color: var(--primary);
            margin-bottom: 16px;
            padding-bottom: 8px;
            border-bottom: 2px solid var(--border);
        }
        
        .two-column {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 24px;
        }
        
        .metadata-table {
            font-size: 14px;
        }
        
        .metadata-table td:first-child {
            font-weight: 500;
            color: var(--text-secondary);
            width: 40%;
        }
        
        .actions {
            display: flex;
            gap: 12px;
            margin-top: 16px;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Internet Exposure Risk Scoring System</h1>
        <p>Machine Learning-Based Security Risk Assessment Platform</p>
    </div>
    
    <div class="container">
        <!-- Input Section -->
        <div class="card" id="inputSection">
            <div class="card-header">Analysis Input</div>
            <div class="card-body">
                <div class="form-group">
                    <label>Enter Domain Names or IP Addresses (one per line)</label>
                    <textarea id="targets" placeholder="example.com
192.168.1.100
subdomain.domain.org"></textarea>
                </div>
                
                <div class="form-group">
                    <label>Or Upload a List (CSV or Text File)</label>
                    <div class="file-upload">
                        <input type="file" id="fileInput" accept=".csv,.txt">
                        <button class="btn btn-secondary" onclick="clearFile()">Clear</button>
                    </div>
                </div>
                
                <div class="actions">
                    <button class="btn btn-primary" onclick="runAnalysis()">Start Analysis</button>
                    <button class="btn btn-secondary" onclick="toggleSuggestions()">Show Sample Domains</button>
                </div>
                
                <!-- AI-Assisted Suggestions -->
                <div id="suggestions" style="display:none; margin-top: 20px;">
                    <label style="font-weight: 500; color: var(--text-secondary);">
                        Select sample domains for testing (click to add):
                    </label>
                    <div class="suggestion-list" id="suggestionList"></div>
                </div>
            </div>
        </div>
        
        <!-- Loading State -->
        <div class="loading" id="loading">
            <div class="spinner"></div>
            <p>Executing automated analysis pipeline...</p>
            <p style="font-size: 13px; color: var(--text-secondary);">
                Processing: Data Ingestion, Feature Engineering, ML Prediction, Graph Analysis
            </p>
        </div>
        
        <!-- Results Section -->
        <div class="results" id="results">
            <!-- Summary Cards -->
            <div class="summary-grid">
                <div class="summary-card critical">
                    <div class="count" id="criticalCount">0</div>
                    <div class="label">Critical</div>
                </div>
                <div class="summary-card high">
                    <div class="count" id="highCount">0</div>
                    <div class="label">High</div>
                </div>
                <div class="summary-card medium">
                    <div class="count" id="mediumCount">0</div>
                    <div class="label">Medium</div>
                </div>
                <div class="summary-card low">
                    <div class="count" id="lowCount">0</div>
                    <div class="label">Low</div>
                </div>
            </div>
            
            <!-- Detailed Results -->
            <div class="card">
                <div class="card-header">Risk Assessment Results</div>
                <div class="card-body">
                    <table id="resultsTable">
                        <thead>
                            <tr>
                                <th>Asset</th>
                                <th>Risk Score</th>
                                <th>Risk Level</th>
                                <th>Confidence</th>
                                <th>Anomaly Score</th>
                                <th>Graph Impact</th>
                                <th>Evidence Findings</th>
                            </tr>
                        </thead>
                        <tbody id="resultsBody"></tbody>
                    </table>
                </div>
            </div>
            
            <!-- Evaluation & Reproducibility -->
            <div class="two-column">
                <div class="card">
                    <div class="card-header">Comparative Evaluation</div>
                    <div class="card-body">
                        <table class="metadata-table">
                            <tr><td>Rule-Based Accuracy</td><td id="baselineAccuracy">-</td></tr>
                            <tr><td>ML-Assisted Accuracy</td><td id="mlAccuracy">-</td></tr>
                            <tr><td>Accuracy Improvement</td><td id="improvement">-</td></tr>
                            <tr><td>False Positive Reduction</td><td id="fpReduction">-</td></tr>
                        </table>
                    </div>
                </div>
                
                <div class="card">
                    <div class="card-header">Reproducibility Information</div>
                    <div class="card-body">
                        <table class="metadata-table">
                            <tr><td>Run ID</td><td id="runId">-</td></tr>
                            <tr><td>Timestamp</td><td id="timestamp">-</td></tr>
                            <tr><td>Duration</td><td id="duration">-</td></tr>
                            <tr><td>Input Hash</td><td id="inputHash">-</td></tr>
                            <tr><td>Data Freshness</td><td id="freshness">-</td></tr>
                        </table>
                    </div>
                </div>
            </div>
            
            <!-- JSON Output -->
            <div class="card">
                <div class="card-header">Complete JSON Report</div>
                <div class="card-body">
                    <pre class="json-output" id="jsonOutput"></pre>
                </div>
            </div>
            
            <div class="actions">
                <button class="btn btn-primary" onclick="downloadPDF()">Download Report (PDF)</button>
                <button class="btn btn-secondary" onclick="downloadReport()">Download Report (JSON)</button>
                <button class="btn btn-secondary" onclick="newAnalysis()">New Analysis</button>
            </div>
        </div>
    </div>
    
    <script>
        const SAMPLE_DOMAINS = """ + json.dumps(SAMPLE_DOMAINS) + """;
        let selectedDomains = new Set();
        let currentResults = null;
        
        // Initialize suggestions
        function initSuggestions() {
            const list = document.getElementById('suggestionList');
            list.innerHTML = SAMPLE_DOMAINS.map(d => `
                <div class="suggestion-item" onclick="toggleDomain('${d.domain}')" id="sug-${d.domain.replace('.', '-')}">
                    <strong>${d.domain}</strong>
                    <span>${d.description} (${d.category})</span>
                </div>
            `).join('');
        }
        
        function toggleSuggestions() {
            const sug = document.getElementById('suggestions');
            sug.style.display = sug.style.display === 'none' ? 'block' : 'none';
        }
        
        function toggleDomain(domain) {
            const el = document.getElementById('sug-' + domain.replace('.', '-'));
            const textarea = document.getElementById('targets');
            
            if (selectedDomains.has(domain)) {
                selectedDomains.delete(domain);
                el.classList.remove('selected');
            } else {
                selectedDomains.add(domain);
                el.classList.add('selected');
            }
            
            // Update textarea
            const current = textarea.value.split('\\n').filter(x => x.trim() && !SAMPLE_DOMAINS.some(d => d.domain === x.trim()));
            const selected = Array.from(selectedDomains);
            textarea.value = [...current, ...selected].filter(x => x).join('\\n');
        }
        
        function clearFile() {
            document.getElementById('fileInput').value = '';
        }
        
        async function runAnalysis() {
            const textarea = document.getElementById('targets');
            const fileInput = document.getElementById('fileInput');
            
            let input = textarea.value;
            
            // Handle file upload
            if (fileInput.files.length > 0) {
                const file = fileInput.files[0];
                const text = await file.text();
                input = input ? input + '\\n' + text : text;
            }
            
            if (!input.trim()) {
                alert('Please enter at least one domain or IP address.');
                return;
            }
            
            // Show loading
            document.getElementById('inputSection').style.display = 'none';
            document.getElementById('loading').style.display = 'block';
            document.getElementById('results').style.display = 'none';
            
            try {
                const response = await fetch('/api/analyze', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({input: input})
                });
                
                const data = await response.json();
                currentResults = data;
                displayResults(data);
            } catch (error) {
                alert('Analysis failed: ' + error.message);
                document.getElementById('inputSection').style.display = 'block';
            }
            
            document.getElementById('loading').style.display = 'none';
        }
        
        function displayResults(data) {
            // Summary
            document.getElementById('criticalCount').textContent = data.summary.critical;
            document.getElementById('highCount').textContent = data.summary.high;
            document.getElementById('mediumCount').textContent = data.summary.medium;
            document.getElementById('lowCount').textContent = data.summary.low;
            
            // Results table
            const tbody = document.getElementById('resultsBody');
            tbody.innerHTML = data.risk_reports.map(r => {
                const level = r.risk_level.toLowerCase();
                const evidence = (r.evidence || []).map(e => `<li>${e}</li>`).join('');
                const graphImpact = r.graph_impact ? 
                    `${r.graph_impact.connected_assets} connected, Breach proximity: ${r.graph_impact.breach_proximity ? 'Yes' : 'No'}` : 
                    'N/A';
                
                return `
                    <tr>
                        <td><strong>${r.asset}</strong></td>
                        <td>${r.risk_score}/100</td>
                        <td><span class="badge badge-${level}">${r.risk_level}</span></td>
                        <td>${r.severity_model?.confidence || 'N/A'}</td>
                        <td>${r.anomaly_score || 'N/A'}</td>
                        <td>${graphImpact}</td>
                        <td><ul class="evidence-list">${evidence}</ul></td>
                    </tr>
                `;
            }).join('');
            
            // Evaluation
            if (data.comparative_evaluation?.comparison) {
                const eval_data = data.comparative_evaluation.comparison;
                document.getElementById('baselineAccuracy').textContent = eval_data.rule_based_accuracy;
                document.getElementById('mlAccuracy').textContent = eval_data.ml_assisted_accuracy;
                document.getElementById('improvement').textContent = eval_data.accuracy_improvement;
                document.getElementById('fpReduction').textContent = eval_data.false_positive_reduction;
            }
            
            // Reproducibility
            if (data.reproducibility) {
                document.getElementById('runId').textContent = data.reproducibility.run_id;
                document.getElementById('timestamp').textContent = data.reproducibility.timestamp;
                document.getElementById('duration').textContent = data.reproducibility.duration_seconds + 's';
                document.getElementById('inputHash').textContent = data.reproducibility.input_hash;
                document.getElementById('freshness').textContent = data.reproducibility.data_freshness;
            }
            
            // JSON output
            document.getElementById('jsonOutput').textContent = JSON.stringify(data.risk_reports, null, 2);
            
            document.getElementById('results').style.display = 'block';
        }
        
        function downloadReport() {
            if (!currentResults) return;
            
            const blob = new Blob([JSON.stringify(currentResults, null, 2)], {type: 'application/json'});
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `risk_report_${new Date().toISOString().slice(0,10)}.json`;
            a.click();
            URL.revokeObjectURL(url);
        }
        
        async function downloadPDF() {
            if (!currentResults || !currentResults.risk_reports) return;
            
            const report = currentResults.risk_reports[0];
            if (!report) return;
            
            try {
                const response = await fetch('/api/generate-pdf', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(currentResults)
                });
                
                if (response.ok) {
                    const blob = await response.blob();
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = `risk_report_${report.asset.replace(/\\./g, '_')}_${new Date().toISOString().slice(0,10)}.pdf`;
                    a.click();
                    URL.revokeObjectURL(url);
                } else {
                    alert('Failed to generate PDF report');
                }
            } catch (error) {
                alert('Error generating PDF: ' + error.message);
            }
        }
        
        function newAnalysis() {
            document.getElementById('inputSection').style.display = 'block';
            document.getElementById('results').style.display = 'none';
            selectedDomains.clear();
            document.querySelectorAll('.suggestion-item').forEach(el => el.classList.remove('selected'));
        }
        
        // Initialize
        initSuggestions();
    </script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
async def index():
    """Serve the main interface."""
    return INTERFACE_HTML


@app.post("/api/analyze")
async def analyze_assets(request: Request):
    """Run risk analysis on provided assets."""
    data = await request.json()
    input_text = data.get('input', '')
    
    # Parse input
    assets = parse_input_list(input_text)
    
    if not assets:
        return JSONResponse({"error": "No valid assets provided"}, status_code=400)
    
    # Run automated pipeline
    pipeline = AutomatedPipeline()
    results = pipeline.run(assets)
    
    return JSONResponse(results)


@app.get("/api/suggestions")
async def get_suggestions():
    """Return sample domain suggestions."""
    return JSONResponse(SAMPLE_DOMAINS)


@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "operational",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0"
    }


@app.post("/api/generate-pdf")
async def generate_pdf(request: Request):
    """Generate PDF report from analysis results."""
    data = await request.json()
    
    if not data.get('risk_reports'):
        return JSONResponse({"error": "No risk reports to generate PDF"}, status_code=400)
    
    # Get first report for individual PDF
    report = data['risk_reports'][0]
    
    # Create asset info from report
    asset_info = {
        'domain': report.get('asset') if '.' in str(report.get('asset', '')) and not report.get('asset', '').replace('.', '').isdigit() else None,
        'ip': report.get('asset') if report.get('asset', '').replace('.', '').isdigit() else None,
        'port': 443,
        'service': 'https',
        'source': 'analysis'
    }
    
    try:
        # Generate PDF
        pdf_generator = PDFReportGenerator()
        pdf_path = pdf_generator.generate_report(report, asset_info)
        
        # Return file
        return FileResponse(
            path=pdf_path,
            media_type='application/pdf',
            filename=Path(pdf_path).name
        )
    except Exception as e:
        return JSONResponse({"error": f"PDF generation failed: {str(e)}"}, status_code=500)


def open_browser():
    """Open browser after short delay to allow server startup."""
    time.sleep(1.5)
    webbrowser.open(f"http://{APP_HOST}:{APP_PORT}")


def main():
    """Main entry point - single command execution."""
    print()
    print("=" * 70)
    print("  INTERNET EXPOSURE RISK SCORING SYSTEM")
    print("  Machine Learning-Based Security Risk Assessment Platform")
    print("=" * 70)
    print()
    print(f"  Starting server at http://{APP_HOST}:{APP_PORT}")
    print("  Opening browser automatically...")
    print()
    print("  Press Ctrl+C to stop the server")
    print()
    print("-" * 70)
    
    # Start browser in background thread
    browser_thread = threading.Thread(target=open_browser, daemon=True)
    browser_thread.start()
    
    # Start server
    uvicorn.run(app, host=APP_HOST, port=APP_PORT, log_level="info")


if __name__ == "__main__":
    main()
