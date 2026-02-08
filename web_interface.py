#!/usr/bin/env python
"""
Lightweight Web Interface for Risk Scanner
A simple Flask/FastAPI interface for the prototype demonstration.
"""

from fastapi import FastAPI, Request, Form, UploadFile, File
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
import json
import csv
import io
from datetime import datetime
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent))

from risk_scanner import AutomatedPipeline, parse_input_list

app = FastAPI(title="Internet Exposure Risk Scanner", version="1.0.0")


# HTML Templates
INDEX_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Internet Exposure Risk Scanner</title>
    <style>
        * { box-sizing: border-box; font-family: 'Segoe UI', sans-serif; }
        body { margin: 0; padding: 20px; background: #1a1a2e; color: #eee; }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { color: #00d4ff; border-bottom: 2px solid #00d4ff; padding-bottom: 10px; }
        .input-section { background: #16213e; padding: 20px; border-radius: 10px; margin: 20px 0; }
        h2 { color: #00d4ff; margin-top: 0; }
        textarea { width: 100%; height: 150px; background: #0f0f23; border: 1px solid #00d4ff; 
                   color: #eee; padding: 10px; border-radius: 5px; font-family: monospace; }
        button { background: #00d4ff; color: #1a1a2e; border: none; padding: 15px 30px; 
                 font-size: 16px; cursor: pointer; border-radius: 5px; margin-top: 10px; }
        button:hover { background: #00a8cc; }
        .results { background: #16213e; padding: 20px; border-radius: 10px; margin: 20px 0; }
        .artifact { background: #0f0f23; padding: 15px; margin: 10px 0; border-radius: 5px; border-left: 4px solid #00d4ff; }
        .artifact h3 { color: #00d4ff; margin: 0 0 10px 0; }
        pre { background: #0a0a15; padding: 15px; overflow-x: auto; border-radius: 5px; }
        .risk-card { display: inline-block; padding: 10px 20px; margin: 5px; border-radius: 5px; }
        .critical { background: #dc3545; }
        .high { background: #fd7e14; }
        .medium { background: #ffc107; color: #333; }
        .low { background: #28a745; }
        .loading { display: none; text-align: center; padding: 20px; }
        .spinner { border: 4px solid #f3f3f3; border-top: 4px solid #00d4ff; 
                   border-radius: 50%; width: 40px; height: 40px; animation: spin 1s linear infinite; margin: 0 auto; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #333; }
        th { background: #0f0f23; color: #00d4ff; }
        .evidence-list { margin: 0; padding-left: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Internet Exposure Risk Scanner</h1>
        <p>ML-powered risk assessment system with explainable AI</p>
        
        <div class="input-section">
            <h2>Artifact 1: Controlled Input Interface</h2>
            <form id="scanForm" onsubmit="runScan(event)">
                <label>Enter domains/IPs (one per line):</label>
                <textarea id="targets" placeholder="example.com
192.168.1.100
test.org
10.0.0.1"></textarea>
                <button type="submit">🚀 Run Risk Assessment</button>
            </form>
        </div>
        
        <div class="loading" id="loading">
            <div class="spinner"></div>
            <p>Running automated ML pipeline...</p>
        </div>
        
        <div id="results" style="display:none;">
            <!-- Results will be injected here -->
        </div>
    </div>
    
    <script>
        async function runScan(e) {
            e.preventDefault();
            const targets = document.getElementById('targets').value;
            const loading = document.getElementById('loading');
            const results = document.getElementById('results');
            
            loading.style.display = 'block';
            results.style.display = 'none';
            
            try {
                const response = await fetch('/api/scan', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({input: targets})
                });
                const data = await response.json();
                displayResults(data);
            } catch (error) {
                results.innerHTML = '<div class="artifact"><h3>Error</h3><p>' + error + '</p></div>';
            }
            
            loading.style.display = 'none';
            results.style.display = 'block';
        }
        
        function displayResults(data) {
            const results = document.getElementById('results');
            let html = '';
            
            // Summary
            html += '<div class="results">';
            html += '<h2>📊 Summary</h2>';
            html += '<div class="risk-card critical">CRITICAL: ' + data.summary.critical + '</div>';
            html += '<div class="risk-card high">HIGH: ' + data.summary.high + '</div>';
            html += '<div class="risk-card medium">MEDIUM: ' + data.summary.medium + '</div>';
            html += '<div class="risk-card low">LOW: ' + data.summary.low + '</div>';
            html += '</div>';
            
            // Artifact 2: Pipeline Logs
            html += '<div class="artifact">';
            html += '<h3>✅ Artifact 2: Automated Pipeline Execution</h3>';
            html += '<pre>' + data.pipeline_logs.join('\\n') + '</pre>';
            html += '</div>';
            
            // Artifact 3: Risk Reports
            html += '<div class="artifact">';
            html += '<h3>✅ Artifact 3: Risk Report Output (Industry Standard)</h3>';
            html += '<table><tr><th>Asset</th><th>Risk Score</th><th>Level</th><th>Confidence</th><th>Evidence</th></tr>';
            data.risk_reports.forEach(r => {
                const levelClass = r.risk_level.toLowerCase();
                html += '<tr>';
                html += '<td>' + r.asset + '</td>';
                html += '<td>' + r.risk_score + '/100</td>';
                html += '<td class="' + levelClass + '">' + r.risk_level + '</td>';
                html += '<td>' + (r.severity_model?.confidence || 'N/A') + '</td>';
                html += '<td><ul class="evidence-list">';
                (r.evidence || []).forEach(e => html += '<li>' + e + '</li>');
                html += '</ul></td>';
                html += '</tr>';
            });
            html += '</table>';
            html += '<h4>Full JSON Report:</h4>';
            html += '<pre>' + JSON.stringify(data.risk_reports[0], null, 2) + '</pre>';
            html += '</div>';
            
            // Artifact 4: Comparative Evaluation
            html += '<div class="artifact">';
            html += '<h3>✅ Artifact 4: Comparative Evaluation (ML vs Baseline)</h3>';
            const eval_data = data.comparative_evaluation;
            html += '<table>';
            html += '<tr><td><strong>Rule-based accuracy:</strong></td><td>' + eval_data.comparison.rule_based_accuracy + '</td></tr>';
            html += '<tr><td><strong>ML-assisted accuracy:</strong></td><td>' + eval_data.comparison.ml_assisted_accuracy + '</td></tr>';
            html += '<tr><td><strong>Improvement:</strong></td><td>' + eval_data.comparison.accuracy_improvement + '</td></tr>';
            html += '<tr><td><strong>False positive reduction:</strong></td><td>' + eval_data.comparison.false_positive_reduction + '</td></tr>';
            html += '</table>';
            html += '<p><em>' + eval_data.justification + '</em></p>';
            html += '</div>';
            
            // Artifact 5: Reproducibility
            html += '<div class="artifact">';
            html += '<h3>✅ Artifact 5: Reproducibility Proof</h3>';
            const repro = data.reproducibility;
            html += '<table>';
            html += '<tr><td><strong>Run ID:</strong></td><td>' + repro.run_id + '</td></tr>';
            html += '<tr><td><strong>Timestamp:</strong></td><td>' + repro.timestamp + '</td></tr>';
            html += '<tr><td><strong>Duration:</strong></td><td>' + repro.duration_seconds + 's</td></tr>';
            html += '<tr><td><strong>Input Hash:</strong></td><td>' + repro.input_hash + '</td></tr>';
            html += '<tr><td><strong>Data Freshness:</strong></td><td>' + repro.data_freshness + '</td></tr>';
            html += '</table>';
            html += '<h4>Model Versions:</h4>';
            html += '<pre>' + JSON.stringify(repro.model_versions, null, 2) + '</pre>';
            html += '</div>';
            
            results.innerHTML = html;
        }
    </script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
async def index():
    """Serve the main page."""
    return INDEX_HTML


@app.post("/api/scan")
async def scan_assets(request: Request):
    """Run risk assessment on provided assets."""
    data = await request.json()
    input_text = data.get('input', '')
    
    # Parse input
    assets = parse_input_list(input_text)
    
    if not assets:
        return JSONResponse({"error": "No valid assets provided"}, status_code=400)
    
    # Run pipeline
    pipeline = AutomatedPipeline()
    results = pipeline.run(assets)
    
    return JSONResponse(results)


@app.get("/api/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}


if __name__ == "__main__":
    import uvicorn
    print("\n" + "="*60)
    print("🔒 Internet Exposure Risk Scanner - Web Interface")
    print("="*60)
    print("\n📌 Open browser: http://localhost:8080")
    print("📌 API docs: http://localhost:8080/docs")
    print("\nPress Ctrl+C to stop\n")
    uvicorn.run(app, host="0.0.0.0", port=8080)
