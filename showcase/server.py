"""
CyberShield Showcase API - Flask Backend

Provides REST API endpoints for the showcase website to scan URLs
using the integrated risk scoring engine.
"""

import sys
from pathlib import Path
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from risk_scoring.heuristic_detector import get_heuristic_detector

# Initialize Flask app
app = Flask(__name__, static_folder='.')
CORS(app)  # Enable CORS for development

# Initialize detector
detector = get_heuristic_detector()


@app.route('/')
def index():
    """Serve the main HTML page."""
    return send_from_directory('.', 'index.html')


@app.route('/css/<path:filename>')
def serve_css(filename):
    """Serve CSS files."""
    return send_from_directory('css', filename)


@app.route('/js/<path:filename>')
def serve_js(filename):
    """Serve JavaScript files."""
    return send_from_directory('js', filename)


@app.route('/api/scan', methods=['POST'])
def scan_url():
    """
    Scan a single URL for security risks.
    
    Request Body:
        {
            "domain": "example.com",
            "port": 443,
            "service": "https"
        }
    
    Response:
        {
            "domain": "example.com",
            "port": 443,
            "risk_score": 75,
            "risk_level": "HIGH",
            "evidence": [...],
            "timestamp": "2024-..."
        }
    """
    try:
        data = request.get_json()
        
        if not data or 'domain' not in data:
            return jsonify({'error': 'Missing domain parameter'}), 400
        
        domain = data.get('domain', '').strip().lower()
        port = data.get('port', 443)
        
        if not domain:
            return jsonify({'error': 'Empty domain'}), 400
        
        # Run heuristic analysis
        result = detector.get_complete_analysis(domain, port)
        
        # Add additional metadata
        result['scan_type'] = 'heuristic+ml'
        result['timestamp'] = datetime.now().isoformat()
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({
            'error': str(e),
            'domain': data.get('domain', 'unknown') if data else 'unknown',
            'risk_score': 0,
            'risk_level': 'ERROR'
        }), 500


@app.route('/api/scan/batch', methods=['POST'])
def scan_batch():
    """
    Scan multiple URLs in batch.
    
    Request Body:
        {
            "urls": [
                {"domain": "example.com", "port": 443},
                {"domain": "test.com", "port": 80}
            ]
        }
    
    Response:
        {
            "results": [...],
            "summary": {
                "total": 2,
                "critical": 0,
                "high": 1,
                "medium": 1,
                "low": 0
            }
        }
    """
    try:
        data = request.get_json()
        
        if not data or 'urls' not in data:
            return jsonify({'error': 'Missing urls parameter'}), 400
        
        urls = data.get('urls', [])
        results = []
        
        for url_data in urls[:50]:  # Limit to 50 URLs
            domain = url_data.get('domain', '').strip().lower()
            port = url_data.get('port', 443)
            
            if domain:
                result = detector.get_complete_analysis(domain, port)
                results.append(result)
        
        # Calculate summary
        summary = {
            'total': len(results),
            'critical': sum(1 for r in results if r['risk_level'] == 'CRITICAL'),
            'high': sum(1 for r in results if r['risk_level'] == 'HIGH'),
            'medium': sum(1 for r in results if r['risk_level'] == 'MEDIUM'),
            'low': sum(1 for r in results if r['risk_level'] == 'LOW'),
        }
        
        return jsonify({
            'results': results,
            'summary': summary,
            'timestamp': datetime.now().isoformat()
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'service': 'CyberShield Risk Scanner API',
        'version': '1.0.0',
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/known-vulnerabilities', methods=['GET'])
def known_vulnerabilities():
    """Get list of known vulnerable domains in the database."""
    from risk_scoring.heuristic_detector import KNOWN_VULNERABLE_DOMAINS
    
    vulns = []
    for domain, info in KNOWN_VULNERABLE_DOMAINS.items():
        vulns.append({
            'domain': domain,
            'risk_score': info['risk'],
            'description': info['reason']
        })
    
    return jsonify({
        'count': len(vulns),
        'vulnerabilities': sorted(vulns, key=lambda x: -x['risk_score'])
    })


def run_server(host='127.0.0.1', port=5000, debug=True):
    """Run the Flask development server."""
    print(f"""
+------------------------------------------------------------------+
|                                                                  |
|   CyberShield Showcase Website                                   |
|   -------------------------------------------------------------  |
|                                                                  |
|   Server running at: http://{host}:{port}                       |
|   API endpoint:      http://{host}:{port}/api/scan              |
|                                                                  |
|   Press Ctrl+C to stop                                           |
|                                                                  |
+------------------------------------------------------------------+
    """)
    app.run(host=host, port=port, debug=debug)


if __name__ == '__main__':
    run_server()
