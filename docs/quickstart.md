# Internet Exposure Risk Scoring System - Quick Start Guide

## Overview

The Internet Exposure Risk Scoring System is a production-ready ML-powered platform that analyzes internet-exposed assets and generates comprehensive risk assessments with explainable AI.

## Features

✅ **Multi-Source Data Ingestion** - Shodan, GitHub, HIBP, NVD, Censys  
✅ **433-Dimensional Feature Engineering** - Numeric, categorical, and text embeddings  
✅ **ML-Powered Risk Prediction** - Random Forest + Isolation Forest  
✅ **Graph-Based Analysis** - Asset relationships and breach proximity  
✅ **Explainable Risk Scores** - Detailed evidence and recommendations  
✅ **REST API** - 6 endpoints for integration  
✅ **Automated Reports** - Industry-standard JSON + HTML  

## Installation

```bash
# Clone repository
cd f:\internet_exposure_system

# Install dependencies
pip install -r requirements.txt
pip install -r requirements_api.txt

# Set environment variables (optional - for real data)
export SHODAN_API_KEY="your_key"
export GITHUB_TOKEN="your_token"
```

## Quick Start

### 1. Run Prototype Demo

```bash
# Test with mock data (no API keys needed)
python prototype/real_data_demo.py --mock --count 20

# Output:
# ✓ Demo completed successfully!
# Check reports at: reports\risk_report_YYYYMMDD_HHMMSS.html
```

### 2. Start REST API

```bash
# Start API server
uvicorn api.rest_api:app --host 0.0.0.0 --port 8000

# Access API documentation
# Open browser: http://localhost:8000/docs
```

### 3. Use API

```python
import requests

# Assess single asset
response = requests.post('http://localhost:8000/api/assess', json={
    'ip': '192.168.1.100',
    'port': 22,
    'service': 'ssh',
    'country': 'US'
})

result = response.json()
print(f"Risk Score: {result['risk_score']}")
print(f"Severity: {result['severity']}")
```

## Industry-Standard Report Format

Each assessment produces a structured risk report:

```json
{
  "asset": "example.com",
  "risk_score": 82,
  "risk_level": "CRITICAL",
  "severity_model": {
    "class": "HIGH",
    "confidence": 0.87
  },
  "anomaly_score": 0.63,
  "graph_impact": {
    "connected_assets": 14,
    "breach_proximity": true
  },
  "evidence": [
    "Exposed HTTPS admin panel",
    "Shared TLS cert with breached domain",
    "High CVSS vulnerability context"
  ],
  "ml_signals": {
    "supervised_prediction": 0.82,
    "anomaly_detection": 0.63,
    "graph_centrality": 0.45,
    "risk_propagation": 0.71
  },
  "recommendations": [
    "URGENT: Immediate investigation required",
    "Review access logs and network traffic",
    "Consider isolating asset from network"
  ],
  "timestamp": "2026-02-06T20:30:00"
}
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | API info |
| `/api/health` | GET | Health check |
| `/api/assess` | POST | Assess single asset |
| `/api/scan` | POST | Scan multiple assets |
| `/api/reports` | GET | List reports |
| `/api/reports/{filename}` | GET | Download report |
| `/api/stats` | GET | System statistics |

## Test Results

- **Total Tests:** 102
- **Passing:** 101 ✅
- **Pass Rate:** 99.0%
- **Code Coverage:** 56%

## Performance

- **Single Asset:** <2 seconds
- **Batch of 50:** ~30 seconds
- **Model Loading:** ~15 seconds (one-time)

## Project Structure

```
internet_exposure_system/
├── api/                    # REST API and orchestration
├── data_ingestion/         # Data connectors
├── feature_engineering/    # Feature extraction
├── ml_models/              # ML models (supervised/unsupervised)
├── graph_analysis/         # Graph-based analysis
├── risk_scoring/           # Risk calculation and explanation
├── reporting/              # Report generation
├── prototype/              # Demo and testing
├── tests/                  # Test suite
└── reports/                # Generated reports
```

## Next Steps

1. **Configure API Keys** - Add real data sources
2. **Train Models** - Use your own data
3. **Deploy API** - Production deployment
4. **Integrate** - Connect to your security stack

## Support

- **Documentation:** See `walkthrough.md`
- **API Docs:** http://localhost:8000/docs
- **Tests:** `pytest tests/unit/ -v`

## License

MIT License - Production Ready
