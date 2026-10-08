# Architecture Overview

## System Pipeline

```
User Input (CLI / Streamlit)
        │
        ▼
┌──────────────────┐
│  Input Validation │ ← utils/validators.py
│  & Parsing        │ ← risk_scanner.parse_input_list()
└──────────────────┘
        │
        ▼
┌──────────────────┐
│  Data Ingestion   │ ← Shodan, Censys, GitHub, HIBP connectors
│  & Normalisation  │ ← data_ingestion/
└──────────────────┘
        │
        ▼
┌──────────────────┐
│  Feature          │ ← feature_engineering/
│  Engineering      │   Categorical, numerical, text features
└──────────────────┘
        │
        ▼
┌──────────────────┐
│  Threat Intel     │ ← risk_scoring/threat_intel/
│  Enrichment       │   Shodan ports, Censys certs, NVD CVEs
└──────────────────┘
        │
        ▼
┌──────────────────┐
│  ML Prediction    │ ← ml_models/
│  & Anomaly Det.   │   Random Forest + Isolation Forest
└──────────────────┘
        │
        ▼
┌──────────────────┐
│  Graph Analysis   │ ← graph_analysis/
│  & Propagation    │   NetworkX-based risk propagation
└──────────────────┘
        │
        ▼
┌──────────────────┐
│  Risk Scoring     │ ← risk_scoring/
│  Engine           │   Weighted signals + heuristic boost
│                   │   + NVD Technology Risk Index
└──────────────────┘
        │
        ▼
┌──────────────────┐
│  Explanation &    │ ← risk_scoring/explanation_generator.py
│  Report Output    │ ← reporting/
└──────────────────┘
```

## Key Components

### Input Layer
- `risk_scanner.parse_input_list()` — parses domains, URLs, and IPs with RFC-compliant validation
- `utils/validators.py` — rejects private IPs, invalid TLDs, and oversized inputs
- `utils/safe_requests.py` — centralised HTTP client with retries, timeouts, and error wrapping

### Scoring Engine
- **Weighted Signal Combination**: ML (30%) + Anomaly (25%) + Graph (20%) + Propagation (25%)
- **Heuristic Boost**: `heuristic_detector.py` provides 360° URL inspection (entropy, patterns, path analysis)
- **NVD Context**: `vulnerability_context.py` computes a Technology Risk Index (up to +15% boost)
- **Trusted Domains**: Major platforms are recognised and shielded from false-positive heuristics

### Data Flow
1. User submits targets via Streamlit (`app.py`) or CLI (`risk_scanner.py`)
2. `ScanEngine` wraps `AutomatedPipeline` for streaming progress
3. Pipeline validates → enriches → predicts → scores → reports
4. Results displayed in dashboard or written to JSON

### NVD Integration
- `nvd_sync_service.py` pulls CVEs from NVD API 2.0 into local SQLite (`data/nvd_cve_cache.db`)
- `technology_inferrer.py` infers technology categories from passive metadata
- `vulnerability_context.py` computes risk index from matched CVEs
- All NVD data fetching is offline-only — never during live scans
