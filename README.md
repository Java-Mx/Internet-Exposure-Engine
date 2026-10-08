# Internet Exposure Engine

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/Python-3.12+-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/API-FastAPI-009688.svg)](https://fastapi.tiangolo.com/)
[![Streamlit](https://img.shields.io/badge/UI-Streamlit-FF4B4B.svg)](https://streamlit.io/)

**Internet Exposure Engine (AERIS — Autonomous Exposure & Risk Intelligence System)** is an enterprise-grade security intelligence and attack surface management platform. It discovers, analyzes, and prioritizes internet-facing exposures using **strictly public, passive telemetry** — without active port scanning, intrusive probing, or network exploitation.

The system combines multi-source threat intelligence, machine learning classifiers, anomaly detection, network graph propagation, and vulnerability context (NVD/EPSS) to deliver actionable, explainable cyber risk assessments.

---

## Table of Contents

- [Problem Statement](#problem-statement)
- [Key Capabilities](#key-capabilities)
- [Architecture & High-Level Workflow](#architecture--high-level-workflow)
- [Risk Scoring Methodology](#risk-scoring-methodology)
- [Technology Stack](#technology-stack)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Installation & Setup](#installation--setup)
- [Configuration & Environment](#configuration--environment)
- [How to Run](#how-to-run)
  - [1. Interactive Dashboard (Streamlit)](#1-interactive-dashboard-streamlit)
  - [2. Enterprise API Gateway (FastAPI)](#2-enterprise-api-gateway-fastapi)
  - [3. Docker Compose Deployment](#3-docker-compose-deployment)
  - [4. Kubernetes Orchestration](#4-kubernetes-orchestration)
- [API Overview](#api-overview)
- [Testing & Quality Governance](#testing--quality-governance)
- [Security Considerations & Passive Compliance](#security-considerations--passive-compliance)
- [Limitations & Constraints](#limitations--constraints)
- [Contributing](#contributing)
- [License](#license)

---

## Problem Statement

Modern enterprise perimeters are dynamic, decentralized, and prone to silent exposure through cloud misconfigurations, shadow IT, abandoned subdomains, exposed credentials, and unpatched third-party dependencies. Traditional vulnerability scanning tools often:

1. Rely on intrusive, noisy network probes that trigger firewall blocks or disrupt production environments.
2. Produce overwhelming volumes of uncontextualized alerts with high false-positive rates.
3. Lack asset criticality and real-world exploitability context (e.g., EPSS, active weaponization).

The **Internet Exposure Engine** addresses these challenges by operating entirely passively from the adversary's outside-in perspective, aggregating real-time threat intelligence and prioritizing exposures based on composite business risk and exploit probability.

---

## Key Capabilities

| Capability | Description |
|---|---|
| **Passive Attack Surface Discovery** | Discovers subdomains, certificate transparency logs (`crt.sh`), DNS records, cloud storage buckets, and public exposures without direct target interaction. |
| **Multi-Source Threat Intelligence** | Integrates AbuseIPDB, URLHaus, Censys, Shodan, HaveIBeenPwned (HIBP), and the National Vulnerability Database (NVD). |
| **Hybrid Machine Learning Scoring** | Blends supervised classifiers (Random Forest, Logistic Regression), deep representations (PyTorch NN), and unsupervised anomaly detectors (Isolation Forest, Autoencoders). |
| **Heuristic & Anomaly Detection** | Evaluates 200+ domain and URL heuristics, entropy variations, DGA behavior, and lexical typosquatting patterns. |
| **Graph-Based Exposure Propagation** | Analyzes infrastructure topology with NetworkX to calculate centrality metrics, blast radius, and breach proximity across interconnected assets. |
| **EPSS & NVD Exploit Prioritization** | Correlates discovered components against NVD CVEs and Exploit Prediction Scoring System (EPSS) probabilities to filter out non-weaponizable vulnerabilities. |
| **Trusted Domain Whitelisting** | Configurable domain whitelist (`config/trusted_domains.txt`) prevents false-positive alerts on major corporate cloud infrastructure and SaaS services. |
| **Enterprise Portal & Multi-Tenancy** | Production-ready FastAPI gateway with JWT authentication, Token Bucket rate limiting, SIEM logging, tenant segregation, and analyst triage workflows. |
| **Executive & Technical Reporting** | Produces human-readable explanations, PDF summaries (via ReportLab), and JSON/HTML triage exports. |
| **Automated Anti-Theater Governance** | Code quality, mutation testing, test coverage assertion, and model leakage verification built directly into the CI/CD pipeline. |

---

## Architecture & High-Level Workflow

The engine executes across five coordinated stages:

```
┌────────────────────────────────────────────────────────────────────────┐
│ 1. EXPOSURE DISCOVERY (Passive Only)                                   │
│    - Subdomain Enumeration       - Certificate Transparency (crt.sh)   │
│    - Cloud Asset Scanning        - Public Credential Dumps (HIBP)      │
└───────────────────────────────────┬────────────────────────────────────┘
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ 2. THREAT INTELLIGENCE & CORRELATION                                   │
│    - AbuseIPDB / URLHaus Feeds   - Shodan / Censys Telemetry           │
│    - NVD CVE Database Cache      - EPSS Exploit Prediction             │
└───────────────────────────────────┬────────────────────────────────────┘
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ 3. MULTI-SIGNAL RISK ENGINE                                            │
│    - 200+ Heuristic Rules        - Lexical / Entropy Analyzers         │
│    - Supervised ML Severity      - Unsupervised Anomaly Scoring        │
│    - Graph Proximity / Centrality- Technology Risk Index               │
└───────────────────────────────────┬────────────────────────────────────┘
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ 4. BUSINESS & ASSET PRIORITIZATION                                     │
│    - Asset Criticality Mapping   - Business Unit Attribution           │
│    - Exploitability Weighting    - Composite Priority Formula          │
└───────────────────────────────────┬────────────────────────────────────┘
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ 5. PRESENTATION & INTEGRATION                                          │
│    - Streamlit Security Dashboard│ - FastAPI Enterprise Gateway        │
│    - Analyst Triage Queue        │ - Executive PDF / SIEM Exports      │
└────────────────────────────────────────────────────────────────────────┘
```

---

## Risk Scoring Methodology

The engine calculates a composite **Risk Score (0–100)** utilizing weighted multi-signal aggregation:

```text
Base Risk = (30% × ML Severity)
          + (25% × Anomaly Score)
          + (20% × Graph Centrality)
          + (25% × Risk Propagation)
          + [Up to +15% NVD Technology Risk Boost]
```

Asset prioritization subsequently factors in asset criticality and real-world exploit probability:

```text
Priority Score = (35% × Risk Score)
               + (25% × Asset Criticality)
               + (20% × EPSS Probability)
               + (10% × Active Threat Intel)
               + (10% × Compliance Scope)
```

### Risk Severity Tiers

| Score Range | Severity | Actionable Interpretation |
|---|---|---|
| **0 – 24** | **Low** | Routine internet presence; maintain normal monitoring cycles. |
| **25 – 49** | **Medium** | Minor exposures or hygiene issues; schedule review during regular maintenance. |
| **50 – 74** | **High** | Exposed sensitive services or elevated exploit potential; investigate with priority. |
| **75 – 100** | **Critical** | Active breach correlation, critical vulnerability with high EPSS, or dangerous misconfiguration. Urgent remediation required. |

---

## Technology Stack

- **Runtime:** Python 3.12+
- **Machine Learning & Data Science:** PyTorch, Scikit-Learn, Pandas, NumPy
- **Graph & Topology Analysis:** NetworkX
- **NLP & Text Representations:** Sentence-Transformers
- **API Framework:** FastAPI, Uvicorn, Pydantic
- **Dashboard & User Interface:** Streamlit, Plotly
- **Data Persistence:** SQLite, SQLAlchemy
- **Reporting:** ReportLab (PDF), Plotly Charts
- **Testing & Quality:** Pytest, Pytest-Cov, Bandit, Flake8, Black
- **Containerization & Orchestration:** Docker, Docker Compose, Kubernetes

---

## Project Structure

```text
internet_exposure_system/
├── app.py                      # Interactive Streamlit dashboard application
├── Dockerfile.dashboard        # Container definition for UI dashboard
├── Dockerfile.portal           # Container definition for API gateway
├── docker-compose.yml          # Multi-container orchestration
├── k8s-deployment.yaml         # Kubernetes deployment & service specifications
├── requirements.txt            # Python dependencies
├── pytest.ini                  # Pytest configuration & test markers
├── DATASET_AUDIT.md            # ML dataset provenance and leakage audit
├── LICENSE                     # Apache License 2.0
├── PATENT.md                   # Patent license agreement
├── SECURITY.md                 # Security reporting and disclosure policy
│
├── config/                     # Configuration and environment loaders
│   ├── settings.py             # Global application settings
│   ├── logging_config.py       # Structured SIEM logging setup
│   ├── env_validator.py        # Environment variable sanity checking
│   ├── org_mappings.json       # Asset-to-business-unit taxonomy
│   ├── prometheus.yml          # Telemetry monitoring config
│   └── trusted_domains.txt     # Whitelist for false-positive reduction
│
├── portal/                     # Enterprise FastAPI Gateway & Portal
│   ├── api.py                  # API endpoints, authentication, triage queues
│   └── core/                   # Auth, telemetry, workflows, tenancy, db
│
├── exposure_discovery/         # Passive asset & exposure discovery
│   ├── cloud_asset_scanner.py  # Public cloud storage bucket scanner
│   ├── credential_monitor.py   # Public breach and credential monitor (HIBP)
│   ├── discovery_orchestrator.py # Multi-feed discovery pipeline
│   ├── phishing_tracker.py     # Typosquatting and domain impersonation
│   └── subdomain_enumerator.py # Passive DNS and crt.sh enumeration
│
├── intelligence/               # Threat intelligence correlation
│   ├── correlation_engine.py   # Cross-source intelligence enrichment
│   ├── threat_reasoning.py     # Automated exposure contextualization
│   ├── threat_memory.py        # Historical incident and exposure cache
│   ├── business_context.py     # Business unit attribution
│   └── adversarial_filter.py   # Anti-spoofing and telemetry validation
│
├── prioritization/             # Risk prioritization & impact scoring
│   ├── prioritization_engine.py# Composite prioritization algorithm
│   ├── epss_client.py          # EPSS API integration
│   └── impact_estimator.py     # Business impact severity calculator
│
├── risk_scoring/               # Core risk calculation modules
│   ├── risk_calculator.py      # Weighted risk formula engine
│   ├── heuristic_detector.py   # 200+ domain/URL heuristic checks
│   ├── signal_integrator.py    # Multi-model score assembler
│   └── explanation_generator.py# Human-readable risk explanations
│
├── graph_analysis/             # Network topology & breach proximity
│   ├── graph_builder.py        # Asset relationship graph generator
│   ├── breach_proximity.py     # Distance to compromised assets
│   ├── centrality_calculator.py# Eigenvector and degree centrality
│   └── risk_propagator.py      # Graph-based risk diffusion
│
├── ml_models/                  # Supervised & unsupervised ML architectures
│   ├── supervised/             # Random Forest, Logistic Regression, Neural Net
│   ├── unsupervised/           # Isolation Forest, Autoencoder anomaly detectors
│   └── datasets/               # Evaluation dataset seeds & metadata
│
├── asset_registry/             # Asset inventory and organizational tracking
├── auth/                       # RBAC, user authentication, and session handling
├── components/                 # Streamlit UI modular components
├── database/                   # Schema definitions and migrations
├── evaluation/                 # ML metric calculation and benchmarking
├── governance/                 # Anti-theater scanners, coverage & mutation tests
├── pages/                      # Multi-page Streamlit dashboards
├── records/                    # Scan history and SQLite database manager
├── reporting/                  # Technical & executive PDF report generators
├── research/                   # Research benchmarks and dataset loaders
├── services/                   # Business services (assessment, memory, history)
├── tests/                      # Comprehensive unit and integration test suite
├── utils/                      # Validators, network clients, helpers
└── visualizations/             # Plotly charts, timelines, and topology maps
```

---

## Prerequisites

- **Python:** 3.12 or newer
- **Operating System:** Linux, macOS, or Windows
- **Memory:** Minimum 4 GB RAM (8 GB recommended for training ML models)
- **Optional Tools:** Docker & Docker Compose (for containerized deployments), Ollama (for local LLM summarization)

---

## Installation & Setup

### 1. Clone the Repository

```bash
git clone https://github.com/Java-Mx/Internet-Exposure-Engine.git
cd Internet-Exposure-Engine
```

### 2. Create and Activate Virtual Environment

```bash
# Linux / macOS
python3 -m venv venv
source venv/bin/activate

# Windows (PowerShell)
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### 3. Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

---

## Configuration & Environment

The application relies on environment variables for external threat intelligence integrations. A pre-configured template is provided in `.env.example`.

Create your local `.env` file:

```bash
cp .env.example .env     # Linux / macOS
copy .env.example .env   # Windows
```

Configure relevant API keys in `.env`:

```ini
# External Threat Intelligence APIs (Free tiers available for all)
SHODAN_API_KEY=your_shodan_api_key
CENSYS_API_ID=your_censys_api_id
CENSYS_API_SECRET=your_censys_api_secret
GITHUB_TOKEN=your_github_token
HIBP_API_KEY=your_hibp_api_key
NVD_API_KEY=your_nvd_api_key

# Reputation Feeds
GOOGLE_SAFE_BROWSING_API_KEY=your_gsb_key
VIRUSTOTAL_API_KEY=your_virustotal_key
ABUSEIPDB_API_KEY=your_abuseipdb_key

# System & Prioritization Weights
LOG_LEVEL=INFO
WEIGHT_SEVERITY=0.30
WEIGHT_BREACH=0.25
WEIGHT_GRAPH=0.20
WEIGHT_ANOMALY=0.15
WEIGHT_CVE=0.10

PRIORITY_W_RISK=0.35
PRIORITY_W_CRITICALITY=0.25
PRIORITY_W_EPSS=0.20
PRIORITY_W_THREAT=0.10
PRIORITY_W_COMPLIANCE=0.10
```

> **Security Note:** Never commit your `.env` file. It is excluded by `.gitignore`. The system operates gracefully in offline/fallback mode if API keys are not supplied.

---

## How to Run

### 1. Interactive Dashboard (Streamlit)

Launch the interactive security analyst dashboard:

```bash
streamlit run app.py
```

Access the UI at `http://localhost:8501`.

The dashboard includes:
- Live target assessments (single or batch targets)
- Attack surface topology graphs
- Risk breakdown and explanation panels
- Scan history and remediation tracking
- Red-team simulation & stress-test workspaces

### 2. Enterprise API Gateway (FastAPI)

Launch the REST API portal for programmatic integration:

```bash
uvicorn portal.api:app --host 0.0.0.0 --port 8000 --reload
```

Interactive OpenAPI documentation is available at `http://localhost:8000/docs`.

### 3. Docker Compose Deployment

To build and run both the API Gateway and Streamlit Dashboard concurrently:

```bash
docker compose up --build -d
```

- **Dashboard UI:** `http://localhost:8501`
- **API Gateway:** `http://localhost:8000`
- **API Docs:** `http://localhost:8000/docs`

To stop services:
```bash
docker compose down
```

### 4. Kubernetes Orchestration

Deploy the complete multi-tier setup to a Kubernetes cluster:

```bash
kubectl apply -f k8s-deployment.yaml
```

This provisions deployments, services, ConfigMaps, and resource quotas for both the API and dashboard containers.

---

## API Overview

The FastAPI gateway (`portal/api.py`) exposes endpoints for automation and SIEM orchestration:

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/healthz` | System health check and telemetry status |
| `GET` | `/metrics` | Prometheus performance and rate-limit metrics |
| `POST` | `/api/v1/auth/login` | Authenticate and obtain JWT bearer token |
| `POST` | `/api/v1/scan/schedule` | Schedule an exposure assessment scan |
| `GET` | `/api/v1/assets` | Retrieve asset inventory and exposure classifications |
| `GET` | `/api/v1/triage` | Fetch prioritization queue for security analysts |
| `POST` | `/api/v1/triage/{id}/action` | Update remediation status (Accept, Remediate, Suppress) |
| `GET` | `/api/v1/compliance` | Generate forensic evidence and compliance mappings |

---

## Testing & Quality Governance

The repository includes a comprehensive test suite covering unit tests, integration pipelines, adversarial robustness, and governance checks.

### Running Pytest

```bash
# Run all tests
pytest tests/ -v

# Run unit tests only
pytest tests/unit/ -v

# Run integration tests
pytest tests/integration/ -v

# Run with test coverage report
pytest --cov=. --cov-report=term-missing
```

### Governance & Anti-Theater Auditing

The system enforces automated code quality and anti-theater verification:

```bash
# Verify test coverage targets
python governance/check_coverage.py

# Run anti-theater static compliance scanner
python governance/anti_theater_scanner.py --fail-on HIGH

# Run mutation testing suite
python governance/mutation_tester.py

# Run full CI validation suite
python tests/run_validation.py --skip-benchmarks
```

---

## Security Considerations & Passive Compliance

The engine is engineered specifically for **non-intrusive, passive security assessment**:

- **No Active Scanning:** Does not perform TCP/UDP port scans, banner grabs, or packet probing.
- **No Exploitation:** Does not attempt vulnerability verification, credential stuffing, or exploit payloads.
- **Public Intelligence Only:** Consumes data exclusively from public APIs, DNS registries, and certificate logs.
- **Input Sanitization:** Enforces strict RFC domain and public IP validation; private/loopback addresses are rejected.
- **Rate-Limited Telemetry:** Implements token-bucket rate limiting and exponential backoff on all outbound requests to external APIs.

---

## Limitations & Constraints

1. **Passive Inference Boundaries:** Because the engine does not perform intrusive verification, exposed services are inferred from passive intelligence and open datasets. Verification should precede patching decisions.
2. **External Feed Rate Limits:** Public API tiers (e.g., Shodan, Censys, VirusTotal) impose request quotas. Supplying valid API keys in `.env` ensures uninterrupted throughput.
3. **Domain Whitelisting:** Cloud providers and SaaS platforms may host arbitrary customer content; the whitelist (`config/trusted_domains.txt`) suppresses false positives on reputable shared domains.

---

## Contributing

Contributions are welcome! Please adhere to the following workflow:

1. Fork the repository.
2. Create a focused feature branch (`git checkout -b feature/new-capability`).
3. Commit changes adhering to project linting (`black`, `flake8`) and ensure tests pass.
4. Push to your branch and submit a Pull Request.

Please consult [SECURITY.md](SECURITY.md) for vulnerability disclosure procedures.

---

## License

This project is licensed under the **Apache License, Version 2.0**. See the [LICENSE](LICENSE) file for details.  
Patent grants and terms are documented in [PATENT.md](PATENT.md).

Copyright (c) 2026 Java-Mx.
