# Internet Exposure Discovery and Risk Scoring System

A real-time, external-only Internet exposure discovery and risk scoring system that operates entirely on ethical, non-intrusive public data sources.

## 🎯 Overview

This system combines multiple machine learning techniques to discover and assess internet-facing assets:

- **Supervised Learning**: Severity classification (Low/Medium/High)
- **Unsupervised Learning**: Anomaly detection for novel exposure patterns
- **Graph Analysis**: Risk propagation through connected assets
- **Optional CNN**: Structural pattern recognition on graph projections

## 🚀 Features

- **Continuous Data Ingestion** from public sources (Shodan, Censys, GitHub, HaveIBeenPwned, NVD)
- **ML-Powered Risk Assessment** with explainable scoring
- **Graph-Based Risk Propagation** across related assets
- **Evidence-Backed Reports** with confidence scores
- **Ethical & Legal Compliance** - discovery only, no exploitation

## 📋 Prerequisites

- Python 3.9 or higher
- MySQL 8.0 or higher
- API keys for data sources (see Configuration)

## 🛠️ Installation

### 1. Clone and Setup

```bash
cd f:\internet_exposure_system
python -m venv venv
venv\Scripts\activate  # On Windows
pip install -r requirements.txt
```

### 2. Configure Database

Create a MySQL database:

```sql
CREATE DATABASE exposure_discovery CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'exposure_user'@'localhost' IDENTIFIED BY 'your_password';
GRANT ALL PRIVILEGES ON exposure_discovery.* TO 'exposure_user'@'localhost';
FLUSH PRIVILEGES;
```

### 3. Configure Environment

Copy the example environment file and edit it:

```bash
copy .env.example .env
```

Edit `.env` and configure:

```env
# Database
DB_HOST=localhost
DB_PORT=3306
DB_NAME=exposure_discovery
DB_USER=exposure_user
DB_PASSWORD=your_password

# API Keys
SHODAN_API_KEY=your_shodan_key
CENSYS_API_ID=your_censys_id
CENSYS_API_SECRET=your_censys_secret
GITHUB_TOKEN=your_github_token
HIBP_API_KEY=your_hibp_key
```

### 4. Initialize System

```bash
python main.py
```

This will create all necessary database tables and verify configuration.

## 📊 Data Sources

| Source | Purpose | API Required |
|--------|---------|--------------|
| Shodan InternetDB | Exposed services, ports, banners | Yes (paid) |
| Censys Open Data | TLS certificates, fingerprints | Yes (free tier) |
| GitHub Public Events | Potential credential leaks | Yes (free) |
| HaveIBeenPwned | Breach confirmation | Yes (free) |
| NVD/CVE JSON | Vulnerability context | No |

## 🏗️ Architecture

```
Data Ingestion → Normalization → Feature Engineering
                                        ↓
                              ML Models (Supervised + Unsupervised)
                                        ↓
                              Graph Analysis & Risk Propagation
                                        ↓
                              Risk Scoring Engine
                                        ↓
                              Report Generation
```

## 📁 Project Structure

```
internet_exposure_system/
├── config/              # Configuration and settings
├── database/            # Database models and schema
├── data_ingestion/      # Data source connectors
├── feature_engineering/ # Feature extraction and assembly
├── ml_models/           # ML models (supervised, unsupervised, CNN)
├── graph_analysis/      # Graph construction and risk propagation
├── risk_scoring/        # Final risk calculation
├── reporting/           # Report generation
├── tests/               # Unit and integration tests
├── docs/                # Documentation
├── logs/                # Application logs
└── main.py              # Entry point
```

## 🔒 Ethical & Legal Compliance

This system is designed for **discovery only**, not exploitation:

- ✅ Uses only public, official APIs
- ✅ No port scanning or network probing
- ✅ No vulnerability exploitation
- ✅ No authentication testing
- ✅ No internal network analysis

All data access is ethical and legal.

## 📈 Usage

### Run Data Ingestion

```bash
python -m data_ingestion.run_ingestion
```

### Train ML Models

```bash
python -m ml_models.train
```

### Generate Risk Reports

```bash
python -m reporting.generate_reports
```

## 🧪 Testing

Run unit tests:

```bash
pytest tests/unit/
```

Run integration tests:

```bash
pytest tests/integration/
```

## 📝 Risk Scoring Formula

```
Final Risk = 30% × Severity + 25% × Breach + 20% × Graph + 15% × Anomaly + 10% × CVE
```

Risk levels:
- **0-30**: Low
- **31-70**: High
- **71-100**: Critical

## 🤝 Contributing

This is an academic/research project focused on ethical security discovery.

## 📄 License

[Specify your license]

## 🔗 Resources

- [Shodan API Documentation](https://developer.shodan.io/)
- [Censys API Documentation](https://search.censys.io/api)
- [GitHub API Documentation](https://docs.github.com/en/rest)
- [HaveIBeenPwned API](https://haveibeenpwned.com/API/v3)
- [NVD Data Feeds](https://nvd.nist.gov/vuln/data-feeds)

## ⚠️ Disclaimer

This system provides risk assessments based on publicly available data. Results should be verified and used as part of a comprehensive security program. False positives are possible.
