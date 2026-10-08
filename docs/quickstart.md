# Quick Start Guide

## Prerequisites

- Python 3.9+
- pip

## Setup

```bash
# 1. Create virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # macOS/Linux

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure environment
copy .env.example .env       # Windows
cp .env.example .env         # macOS/Linux
```

Edit `.env` with your API keys (Shodan, NVD are optional but recommended).

## Run the Dashboard

```bash
streamlit run app.py
```

1. Enter domains/URLs in the text area (one per line)
2. Click **Start Strategic Scan**
3. View results in the tabs: Summary, Accuracy, Graph, Detailed Results

## Run via CLI

```bash
# Single target
python risk_scanner.py --targets "example.com"

# Multiple targets
python risk_scanner.py --targets "google.com, github.com, example.com"

# From CSV file
python risk_scanner.py --csv assets.csv
```

## Sync NVD Data (Optional)

```bash
# Pull last 30 days of CVEs
python nvd_sync.py --days-back 30

# View cache statistics
python nvd_sync.py --stats
```

## Run Tests

```bash
python -m pytest tests/ -v --tb=short -W ignore::ResourceWarning
```

## Input Rules

- **Domains**: must be valid (e.g. `example.com`, not `localhost`)
- **IPs**: public only — `192.168.x.x`, `10.x.x.x`, `127.0.0.1` are rejected
- **Batch limit**: 50 targets per scan
- **Supported formats**: bare domain, full URL, IP address, URL with port
