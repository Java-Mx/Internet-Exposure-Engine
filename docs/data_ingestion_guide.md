# Data Ingestion Layer - Usage Guide

## Overview

The data ingestion layer provides connectors for 5 public data sources:
- **Shodan**: Exposed services and ports
- **Censys**: TLS certificates and host data
- **GitHub**: Potential credential leaks
- **HaveIBeenPwned**: Breach information
- **NVD**: CVE vulnerability data

## Quick Start

### 1. Configure API Keys

Edit your `.env` file:

```env
SHODAN_API_KEY=your_shodan_key
CENSYS_API_ID=your_censys_id
CENSYS_API_SECRET=your_censys_secret
GITHUB_TOKEN=your_github_token
HIBP_API_KEY=your_hibp_key
```

### 2. Run Ingestion

```bash
# Activate virtual environment
.\venv\Scripts\Activate.ps1

# Run all sources
python -m data_ingestion.run_ingestion --source all

# Run specific source
python -m data_ingestion.run_ingestion --source nvd
python -m data_ingestion.run_ingestion --source hibp
python -m data_ingestion.run_ingestion --source github --limit 50
```

## Individual Connector Usage

### Shodan

```python
from data_ingestion import ShodanConnector, DataNormalizer, DataStorage

connector = ShodanConnector()
normalizer = DataNormalizer()
storage = DataStorage()

# Fetch data for specific IP
normalized_data = connector.fetch_and_normalize('8.8.8.8')

# Expand multi-port assets
expanded = []
for data in normalized_data:
    expanded.extend(normalizer.expand_multi_port_assets(data))

# Convert to models and save
assets = [normalizer.normalize_asset(d) for d in expanded]
storage.save_assets([a for a in assets if a])
```

### Censys

```python
from data_ingestion import CensysConnector

connector = CensysConnector()

# Search for hosts
results = connector.search_and_normalize('services.port:443', index='hosts')

# Get specific host
host_data = connector.get_host('1.1.1.1')
if host_data:
    normalized = connector.normalize_data(host_data)
```

### GitHub

```python
from data_ingestion import GitHubConnector

connector = GitHubConnector()

# Fetch and detect secrets in public events
exposures = connector.fetch_and_normalize(event_type='PushEvent', limit=100)

# Search code for specific patterns
results = connector.search_code('api_key password')
```

### HaveIBeenPwned

```python
from data_ingestion import HIBPConnector

connector = HIBPConnector()

# Fetch all breaches
breaches = connector.fetch_and_normalize()

# Check specific account (requires API key)
account_breaches = connector.check_and_normalize_account('test@example.com')

# Check domain
domain_breaches = connector.check_domain('example.com')
```

### NVD

```python
from data_ingestion import NVDConnector

connector = NVDConnector()

# Fetch recently modified CVEs
cves = connector.fetch_and_normalize(modified=True)

# Fetch specific year
cves_2023 = connector.fetch_and_normalize(year=2023)

# Search specific CVE
cve = connector.search_cve('CVE-2023-12345')
```

## Rate Limits

Each connector implements rate limiting:

| Source | Rate Limit | Notes |
|--------|-----------|-------|
| Shodan | 1 req/sec | Conservative limit |
| Censys | 0.4 req/sec | Free tier: 120/5min |
| GitHub | 1 req/sec | Higher with token |
| HIBP | 0.05 req/sec | 1 req/1.5sec |
| NVD | 0.6 req/sec | Max 5/30sec |

## Data Flow

```
API Call → Connector.fetch_data()
         ↓
    Connector.normalize_data()
         ↓
    DataNormalizer.expand_multi_port_assets()
         ↓
    DataNormalizer.normalize_asset/cve/breach/exposure()
         ↓
    DataStorage.save_*()
         ↓
    MySQL Database
```

## Error Handling

All connectors include:
- Automatic retry on rate limit (429)
- Graceful handling of network errors
- Logging of all errors
- Skip on duplicate data

## Testing

```bash
# Run unit tests
pytest tests/unit/test_connectors.py -v

# Run integration tests
pytest tests/integration/test_ingestion_pipeline.py -v

# Run with coverage
pytest tests/ --cov=data_ingestion --cov-report=html
```

## Troubleshooting

### No API Key Warnings

```
WARNING - Shodan API key not configured. Limited functionality.
```

**Solution**: Add API keys to `.env` file

### Rate Limit Errors

```
WARNING - Rate limit exceeded, backing off...
```

**Solution**: Connectors automatically wait and retry. No action needed.

### Import Errors

```
ModuleNotFoundError: No module named 'data_ingestion'
```

**Solution**: Ensure virtual environment is activated and you're in the project root

## Next Steps

After ingestion, data is ready for:
1. **Phase 3**: Feature engineering
2. **Phase 4**: ML model training
3. **Phase 5**: Anomaly detection
