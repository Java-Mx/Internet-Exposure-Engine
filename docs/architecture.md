# System Architecture

## Overview

The Internet Exposure Discovery and Risk Scoring System follows a modular, pipeline-driven architecture where each component is independent and testable.

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Data Ingestion Layer                        │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────┐ ┌──────────┐ │
│  │  Shodan  │ │  Censys  │ │  GitHub  │ │ HIBP │ │   NVD    │ │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └───┬──┘ └────┬─────┘ │
└───────┼────────────┼────────────┼────────────┼─────────┼───────┘
        │            │            │            │         │
        └────────────┴────────────┴────────────┴─────────┘
                              │
                    ┌─────────▼─────────┐
                    │   Normalization   │
                    └─────────┬─────────┘
                              │
                    ┌─────────▼─────────┐
                    │  MySQL Database   │
                    └─────────┬─────────┘
                              │
                    ┌─────────▼─────────┐
                    │Feature Engineering│
                    └─────────┬─────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
┌───────▼────────┐  ┌─────────▼─────────┐  ┌───────▼────────┐
│   Supervised   │  │  Unsupervised     │  │ Graph Analysis │
│   ML Models    │  │  Anomaly Detection│  │ & Propagation  │
└───────┬────────┘  └─────────┬─────────┘  └───────┬────────┘
        │                     │                     │
        └─────────────────────┼─────────────────────┘
                              │
                    ┌─────────▼─────────┐
                    │  Risk Scoring     │
                    │     Engine        │
                    └─────────┬─────────┘
                              │
                    ┌─────────▼─────────┐
                    │  Report Generator │
                    └───────────────────┘
```

## Component Details

### 1. Data Ingestion Layer
- **Purpose**: Continuously fetch data from public APIs
- **Components**: 5 connectors (Shodan, Censys, GitHub, HIBP, NVD)
- **Output**: Normalized Asset entities with timestamps

### 2. Feature Engineering
- **Purpose**: Transform raw data into ML-ready features
- **Components**: 
  - Numeric extractors (CVSS, port, duration)
  - Categorical encoders (service, ASN, country)
  - Text embeddings (Sentence-BERT)
- **Output**: Feature vectors for each asset

### 3. ML Models
- **Supervised**: Logistic Regression, Random Forest, Neural Network
- **Unsupervised**: Isolation Forest, DBSCAN
- **Output**: Severity predictions + anomaly scores

### 4. Graph Analysis
- **Purpose**: Model asset relationships and propagate risk
- **Components**: NetworkX graph, centrality metrics, risk propagation
- **Output**: Graph risk scores

### 5. Risk Scoring Engine
- **Purpose**: Combine all signals into final risk score
- **Formula**: `0.3×severity + 0.25×breach + 0.2×graph + 0.15×anomaly + 0.1×CVE`
- **Output**: Risk score (0-100) + explanation

### 6. Reporting
- **Purpose**: Generate evidence-backed reports
- **Output**: HTML/PDF reports with visualizations

## Database Schema

See [schema.sql](file:///f:/internet_exposure_system/database/schema.sql) for complete schema.

**Key Tables**:
- `assets` - Core asset data
- `cve_data` - Vulnerability information
- `breach_data` - Breach records
- `github_exposures` - Credential leaks
- `asset_features` - ML features
- `risk_assessments` - Final risk scores
- `ml_predictions` - Model outputs
- `graph_edges` - Asset relationships

## Data Flow

1. **Ingestion** → Raw data from APIs
2. **Normalization** → Canonical Asset format
3. **Storage** → MySQL database (append-only)
4. **Feature Engineering** → ML-ready vectors
5. **ML Inference** → Predictions + anomaly scores
6. **Graph Analysis** → Relationship mapping + risk propagation
7. **Risk Scoring** → Weighted combination
8. **Reporting** → Evidence-backed reports

## Technology Stack

- **Language**: Python 3.9+
- **Database**: MySQL 8.0+
- **ML Frameworks**: TensorFlow, scikit-learn
- **Graph**: NetworkX
- **NLP**: Sentence-Transformers
- **ORM**: SQLAlchemy
- **Testing**: pytest
