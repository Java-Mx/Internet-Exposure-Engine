# Feature Mapping — IERSS Feature Documentation

## Overview

All features are derived from **passive metadata collection** only. No active scanning or intrusive probing is performed.

## Numeric Features

| Feature | Description | Range | Source | Leakage Risk |
|---------|-------------|-------|--------|--------------|
| `port_normalized` | Normalized port number | 0.0 – 1.0 | Asset metadata | None |
| `is_https` | Whether service uses HTTPS | 0 or 1 | Service detection | None |
| `has_banner` | Whether HTTP banner/header exists | 0 or 1 | Passive header | None |
| `is_ip_address` | Whether target is a raw IP | 0 or 1 | URL parsing | None |
| `open_port_count` | Count of open ports from Shodan | 0 – N | Shodan API | None |
| `cert_valid` | SSL certificate validity | 0 or 1 | Censys API | None |
| `cvss_normalized` | Normalized CVSS score | 0.0 – 1.0 | NVD API | None |
| `has_asn` | Whether ASN info is available | 0 or 1 | Shodan/Censys | None |
| `asn_normalized` | Normalized ASN number | 0.0 – 1.0 | Shodan/Censys | None |
| `is_breached` | Domain appears in breach data | 0 or 1 | HIBP API | None |
| `breach_severity` | Severity of breach (by pwn_count) | 0.0 – 1.0 | HIBP API | None |
| `nvd_critical_count` | Count of critical CVEs | 0 – N | NVD sync | None |
| `nvd_max_score` | Maximum CVE CVSS score | 0.0 – 10.0 | NVD sync | None |

## Categorical Features

| Feature | Description | Encoding | Source |
|---------|-------------|----------|--------|
| `service_type` | Service protocol (http/https/ssh/etc.) | One-hot | Asset metadata |
| `country` | Hosting country code | One-hot | Shodan/Censys |
| `tld` | Top-level domain | One-hot | URL parsing |

## Text Embeddings

| Feature | Description | Dimension | Source |
|---------|-------------|-----------|--------|
| `banner_embedding_*` | Sentence-BERT embedding of service banner | 384 | Banner text |

> **Note**: Embeddings use `all-MiniLM-L6-v2` model with fixed random seed for deterministic output.

## Feature Leakage Prevention

The following safeguards prevent feature leakage:

1. **No post-prediction features**: Features represent pre-analysis state only
2. **No target-encoded features**: Labels are never used to create features
3. **Temporal ordering**: All features are from the observation phase, before classification
4. **Deterministic embeddings**: Same input always produces the same embedding vector

## Normalization

- All numeric features are normalized using `StandardScaler` fitted **only on training data**
- The scaler is then applied to validation and test sets via `transform()` (not `fit_transform()`)
- This prevents data leakage from test set statistics into training
