# IERSS Machine Learning Architecture & Critical Audit Report

**Date:** 01 May 2026 | **System:** Internet Exposure & Risk Scoring System v2.4.1

This document provides a comprehensive audit of how the IERSS system learns, classifies, and makes decisions. It covers every ML component, identifies critical gaps, and provides actionable improvement recommendations.

---

## 1. Architecture Overview — How the Machine Thinks

The IERSS system uses a **three-tier intelligence architecture**:

| Tier | Type | Engine | Status |
|------|------|--------|--------|
| Tier 1 (Primary) | Rule-Based Heuristic | `heuristic_detector.py` | ✅ ACTIVE & LIVE |
| Tier 2 (Supervised ML) | Classification Models | `ml_models/supervised/` | ⚠️ BUILT, NOT CONNECTED |
| Tier 3 (Unsupervised ML) | Anomaly Detection | `ml_models/unsupervised/` | ⚠️ BUILT, NOT CONNECTED |

> **🔴 CRITICAL FINDING:** The Streamlit dashboard and the live scanning engine (`app.py`) currently use ONLY Tier 1 (the Heuristic Detector). Tiers 2 and 3 are fully coded, architecturally sound, but are **not wired into the live inference pipeline**. The system does not learn from past scans. It relies entirely on hard-coded pattern matching and API lookups.

---

## 2. Tier 1 — Heuristic Rule Engine (Currently Active)

### How It Works
The `HeuristicRiskDetector` class in `risk_scoring/heuristic_detector.py` (1,490+ lines) is the sole engine powering all live assessments. It does NOT use machine learning. It uses:

- **Pattern Matching:** 50+ compiled regex patterns (`SUSPICIOUS_URL_PATTERNS`) that detect typosquatting, phishing keywords, brand impersonation, and malicious payloads.
- **Known Vulnerability Database:** A hard-coded dictionary (`KNOWN_VULNERABLE_DOMAINS`) of domains with assigned risk scores.
- **TLD Risk Scoring:** Suspicious top-level domains (e.g., `.xyz`, `.top`, `.buzz`) trigger automatic risk elevation.
- **Infrastructure Complexity Scoring:** Known complex platforms (Amazon, Shopify, PayPal, etc.) receive complexity penalties.
- **API Enrichment:** Google Safe Browsing and VirusTotal APIs are queried for external reputation data.
- **Active Reachability:** The engine now physically visits the target URL, extracts the live HTML `<title>` tag, and flags unreachable domains as CRITICAL.

### Strengths
- Zero latency — no model loading or inference delay.
- Fully deterministic — the same URL always produces the same score.
- Human-auditable — every rule is readable Python code.

### Weaknesses
- 🔴 **Does not learn.** If a new phishing technique emerges that does not match any existing regex, it will pass through undetected.
- 🔴 **High false-positive rate on legacy infrastructure** (educational and government websites) because missing security headers trigger the same patterns as phishing sites.
- Hard-coded thresholds require manual tuning by a developer.

---

## 3. Tier 2 — Supervised Learning (Built, Not Connected)

### What Exists
Three fully implemented classification models live in `ml_models/supervised/`:

| Model | File | Algorithm | Output |
|-------|------|-----------|--------|
| Logistic Regression | `logistic_regression_model.py` | sklearn LogisticRegression (L-BFGS solver) | 4-class severity (LOW, MEDIUM, HIGH, CRITICAL) |
| Random Forest | `random_forest_model.py` | sklearn RandomForestClassifier (100 trees, depth 10) | 4-class severity + feature importances |
| Neural Network | `neural_network_model.py` | TensorFlow/Keras Sequential (128→64→32 Dense + BatchNorm + Dropout) | 4-class softmax probabilities |

### How They Are Supposed to Learn (Supervised)
Supervised learning means the model is given **labeled examples** (URL + correct answer) and learns the mapping between features and severity labels.

1. **Feature Extraction:** The `FeatureAssembler` converts raw asset data into a 49-dimensional numeric vector. Features include: port risk, CVSS score, breach severity, open port count, TLD type, country risk, Shodan/Censys/NVD intel signals, and optionally 384-dim sentence-transformer text embeddings.
2. **Label Assignment:** The `DatasetBuilder.generate_severity_label()` method assigns a ground-truth severity (0=LOW, 1=MEDIUM, 2=HIGH, 3=CRITICAL) based on CVSS score, breach count, and exposure type.
3. **Training:** `train_models.py` orchestrates a full training run: build dataset → stratified 60/20/20 split → train all models → evaluate on test set → save best model.

> **Current Training Data Source:** The system uses a `create_synthetic_dataset()` method that generates 5,000 stochastic fake samples with controlled class distributions. There is also a `load_user_samples()` method that can ingest a CSV file (`data/user_samples.csv`) of real labeled URLs.

### Neural Network Architecture (Detailed)

```
Input Layer:  49 features (or 49 + 3×384 = 1,201 with embeddings)
     │
Dense(128, ReLU) + BatchNorm + Dropout(0.3)
     │
Dense(64, ReLU)  + BatchNorm + Dropout(0.3)
     │
Dense(32, ReLU)  + BatchNorm + Dropout(0.3)
     │
Dense(4, Softmax)  →  [P(LOW), P(MEDIUM), P(HIGH), P(CRITICAL)]
```

- **Optimizer:** Adam (lr=0.001)
- **Loss:** Sparse Categorical Cross-Entropy
- **Callbacks:** EarlyStopping (patience=10), ReduceLROnPlateau (factor=0.5, patience=5)
- **Total Parameters:** ~15,000 (without embeddings)

> **🔴 CRITICAL ISSUE:** The neural network depends on `tensorflow`, which is **incompatible with Python 3.13+**. The training script (`train_models.py`, line 118) explicitly skips the neural network: *"Neural Network training skipped (TensorFlow incompatible with Python 3.14)"*. This means the neural network has **never been trained or validated** on this system.

---

## 4. Tier 3 — Unsupervised Learning (Built, Not Connected)

### What Exists
Two anomaly detection models in `ml_models/unsupervised/`:

| Model | File | Algorithm | How It Works |
|-------|------|-----------|--------------|
| Isolation Forest | `isolation_forest_detector.py` | sklearn IsolationForest (100 trees, 256 max samples) | Isolates anomalies by random partitioning. Points that are easy to isolate = anomalous. |
| Autoencoder | `autoencoder_detector.py` | sklearn MLPRegressor (32→16→32 bottleneck) | Learns to reconstruct "normal" data. High reconstruction error = anomaly. |

### How They Are Supposed to Learn (Unsupervised)
Unsupervised learning means the model is given data **without labels** and must discover patterns on its own.

1. **Isolation Forest:** Trained on the full feature matrix. It builds random decision trees. Normal data points require many splits to isolate; anomalies require few splits. The `contamination` parameter (default 10%) tells the model what fraction of data to consider anomalous.
2. **Autoencoder:** Trained to reconstruct its own input through a bottleneck layer (49 → 32 → 16 → 32 → 49). Normal data reconstructs well; anomalous data has high reconstruction error. The threshold is set at the (1 - contamination) percentile of training errors.
3. **Ensemble:** The `AnomalyScorer` combines both models with weighted voting (60% Isolation Forest, 40% Autoencoder) to produce a final anomaly score.

> **Important:** The autoencoder here is NOT a deep learning autoencoder (TensorFlow/PyTorch). It is implemented as an `sklearn.neural_network.MLPRegressor` — a shallow feedforward network. This is a practical decision to avoid the TensorFlow dependency, but it limits representational capacity.

---

## 5. Graph-Based Risk Propagation

A separate intelligence layer exists in `graph_analysis/` that uses **NetworkX** to build knowledge graphs of infrastructure relationships:

- **Nodes:** IPs, Domains, Services, Credentials, ASNs, Email Domains.
- **Edges:** `resolves_to`, `hosts_service`, `belongs_to_asn`, `associated_with_email_domain`.
- **Risk Propagation:** A PageRank-like iterative algorithm (`RiskPropagator`) that spreads risk from known-bad nodes to their neighbors with a decay factor of 0.8. It converges when the maximum score change drops below 0.001.

This is conceptually powerful but, like the ML models, is **not connected to the live pipeline**.

---

## 6. Critical Improvements Required

### 6.1 🔴 CRITICAL: Wire ML Models into Live Inference

> **The #1 Priority.** Right now, the system is a glorified regex engine with API lookups. The ML models exist but produce zero value because they are never called during a live scan. The fix:
> - After the heuristic scan completes, pass the same URL through the Isolation Forest and Autoencoder.
> - Use the ML anomaly score as a **modifier** on the heuristic score (e.g., if the heuristic says LOW but the ML says HIGH anomaly, escalate to MEDIUM).
> - This creates a hybrid scoring system that catches threats the regex patterns miss.

### 6.2 🔴 CRITICAL: Replace TensorFlow Neural Network with PyTorch

> The neural network model is dead code. TensorFlow does not support Python 3.13+. Options:
> - **Option A (Recommended):** Rewrite `neural_network_model.py` using `torch.nn` (PyTorch is already in `requirements.txt`).
> - **Option B:** Keep the sklearn MLPClassifier as a lightweight drop-in replacement (already proven working in the autoencoder).

### 6.3 ⚠️ HIGH: Implement Online Learning / Feedback Loop

> The system has a "Report Incorrect Assessment" feedback form in the Streamlit UI. But this feedback is **never used to retrain the models**. The fix:
> - Every user-submitted correction should be saved as a labeled training example (`URL` + `correct_severity`).
> - Implement a periodic retraining script that incorporates these corrections into the supervised training set.
> - This creates a genuine **learning loop** where the machine improves over time.

### 6.4 ⚠️ HIGH: Replace Synthetic Training Data with Real Phishing Datasets

> Both training pipelines currently use randomly generated synthetic data. This means the models have never seen a real phishing URL. The fix:
> - Integrate the **PhishTank** or **OpenPhish** public datasets (50,000+ verified phishing URLs with labels).
> - Combine with the **Alexa Top 1M** or **Tranco List** for verified benign URLs.
> - Train on this real-world data to achieve production-grade accuracy.

### 6.5 ⚠️ HIGH: Feature Engineering Gap

> The `FeatureAssembler` extracts 49 features from structured asset data (ports, CVSS, breaches). But it does NOT extract features from the raw URL string itself (URL length, number of dots, entropy, presence of IP in URL, etc.). These URL-level features are the most predictive for phishing detection and are currently only handled by regex in the heuristic engine. The fix:
> - Add a `URLFeatureExtractor` that computes: URL length, subdomain count, path depth, query parameter count, character entropy, digit ratio, special character ratio, TLD category, and Levenshtein distance to known brands.
> - Feed these into the supervised models.

### 6.6 MODERATE: Confidence Calibration

The `ModelEvaluator` has an Expected Calibration Error (ECE) calculator but it is never used in production. Calibrated confidence scores would allow the UI to display trustworthy probability statements ("87% confident this is phishing") instead of arbitrary 0-1 floats.

### 6.7 MODERATE: Graph Analysis Integration

The graph-based risk propagation system could dramatically improve accuracy for coordinated attacks (e.g., 50 phishing domains all hosted on the same ASN). Currently unused.

---

## 7. Summary Scorecard

| Component | Maturity | Connected to Live System? | Production Ready? |
|-----------|----------|--------------------------|-------------------|
| Heuristic Detector | ✅ High | ✅ YES | ✅ YES |
| Google Safe Browsing API | ✅ High | ✅ YES | ✅ YES |
| VirusTotal API | ✅ High | ✅ YES | ✅ YES |
| Active Title Extraction | ✅ High | ✅ YES | ✅ YES |
| Logistic Regression | ⚠️ Medium | 🔴 NO | ⚠️ Needs real data |
| Random Forest | ⚠️ Medium | 🔴 NO | ⚠️ Needs real data |
| Neural Network (TF) | 🔴 Dead Code | 🔴 NO | 🔴 TF incompatible |
| Isolation Forest | ⚠️ Medium | 🔴 NO | ⚠️ Needs real data |
| Autoencoder | ⚠️ Medium | 🔴 NO | ⚠️ Needs real data |
| Anomaly Scorer (Ensemble) | ✅ High | 🔴 NO | ⚠️ Needs integration |
| Feature Assembler (49-dim) | ✅ High | 🔴 NO | ⚠️ Missing URL features |
| Graph Risk Propagation | ✅ High | 🔴 NO | ⚠️ Needs DB |
| PDF Reporting Engine | ✅ High | ✅ YES | ✅ YES |
| Feedback Loop / Retraining | 🔴 Not Built | 🔴 NO | 🔴 Not Built |

---

## 8. Recommended Roadmap

1. **Phase 1 (Immediate):** Rewrite the Neural Network from TensorFlow to PyTorch. Wire the Isolation Forest + Autoencoder into `get_complete_analysis()` as a secondary scoring signal.
2. **Phase 2 (1-2 weeks):** Replace synthetic training data with PhishTank + Tranco real-world datasets. Retrain all models. Validate with confusion matrix and ROC-AUC.
3. **Phase 3 (2-4 weeks):** Build the feedback learning loop. Every user correction becomes a training sample. Implement scheduled weekly retraining.
4. **Phase 4 (Production):** Package with SQLite + PyInstaller. Deploy as a standalone commercial application with license key activation.

---

*This document was generated from a complete source code audit of all 40+ Python modules in the IERSS codebase.*
