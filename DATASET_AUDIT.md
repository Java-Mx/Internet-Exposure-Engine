# AERIS Dataset Integrity Audit Report

This report documents the dataset origin, class balance, duplicate analysis, and leakage/contamination checks performed on the reconstructed dataset splits.

---

## 1. Dataset Origin & Metadata

* **Malicious Source:** PhishTank (online verified phishing URLs)
* **Benign Source:** Tranco Top-1M (highly reputable benign domains)
* **Total Samples in Cached NPZ:** 29972
* **Balance:** Balanced 50% Benign / 50% Malicious
* **Feature Dimensions:** 24 features extracted per URL

---

## 2. Reconstructed Splits (60/20/20 Stratified)

| Split | Sample Count | Benign (Class 0) | Malicious (Class 1) | Target Ratio |
|---|---|---|---|---|
| **Training** | 17982 | 8991 | 8991 | 60% |
| **Validation** | 5995 | 2997 | 2998 | 20% |
| **Testing** | 5995 | 2998 | 2997 | 20% |
| **Total** | 29972 | 14986 | 14986 | 100% |

---

## 3. Duplicate Analysis

* **Deduplication Method:** Overlap of benign domains with malicious phish domains was removed during construction to prevent label confusion.
* **Duplicate URLs within Training Split:** 0
* **Duplicate URLs within Validation Split:** 0
* **Duplicate URLs within Testing Split:** 0

---

## 4. Leakage & Contamination Analysis

> [!IMPORTANT]
> A critical security boundary check is performed to guarantee that no training/validation data leaks into the test set.

* **Train / Test URL Overlap:** 0 domains/URLs
* **Val / Test URL Overlap:** 0 domains/URLs
* **Train / Val URL Overlap:** 0 domains/URLs
* **Feature Vector Train / Test Overlap:** 1076 identical feature rows (legitimate profile matches on independent domains)

* **Contamination Status:** ✅ CLEAN (Zero URL leakage between train/val and test splits)

---

## 5. Random Seed & Determinism Verification

* **Numpy seed:** `42`
* **Scikit-Learn stratified random state:** `42`
* **Split Alignment:** Re-running splits produces the exact same permutation and indices deterministically.
* **Audit Verdict:** PASS
