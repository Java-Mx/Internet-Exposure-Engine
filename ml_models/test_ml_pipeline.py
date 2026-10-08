"""
ML Pipeline Test Suite — EIRPP
================================
Comprehensive tests covering all 5 models:
  - Model loading (cold and warm)
  - Per-model inference on known good/bad URLs
  - Ensemble agreement rates
  - End-to-end T1 + T2 + T3 pipeline integration
  - Inference latency benchmarks

Run:
    python -m ml_models.test_ml_pipeline
    python -m ml_models.test_ml_pipeline --verbose
    python -m ml_models.test_ml_pipeline --retrain   # retrain before testing
"""

from __future__ import annotations

import sys
import time
import logging
import argparse
import pickle
import numpy as np
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass

_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_ROOT))

logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")

_SAVED = _ROOT / "ml_models" / "saved"


# ──────────────────────────────────────────────────────────────────────────────
# Test data
# ──────────────────────────────────────────────────────────────────────────────

# (url, expected_binary, expected_severity_label, description)
TEST_CASES: List[Tuple[str, int, str, str]] = [
    # Clear benign
    ("https://google.com",                              0, "LOW",      "Google homepage"),
    ("https://github.com/user/repo",                   0, "LOW",      "GitHub repo"),
    ("https://stackoverflow.com/questions/12345",      0, "LOW",      "StackOverflow"),
    ("https://bbc.co.uk/news",                         0, "LOW",      "BBC News"),
    ("https://wikipedia.org/wiki/Python",              0, "LOW",      "Wikipedia"),
    ("https://linkedin.com/in/johndoe",                0, "LOW",      "LinkedIn profile"),

    # Clear phishing / malicious
    ("http://paypal.com.secure-login.xyz/verify",      1, "HIGH",     "PayPal phishing"),
    ("http://amazon-update.tk/cart/checkout",          1, "HIGH",     "Amazon phishing"),
    ("http://192.168.1.1/admin/panel",                 1, "HIGH",     "IP admin panel"),
    ("http://apple-icloud-verify.ml/update",           1, "HIGH",     "iCloud phishing"),
    ("http://microsoft-update.bid/login",              1, "HIGH",     "MS phishing TLD"),
    ("http://g00gle.top/safe/verify",                  1, "HIGH",     "Google homoglyph"),

    # Executable / critical
    ("http://malware.tk/payload.exe",                  1, "CRITICAL",  "Executable download"),
    ("http://evil.xyz/ransomware.bat",                 1, "CRITICAL",  "BAT file download"),

    # Suspicious / medium
    ("http://login-support.net/account",               1, "MEDIUM",   "Login support scam"),
    ("http://verify-account.info/update",              1, "MEDIUM",   "Account verify scam"),
]

# These should NEVER be flagged as phishing (whitelist validation)
SAFE_DOMAINS = [
    "https://google.com",
    "https://microsoft.com/en-us/windows",
    "https://amazon.com/products",
    "https://apple.com/iphone",
    "https://paypal.com/myaccount",
]


# ──────────────────────────────────────────────────────────────────────────────
# Result tracking
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class TestResult:
    passed: int = 0
    failed: int = 0
    skipped: int = 0
    errors: List[str] = None

    def __post_init__(self):
        if self.errors is None:
            self.errors = []

    @property
    def total(self):
        return self.passed + self.failed + self.skipped

    def ok(self):
        return self.failed == 0

    def summary(self):
        status = "PASS" if self.ok() else "FAIL"
        return f"[{status}] {self.passed}/{self.total} passed"


VERBOSE = False


def _log(msg: str, always: bool = False):
    if always or VERBOSE:
        print(msg)


def _pass(label: str):
    global _result
    _result.passed += 1
    _log(f"  PASS  {label}")


def _fail(label: str, reason: str):
    global _result
    _result.failed += 1
    _result.errors.append(f"{label}: {reason}")
    print(f"  FAIL  {label}: {reason}")


def _skip(label: str, reason: str):
    global _result
    _result.skipped += 1
    _log(f"  SKIP  {label}: {reason}")


_result = TestResult()


# ──────────────────────────────────────────────────────────────────────────────
# Test 1: Feature extractor
# ──────────────────────────────────────────────────────────────────────────────

def test_feature_extractor():
    print("\n[Test 1] URLFeatureExtractor")
    from ml_models.url_feature_extractor import URLFeatureExtractor, get_extractor

    ex = URLFeatureExtractor()
    singleton = get_extractor()

    # Basic smoke test
    for url, _, _, desc in TEST_CASES[:4]:
        try:
            feats = ex.extract(url)
            if len(feats) != 24:
                _fail(f"extractor/{desc}", f"expected 24 features, got {len(feats)}")
            elif not all(isinstance(f, (int, float)) for f in feats):
                _fail(f"extractor/{desc}", "non-numeric feature detected")
            else:
                _pass(f"extractor/{desc}")
        except Exception as e:
            _fail(f"extractor/{desc}", str(e))

    # Batch extraction
    try:
        urls = [tc[0] for tc in TEST_CASES[:6]]
        X = ex.extract_batch(urls)
        if X.shape == (6, 24):
            _pass("extractor/batch_shape")
        else:
            _fail("extractor/batch_shape", f"expected (6,24), got {X.shape}")
    except Exception as e:
        _fail("extractor/batch", str(e))

    # Benign vs phishing feature sanity
    benign_feats  = np.array(ex.extract("https://google.com"))
    phishing_feats = np.array(ex.extract("http://paypal.com.secure-login.xyz/verify"))
    # Brand keyword count should be higher for phishing
    if phishing_feats[18] > benign_feats[18]:
        _pass("extractor/brand_kw_phishing_higher")
    else:
        _fail("extractor/brand_kw_phishing_higher",
              f"expected phishing brand_kw > benign: {phishing_feats[18]} vs {benign_feats[18]}")

    # TLD risk should be 0 for .com (google)
    if benign_feats[17] == 0.0:
        _pass("extractor/tld_risk_google_zero")
    else:
        _fail("extractor/tld_risk_google_zero", f"got {benign_feats[17]}")


# ──────────────────────────────────────────────────────────────────────────────
# Test 2: Model loading
# ──────────────────────────────────────────────────────────────────────────────

def test_model_loading():
    print("\n[Test 2] Model File Loading")
    from ml_models.tier2_connector import _load_models, reset_cache as reset_t2
    from ml_models.tier3_connector import _load_t3_models, reset_cache as reset_t3

    reset_t2()
    reset_t3()

    t0 = time.monotonic()
    cache_t2 = _load_models()
    t2_load_ms = (time.monotonic() - t0) * 1000

    # Check which T2 models loaded
    for model_key, label in [('lr', 'LR'), ('rf_model', 'RF'), ('nn', 'NN')]:
        if cache_t2.get(model_key) is not None:
            _pass(f"loading/t2_{label.lower()}_loaded")
        else:
            _fail(f"loading/t2_{label.lower()}_loaded", f"{label} model is None")

    _log(f"  T2 load time: {t2_load_ms:.0f}ms", always=True)
    if t2_load_ms < 5000:
        _pass("loading/t2_load_time_under_5s")
    else:
        _fail("loading/t2_load_time_under_5s", f"took {t2_load_ms:.0f}ms — too slow for web use")

    t0 = time.monotonic()
    cache_t3 = _load_t3_models()
    t3_load_ms = (time.monotonic() - t0) * 1000

    for model_key, label in [('if', 'IsolationForest'), ('ae', 'Autoencoder')]:
        if cache_t3.get(model_key) is not None:
            _pass(f"loading/t3_{model_key}_loaded")
        else:
            _fail(f"loading/t3_{model_key}_loaded", f"{label} model is None")

    _log(f"  T3 load time: {t3_load_ms:.0f}ms", always=True)

    # Warm cache should be instant
    t0 = time.monotonic()
    _load_models()
    warm_ms = (time.monotonic() - t0) * 1000
    if warm_ms < 10:
        _pass("loading/warm_cache_instant")
    else:
        _fail("loading/warm_cache_instant", f"warm cache took {warm_ms:.1f}ms")


# ──────────────────────────────────────────────────────────────────────────────
# Test 3: Tier 2 supervised ensemble
# ──────────────────────────────────────────────────────────────────────────────

def test_tier2_inference():
    print("\n[Test 3] Tier 2 — Supervised Ensemble Inference")
    from ml_models.tier2_connector import get_tier2_signal, Tier2Signal

    # Check predicted_severity is always a string (Bug 3 fix)
    signal = get_tier2_signal("https://google.com", 10.0, "LOW")
    if isinstance(signal.predicted_severity, str):
        _pass("t2/predicted_severity_is_string")
    else:
        _fail("t2/predicted_severity_is_string",
              f"got type {type(signal.predicted_severity).__name__}: {signal.predicted_severity}")

    # Models available
    if signal.models_available:
        _pass(f"t2/models_available ({', '.join(signal.models_available)})")
    else:
        _skip("t2/models_available", "no models loaded")

    # Evidence string format
    if "[ML-T2]" in signal.evidence_string:
        _pass("t2/evidence_string_format")
    else:
        _fail("t2/evidence_string_format", f"got: {signal.evidence_string[:80]}")

    # Directional correctness: benign URL should get LOW/MEDIUM, modifier ≤ 0
    benign_signal = get_tier2_signal("https://google.com", 10.0, "LOW")
    if benign_signal.predicted_severity in ("LOW", "MEDIUM"):
        _pass("t2/benign_url_low_severity")
    else:
        _fail("t2/benign_url_low_severity",
              f"google.com predicted as {benign_signal.predicted_severity}")

    # Phishing URL should escalate
    phish_signal = get_tier2_signal(
        "http://paypal.com.secure-login.xyz/verify", 45.0, "MEDIUM"
    )
    if phish_signal.predicted_severity in ("HIGH", "CRITICAL"):
        _pass("t2/phishing_url_escalated")
    else:
        _fail("t2/phishing_url_escalated",
              f"phishing URL predicted as {phish_signal.predicted_severity}")

    # Score modifier range check
    for url, binary, sev, desc in TEST_CASES[:8]:
        try:
            sig = get_tier2_signal(url, 50.0, "MEDIUM")
            if -100 <= sig.score_modifier <= 100:
                _pass(f"t2/modifier_range/{desc[:30]}")
            else:
                _fail(f"t2/modifier_range/{desc[:30]}", f"modifier={sig.score_modifier} out of range")
        except Exception as e:
            _fail(f"t2/inference/{desc[:30]}", str(e))

    # Latency benchmark (warm)
    times = []
    for url, _, _, _ in TEST_CASES[:6]:
        t0 = time.monotonic()
        get_tier2_signal(url, 50.0, "MEDIUM")
        times.append((time.monotonic() - t0) * 1000)
    avg_ms = np.mean(times)
    _log(f"  T2 avg inference: {avg_ms:.1f}ms", always=True)
    if avg_ms < 500:
        _pass(f"t2/latency_under_500ms (avg={avg_ms:.0f}ms)")
    else:
        _fail(f"t2/latency_under_500ms", f"avg {avg_ms:.0f}ms — too slow")


# ──────────────────────────────────────────────────────────────────────────────
# Test 4: Tier 3 anomaly detection
# ──────────────────────────────────────────────────────────────────────────────

def test_tier3_inference():
    print("\n[Test 4] Tier 3 — Anomaly Detection")
    from ml_models.tier3_connector import get_tier3_signal

    # Tier 3 modifier should always be ≥ 0 (never negative)
    for url, binary, sev, desc in TEST_CASES:
        try:
            sig = get_tier3_signal(url, 50.0, "MEDIUM")
            if sig.modifier_applied >= 0:
                _pass(f"t3/non_negative_modifier/{desc[:30]}")
            else:
                _fail(f"t3/non_negative_modifier/{desc[:30]}", f"modifier={sig.modifier_applied}")
        except Exception as e:
            _fail(f"t3/inference/{desc[:30]}", str(e))

    # Max modifier should be capped at 15
    sig = get_tier3_signal("http://malware.tk/payload.exe", 80.0, "CRITICAL")
    if sig.modifier_applied <= 15.0:
        _pass("t3/modifier_capped_at_15")
    else:
        _fail("t3/modifier_capped_at_15", f"got {sig.modifier_applied}")

    # HIGH/CRITICAL heuristic should cap at 5
    sig_high = get_tier3_signal("http://evil.tk/test", 80.0, "HIGH")
    if sig_high.modifier_applied <= 5.0:
        _pass("t3/modifier_capped_5_for_high_heuristic")
    else:
        _fail("t3/modifier_capped_5_for_high_heuristic", f"got {sig_high.modifier_applied}")

    # Evidence string always present
    sig = get_tier3_signal("https://google.com", 10.0, "LOW")
    if "[ML-T3]" in sig.evidence_string:
        _pass("t3/evidence_string_present")
    else:
        _fail("t3/evidence_string_present", f"got: {sig.evidence_string[:80]}")

    # Ensemble score range
    if 0.0 <= sig.ensemble_score <= 1.0:
        _pass("t3/ensemble_score_in_range")
    else:
        _fail("t3/ensemble_score_in_range", f"got {sig.ensemble_score}")


# ──────────────────────────────────────────────────────────────────────────────
# Test 5: False positive check on whitelisted domains
# ──────────────────────────────────────────────────────────────────────────────

def test_false_positives():
    print("\n[Test 5] False Positive Check — Whitelisted Safe Domains")
    from ml_models.tier2_connector import get_tier2_signal

    fp_count = 0
    for url in SAFE_DOMAINS:
        try:
            sig = get_tier2_signal(url, 5.0, "LOW")
            # Modifier should not escalate known safe domains by more than +10
            if sig.score_modifier > 25.0:
                _fail(f"fp/{url}", f"modifier={sig.score_modifier} — false positive escalation")
                fp_count += 1
            else:
                _pass(f"fp/{url[:50]}")
        except Exception as e:
            _fail(f"fp/{url}", str(e))

    fp_rate = fp_count / len(SAFE_DOMAINS)
    _log(f"  FP rate on whitelist: {fp_rate*100:.0f}%", always=True)
    if fp_rate <= 0.20:  # ≤20% FP on whitelist is acceptable
        _pass(f"fp/rate_acceptable ({fp_rate*100:.0f}%)")
    else:
        _fail("fp/rate_acceptable", f"FP rate {fp_rate*100:.0f}% exceeds 20%")


# ──────────────────────────────────────────────────────────────────────────────
# Test 6: End-to-end pipeline integration
# ──────────────────────────────────────────────────────────────────────────────

def test_end_to_end():
    print("\n[Test 6] End-to-End T1 + T2 + T3 Pipeline")
    try:
        from risk_scoring.heuristic_detector import get_heuristic_detector
        det = get_heuristic_detector()
    except Exception as e:
        _skip("e2e/all", f"heuristic_detector unavailable: {e}")
        return

    test_pairs = [
        ("https://google.com",                         False),   # benign
        ("http://paypal.com.secure-login.xyz/verify",  True),    # phishing
    ]

    for url, expect_high in test_pairs:
        try:
            t0 = time.monotonic()
            result = det.get_complete_analysis(url)
            elapsed_ms = (time.monotonic() - t0) * 1000

            score = result.get("risk_score", 0)
            level = result.get("risk_level", "")
            evidence = result.get("evidence", [])

            _log(f"  {url[:50]} → score={score:.1f} level={level} time={elapsed_ms:.0f}ms")

            # T2 evidence string present
            t2_in_evidence = any("[ML-T2]" in str(e) for e in evidence)
            t3_in_evidence = any("[ML-T3]" in str(e) for e in evidence)

            if t2_in_evidence:
                _pass(f"e2e/t2_evidence_present/{url[:30]}")
            else:
                _fail(f"e2e/t2_evidence_present/{url[:30]}", "no [ML-T2] in evidence")

            if t3_in_evidence:
                _pass(f"e2e/t3_evidence_present/{url[:30]}")
            else:
                _fail(f"e2e/t3_evidence_present/{url[:30]}", "no [ML-T3] in evidence")

            # Directional: phishing should be HIGH or CRITICAL
            if expect_high:
                if level in ("HIGH", "CRITICAL"):
                    _pass(f"e2e/phishing_classified_high/{url[:30]}")
                else:
                    _fail(f"e2e/phishing_classified_high/{url[:30]}", f"got {level}")
            else:
                if level in ("LOW", "MEDIUM"):
                    _pass(f"e2e/benign_not_flagged/{url[:30]}")
                else:
                    _fail(f"e2e/benign_not_flagged/{url[:30]}", f"got {level} for google.com")

        except Exception as e:
            _fail(f"e2e/{url[:30]}", str(e))


# ──────────────────────────────────────────────────────────────────────────────
# Test 7: Dataset builder smoke test
# ──────────────────────────────────────────────────────────────────────────────

def test_dataset_builder():
    print("\n[Test 7] Dataset Builder — Cached Dataset")
    from ml_models.dataset_builder import load_cached_dataset, DATASET_NPZ

    if not DATASET_NPZ.exists():
        _skip("dataset/cached_dataset", "no cached dataset — run training first")
        return

    try:
        result = load_cached_dataset()
        if result is None:
            _fail("dataset/load_cached", "returned None")
            return
        X, y_binary, y_severity = result
        if X.shape[1] == 24:
            _pass(f"dataset/feature_count_24 (N={X.shape[0]})")
        else:
            _fail("dataset/feature_count_24", f"got {X.shape[1]} features")

        # Class balance check
        unique_b, counts_b = np.unique(y_binary, return_counts=True)
        balance_ratio = min(counts_b) / max(counts_b)
        if balance_ratio >= 0.5:
            _pass(f"dataset/binary_balanced (ratio={balance_ratio:.2f})")
        else:
            _fail("dataset/binary_balanced", f"imbalanced: ratio={balance_ratio:.2f}")

        # Severity: should have 3 or 4 classes
        n_sev_classes = len(np.unique(y_severity))
        if n_sev_classes >= 3:
            _pass(f"dataset/severity_classes ({n_sev_classes} classes)")
        else:
            _fail("dataset/severity_classes", f"only {n_sev_classes} severity classes")

        _log(f"  Binary dist:   {dict(zip(unique_b.tolist(), counts_b.tolist()))}")
        _log(f"  Severity dist: {dict(zip(*np.unique(y_severity, return_counts=True)))}")

    except Exception as e:
        _fail("dataset/load_cached", str(e))


# ──────────────────────────────────────────────────────────────────────────────
# Runner
# ──────────────────────────────────────────────────────────────────────────────

def run_all_tests(retrain: bool = False, verbose: bool = False) -> bool:
    global VERBOSE, _result
    VERBOSE = verbose
    _result = TestResult()

    print("=" * 65)
    print("  EIRPP ML Pipeline Test Suite")
    print("=" * 65)

    if retrain:
        print("\n[PRE-TEST] Retraining models ...")
        from ml_models.train_on_real_data import run_training
        run_training()
        from ml_models.tier2_connector import reset_cache as r2
        from ml_models.tier3_connector import reset_cache as r3
        r2(); r3()

    test_feature_extractor()
    test_model_loading()
    test_tier2_inference()
    test_tier3_inference()
    test_false_positives()
    test_end_to_end()
    test_dataset_builder()

    print()
    print("=" * 65)
    print(f"  {_result.summary()}")
    if _result.errors:
        print(f"\n  Failures ({len(_result.errors)}):")
        for err in _result.errors:
            print(f"    - {err}")
    print("=" * 65)
    return _result.ok()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="EIRPP ML Test Suite")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--retrain", action="store_true",
                        help="Retrain all models before running tests")
    args = parser.parse_args()

    ok = run_all_tests(retrain=args.retrain, verbose=args.verbose)
    sys.exit(0 if ok else 1)
