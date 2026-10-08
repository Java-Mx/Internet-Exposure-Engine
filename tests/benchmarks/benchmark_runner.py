"""
Real Dataset Benchmark Runner
==============================
Suite 3 -- Precision, Recall, F1, FPR against real-world datasets.

Strategy:
  - Phase A (offline): URL feature-only scoring (no external API calls)
    Test against URLhaus samples + Tranco benign samples
    Target: P≥0.80, R≥0.75, F1≥0.77, FPR≤0.15

  - Phase B (optional API): Same URLs with real VirusTotal/GSB enrichment
    Run only if VIRUSTOTAL_API_KEY is set in .env
    Target: P≥0.88, R≥0.85, F1≥0.86

Datasets:
  URLhaus recent:    https://urlhaus.abuse.ch/downloads/text_recent/
  Tranco top-1M:    https://tranco-list.eu/ (samples first 500 for speed)
  OpenPhish:        https://openphish.com/feed.txt

Run:
    python tests/benchmarks/benchmark_runner.py
    python tests/benchmarks/benchmark_runner.py --limit 50   # fast mode
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))


# -- Thresholds ----------------------------------------------------------------

THRESHOLDS = {
    "precision":          0.80,
    "recall":             0.75,
    "f1":                 0.77,
    "fpr":                0.15,  # max acceptable false positive rate
    "mean_conf_tp":       0.55,  # min mean confidence on true positives
    "mean_conf_fp":       0.65,  # max mean confidence on false positives
}


@dataclass
class BenchmarkSample:
    url: str
    true_label: int   # 1 = malicious, 0 = benign
    source: str


@dataclass
class PredictionResult:
    url: str
    true_label: int
    predicted_label: int
    score: float
    confidence: float
    evidence_count: int
    elapsed_ms: float


@dataclass
class BenchmarkReport:
    dataset_name: str
    total_samples: int
    tp: int = 0
    tn: int = 0
    fp: int = 0
    fn: int = 0
    total_elapsed_ms: float = 0.0
    errors: int = 0
    confidence_tp: List[float] = field(default_factory=list)
    confidence_fp: List[float] = field(default_factory=list)

    @property
    def precision(self) -> float:
        return self.tp / max(self.tp + self.fp, 1)

    @property
    def recall(self) -> float:
        return self.tp / max(self.tp + self.fn, 1)

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2*p*r / max(p+r, 1e-9)

    @property
    def fpr(self) -> float:
        return self.fp / max(self.fp + self.tn, 1)

    @property
    def accuracy(self) -> float:
        return (self.tp + self.tn) / max(self.total_samples, 1)

    @property
    def mean_conf_tp(self) -> float:
        return sum(self.confidence_tp) / max(len(self.confidence_tp), 1)

    @property
    def mean_conf_fp(self) -> float:
        return sum(self.confidence_fp) / max(len(self.confidence_fp), 1)

    @property
    def throughput_per_sec(self) -> float:
        return self.total_samples / max(self.total_elapsed_ms / 1000, 0.001)


# -- Dataset loaders -----------------------------------------------------------

def load_urlhaus_samples(limit: int = 100) -> List[BenchmarkSample]:
    """
    Download URLhaus recent malicious URLs.
    Falls back to a hard-coded seed set if download fails.
    """
    import requests
    samples = []
    try:
        resp = requests.get(
            "https://urlhaus.abuse.ch/downloads/text_recent/",
            timeout=15,
            headers={"User-Agent": "AERIS-Benchmark/2.0 (research)"},
        )
        if resp.status_code == 200:
            lines = resp.text.strip().split("\n")
            for line in lines:
                line = line.strip()
                if line and not line.startswith("#") and line.startswith("http"):
                    samples.append(BenchmarkSample(url=line, true_label=1, source="urlhaus"))
                    if len(samples) >= limit:
                        break
            print(f"  URLhaus: loaded {len(samples)} malicious samples")
    except Exception as e:
        print(f"  URLhaus download failed ({e}), using seed set")

    if not samples:
        # Hard-coded seed set for offline testing
        seed_malicious = [
            "http://testsafebrowsing.appspot.com/s/malware.html",
            "http://malware.wicar.org/data/ms10_090_ie_ss7.html",
            "http://testphp.vulnweb.com/login.php",
            "http://dvwa.co.uk/",
            "http://paypal-secure-login.tk/verify",
            "http://microsoft-update-center.ml/account",
            "http://secure-paypal.ml/login.php",
            "http://apple-id-verify.cf/signin",
            "http://juice-shop.herokuapp.com/",
            "http://faceb00k-login.com/account",
        ]
        samples = [BenchmarkSample(url=u, true_label=1, source="seed_malicious")
                   for u in seed_malicious[:limit]]
        print(f"  Seed malicious set: {len(samples)} samples")
    return samples


def load_tranco_samples(limit: int = 100) -> List[BenchmarkSample]:
    """
    Load Tranco benign domain samples.
    Falls back to hard-coded reputable domains if download fails.
    """
    import requests
    import io
    import zipfile

    samples = []
    try:
        resp = requests.get(
            "https://tranco-list.eu/download/top-1m.csv.zip",
            timeout=20,
            headers={"User-Agent": "AERIS-Benchmark/2.0 (research)"},
            stream=True,
        )
        if resp.status_code == 200:
            zf = zipfile.ZipFile(io.BytesIO(resp.content))
            csv_name = zf.namelist()[0]
            with zf.open(csv_name) as f:
                lines = f.read().decode("utf-8").split("\n")
                for line in lines[1:]:   # skip header
                    parts = line.strip().split(",")
                    if len(parts) >= 2:
                        domain = parts[1].strip()
                        if domain and "." in domain:
                            samples.append(BenchmarkSample(
                                url=f"https://{domain}", true_label=0, source="tranco"
                            ))
                    if len(samples) >= limit:
                        break
            print(f"  Tranco: loaded {len(samples)} benign samples")
    except Exception as e:
        print(f"  Tranco download failed ({e}), using curated benign set")

    if not samples:
        benign_domains = [
            "https://google.com", "https://microsoft.com", "https://apple.com",
            "https://amazon.com", "https://github.com", "https://wikipedia.org",
            "https://stackoverflow.com", "https://python.org", "https://mozilla.org",
            "https://bbc.com", "https://reuters.com", "https://nasa.gov",
            "https://mit.edu", "https://linux.org", "https://ubuntu.com",
            "https://nodejs.org", "https://npmjs.com", "https://pypi.org",
            "https://docker.com", "https://kubernetes.io", "https://cloudflare.com",
            "https://letsencrypt.org", "https://archive.org", "https://eff.org",
            "https://nist.gov", "https://owasp.org", "https://cisa.gov",
        ]
        samples = [BenchmarkSample(url=u, true_label=0, source="curated_benign")
                   for u in benign_domains[:limit]]
        print(f"  Curated benign set: {len(samples)} samples")
    return samples


def load_openphish_samples(limit: int = 50) -> List[BenchmarkSample]:
    """Download OpenPhish feed for phishing URLs."""
    import requests
    samples = []
    try:
        resp = requests.get(
            "https://openphish.com/feed.txt",
            timeout=10,
            headers={"User-Agent": "AERIS-Benchmark/2.0"},
        )
        if resp.status_code == 200:
            for line in resp.text.strip().split("\n"):
                line = line.strip()
                if line.startswith("http"):
                    samples.append(BenchmarkSample(url=line, true_label=1, source="openphish"))
                    if len(samples) >= limit:
                        break
    except Exception as e:
        print(f"  OpenPhish download failed ({e})")
    return samples


# -- Scoring -------------------------------------------------------------------

def score_url(url: str) -> Tuple[float, float, int]:
    """Returns (risk_score, confidence_composite, evidence_count)."""
    try:
        from risk_scoring.heuristic_detector import HeuristicRiskDetector
        from risk_scoring.confidence_scorer import ConfidenceScorer

        det = HeuristicRiskDetector()
        score, evidence, severity = det.analyze_url(url)

        scorer = ConfidenceScorer()
        signals = {"heuristic": score / 100.0}
        if evidence:
            # Infer API signals from evidence strings
            for ev in evidence:
                ev_lower = ev.lower()
                if "virustotal" in ev_lower:     signals["virustotal"] = 0.8
                if "google safe browsing" in ev_lower: signals["gsb"] = 0.8
                if "urlhaus" in ev_lower:         signals["urlhaus"] = 0.9

        tc = scorer.calculate(signals)
        return float(score), tc.composite, len(evidence)
    except Exception as e:
        return 0.0, 0.0, 0


# -- Run benchmark -------------------------------------------------------------

def run_benchmark(samples: List[BenchmarkSample], threshold: float = 40.0) -> BenchmarkReport:
    """Run scoring pipeline against all samples, compute metrics."""
    dataset_name = samples[0].source if samples else "unknown"
    report = BenchmarkReport(dataset_name=dataset_name, total_samples=len(samples))

    for sample in samples:
        t0 = time.time()
        try:
            score, conf, ev_count = score_url(sample.url)
            elapsed = (time.time() - t0) * 1000
            predicted = 1 if score >= threshold else 0

            if sample.true_label == 1 and predicted == 1:
                report.tp += 1
                report.confidence_tp.append(conf)
            elif sample.true_label == 0 and predicted == 0:
                report.tn += 1
            elif sample.true_label == 0 and predicted == 1:
                report.fp += 1
                report.confidence_fp.append(conf)
            elif sample.true_label == 1 and predicted == 0:
                report.fn += 1

            report.total_elapsed_ms += elapsed
        except Exception:
            report.errors += 1

    return report


# -- Master benchmark runner ---------------------------------------------------

def run_benchmark_suite(limit: int = 50) -> Dict:
    print("\n" + "="*70)
    print("  SUITE 3 -- REAL DATASET BENCHMARKING")
    print("="*70)
    print(f"  Sample limit per dataset: {limit}")
    print(f"  Detection threshold: 40.0/100")

    malicious_samples = load_urlhaus_samples(limit)
    benign_samples    = load_tranco_samples(limit)
    phish_samples     = load_openphish_samples(min(limit // 2, 25))

    all_samples = malicious_samples + benign_samples + phish_samples

    print(f"\n  Scoring {len(all_samples)} URLs...")
    t_start = time.time()

    # Run combined benchmark
    report = run_benchmark(all_samples)
    report.dataset_name = "combined"
    report.total_samples = len(all_samples)

    total_time = time.time() - t_start

    # Per-dataset breakdown
    mal_report   = run_benchmark(malicious_samples, threshold=40.0)
    benign_report = run_benchmark(benign_samples, threshold=40.0)

    print(f"\n  {'-'*60}")
    print(f"  RESULTS (combined {len(all_samples)} URLs):")
    print(f"  Precision:          {report.precision:.3f}  (threshold: ≥{THRESHOLDS['precision']})")
    print(f"  Recall:             {report.recall:.3f}  (threshold: ≥{THRESHOLDS['recall']})")
    print(f"  F1 Score:           {report.f1:.3f}  (threshold: ≥{THRESHOLDS['f1']})")
    print(f"  False Positive Rate:{report.fpr:.3f}  (threshold: ≤{THRESHOLDS['fpr']})")
    print(f"  Accuracy:           {report.accuracy:.3f}")
    print(f"  Mean conf (TP):     {report.mean_conf_tp:.3f}")
    print(f"  Mean conf (FP):     {report.mean_conf_fp:.3f}")
    print(f"  Throughput:         {report.throughput_per_sec:.1f} URLs/sec")
    print(f"  Errors:             {report.errors}")

    print(f"\n  Malicious-only (URLhaus+seeds): P={mal_report.precision:.3f} R={mal_report.recall:.3f}")
    print(f"  Benign-only (Tranco/curated):   FPR={benign_report.fpr:.3f}")

    meets_precision = report.precision >= THRESHOLDS["precision"]
    meets_recall    = report.recall    >= THRESHOLDS["recall"]
    meets_f1        = report.f1        >= THRESHOLDS["f1"]
    meets_fpr       = report.fpr       <= THRESHOLDS["fpr"]
    all_pass        = meets_precision and meets_recall and meets_f1 and meets_fpr

    print(f"\n  Threshold checks:")
    print(f"    {'PASS' if meets_precision else 'FAIL'} Precision ≥ {THRESHOLDS['precision']}")
    print(f"    {'PASS' if meets_recall    else 'FAIL'} Recall    ≥ {THRESHOLDS['recall']}")
    print(f"    {'PASS' if meets_f1        else 'FAIL'} F1        ≥ {THRESHOLDS['f1']}")
    print(f"    {'PASS' if meets_fpr       else 'FAIL'} FPR       ≤ {THRESHOLDS['fpr']}")

    status = "PASS" if all_pass else "NEEDS_WORK"
    print(f"\n  BENCHMARK SUITE: {status}")
    print("="*70)

    return {
        "suite": "benchmarks",
        "total_samples": len(all_samples),
        "precision": round(report.precision, 4),
        "recall":    round(report.recall, 4),
        "f1":        round(report.f1, 4),
        "fpr":       round(report.fpr, 4),
        "accuracy":  round(report.accuracy, 4),
        "mean_confidence_tp": round(report.mean_conf_tp, 4),
        "mean_confidence_fp": round(report.mean_conf_fp, 4),
        "throughput_per_sec": round(report.throughput_per_sec, 2),
        "errors": report.errors,
        "status": status,
        "confusion_matrix": {"tp": report.tp, "tn": report.tn, "fp": report.fp, "fn": report.fn},
        "threshold_used": 40.0,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=50, help="URLs per dataset")
    args = parser.parse_args()
    run_benchmark_suite(limit=args.limit)
