"""
Dataset Builder — IERSS ML Real-World Training Data
====================================================
Downloads PhishTank (phishing) + Tranco Top-1M (benign) datasets,
extracts 24 URL features, and produces a labelled numpy dataset
ready for supervised + unsupervised training.

Labels
------
Binary:   0 = BENIGN, 1 = MALICIOUS
Severity: 0=LOW, 1=MEDIUM, 2=HIGH, 3=CRITICAL  (derived from heuristic thresholds)
"""

import os
import csv
import time
import logging
import zipfile
import hashlib
import requests
import numpy as np
from pathlib import Path
from typing import Tuple, List, Optional

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
#  Paths & constants                                                            #
# --------------------------------------------------------------------------- #

_ROOT = Path(__file__).parent.parent
_DATA_DIR = _ROOT / "ml_models" / "datasets"
_DATA_DIR.mkdir(parents=True, exist_ok=True)

PHISHTANK_CSV   = _DATA_DIR / "phishtank_online_valid.csv"
TRANCO_CSV      = _DATA_DIR / "tranco_top1m.csv"
DATASET_NPZ     = _DATA_DIR / "real_world_dataset.npz"

# PhishTank: free, no key needed (may be rate-limited occasionally)
PHISHTANK_URL = (
    "https://data.phishtank.com/data/online-valid.csv"
)
# Tranco Top 1M (stable mirror)
TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"

# How many benign domains to sample (cap to keep training balanced)
MAX_BENIGN = 15_000
MAX_PHISH  = 15_000

# Severity label boundaries (mirrors heuristic thresholds)
_SEV_CRITICAL  = 75.0
_SEV_HIGH      = 50.0
_SEV_MEDIUM    = 30.0

from ml_models.url_feature_extractor import URLFeatureExtractor
_extractor = URLFeatureExtractor()


# --------------------------------------------------------------------------- #
#  Download helpers                                                             #
# --------------------------------------------------------------------------- #

def _download_file(url: str, dest: Path, description: str, timeout: int = 60) -> bool:
    """Download *url* to *dest* with progress. Returns True on success."""
    logger.info(f"Downloading {description} from {url} ...")
    try:
        resp = requests.get(url, timeout=timeout, stream=True)
        resp.raise_for_status()
        total = int(resp.headers.get('content-length', 0))
        downloaded = 0
        with open(dest, 'wb') as f:
            for chunk in resp.iter_content(chunk_size=65536):
                if chunk:
                    f.write(chunk)
                    downloaded += len(chunk)
        logger.info(f"  Saved {downloaded/1024:.1f} KB -> {dest.name}")
        return True
    except Exception as exc:
        logger.warning(f"  Download failed: {exc}")
        return False


def _maybe_download_phishtank(force: bool = False) -> bool:
    """Download PhishTank CSV if not cached. Returns True if available."""
    if PHISHTANK_CSV.exists() and not force:
        age_hours = (time.time() - PHISHTANK_CSV.stat().st_mtime) / 3600
        if age_hours < 48:
            logger.info(f"PhishTank cache is {age_hours:.1f}h old — skipping download.")
            return True
    return _download_file(PHISHTANK_URL, PHISHTANK_CSV, "PhishTank phishing URLs")


def _maybe_download_tranco(force: bool = False) -> bool:
    """Download and extract Tranco Top-1M CSV if not cached."""
    if TRANCO_CSV.exists() and not force:
        age_hours = (time.time() - TRANCO_CSV.stat().st_mtime) / 3600
        if age_hours < 168:   # refresh weekly
            logger.info(f"Tranco cache is {age_hours:.1f}h old — skipping download.")
            return True

    zip_path = _DATA_DIR / "tranco_top1m.zip"
    ok = _download_file(TRANCO_URL, zip_path, "Tranco Top-1M")
    if not ok:
        return False
    try:
        with zipfile.ZipFile(zip_path, 'r') as z:
            # The zip contains top-1m.csv
            names = z.namelist()
            csv_name = next((n for n in names if n.endswith('.csv')), names[0])
            with z.open(csv_name) as src, open(TRANCO_CSV, 'wb') as dst:
                dst.write(src.read())
        logger.info(f"Extracted Tranco CSV -> {TRANCO_CSV.name}")
        return True
    except Exception as exc:
        logger.warning(f"Tranco extraction failed: {exc}")
        return False


# --------------------------------------------------------------------------- #
#  Parsers                                                                      #
# --------------------------------------------------------------------------- #

def _load_phishtank_urls(limit: int = MAX_PHISH) -> List[str]:
    """Return list of phishing URL strings from PhishTank CSV."""
    if not PHISHTANK_CSV.exists():
        logger.warning("PhishTank CSV not found — skipping.")
        return []
    urls = []
    try:
        with open(PHISHTANK_CSV, encoding='utf-8', errors='replace', newline='') as f:
            reader = csv.DictReader(f)
            for row in reader:
                url = (row.get('url') or row.get('URL') or '').strip()
                if url and url.startswith('http'):
                    urls.append(url)
                if len(urls) >= limit:
                    break
    except Exception as exc:
        logger.warning(f"PhishTank CSV parse error: {exc}")
    logger.info(f"Loaded {len(urls)} phishing URLs from PhishTank.")
    return urls


def _load_tranco_domains(limit: int = MAX_BENIGN) -> List[str]:
    """Return list of HTTPS URLs built from Tranco top-1M benign domains, enlivened with realistic structures."""
    if not TRANCO_CSV.exists():
        logger.warning("Tranco CSV not found — skipping.")
        return []
    
    # Pre-defined templates for realistic path, query, and subdomain synthesis
    paths = [
        "", "", "", "", "",  # 50% chance of raw domain
        "/about", "/contact", "/news", "/blog", "/terms", "/privacy", "/help",
        "/products/list", "/kb/article/102", "/en-us/windows", "/search/query",
        "/main/dashboard", "/assets/main.js", "/index.php"
    ]
    subdomains = [
        "www", "www", "www",  # 60% standard www
        "blog", "support", "news", "mail", "dev", "docs", "app", "status"
    ]
    queries = [
        "", "", "", "", "", "", "", "",  # 80% no query
        "?q=test", "?id=42", "?page=2", "?lang=en", "?utm_source=feed"
    ]

    import random

    domains = []
    try:
        with open(TRANCO_CSV, encoding='utf-8', errors='replace', newline='') as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) >= 2:
                    domain = row[1].strip()
                elif len(row) == 1:
                    domain = row[0].strip()
                else:
                    continue
                if domain:
                    # Use deterministic random seeding by domain to keep dataset generation reproducible
                    rand = random.Random(domain)
                    
                    # 15% chance to enlivened with realistic path/subdomain/query structures,
                    # keeping 85% as standard raw domains to preserve natural distribution spacing.
                    if rand.random() < 0.15:
                        sub = rand.choice(subdomains)
                        path = rand.choice(paths)
                        query = rand.choice(queries)
                        
                        full_url = f"https://{domain}"
                        if sub != "www":
                            full_url = f"https://{sub}.{domain}"
                        if path:
                            full_url += path
                        if query:
                            full_url += query
                    else:
                        full_url = f"https://{domain}"
                        
                    domains.append(full_url)
                if len(domains) >= limit:
                    break
    except Exception as exc:
        logger.warning(f"Tranco CSV parse error: {exc}")
    logger.info(f"Loaded {len(domains)} enriched benign domains from Tranco.")
    return domains


# --------------------------------------------------------------------------- #
#  Label functions                                                               #
# --------------------------------------------------------------------------- #

def _binary_label(is_phish: bool) -> int:
    """0=BENIGN, 1=MALICIOUS"""
    return 1 if is_phish else 0


def _severity_label_from_features(features: List[float], is_phish: bool) -> int:
    """
    Assign 4-class severity (0=LOW, 1=MEDIUM, 2=HIGH, 3=CRITICAL)
    from feature vector + ground-truth label.

    Design goals:
    - Benign URLs → LOW (0) or MEDIUM (1) based on suspicious signals
    - Phishing URLs → HIGH (2) or CRITICAL (3) based on indicator strength
    - All 4 classes must be represented in training data
    """
    susp_score = features[19]  # suspicious_pattern_score
    ts_score   = features[22]  # typosquat_score
    brand_kw   = features[18]  # brand_keyword_count
    exec_ext   = features[21]  # has_executable_extension
    has_ip     = features[9]   # has_ip_in_url
    tld_risk   = features[17]  # tld_risk_score
    entropy    = features[14]  # url_entropy

    if not is_phish:
        # Benign URLs: LOW by default, MEDIUM if suspicious signals present
        if susp_score >= 40 or ts_score >= 50 or tld_risk >= 10:
            return 1   # MEDIUM (suspicious benign)
        return 0       # LOW

    # Phishing URLs: HIGH by default, CRITICAL for strongest signals
    # CRITICAL: executable downloads, high typosquat, IP-based, or very high pattern score
    is_critical = (
        exec_ext > 0.5               # executable file linked
        or ts_score >= 70.0          # confirmed brand squatting
        or has_ip > 0.5              # IP-based URL (never legitimate)
        or susp_score >= 80.0        # multiple high-weight patterns
        or (brand_kw >= 2 and tld_risk >= 10)  # brand + risky TLD combo
    )
    if is_critical:
        return 3   # CRITICAL

    # HIGH: confirmed phishing but moderate signal strength
    # (all remaining phishing URLs — ensures HIGH is well-populated)
    return 2   # HIGH


# --------------------------------------------------------------------------- #
#  Main builder                                                                  #
# --------------------------------------------------------------------------- #

def build_dataset(
    force_download: bool = False,
    max_phish: int = MAX_PHISH,
    max_benign: int = MAX_BENIGN,
    verbose: bool = True,
) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    """
    Download (if needed) and build the real-world dataset.

    Returns
    -------
    X : np.ndarray, shape (N, 24)   — feature matrix
    y_binary : np.ndarray, shape (N,) — binary labels (0=benign, 1=malicious)
    y_severity : np.ndarray, shape (N,) — 4-class severity (0–3)
    """
    if verbose:
        print("[DatasetBuilder] Fetching datasets ...")

    # --- Download ---
    phish_ok  = _maybe_download_phishtank(force=force_download)
    tranco_ok = _maybe_download_tranco(force=force_download)

    phish_urls  = _load_phishtank_urls(limit=max_phish)  if phish_ok  else []
    benign_urls = _load_tranco_domains(limit=max_benign) if tranco_ok else []

    # --- Deduplicate and filter out domain overlaps to prevent label confusion ---
    from urllib.parse import urlparse
    def _get_domain(u: str) -> str:
        try:
            return urlparse(u).netloc.lower()
        except:
            return ""

    phish_domains = {_get_domain(u) for u in phish_urls if u}
    filtered_benign = []
    overlap_count = 0
    for u in benign_urls:
        dom = _get_domain(u)
        if dom in phish_domains:
            overlap_count += 1
            continue
        filtered_benign.append(u)
    
    if verbose and overlap_count > 0:
        print(f"[DatasetBuilder] Excluded {overlap_count} benign URLs due to domain overlap with PhishTank (redirectors/shorteners)")
    benign_urls = filtered_benign

    # --- Fallback synthetic data if both downloads fail ---
    if not phish_urls and not benign_urls:
        if verbose:
            print("[DatasetBuilder] Both downloads failed — using synthetic fallback.")
        return _synthetic_fallback()

    if not phish_urls:
        if verbose:
            print("[DatasetBuilder] PhishTank unavailable — using partial benign-only mode.")
        phish_urls = _make_synthetic_phish(1000)

    if not benign_urls:
        if verbose:
            print("[DatasetBuilder] Tranco unavailable — using synthetic benign fallback.")
        benign_urls = _make_synthetic_benign(1000)

    # --- Balance classes ---
    min_size = min(len(phish_urls), len(benign_urls))
    np.random.seed(42)
    phish_idx  = np.random.choice(len(phish_urls),  min_size, replace=False)
    benign_idx = np.random.choice(len(benign_urls), min_size, replace=False)
    phish_sample  = [phish_urls[i]  for i in phish_idx]
    benign_sample = [benign_urls[i] for i in benign_idx]

    if verbose:
        print(f"[DatasetBuilder] Balanced: {min_size} phishing + {min_size} benign URLs")

    # --- Extract features ---
    all_urls    = phish_sample  + benign_sample
    all_labels  = [1] * min_size + [0] * min_size   # binary

    if verbose:
        print(f"[DatasetBuilder] Extracting {len(all_urls)} feature vectors ...")

    X_list = []
    y_sev_list = []
    for i, (url, lbl) in enumerate(zip(all_urls, all_labels)):
        feats = _extractor.extract(url)
        X_list.append(feats)
        y_sev_list.append(_severity_label_from_features(feats, bool(lbl)))
        if verbose and (i + 1) % 5000 == 0:
            print(f"  ... {i+1}/{len(all_urls)} processed")

    X          = np.array(X_list,    dtype=np.float32)
    y_binary   = np.array(all_labels, dtype=np.int32)
    y_severity = np.array(y_sev_list, dtype=np.int32)

    # Shuffle together
    perm = np.random.permutation(len(X))
    X, y_binary, y_severity = X[perm], y_binary[perm], y_severity[perm]

    # --- Cache to disk ---
    np.savez_compressed(
        DATASET_NPZ,
        X=X, y_binary=y_binary, y_severity=y_severity,
        feature_names=URLFeatureExtractor.FEATURE_NAMES,
    )
    if verbose:
        print(f"[DatasetBuilder] Dataset saved -> {DATASET_NPZ.name}")
        print(f"  Shape: X={X.shape}, y_binary dist: {dict(zip(*np.unique(y_binary, return_counts=True)))}")
        print(f"  Severity dist: {dict(zip(*np.unique(y_severity, return_counts=True)))}")

    return X, y_binary, y_severity


def load_cached_dataset() -> Optional[Tuple[np.ndarray, np.ndarray, np.ndarray]]:
    """Load previously built dataset from disk cache. Returns None if missing."""
    if not DATASET_NPZ.exists():
        return None
    data = np.load(DATASET_NPZ, allow_pickle=True)
    return data['X'], data['y_binary'], data['y_severity']


# --------------------------------------------------------------------------- #
#  Fallback synthetic generators                                               #
# --------------------------------------------------------------------------- #

def _make_synthetic_phish(n: int) -> List[str]:
    """Generate synthetic phishing-like URLs."""
    templates = [
        "http://paypal.com.secure-login.{tld}/verify/account",
        "http://amazon-{rand}.{tld}/cart/checkout",
        "http://microsoft-update.{tld}/login",
        "http://{rand}{rand}.tk/phish/exec.exe",
        "http://g00gle.{tld}/safe/verify",
        "http://{rand}-bank.xyz/account-secure",
        "http://192.168.{n}.{n}/admin/panel",
        "http://apple-icloud-verify.{tld}/update",
    ]
    tlds = ['xyz', 'tk', 'ml', 'top', 'bid', 'win', 'ga', 'cf']
    rng = np.random.default_rng(1)
    urls = []
    while len(urls) < n:
        t = templates[rng.integers(len(templates))]
        tld = tlds[rng.integers(len(tlds))]
        rand = ''.join(chr(rng.integers(97, 123)) for _ in range(rng.integers(4, 10)))
        num = rng.integers(1, 254)
        url = t.replace('{tld}', tld).replace('{rand}', rand).replace('{n}', str(num))
        urls.append(url)
    return urls


def _make_synthetic_benign(n: int) -> List[str]:
    """Generate synthetic benign-like URLs."""
    domains = [
        'google.com', 'github.com', 'wikipedia.org', 'amazon.com',
        'stackoverflow.com', 'reddit.com', 'linkedin.com', 'twitter.com',
        'bbc.co.uk', 'nytimes.com', 'microsoft.com', 'apple.com',
    ]
    paths = ['/', '/about', '/help', '/docs', '/news', '/products', '/blog']
    rng = np.random.default_rng(2)
    urls = []
    while len(urls) < n:
        domain = domains[rng.integers(len(domains))]
        path   = paths[rng.integers(len(paths))]
        urls.append(f"https://{domain}{path}")
    return urls


def _synthetic_fallback() -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Fallback: generate a balanced 2,000-sample synthetic dataset."""
    phish  = _make_synthetic_phish(1000)
    benign = _make_synthetic_benign(1000)
    all_urls = phish + benign
    labels   = [1] * 1000 + [0] * 1000
    X_list, sev_list = [], []
    for url, lbl in zip(all_urls, labels):
        feats = _extractor.extract(url)
        X_list.append(feats)
        sev_list.append(_severity_label_from_features(feats, bool(lbl)))
    X = np.array(X_list, dtype=np.float32)
    y_b = np.array(labels, dtype=np.int32)
    y_s = np.array(sev_list, dtype=np.int32)
    perm = np.random.permutation(len(X))
    return X[perm], y_b[perm], y_s[perm]


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    X, yb, ys = build_dataset(verbose=True)
    print(f"Done. X={X.shape}, binary={yb.shape}, severity={ys.shape}")
