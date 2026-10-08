"""
URL Feature Extractor — IERSS Tier 2 & 3 ML Pipeline
=====================================================
Extracts 24 numerical features from any URL string.

Features are purely syntactic/structural (no network calls) so they can be
computed instantly for both live inference and offline dataset training.
"""

import re
import math
from urllib.parse import urlparse, unquote
from typing import List, Tuple, Optional


# --------------------------------------------------------------------------- #
#  Shared constants (kept in sync with heuristic_detector.py)                  #
# --------------------------------------------------------------------------- #

_SUSPICIOUS_TLDS = [
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top',
    '.bid', '.win', '.ru', '.cn', '.onion', '.tk',
]

# Brand keywords that should never appear in a non-brand domain
_BRAND_KEYWORDS = [
    'paypal', 'amazon', 'microsoft', 'apple', 'google', 'icloud',
    'netflix', 'steam', 'discord', 'facebook', 'whatsapp', 'instagram',
    'dropbox', 'adobe', 'bank', 'wallet', 'blockchain', 'coinbase',
    'binance', 'chase', 'wellsfargo', 'citibank', 'ebay', 'alibaba',
    'chatgpt', 'openai', 'anthropic', 'linkedin', 'youtube', 'tiktok',
]

_OFFICIAL_BRAND_DOMAINS = [
    'paypal.com', 'amazon.com', 'microsoft.com', 'apple.com', 'google.com',
    'gmail.com', 'icloud.com', 'netflix.com', 'steampowered.com',
    'discord.com', 'facebook.com', 'fb.com', 'whatsapp.com',
    'instagram.com', 'dropbox.com', 'adobe.com', 'coinbase.com',
    'binance.com', 'chase.com', 'wellsfargo.com', 'citibank.com',
    'ebay.com', 'alibaba.com', 'openai.com', 'anthropic.com',
    'linkedin.com', 'youtube.com', 'tiktok.com', 'github.com',
]

_EXECUTABLE_EXTENSIONS = [
    '.exe', '.msi', '.bat', '.scr', '.vbs', '.ps1', '.bin',
    '.sh', '.apk', '.jar', '.elf', '.arm', '.mips', '.x86',
]

_SUSPICIOUS_PATTERNS = [
    (r'admin', 30),
    (r'phpmyadmin', 60),
    (r'\.git', 70),
    (r'\.env', 75),
    (r'wp-admin', 35),
    (r'\.sql', 65),
    (r'debug', 45),
    (r'verify|secure|update|account|billing', 40),
    (r'webscr|cgi-bin', 45),
    (r'hacked|defaced|pwned', 85),
    (r'upload.*\.php', 75),
    (r'malware|phish|trojan|botnet|exploit', 80),
    (r'@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', 85),
    (r'cutt\.ly|bit\.ly|tinyurl\.com|ow\.ly', 65),
    (r'blob\.core\.windows\.net', 80),
    (r'pastebin\.com/raw', 80),
    (r'drive\.google\.com/uc\?export=download', 85),
]

# Pre-compile patterns
_COMPILED_PATTERNS = [
    (re.compile(p, re.IGNORECASE), score)
    for p, score in _SUSPICIOUS_PATTERNS
]

_IP_REGEX = re.compile(
    r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
)


# --------------------------------------------------------------------------- #
#  Helper functions                                                             #
# --------------------------------------------------------------------------- #

def _shannon_entropy(text: str) -> float:
    """Shannon entropy of a string."""
    if not text:
        return 0.0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    n = len(text)
    return -sum((count / n) * math.log2(count / n) for count in freq.values())


def _is_ip_address(host: str) -> bool:
    m = _IP_REGEX.match(host)
    if not m:
        return False
    return all(0 <= int(g) <= 255 for g in m.groups())


def _get_tld_risk(domain: str) -> float:
    """Return a numeric TLD risk score (0–20)."""
    domain_lower = domain.lower()
    for tld in _SUSPICIOUS_TLDS:
        if domain_lower.endswith(tld):
            if tld in ('.tk', '.ml', '.ga', '.cf', '.gq'):
                return 15.0
            if tld in ('.xyz', '.top', '.bid', '.win'):
                return 10.0
            if tld in ('.ru', '.cn'):
                return 5.0
    return 0.0


def _count_brand_keywords(url: str, domain: str) -> int:
    """Count brand keywords in the URL that are NOT in their official domain."""
    url_lower = url.lower()
    domain_lower = domain.lower()
    # Skip if it's an official brand domain
    for official in _OFFICIAL_BRAND_DOMAINS:
        if domain_lower == official or domain_lower.endswith('.' + official):
            return 0
    count = 0
    for kw in _BRAND_KEYWORDS:
        if kw in url_lower:
            count += 1
    return count


def _suspicious_pattern_score(url: str) -> float:
    """Sum of risk scores for all suspicious patterns that fired."""
    total = 0.0
    for compiled_re, score in _COMPILED_PATTERNS:
        if compiled_re.search(url):
            total += score
    return min(total, 100.0)


# --------------------------------------------------------------------------- #
#  Main extractor                                                               #
# --------------------------------------------------------------------------- #

class URLFeatureExtractor:
    """
    Extracts 24 numerical features from a URL string.

    All features are:
    - Derived from the URL string alone (no network calls)
    - Normalised to float
    - On a consistent scale usable across training and live inference

    Returns a list of 24 floats.
    """

    # Ordered feature names (must match extract() return order)
    FEATURE_NAMES: List[str] = [
        "url_length",               # 0
        "domain_length",            # 1
        "path_length",              # 2
        "num_dots",                 # 3
        "num_subdomains",           # 4
        "num_hyphens",              # 5
        "num_digits",               # 6
        "digit_ratio",              # 7
        "num_special_chars",        # 8
        "has_ip_in_url",            # 9
        "has_at_symbol",            # 10
        "has_double_slash_in_path", # 11
        "path_depth",               # 12
        "query_param_count",        # 13
        "url_entropy",              # 14
        "domain_entropy",           # 15
        "is_https",                 # 16
        "tld_risk_score",           # 17
        "brand_keyword_count",      # 18
        "suspicious_pattern_score", # 19
        "has_hex_encoding",         # 20
        "has_executable_extension", # 21
        "typosquat_score",          # 22
        "heuristic_tier1_count",    # 23
    ]

    N_FEATURES: int = 24

    def extract(
        self,
        url: str,
        typosquat_score: float = 0.0,
        heuristic_tier1_count: int = 0,
    ) -> List[float]:
        """
        Extract 24 features from *url*.

        Optional parameters carry information from the heuristic engine when
        available:
        - typosquat_score: score from _detect_typosquatting() (0 if no match)
        - heuristic_tier1_count: number of T1 signals that fired
        """
        if not url:
            return [0.0] * self.N_FEATURES

        # Decode percent-encoding
        url = unquote(url.strip())

        # Ensure scheme is present for urlparse
        if '://' not in url:
            full_url = 'http://' + url
        else:
            full_url = url

        try:
            parsed = urlparse(full_url)
            scheme   = parsed.scheme.lower()
            host     = (parsed.hostname or '').lower()
            path     = parsed.path or ''
            query    = parsed.query or ''
        except Exception:
            scheme = 'http'
            host = url.split('/')[0].lower()
            path = ''
            query = ''

        # --- Feature computation ---

        # 0. url_length
        url_length = float(len(url))

        # 1. domain_length
        domain_length = float(len(host))

        # 2. path_length
        path_length = float(len(path))

        # 3. num_dots (in full URL)
        num_dots = float(url.count('.'))

        # 4. num_subdomains (dots in host minus 1, min 0)
        num_subdomains = float(max(host.count('.') - 1, 0))

        # 5. num_hyphens (in domain/host only)
        num_hyphens = float(host.count('-'))

        # 6. num_digits (total in URL)
        num_digits = float(sum(c.isdigit() for c in url))

        # 7. digit_ratio
        digit_ratio = num_digits / max(url_length, 1)

        # 8. num_special_chars (@, %, =, ?, &, #, !, $, ~)
        special = set('@%=?&#!$~')
        num_special_chars = float(sum(c in special for c in url))

        # 9. has_ip_in_url
        has_ip_in_url = 1.0 if _is_ip_address(host) else 0.0

        # 10. has_at_symbol (obfuscation indicator)
        has_at_symbol = 1.0 if '@' in url else 0.0

        # 11. has_double_slash_in_path (redirect trick)
        has_double_slash = 1.0 if '//' in path else 0.0

        # 12. path_depth
        path_depth = float(len([s for s in path.split('/') if s]))

        # 13. query_param_count
        query_param_count = float(
            len([p for p in query.split('&') if p]) if query else 0
        )

        # 14. url_entropy
        url_entropy = _shannon_entropy(url)

        # 15. domain_entropy
        domain_entropy = _shannon_entropy(host)

        # 16. is_https
        is_https = 1.0 if scheme == 'https' else 0.0

        # 17. tld_risk_score
        tld_risk_score = _get_tld_risk(host)

        # 18. brand_keyword_count (non-official domain only)
        brand_keyword_count = float(_count_brand_keywords(url, host))

        # 19. suspicious_pattern_score (capped at 100)
        suspicious_pattern_score = _suspicious_pattern_score(url)

        # 20. has_hex_encoding (%xx patterns)
        has_hex_encoding = 1.0 if re.search(r'%[0-9a-fA-F]{2}', url) else 0.0

        # 21. has_executable_extension
        path_lower = path.lower()
        has_exec_ext = 1.0 if any(path_lower.endswith(ext) for ext in _EXECUTABLE_EXTENSIONS) else 0.0

        # 22. typosquat_score (passed in from heuristic engine)
        ts_score = float(typosquat_score)

        # 23. heuristic_tier1_count (passed in from heuristic engine)
        t1_count = float(heuristic_tier1_count)

        return [
            url_length,             # 0
            domain_length,          # 1
            path_length,            # 2
            num_dots,               # 3
            num_subdomains,         # 4
            num_hyphens,            # 5
            num_digits,             # 6
            digit_ratio,            # 7
            num_special_chars,      # 8
            has_ip_in_url,          # 9
            has_at_symbol,          # 10
            has_double_slash,       # 11
            path_depth,             # 12
            query_param_count,      # 13
            url_entropy,            # 14
            domain_entropy,         # 15
            is_https,               # 16
            tld_risk_score,         # 17
            brand_keyword_count,    # 18
            suspicious_pattern_score,# 19
            has_hex_encoding,       # 20
            has_exec_ext,           # 21
            ts_score,               # 22
            t1_count,               # 23
        ]

    def extract_batch(
        self,
        urls: List[str],
        typosquat_scores: Optional[List[float]] = None,
        tier1_counts: Optional[List[int]] = None,
    ):
        """Extract features for a list of URLs. Returns numpy array (N×24)."""
        import numpy as np
        n = len(urls)
        ts_scores = typosquat_scores if typosquat_scores is not None else [0.0] * n
        t1_counts  = tier1_counts    if tier1_counts    is not None else [0] * n
        return np.array([
            self.extract(url, ts, t1)
            for url, ts, t1 in zip(urls, ts_scores, t1_counts)
        ], dtype=np.float32)


# Module-level singleton
_extractor: Optional[URLFeatureExtractor] = None

def get_extractor() -> URLFeatureExtractor:
    global _extractor
    if _extractor is None:
        _extractor = URLFeatureExtractor()
    return _extractor
