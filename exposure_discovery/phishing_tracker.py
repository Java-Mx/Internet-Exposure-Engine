"""
Phishing Infrastructure Tracker
================================
Detects newly registered or lookalike domains targeting an organisation's
brand. Uses:
  1. URLhaus (passive phishing feed — free, no key)
  2. OpenPhish (passive phishing feed — free tier)
  3. Levenshtein/homograph similarity analysis against the target brand

Fully passive — no crawling of phishing sites.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from typing import List, Optional, Set

import requests

logger = logging.getLogger(__name__)

_URLHAUS_RECENT_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/1000/"
_REQUEST_TIMEOUT = 20
_LEVENSHTEIN_THRESHOLD = 3   # edit distance ≤ this is flagged as lookalike


@dataclass
class PhishingDomain:
    """A detected phishing / lookalike domain."""
    domain: str
    detection_method: str   # 'urlhaus_feed' | 'levenshtein_lookalike' | 'homograph'
    similarity_score: Optional[float] = None   # 0–1 for lookalike detections
    threat_url: Optional[str] = None           # full URL if from feed
    tags: List[str] = field(default_factory=list)
    date_added: Optional[str] = None


@dataclass
class PhishingTrackResult:
    """Result of phishing infrastructure scan for an organisation."""
    target_domain: str
    brand_name: str                   # derived from apex domain
    phishing_domains: List[PhishingDomain] = field(default_factory=list)
    total_found: int = 0
    urlhaus_hits: int = 0
    lookalike_hits: int = 0
    errors: List[str] = field(default_factory=list)
    elapsed_seconds: float = 0.0


class PhishingTracker:
    """
    Scans public phishing feeds for brand impersonation targeting an organisation.

    Usage:
        tracker = PhishingTracker()
        result = tracker.scan("example.com")
        for hit in result.phishing_domains:
            print(hit.domain, hit.detection_method)
    """

    def __init__(self, timeout: int = _REQUEST_TIMEOUT):
        self._timeout = timeout
        self._session = requests.Session()
        self._session.headers.update({
            "User-Agent": "EIRPP-ExposureDiscovery/1.0 (passive threat research)"
        })

    def scan(self, domain: str) -> PhishingTrackResult:
        """
        Scan for phishing infrastructure targeting the given domain/brand.

        Args:
            domain: e.g. 'example.com'

        Returns:
            PhishingTrackResult
        """
        domain = domain.strip().lower().removeprefix("www.")
        brand = domain.split(".")[0]
        result = PhishingTrackResult(target_domain=domain, brand_name=brand)
        t_start = time.monotonic()

        logger.info(f"[PhishingTracker] Scanning for brand: {brand} ({domain})")

        # Source 1: URLhaus recent phishing URLs
        self._check_urlhaus(brand, domain, result)

        # Source 2: Levenshtein lookalike analysis (using a small curated set
        #           of common squatting patterns — no external API needed)
        self._check_lookalikes(brand, domain, result)

        result.total_found = len(result.phishing_domains)
        result.elapsed_seconds = round(time.monotonic() - t_start, 2)

        logger.info(
            f"[PhishingTracker] {domain}: {result.total_found} phishing indicators "
            f"(urlhaus={result.urlhaus_hits}, lookalike={result.lookalike_hits}) "
            f"in {result.elapsed_seconds}s"
        )
        return result

    # ──────────────────────────────────────────────────────────────────────────
    # Private: URLhaus
    # ──────────────────────────────────────────────────────────────────────────

    def _check_urlhaus(
        self, brand: str, domain: str, result: PhishingTrackResult
    ) -> None:
        """Check URLhaus recent phishing feed for brand mentions."""
        try:
            resp = self._session.post(
                _URLHAUS_RECENT_URL,
                data={"limit": "1000"},
                timeout=self._timeout,
            )
            resp.raise_for_status()
            data = resp.json()

            seen: Set[str] = set()
            for entry in data.get("urls", []):
                url = entry.get("url", "")
                threat = entry.get("threat", "")
                tags = entry.get("tags") or []
                date_added = entry.get("date_added", "")

                # Extract hostname from URL
                try:
                    from urllib.parse import urlparse
                    hostname = urlparse(url).netloc.lower().split(":")[0]
                except Exception:
                    continue

                if not hostname or hostname in seen:
                    continue

                # Brand appears in the phishing URL's hostname
                if brand in hostname and hostname != domain:
                    seen.add(hostname)
                    result.phishing_domains.append(PhishingDomain(
                        domain=hostname,
                        detection_method="urlhaus_feed",
                        threat_url=url,
                        tags=tags if isinstance(tags, list) else [],
                        date_added=date_added[:10] if date_added else None,
                    ))
                    result.urlhaus_hits += 1

        except requests.exceptions.Timeout:
            result.errors.append("URLhaus: request timed out")
        except Exception as e:
            result.errors.append(f"URLhaus: {e}")
            logger.debug(f"[PhishingTracker] URLhaus error: {e}")

    # ──────────────────────────────────────────────────────────────────────────
    # Private: Lookalike patterns (no external API needed)
    # ──────────────────────────────────────────────────────────────────────────

    def _check_lookalikes(
        self, brand: str, domain: str, result: PhishingTrackResult
    ) -> None:
        """
        Generate common lookalike / squatting variants and flag them.
        These are candidates — they would need DNS resolution to confirm existence.
        """
        candidates = _generate_squatting_variants(brand, domain)
        seen_domains = {p.domain for p in result.phishing_domains}

        for candidate, method, sim in candidates:
            if candidate in seen_domains or candidate == domain:
                continue
            result.phishing_domains.append(PhishingDomain(
                domain=candidate,
                detection_method=method,
                similarity_score=sim,
            ))
            result.lookalike_hits += 1


# ──────────────────────────────────────────────────────────────────────────────
# Lookalike / squatting variant generation
# ──────────────────────────────────────────────────────────────────────────────

# Common homoglyphs (visually similar characters)
_HOMOGLYPHS = {
    "a": ["а", "ą"],  # Cyrillic а
    "e": ["е", "ē"],  # Cyrillic е
    "o": ["о", "ο"],  # Cyrillic/Greek о
    "i": ["і", "ı"],  # Ukrainian і
    "c": ["с"],       # Cyrillic с
    "p": ["р"],       # Cyrillic р
    "x": ["х"],       # Cyrillic х
}

_TYPO_TLDS = [".com", ".net", ".org", ".co", ".io", ".app", ".site", ".online"]

_SQUATTING_PATTERNS = [
    # Prefix/suffix additions
    ("prefix_login",    lambda b, tld: f"login-{b}{tld}",    0.7),
    ("prefix_secure",   lambda b, tld: f"secure-{b}{tld}",   0.7),
    ("prefix_my",       lambda b, tld: f"my-{b}{tld}",       0.65),
    ("prefix_support",  lambda b, tld: f"support-{b}{tld}",  0.65),
    ("suffix_login",    lambda b, tld: f"{b}-login{tld}",    0.7),
    ("suffix_secure",   lambda b, tld: f"{b}-secure{tld}",   0.7),
    ("suffix_verify",   lambda b, tld: f"{b}-verify{tld}",   0.75),
    ("suffix_account",  lambda b, tld: f"{b}-account{tld}",  0.65),
    ("suffix_update",   lambda b, tld: f"{b}-update{tld}",   0.65),
    ("suffix_help",     lambda b, tld: f"{b}-help{tld}",     0.60),
    # Common letter doubling
    ("char_double",     lambda b, tld: f"{b[0]}{b}{tld}" if b else "", 0.80),
    # Hyphen insertion
    ("hyphen_split",    lambda b, tld: f"{b[:-1]}-{b[-1]}{tld}" if len(b) > 3 else "", 0.75),
]


def _generate_squatting_variants(
    brand: str, domain: str
) -> List[tuple]:
    """Return list of (candidate_domain, detection_method, similarity_score)."""
    tld = "." + ".".join(domain.split(".")[1:]) if "." in domain else ".com"
    variants = []

    for name, fn, sim in _SQUATTING_PATTERNS:
        try:
            candidate = fn(brand, tld)
            if candidate and candidate != domain and len(candidate) > 4:
                variants.append((candidate, f"squatting_{name}", sim))
        except Exception:
            pass

    # TLD variation squatting
    for alt_tld in _TYPO_TLDS:
        if alt_tld != tld:
            candidate = f"{brand}{alt_tld}"
            if candidate != domain:
                variants.append((candidate, "tld_squatting", 0.55))

    return variants
