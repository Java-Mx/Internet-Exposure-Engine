"""
Adversarial Robustness Filter
==============================
Layer 1 Enhancement -- detects evasion techniques before the scoring pipeline.

Detects:
  - Unicode confusable character substitution (e.g. 'paypal.com' using Cyrillic 'a')
  - IDN homoglyph domains (xn-- Punycode encoded lookalikes)
  - Partial legitimacy masking (known brand name embedded in suspicious structure)
  - Structural evasion patterns (excessive hyphens, deep subdomains, IP-like patterns)

Output: AdversarialProfile consumed by PrioritizationEngine as a priority amplifier.
(Evasive targets get HIGHER priority, not lower -- they are harder to detect)
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import List
from urllib.parse import urlparse


_KNOWN_BRANDS = [
    "paypal", "google", "microsoft", "apple", "amazon", "facebook",
    "netflix", "linkedin", "twitter", "instagram", "bank", "chase",
    "wellsfargo", "citibank", "hsbc", "barclays", "mastercard", "visa",
    "stripe", "shopify", "salesforce", "oracle", "adobe",
]

_CONFUSABLE_RANGES = [
    (0x0400, 0x04FF),   # Cyrillic (looks like Latin)
    (0x0370, 0x03FF),   # Greek
    (0x0530, 0x058F),   # Armenian
    (0xFF00, 0xFFEF),   # Fullwidth Latin
    (0x0250, 0x02AF),   # IPA extensions (lookalike Latin)
]


@dataclass
class AdversarialProfile:
    target: str
    evasion_score: float             # 0-1 (1 = maximally evasive)
    evasion_techniques: List[str]    # Human-readable detected techniques
    unicode_confusables: List[str]   # Suspicious unicode characters found
    is_idn_homoglyph: bool           # True if domain uses Punycode encoding
    has_partial_legitimacy: bool     # Known brand embedded in suspicious structure
    priority_amplifier: float        # Applied as boost to priority (evasive = more urgent)

    @property
    def is_adversarial(self) -> bool:
        return self.evasion_score > 0.25


class AdversarialFilter:
    """Runs evasion detection before any scoring occurs."""

    def analyze(self, url: str) -> AdversarialProfile:
        domain = self._extract_domain(url)
        techniques: List[str] = []
        confusables: List[str] = []

        # 1. Unicode confusable character detection
        unicode_score, confusables = self._check_unicode_confusables(domain)
        if confusables:
            techniques.append(
                f"Unicode confusable characters detected: {', '.join(confusables[:3])}"
            )

        # 2. IDN homoglyph (Punycode)
        is_idn = self._check_idn_homoglyph(domain)
        if is_idn:
            techniques.append("IDN homoglyph domain (Punycode xn-- encoded)")

        # 3. Partial legitimacy masking (brand in suspicious structure)
        has_partial = self._check_partial_legitimacy(domain)
        if has_partial:
            techniques.append(
                "Partial legitimacy masking: known brand name embedded in suspicious domain structure"
            )

        # 4. Structural evasion
        struct_score = self._check_structural_evasion(domain)
        if struct_score > 0.25:
            techniques.append(
                f"Structural evasion indicators detected (score: {struct_score:.2f})"
            )

        evasion_score = min(1.0,
            unicode_score * 0.35
            + (0.40 if is_idn else 0.0)
            + (0.25 if has_partial else 0.0)
            + struct_score * 0.20
        )

        # Evasive targets get HIGHER priority (amplifier > 1.0 means boost)
        priority_amplifier = 1.0 + (evasion_score * 0.30)

        return AdversarialProfile(
            target=url,
            evasion_score=round(evasion_score, 3),
            evasion_techniques=techniques,
            unicode_confusables=confusables,
            is_idn_homoglyph=is_idn,
            has_partial_legitimacy=has_partial,
            priority_amplifier=round(priority_amplifier, 3),
        )

    def _extract_domain(self, url: str) -> str:
        try:
            parsed = urlparse(url if "://" in url else f"http://{url}")
            return (parsed.hostname or url).lower()
        except Exception:
            return url.lower()

    def _check_unicode_confusables(self, domain: str) -> tuple:
        found: List[str] = []
        for char in domain:
            cp = ord(char)
            for start, end in _CONFUSABLE_RANGES:
                if start <= cp <= end:
                    name = unicodedata.name(char, "UNKNOWN")
                    found.append(f"{char!r} U+{cp:04X} ({name})")
        score = min(1.0, len(found) * 0.35)
        return score, found

    def _check_idn_homoglyph(self, domain: str) -> bool:
        return domain.startswith("xn--") or ".xn--" in domain

    def _check_partial_legitimacy(self, domain: str) -> bool:
        clean = domain.replace("-", "").replace(".", "")
        has_brand = any(brand in clean for brand in _KNOWN_BRANDS)
        is_official = any(
            domain in (f"{brand}.com", f"www.{brand}.com", f"{brand}.org")
            for brand in _KNOWN_BRANDS
        )
        return has_brand and not is_official

    def _check_structural_evasion(self, domain: str) -> float:
        score = 0.0
        if domain.count("-") > 3:
            score += 0.20
        if domain.count(".") > 4:
            score += 0.20
        if re.search(r"\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}", domain):
            score += 0.35
        parts = domain.split(".")
        if parts and len(parts[0]) > 22:
            score += 0.20
        return min(1.0, score)
