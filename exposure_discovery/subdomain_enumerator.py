"""
Subdomain Enumerator
====================
Passively discovers subdomains for a target organisation using:
  1. Certificate Transparency logs via crt.sh (free, no key required)
  2. HackerTarget subdomain API (free tier)
  3. Deduplication and validation against the IERSS validator

All discovery is fully passive — no DNS brute-forcing, no active probing.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from typing import List, Optional, Set

import requests

from utils.validators import validate_domain

logger = logging.getLogger(__name__)

_CRT_SH_URL = "https://crt.sh/?q={domain}&output=json"
_HACKERTARGET_URL = "https://api.hackertarget.com/hostsearch/?q={domain}"
_REQUEST_TIMEOUT = 15
_RATE_LIMIT_DELAY = 1.0  # seconds between external API calls


@dataclass
class DiscoveredSubdomain:
    """A single subdomain discovered through passive CT or API sources."""
    subdomain: str
    source: str                  # 'crt.sh' | 'hackertarget'
    issuer: Optional[str] = None
    first_seen: Optional[str] = None
    is_valid: bool = True


@dataclass
class SubdomainEnumerationResult:
    """Full result set for a target domain."""
    target_domain: str
    subdomains: List[DiscoveredSubdomain] = field(default_factory=list)
    total_discovered: int = 0
    sources_used: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    elapsed_seconds: float = 0.0

    def unique_hostnames(self) -> List[str]:
        """Returns deduplicated list of subdomain strings."""
        return sorted({s.subdomain for s in self.subdomains if s.is_valid})


class SubdomainEnumerator:
    """
    Discovers subdomains for a given apex domain using public,
    passive Certificate Transparency and DNS aggregation APIs.

    Usage:
        enumerator = SubdomainEnumerator()
        result = enumerator.enumerate("example.com")
        for hostname in result.unique_hostnames():
            print(hostname)
    """

    def __init__(self, timeout: int = _REQUEST_TIMEOUT):
        self._timeout = timeout
        self._session = requests.Session()
        self._session.headers.update({
            "User-Agent": "EIRPP-ExposureDiscovery/1.0 (passive security research)"
        })

    def enumerate(self, domain: str) -> SubdomainEnumerationResult:
        """
        Run all passive subdomain discovery sources for the given domain.

        Args:
            domain: Apex domain (e.g. 'example.com') — no protocol prefix.

        Returns:
            SubdomainEnumerationResult with all discovered subdomains.
        """
        domain = domain.strip().lower().removeprefix("www.")
        result = SubdomainEnumerationResult(target_domain=domain)
        t_start = time.monotonic()

        logger.info(f"[SubdomainEnumerator] Starting enumeration for: {domain}")

        # Source 1: Certificate Transparency (crt.sh)
        ct_subs = self._query_crt_sh(domain, result)
        result.subdomains.extend(ct_subs)
        if ct_subs:
            result.sources_used.append("crt.sh")

        time.sleep(_RATE_LIMIT_DELAY)

        # Source 2: HackerTarget DNS aggregation
        ht_subs = self._query_hackertarget(domain, result)
        result.subdomains.extend(ht_subs)
        if ht_subs:
            result.sources_used.append("hackertarget")

        # Deduplicate
        seen: Set[str] = set()
        deduped = []
        for s in result.subdomains:
            if s.subdomain not in seen:
                seen.add(s.subdomain)
                deduped.append(s)
        result.subdomains = deduped
        result.total_discovered = len(deduped)
        result.elapsed_seconds = round(time.monotonic() - t_start, 2)

        logger.info(
            f"[SubdomainEnumerator] {domain}: {result.total_discovered} unique subdomains "
            f"in {result.elapsed_seconds}s via {result.sources_used}"
        )
        return result

    # ──────────────────────────────────────────────────────────────────────────
    # Private: crt.sh
    # ──────────────────────────────────────────────────────────────────────────

    def _query_crt_sh(
        self, domain: str, result: SubdomainEnumerationResult
    ) -> List[DiscoveredSubdomain]:
        """Query Certificate Transparency logs via crt.sh JSON API."""
        discovered: List[DiscoveredSubdomain] = []
        try:
            url = _CRT_SH_URL.format(domain=domain)
            resp = self._session.get(url, timeout=self._timeout)
            resp.raise_for_status()
            entries = resp.json()

            seen_in_source: Set[str] = set()
            for entry in entries:
                name_value = entry.get("name_value", "")
                issuer = entry.get("issuer_name", "")
                not_before = entry.get("not_before", "")

                # CT entries can contain wildcard and multi-SAN entries
                for raw_name in name_value.splitlines():
                    raw_name = raw_name.strip().lower()
                    # Strip wildcard prefix
                    if raw_name.startswith("*."):
                        raw_name = raw_name[2:]
                    if not raw_name.endswith(f".{domain}") and raw_name != domain:
                        continue
                    if raw_name in seen_in_source:
                        continue
                    seen_in_source.add(raw_name)

                    valid, _ = validate_domain(raw_name)
                    discovered.append(DiscoveredSubdomain(
                        subdomain=raw_name,
                        source="crt.sh",
                        issuer=_extract_cn(issuer),
                        first_seen=not_before[:10] if not_before else None,
                        is_valid=valid,
                    ))

        except requests.exceptions.Timeout:
            msg = "crt.sh: request timed out"
            logger.warning(f"[SubdomainEnumerator] {msg}")
            result.errors.append(msg)
        except requests.exceptions.HTTPError as e:
            msg = f"crt.sh: HTTP {e.response.status_code}"
            logger.warning(f"[SubdomainEnumerator] {msg}")
            result.errors.append(msg)
        except Exception as e:
            msg = f"crt.sh: unexpected error — {e}"
            logger.warning(f"[SubdomainEnumerator] {msg}")
            result.errors.append(msg)

        return discovered

    # ──────────────────────────────────────────────────────────────────────────
    # Private: HackerTarget
    # ──────────────────────────────────────────────────────────────────────────

    def _query_hackertarget(
        self, domain: str, result: SubdomainEnumerationResult
    ) -> List[DiscoveredSubdomain]:
        """Query HackerTarget host search (free tier, passive DNS aggregation)."""
        discovered: List[DiscoveredSubdomain] = []
        try:
            url = _HACKERTARGET_URL.format(domain=domain)
            resp = self._session.get(url, timeout=self._timeout)
            resp.raise_for_status()
            text = resp.text.strip()

            # Rate limit / error responses from HackerTarget
            if text.startswith("error") or "API count exceeded" in text:
                result.errors.append(f"hackertarget: {text[:80]}")
                return discovered

            seen_in_source: Set[str] = set()
            for line in text.splitlines():
                parts = line.split(",")
                if not parts:
                    continue
                hostname = parts[0].strip().lower()
                if not hostname.endswith(f".{domain}") and hostname != domain:
                    continue
                if hostname in seen_in_source:
                    continue
                seen_in_source.add(hostname)

                valid, _ = validate_domain(hostname)
                discovered.append(DiscoveredSubdomain(
                    subdomain=hostname,
                    source="hackertarget",
                    is_valid=valid,
                ))

        except requests.exceptions.Timeout:
            msg = "hackertarget: request timed out"
            logger.warning(f"[SubdomainEnumerator] {msg}")
            result.errors.append(msg)
        except requests.exceptions.HTTPError as e:
            msg = f"hackertarget: HTTP {e.response.status_code}"
            logger.warning(f"[SubdomainEnumerator] {msg}")
            result.errors.append(msg)
        except Exception as e:
            msg = f"hackertarget: unexpected error — {e}"
            logger.warning(f"[SubdomainEnumerator] {msg}")
            result.errors.append(msg)

        return discovered


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _extract_cn(issuer_string: str) -> Optional[str]:
    """Extract the CN= value from an X.509 issuer string."""
    match = re.search(r"CN=([^,]+)", issuer_string)
    return match.group(1).strip() if match else None
