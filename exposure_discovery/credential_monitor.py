"""
Credential Monitor
==================
Checks whether an organisation's domain appears in known data breaches
using the HaveIBeenPwned (HIBP) Domain Search API.

Requires HIBP_API_KEY in environment (HIBP API v3 subscription required
for domain search; individual email checks use the free k-anonymity model).

Passive only — no credential stuffing, no authentication testing.
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import requests

logger = logging.getLogger(__name__)

_HIBP_DOMAIN_URL = "https://haveibeenpwned.com/api/v3/breacheddomain/{domain}"
_HIBP_BREACH_URL = "https://haveibeenpwned.com/api/v3/breach/{name}"
_REQUEST_TIMEOUT = 15
_RATE_LIMIT_DELAY = 1.5  # HIBP enforces strict rate limits


@dataclass
class BreachRecord:
    """A single breach affecting the target domain."""
    breach_name: str
    breach_date: Optional[str]
    pwn_count: int
    data_classes: List[str]           # e.g. ['Passwords', 'Email addresses']
    affected_accounts: Optional[int]  # number of accounts from target domain
    is_sensitive: bool
    is_verified: bool
    description_snippet: str


@dataclass
class CredentialMonitorResult:
    """Result of HIBP breach check for a domain."""
    target_domain: str
    breaches: List[BreachRecord] = field(default_factory=list)
    total_breach_count: int = 0
    password_breaches: int = 0          # breaches that include plaintext/hashed passwords
    most_recent_breach: Optional[str] = None
    has_active_risk: bool = False       # True if breach < 2 years old with passwords
    errors: List[str] = field(default_factory=list)
    api_available: bool = True


class CredentialMonitor:
    """
    Checks an organisation's domain against the HIBP breach database.
    Falls back gracefully if no API key is configured.

    Usage:
        monitor = CredentialMonitor()
        result = monitor.check("example.com")
        print(result.total_breach_count, result.password_breaches)
    """

    def __init__(self, api_key: Optional[str] = None, timeout: int = _REQUEST_TIMEOUT):
        self._api_key = api_key or os.getenv("HIBP_API_KEY", "")
        self._timeout = timeout
        self._session = requests.Session()
        if self._api_key:
            self._session.headers.update({
                "hibp-api-key": self._api_key,
                "User-Agent": "EIRPP-ExposureDiscovery/1.0",
            })

    def check(self, domain: str) -> CredentialMonitorResult:
        """
        Check a domain against known data breaches.

        Args:
            domain: Organisation domain (e.g. 'example.com')

        Returns:
            CredentialMonitorResult
        """
        domain = domain.strip().lower().removeprefix("www.")
        result = CredentialMonitorResult(target_domain=domain)

        if not self._api_key:
            result.api_available = False
            result.errors.append(
                "HIBP_API_KEY not configured — credential monitoring unavailable. "
                "Set HIBP_API_KEY in .env to enable this feature."
            )
            logger.warning("[CredentialMonitor] No HIBP API key configured.")
            return result

        try:
            url = _HIBP_DOMAIN_URL.format(domain=domain)
            resp = self._session.get(url, timeout=self._timeout)

            if resp.status_code == 404:
                # Domain not found in any breach — clean result
                logger.info(f"[CredentialMonitor] {domain}: no breaches found")
                return result
            elif resp.status_code == 401:
                result.api_available = False
                result.errors.append("HIBP API key invalid or expired.")
                return result
            elif resp.status_code == 429:
                result.errors.append("HIBP rate limit hit — retry later.")
                return result

            resp.raise_for_status()
            breach_map: Dict[str, int] = resp.json()  # {BreachName: accountCount}

            breach_dates = []
            for breach_name, account_count in breach_map.items():
                time.sleep(_RATE_LIMIT_DELAY)
                detail = self._fetch_breach_detail(breach_name)
                if detail is None:
                    continue

                data_classes = detail.get("DataClasses", [])
                has_passwords = any(
                    "password" in dc.lower() for dc in data_classes
                )
                breach_date = detail.get("BreachDate", "")
                if breach_date:
                    breach_dates.append(breach_date)

                record = BreachRecord(
                    breach_name=breach_name,
                    breach_date=breach_date or None,
                    pwn_count=detail.get("PwnCount", 0),
                    data_classes=data_classes,
                    affected_accounts=account_count,
                    is_sensitive=detail.get("IsSensitive", False),
                    is_verified=detail.get("IsVerified", True),
                    description_snippet=_strip_html(
                        detail.get("Description", "")
                    )[:300],
                )
                result.breaches.append(record)
                if has_passwords:
                    result.password_breaches += 1

            result.total_breach_count = len(result.breaches)
            if breach_dates:
                result.most_recent_breach = max(breach_dates)
                # Active risk: password breach within last 2 years
                from datetime import date
                try:
                    recent_year = int(result.most_recent_breach[:4])
                    result.has_active_risk = (
                        result.password_breaches > 0
                        and (date.today().year - recent_year) <= 2
                    )
                except (ValueError, TypeError):
                    pass

            logger.info(
                f"[CredentialMonitor] {domain}: {result.total_breach_count} breaches, "
                f"{result.password_breaches} with passwords, "
                f"active_risk={result.has_active_risk}"
            )

        except requests.exceptions.Timeout:
            result.errors.append("HIBP request timed out.")
        except requests.exceptions.HTTPError as e:
            result.errors.append(f"HIBP HTTP error: {e.response.status_code}")
        except Exception as e:
            result.errors.append(f"HIBP unexpected error: {e}")
            logger.exception(f"[CredentialMonitor] Error checking {domain}")

        return result

    def _fetch_breach_detail(self, breach_name: str) -> Optional[dict]:
        """Fetch detailed metadata for a single breach."""
        try:
            resp = self._session.get(
                _HIBP_BREACH_URL.format(name=breach_name),
                timeout=self._timeout,
            )
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass
        return None


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _strip_html(text: str) -> str:
    """Remove HTML tags from HIBP breach descriptions."""
    import re
    return re.sub(r"<[^>]+>", "", text).strip()
