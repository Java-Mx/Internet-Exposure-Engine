"""
Threat Feed Connector
=====================
External enrichment feeds for AERIS Correlation Engine.

Architecture principle:
    Feeds ENRICH and CONTEXTUALIZE -- they NEVER directly determine verdict.
    Feed hits add evidence with reliability=MEDIUM to the EvidenceChain.
    A single feed hit does NOT equal malicious. It equals additional context.

Enabled feeds (configured via .env):
    - crt.sh      : Certificate transparency (no API key needed)
    - URLhaus     : Malicious URL database (no API key needed)
    - AbuseIPDB   : IP reputation (free API key from abuseipdb.com)
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional

import requests

logger = logging.getLogger(__name__)

_TIMEOUT = 8   # seconds per request


@dataclass
class FeedResult:
    feed_name: str
    target: str
    hit: bool
    confidence: float       # 0-1 feed-specific reliability
    detail: str
    raw: Optional[Dict] = None
    queried_at: datetime = field(default_factory=datetime.now)


@dataclass
class FeedEnrichment:
    target: str
    results: List[FeedResult] = field(default_factory=list)
    total_hits: int = 0
    enrichment_narrative: str = ""
    query_errors: List[str] = field(default_factory=list)

    def has_hit(self) -> bool:
        return any(r.hit for r in self.results)

    def hit_count(self) -> int:
        return sum(1 for r in self.results if r.hit)

    def get_result(self, feed_name: str) -> Optional[FeedResult]:
        return next((r for r in self.results if r.feed_name == feed_name), None)


class FeedConnector:
    """Queries curated threat intelligence enrichment feeds."""

    def __init__(self):
        self._urlhaus = os.getenv("URLHAUS_ENABLED", "true").lower() == "true"
        self._crtsh   = os.getenv("CRTSH_ENABLED",   "true").lower() == "true"
        self._abuse   = os.getenv("ABUSEIPDB_ENABLED","false").lower() == "true"
        self._abuse_key = os.getenv("ABUSEIPDB_API_KEY", "")
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": "AERIS-Intelligence/2.0"})

    def enrich(self, target: str) -> FeedEnrichment:
        """Query all enabled feeds and return aggregated enrichment data."""
        enrichment = FeedEnrichment(target=target)

        if self._crtsh:
            try:
                enrichment.results.append(self._query_crtsh(target))
            except Exception as e:
                enrichment.query_errors.append(f"crt.sh: {e}")

        if self._urlhaus:
            try:
                enrichment.results.append(self._query_urlhaus(target))
            except Exception as e:
                enrichment.query_errors.append(f"URLhaus: {e}")

        if self._abuse and self._abuse_key:
            try:
                enrichment.results.append(self._query_abuseipdb(target))
            except Exception as e:
                enrichment.query_errors.append(f"AbuseIPDB: {e}")

        enrichment.total_hits = enrichment.hit_count()
        enrichment.enrichment_narrative = self._narrative(enrichment)
        return enrichment

    def _query_crtsh(self, domain: str) -> FeedResult:
        clean = self._domain(domain)
        try:
            resp = self._session.get(
                "https://crt.sh/",
                params={"q": f"%.{clean}", "output": "json"},
                timeout=_TIMEOUT,
            )
            if resp.status_code == 200 and resp.content:
                certs = resp.json()
                if isinstance(certs, list) and certs:
                    names: set = set()
                    for cert in certs[:30]:
                        for n in cert.get("name_value", "").split("\n"):
                            n = n.strip().lstrip("*.")
                            if n and n != clean and "." in n:
                                names.add(n)
                    return FeedResult(
                        feed_name="crt.sh",
                        target=clean,
                        hit=bool(names),
                        confidence=0.60,
                        detail=(
                            f"{len(certs)} certificates; related domains: "
                            + ", ".join(list(names)[:5])
                            if names else f"{len(certs)} certificates found"
                        ),
                        raw={"cert_count": len(certs), "related_names": list(names)[:10]},
                    )
        except Exception as e:
            logger.debug(f"[FeedConnector] crt.sh failed: {e}")
        return FeedResult("crt.sh", domain, False, 0.0, "No data or query failed")

    def _query_urlhaus(self, url: str) -> FeedResult:
        target = url if "://" in url else f"http://{url}"
        try:
            resp = self._session.post(
                "https://urlhaus-api.abuse.ch/v1/url/",
                data={"url": target},
                timeout=_TIMEOUT,
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("query_status") == "is_listed":
                    tags = data.get("tags") or []
                    return FeedResult(
                        feed_name="URLhaus",
                        target=url,
                        hit=True,
                        confidence=0.85,
                        detail=(
                            f"Listed in URLhaus. Status: {data.get('url_status','unknown')}. "
                            f"Tags: {', '.join(tags) or 'none'}"
                        ),
                        raw={"id": data.get("id"), "tags": tags, "status": data.get("url_status")},
                    )
        except Exception as e:
            logger.debug(f"[FeedConnector] URLhaus failed: {e}")
        return FeedResult("URLhaus", url, False, 0.0, "Not listed in URLhaus")

    def _query_abuseipdb(self, ip: str) -> FeedResult:
        try:
            resp = self._session.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": self._abuse_key, "Accept": "application/json"},
                timeout=_TIMEOUT,
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                score = int(data.get("abuseConfidenceScore", 0))
                if score > 15:
                    return FeedResult(
                        feed_name="AbuseIPDB",
                        target=ip,
                        hit=True,
                        confidence=min(0.95, score / 100.0 + 0.10),
                        detail=(
                            f"AbuseIPDB score: {score}/100. "
                            f"Reports: {data.get('totalReports',0)}. "
                            f"Country: {data.get('countryCode','?')}"
                        ),
                        raw={"score": score, "reports": data.get("totalReports"), "country": data.get("countryCode")},
                    )
        except Exception as e:
            logger.debug(f"[FeedConnector] AbuseIPDB failed: {e}")
        return FeedResult("AbuseIPDB", ip, False, 0.0, "Not flagged or score below threshold")

    def _narrative(self, enrichment: FeedEnrichment) -> str:
        hits = [r for r in enrichment.results if r.hit]
        if not hits:
            return "No threat intelligence feed hits for this target."
        summaries = [f"{r.feed_name}: {r.detail}" for r in hits]
        return f"{len(hits)} feed(s) returned threat intelligence. " + " | ".join(summaries)

    @staticmethod
    def _domain(url: str) -> str:
        from urllib.parse import urlparse
        try:
            return (urlparse(url if "://" in url else f"http://{url}").hostname or url).lower().lstrip("www.")
        except Exception:
            return url.lower()
