"""
Cloud Asset Scanner
===================
Passively detects publicly accessible cloud storage assets for a domain:
  - AWS S3 buckets (common naming patterns)
  - Google Cloud Storage buckets
  - Azure Blob Storage containers

Discovery is fully passive — HTTP HEAD/GET requests to well-known public
endpoints only. No credentials used, no account enumeration.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)

_REQUEST_TIMEOUT = 10
_RATE_LIMIT_DELAY = 0.3


@dataclass
class CloudAsset:
    """A discovered cloud storage asset."""
    url: str
    provider: str        # 'AWS S3' | 'GCS' | 'Azure Blob'
    bucket_name: str
    is_public: bool
    status_code: int
    risk_indicator: str  # 'PUBLIC_READ' | 'LISTED' | 'EXISTS_PRIVATE' | 'NOT_FOUND'
    size_hint: Optional[str] = None  # from Content-Length if available


@dataclass
class CloudScanResult:
    """Result of cloud asset scan for a domain."""
    target_domain: str
    assets: List[CloudAsset] = field(default_factory=list)
    public_count: int = 0
    errors: List[str] = field(default_factory=list)
    elapsed_seconds: float = 0.0

    def public_assets(self) -> List[CloudAsset]:
        return [a for a in self.assets if a.is_public]


# Common bucket name patterns derived from a domain
def _bucket_candidates(domain: str) -> List[str]:
    """Generate likely bucket names from a domain."""
    apex = domain.split(".")[0]  # e.g. 'example' from 'example.com'
    return list(dict.fromkeys([
        apex,
        domain,
        domain.replace(".", "-"),
        f"{apex}-backup",
        f"{apex}-assets",
        f"{apex}-static",
        f"{apex}-media",
        f"{apex}-data",
        f"{apex}-uploads",
        f"{apex}-files",
        f"www-{apex}",
        f"{apex}-dev",
        f"{apex}-staging",
        f"{apex}-prod",
    ]))


class CloudAssetScanner:
    """
    Checks well-known cloud storage endpoints for a target domain's
    likely bucket names. All checks are passive HEAD/GET requests.

    Usage:
        scanner = CloudAssetScanner()
        result = scanner.scan("example.com")
        for asset in result.public_assets():
            print(asset.url, asset.risk_indicator)
    """

    def __init__(self, timeout: int = _REQUEST_TIMEOUT):
        self._timeout = timeout
        self._session = requests.Session()
        self._session.headers.update({
            "User-Agent": "EIRPP-ExposureDiscovery/1.0 (passive security research)"
        })

    def scan(self, domain: str) -> CloudScanResult:
        domain = domain.strip().lower().removeprefix("www.")
        result = CloudScanResult(target_domain=domain)
        t_start = time.monotonic()

        logger.info(f"[CloudAssetScanner] Scanning: {domain}")
        candidates = _bucket_candidates(domain)

        for bucket in candidates:
            # AWS S3
            self._check_s3(bucket, result)
            time.sleep(_RATE_LIMIT_DELAY)
            # GCS
            self._check_gcs(bucket, result)
            time.sleep(_RATE_LIMIT_DELAY)
            # Azure
            self._check_azure(bucket, result)
            time.sleep(_RATE_LIMIT_DELAY)

        result.public_count = len(result.public_assets())
        result.elapsed_seconds = round(time.monotonic() - t_start, 2)

        logger.info(
            f"[CloudAssetScanner] {domain}: {len(result.assets)} checked, "
            f"{result.public_count} public in {result.elapsed_seconds}s"
        )
        return result

    # ──────────────────────────────────────────────────────────────────────────
    # Provider checks
    # ──────────────────────────────────────────────────────────────────────────

    def _check_s3(self, bucket: str, result: CloudScanResult) -> None:
        url = f"https://{bucket}.s3.amazonaws.com/"
        self._probe(url, "AWS S3", bucket, result)

    def _check_gcs(self, bucket: str, result: CloudScanResult) -> None:
        url = f"https://storage.googleapis.com/{bucket}/"
        self._probe(url, "GCS", bucket, result)

    def _check_azure(self, bucket: str, result: CloudScanResult) -> None:
        # Azure storage accounts: <name>.blob.core.windows.net
        safe_name = bucket.replace(".", "").replace("-", "")[:24]
        if not safe_name:
            return
        url = f"https://{safe_name}.blob.core.windows.net/$web/"
        self._probe(url, "Azure Blob", safe_name, result)

    def _probe(
        self, url: str, provider: str, bucket: str, result: CloudScanResult
    ) -> None:
        """Fire a HEAD (then GET if needed) to determine bucket accessibility."""
        try:
            resp = self._session.head(url, timeout=self._timeout, allow_redirects=True)
            code = resp.status_code

            is_public = False
            indicator = "NOT_FOUND"

            if code == 200:
                is_public = True
                # Attempt a GET to see if listing is enabled
                try:
                    get_resp = self._session.get(url, timeout=self._timeout, stream=True)
                    body_start = next(get_resp.iter_content(512), b"")
                    if b"ListBucketResult" in body_start or b"<Contents>" in body_start:
                        indicator = "LISTED"
                    else:
                        indicator = "PUBLIC_READ"
                    get_resp.close()
                except Exception:
                    indicator = "PUBLIC_READ"
                size_hint = resp.headers.get("Content-Length")
            elif code == 403:
                # Bucket exists but access denied — still an intel signal
                is_public = False
                indicator = "EXISTS_PRIVATE"
                size_hint = None
            elif code in (301, 302, 307, 308):
                # Redirect may indicate bucket exists in different region
                is_public = False
                indicator = "EXISTS_PRIVATE"
                size_hint = None
            else:
                return  # 404 / 400 / connection refused — bucket doesn't exist

            result.assets.append(CloudAsset(
                url=url,
                provider=provider,
                bucket_name=bucket,
                is_public=is_public,
                status_code=code,
                risk_indicator=indicator,
                size_hint=size_hint,
            ))

        except requests.exceptions.Timeout:
            pass  # Bucket not reachable — not interesting
        except requests.exceptions.ConnectionError:
            pass  # DNS does not resolve — bucket name not taken
        except Exception as e:
            logger.debug(f"[CloudAssetScanner] Probe error for {url}: {e}")
