
import re
import ssl
import socket
import ipaddress
import logging
import os
from pathlib import Path
from typing import Tuple, List, Optional
from functools import lru_cache

logger = logging.getLogger(__name__)


_ROOT = Path(__file__).parent.parent
_WHITELIST_PATH = _ROOT / "config" / "trusted_domains.txt"


def check_domain_age(domain: str) -> Tuple[float, str, str]:
    try:
        import whois
        from datetime import datetime, timezone

        w = whois.whois(domain)
        creation = w.creation_date
        if creation is None:
            return 0.0, 'INFO', '[INFO] Domain age: WHOIS record found but no creation date available.'


        if isinstance(creation, list):
            creation = creation[0]

        now = datetime.now(timezone.utc)

        if creation.tzinfo is None:
            from datetime import timezone as _tz
            creation = creation.replace(tzinfo=_tz.utc)

        age_days = (now - creation).days

        if age_days < 0:
            return 0.0, 'INFO', '[INFO] Domain age: WHOIS date is in the future (may be pre-registered).'

        if age_days < 7:
            return 45.0, 'T1', (
                f'[T1] NEWLY REGISTERED DOMAIN: Created {age_days} day(s) ago. '
                'Domains registered less than 7 days ago are a strong phishing indicator.'
            )
        elif age_days < 30:
            return 35.0, 'T2', (
                f'[T2] VERY NEW DOMAIN: Registered {age_days} days ago. '
                'Domains under 30 days old are commonly used for phishing campaigns.'
            )
        elif age_days < 90:
            return 15.0, 'T2', (
                f'[T2] NEW DOMAIN: Registered {age_days} days ago. '
                'Domain is less than 3 months old -- treat with caution.'
            )
        elif age_days < 365:
            return 0.0, 'INFO', (
                f'[INFO] Domain age: {age_days} days ({age_days // 30} months). '
                'Less than 1 year old -- no automatic penalty.'
            )
        else:
            years = age_days // 365
            return -0.05, 'INFO', (
                f'[INFO] Established domain: {years} year(s) old. '
                'Domain age reduces likelihood of opportunistic registration.'
            )

    except ImportError:
        logger.debug('python-whois not installed -- domain age check skipped.')
        return 0.0, 'INFO', ''
    except Exception as exc:
        logger.debug(f'WHOIS lookup failed for {domain}: {exc}')
        return 0.0, 'INFO', ''


@lru_cache(maxsize=1)
def _load_whitelist() -> List[str]:
    entries = []
    try:
        if _WHITELIST_PATH.exists():
            for line in _WHITELIST_PATH.read_text(encoding='utf-8').splitlines():
                line = line.strip()
                if line and not line.startswith('#'):
                    entries.append(line.lower())
    except Exception as exc:
        logger.debug(f'Trusted domain whitelist load error: {exc}')
    return entries


def is_trusted_domain(domain: str) -> bool:
    domain_lower = domain.lower().rstrip('.')
    for entry in _load_whitelist():
        if entry.startswith('.'):

            if domain_lower == entry[1:] or domain_lower.endswith(entry):
                return True
        else:
            if domain_lower == entry:
                return True
    return False


_PRIVATE_SUFFIXES = (
    '.local', '.internal', '.corp', '.lan', '.intranet',
    '.home', '.private', '.localdomain', '.localhost',
)

_PRIVATE_IP_NETWORKS = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),
    ipaddress.ip_network('::1/128'),
    ipaddress.ip_network('fc00::/7'),
]


def is_private_or_intranet(domain: str) -> Tuple[bool, str]:
    d = domain.lower().strip()


    if d in ('localhost', '127.0.0.1', '::1'):  # nosec: loopback guard — membership check, not hardcoded endpoint
        return True, 'Loopback address -- local development environment.'


    for suffix in _PRIVATE_SUFFIXES:
        if d == suffix.lstrip('.') or d.endswith(suffix):
            return True, f'Private/intranet domain suffix detected: {suffix}'


    try:
        addr = ipaddress.ip_address(d)
        for net in _PRIVATE_IP_NETWORKS:
            if addr in net:
                return True, f'Private RFC 1918 / loopback IP address: {d}'
    except ValueError:
        pass

    return False, ''


def check_ssl_certificate(domain: str, port: int = 443) -> Tuple[float, str, str]:
    import datetime as _dt

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED

        with socket.create_connection((domain, port), timeout=2.0) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()


        not_after_str = cert.get('notAfter', '')
        if not_after_str:
            not_after = _dt.datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z')
            days_left = (not_after - _dt.datetime.utcnow()).days
            if days_left < 0:
                return 40.0, 'T2', (
                    f'[T2] EXPIRED SSL CERTIFICATE: Certificate expired {abs(days_left)} day(s) ago. '
                    'Encrypted connections may be interceptable.'
                )
            elif days_left <= 14:
                return 15.0, 'T2', (
                    f'[T2] SSL CERTIFICATE EXPIRING SOON: {days_left} day(s) remaining. '
                    'Sites with expiring certificates may indicate neglected security.'
                )

        return 0.0, 'INFO', f'[INFO] SSL certificate valid.'

    except ssl.SSLCertVerificationError as exc:
        reason = str(exc)
        if 'CERTIFICATE_VERIFY_FAILED' in reason or 'self signed' in reason.lower():
            return 30.0, 'T2', (
                '[T2] SSL CERTIFICATE UNTRUSTED: Self-signed or unverifiable certificate. '
                'The site cannot prove its identity -- data may not be encrypted to a trusted party.'
            )
        if 'hostname' in reason.lower():
            return 35.0, 'T2', (
                '[T2] SSL HOSTNAME MISMATCH: Certificate is not issued for this domain. '
                'This is a strong indicator of a man-in-the-middle attack or misconfigured server.'
            )
        return 20.0, 'T2', f'[T2] SSL CERTIFICATE ERROR: {reason[:120]}'

    except (socket.timeout, ConnectionRefusedError, OSError):

        return 0.0, 'INFO', ''

    except Exception as exc:
        logger.debug(f'SSL check failed for {domain}: {exc}')
        return 0.0, 'INFO', ''


_HTML_PATTERNS = [

    (r'<form[^>]+action=["\']https?://(?!{domain})[^"\']+["\']', 55, 'T1',
     'Credential form submitting to external host (credential harvesting)'),


    (r'<iframe[^>]+(width=["\']0["\']|height=["\']0["\']|display\s*:\s*none)', 40, 'T2',
     'Hidden iframe detected (potential clickjacking or drive-by-download)'),

    (r'eval\s*\(\s*(atob|unescape|String\.fromCharCode)\s*\(', 50, 'T1',
     'Obfuscated JavaScript execution detected (eval+decode pattern)'),

    (r'document\.write\s*\(\s*unescape\s*\(', 45, 'T1',
     'Obfuscated document.write detected'),

    (r'coinhive|cryptonight|minero\.cc|coin-hive', 60, 'T1',
     'Crypto-miner script detected'),

    (r'<title>[^<]*(verify your account|confirm your identity|suspended account|unusual activity)[^<]*</title>',
     35, 'T2', 'Phishing page title pattern detected'),

    (r'<meta[^>]+http-equiv=["\']refresh["\'][^>]+url=https?://', 25, 'T2',
     'Automatic redirect via meta refresh tag'),

    (r'href=["\']data:text/html;base64,', 50, 'T1',
     'Base64-encoded data URI redirect detected'),
]


def scan_html_content(url: str, domain: str) -> List[Tuple[float, str, str]]:
    results: List[Tuple[float, str, str]] = []
    try:
        import requests
        headers = {
            'User-Agent': 'Mozilla/5.0 (compatible; IERSS/2.1; +security-scanner)',
            'Accept': 'text/html,application/xhtml+xml',
        }
        resp = requests.get(url, timeout=3.0, headers=headers, allow_redirects=True,
                            verify=False, stream=True)

        raw = b''
        for chunk in resp.iter_content(chunk_size=8192):
            raw += chunk
            if len(raw) > 200_000:
                break

        html = raw.decode('utf-8', errors='replace').lower()

        for pattern, score, tier, description in _HTML_PATTERNS:

            p = pattern.replace('{domain}', re.escape(domain.lower()))
            if re.search(p, html, re.IGNORECASE | re.DOTALL):
                results.append((
                    float(score), tier,
                    f'[{tier}] HTML CONTENT: {description}'
                ))

        if not results:
            results.append((0.0, 'INFO', '[INFO] HTML content scan: no suspicious patterns detected.'))

    except ImportError:
        logger.debug('requests not available -- HTML content scan skipped.')
    except Exception as exc:
        logger.debug(f'HTML content scan failed for {url}: {exc}')

    return results


def check_urlhaus(url: str) -> Tuple[float, str, str]:
    try:
        import requests

        resp = requests.post(
            'https://urlhaus-api.abuse.ch/v1/url/',
            data={'url': url},
            timeout=3.0,
        )
        data = resp.json()

        if data.get('query_status') == 'is_active':
            tags = ', '.join(data.get('tags') or []) or 'unknown'
            threat = data.get('threat', 'malware')
            return (
                90.0, 'T1',
                f'[T1] URLHAUS: URL is flagged as ACTIVE {threat.upper()} by abuse.ch '
                f'(tags: {tags}). Do not visit or download from this URL.'
            )
        elif data.get('query_status') == 'is_offline':
            return (
                35.0, 'T2',
                '[T2] URLHAUS: URL was previously flagged as malware by abuse.ch '
                '(currently offline). Historical threat record exists.'
            )

        return 0.0, 'INFO', ''

    except Exception as exc:
        logger.debug(f'URLhaus check failed for {url}: {exc}')
        return 0.0, 'INFO', ''