
import re
import ipaddress
from typing import Tuple, List, Optional, Dict, Any
from urllib.parse import urlparse

from config.logging_config import get_logger

logger = get_logger(__name__)


MAX_DOMAIN_LENGTH = 253
MAX_LABEL_LENGTH = 63
MAX_BATCH_SIZE = 50
MAX_INPUT_LENGTH = 10_000


_LABEL_RE = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$')


_VALID_TLDS = {
    'com', 'org', 'net', 'edu', 'gov', 'mil', 'int',
    'io', 'co', 'ai', 'dev', 'app', 'me', 'us', 'uk', 'de', 'fr',
    'jp', 'cn', 'in', 'au', 'ca', 'br', 'ru', 'it', 'es', 'nl',
    'se', 'no', 'fi', 'dk', 'pl', 'cz', 'at', 'ch', 'be', 'pt',
    'ie', 'nz', 'za', 'kr', 'tw', 'sg', 'hk', 'mx', 'ar', 'cl',
    'info', 'biz', 'name', 'pro', 'museum', 'coop', 'aero',
    'xyz', 'online', 'site', 'tech', 'store', 'cloud', 'digital',
    'solutions', 'systems', 'network', 'services', 'agency',
    'design', 'media', 'marketing', 'software', 'space',
    'blog', 'live', 'shop', 'world', 'global', 'group',
    'tools', 'engineering', 'consulting', 'technology',
    'ventures', 'capital', 'partners', 'foundation', 'institute',
    'academy', 'center', 'exchange', 'health', 'care', 'social',
    'travel', 'finance', 'money', 'bank', 'fund', 'report',
    'security', 'insurance', 'legal', 'law', 'tax', 'energy',
    'eco', 'green', 'bio', 'organic', 'earth', 'land', 'farm',
    'garden', 'vet', 'pet', 'dog', 'cat', 'horse', 'fish',
    'top', 'win', 'bid', 'trade', 'market', 'sale', 'cheap',
    'discount', 'deals', 'promo', 'free', 'download', 'click',
    'link', 'page', 'website', 'web', 'host', 'server',

    'ac', 'ad', 'ae', 'af', 'ag', 'al', 'am', 'ao', 'aq',
    'as', 'az', 'ba', 'bb', 'bd', 'bf', 'bg', 'bh', 'bi',
    'bj', 'bm', 'bn', 'bo', 'bs', 'bt', 'bw', 'by', 'bz',
    'cc', 'cd', 'cf', 'cg', 'ci', 'ck', 'cm', 'cr', 'cu',
    'cv', 'cw', 'cx', 'cy', 'dj', 'dm', 'do', 'dz', 'ec',
    'ee', 'eg', 'er', 'et', 'eu', 'fj', 'fk', 'fm', 'fo',
    'ga', 'gb', 'gd', 'ge', 'gf', 'gg', 'gh', 'gi', 'gl',
    'gm', 'gn', 'gp', 'gq', 'gr', 'gs', 'gt', 'gu', 'gw',
    'gy', 'hm', 'hn', 'hr', 'ht', 'hu', 'id', 'il', 'im',
    'iq', 'ir', 'is', 'je', 'jm', 'jo', 'ke', 'kg', 'kh',
    'ki', 'km', 'kn', 'kp', 'kw', 'ky', 'kz', 'la', 'lb',
    'lc', 'li', 'lk', 'lr', 'ls', 'lt', 'lu', 'lv', 'ly',
    'ma', 'mc', 'md', 'mg', 'mh', 'mk', 'ml', 'mm', 'mn',
    'mo', 'mp', 'mq', 'mr', 'ms', 'mt', 'mu', 'mv', 'mw',
    'my', 'mz', 'na', 'nc', 'ne', 'nf', 'ng', 'ni', 'np',
    'nr', 'nu', 'om', 'pa', 'pe', 'pf', 'pg', 'ph', 'pk',
    'pm', 'pn', 'pr', 'ps', 'pw', 'py', 'qa', 're', 'ro',
    'rs', 'rw', 'sa', 'sb', 'sc', 'sd', 'si', 'sj', 'sk',
    'sl', 'sm', 'sn', 'so', 'sr', 'ss', 'st', 'su', 'sv',
    'sx', 'sy', 'sz', 'tc', 'td', 'tf', 'tg', 'th', 'tj',
    'tk', 'tl', 'tm', 'tn', 'to', 'tp', 'tr', 'tt', 'tv',
    'tz', 'ua', 'ug', 'uy', 'uz', 'va', 'vc', 've', 'vg',
    'vi', 'vn', 'vu', 'wf', 'ws', 'ye', 'yt', 'zm', 'zw',
}


def validate_domain(domain: str) -> Tuple[bool, str]:
    if not domain or not isinstance(domain, str):
        return False, "Domain is empty or not a string"

    domain = domain.strip().lower().rstrip('.')

    if len(domain) > MAX_DOMAIN_LENGTH:
        return False, f"Domain exceeds maximum length of {MAX_DOMAIN_LENGTH} characters"

    labels = domain.split('.')
    if len(labels) < 2:
        return False, "Domain must have at least two labels (e.g. example.com)"

    for label in labels:
        if not label:
            return False, "Domain contains empty label (double dot)"
        if len(label) > MAX_LABEL_LENGTH:
            return False, f"Label '{label}' exceeds {MAX_LABEL_LENGTH} characters"
        if not _LABEL_RE.match(label):
            return False, f"Label '{label}' contains invalid characters"

    tld = labels[-1]
    if tld not in _VALID_TLDS:

        if not (2 <= len(tld) <= 6 and tld.isalpha()):
            return False, f"Unrecognised TLD '.{tld}'"

    return True, ""


def validate_ip(ip_str: str) -> Tuple[bool, str]:
    if not ip_str or not isinstance(ip_str, str):
        return False, "IP address is empty or not a string"

    try:
        addr = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return False, f"'{ip_str}' is not a valid IP address"

    if addr.is_private:
        return False, f"{ip_str} is a private address — only public IPs are supported"
    if addr.is_loopback:
        return False, f"{ip_str} is a loopback address"
    if addr.is_reserved:
        return False, f"{ip_str} is a reserved address"
    if addr.is_link_local:
        return False, f"{ip_str} is a link-local address"
    if addr.is_multicast:
        return False, f"{ip_str} is a multicast address"

    return True, ""


def validate_url(url: str) -> Tuple[bool, str]:
    if not url or not isinstance(url, str):
        return False, "URL is empty or not a string"

    url = url.strip()
    if len(url) > 2048:
        return False, "URL exceeds maximum length of 2048 characters"


    working = url if '://' in url else f'http://{url}'

    try:
        parsed = urlparse(working)
    except Exception:
        return False, f"Could not parse URL: {url}"

    host = parsed.hostname
    if not host:
        return False, "URL has no hostname"


    try:
        ipaddress.ip_address(host)
        return validate_ip(host)
    except ValueError:
        return validate_domain(host)


def sanitize_input(raw_text: str) -> str:
    if not raw_text:
        return ""

    cleaned = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', raw_text)
    return cleaned[:MAX_INPUT_LENGTH]


def validate_batch_size(items: list) -> Tuple[bool, str]:
    if not items:
        return False, "No valid targets provided"
    if len(items) > MAX_BATCH_SIZE:
        return False, f"Too many targets ({len(items)}). Maximum is {MAX_BATCH_SIZE} per batch."
    return True, ""


def validate_api_response(
    response: Optional[Any],
    provider: str,
    expected_keys: Optional[List[str]] = None,
) -> Tuple[bool, str, Optional[Dict]]:
    if response is None:
        return False, f"{provider}: no response received", None


    if hasattr(response, 'status_code'):
        if response.status_code == 429:
            return False, f"{provider}: rate limited (429)", None
        if response.status_code == 403:
            return False, f"{provider}: authentication failed (403)", None
        if response.status_code >= 500:
            return False, f"{provider}: server error ({response.status_code})", None
        if response.status_code >= 400:
            return False, f"{provider}: client error ({response.status_code})", None

        try:
            data = response.json()
        except Exception:
            return False, f"{provider}: response is not valid JSON", None

        if expected_keys:
            missing = [k for k in expected_keys if k not in data]
            if missing:
                return False, f"{provider}: missing keys {missing}", None

        return True, "", data


    if isinstance(response, dict):
        if expected_keys:
            missing = [k for k in expected_keys if k not in response]
            if missing:
                return False, f"{provider}: missing keys {missing}", None
        return True, "", response

    return False, f"{provider}: unexpected response type {type(response)}", None