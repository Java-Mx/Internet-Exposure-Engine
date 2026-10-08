
import re
import math
from typing import Dict, List, Any, Tuple, Optional
from datetime import datetime
from urllib.parse import urlparse

from config.logging_config import get_logger

logger = get_logger(__name__)


def smart_parse_url(url: str) -> str:
    if not url:
        return ""


    from urllib.parse import unquote
    url = unquote(url)


    clean = url.lower().strip()
    if '://' in clean:
        clean = clean.split('://')[1]


    clean = clean.split('/')[0]
    clean = clean.split('?')[0]
    clean = clean.split('#')[0]


    if ':' in clean:
        clean = clean.split(':')[0]


    clean = clean.rstrip('.')

    return clean

def calculate_entropy(text: str) -> float:
    if not text:
        return 0.0

    prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
    entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob])
    return entropy


KNOWN_VULNERABLE_DOMAINS = {
    'testphp.vulnweb.com': {'risk': 95, 'reason': 'Known intentionally vulnerable test site (Acunetix)'},
    'demo.testfire.net': {'risk': 90, 'reason': 'Known vulnerable demo site (IBM AppScan)'},
    'hack.me': {'risk': 85, 'reason': 'Hacking challenge site'},
    'hackerone.com': {'risk': 20, 'reason': 'Bug bounty platform (secure)'},
    'zero.webappsecurity.com': {'risk': 85, 'reason': 'Known test vulnerable site'},
    'juice-shop.herokuapp.com': {'risk': 90, 'reason': 'OWASP Juice Shop (intentionally vulnerable)'},
    'owasp-juice.shop': {'risk': 90, 'reason': 'OWASP Juice Shop'},
    'portswigger.net': {'risk': 15, 'reason': 'Security vendor (secure)'},
    'dvwa.co.uk': {'risk': 95, 'reason': 'Damn Vulnerable Web Application'},
    'bwapp.hakhub.net': {'risk': 90, 'reason': 'bWAPP vulnerable web app'},
    'webhacking.kr': {'risk': 80, 'reason': 'Web hacking challenge site'},
    'vulnhub.com': {'risk': 25, 'reason': 'Vulnerability resources (educational)'},
    'pentesterlab.com': {'risk': 20, 'reason': 'Security training platform (secure)'},
    'attackdefense.com': {'risk': 25, 'reason': 'Attack/Defense lab'},
    'hackthebox.com': {'risk': 20, 'reason': 'Hacking training platform'},
    'tryhackme.com': {'risk': 20, 'reason': 'Security training platform'},
    'xss-game.appspot.com': {'risk': 85, 'reason': 'XSS vulnerable game'},
    'xss-quiz.int21h.jp': {'risk': 85, 'reason': 'XSS challenge site'},
}


SUSPICIOUS_URL_PATTERNS = [
    (r'admin', 30, 'Admin panel detected'),
    (r'login', 15, 'Login page detected'),
    (r'wp-admin', 35, 'WordPress admin detected'),
    (r'phpmyadmin', 60, 'phpMyAdmin detected'),
    (r'\.git', 70, 'Git repository exposed'),
    (r'\.env', 75, 'Environment file exposed'),
    (r'config\.(php|json|yaml|yml)', 60, 'Config file detected'),
    (r'backup', 40, 'Backup files detected'),
    (r'\.sql', 65, 'SQL file exposed'),
    (r'debug', 45, 'Debug mode detected'),
    (r'(^|[\.\/])test([\.\/]|$)', 25, 'Test environment'),
    (r'staging', 35, 'Staging environment'),
    (r'dev\.', 30, 'Development environment'),
    (r'api/.*v[0-9]', 20, 'API endpoint detected'),

    (r'paypal', 70, 'Brand imitation: PayPal'),
    (r'amazon', 65, 'Brand imitation: Amazon'),
    (r'microsoft', 65, 'Brand imitation: Microsoft'),
    (r'apple', 60, 'Brand imitation: Apple'),
    (r'gmail|google', 60, 'Brand imitation: Google/Gmail'),
    (r'icloud', 70, 'Brand imitation: iCloud'),
    (r'netflix', 65, 'Brand imitation: Netflix'),
    (r'steam', 60, 'Brand imitation: Steam'),
    (r'discord', 60, 'Brand imitation: Discord'),
    (r'facebook|faceb00k', 75, 'Brand imitation: Facebook'),
    (r'whatsapp', 70, 'Brand imitation: WhatsApp'),
    (r'instagram', 65, 'Brand imitation: Instagram'),
    (r'dropbox', 60, 'Brand imitation: Dropbox'),
    (r'adobe', 55, 'Brand imitation: Adobe'),
    (r'bank|finance|wallet|blockchain', 45, 'Financial service keyword'),

    (r'verify|secure|update|account|billing', 40, 'Security-themed keyword'),
    (r'login|signin|sign-in|log-in', 30, 'Authentication keyword'),
    (r'webscr|cgi-bin|cmd=_', 45, 'Legacy technical handler (cgi-bin/webscr)'),
    (r'verification|security-check|confirm', 50, 'Urgency-themed phishing trigger'),
    (r'web-validation|account-safe', 50, 'Security-themed deception'),

    (r'com_content|com_user|reset\.html', 65, 'CMS vulnerability signal (potential defacement target)'),
    (r'wp-config|wp-admin|joomla|drupal', 55, 'CMS internal path exposed'),
    (r'index\.php\?option=', 60, 'Joomla vulnerability pattern'),
    (r'hacked|defaced|pwned|team-.*-hacker', 85, 'Defacement keyword detected'),
    (r'upload.*\.php', 75, 'Suspicious shell upload pattern'),
    (r'americanas.*orders', 85, "Brand Imitation: Americanas phishing pattern"),
    (r'americanas.*cart', 80, "Brand Imitation: Americanas phishing pattern"),
    (r'mercadolivre.*orders', 85, "Brand Imitation: Mercado Livre phishing pattern"),
    (r'alibaba.*login', 85, "Brand Imitation: Alibaba phishing pattern"),
    (r'runescape.*weblogin', 85, "Brand Imitation: RuneScape phishing pattern"),
    (r'cutt\.ly/.*|bit\.ly/.*|tinyurl\.com/.*|t\.co/.*|ow\.ly/.*|goo\.gl/.*|is\.gd/.*|v\.gd/.*|rb\.gy/.*', 65, "URL Shortener: Potential redirection risk"),
    (r'unaux\.com', 75, "Suspicious Hosting: Known phishing provider"),
    (r'000webhostapp\.com', 75, "Suspicious Hosting: Free tier often abused"),
    (r'blob\.core\.windows\.net.*', 80, "Suspicious Azure Storage hosting"),
    (r'cloudflare-hosted\.xyz', 60, "Platform Abuse: Cloudflare masked delivery"),
    (r'@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', 85, 'Suspicious: @ Obfuscation in URL'),

    (r'\.exe($|\?)', 90, 'Malicious Payload: Executable file (.exe) detected'),
    (r'\.msi($|\?)', 90, 'Malicious Payload: Installer file (.msi) detected'),
    (r'\.bat($|\?)', 85, 'Malicious Payload: Batch script (.bat) detected'),
    (r'\.scr($|\?)', 90, 'Malicious Payload: Screen saver (.scr) often used for malware'),
    (r'\.vbs($|\?)', 85, 'Malicious Payload: VBS script detected'),
    (r'\.ps1($|\?)', 80, 'Malicious Payload: PowerShell script detected'),
    (r'\.m($|\?)|\.elf($|\?)|\.bin($|\?)|\.sh($|\?)|\.arm\d($|\?)|\.mips($|\?)|\.mpsl($|\?)|\.spc($|\?)|\.x86($|\?)|\.apk($|\?)|\.jar($|\?)|\.ppc($|\?)|\.i($|\?)', 90, 'Malicious Payload: Confirmed malware/dropper extension'),
    (r'/bins/|/arm\d|/mips|/sh4|/mipsel|/x86|/i686|/i586', 85, 'Malicious Payload: IoT/Linux botnet binary path'),
    (r'miner\.js', 85, 'Malicious Payload: Cryptominer script detected'),
    (r'\.zip$|\.rar$|\.7z$|\.iso$', 60, 'Suspicious archive download (check context)'),

    (r'forms\.office\.com/Pages/ResponsePage', 75, 'Platform Abuse: Office Forms phishing'),
    (r'docs\.google\.com/forms/.*/viewform', 75, 'Platform Abuse: Google Forms phishing'),
    (r'onedrive\.live\.com', 75, 'Platform Abuse: OneDrive cloud storage link'),
    (r'sharepoint\.com', 70, 'Platform Abuse: SharePoint link (possible phishing attachment)'),
    (r'pastebin\.com/raw/|gitlab\.com/.*/raw/', 80, 'Platform Abuse: Raw code/config snippet (often malware payload)'),
    (r'drive\.google\.com/uc\?export=download', 85, 'Platform Abuse: Direct Google Drive download (bypass safety scan)'),
    (r'storage\.googleapis\.com', 60, 'Platform Abuse: Google Cloud Storage (generic)'),
    (r'dropbox\.com/s/.*dl=1|dpboxxx?\.com', 75, 'Platform Abuse: Direct Dropbox download or impersonation'),
    (r'freewebs\.com|angelfire\.com|blogspot\.com|tripod\.com|webwavecms\.com', 60, 'Free hosting platform (high abuse indicator)'),

    (r'[^\w]paypal\.|[^\w]wellsfargo\.|[^\w]chase\.|[^\w]ziraat\.|[^\w]sagawa\.|[^\w]fastweb\.', 75, 'Brand name detected in suspicious subdomain context'),
    (r'[\?&].*(paypal|amazon|apple|microsoft|battle\.net|netflix|mufg|caisse|itau|bradesco)', 65, 'Brand name detected inside URL query parameters (phishing redirect?)'),
    (r'recover-|update-|verify-|account-|security-|zaglosuj-|glosowanie-|ebok-', 45, 'Suspicious hyphenated prefix (often phishing)'),

    (r'jSessionID=|authkey=|access_token=', 30, 'Potential session/token exposure or obfuscation'),

    (r'tmpl=component|print=1|layout=default', 40, 'CMS internal view exposure (defacement target)'),
    (r'index\.php\?option=com_', 40, 'CMS component vulnerability surface'),

    (r'malware|phish|trojan|botnet|exploit|keylog|ransomware', 80, 'Malware/phishing keyword detected in URL'),
    (r'cdn-provider\.', 50, 'Infrastructure: Generic CDN provider pattern'),
]


OFFICIAL_BRAND_DOMAINS = {
    'paypal': ['paypal.com', 'paypal.me'],
    'amazon': ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.co.jp', 'amazon.in'],
    'microsoft': ['microsoft.com', 'outlook.com', 'live.com', 'azure.com'],
    'apple': ['apple.com', 'icloud.com', 'me.com'],
    'google': ['google.com', 'gstatic.com', 'googleapis.com', 'gmail.com'],
    'netflix': ['netflix.com'],
    'steam': ['steampowered.com', 'steamcommunity.com'],
    'discord': ['discord.com', 'discord.gg'],
    'facebook': ['facebook.com', 'fb.com', 'messenger.com'],
    'whatsapp': ['whatsapp.com'],
    'instagram': ['instagram.com'],
    'dropbox': ['dropbox.com'],
    'adobe': ['adobe.com'],
    'github': ['github.com', 'github.io', 'githubusercontent.com'],
    'battle.net': ['battle.net', 'blizzard.com'],
    'steampowered': ['steampowered.com', 'steamcommunity.com'],
    'otomoto': ['otomoto.pl'],

    'ebay': ['ebay.com', 'ebay.co.uk', 'ebay.de'],
    'etsy': ['etsy.com'],
    'shopify': ['shopify.com', 'myshopify.com'],
    'walmart': ['walmart.com'],
    'alibaba': ['alibaba.com', 'aliexpress.com'],
    'target': ['target.com'],
    'bestbuy': ['bestbuy.com'],
    'wayfair': ['wayfair.com'],

    'slack': ['slack.com'],
    'zoom': ['zoom.us', 'zoom.com'],
    'notion': ['notion.so', 'notion.com'],
    'trello': ['trello.com'],
    'canva': ['canva.com'],
    'figma': ['figma.com'],
    'airtable': ['airtable.com'],

    'linkedin': ['linkedin.com'],
    'youtube': ['youtube.com', 'youtu.be'],
    'wikipedia': ['wikipedia.org', 'wikimedia.org'],
}


TRUSTED_CONTENT_PROVIDERS = [
    'fortune.com', 'bloomberg.com', 'reuters.com', 'ap.org',
    'yahoo.com', 'google.com', 'microsoft.com', 'github.com',
    'lyricsfreak.com', 'findagrave.com', 'glassdoor.com',
    'extratorrent.cc', 'kat.cr', 'thepiratebay.org'
]


HIGH_RISK_PORTS = {
    21: (70, 'FTP port exposed'),
    22: (40, 'SSH port'),
    23: (85, 'Telnet port (critical)'),
    25: (35, 'SMTP port'),
    3306: (75, 'MySQL port exposed'),
    5432: (75, 'PostgreSQL port exposed'),
    5900: (70, 'VNC port exposed'),
    6379: (80, 'Redis port exposed'),
    27017: (80, 'MongoDB port exposed'),
    8080: (20, 'HTTP alternate port'),
    8888: (50, 'Development/Jupyter port'),
    9200: (75, 'Elasticsearch port exposed'),
    3389: (65, 'RDP port exposed'),
}


SUSPICIOUS_TLDS = [
    ('.ru', 5, 'Russian TLD (contextual signal only)'),
    ('.cn', 5, 'Chinese TLD (contextual signal only)'),
    ('.tk', 15, 'Free TLD: .tk (abuse-prone, contextual signal)'),
    ('.ml', 15, 'Free TLD: .ml (abuse-prone, contextual signal)'),
    ('.ga', 15, 'Free TLD: .ga (abuse-prone, contextual signal)'),
    ('.cf', 15, 'Free TLD: .cf (abuse-prone, contextual signal)'),
    ('.gq', 15, 'Free TLD: .gq (abuse-prone, contextual signal)'),
    ('.onion', 20, 'Tor hidden service (contextual signal)'),
    ('.xyz', 10, 'Low-cost TLD (contextual signal)'),
    ('.top', 10, 'Low-cost TLD (contextual signal)'),
    ('.bid', 10, 'Low-cost TLD (contextual signal)'),
    ('.win', 10, 'Low-cost TLD (contextual signal)'),
]


HOMOGLYPH_MAP: dict = {
    '0': 'o',
    '1': 'l',
    '3': 'e',
    '4': 'a',
    '5': 's',
    '6': 'g',
    '8': 'b',
    '@': 'a',
    '$': 's',
    '!': 'i',
    '|': 'l',
    'і': 'i',
    'a': 'a',
    'е': 'e',
    'о': 'o',
    'р': 'p',
    'у': 'y',

    'à': 'a', 'á': 'a', 'â': 'a', 'ã': 'a', 'ä': 'a', 'å': 'a',
    'è': 'e', 'é': 'e', 'ê': 'e', 'ë': 'e',
    'ì': 'i', 'í': 'i', 'î': 'i', 'ï': 'i',
    'ò': 'o', 'ó': 'o', 'ô': 'o', 'õ': 'o', 'ö': 'o',
    'ù': 'u', 'ú': 'u', 'û': 'u', 'ü': 'u',
    'ñ': 'n', 'ý': 'y', 'ÿ': 'y', 'ç': 'c', 'ð': 'd', 'ß': 'ss',
    'vv': 'w',
    'rn': 'm',
}


TYPOSQUATTING_BRANDS: dict = {
    'google':    ('Google',    85, ['google.com', 'google.co.in', 'google.co.uk', 'googleapis.com', 'gstatic.com', 'gmail.com', 'youtube.com', 'android.com']),
    'paypal':    ('PayPal',    88, ['paypal.com', 'paypal.me', 'paypalobjects.com']),
    'amazon':    ('Amazon',    82, ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.in', 'amazonaws.com', 'amazonpay.com']),
    'microsoft': ('Microsoft', 82, ['microsoft.com', 'outlook.com', 'live.com', 'azure.com', 'bing.com', 'office.com', 'msn.com']),
    'apple':     ('Apple',     83, ['apple.com', 'icloud.com', 'me.com', 'itunes.com', 'applecdn.net']),
    'facebook':  ('Facebook',  85, ['facebook.com', 'fb.com', 'fbcdn.net', 'messenger.com', 'facebook.net']),
    'netflix':   ('Netflix',   80, ['netflix.com', 'nflxvideo.net', 'nflximg.com']),
    'steam':     ('Steam',     80, ['steampowered.com', 'steamcommunity.com', 'steamgames.com']),
    'instagram': ('Instagram', 78, ['instagram.com', 'cdninstagram.com']),
    'twitter':   ('Twitter/X', 75, ['twitter.com', 'x.com', 't.co', 'twimg.com']),
    'whatsapp':  ('WhatsApp',  80, ['whatsapp.com', 'whatsapp.net']),
    'discord':   ('Discord',   78, ['discord.com', 'discord.gg', 'discordapp.com']),
    'dropbox':   ('Dropbox',   75, ['dropbox.com', 'dropboxusercontent.com']),
    'linkedin':  ('LinkedIn',  75, ['linkedin.com', 'licdn.com']),
    'github':    ('GitHub',    72, ['github.com', 'github.io', 'githubusercontent.com', 'githubassets.com']),
    'adobe':     ('Adobe',     72, ['adobe.com', 'adobedtm.com', 'adobelogin.com']),
    'walmart':   ('Walmart',   78, ['walmart.com', 'walmart.ca']),
    'chase':     ('Chase',     85, ['chase.com', 'jpmorgan.com']),
    'bankofamerica': ('Bank of America', 88, ['bankofamerica.com']),
    'wells':     ('Wells Fargo', 85, ['wellsfargo.com']),
    'citibank':  ('Citibank',  85, ['citi.com', 'citibank.com']),

    'chatgpt':   ('ChatGPT / OpenAI', 88, ['chat.openai.com', 'openai.com', 'chatgpt.com']),
    'openai':    ('OpenAI',    85, ['openai.com', 'chat.openai.com', 'api.openai.com']),
    'anthropic': ('Anthropic', 82, ['anthropic.com', 'claude.ai']),
    'claude':    ('Claude / Anthropic', 82, ['claude.ai', 'anthropic.com']),
    'gemini':    ('Google Gemini', 83, ['gemini.google.com', 'bard.google.com']),
    'spotify':   ('Spotify',   78, ['spotify.com', 'spotify.dev', 'spoti.fi']),
    'tiktok':    ('TikTok',   78, ['tiktok.com', 'tiktokv.com']),
    'binance':   ('Binance',  88, ['binance.com', 'binance.us', 'binance.org']),
    'coinbase':  ('Coinbase', 88, ['coinbase.com', 'coinbase.pro']),
    'youtube':   ('YouTube',  82, ['youtube.com', 'youtu.be', 'youtube-nocookie.com', 'youtubei.googleapis.com']),
    'zoom':      ('Zoom',     78, ['zoom.us', 'zoom.com', 'zoomgov.com']),
    'slack':     ('Slack',    75, ['slack.com', 'slack-edge.com']),
}


_TYPOSQUAT_THRESHOLD = 0.72

_MIN_BRAND_LEN = 5


def _check_dns_exists(domain: str, timeout: float = 3.0) -> bool:
    import socket
    try:
        infos = socket.getaddrinfo(domain, None)
        if infos:
            addr = infos[0][4]
            with socket.socket(infos[0][0], socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                try:
                    sock.connect((addr[0], 80))
                except (ConnectionRefusedError, OSError):
                    pass
            return True
        return False
    except (socket.gaierror, socket.herror, OSError):
        return False


def _normalize_homoglyphs(text: str) -> str:
    result = text.lower()

    result = result.replace('vv', 'w').replace('rn', 'm')

    single_map = {k: v for k, v in HOMOGLYPH_MAP.items() if len(k) == 1}
    return ''.join(single_map.get(c, c) for c in result)


def _levenshtein(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (c1 != c2)))
        prev = curr
    return prev[-1]


def _detect_typosquatting(
    domain: str,
    official_domains: list,
) -> tuple:
    label = domain.split('.')[0]


    try:
        decoded_label = label.encode('ascii').decode('idna') if label.startswith('xn--') else label
    except (UnicodeError, UnicodeDecodeError):
        decoded_label = label

    normalized_label = _normalize_homoglyphs(label)
    normalized_decoded = _normalize_homoglyphs(decoded_label)

    digit_stripped = ''.join(c for c in label if not c.isdigit())

    for brand_key, (brand_name, risk_score, brand_official_domains) in TYPOSQUATTING_BRANDS.items():
        if any(domain == od or domain.endswith('.' + od) for od in brand_official_domains):
            continue
        if len(brand_key) < _MIN_BRAND_LEN:
            continue


        if (normalized_label == brand_key or normalized_decoded == brand_key) and label != brand_key:
            return (
                brand_name, float(risk_score),
                f'[T1] TYPOSQUATTING: "{domain}" uses character substitution to impersonate '
                f'{brand_name} (decoded: "{normalized_label}", IDN: "{normalized_decoded}"). '
                f'Classic phishing -- zeros/ones replacing letters.'
            )


        if label.startswith('xn--'):
            ascii_only = ''.join(c for c in normalized_decoded if ord(c) < 128)
            if ascii_only and ascii_only != brand_key:
                idn_dist = _levenshtein(ascii_only, brand_key)
                if idn_dist <= 2 and len(ascii_only) >= _MIN_BRAND_LEN:
                    return (
                        brand_name, float(risk_score),
                        f'[T1] TYPOSQUATTING: "{domain}" is an IDN homograph impersonating '
                        f'{brand_name} (punycode decoded to "{decoded_label}", '
                        f'ASCII-stripped: "{ascii_only}", edit distance: {idn_dist}).'
                    )


        if (brand_key in normalized_label and label != normalized_label) or \
           (brand_key in normalized_decoded and decoded_label != brand_key):
            return (
                brand_name, float(risk_score),
                f'[T1] TYPOSQUATTING: "{domain}" contains brand name "{brand_key}" '
                f'after character decoding (decoded: "{normalized_label}", IDN: "{normalized_decoded}"). '
                f'Likely impersonating {brand_name}.'
            )


        edit_dist = min(_levenshtein(normalized_label, brand_key), _levenshtein(normalized_decoded, brand_key))
        max_allowed = 1 if len(brand_key) <= 6 else 2


        best_norm = normalized_decoded if _levenshtein(normalized_decoded, brand_key) < _levenshtein(normalized_label, brand_key) else normalized_label
        if edit_dist <= max_allowed and len(best_norm) >= _MIN_BRAND_LEN:

            overlap = sum(1 for a, b in zip(sorted(best_norm), sorted(brand_key)) if a == b)
            ratio = overlap / max(len(brand_key), 1)


            if ratio >= 0.65 or (edit_dist == 1 and len(brand_key) >= 5):
                return (
                    brand_name, max(float(risk_score) * 0.90, 70.0),
                    f'[T1] TYPOSQUATTING: "{domain}" is visually similar to {brand_name} '
                    f'(edit distance {edit_dist} after decoding, decoded: "{best_norm}"). '
                    f'Likely typosquatting or letter-scrambling attack.'
                )


        if label != digit_stripped and len(digit_stripped) >= _MIN_BRAND_LEN:
            ds_edit_dist = _levenshtein(digit_stripped, brand_key)
            ds_max = 1 if len(brand_key) <= 6 else 2
            if ds_edit_dist <= ds_max:
                return (
                    brand_name, max(float(risk_score) * 0.85, 65.0),
                    f'[T1] TYPOSQUATTING: "{domain}" contains digit substitution '
                    f'resembling {brand_name} (stripped: "{digit_stripped}", '
                    f'edit distance {ds_edit_dist}). '
                    f'Numeric character replacement is a common phishing technique.'
                )

    return ('', 0.0, '')


class HeuristicRiskDetector:

    def __init__(self):
        self.logger = logger

    def analyze_url(self, target: str, progress_callback=None) -> Tuple[float, List[str], str]:

        if target is not None:
            target = str(target).strip()
        if not target:
            return 0.0, ['No target provided'], 'LOW'

        if '://' not in target and not target.startswith('/'):
            full_url = f"http://{target}"
        else:
            full_url = target

        try:
            parsed = urlparse(full_url)
            domain = parsed.hostname or smart_parse_url(target)
            path = parsed.path
            query = parsed.query
        except Exception:
            domain = smart_parse_url(target)
            path = target
            query = ""


        if not domain:
            return 0.0, ['Could not extract domain from input'], 'LOW'

        original_input = target
        evidence = []
        domain_lower = domain.lower()
        is_trusted_provider = any(p in domain_lower for p in TRUSTED_CONTENT_PROVIDERS)


        from risk_scoring.patches import is_private_or_intranet
        _is_private, _private_reason = is_private_or_intranet(domain_lower)
        if _is_private:
            return 0.0, [
                f'[INFO] INTERNAL / PRIVATE ADDRESS: {_private_reason} '
                'This address is not routable on the public internet. '
                'Risk assessment is not applicable.'
            ], 'LOW'


        _ACADEMIC_GOV_TLDS = (
            '.edu', '.ac.uk', '.ac.in', '.edu.in', '.edu.au', '.ac.nz',
            '.ac.za', '.edu.pk', '.edu.bd', '.edu.my', '.edu.sg',
            '.gov', '.gov.in', '.gov.uk', '.gov.au', '.gov.nz',
            '.mil', '.int', '.nato.int',
        )
        _is_academic_or_gov = any(
            domain_lower == tld.lstrip('.') or domain_lower.endswith(tld)
            for tld in _ACADEMIC_GOV_TLDS
        )
        if _is_academic_or_gov:
            evidence.append(
                '[INFO] INSTITUTIONAL DOMAIN: Registered under an academic, '
                'government, or international organisation TLD. '
                'Infrastructure complexity and path keyword penalties are suppressed.'
            )


        from risk_scoring.patches import is_trusted_domain
        _domain_is_trusted = is_trusted_domain(domain_lower)
        if _domain_is_trusted:
            evidence.append(
                '[INFO] TRUSTED DOMAIN: This domain is on your organisation\'s '
                'trusted domain whitelist (config/trusted_domains.txt). '
                'Infrastructure complexity scoring is skipped.'
            )


        try:
            domain_exists = _check_dns_exists(domain_lower)
        except Exception as _dns_err:
            logger.debug(f"DNS check failed: {_dns_err}")
            domain_exists = False

        if not domain_exists:
            evidence.append(
                "[INFO] DOMAIN UNREACHABLE: DNS resolution failed for this domain. "
                f"The domain '{domain_lower}' does not appear to be active or reachable. "
                "Analysis is based on structural and reputation indicators only."
            )


        tier1_scores: List[float] = []
        tier2_scores: List[float] = []
        tier3_scores: List[float] = []


        _is_https = full_url.lower().startswith('https://')
        if _is_https:
            from risk_scoring.patches import check_ssl_certificate
            _ssl_score, _ssl_tier, _ssl_ev = check_ssl_certificate(domain_lower, 443)
            if _ssl_score > 0 and _ssl_ev:
                tier2_scores.append(_ssl_score)
                evidence.append(_ssl_ev)
            elif _ssl_ev:
                evidence.append(_ssl_ev)


        from risk_scoring.patches import check_domain_age
        _age_delta, _age_tier, _age_ev = check_domain_age(domain_lower)
        if _age_ev:
            if _age_tier == 'T1' and _age_delta > 0:
                tier1_scores.append(_age_delta)
                evidence.append(_age_ev)
            elif _age_tier == 'T2' and _age_delta > 0:
                tier2_scores.append(_age_delta)
                evidence.append(_age_ev)
            else:
                evidence.append(_age_ev)


        if progress_callback: progress_callback(1)


        try:
            from risk_scoring.reputation_aggregator import check_reputation
            reputation = check_reputation(full_url)
            if reputation.is_unsafe:
                tier1_scores.append(reputation.tier1_score)
                for ev in reputation.evidence_strings:
                    if ev:
                        evidence.append(ev)
            elif reputation.fully_checked and reputation.vt_result is not None:

                ev = reputation.vt_result.evidence_string
                if ev:
                    tier2_scores.append(min(reputation.vt_result.tier1_score, 45.0))
                    evidence.append(ev)
        except Exception as _rep_err:
            logger.debug(f"Reputation check error (non-fatal): {_rep_err}")


        try:
            from risk_scoring.patches import check_urlhaus
            _uh_score, _uh_tier, _uh_ev = check_urlhaus(full_url)
            if _uh_score > 0 and _uh_ev:
                tier1_scores.append(_uh_score)
                evidence.append(_uh_ev)
        except Exception as _uh_err:
            logger.debug(f"URLhaus check error (non-fatal): {_uh_err}")


        if domain_exists:
            try:
                from risk_scoring.patches import scan_html_content
                _html_findings = scan_html_content(full_url, domain_lower)
                for _h_score, _h_tier, _h_ev in _html_findings:
                    if _h_score > 0 and _h_ev:
                        if _h_tier == 'T1':
                            tier1_scores.append(_h_score)
                        else:
                            tier2_scores.append(_h_score)
                        evidence.append(_h_ev)
                    elif _h_ev and _h_ev.startswith('[INFO]'):
                        evidence.append(_h_ev)
            except Exception as _html_err:
                logger.debug(f"HTML content scan error (non-fatal): {_html_err}")


        if progress_callback: progress_callback(2)


        try:
            ts_brand, ts_score, ts_reason = _detect_typosquatting(
                domain_lower,
                list(OFFICIAL_BRAND_DOMAINS.values()),
            )
            if ts_score > 0 and ts_reason:
                tier1_scores.append(ts_score)
                evidence.append(ts_reason)
        except Exception as _ts_err:
            logger.debug(f"Typosquatting check error (non-fatal): {_ts_err}")

        from risk_scoring.safety_signals import get_safety_analyser
        safety = get_safety_analyser().assess(
            domain=domain, port=443, path=path, url=original_input
        )
        confidence_mod = safety.confidence_modifier


        for vuln_domain, info in KNOWN_VULNERABLE_DOMAINS.items():
            if vuln_domain in domain or domain.endswith(vuln_domain):
                tier1_scores.append(float(info['risk']))
                evidence.append(f"[T1] KNOWN VULNERABILITY: {info['reason']}")
                self.logger.info(f"Known vulnerable domain detected: {domain}")


        search_target = original_input

        for pattern, risk, reason in SUSPICIOUS_URL_PATTERNS:
            match_target = path if 'Malicious Payload' in reason else search_target


            if _is_academic_or_gov:
                _soft_patterns = [
                    'Authentication keyword', 'Security-themed keyword',
                    'Financial service keyword', 'Urgency-themed phishing trigger',
                    'Security-themed deception', 'Admin panel detected',
                    'Login page detected', 'Suspicious hyphenated prefix',
                    'Backup files detected', 'Debug mode detected',
                    'Test environment', 'Staging environment',
                    'Development environment', 'API endpoint detected',
                    'Infrastructure: Generic CDN provider',
                ]
                if any(soft in reason for soft in _soft_patterns):
                    continue

            if re.search(pattern, match_target, re.IGNORECASE):


                is_self_reference = False
                if any(k in reason.lower() for k in ['brand imitation', 'typosquatting',
                                                      'authentication keyword',
                                                      'security-themed keyword']):

                    for brand_kw, owned_domains in OFFICIAL_BRAND_DOMAINS.items():
                        if brand_kw in reason.lower() or brand_kw in str(pattern).lower():
                            for owned in owned_domains:
                                if domain_lower == owned or domain_lower.endswith('.' + owned):
                                    is_self_reference = True
                                    break
                            if is_self_reference:
                                break


                    if not is_self_reference:
                        domain_label = domain_lower.split('.')[0]
                        try:
                            kw_in_pattern = str(pattern).strip(r'\b').split('|')[0]
                            kw_in_pattern = re.sub(r'[\\\^\$\*\+\?\(\)\[\]\{\}\|]', '', kw_in_pattern)
                            if kw_in_pattern and kw_in_pattern.lower() == domain_label:
                                is_self_reference = True
                        except Exception:
                            pass

                if is_self_reference:
                    continue


                is_tier1_pattern = any(x in reason for x in [
                    'Malicious Payload', 'Exploit', 'Shell', 'Hacked', 'Defacement',
                    'Brand imitation', 'brand imitation',
                    'Phishing', 'credential', 'Credential',
                    'URL Shortener', 'Suspicious Hosting', 'Platform Abuse',
                    'Obfuscation in URL', 'Cryptominer',
                    'malware', 'phishing keyword',
                ])
                if is_tier1_pattern:
                    tier1_scores.append(float(risk))
                    evidence.append(f"[T1] Pattern Detected: {reason}")
                else:
                    tier2_scores.append(float(risk))
                    evidence.append(f"[T2] Pattern Detected: {reason}")


        for tld, risk, reason in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                tier3_scores.append(float(risk))
                evidence.append(f"[T3] TLD Context: {reason}")


        if self._is_ip_address(domain):

            malware_exts = ['.arm', '.mips', '.bin', '.sh', '.mpsl', '.spc', '.x86', '.i686', '.i586']
            if any(x in original_input.lower() for x in malware_exts + ['/bins/']):
                tier1_scores.append(90)
                evidence.append("[T1] CRITICAL: IP-based URL carrying detected malware binary path")
            else:

                try:
                    import socket
                    rdns = socket.getfqdn(domain)
                    has_rdns = rdns != domain and '.' in rdns
                except Exception:
                    has_rdns = False


                sensitive_kws = ['login', 'admin', 'signin', 'account', 'pay',
                                 'checkout', 'password', 'auth', 'panel']
                has_sensitive = any(kw in original_input.lower() for kw in sensitive_kws)

                if has_rdns:

                    tier3_scores.append(10)
                    evidence.append(f"[T3] Direct IP access with valid reverse DNS ({rdns})")
                elif has_sensitive:

                    tier2_scores.append(30)
                    evidence.append("[T2] Raw IP address with sensitive service path (no reverse DNS)")
                else:

                    tier3_scores.append(15)
                    evidence.append("[T3] Direct IP access (no domain name, no reverse DNS)")


        if re.search(r'\d{5,}', domain):
            tier1_scores.append(45)
            evidence.append("[T1] Suspicious: Long numeric sequence in domain (likely DGA)")


        domain_parts = domain_lower.split('.')
        if len(domain_parts) >= 2:
            sld = domain_parts[-2]
            if len(sld) >= 6:
                sld_entropy = calculate_entropy(sld)
                has_mixed_chars = bool(re.search(r'[a-z]', sld) and re.search(r'\d', sld))
                if sld_entropy > 3.0 and has_mixed_chars:
                    tier1_scores.append(50)
                    evidence.append(
                        f"[T1] Suspicious: Domain name '{sld}' has high entropy "
                        f"({sld_entropy:.2f}) with mixed characters (likely DGA/auto-generated)"
                    )


        explicit_http = original_input.lower().startswith('http://') and not original_input.lower().startswith('http://localhost')
        if explicit_http:
            sensitive_path_keywords = ['login', 'signin', 'account', 'pay', 'checkout',
                                      'cart', 'order', 'billing', 'password', 'register',
                                      'submit', 'transfer', 'verify', 'secure', 'banking',
                                      'admin', 'auth', 'panel', 'keys', 'shell', 'cmd', 'api']
            path_lower = path.lower() if path else ''
            has_sensitive_path = any(kw in path_lower for kw in sensitive_path_keywords)

            if has_sensitive_path:
                tier2_scores.append(55)
                evidence.append(
                    "[T2] INSECURE CONNECTION: Site uses unencrypted HTTP with "
                    "sensitive content path. Data in transit (credentials, payment info) "
                    "is exposed to interception."
                )
            else:
                tier2_scores.append(30)
                evidence.append(
                    "[T2] INSECURE CONNECTION: Site uses unencrypted HTTP. "
                    "No transport-layer encryption -- data in transit is visible to "
                    "network observers. Modern sites should use HTTPS."
                )


        if len(domain) > 50:
            tier2_scores.append(25)
            evidence.append("[T2] Suspicious: Very long domain name")


        subdomain_count = domain.count('.')
        if subdomain_count > 4:
            tier2_scores.append(40)
            evidence.append(f"[T2] Suspicious: {subdomain_count} subdomain levels")


        if path and len(path) > 1:
            segments = [s for s in path.split('/') if s]
            for seg in segments:
                clean_seg = seg
                if '.' in seg:
                    clean_seg = seg.rpartition('.')[0]
                if len(clean_seg) > 15:
                    if '-' in clean_seg and clean_seg.count('-') > 3:
                        continue
                    entropy = calculate_entropy(clean_seg)
                    domain_str = str(domain)
                    tld = domain_str.split('.')[-1] if '.' in domain_str else ""
                    is_suspicious_tld = any(t[0] == f'.{tld}' for t in SUSPICIOUS_TLDS)
                    if entropy > 4.5:
                        penalty = 85 if is_suspicious_tld else 40

                        if is_suspicious_tld:
                            tier1_scores.append(float(penalty))
                            evidence.append(f"[T1] High-Entropy Path Segment: '{clean_seg}' (Entropy: {entropy:.2f})")
                        else:
                            tier2_scores.append(float(penalty))
                            evidence.append(f"[T2] High-Entropy Path Segment: '{clean_seg}' (Entropy: {entropy:.2f})")
                    elif entropy > 3.8:
                        penalty = 40 if is_suspicious_tld else 15
                        tier2_scores.append(float(penalty))
                        evidence.append(f"[T2] Suspicious Randomness: '{clean_seg}' (Entropy: {entropy:.2f})")


        if not _is_academic_or_gov and not _domain_is_trusted:
            complexity_score, complexity_reason = self._assess_infrastructure_complexity(domain, path)
            if complexity_score > 0:
                tier3_scores.append(complexity_score)
                evidence.append(f"[T3] Infrastructure Complexity: {complexity_reason}")
        else:
            complexity_score = 0.0


        all_scores = tier1_scores + tier2_scores + tier3_scores


        _genuine_t1 = [
            s for s, e in zip(
                tier1_scores,
                [ev for ev in evidence if '[T1]' in ev]
            )
        ]
        _has_genuine_t1 = any(
            any(kw in ev for kw in [
                'REPUTATION', 'TYPOSQUATTING', 'Malicious Payload', 'URLHAUS',
                'DGA', 'Newly Registered', 'NEWLY REGISTERED'
            ])
            for ev in evidence if '[T1]' in ev
        )
        if _has_genuine_t1 and len(all_scores) >= 3:
            max_r = float(max(tier1_scores))
            compound_bonus = min(max_r + 10.0, 90.0)
            tier1_scores.append(compound_bonus)
            evidence.append("360-DEGREE AUDIT: Compound confirmed threat indicators")


        unique_categories = set()
        for e in evidence:
            if 'Pattern' in e: unique_categories.add('pattern')
            if 'TLD' in e: unique_categories.add('tld')
            if 'Entropy' in e or 'Randomness' in e: unique_categories.add('obfuscation')
            if 'IP' in e: unique_categories.add('ip')
            if 'Complexity' in e: unique_categories.add('complexity')
            if 'DGA' in e: unique_categories.add('dga')


        def _tier_score(scores: List[float]) -> float:
            if not scores:
                return 0.0
            mx = float(max(scores))
            avg = float(sum(scores)) / len(scores)
            return (mx * 0.7) + (avg * 0.3)

        t1_score = _tier_score(tier1_scores)
        t2_score = _tier_score(tier2_scores)
        t3_score = _tier_score(tier3_scores)

        import math

        if tier1_scores:


            partial_mod = math.sqrt(confidence_mod)
            final_score = t1_score + (t2_score * partial_mod * 0.3) + (t3_score * confidence_mod * 0.1)


            _confirmed_t1_ev = [
                e for e in evidence if '[T1]' in e and any(
                    kw in e for kw in ['REPUTATION', 'TYPOSQUATTING', 'URLHAUS',
                                       'Malicious Payload', 'DGA', 'NEWLY REGISTERED']
                )
            ]
            if len(unique_categories) >= 2 and final_score < 75 and _confirmed_t1_ev:
                final_score += 12.0
                evidence.append(f"SIGNAL AGREEMENT: Multi-category risk confirmed ({', '.join(unique_categories)})")


            if any('Malicious Payload' in e for e in evidence) and final_score < 90:
                final_score = 90.0
                evidence.append("RISK OVERRIDE: Confirmed malware patterns take precedence")


            final_score = max(final_score, float(max(tier1_scores)))

        elif tier2_scores:

            partial_mod = math.sqrt(confidence_mod)
            final_score = (t2_score * partial_mod) + (t3_score * confidence_mod * 0.3)

            if len(unique_categories) >= 2 and final_score < 75:
                final_score += 10.0
                evidence.append(f"SIGNAL AGREEMENT: Multi-category risk detected ({', '.join(unique_categories)})")


            if complexity_score > 0:
                final_score = max(final_score, complexity_score * 0.92)

        else:

            if tier3_scores:
                final_score = t3_score * confidence_mod

                if complexity_score > 0:
                    final_score = max(final_score, complexity_score * 0.92)
            else:
                final_score = 15.0
                evidence.append("Baseline risk: No significant anomalies found")

        evidence.append(
            f"Confidence: {confidence_mod:.2f} (safety={safety.safety_score:.0f}/100) "
            f"[T1={len(tier1_scores)} T2={len(tier2_scores)} T3={len(tier3_scores)}]"
        )
        evidence.append(
            f"Data sources checked at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )


        rounded_total = float(final_score)
        if rounded_total >= 75:
            severity = 'CRITICAL'
        elif rounded_total >= 50:
            severity = 'HIGH'
        elif rounded_total >= 30:
            severity = 'MEDIUM'
        else:
            severity = 'LOW'


        from risk_scoring.threat_escalation import evaluate_escalation
        escalation = evaluate_escalation(domain, rounded_total, severity, evidence)

        if escalation.triggered:
            severity = escalation.escalated_severity
            evidence.append(f"THREAT ESCALATION: {escalation.reasoning}")
            evidence.append(f"Rules matched: {', '.join(escalation.rules_matched)}")


        assumption_flags = []
        for e in evidence:
            if '[T3] TLD Context' in e:
                assumption_flags.append('TLD-geography')
            if 'complex infrastructure' in e.lower() and 'Infrastructure Complexity' in e:
                assumption_flags.append('brand-name-complexity')
        if assumption_flags and not tier1_scores and len(tier2_scores) == 0:
            evidence.append(
                f"[DIAGNOSTIC] assumption-based classification: "
                f"decision influenced by {', '.join(set(assumption_flags))} "
                f"rather than observed behavioral evidence"
            )

        return min(rounded_total, 100.0), evidence, severity

    def analyze_port(self, port: int) -> Tuple[float, str]:
        if port in HIGH_RISK_PORTS:
            risk, reason = HIGH_RISK_PORTS[port]
            return risk, reason


        if port in [80, 443]:
            return 0, "Standard web port"


        if port > 8000:
            return 25, f"Non-standard port {port}"

        return 10, f"Port {port}"

    def analyze_url_raw(self, target: str) -> Tuple[float, List[str], str]:

        if target is not None:
            target = str(target).strip()
        if not target:
            return 0.0, ['No target provided'], 'LOW'

        if '://' not in target and not target.startswith('/'):
            full_url = f"http://{target}"
        else:
            full_url = target

        try:
            parsed = urlparse(full_url)
            domain = parsed.hostname or smart_parse_url(target)
            path = parsed.path
            query = parsed.query
        except Exception:
            domain = smart_parse_url(target)
            path = target
            query = ""


        if not domain:
            return 0.0, ['Could not extract domain from input'], 'LOW'

        original_input = target
        evidence = []
        risk_scores: List[float] = []
        domain_lower = domain.lower()


        for vuln_domain, info in KNOWN_VULNERABLE_DOMAINS.items():
            if vuln_domain in domain or domain.endswith(vuln_domain):
                risk_scores.append(float(info['risk']))
                evidence.append(f"KNOWN VULNERABILITY: {info['reason']}")


        search_target = original_input
        for pattern, risk, reason in SUSPICIOUS_URL_PATTERNS:
            match_target = path if 'Malicious Payload' in reason else search_target
            if re.search(pattern, match_target, re.IGNORECASE):

                is_official = False
                for brand, official_domains in OFFICIAL_BRAND_DOMAINS.items():
                    if brand.lower() in reason.lower():
                        if any(off in domain or domain.endswith(off) for off in official_domains):
                            is_official = True
                            break

                is_false_positive = False
                if any(k in reason.lower() for k in ['brand imitation', 'typosquatting']):
                    if is_official:
                        is_false_positive = True

                if not is_false_positive:
                    risk_scores.append(float(risk))
                    evidence.append(f"Pattern Detected: {reason}")


        for tld, risk, reason in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                risk_scores.append(float(risk))
                evidence.append(f"TLD Risk: {reason}")


        if self._is_ip_address(domain):
            risk_scores.append(35)
            evidence.append("Direct IP access (no domain name)")
            malware_exts = ['.arm', '.mips', '.bin', '.sh', '.mpsl', '.spc', '.x86', '.i686', '.i586']
            if any(x in original_input.lower() for x in malware_exts + ['/bins/']):
                risk_scores.append(90)
                evidence.append("CRITICAL: IP-based URL carrying detected malware binary path")


        if len(domain) > 50:
            risk_scores.append(25)
            evidence.append("Suspicious: Very long domain name")


        subdomain_count = domain.count('.')
        if subdomain_count > 4:
            risk_scores.append(40)
            evidence.append(f"Suspicious: {subdomain_count} subdomain levels")


        if re.search(r'\d{5,}', domain):
            risk_scores.append(45)
            evidence.append("Suspicious: Long numeric sequence in domain (likely DGA)")


        if path and len(path) > 1:
            segments = [s for s in path.split('/') if s]
            for seg in segments:
                clean_seg = seg
                if '.' in seg:
                    clean_seg = seg.rpartition('.')[0]
                if len(clean_seg) > 15:
                    if '-' in clean_seg and clean_seg.count('-') > 3:
                        continue
                    entropy = calculate_entropy(clean_seg)
                    domain_str = str(domain)
                    tld = domain_str.split('.')[-1] if '.' in domain_str else ""
                    is_suspicious_tld = any(t[0] == f'.{tld}' for t in SUSPICIOUS_TLDS)
                    if entropy > 4.5:
                        penalty = 85 if is_suspicious_tld else 40
                        risk_scores.append(float(penalty))
                        evidence.append(f"High-Entropy Path Segment: '{clean_seg}' (Entropy: {entropy:.2f})")
                    elif entropy > 3.8:
                        penalty = 40 if is_suspicious_tld else 15
                        risk_scores.append(float(penalty))
                        evidence.append(f"Suspicious Randomness: '{clean_seg}' (Entropy: {entropy:.2f})")


        complexity_score, complexity_reason = self._assess_infrastructure_complexity(domain, path)
        if complexity_score > 0:
            risk_scores.append(complexity_score)
            evidence.append(f"Infrastructure Complexity: {complexity_reason}")


        if len(risk_scores) >= 3:
            max_r = float(max(risk_scores))
            risk_scores.append(min(max_r + 20.0, 95.0))
            evidence.append("360-DEGREE AUDIT: Compound threat indicators found")


        if not risk_scores:
            risk_scores.append(15)
            evidence.append("Baseline risk: No significant anomalies found")


        if risk_scores:
            max_score = float(max(risk_scores))
            avg_score = float(sum(risk_scores)) / len(risk_scores)
            final_score = (max_score * 0.7) + (avg_score * 0.3)
        else:
            final_score = 10.0


        unique_categories = set()
        for e in evidence:
            if 'Pattern' in e: unique_categories.add('pattern')
            if 'TLD' in e: unique_categories.add('tld')
            if 'Entropy' in e or 'Randomness' in e: unique_categories.add('obfuscation')
            if 'IP' in e: unique_categories.add('ip')
            if 'Complexity' in e: unique_categories.add('complexity')
        if len(unique_categories) >= 2 and final_score < 75:
            final_score += 15.0
            evidence.append(f"SIGNAL AGREEMENT: Multi-category risk detected ({', '.join(unique_categories)})")


        if any('Malicious Payload' in e for e in evidence):
            if final_score < 90:
                final_score = 90.0
                evidence.append("RISK OVERRIDE: Confirmed malware patterns take precedence")

        rounded_total = float(final_score)
        if rounded_total >= 75:
            severity = 'CRITICAL'
        elif rounded_total >= 50:
            severity = 'HIGH'
        elif rounded_total >= 30:
            severity = 'MEDIUM'
        else:
            severity = 'LOW'

        return min(rounded_total, 100.0), evidence, severity

    def _assess_infrastructure_complexity(self, domain: str, path: str = "") -> Tuple[float, str]:
        domain_lower = domain.lower()


        try:
            from risk_scoring.patches import is_trusted_domain
            if is_trusted_domain(domain_lower):
                return 0.0, "Trusted domain -- complexity scoring skipped (see trusted_domains.txt)"
        except Exception:
            pass

        reasons = []
        score = 0.0


        cdn_indicators = ['cdn', 'static', 'assets', 'media', 'images', 'cache']
        if any(ind in domain_lower for ind in cdn_indicators):
            score += 8.0
            reasons.append("CDN pattern")


        service_prefixes = ['api', 'app', 'mail', 'auth', 'login', 'admin',
                           'dashboard', 'console', 'portal', 'accounts']
        subdomain_parts = domain_lower.split('.')
        if len(subdomain_parts) > 2:
            prefix = subdomain_parts[0]
            if prefix in service_prefixes:
                score += 12.0
                reasons.append(f"multi-service ({prefix})")


        commerce_keywords = ['shop', 'store', 'pay', 'checkout', 'cart', 'order',
                            'billing', 'invoice', 'marketplace']
        fintech_keywords = ['bank', 'finance', 'capital', 'trade', 'invest',
                           'credit', 'lending', 'insurance', 'wallet']
        if any(kw in domain_lower for kw in commerce_keywords):
            score += 18.0
            reasons.append("e-commerce infrastructure")
        elif any(kw in domain_lower for kw in fintech_keywords):
            score += 18.0
            reasons.append("financial service infrastructure")


        saas_keywords = ['cloud', 'platform', 'service', 'saas', 'hub', 'forge',
                        'suite', 'workspace', 'enterprise']
        if any(kw in domain_lower for kw in saas_keywords):
            score += 12.0
            reasons.append("SaaS/platform complexity")


        complex_infra_patterns = [

            ('amazon', 35), ('shopify', 35), ('ebay', 33), ('etsy', 33),
            ('walmart', 33), ('alibaba', 35),

            ('stripe', 38), ('paypal', 38), ('square', 35), ('plaid', 35),
            ('coinbase', 38),

            ('salesforce', 33), ('hubspot', 33), ('atlassian', 33),
            ('slack', 30), ('zoom', 30), ('twilio', 33),
            ('zendesk', 30), ('intercom', 30), ('datadog', 30),
            ('snowflake', 33), ('databricks', 33), ('confluent', 33),
            ('servicenow', 33),

            ('booking', 35), ('airbnb', 35), ('expedia', 35),
            ('uber', 35), ('lyft', 33), ('tripadvisor', 30),

            ('aws.amazon', 35), ('azure', 33), ('googleapis', 33),
        ]

        for pattern, complexity_val in complex_infra_patterns:
            if pattern in domain_lower:

                score = max(score, float(complexity_val))
                reasons.append(f"complex infrastructure ({pattern})")
                break


        dot_count = domain_lower.count('.')
        if dot_count >= 3:
            score += 5.0
            reasons.append(f"{dot_count}-level domain hierarchy")


        final_score = min(score, 45.0)

        if final_score > 0:
            return final_score, "; ".join(reasons)
        return 0.0, ""

    def _is_ip_address(self, domain: str) -> bool:
        parts = domain.split('.')
        if len(parts) != 4:
            return False
        return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)

    def get_complete_analysis(
        self,
        target: str,
        port: int = 443,
        additional_context: Optional[Dict] = None,
        progress_callback=None
    ) -> Dict[str, Any]:


        if target is None:
            target = ""
        target = str(target).strip()
        if not target:
            return {
                'target': target, 'port': port, 'risk_score': 0.0,
                'risk_level': 'LOW', 'confidence': 0.0,
                'reasoning': 'No target provided.',
                'evidence': ['No target provided'], 'analysis_type': 'inconclusive',
                'timestamp': datetime.now().isoformat(),
                'details': {'url_risk': 0.0, 'port_risk': 0.0,
                            'indicators_found': 0, 'confidence_modifier': 0.0}
            }

        # --- Active Title & Reachability Check ---
        import requests
        import re
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        page_title = "Unknown"
        is_unreachable = False
        unreachable_reason = ""
        
        test_url = target if "://" in target else "https://" + target
        try:
            resp = requests.get(test_url, timeout=4, verify=False, allow_redirects=True)
            if resp.status_code == 200:
                match = re.search(r'<title[^>]*>([^<]+)</title>', resp.text, re.IGNORECASE)
                if match:
                    page_title = match.group(1).strip()
                else:
                    page_title = "No Title Provided"
            else:
                is_unreachable = True
                unreachable_reason = f"HTTP {resp.status_code}"
                page_title = f"Unreachable ({unreachable_reason})"
        except requests.exceptions.RequestException:
            # Fallback to http if https fails
            try:
                test_url = "http://" + target.replace("https://", "")
                resp = requests.get(test_url, timeout=4, verify=False, allow_redirects=True)
                if resp.status_code == 200:
                    match = re.search(r'<title[^>]*>([^<]+)</title>', resp.text, re.IGNORECASE)
                    if match:
                        page_title = match.group(1).strip()
                    else:
                        page_title = "No Title Provided"
                else:
                    is_unreachable = True
                    unreachable_reason = f"HTTP {resp.status_code}"
                    page_title = f"Unreachable ({unreachable_reason})"
            except requests.exceptions.RequestException as e:
                is_unreachable = True
                unreachable_reason = "Connection Failed / DNS Resolution Error"
                page_title = "Unreachable (Connection Error)"

        port_risk, port_reason = self.analyze_port(port)

        if is_unreachable:
            # We add unreachable evidence but do not bypass ML models!
            evidence_unreachable = [
                f"Connection Status: UNREACHABLE",
                f"Reason: {unreachable_reason}",
                "Behavior: Target refused connection or timed out",
                f"[DIAGNOSTIC] Address Context: {page_title}"
            ]
            port_risk = max(port_risk, 30.0) # Small penalty for unreachability
            
        from urllib.parse import unquote as _unquote
        target = _unquote(target)

        try:
            _result = self.analyze_url(target, progress_callback=progress_callback)
        except Exception as _exc:
            logger.warning(f"analyze_url raised exception for '{target[:80]}': {_exc}")
            _result = None

        if _result is None or not isinstance(_result, tuple) or len(_result) != 3:
            return {
                'target': target, 'port': port, 'risk_score': 0.0,
                'risk_level': 'INCONCLUSIVE', 'confidence': 0.0,
                'reasoning': 'Analysis could not be completed for this input.',
                'evidence': [f'Input produced no parseable result: {target[:120]}'],
                'analysis_type': 'inconclusive',
                'timestamp': datetime.now().isoformat(),
                'details': {'url_risk': 0.0, 'port_risk': float(port_risk),
                            'indicators_found': 0, 'confidence_modifier': 0.0}
            }

        risk, evidence, severity = _result
        
        if is_unreachable:
            evidence.extend(evidence_unreachable)
            evidence.append("[HEURISTIC] Domain unreachable, applying +30 risk penalty.")
            risk = max(risk, 30.0)

        if port_risk > 0:
            evidence.append(f"Port Risk: {port_reason}")


        combined_risk = max(risk, port_risk)


        if combined_risk >= 75:
            base_severity = 'CRITICAL'
        elif combined_risk >= 50:
            base_severity = 'HIGH'
        elif combined_risk >= 30:
            base_severity = 'MEDIUM'
        else:
            base_severity = 'LOW'


        _SEV_ORDER = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}
        final_severity = severity

        if _SEV_ORDER.get(base_severity, 0) > _SEV_ORDER.get(final_severity, 0):
            final_severity = base_severity

        severity = final_severity


        confidence_val = 0.5
        for e in evidence:
            if e.startswith("Confidence:"):
                try:
                    confidence_val = float(e.split(":")[1].strip().split(" ")[0])
                except (ValueError, IndexError):
                    pass
                break


        

        # -- Tier 2 & Tier 3 ML Signals -------------------------------------
        _ts_score = 0.0
        _t1_count = sum(1 for ev in evidence if ev.startswith('[T1]'))
        for ev in evidence:
            if '[T1] TYPOSQUATTING' in ev:
                import re as _re2
                _tsm = _re2.search(r'\b(\d{2,3}\.\d)', ev)
                if _tsm:
                    _ts_score = float(_tsm.group(1))
                break

        try:
            from ml_models.tier2_connector import get_tier2_signal
            t2_signal = get_tier2_signal(
                url=target,
                heuristic_score=combined_risk,
                heuristic_severity=severity,
                typosquat_score=_ts_score,
                tier1_count=_t1_count,
            )
            _sev_ord = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}
            if t2_signal.score_modifier != 0 and t2_signal.models_available:
                combined_risk = min(max(combined_risk + t2_signal.score_modifier, 0.0), 100.0)
            _t2_pred = (
                t2_signal.predicted_severity
                if isinstance(t2_signal.predicted_severity, str)
                else {0: 'LOW', 1: 'MEDIUM', 2: 'HIGH', 3: 'CRITICAL'}.get(
                    t2_signal.predicted_severity, 'LOW'
                )
            )
            if _sev_ord.get(_t2_pred, 0) > _sev_ord.get(severity, 0) and t2_signal.confidence > 0.60:
                severity = _t2_pred
            if t2_signal.evidence_string:
                evidence.append(t2_signal.evidence_string)
        except Exception as _t2_err:
            logger.debug(f"Tier 2 inference error (non-fatal): {_t2_err}")

        try:
            from ml_models.tier3_connector import get_tier3_signal
            t3_signal = get_tier3_signal(
                url=target,
                heuristic_score=combined_risk,
                heuristic_severity=severity,
                typosquat_score=_ts_score,
                tier1_count=_t1_count,
            )
            if t3_signal.modifier_applied > 0:
                combined_risk = min(combined_risk + t3_signal.modifier_applied, 100.0)
            if t3_signal.evidence_string:
                evidence.append(t3_signal.evidence_string)
        except Exception as _t3_err:
            logger.debug(f"Tier 3 inference error (non-fatal): {_t3_err}")

        # -- Graph Analysis Integration -------------------------------------
        try:
            from graph_analysis.graph_connector import update_graph_and_get_risk
            from urllib.parse import urlparse
            import socket
            
            raw_host = urlparse(target if '://' in target else f'http://{target}').hostname or target
            fb_domain = raw_host.lower().lstrip('www.')
            
            # Simple IP resolution
            resolved_ip = None
            try:
                resolved_ip = socket.gethostbyname(fb_domain)
            except Exception:
                pass
                
            # We don't have active ASN resolution here without heavy external API dependencies
            # so we map Domain <-> IP for the graph
            graph_risk = update_graph_and_get_risk(fb_domain, ip=resolved_ip, initial_risk=combined_risk)
            
            # If the graph identifies this as a highly-connected risk component, escalate
            if graph_risk > 50.0 and combined_risk < 100.0:
                modifier = min(15.0, graph_risk * 0.2) # Max +15 modifier from graph
                combined_risk = min(combined_risk + modifier, 100.0)
                evidence.append(f"[GRAPH] Propagated risk from connected infrastructure: {graph_risk:.1f} -> ESCALATION (+{modifier:.0f})")
                
        except Exception as _graph_err:
            logger.debug(f"Graph integration error: {_graph_err}")

        # Re-derive severity after ML modifiers applied
        if combined_risk >= 75:
            severity = 'CRITICAL'
        elif combined_risk >= 50:
            severity = 'HIGH'
        elif combined_risk >= 30:
            severity = 'MEDIUM'
        else:
            severity = 'LOW'
        # -------------------------------------------------------------------

        # -- Analyst Feedback Override Interception (Operational Feedback Loops) --
        try:
            from portal.core.feedback import FeedbackEngine
            suppressed = FeedbackEngine.get_suppressed_signals(target)
            if suppressed:
                filtered_evidence = []
                suppressed_count = 0
                for ev in evidence:
                    matched = False
                    for sig in suppressed:
                        if sig in ev.upper() or (sig == "TYPOSQUATTING" and "TYPO" in ev.upper()) or (sig == "HOMOGLYPH" and "HOMO" in ev.upper()):
                            matched = True
                            break
                    if matched:
                        suppressed_count += 1
                    else:
                        filtered_evidence.append(ev)
                
                if suppressed_count > 0:
                    evidence = filtered_evidence
                    evidence.append(f"[FEEDBACK_LOOP] {suppressed_count} heuristic signal(s) suppressed by analyst override.")
                    # Calibrate risk score downward
                    combined_risk = max(0.0, combined_risk - (25.0 * suppressed_count))
                    
                    # Re-derive severity after suppression
                    if combined_risk >= 75:
                        severity = 'CRITICAL'
                    elif combined_risk >= 50:
                        severity = 'HIGH'
                    elif combined_risk >= 30:
                        severity = 'MEDIUM'
                    else:
                        severity = 'LOW'
        except Exception as _fb_err:
            logger.debug(f"Feedback loop override error: {_fb_err}")

        if progress_callback: progress_callback(4)
        reasoning = self._generate_reasoning(severity, confidence_val, evidence)

        if progress_callback: progress_callback(5)
        return {
            'target': target,
            'port': port,
            'risk_score': float(combined_risk),
            'risk_level': severity,
            'confidence': confidence_val,
            'reasoning': reasoning,
            'evidence': evidence,
            'analysis_type': 'probabilistic_360',
            'timestamp': datetime.now().isoformat(),
            'details': {
                'url_risk': float(risk),
                'port_risk': float(port_risk),
                'indicators_found': len(evidence),
                'confidence_modifier': confidence_val,
            },
            'page_title': page_title
        }

    def _generate_reasoning(self, severity: str, confidence: float, evidence: List[str]) -> str:
        risk_signals = [e for e in evidence
                        if not e.startswith("Confidence:")
                        and not e.startswith("Baseline")
                        and not e.startswith("[DIAGNOSTIC]")]
        signal_count = len(risk_signals)

        if confidence >= 0.85:
            conf_text = "high"
        elif confidence >= 0.50:
            conf_text = "moderate"
        else:
            conf_text = "low"

        if severity in ('CRITICAL', 'HIGH'):
            return (
                f"The system observed {signal_count} risk indicators in the website's "
                f"structure and behavior suggesting elevated exposure. "
                f"Confidence is {conf_text} based on signal agreement across multiple "
                f"independent checks. Immediate review is recommended."
            )
        elif severity == 'MEDIUM':
            return (
                f"The system observed infrastructure complexity and limited risk indicators "
                f"in the website's structure. Confidence is {conf_text}. "
                f"No direct threat was detected, but the environment warrants monitoring."
            )
        else:
            return (
                f"No risk indicators were observed in the website's structure or behavior. "
                f"Confidence is {conf_text} based on observed infrastructure signals. "
                f"No immediate action required."
            )


_detector = None

def get_heuristic_detector() -> HeuristicRiskDetector:
    global _detector
    if _detector is None:
        _detector = HeuristicRiskDetector()
    return _detector


def analyze_url_risk(url: str, port: int = 443) -> Dict[str, Any]:
    detector = get_heuristic_detector()
    return detector.get_complete_analysis(url, port)

