"""
Heuristic Risk Detector - 360-Degree Scoring Without API Data

This module provides risk scoring based on URL analysis, known patterns, 
and heuristics when external API data is unavailable.

Security Audit Enhancement - Fixes low scores for insecure websites
Now includes:
- Shannon Entropy Analysis (DGA Detection)
- Path-Level Heuristics (Extensions, Context)
- 360-Degree URL Inspection
"""

import re
import math
from typing import Dict, List, Any, Tuple, Optional
from datetime import datetime
from urllib.parse import urlparse

from config.logging_config import get_logger

logger = get_logger(__name__)


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def smart_parse_url(url: str) -> str:
    """
    Extract the clean domain from a URL or raw string.
    Handles protocols, paths, query parameters, and ports.
    """
    if not url:
        return ""
    
    # Remove protocol
    clean = url.lower().strip()
    if '://' in clean:
        clean = clean.split('://')[1]
    
    # Remove path, query, fragment
    clean = clean.split('/')[0]
    clean = clean.split('?')[0]
    clean = clean.split('#')[0]
    
    # Remove port
    if ':' in clean:
        clean = clean.split(':')[0]
    
    # Remove trailing dots (some malicious URLs use them)
    clean = clean.rstrip('.')
    
    return clean

def calculate_entropy(text: str) -> float:
    """Calculate Shannon Entropy for a string."""
    if not text:
        return 0.0
    
    prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
    entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob])
    return entropy


# ============================================================================
# KNOWN INSECURE/VULNERABLE PATTERNS
# ============================================================================

# Known vulnerable test sites (INTENTIONALLY VULNERABLE for testing)
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

# Suspicious URL patterns - ENHANCED for Path Detection
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
    (r'(^|[\.\/])test([\.\/]|$)', 25, 'Test environment'), # Added boundary
    (r'staging', 35, 'Staging environment'),
    (r'dev\.', 30, 'Development environment'),
    (r'api/.*v[0-9]', 20, 'API endpoint detected'),
    # Phishing Brand Imitation
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
    (r'bank|finance|wallet|blockchain', 80, 'Financial service imitation'),
    # Phishing Technical Triggers
    (r'verify|secure|update|account|billing', 45, 'Security-themed phishing trigger'),
    (r'login|signin|sign-in|log-in', 30, 'Authentication trigger'),
    (r'webscr|cgi-bin|cmd=_', 75, 'Technical phishing trigger (PayPal/Legacy style)'),
    (r'verification|security-check|confirm', 50, 'Urgency-themed phishing trigger'),
    (r'web-validation|account-safe', 50, 'Security-themed deception'),
    # Defacement & CMS vulnerability signals
    (r'com_content|com_user|reset\.html', 65, 'CMS vulnerability signal (potential defacement target)'),
    (r'wp-config|wp-admin|joomla|drupal', 55, 'CMS internal path exposed'),
    (r'index\.php\?option=', 60, 'Joomla vulnerability pattern'),
    (r'hacked|defaced|pwned|team-.*-hacker', 85, 'Defacement keyword detected'),
    (r'upload.*\.php', 75, 'Suspicious shell upload pattern'),
    # Malware & Exploit signals - CRITICAL BOOST
    (r'\.exe($|\?)', 90, 'Malicious Payload: Executable file (.exe) detected'),
    (r'\.msi($|\?)', 90, 'Malicious Payload: Installer file (.msi) detected'),
    (r'\.bat($|\?)', 85, 'Malicious Payload: Batch script (.bat) detected'),
    (r'\.scr($|\?)', 90, 'Malicious Payload: Screen saver (.scr) often used for malware'),
    (r'\.vbs($|\?)', 85, 'Malicious Payload: VBS script detected'),
    (r'\.ps1($|\?)', 80, 'Malicious Payload: PowerShell script detected'),
    (r'\.zip$|\.rar$|\.7z$|\.iso$', 60, 'Suspicious archive download (check context)'),
    (r'download/.*\.php', 70, 'Suspicious PHP download handler'),
    (r'exploit|malware|virus|trojan', 80, 'Malware keyword detected'),
    (r'\bbit\.ly\b|\bt\.co\b|\bgoo\.gl\b|\btinyurl\b', 30, 'URL shortener (often used in phishing/malware)'),
    # Suspicious Directories
    (r'/omg/|/tmp/|/uploads/|/private/', 50, 'Suspicious directory path'),
    # Typosquatting / Character obscuration
    (r'[0o]ffice', 45, 'Potential Office365 typosquatting'),
    (r'fac[e3]b[0o][0o]k', 80, 'Potential Facebook typosquatting'),
    (r'g[0o][0o]gl[e3]', 80, 'Potential Google typosquatting'),
]

# Official domains for brands to avoid false positives in imitation detection
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
}

# High-risk port mappings (for non-standard ports in URLs)
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

# Suspicious TLD patterns
SUSPICIOUS_TLDS = [
    ('.ru', 35, 'Russian TLD (high abuse rate)'),
    ('.cn', 35, 'Chinese TLD (high abuse rate)'),
    ('.tk', 65, 'Free TLD: .tk (critical phishing signal)'),
    ('.ml', 65, 'Free TLD: .ml (critical phishing signal)'),
    ('.ga', 65, 'Free TLD: .ga (critical phishing signal)'),
    ('.cf', 65, 'Free TLD: .cf (critical phishing signal)'),
    ('.gq', 65, 'Free TLD: .gq (critical phishing signal)'),
    ('.onion', 80, 'Tor hidden service (anonymity risk)'),
    ('.xyz', 40, 'Low-cost TLD often used in spam'),
    ('.top', 40, 'Low-cost TLD often used in spam'),
    ('.bid', 40, 'Low-cost TLD often used in spam'),
    ('.win', 40, 'Low-cost TLD often used in spam'),
]


class HeuristicRiskDetector:
    """
    Provides risk scoring based on URL analysis, known patterns, 
    and heuristics when external API data is unavailable.
    """
    
    def __init__(self):
        self.logger = logger
    
    def analyze_url(self, target: str) -> Tuple[float, List[str], str]:
        """
        Analyze a URL (domain or full path) and return risk score, evidence, and severity.
        Performs "360-Degree" analysis including Entropy and Path Context.
        
        Args:
            target: Domain or URL to analyze
            
        Returns:
            Tuple of (risk_score 0-100, evidence_list, severity_level)
        """
        if not target:
            return 0.0, ['No target provided'], 'LOW'
        
        # Determine if it's a full URL or just a domain
        if '://' not in target and not target.startswith('/'):
            # Treat as domain if possible, but might be pathless domain
            full_url = f"http://{target}"
        else:
            full_url = target
            
        try:
            parsed = urlparse(full_url)
            domain = parsed.hostname or smart_parse_url(target)
            path = parsed.path
            query = parsed.query
        except Exception:
            # Fallback
            domain = smart_parse_url(target)
            path = target
            query = ""
            
        original_input = target
        
        evidence = []
        risk_scores = []
        
        # 1. Check known vulnerable domains
        for vuln_domain, info in KNOWN_VULNERABLE_DOMAINS.items():
            if vuln_domain in domain or domain.endswith(vuln_domain):
                risk_scores.append(info['risk'])
                evidence.append(f"KNOWN VULNERABILITY: {info['reason']}")
                self.logger.info(f"Known vulnerable domain detected: {domain}")
        
        # 2. Check suspicious URL patterns (Regex across FULL URL)
        # Use full_url or original_input to catch path-based signals
        search_target = original_input
        
        for pattern, risk, reason in SUSPICIOUS_URL_PATTERNS:
            if re.search(pattern, search_target, re.IGNORECASE):
                # Check for Brand Imitation or Typosquatting False Positives
                is_false_positive = False
                if any(k in reason.lower() for k in ['brand imitation', 'typosquatting']):
                    # Find which brand we are talking about
                    for brand_name in OFFICIAL_BRAND_DOMAINS.keys():
                        if brand_name in reason.lower():
                            for official in OFFICIAL_BRAND_DOMAINS[brand_name]:
                                if official in domain or domain.endswith(official):
                                    is_false_positive = True
                                    break
                        if is_false_positive: break
                
                if not is_false_positive:
                    risk_scores.append(risk)
                    evidence.append(f"Pattern Detected: {reason}")
        
        # 3. Check TLD
        for tld, risk, reason in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                risk_scores.append(risk)
                evidence.append(f"TLD Risk: {reason}")
        
        # 4. Check for IP address (not domain)
        if self._is_ip_address(domain):
            risk_scores.append(35)
            evidence.append("Direct IP access (no domain name)")
        
        # 5. Check domain length (very long domains are suspicious)
        if len(domain) > 50:
            risk_scores.append(25)
            evidence.append("Suspicious: Very long domain name")
        
        # 6. Check for excessive subdomains
        subdomain_count = domain.count('.')
        if subdomain_count > 4:
            risk_scores.append(40)
            evidence.append(f"Suspicious: {subdomain_count} subdomain levels")
        
        # 7. Check for numeric patterns (phishing/DGA indicator)
        if re.search(r'\d{5,}', domain):
            risk_scores.append(45)
            evidence.append("Suspicious: Long numeric sequence in domain (likely DGA)")
        
        # 8. Path Entropy Analysis (DGA / Obfuscation Detection)
        # Splits path segments and checks for high randomness
        if  path and len(path) > 1:
            segments = [s for s in path.split('/') if s]
            for seg in segments:
                # Remove common extensions for entropy check purely on name
                clean_seg = seg
                if '.' in seg:
                    clean_seg = seg.rpartition('.')[0]
                
                if len(clean_seg) > 8: # Only check entropy for reasonable lengths
                    entropy = calculate_entropy(clean_seg)
                    # Lowered threshold to catch 9EYJSFYHMS (entropy ~2.92)
                    if entropy > 4.0: # Very high entropy
                        risk_scores.append(85)
                        evidence.append(f"High-Entropy Path Segment: '{clean_seg}' (Entropy: {entropy:.2f})")
                    elif entropy > 2.8: # Suspicious entropy (was 3.0)
                        risk_scores.append(50)
                        evidence.append(f"Suspicious Randomness: '{clean_seg}' (Entropy: {entropy:.2f})")
        
        # 9. Compound Risk Multiplier
        # If we have matches from multiple high-risk categories, boost the score
        if len(risk_scores) >= 3:
            max_r = float(max(risk_scores))
            risk_scores.append(min(max_r + 20.0, 95.0))
            evidence.append("360-DEGREE AUDIT: Compound threat indicators found")

        # 10. Minimum risk for any scanned domain
        if not risk_scores:
            # Apply baseline analysis
            risk_scores.append(15)
            evidence.append("Baseline risk: No significant anomalies found")
        
        # Calculate final score (weighted average with max consideration)
        if risk_scores:
            max_score = float(max(risk_scores))
            avg_score = float(sum(risk_scores)) / len(risk_scores)
            final_score = (max_score * 0.7) + (avg_score * 0.3)
        else:
            final_score = 10.0
            
        # Malware Override: If explicit malware signal, force Critical
        if any('Malicious Payload' in e or 'High-Entropy Path' in e for e in evidence):
             if final_score < 90:
                 final_score = 90.0
                 evidence.append("RISK OVERRIDE: Malware/Obfuscation signals take precedence")
        
        # Determine severity
        if final_score >= 75:
            severity = 'CRITICAL'
        elif final_score >= 50:
            severity = 'HIGH'
        elif final_score >= 30:
            severity = 'MEDIUM'
        else:
            severity = 'LOW'
        
        return min(final_score, 100), evidence, severity
    
    def analyze_port(self, port: int) -> Tuple[float, str]:
        """Analyze risk based on port number."""
        if port in HIGH_RISK_PORTS:
            risk, reason = HIGH_RISK_PORTS[port]
            return risk, reason
        
        # Standard ports
        if port in [80, 443]:
            return 0, "Standard web port"
        
        # Unknown high port
        if port > 8000:
            return 25, f"Non-standard port {port}"
        
        return 10, f"Port {port}"
    
    def _is_ip_address(self, domain: str) -> bool:
        """Check if domain is actually an IP address."""
        parts = domain.split('.')
        if len(parts) != 4:
            return False
        return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
    
    def get_complete_analysis(
        self,
        target: str,
        port: int = 443,
        additional_context: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """
        Get complete risk analysis for a domain/URL.
        
        Args:
            target: Domain or URL to analyze
            port: Port number
            additional_context: Optional additional data
            
        Returns:
            Complete analysis dictionary
        """
        # Analyze URL/Domain
        risk, evidence, severity = self.analyze_url(target)
        
        # Analyze port
        port_risk, port_reason = self.analyze_port(port)
        
        if port_risk > 0:
            evidence.append(f"Port Risk: {port_reason}")
        
        # Combine scores
        combined_risk = max(risk, port_risk)
        
        # Re-determine severity based on combined
        if combined_risk >= 75:
            severity = 'CRITICAL'
        elif combined_risk >= 50:
            severity = 'HIGH'
        elif combined_risk >= 30:
            severity = 'MEDIUM'
        else:
            severity = 'LOW'
        
        return {
            'target': target,
            'port': port,
            'risk_score': round(float(combined_risk), 1),
            'risk_level': severity,
            'evidence': evidence,
            'analysis_type': 'heuristic_360',
            'timestamp': datetime.now().isoformat(),
            'details': {
                'url_risk': round(float(risk), 1),
                'port_risk': round(float(port_risk), 1),
                'indicators_found': len(evidence)
            }
        }


# Singleton instance
_detector = None

def get_heuristic_detector() -> HeuristicRiskDetector:
    """Get singleton heuristic detector instance."""
    global _detector
    if _detector is None:
        _detector = HeuristicRiskDetector()
    return _detector


def analyze_url_risk(url: str, port: int = 443) -> Dict[str, Any]:
    """
    Convenience function to analyze URL risk.
    """
    detector = get_heuristic_detector()
    return detector.get_complete_analysis(url, port)


# Test function
if __name__ == '__main__':
    detector = HeuristicRiskDetector()
    
    test_targets = [
        'testphp.vulnweb.com',
        'https://toulousa.com/omg/9EYJSFYHMS.exe', # Expected CRITICAL
        'https://toulousa.com/omg/91EYJSFYHMS.exe',
        'google.com',
        'http://example.com/clean/file.txt',
        'http://suspicious.tk/admin.php',
    ]
    
    print("=" * 70)
    print("HEURISTIC 360-DEGREE RISK DETECTOR TEST")
    print("=" * 70)
    
    for target in test_targets:
        result = detector.get_complete_analysis(target)
        print(f"\n{target}")
        print(f"  Risk Score: {result['risk_score']}")
        print(f"  Severity: {result['risk_level']}")
        print(f"  Evidence: {result['evidence']}")
