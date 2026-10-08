
import re
import math
from typing import Dict, List, Tuple, Optional
from urllib.parse import urlparse
from dataclasses import dataclass, field

from config.logging_config import get_logger

logger = get_logger(__name__)


STANDARD_PORTS = {80, 443, 8080, 8443}


ESTABLISHED_TLDS = {

    '.com', '.org', '.net', '.edu', '.gov', '.mil',

    '.co.uk', '.org.uk', '.gov.uk', '.ac.uk', '.net.uk', '.sch.uk', '.nhs.uk',

    '.co.in', '.edu.in', '.ac.in', '.net.in', '.org.in', '.gov.in', '.mil.in', '.res.in',

    '.co.jp', '.ac.jp', '.go.jp', '.ne.jp', '.or.jp',

    '.com.au', '.org.au', '.net.au', '.edu.au', '.gov.au', '.asn.au', '.id.au',

    '.co.nz', '.org.nz', '.gov.nz', '.net.nz', '.ac.nz',

    '.ca',

    '.de', '.fr',

    '.ie', '.sg', '.co.za', '.co.kr',

    '.com.br', '.org.br', '.gov.br', '.edu.br',

    '.in', '.au', '.nz', '.it', '.es', '.nl', '.be', '.se', '.no', '.fi', '.dk', '.pt',
    '.ch', '.at', '.pl', '.cz', '.hu', '.ro', '.bg', '.gr', '.tr', '.il', '.ae',
}


FREE_TLDS = {'.tk', '.ml', '.ga', '.cf', '.gq'}


MAX_CLEAN_DOMAIN_LENGTH = 40


DGA_ENTROPY_THRESHOLD = 4.0


@dataclass
class SafetyAssessment:
    safety_score: float = 0.0
    is_safe: bool = False
    signals: Dict[str, float] = field(default_factory=dict)
    evidence: List[str] = field(default_factory=list)
    explanation: str = ""

    @property
    def should_suppress_low_confidence(self) -> bool:
        return False

    @property
    def confidence_modifier(self) -> float:
        if self.safety_score >= 85:
            return 0.35
        elif self.safety_score >= 70:
            return 0.50
        elif self.safety_score >= 50:
            return 0.70
        elif self.safety_score >= 30:
            return 0.85
        else:
            return 1.0


class SafetySignalAnalyser:

    SAFETY_THRESHOLD = 85

    def __init__(self):
        self.logger = logger

    def assess(
        self,
        domain: str,
        port: int = 443,
        path: str = "",
        url: str = "",
        threat_intel: Optional[Dict] = None,
        heuristic_flags: Optional[List[str]] = None,
    ) -> SafetyAssessment:
        if not domain:
            return SafetyAssessment(
                safety_score=0,
                explanation="No domain provided for safety assessment"
            )

        signals: Dict[str, float] = {}
        evidence: List[str] = []


        port_score = self._assess_port(port)
        signals["standard_port"] = port_score
        if port_score > 0:
            evidence.append(f"Standard web port ({port})")


        tld_score = self._assess_tld(domain)
        signals["established_tld"] = tld_score
        if tld_score >= 10:
            tld_part = self._extract_tld(domain)
            evidence.append(f"Established TLD ({tld_part})")
        elif tld_score < 0:
            evidence.append("Free/disposable TLD (higher abuse rate)")


        structure_score = self._assess_domain_structure(domain)
        signals["domain_structure"] = structure_score
        if structure_score >= 10:
            evidence.append("Clean, well-structured domain name")


        pattern_score = self._assess_pattern_absence(
            domain, path, url, evidence, heuristic_flags
        )
        signals["no_suspicious_patterns"] = pattern_score
        if pattern_score >= 15:

            platform_abuse = any(x in url.lower() for x in ['/raw/', '/download', 'guestaccesstoken', 'ResponsePage', 'viewform', 'export=download'])
            is_platform = any(d in domain.lower() for d in ['office.com', 'live.com', 'google.com', 'pastebin.com', 'dropbox.com', 'gitlab.com'])

            if platform_abuse and is_platform:
                pattern_score = -50.0
                evidence.append(f"Safety Override: Platform abuse pattern detected on {domain}")
            else:
                evidence.append("No suspicious URL patterns detected")


        signals["brand_legitimacy"] = 0.0


        entropy_score = self._assess_path_entropy(path)
        signals["low_path_entropy"] = entropy_score
        if entropy_score >= 8:
            evidence.append("Normal path structure (low entropy)")


        infra_score = self._assess_infrastructure(threat_intel)
        signals["normal_infrastructure"] = infra_score
        if infra_score >= 5:
            evidence.append("Standard infrastructure profile")


        vuln_score = self._assess_not_known_vulnerable(domain)
        signals["not_known_vulnerable"] = vuln_score
        if vuln_score <= 0:
            evidence.append("Known intentionally vulnerable test site")


        total = sum(max(v, 0) for v in signals.values())

        safety_score = float(min(total, 100.0))
        is_safe = safety_score >= self.SAFETY_THRESHOLD


        if is_safe:

            top_evidence = evidence[:4] if len(evidence) >= 4 else evidence
            explanation = (
                f"Safety assessment: this site appears normal and low-risk "
                f"(score: {safety_score:.0f}/100). "
                f"Observed signals: {', '.join(top_evidence)}."
            )
        else:
            explanation = (
                f"Safety assessment: insufficient positive signals "
                f"(score: {safety_score:.0f}/100). "
                f"Site did not meet the threshold for low-risk classification."
            )

        return SafetyAssessment(
            safety_score=safety_score,
            is_safe=is_safe,
            signals=signals,
            evidence=evidence,
            explanation=explanation,
        )


    def _assess_port(self, port: int) -> float:
        if port in STANDARD_PORTS:
            return 5.0
        return 0.0

    def _assess_tld(self, domain: str) -> float:
        tld = self._extract_tld(domain)
        if tld in FREE_TLDS:
            return -15.0
        if tld in ESTABLISHED_TLDS:
            return 5.0
        return 0.0

    def _assess_domain_structure(self, domain: str) -> float:
        score = 10.0


        dots = domain.count('.')
        if dots > 4:
            score -= 15.0
        elif dots > 2:
            score -= 5.0


        if sum(c.isdigit() for c in domain) > 5:
            score -= 10.0

        return max(score, -20.0)

    def _assess_pattern_absence(
        self,
        domain: str,
        path: str,
        url: str,
        evidence: List[str],
        heuristic_flags: Optional[List[str]] = None,
    ) -> float:
        score = 20.0
        current_score = float(score)


        check_target = url or domain
        critical_patterns = [
            r'\.exe($|\?)', r'\.msi($|\?)', r'\.bat($|\?)',
            r'exploit', r'malware', r'hacked', r'defaced',
            r'phpmyadmin', r'\.git', r'\.env', r'\.sql',
        ]
        for pat in critical_patterns:
            if re.search(pat, check_target, re.IGNORECASE):
                current_score = current_score - 10.0
                evidence.append(f"Suspicious pattern detected in URL: {pat}")


        phishing_keywords = [
            'login', 'signin', 'verify', 'update', 'account', 'banking',
            'secure', 'billing', 'confirm', 'validation', 'setup',
            'orders', 'payment', 'cart', 'checkout', 'myaccount',
            'caisse', 'itau', 'bradesco', 'santander', 'pontos', 'notification',
            'cadastro', 'zaglosuj', 'glosowanie', 'ebok'
        ]
        path_lower = (path or "").lower()
        if any(k in path_lower for k in phishing_keywords):

            base_penalty = 40.0 if current_score < 70 else 15.0
            current_score = current_score - base_penalty
            evidence.append(f"Phishing-related keywords detected in URL path (Penalty: {base_penalty})")


            tld = self._extract_tld(domain)
            if tld in ['.site', '.website', '.xyz', '.buzz', '.pw', '.info', '.top']:
                if any(k in path_lower for k in ['update', 'service', 'notification', 'secure']):
                    score = float(score) - 20.0
                    evidence.append(f"Hardened Penalty: High-risk keyword in {tld} context")


        if heuristic_flags is not None:
            flag_count = len(heuristic_flags)
            current_score = current_score - min(float(flag_count) * 5.0, 20.0)

        return float(max(current_score, -50.0))

    def _assess_brand_legitimacy(self, domain: str) -> float:

        from risk_scoring.heuristic_detector import OFFICIAL_BRAND_DOMAINS

        for brand, official_domains in OFFICIAL_BRAND_DOMAINS.items():
            for official in official_domains:
                if domain == official or domain.endswith('.' + official):
                    return 10.0
        return 0.0

    def _assess_path_entropy(self, path: str) -> float:
        if not path or path in ('/', ''):
            return 10.0


        segments = [s for s in path.split('/') if s and len(s) > 15]
        for seg in segments:
            clean_seg = seg.rpartition('.')[0] if '.' in seg else seg
            if len(clean_seg) > 15:

                if '-' in clean_seg and clean_seg.count('-') > 3:
                    continue

                entropy = self._calculate_entropy(clean_seg)
                if entropy > 4.8:
                    return 0.0

        return 10.0

    def _assess_infrastructure(self, threat_intel: Optional[Dict]) -> float:
        if not threat_intel:
            return 5.0

        score = 5.0


        censys = threat_intel.get('censys', {})
        if censys:
            cert = censys.get('certificate', {})
            if cert.get('valid') is True:
                score += 3.0
            elif cert.get('valid') is False:
                score -= 5.0


        shodan = threat_intel.get('shodan', {})
        if shodan:
            if not shodan.get('vulns'):
                score += 2.0
            else:
                score -= 5.0

        return max(score, 0.0)

    def _assess_not_known_vulnerable(self, domain: str) -> float:
        from risk_scoring.heuristic_detector import KNOWN_VULNERABLE_DOMAINS

        for vuln_domain in KNOWN_VULNERABLE_DOMAINS:
            if vuln_domain in domain or domain.endswith(vuln_domain):
                return -10.0
        return 5.0


    @staticmethod
    def _extract_tld(domain: str) -> str:
        parts = domain.rsplit('.', 2)
        if len(parts) >= 2:
            tld = '.' + parts[-1]

            if len(parts) >= 3:
                compound = '.' + parts[-2] + '.' + parts[-1]
                if compound in ESTABLISHED_TLDS:
                    return compound
            return tld
        return ''

    @staticmethod
    def _calculate_entropy(text: str) -> float:
        if not text:
            return 0.0
        freq = {}
        for c in text:
            freq[c] = freq.get(c, 0) + 1
        length = len(text)
        return -sum(
            (count / length) * math.log2(count / length)
            for count in freq.values()
        )


_analyser = None


def get_safety_analyser() -> SafetySignalAnalyser:
    global _analyser
    if _analyser is None:
        _analyser = SafetySignalAnalyser()
    return _analyser