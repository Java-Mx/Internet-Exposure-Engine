import re
import math
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field


@dataclass
class EscalationResult:
    triggered: bool = False
    escalated_severity: Optional[str] = None
    rules_matched: List[str] = field(default_factory=list)
    reasoning: str = ""
    confidence_boost: float = 0.0


_SEVERITY_ORDER = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}


def _severity_max(a: str, b: str) -> str:
    return a if _SEVERITY_ORDER.get(a, 0) >= _SEVERITY_ORDER.get(b, 0) else b


def _domain_entropy(domain: str) -> float:

    parts = domain.lower().split('.')
    if len(parts) >= 2:
        label = parts[0] if len(parts) == 2 else '.'.join(parts[:-1])
    else:
        label = domain

    if not label:
        return 0.0

    freq = {}
    for c in label:
        freq[c] = freq.get(c, 0) + 1
    length = len(label)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def _lexical_score(domain: str) -> float:
    parts = domain.lower().split('.')
    label = parts[0] if parts else domain

    if not label:
        return 0.5

    vowels = set('aeiou')
    consonants = set('bcdfghjklmnpqrstvwxyz')
    digits = set('0123456789')

    vowel_count = sum(1 for c in label if c in vowels)
    consonant_count = sum(1 for c in label if c in consonants)
    digit_count = sum(1 for c in label if c in digits)
    special_count = sum(1 for c in label if c not in vowels | consonants | digits and c != '-')
    total = len(label)

    if total == 0:
        return 0.5


    digit_ratio = digit_count / total
    if digit_ratio > 0.5:
        return max(0.0, 0.3 - digit_ratio)


    if vowel_count == 0 and total > 3:
        return 0.1


    vowel_ratio = vowel_count / max(1, vowel_count + consonant_count)
    ratio_score = 1.0 - abs(vowel_ratio - 0.40) * 3.0


    max_consec_consonants = 0
    current = 0
    for c in label:
        if c in consonants:
            current += 1
            max_consec_consonants = max(max_consec_consonants, current)
        else:
            current = 0
    consonant_penalty = max(0, (max_consec_consonants - 2) * 0.15)

    score = max(0.0, min(1.0, ratio_score - consonant_penalty - (special_count * 0.1)))
    return score


def _has_lure_keywords(domain: str) -> bool:
    lure_patterns = [
        'free', 'gift', 'winner', 'prize', 'reward', 'bonus',
        'update', 'verify', 'confirm', 'secure', 'alert',
        'account', 'login', 'signin', 'password', 'credential',
        'suspend', 'expire', 'urgent', 'action', 'required',
        'wallet', 'payment', 'refund', 'invoice', 'billing',
        'support', 'helpdesk', 'service', 'recover', 'unlock',
    ]
    domain_lower = domain.lower()
    matches = [kw for kw in lure_patterns if kw in domain_lower]
    return len(matches) >= 1


def _has_deceptive_structure(domain: str) -> bool:
    parts = domain.lower().split('.')
    label = parts[0] if parts else domain


    if label.count('-') >= 2:
        return True


    if len(parts) >= 4:
        return True

    return False


def _extract_tld(domain: str) -> str:
    parts = domain.lower().split('.')
    return f".{parts[-1]}" if parts else ""


_HIGH_ABUSE_TLDS = {
    '.tk', '.ml', '.ga', '.cf', '.gq',
    '.top', '.xyz', '.buzz', '.club', '.online', '.site', '.icu',
    '.cc', '.ws', '.pw', '.su', '.me',
}

_CRITICAL_ABUSE_TLDS = {
    '.tk', '.ml', '.ga', '.cf', '.gq',
}


def _rule_dga_escalation(domain: str, evidence: List[str], score: float) -> Optional[Tuple[str, str, str]]:
    entropy = _domain_entropy(domain)
    lexical = _lexical_score(domain)
    tld = _extract_tld(domain)

    if entropy >= 2.8 and lexical <= 0.35 and tld in _HIGH_ABUSE_TLDS:
        return (
            'HIGH',
            'DGA_ESCALATION',
            f"Domain shows algorithmic generation patterns: high entropy ({entropy:.2f}), "
            f"low lexical similarity ({lexical:.2f}), and high-abuse TLD ({tld}). "
            f"This combination is consistent with domain generation algorithms used in malware infrastructure."
        )


    if entropy >= 3.5 and tld in _CRITICAL_ABUSE_TLDS:
        return (
            'HIGH',
            'DGA_ESCALATION',
            f"Domain has extremely high entropy ({entropy:.2f}) on a critical abuse TLD ({tld}). "
            f"This is consistent with automated domain generation."
        )

    return None


def _rule_phishing_structure(domain: str, evidence: List[str], score: float) -> Optional[Tuple[str, str, str]]:
    tld = _extract_tld(domain)
    has_lure = _has_lure_keywords(domain)
    has_deceptive = _has_deceptive_structure(domain)
    has_suspicious_tld = tld in _HIGH_ABUSE_TLDS

    if has_lure and has_suspicious_tld:
        return (
            'HIGH',
            'PHISHING_STRUCTURE',
            f"Domain contains social engineering lure keywords and uses a high-abuse TLD ({tld}). "
            f"This combination is characteristic of phishing campaigns targeting user credentials."
        )

    if has_lure and has_deceptive:
        return (
            'HIGH',
            'PHISHING_STRUCTURE',
            f"Domain contains lure keywords with deceptive structural patterns "
            f"(excessive hyphens or subdomain depth). "
            f"This is consistent with credential harvesting infrastructure."
        )

    return None


def _rule_brand_impersonation(domain: str, evidence: List[str], score: float) -> Optional[Tuple[str, str, str]]:
    has_brand_signal = any('[T1] Pattern Detected: Brand imitation' in e for e in evidence)

    if not has_brand_signal:
        return None

    tld = _extract_tld(domain)
    has_suspicious_tld = tld in _HIGH_ABUSE_TLDS
    has_deceptive = _has_deceptive_structure(domain)

    if has_brand_signal and (has_suspicious_tld or has_deceptive):
        return (
            'HIGH',
            'BRAND_IMPERSONATION',
            f"The system detected brand impersonation patterns combined with "
            f"{'a high-abuse TLD (' + tld + ')' if has_suspicious_tld else 'deceptive domain structure'}. "
            f"Because multiple threat indicators were present simultaneously, "
            f"the risk classification was elevated to HIGH."
        )

    return None


def _rule_malware_association(domain: str, evidence: List[str], score: float) -> Optional[Tuple[str, str, str]]:
    has_malware = any(
        'Malicious Payload' in e or 'malware binary' in e or 'RISK OVERRIDE' in e
        for e in evidence
    )

    if has_malware:
        return (
            'CRITICAL',
            'MALWARE_ASSOCIATION',
            "Confirmed malware indicators detected. "
            "The system identified delivery mechanisms or payload patterns "
            "associated with active malware campaigns. Immediate action required."
        )

    return None


def _rule_compound_threat(domain: str, evidence: List[str], score: float) -> Optional[Tuple[str, str, str]]:
    t1_categories = set()
    for e in evidence:
        if '[T1]' not in e:
            continue
        if 'TLD Risk' in e:
            t1_categories.add('tld')
        if 'Pattern Detected' in e:
            t1_categories.add('pattern')
        if 'KNOWN VULNERABILITY' in e:
            t1_categories.add('vuln')
        if 'DGA' in e or 'numeric sequence' in e:
            t1_categories.add('dga')
        if 'Entropy' in e:
            t1_categories.add('entropy')
        if 'malware' in e.lower():
            t1_categories.add('malware')

    if len(t1_categories) >= 2:
        return (
            'HIGH',
            'COMPOUND_THREAT',
            f"Multiple independent threat categories detected ({', '.join(sorted(t1_categories))}). "
            f"The convergence of {len(t1_categories)} distinct threat indicators "
            f"elevates this beyond environmental risk into active threat classification."
        )

    return None


def _rule_c2_pattern(domain: str, evidence: List[str], score: float) -> Optional[Tuple[str, str, str]]:
    c2_keywords = ['agent', 'bot', 'beacon', 'loader', 'dropper',
                   'payload', 'implant', 'backdoor', 'shell', 'c2', 'cnc']
    domain_lower = domain.lower()
    tld = _extract_tld(domain)

    matched_keywords = [kw for kw in c2_keywords if kw in domain_lower]

    if matched_keywords and tld in _HIGH_ABUSE_TLDS:
        return (
            'HIGH',
            'C2_PATTERN',
            f"Domain contains C2-associated terminology ({', '.join(matched_keywords)}) "
            f"combined with a high-abuse TLD ({tld}). "
            f"This pattern is consistent with command-and-control infrastructure."
        )

    return None


_ESCALATION_RULES = [
    _rule_malware_association,
    _rule_brand_impersonation,
    _rule_dga_escalation,
    _rule_phishing_structure,
    _rule_c2_pattern,
    _rule_compound_threat,
]


def evaluate_escalation(
    domain: str,
    score: float,
    severity: str,
    evidence: List[str],
) -> EscalationResult:
    result = EscalationResult()
    highest_severity = severity

    for rule_fn in _ESCALATION_RULES:
        match = rule_fn(domain, evidence, score)
        if match is not None:
            escalated_level, rule_name, reasoning = match
            result.rules_matched.append(rule_name)


            if _SEVERITY_ORDER.get(escalated_level, 0) > _SEVERITY_ORDER.get(highest_severity, 0):
                highest_severity = escalated_level
                result.reasoning = reasoning

    if highest_severity != severity:
        result.triggered = True
        result.escalated_severity = highest_severity

    return result