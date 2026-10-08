
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime

from config.logging_config import get_logger

logger = get_logger(__name__)


SEVERITY_BUSINESS_MAP: Dict[str, Dict[str, str]] = {
    "LOW": {
        "label":       "Normal Internet Exposure",
        "description": "No significant concerns were identified. This website appears to "
                       "operate within expected parameters for a standard internet presence.",
        "urgency":     "Routine",
        "urgency_color": "green",
        "business_meaning": (
            "The site shows no indicators of deceptive, malicious, or misconfigured behavior "
            "based on external analysis. Routine security practices should be maintained."
        ),
    },
    "MEDIUM": {
        "label":       "Requires Monitoring and Configuration Review",
        "description": "Some characteristics warrant attention. While not immediately dangerous, "
                       "additional verification is recommended before sharing sensitive information.",
        "urgency":     "Review within 7 days",
        "urgency_color": "orange",
        "business_meaning": (
            "One or more indicators were found that suggest the site may have configuration gaps "
            "or characteristics associated with increased risk. This does not confirm a threat, "
            "but warrants review by a responsible administrator."
        ),
    },
    "HIGH": {
        "label":       "Likely Unsafe or Deceptive Behavior",
        "description": "Multiple concerning indicators were identified. Exercise caution and "
                       "verify the legitimacy of this website before proceeding.",
        "urgency":     "Immediate review required",
        "urgency_color": "red",
        "business_meaning": (
            "Several indicators consistent with deceptive, impersonating, or misconfigured systems "
            "were detected. Interacting with this site — particularly sharing credentials or "
            "financial information — carries meaningful risk."
        ),
    },
    "CRITICAL": {
        "label":       "Active Threat Likely or Confirmed",
        "description": "Strong indicators of potential risk were detected. Avoid entering "
                       "personal or financial information until the website's legitimacy "
                       "is confirmed through trusted channels.",
        "urgency":     "Do not interact — escalate immediately",
        "urgency_color": "red",
        "business_meaning": (
            "Indicators consistent with known attack patterns — such as brand impersonation, "
            "malicious payload delivery, or confirmed threat intelligence flags — were detected. "
            "This site should be treated as a potential active threat until independently verified."
        ),
    },
}


TECHNICAL_TRANSLATIONS: Dict[str, Dict[str, str]] = {
    "typosquatting": {
        "observed":    "The website address uses character substitution to resemble a well-known brand.",
        "meaning":     "This is a common impersonation technique where criminals replace letters "
                       "with visually similar characters (e.g., zeros instead of the letter 'o') "
                       "to deceive visitors into believing they are on a legitimate site.",
        "impact":      "Visitors may unknowingly submit login credentials, payment details, or "
                       "personal information to an attacker-controlled site.",
        "action":      "Do not access or interact with this site. Alert relevant personnel and "
                       "verify the legitimate website address through an independent, trusted source.",
    },
    "brand_impersonation": {
        "observed":    "The website address closely resembles a well-known brand name.",
        "meaning":     "This may be an attempt to deceive visitors into believing they are on "
                       "a legitimate website. Such techniques are commonly used in identity theft "
                       "and financial fraud.",
        "impact":      "Users may share sensitive information with an unintended party.",
        "action":      "Do not enter personal information. Navigate directly to the official brand "
                       "website using a known, trusted address.",
    },
    "gsb_flagged": {
        "observed":    "This website has been flagged by Google Safe Browsing.",
        "meaning":     "Google's threat intelligence database has identified this site as associated "
                       "with phishing, malware distribution, or other harmful activity.",
        "impact":      "Visiting this site may expose devices or data to active threats.",
        "action":      "Immediately stop using this site. Report to your IT administrator or security contact.",
    },
    "virustotal_flagged": {
        "observed":    "This website has been identified as a threat by multiple security vendors.",
        "meaning":     "Cross-referencing across dozens of security providers confirmed this site "
                       "is associated with malicious activity.",
        "impact":      "High likelihood of data theft, malware delivery, or fraud.",
        "action":      "Immediately stop using this site. Do not click any links from it.",
    },
    "suspicious_tld": {
        "observed":    "The website uses an uncommon domain extension.",
        "meaning":     "Certain domain extensions are more frequently associated with fraudulent "
                       "or temporary websites. This does not confirm malicious intent but warrants "
                       "additional verification.",
        "impact":      "Increased likelihood that the operator is not a verified organization.",
        "action":      "Verify the legitimacy of the organization behind this domain before "
                       "sharing any sensitive information.",
    },
    "high_entropy_domain": {
        "observed":    "The website address contains an unusual or algorithmically generated pattern.",
        "meaning":     "Randomly structured website addresses are sometimes used by automated "
                       "malicious systems. This pattern is inconsistent with typical business naming.",
        "impact":      "May indicate an automated attack infrastructure rather than a legitimate site.",
        "action":      "Exercise caution. Verify the site through independent channels before interacting.",
    },
    "sensitive_port": {
        "observed":    "The website is accessible via a non-standard network connection point.",
        "meaning":     "Standard websites operate on well-known channels. Unusual access points "
                       "may indicate development environments not secured for public access.",
        "impact":      "Data transmitted may not be adequately protected.",
        "action":      "If this is a business-facing service, ensure it runs on standard channels "
                       "with proper access controls.",
    },
    "ip_address_access": {
        "observed":    "The website is accessed using a numeric address rather than a named domain.",
        "meaning":     "Legitimate organizations typically use named website addresses. "
                       "Direct numeric access may indicate temporary or unverified infrastructure.",
        "impact":      "Visitors cannot verify the identity of the host through standard mechanisms.",
        "action":      "Confirm the ownership of this address before interacting.",
    },
    "suspicious_path": {
        "observed":    "The website address contains administrative or system management paths.",
        "meaning":     "Internal management pages being publicly accessible may allow unauthorized "
                       "access to sensitive controls or information.",
        "impact":      "Unauthorized access to configuration, user data, or administrative controls.",
        "action":      "Restrict access to administrative pages to authorized personnel only "
                       "using network-level controls.",
    },
    "data_breach": {
        "observed":    "This domain has been associated with a known data exposure event.",
        "meaning":     "Information linked to this domain was found in a publicly reported security "
                       "incident. This means personal data may have been exposed.",
        "impact":      "Personal information previously submitted may have been compromised.",
        "action":      "Change any passwords used on this service and turn on two-step login "
                       "verification where available.",
    },
    "cve_exposure": {
        "observed":    "The technology used by this website has publicly documented security weaknesses.",
        "meaning":     "Public records show that the technology running this website has had security "
                       "issues reported. This does not confirm this specific site is affected.",
        "impact":      "If unpatched, these weaknesses may allow unauthorized access or data exposure.",
        "action":      "Ensure the website operators keep their systems updated with the latest "
                       "security patches.",
    },
    "malicious_payload": {
        "observed":    "The website address points to a file type associated with harmful software.",
        "meaning":     "Executable files, scripts, and archive downloads delivered via web links "
                       "are a common method of distributing malware.",
        "impact":      "Downloading or executing this file may compromise the device and network.",
        "action":      "Do not download or open this file. Run a virus scan with updated "
                       "security software before any interaction.",
    },
    "standard_web": {
        "observed":    "The website operates using standard web protocols.",
        "meaning":     "No unusual technical characteristics were detected. This is expected "
                       "behavior for a normal public website.",
        "impact":      "No significant risk indicators identified from this factor.",
        "action":      "No action required. Maintain standard security practices.",
    },
    "trusted_domain": {
        "observed":    "This website belongs to a well-known, established organization.",
        "meaning":     "The website is associated with a recognized and trusted entity, which "
                       "significantly reduces the likelihood of malicious intent.",
        "impact":      "Minimal risk from this factor.",
        "action":      "No action required. Continue using the service as normal.",
    },
}


ADVISORY_NOTICE = (
    "This report was produced using passive external analysis techniques. "
    "No penetration testing, intrusive scanning, or direct system access was performed. "
    "Findings represent observed external exposure indicators and assessed risk likelihood, "
    "not confirmed security breaches or guaranteed compromise. "
    "All final security decisions should be reviewed and validated by a qualified administrator "
    "or security professional with access to internal system information. "
    "This report does not constitute legal, regulatory, or compliance advice."
)


@dataclass
class Observation:
    what_observed:      str
    what_it_means:      str
    business_impact:    str
    recommended_action: str


@dataclass
class BusinessReport:
    url:                str
    domain:             str
    generated_at:       str


    risk_level:         str
    risk_label:         str
    risk_score:         int
    confidence_pct:     int
    urgency:            str


    executive_summary:  str
    business_impact:    str
    likelihood:         str
    observations:       List[Observation] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)
    advisory_notice:    str = ADVISORY_NOTICE


    risk_change:        Optional[str] = None
    previous_score:     Optional[int] = None


class BusinessTranslator:

    def __init__(self) -> None:
        self.logger = logger

    def create_business_report(
        self,
        url: str,
        score: int,
        severity: str,
        evidence: List[str],
        confidence: float = 0.0,
        previous_score: Optional[int] = None,
    ) -> BusinessReport:
        from urllib.parse import urlparse
        try:
            domain = urlparse(url if "://" in url else f"http://{url}").hostname or url
        except Exception:
            domain = url

        sev_info = SEVERITY_BUSINESS_MAP.get(severity, SEVERITY_BUSINESS_MAP["LOW"])
        observations = self._translate_evidence(evidence)

        exec_summary = self._executive_summary(url, severity, score, evidence)
        impact       = self._business_impact(severity, observations)
        likelihood   = self._likelihood_statement(severity, score, confidence)


        seen: set = set()
        actions: List[str] = []

        if severity in ("HIGH", "CRITICAL"):

            from reporting.recommendations import get_recommendations
            actions = get_recommendations(severity, evidence)
        else:

            for obs in observations:
                a = obs.recommended_action
                if a and a not in seen:
                    actions.append(a)
                    seen.add(a)

            if not actions:
                actions = [self._default_action(severity)]


        risk_change = None
        if previous_score is not None:
            delta = score - previous_score
            if delta >= 5:
                risk_change = "increased"
            elif delta <= -5:
                risk_change = "decreased"

        return BusinessReport(
            url=url,
            domain=domain,
            generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            risk_level=severity,
            risk_label=sev_info["label"],
            risk_score=score,
            confidence_pct=round(confidence * 100),
            urgency=sev_info["urgency"],
            executive_summary=exec_summary,
            business_impact=impact,
            likelihood=likelihood,
            observations=observations,
            recommended_actions=actions,
            advisory_notice=ADVISORY_NOTICE,
            risk_change=risk_change,
            previous_score=previous_score,
        )


    def _translate_evidence(self, evidence: List[str]) -> List[Observation]:
        observations: List[Observation] = []
        matched_keys: set = set()

        for ev in evidence:
            ev_lower = ev.lower()
            key, trans = self._best_match(ev_lower)
            if not key or key in matched_keys:
                continue
            matched_keys.add(key)
            observations.append(Observation(
                what_observed=trans["observed"],
                what_it_means=trans["meaning"],
                business_impact=trans["impact"],
                recommended_action=trans["action"],
            ))

        return observations

    def _best_match(self, ev_lower: str):
        keyword_map = {
            "typosquatting":       ["typosquat", "homoglyph", "character substitution", "impersonat"],
            "gsb_flagged":         ["google safe browsing"],
            "virustotal_flagged":  ["virustotal"],
            "brand_impersonation": ["brand imitation", "brand name", "brand"],
            "suspicious_tld":      ["suspicious tld", ".tk", ".ml", ".xyz", ".top", ".club", "free tld"],
            "high_entropy_domain": ["entropy", "dga", "algorithmically generated", "obfuscat"],
            "malicious_payload":   ["malicious payload", ".exe", ".bat", ".ps1", ".msi", "dropper"],
            "sensitive_port":      ["port exposed", "sensitive port", "non-standard port"],
            "ip_address_access":   ["ip address", "numeric address", "direct ip"],
            "suspicious_path":     ["admin", "phpmyadmin", "wp-admin", "management path"],
            "data_breach":         ["breach", "leaked", "exposed data", "compromised"],
            "cve_exposure":        ["cve", "vulnerability", "nvd", "known weakness"],
            "standard_web":        ["baseline risk", "no significant", "standard"],
            "trusted_domain":      ["trusted", "whitelisted", "recognized", "established"],
        }
        for key, keywords in keyword_map.items():
            if any(kw in ev_lower for kw in keywords):
                trans = TECHNICAL_TRANSLATIONS.get(key)
                if trans:
                    return key, trans
        return None, None

    def _executive_summary(self, url: str, severity: str, score: int, evidence: List[str]) -> str:
        ev_lower = " ".join(evidence).lower()
        if severity == "LOW":
            return (
                f"The external assessment of {url} did not identify significant risk indicators. "
                f"The site appears to operate within normal parameters for a standard internet presence. "
                f"No immediate action is required."
            )
        elif severity == "MEDIUM":
            return (
                f"The assessment of {url} identified characteristics that warrant attention. "
                f"While no immediate or confirmed threat was detected, one or more indicators "
                f"suggest the site may require administrative review or configuration improvement."
            )
        elif severity == "HIGH":
            if "typosquat" in ev_lower or "brand" in ev_lower:
                return (
                    f"The assessment of {url} found strong indicators of brand impersonation. "
                    f"The site appears to be disguising itself as a trusted organization to "
                    f"deceive visitors. The risk score of {score}/100 reflects a high likelihood "
                    f"of deceptive intent."
                )
            return (
                f"The assessment of {url} identified multiple concerning indicators "
                f"(risk score: {score}/100). The site shows characteristics associated with "
                f"unsafe behavior. Interaction with this site carries significant risk."
            )
        else:
            if "google safe browsing" in ev_lower or "virustotal" in ev_lower:
                return (
                    f"The assessment of {url} produced a risk score of {score}/100 — classified "
                    f"as a confirmed or likely active threat. This site has been flagged by external "
                    f"threat intelligence feeds. Immediate cessation of interaction is strongly advised."
                )
            return (
                f"The assessment of {url} produced a risk score of {score}/100. "
                f"Multiple high-confidence indicators of malicious or deceptive activity were "
                f"detected. This site should be treated as an active threat until independently verified."
            )

    def _business_impact(self, severity: str, observations: List[Observation]) -> str:
        if not observations or severity == "LOW":
            return "No significant business impact indicators were identified during this assessment."
        impacts = [o.business_impact for o in observations if o.business_impact]
        if not impacts:
            return SEVERITY_BUSINESS_MAP[severity]["business_meaning"]

        return " ".join(impacts[:2])

    def _likelihood_statement(self, severity: str, score: int, confidence: float) -> str:
        conf_pct = round(confidence * 100)
        lmap = {
            "LOW":      f"Based on the indicators observed, the likelihood of malicious or "
                        f"deceptive intent is low (signal confidence: {conf_pct}%). "
                        f"Standard vigilance is appropriate.",
            "MEDIUM":   f"There is a moderate possibility that this site may be involved in "
                        f"deceptive or unsafe practices (signal confidence: {conf_pct}%). "
                        f"Additional verification is advised.",
            "HIGH":     f"The observed indicators suggest a high probability of deceptive or "
                        f"harmful intent (risk score: {score}/100, confidence: {conf_pct}%). "
                        f"Interaction without verification carries meaningful risk.",
            "CRITICAL": f"The combination of indicators detected suggests a strong likelihood "
                        f"of active malicious behavior (risk score: {score}/100, confidence: {conf_pct}%). "
                        f"This assessment warrants immediate escalation.",
        }
        return lmap.get(severity, lmap["LOW"])

    def _default_action(self, severity: str) -> str:
        action_map = {
            "LOW":      "Continue routine monitoring. No immediate action required.",
            "MEDIUM":   "Ask your IT contact to review login pages and third-party connections. "
                        "Do not share sensitive information until reviewed.",
            "HIGH":     "Do NOT enter any personal information on this site. "
                        "Restrict access and notify your IT contact.",
            "CRITICAL": "Immediately stop all interaction with this site and "
                        "alert your IT administrator or security contact.",
        }
        return action_map.get(severity, action_map["LOW"])