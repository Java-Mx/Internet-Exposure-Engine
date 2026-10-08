
from typing import List, Dict


SEVERITY_BASELINE: Dict[str, List[str]] = {
    "LOW": [
        "Continue routine monitoring of internet-facing assets.",
        "Ensure all staff follow standard security awareness practices.",
        "Conduct periodic reviews of this site every 30–90 days.",
    ],
    "MEDIUM": [
        "Ask your IT contact to review login pages and third-party connections on this site.",
        "Verify that the site uses a secure (HTTPS) connection.",
        "Ensure no internal files or settings are publicly visible.",
        "Inform relevant staff to exercise caution when using this site.",
        "Schedule a follow-up assessment within 14 days.",
    ],
    "HIGH": [
        "Do NOT enter passwords, payment details, or personal information on this site.",
        "Restrict employee access to this site until its legitimacy is confirmed.",
        "Notify your IT administrator or security contact immediately.",
        "Check the domain registration and ownership through an independent lookup.",
        "Conduct a follow-up assessment within 48 hours.",
    ],
    "CRITICAL": [
        "Immediately stop all interaction with this site — do not click, log in, or download anything.",
        "If you already entered a password or personal information, change your passwords now "
        "and turn on two-step login verification.",
        "Alert your IT administrator and management immediately.",
        "Ask your IT team to block this website on all company devices.",
        "Report the site to Google Safe Browsing: "
        "https://safebrowsing.google.com/safebrowsing/report_phish/",
        "Document this incident for your records.",
    ],
}


EVIDENCE_RECOMMENDATIONS: List[Dict] = [
    {
        "keywords": ["typosquat", "homoglyph", "impersonat"],
        "recommendation": (
            "Warn anyone who may have visited this site — it is impersonating a known brand. "
            "Navigate to the real website using a bookmarked or independently "
            "confirmed address — never via links from this domain."
        ),
    },
    {
        "keywords": ["google safe browsing", "virustotal"],
        "recommendation": (
            "This site is flagged by external security databases. "
            "Ask your IT team to block it so no one on your network can accidentally visit it."
        ),
    },
    {
        "keywords": ["phpmyadmin", "wp-admin", "admin panel"],
        "recommendation": (
            "Administrative control panels should never be visible to the public. "
            "Ask your IT team to restrict access so only authorized staff can reach them."
        ),
    },
    {
        "keywords": [".exe", ".bat", ".ps1", ".msi", "payload", "dropper"],
        "recommendation": (
            "Do not download or open any files from this site. "
            "If any files were already downloaded, do not open them — run a "
            "virus scan on the device immediately."
        ),
    },
    {
        "keywords": ["breach", "leaked", "exposed data"],
        "recommendation": (
            "Change all passwords used on this service. Turn on two-step login "
            "verification where available. Monitor financial accounts for suspicious activity."
        ),
    },
    {
        "keywords": ["entropy", "dga", "algorithmically"],
        "recommendation": (
            "This domain appears to be computer-generated, which is common in scam "
            "and botnet operations. Do not interact — ask your IT team to block it."
        ),
    },
    {
        "keywords": ["suspicious tld", ".tk", ".ml", ".xyz", ".cf", ".gq"],
        "recommendation": (
            "This site uses a domain extension that is commonly associated with fraud. "
            "Verify who operates the site through independent means before trusting it."
        ),
    },
    {
        "keywords": ["port exposed", "sensitive port", "mysql", "redis", "mongodb"],
        "recommendation": (
            "Internal database or infrastructure services are exposed to the public internet. "
            "Ask the site operator or your IT team to restrict access using firewall rules."
        ),
    },
    {
        "keywords": ["cve", "vulnerability", "nvd"],
        "recommendation": (
            "The technology running this site has known security weaknesses. "
            "If you operate this site, apply all available software updates immediately."
        ),
    },
]


def get_recommendations(
    severity: str,
    evidence: List[str],
) -> List[str]:
    recommendations: List[str] = []
    seen: set = set()

    ev_combined = " ".join(evidence).lower()


    evidence_recs: List[str] = []
    for rule in EVIDENCE_RECOMMENDATIONS:
        if any(kw in ev_combined for kw in rule["keywords"]):
            r = rule["recommendation"]
            if r not in seen:
                evidence_recs.append(r)
                seen.add(r)


    baseline_recs: List[str] = []
    for r in SEVERITY_BASELINE.get(severity, SEVERITY_BASELINE["LOW"]):
        if r not in seen:
            baseline_recs.append(r)
            seen.add(r)


    if severity in ("HIGH", "CRITICAL"):
        recommendations = baseline_recs + evidence_recs
    else:
        recommendations = evidence_recs + baseline_recs

    return recommendations