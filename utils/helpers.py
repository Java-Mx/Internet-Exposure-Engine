"""
AERIS UI Helper Utilities
===========================
Shared functions for styling, colors, labels, and common translations.
"""
from typing import Tuple

def get_sev_color(sev: str) -> str:
    """Return hex color for a given severity level."""
    verdicts = {
        "CRITICAL": "#dc3545",
        "HIGH": "#dc3545",
        "MEDIUM": "#fd7e14",
        "LOW": "#198754",
        "INFO": "#0dcaf0",
        "UNKNOWN": "#6c757d",
        "IMMEDIATE": "#dc3545",
        "URGENT": "#dc3545",
        "SCHEDULED": "#198754",
    }
    return verdicts.get(str(sev).upper(), "#6c757d")

def get_trust_verdict(severity: str) -> Tuple[str, str]:
    """Return trust verdict title and body for a severity level."""
    verdicts = {
        "CRITICAL": (
            "🚨 ACTIVE FRAUD EXPOSURE CONFIRMED",
            "This target displays multiple high-severity structural indicators, positive machine learning inference classification, and threat feed confirmation. Immediate action required.",
        ),
        "HIGH": (
            "⚠️ ELEVATED BRAND EXPOSURE FLAG",
            "Strong structural anomalies or machine learning signals detected. Triage within standard SLA boundaries is highly recommended.",
        ),
        "MEDIUM": (
            "◌ SUSPICIOUS ANOMALY DETECTION",
            "Moderate signs of exposure. Domain exhibits standard lookalike patterns but lacks active threat intelligence signals. Monitor changes.",
        ),
        "LOW": (
            "✓ NO IMMEDIATE EXPOSURE SIGNALED",
            "No high-severity structural patterns detected. Domain appears legitimate or does not imitate protected organizational assets.",
        ),
    }
    return verdicts.get(str(severity).upper(), verdicts["LOW"])

def get_analysis_depth_label(conf_pct: int) -> Tuple[str, str]:
    """Return depth label and description based on confidence percentage."""
    if conf_pct >= 90:
        return "DEEP SCAN", "Comprehensive intelligence layers compiled and validated."
    elif conf_pct >= 75:
        return "STANDARD", "Standard heuristics, ML, and threat intelligence feeds resolved."
    else:
        return "PARTIAL", "Limited evidence sources or offline-only reputation checks."
