"""
Threat Reasoning Engine
=======================
Layer 5 -- AI-Assisted Investigation

Architecture: Hybrid offline-first deterministic reasoning with optional LLM augmentation.

Core Engine (offline, always runs):
    - Rule-based attacker intent classification
    - Contradiction detection in evidence chain
    - Structured threat narrative generation
    - Remediation plan generation

Optional LLM Enhancement (runs only if LLM_PROVIDER != 'none'):
    - Richer executive summary language
    - Contextual remediation descriptions
    - Attacker-intent explanation in natural language

LLM providers supported:
    - none     (fully offline, default)
    - openai   (requires OPENAI_API_KEY)
    - gemini   (requires GEMINI_API_KEY)
    - ollama   (requires local Ollama server, no key needed)

Enterprise principle:
    Core scoring/reasoning is always deterministic and auditable.
    LLM output is AUGMENTATION only -- it never changes the score or findings.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------------------
# Data Contracts
# ------------------------------------------------------------------------------

@dataclass
class AttackerIntent:
    """Estimated attacker intent based on evidence pattern analysis."""
    primary_intent: str           # credential_harvest | data_exfil | recon | infra_reuse | sabotage
    confidence: float             # 0-1
    supporting_signals: List[str] # Evidence findings that support this intent
    campaign_similarity: Optional[str] = None  # Matched campaign ID if any
    secondary_intents: List[str] = field(default_factory=list)

    def label(self) -> str:
        mapping = {
            "credential_harvest": "Credential Harvesting",
            "data_exfil":         "Data Exfiltration",
            "recon":              "Reconnaissance",
            "infra_reuse":        "Infrastructure Reuse / C2",
            "sabotage":           "Service Disruption / Sabotage",
            "unknown":            "Unknown / Multi-purpose",
        }
        return mapping.get(self.primary_intent, self.primary_intent.replace("_", " ").title())


@dataclass
class RemediationAction:
    priority: int        # 1 = immediate, 2 = short-term, 3 = medium-term
    owner: str           # Security Team | IT Operations | Development | Management
    action: str          # What to do
    rationale: str       # Why this action
    sla_days: int        # Suggested completion timeline
    effort: str          # LOW | MEDIUM | HIGH


@dataclass
class RemediationPlan:
    immediate_actions: List[RemediationAction] = field(default_factory=list)
    short_term_actions: List[RemediationAction] = field(default_factory=list)
    medium_term_actions: List[RemediationAction] = field(default_factory=list)

    def all_actions(self) -> List[RemediationAction]:
        return self.immediate_actions + self.short_term_actions + self.medium_term_actions


@dataclass
class ThreatNarrative:
    """
    Complete threat analysis narrative for a single target.
    Contains both technical (analyst) and executive (board) layers.
    """
    # Core (deterministic -- always populated)
    executive_summary: str              # 2-3 sentence non-technical board summary
    technical_detail: str               # Analyst-level detail with evidence references
    attacker_intent: AttackerIntent
    inconsistencies: List[str]          # Detected contradictions in evidence
    confidence_narrative: str           # Plain-English explanation of confidence

    # Remediation
    remediation_plan: Optional[RemediationPlan] = None

    # LLM augmentation (optional -- only populated if LLM is enabled)
    llm_executive_advisory: Optional[str] = None
    llm_remediation_language: Optional[str] = None
    llm_provider_used: str = "none"

    def executive_output(self) -> str:
        """Return LLM advisory if available, else deterministic summary."""
        return self.llm_executive_advisory or self.executive_summary


# ------------------------------------------------------------------------------
# Intent classification rules
# ------------------------------------------------------------------------------

_INTENT_RULES = {
    "credential_harvest": [
        "login", "signin", "password", "credential", "phishing",
        "harvest", "account", "verify", "authentication", "otp",
    ],
    "data_exfil": [
        "leak", "breach", "exposed", "dump", "exfil", "database",
        "backup", "sql", "sensitive", "pii", ".env", "config",
    ],
    "recon": [
        "admin", "panel", "dashboard", "management", "scan", "probe",
        "enumeration", "subdomain", "discovery",
    ],
    "infra_reuse": [
        "infrastructure", "campaign", "cluster", "reuse", "bulletproof",
        "c2", "command", "control", "hosting",
    ],
    "sabotage": [
        "ddos", "denial", "disruption", "downtime", "takeover",
        "defacement", "injection", "ransomware",
    ],
}

_SEVERITY_ADVISORIES = {
    "CRITICAL": (
        "This target exhibits indicators consistent with an active or imminent threat. "
        "The risk profile warrants immediate escalation to senior security leadership "
        "and an emergency response review."
    ),
    "HIGH": (
        "Significant risk indicators have been detected. This target requires prioritized "
        "attention within the next 24-48 hours to prevent potential escalation."
    ),
    "MEDIUM": (
        "Moderate risk exposure detected. While not immediately critical, these findings "
        "should be reviewed and remediated within the standard SLA window."
    ),
    "LOW": (
        "Low-level indicators detected. Monitor this target and address findings during "
        "the next scheduled security review cycle."
    ),
}


# ------------------------------------------------------------------------------
# ThreatReasoningEngine
# ------------------------------------------------------------------------------

class ThreatReasoningEngine:
    """
    Deterministic threat reasoning with optional LLM augmentation.

    Usage:
        engine = ThreatReasoningEngine()
        narrative = engine.analyze(evidence_chain, tiered_confidence,
                                   correlation_report, severity="HIGH")
    """

    def __init__(self):
        self._llm_provider = os.getenv("LLM_PROVIDER", "none").lower().strip()
        logger.info(f"[ThreatReasoning] LLM provider: {self._llm_provider}")

    def analyze(
        self,
        evidence_chain,           # EvidenceChain
        tiered_confidence,        # TieredConfidence
        correlation_report=None,  # CorrelationReport (optional)
        severity: str = "MEDIUM",
        target: str = "",
    ) -> ThreatNarrative:
        """
        Full threat analysis combining deterministic reasoning and optional LLM.

        Args:
            evidence_chain:     EvidenceChain from risk scoring pipeline
            tiered_confidence:  TieredConfidence from ConfidenceScorer
            correlation_report: CorrelationReport from CorrelationEngine (optional)
            severity:           Risk level string (LOW/MEDIUM/HIGH/CRITICAL)
            target:             Domain or URL being analyzed

        Returns:
            ThreatNarrative with full analysis
        """
        findings = [item.finding for item in evidence_chain] if evidence_chain else []

        # 1. Attacker intent
        intent = self.estimate_attacker_intent(findings, correlation_report)

        # 2. Inconsistencies
        inconsistencies = self.detect_inconsistencies(evidence_chain)

        # 3. Deterministic narrative
        exec_summary = self._build_executive_summary(
            severity, intent, tiered_confidence, target
        )
        technical_detail = self._build_technical_detail(
            findings, intent, inconsistencies, correlation_report
        )
        confidence_narrative = (
            tiered_confidence.narrative()
            if hasattr(tiered_confidence, "narrative")
            else f"Confidence: {getattr(tiered_confidence, 'label', lambda: 'UNKNOWN')()}"
        )

        # 4. Remediation plan
        remediation = self._build_remediation_plan(findings, severity, intent)

        narrative = ThreatNarrative(
            executive_summary=exec_summary,
            technical_detail=technical_detail,
            attacker_intent=intent,
            inconsistencies=inconsistencies,
            confidence_narrative=confidence_narrative,
            remediation_plan=remediation,
            llm_provider_used="none",
        )

        # 5. Optional LLM augmentation (never changes scores or intent)
        if self._llm_provider != "none":
            self._augment_with_llm(narrative, target, severity, findings)

        return narrative

    def estimate_attacker_intent(
        self,
        findings: List[str],
        correlation_report=None,
    ) -> AttackerIntent:
        """Classify attacker intent from evidence findings using rule matching."""
        ev_text = " ".join(findings).lower()
        scores: Dict[str, int] = {}

        for intent, keywords in _INTENT_RULES.items():
            score = sum(1 for kw in keywords if kw in ev_text)
            if score > 0:
                scores[intent] = score

        # Boost from correlation campaigns
        if correlation_report and hasattr(correlation_report, "campaign_matches"):
            for camp_id in correlation_report.campaign_matches:
                camp_lower = camp_id.lower()
                if "credential" in camp_lower:
                    scores["credential_harvest"] = scores.get("credential_harvest", 0) + 3
                elif "reuse" in camp_lower or "infra" in camp_lower:
                    scores["infra_reuse"] = scores.get("infra_reuse", 0) + 3

        if not scores:
            return AttackerIntent(
                primary_intent="unknown",
                confidence=0.25,
                supporting_signals=findings[:3],
            )

        primary = max(scores, key=scores.get)
        total = sum(scores.values())
        confidence = min(0.95, scores[primary] / max(total, 1) * 1.2)

        supporting = [
            f for f in findings
            if any(kw in f.lower() for kw in _INTENT_RULES.get(primary, []))
        ][:5]

        secondary = [
            k for k, v in sorted(scores.items(), key=lambda x: -x[1])
            if k != primary
        ][:2]

        return AttackerIntent(
            primary_intent=primary,
            confidence=round(confidence, 2),
            supporting_signals=supporting,
            secondary_intents=secondary,
        )

    def detect_inconsistencies(self, evidence_chain) -> List[str]:
        """
        Detect contradictions in evidence that reduce confidence.
        Examples: VirusTotal clean + heuristics flag as CRITICAL.
        """
        inconsistencies = []
        if not evidence_chain or len(evidence_chain) == 0:
            return inconsistencies

        items = list(evidence_chain)

        # Check for reputation contradiction
        vt_clean = any(
            "virustotal" in getattr(i, "source", "").lower()
            and getattr(i, "severity_contribution", 0) < 10
            for i in items
        )
        high_struct = any(
            getattr(i, "signal_type", None) is not None
            and "structural" in str(getattr(i, "signal_type", "")).lower()
            and getattr(i, "severity_contribution", 0) > 50
            for i in items
        )
        if vt_clean and high_struct:
            inconsistencies.append(
                "Reputation signals (VirusTotal) indicate low risk, "
                "but structural analysis flags significant concerns. "
                "Target may be newly registered or using evasion techniques."
            )

        # Check for safety vs risk contradiction
        safety_clean = any(
            "safe" in getattr(i, "source", "").lower()
            and getattr(i, "severity_contribution", 0) < 5
            for i in items
        )
        ml_high = any(
            "ml" in str(getattr(i, "signal_type", "")).lower()
            and getattr(i, "severity_contribution", 0) > 40
            for i in items
        )
        if safety_clean and ml_high:
            inconsistencies.append(
                "Safety signals indicate trusted status, but ML model "
                "detected suspicious URL patterns. Recommend manual review."
            )

        return inconsistencies

    # -- Narrative builders --------------------------------------------------

    def _build_executive_summary(
        self,
        severity: str,
        intent: AttackerIntent,
        tiered_confidence,
        target: str,
    ) -> str:
        severity_text = _SEVERITY_ADVISORIES.get(severity.upper(), _SEVERITY_ADVISORIES["MEDIUM"])
        intent_text = (
            f"Analysis indicates the primary threat vector is {intent.label()} "
            f"(confidence: {intent.confidence:.0%})."
        )
        confidence_label = (
            tiered_confidence.label()
            if hasattr(tiered_confidence, "label")
            else "MODERATE"
        )
        confidence_text = (
            f"Assessment confidence is {confidence_label}, based on "
            f"{tiered_confidence.composite_pct if hasattr(tiered_confidence, 'composite_pct') else '--'}% "
            f"composite signal coverage."
        )
        return f"{severity_text} {intent_text} {confidence_text}"

    def _build_technical_detail(
        self,
        findings: List[str],
        intent: AttackerIntent,
        inconsistencies: List[str],
        correlation_report=None,
    ) -> str:
        parts = []

        if findings:
            top_findings = findings[:5]
            parts.append("Key findings: " + " | ".join(top_findings))

        if intent.supporting_signals:
            parts.append(
                f"Intent signals ({intent.label()}): "
                + "; ".join(intent.supporting_signals[:3])
            )

        if correlation_report:
            cluster_size = len(getattr(correlation_report, "infrastructure_cluster", []))
            if cluster_size > 0:
                parts.append(f"Infrastructure correlation: {cluster_size} related domain(s) identified")
            if getattr(correlation_report, "cert_reuse_detected", False):
                parts.append("Certificate transparency: TLS certificate reuse detected across domains")
            campaigns = getattr(correlation_report, "campaign_matches", [])
            if campaigns:
                parts.append(f"Campaign matches: {', '.join(campaigns)}")

        if inconsistencies:
            parts.append("Evidence inconsistencies: " + " | ".join(inconsistencies))

        return "\n".join(parts) if parts else "No detailed technical findings available."

    def _build_remediation_plan(
        self,
        findings: List[str],
        severity: str,
        intent: AttackerIntent,
    ) -> RemediationPlan:
        plan = RemediationPlan()
        ev_text = " ".join(findings).lower()

        # Immediate actions for CRITICAL/HIGH
        if severity in ("CRITICAL", "HIGH"):
            plan.immediate_actions.append(RemediationAction(
                priority=1,
                owner="Security Team",
                action="Block access to this domain/IP at perimeter firewall and DNS resolver",
                rationale="Prevent user traffic from reaching confirmed high-risk infrastructure",
                sla_days=1,
                effort="LOW",
            ))

        # Intent-specific remediations
        if intent.primary_intent == "credential_harvest":
            plan.immediate_actions.append(RemediationAction(
                priority=1,
                owner="Security Team",
                action="Issue credential reset advisory to all users who may have visited this domain",
                rationale="Potential credential compromise via phishing/harvest infrastructure",
                sla_days=1,
                effort="MEDIUM",
            ))

        if "leak" in ev_text or "breach" in ev_text or "credential" in ev_text:
            plan.short_term_actions.append(RemediationAction(
                priority=2,
                owner="IT Operations",
                action="Rotate all API keys, tokens, and service credentials associated with this domain",
                rationale="Evidence suggests credential or secret exposure",
                sla_days=7,
                effort="MEDIUM",
            ))

        if "admin" in ev_text or "panel" in ev_text:
            plan.short_term_actions.append(RemediationAction(
                priority=2,
                owner="IT Operations",
                action="Disable or restrict access to administrative interfaces from public internet",
                rationale="Exposed admin panels are primary targets for unauthorized access",
                sla_days=3,
                effort="LOW",
            ))

        # Standard medium-term actions
        plan.medium_term_actions.append(RemediationAction(
            priority=3,
            owner="Security Team",
            action="Add domain to threat watchlist for ongoing monitoring",
            rationale="Continuous monitoring ensures early detection of infrastructure changes",
            sla_days=30,
            effort="LOW",
        ))

        plan.medium_term_actions.append(RemediationAction(
            priority=3,
            owner="Management",
            action="Review and update third-party domain monitoring coverage",
            rationale="Expand attack surface visibility to detect lookalike domains proactively",
            sla_days=30,
            effort="MEDIUM",
        ))

        return plan

    # -- LLM Augmentation ---------------------------------------------------

    def _augment_with_llm(
        self,
        narrative: ThreatNarrative,
        target: str,
        severity: str,
        findings: List[str],
    ) -> None:
        """
        Optionally enhance the narrative with LLM-generated language.
        NEVER changes scores, intent classification, or evidence.
        Failures are silently swallowed -- core narrative always takes precedence.
        """
        try:
            prompt = self._build_llm_prompt(target, severity, findings, narrative)
            llm_text = self._call_llm(prompt)
            if llm_text:
                narrative.llm_executive_advisory = llm_text
                narrative.llm_provider_used = self._llm_provider
        except Exception as e:
            logger.debug(f"[ThreatReasoning] LLM augmentation failed (non-fatal): {e}")

    def _build_llm_prompt(
        self,
        target: str,
        severity: str,
        findings: List[str],
        narrative: ThreatNarrative,
    ) -> str:
        findings_text = "\n".join(f"- {f}" for f in findings[:8])
        return (
            f"You are a cybersecurity analyst writing an executive advisory for a board-level audience.\n"
            f"Target: {target}\n"
            f"Risk Level: {severity}\n"
            f"Attacker Intent: {narrative.attacker_intent.label()} "
            f"(confidence: {narrative.attacker_intent.confidence:.0%})\n"
            f"Key Findings:\n{findings_text}\n\n"
            f"Write a concise, professional, non-technical executive advisory (3 paragraphs max). "
            f"Do NOT invent findings. Do NOT change the risk level. "
            f"Focus on business impact and recommended executive action."
        )

    def _call_llm(self, prompt: str) -> Optional[str]:
        provider = self._llm_provider

        if provider == "openai":
            return self._call_openai(prompt)
        elif provider == "gemini":
            return self._call_gemini(prompt)
        elif provider == "ollama":
            return self._call_ollama(prompt)
        return None

    def _call_openai(self, prompt: str) -> Optional[str]:
        import requests
        api_key = os.getenv("OPENAI_API_KEY", "")
        if not api_key:
            return None
        resp = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 400,
                "temperature": 0.3,
            },
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"].strip()

    def _call_gemini(self, prompt: str) -> Optional[str]:
        import requests
        api_key = os.getenv("GEMINI_API_KEY", "")
        if not api_key:
            return None
        resp = requests.post(
            f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}",
            json={"contents": [{"parts": [{"text": prompt}]}]},
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()["candidates"][0]["content"]["parts"][0]["text"].strip()

    def _call_ollama(self, prompt: str) -> Optional[str]:
        import requests
        base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
        model = os.getenv("OLLAMA_MODEL", "llama3")
        resp = requests.post(
            f"{base_url}/api/generate",
            json={"model": model, "prompt": prompt, "stream": False},
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json().get("response", "").strip()
