"""
AERIS Intelligence Layer
========================
Modular intelligence engine -- Layer 1 through Layer 6.

Imports:
    from intelligence.adversarial_filter import AdversarialFilter, AdversarialProfile
    from intelligence.correlation_engine import CorrelationEngine, CorrelationReport
    from intelligence.threat_memory import ThreatMemory, HistoricalContext
    from intelligence.threat_reasoning import ThreatReasoningEngine, ThreatNarrative, AttackerIntent
    from intelligence.business_context import BusinessContextEngine, BusinessContextProfile
    from intelligence.feed_connector import FeedConnector, FeedEnrichment
"""
from .adversarial_filter import AdversarialFilter, AdversarialProfile
from .correlation_engine import CorrelationEngine, CorrelationReport
from .threat_memory import ThreatMemory, HistoricalContext, CampaignPattern
from .threat_reasoning import ThreatReasoningEngine, ThreatNarrative, AttackerIntent, RemediationPlan
from .business_context import BusinessContextEngine, BusinessContextProfile
from .feed_connector import FeedConnector, FeedEnrichment

__all__ = [
    "AdversarialFilter", "AdversarialProfile",
    "CorrelationEngine", "CorrelationReport",
    "ThreatMemory", "HistoricalContext", "CampaignPattern",
    "ThreatReasoningEngine", "ThreatNarrative", "AttackerIntent", "RemediationPlan",
    "BusinessContextEngine", "BusinessContextProfile",
    "FeedConnector", "FeedEnrichment",
]
