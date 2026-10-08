"""
AERIS Visualization Framework
==============================
All visualizations in AERIS must:
1. Accept a DataProvenance object as an argument.
2. Render a provenance footer showing SOURCE, DATASET, QUERY, CONFIDENCE, LAST_UPDATED.
3. Return an empty-state HTML string if the evidence data is absent or empty.
4. Never embed hardcoded intelligence data (IPs, ASNs, domains, campaign IDs).

This is a non-negotiable enterprise requirement per docs/AERIS_ENTERPRISE_CONSTITUTION.md
"""
from .provenance import DataProvenance, empty_state_html, provenance_footer_html
