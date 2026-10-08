"""
AERIS Infrastructure Graph Visualization
==========================================
Renders the threat correlation and infrastructure graph from REAL evidence only.

CONSTITUTION REQUIREMENT:
  - Every node must be sourced from actual scan data or DB records.
  - If insufficient data exists, render empty_state_html, not placeholder nodes.
  - DataProvenance is MANDATORY. Never render without it.
  - Banned: Hardcoded IPs, ASNs, campaign IDs, or brand references embedded in this file.
"""
from __future__ import annotations

import html as _html
from typing import List, Optional, Dict, Any
from visualizations.provenance import DataProvenance, provenance_footer_html, empty_state_html


def build_graph_nodes_from_evidence(
    evidence: List[str],
    related_targets: List[str],
    target: str,
    severity: str,
    resolution_ip: Optional[str] = None,
    resolution_asn: Optional[str] = None,
    gsb_flagged: bool = False,
    vt_flagged: bool = False,
    cert_checked: bool = False,
) -> Dict[str, Any]:
    """
    Build graph node data from actual evidence. Returns a dict with node lists.
    Only creates nodes for data that actually exists.

    Returns:
        {
            "central_node": {...},
            "satellite_nodes": [...],
            "data_available": bool
        }
    """
    satellite_nodes = []

    # IP Address node: only if we have a real resolved IP
    if resolution_ip and resolution_ip not in ("", "N/A", "unknown"):
        satellite_nodes.append({
            "label": "HOST IP ADDRESS",
            "sub": _html.escape(resolution_ip),
            "type": "ip",
            "confidence": "DNS Resolution (Recorded at Scan Time)",
            "color": "#fd7e14",
            "source": "dns_resolution",
        })

    # ASN node: only if we have a real resolved ASN
    if resolution_asn and resolution_asn not in ("", "N/A", "unknown"):
        satellite_nodes.append({
            "label": "HOSTING ASN",
            "sub": _html.escape(resolution_asn),
            "type": "asn",
            "confidence": "ASN Lookup (Recorded at Scan Time)",
            "color": "#ffc107",
            "source": "asn_lookup",
        })

    # GSB Threat Signature node: only if Google Safe Browsing flagged this target
    if gsb_flagged:
        satellite_nodes.append({
            "label": "THREAT SIGNATURE",
            "sub": "Google Safe Browsing: FLAGGED",
            "type": "threat_feed",
            "confidence": "Google Safe Browsing API Response",
            "color": "#dc3545",
            "source": "google_safe_browsing",
        })

    # VirusTotal node: only if VT flagged this target
    if vt_flagged:
        satellite_nodes.append({
            "label": "VT DETECTION",
            "sub": "VirusTotal: Engines Flagged",
            "type": "threat_feed",
            "confidence": "VirusTotal API Response",
            "color": "#dc3545",
            "source": "virustotal",
        })

    # Certificate node: only if cert was checked (evidence mentions SSL/TLS)
    if cert_checked or any("SSL" in e.upper() or "TLS" in e.upper() or "CERT" in e.upper() for e in evidence):
        satellite_nodes.append({
            "label": "CERT STATUS",
            "sub": "TLS Certificate Analyzed",
            "type": "certificate",
            "confidence": "SSL Certificate Check",
            "color": "#20c997",
            "source": "ssl_check",
        })

    # Related targets from DB (historical infrastructure cluster)
    for idx, peer in enumerate(related_targets[:3]):
        satellite_nodes.append({
            "label": f"CORRELATED HOST",
            "sub": _html.escape(peer.upper()[:30]),
            "type": "related",
            "confidence": "Historical Infrastructure Cluster (DB)",
            "color": "#a370f7",
            "source": "threat_memory",
        })

    return {
        "central_node": {
            "target": _html.escape(target),
            "severity": severity,
        },
        "satellite_nodes": satellite_nodes,
        "data_available": len(satellite_nodes) > 0,
    }


def render_infrastructure_graph(
    evidence: List[str],
    related_targets: List[str],
    target: str,
    severity: str,
    provenance: DataProvenance,
    resolution_ip: Optional[str] = None,
    resolution_asn: Optional[str] = None,
    gsb_flagged: bool = False,
    vt_flagged: bool = False,
) -> str:
    """
    Render the infrastructure correlation graph as an SVG embedded in HTML.

    All nodes are generated from actual evidence only. If no real infrastructure
    data exists, returns an empty state panel with provenance footer.

    Args:
        evidence:         Evidence strings from the assessment
        related_targets:  Related domains from ThreatMemory (DB-sourced)
        target:           The assessed target domain
        severity:         Risk severity (LOW/MEDIUM/HIGH/CRITICAL)
        provenance:       DataProvenance object (MANDATORY)
        resolution_ip:    Actual resolved IP address (None if not resolved)
        resolution_asn:   Actual ASN string (None if not resolved)
        gsb_flagged:      Whether Google Safe Browsing flagged this target
        vt_flagged:       Whether VirusTotal flagged this target

    Returns:
        HTML string containing the graph or empty state + provenance footer
    """
    graph_data = build_graph_nodes_from_evidence(
        evidence=evidence,
        related_targets=related_targets,
        target=target,
        severity=severity,
        resolution_ip=resolution_ip,
        resolution_asn=resolution_asn,
        gsb_flagged=gsb_flagged,
        vt_flagged=vt_flagged,
    )

    prov_footer = provenance_footer_html(provenance)

    if not graph_data["data_available"]:
        empty = empty_state_html(
            title="No Infrastructure Data Available",
            reason=(
                "Infrastructure graph requires real DNS resolution, ASN data, "
                "or threat feed responses. Run a full assessment to populate this panel. "
                "No placeholder data is shown."
            ),
            icon="⬡",
        )
        return (
            f'<div class="ep" style="border-left:3px solid #6c757d;">'
            f'<div class="ep-hdr" style="background:transparent;">'
            f'<div class="ep-pulse" style="background:#6c757d;"></div>'
            f'<span class="ep-title" style="color:#a0a0a0;">Threat Correlation &amp; Infrastructure Graph</span>'
            f'<span class="ep-tag">Evidence-Conditional</span>'
            f'</div>'
            f'<div class="ep-body">{empty}{prov_footer}</div>'
            f'</div>'
        )

    # Build SVG with only real nodes
    cx, cy = 325, 170
    glow_color = "#dc3545" if severity in ("HIGH", "CRITICAL") else "#fd7e14"
    target_label = _html.escape(target.upper()[:25])

    nodes_html = [
        f'<circle cx="{cx}" cy="{cy}" r="16" fill="#000" stroke="{glow_color}" '
        f'stroke-width="3" style="filter:drop-shadow(0 0 6px {glow_color}80);"/>',
        f'<text x="{cx}" y="{cy - 24}" fill="{glow_color}" font-size="9.5" '
        f'font-weight="900" text-anchor="middle" font-family="monospace">{target_label}</text>',
        f'<text x="{cx}" y="{cy + 28}" fill="{glow_color}" font-size="7" '
        f'opacity="0.6" text-anchor="middle" font-family="monospace">TARGET</text>',
    ]
    lines_html = []

    # Lay out satellite nodes in a circle
    import math
    satellites = graph_data["satellite_nodes"]
    angle_step = 360.0 / max(len(satellites), 1)
    radius = 130

    for i, node in enumerate(satellites):
        angle_rad = math.radians(i * angle_step - 90)
        nx = cx + radius * math.cos(angle_rad)
        ny = cy + radius * math.sin(angle_rad)
        color = node["color"]
        label = node["label"][:16]
        sub = node["sub"][:20]
        conf = _html.escape(node["confidence"])

        # Edge line
        stroke = "rgba(255,255,255,0.08)"
        if node["type"] == "threat_feed":
            stroke = "rgba(220,53,69,0.4)"
        elif node["type"] == "related":
            stroke = "rgba(163,112,247,0.3)"
        elif node["type"] == "certificate":
            stroke = "rgba(32,201,151,0.25)"

        lines_html.append(
            f'<line x1="{cx}" y1="{cy}" x2="{nx:.1f}" y2="{ny:.1f}" '
            f'stroke="{stroke}" stroke-width="1.5"/>'
        )

        nodes_html.append(
            f'<g style="cursor:pointer;">'
            f'<title>Source: {conf}\nData: {sub}</title>'
            f'<circle cx="{nx:.1f}" cy="{ny:.1f}" r="7" fill="#000" '
            f'stroke="{color}" stroke-width="2"/>'
            f'<text x="{nx:.1f}" y="{ny - 14:.1f}" fill="{color}" font-size="7" '
            f'font-weight="800" text-anchor="middle" font-family="monospace">{_html.escape(label)}</text>'
            f'<text x="{nx:.1f}" y="{ny + 16:.1f}" fill="#a0a0a0" font-size="6.5" '
            f'font-weight="500" text-anchor="middle" font-family="monospace">{_html.escape(sub)}</text>'
            f'</g>'
        )

    node_count = len(satellites)
    svg_content = (
        f'<svg width="100%" height="320" viewBox="0 0 650 340" fill="none">'
        f'{"".join(lines_html)}'
        f'{"".join(nodes_html)}'
        f'<text x="15" y="330" fill="#555" font-size="7" font-family="monospace">'
        f'{node_count} evidence-backed nodes \u2014 no placeholder data</text>'
        f'</svg>'
    )

    return (
        f'<div class="ep" style="border-left:3px solid #0dcaf0;">'
        f'<div class="ep-hdr" style="background:linear-gradient(90deg,rgba(13,202,240,0.1) 0%,transparent 100%);">'
        f'<div class="ep-pulse" style="background:#0dcaf0;"></div>'
        f'<span class="ep-title" style="color:#0dcaf0;">Threat Correlation &amp; Infrastructure Graph</span>'
        f'<span class="ep-tag">{node_count} Evidence Nodes</span>'
        f'</div>'
        f'<div class="ep-body">'
        f'<div style="font-size:0.72rem;margin-bottom:8px;opacity:0.7;line-height:1.4;">'
        f'Infrastructure nodes sourced from DNS resolution, ASN lookup, and threat feed responses '
        f'recorded at scan time. Only verified data is shown.'
        f'</div>'
        f'<div style="background:rgba(0,0,0,0.15);border:1px solid rgba(255,255,255,0.04);'
        f'border-radius:6px;padding:8px;">'
        f'{svg_content}'
        f'</div>'
        f'{prov_footer}'
        f'</div>'
        f'</div>'
    )
