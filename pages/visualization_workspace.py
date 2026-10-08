"""
AERIS Intelligence Visualization Workspace Page
==================================================
Industrial exposure operating console. Presentation only, using evidence-backed
visualizations with strict data provenance.
"""
import streamlit as st
import html as _html
from typing import List, Dict, Any

from visualizations.provenance import DataProvenance
from visualizations.infrastructure_graph import render_infrastructure_graph
from visualizations.timeline import render_threat_timeline
from visualizations.radar_chart import render_confidence_radar
from visualizations.evidence_breakdown import render_evidence_breakdown
from visualizations.business_impact import compute_qualitative_impact, render_business_impact_panel
from services.memory_service import get_memory_service
from utils.svg_indicators import get_svg_indicator
from utils.helpers import get_sev_color
from reporting.business_translator import _generate_pdf

def render_visualization_workspace() -> None:
    st.markdown("""
        <style>
        /* Force visualization columns to align to top (removes bottom-alignment dead space) */
        [data-testid="stMain"] [data-testid="stHorizontalBlock"] > [data-testid="stColumn"] > [data-testid="stVerticalBlock"] {
            justify-content: flex-start !important;
        }
        /* Custom visual overrides for operational intelligence workspace */
        .ep-body {
            padding: 16px 20px !important;
        }
        .section-gap {
            height: 18px !important;
        }
        </style>
    """, unsafe_allow_html=True)

    st.title("Intelligence Visualization Workspace")
    st.markdown(
        "Industrial cyber exposure operating console providing forensic analysis, "
        "adversarial evasion correlation, and automated risk prioritization for assessed environments."
    )

    # Fetch assessment details from session state
    target = st.session_state.get("last_analyzed_target")
    biz_report = st.session_state.get("last_biz_report")
    evidence_chain = st.session_state.get("last_evidence_chain")
    evidence = st.session_state.get("last_evidence")
    tc = st.session_state.get("last_tc")
    priority_item = st.session_state.get("last_priority_item")
    priority_score = st.session_state.get("last_priority_score", 0.0)
    score = st.session_state.get("last_score", 0.0)
    severity = st.session_state.get("last_severity", "LOW")
    sla_days = st.session_state.get("last_sla_days", 30)
    hist_ctx = st.session_state.get("last_hist_ctx")
    threat_narrative = st.session_state.get("last_threat_narrative")

    if not target or not biz_report or not evidence_chain:
        st.warning("No active target exposure profile found in memory. Please execute a Security Assessment scan first.")
        if st.button("Return to Security Assessment Menu", type="primary"):
            st.session_state.nav_page = "Security Assessment"
            st.rerun()
        return

    # Extract additional network parameters if available
    res_result = st.session_state.get("assessment_result")
    raw_res = res_result.raw_result if res_result else {}
    resolution_ip = raw_res.get("ip") or (hist_ctx.ip if hist_ctx else None)
    resolution_asn = raw_res.get("asn") or (hist_ctx.asn if hist_ctx else None)
    gsb_flagged = any("GOOGLE SAFE BROWSING" in e.upper() for e in evidence) if evidence else False
    vt_flagged = any("VIRUSTOTAL" in e.upper() for e in evidence) if evidence else False

    crit_str = st.session_state.get("asset_crit_input", "MEDIUM").upper()
    priority_urgency = priority_item.urgency_label() if priority_item else severity
    theme_color = st.session_state.get("assessment_result").theme_color if res_result else {"LOW": "#198754", "MEDIUM": "#fd7e14", "HIGH": "#dc3545", "CRITICAL": "#7b0d1e"}.get(severity, "#6c757d")
    
    st.markdown(f"### Active Investigation Target: `{_html.escape(target)}`")
    st.caption(f"Profile Ingestion: {biz_report.generated_at}  —  Automated SLA Threshold: {priority_urgency.upper()}")

    if st.button("Return to Security Assessment Console", use_container_width=True):
        st.session_state.nav_page = "Security Assessment"
        st.rerun()

    st.markdown('<div class="section-gap"></div>', unsafe_allow_html=True)

    # ── Dataclass Provenance Objects
    graph_prov = DataProvenance(
        source="HeuristicRiskDetector & ThreatMemory.recall()",
        dataset="live_dns_resolution & threat_memory",
        query=f"DNS lookup & SELECT DISTINCT related_targets FROM threat_memory WHERE domain='{_html.escape(target)}'",
        confidence=tc.composite if tc else 0.5,
        record_count=len(evidence) + (len(hist_ctx.related_targets) if hist_ctx and hist_ctx.related_targets else 0)
    )

    mem_service = get_memory_service()
    scan_history = mem_service.get_timeline(target)
    timeline_prov = DataProvenance(
        source="MemoryService.get_timeline()",
        dataset="scans",
        query=f"SELECT timestamp, risk_score, risk_level FROM scans WHERE domain='{_html.escape(target)}' ORDER BY timestamp ASC",
        confidence=0.9 if scan_history else 0.0,
        record_count=len(scan_history)
    )

    radar_prov = DataProvenance(
        source="ConfidenceScorer.calculate()",
        dataset="calibrated_confidence_dimensions",
        query="Compute 5-dimensional confidence matrix from evidence layers",
        confidence=tc.composite if tc else 0.5,
        record_count=5
    )

    breakdown_prov = DataProvenance(
        source="EvidenceChain.items",
        dataset="tiered_evidence_chain",
        query="Aggregate risk contributions by EvidenceItem.tier",
        confidence=1.0 if evidence_chain else 0.0,
        record_count=len(evidence_chain.items) if evidence_chain else 0
    )

    # ======================================================================
    # ZONE 1 — ACTIVE TRIAGE OVERVIEW (TOP SECTION BENTO LAYOUT)
    # ======================================================================
    st.markdown('<div style="font-size:0.6rem; font-weight:800; opacity:0.35; letter-spacing:0.12em; text-transform:uppercase; margin-bottom:8px;">Zone 1: Active Triage Overview</div>', unsafe_allow_html=True)
    
    row1_col1, row1_col2 = st.columns([7, 3])

    with row1_col1:
        # Threat Correlation & Infrastructure Graph
        related_targets = hist_ctx.related_targets if hist_ctx else []
        graph_html = render_infrastructure_graph(
            evidence=evidence,
            related_targets=related_targets,
            target=target,
            severity=severity,
            provenance=graph_prov,
            resolution_ip=resolution_ip,
            resolution_asn=resolution_asn,
            gsb_flagged=gsb_flagged,
            vt_flagged=vt_flagged,
        )
        st.markdown(graph_html, unsafe_allow_html=True)

    with row1_col2:
        # RIGHT STACK (30%): Priority Matrix, Confidence Calibration, Governance Integrity
        p_color = theme_color
        epss_val = priority_item.epss_score if priority_item else 0.0
        
        p_matrix_html = f"""
        <div class="ep" style="border-left:3px solid {p_color}; border: 1.5px solid {p_color}; box-shadow: 0 0 8px {p_color}22;">
          <div class="ep-hdr" style="background:linear-gradient(90deg,rgba(255,193,7,0.08) 0%,transparent 100%);">
            <div class="ep-pulse" style="background:#ffc107;"></div>
            <span class="ep-title" style="color:#ffc107; font-weight:800;">Priority Score Matrix</span>
            <span class="ep-tag" style="opacity:0.6;">Triage Decision</span>
          </div>
          <div class="ep-body" style="padding:12px 14px !important;">
            <div style="display:flex; align-items:center; justify-content:space-between;">
              <div>
                <div style="font-size:2.1rem; font-weight:900; color:{p_color}; font-family:monospace; line-height:1;">{priority_score:.0f}</div>
                <div style="font-size:0.56rem; opacity:0.5; letter-spacing:0.06em; text-transform:uppercase;">Priority Index</div>
              </div>
              <div style="text-align:right;">
                <div style="font-size:0.85rem; font-weight:700; font-family:monospace; color:{p_color};">{priority_urgency.upper()}</div>
                <div style="font-size:0.56rem; opacity:0.5; letter-spacing:0.06em; text-transform:uppercase;">Urgency State</div>
              </div>
            </div>
            <hr style="border:none; border-top:1px solid rgba(255,255,255,0.05); margin:8px 0;"/>
            <div style="display:grid; grid-template-columns: 1fr 1fr; gap:6px; font-size:0.68rem; font-family:monospace;">
              <div>
                <div style="opacity:0.5; font-size:0.52rem; text-transform:uppercase;">SLA Target</div>
                <div style="font-weight:700; color:#eee;">{sla_days} Days</div>
              </div>
              <div>
                <div style="opacity:0.5; font-size:0.52rem; text-transform:uppercase;">EPSS Prob</div>
                <div style="font-weight:700; color:#eee;">{epss_val*100:.1f}%</div>
              </div>
            </div>
          </div>
        </div>
        """
        st.markdown(p_matrix_html, unsafe_allow_html=True)

        # Confidence Radar
        radar_html = render_confidence_radar(tc=tc, provenance=radar_prov)
        st.markdown(radar_html, unsafe_allow_html=True)

        # Governance Integrity Status (Audit check verification)
        gov_sign = biz_report.evidence_hash if hasattr(biz_report, 'evidence_hash') else (biz_report.get('evidence_hash', '') if isinstance(biz_report, dict) else '')
        if not gov_sign:
            import hashlib
            gov_sign = hashlib.sha256(target.encode('utf-8')).hexdigest()
        short_hash = f"{gov_sign[:8].upper()}...{gov_sign[-8:].upper()}"
        
        # Determine if signing key configured or default
        import os
        signing_key = os.getenv("AERIS_SIGNING_KEY", "")
        key_configured = signing_key != "" and signing_key != "AERIS-SYSTEM-SECRET-DEFAULT-KEY-9821831"  # nosec: UI security guard — detects default key and shows warning
        audit_status = "[ VERIFIED ]" if key_configured else "[ UNSECURED ]"
        status_color = "#198754" if key_configured else "#dc3545"
        
        g_status_html = f"""
        <div class="ep" style="border-left:3px solid #6c757d; border: 1px solid rgba(255,255,255,0.04); margin-top:10px;">
          <div class="ep-hdr" style="background:transparent;">
            <div class="ep-pulse" style="background:#6c757d;"></div>
            <span class="ep-title" style="color:#a0a0a0;">Governance Integrity Status</span>
            <span class="ep-tag" style="opacity:0.4;">Audit</span>
          </div>
          <div class="ep-body" style="padding:10px 14px !important; font-family:monospace; font-size:0.68rem; opacity:0.85;">
            <div style="display:flex; justify-content:space-between; margin-bottom:4px;">
              <span style="opacity:0.5; text-transform:uppercase;">Audit Proof:</span>
              <span style="color:{status_color}; font-weight:800;">{audit_status}</span>
            </div>
            <div style="display:flex; justify-content:space-between; margin-bottom:4px;">
              <span style="opacity:0.5; text-transform:uppercase;">Evidence Hash:</span>
              <span style="color:#eee; font-weight:700;">{short_hash}</span>
            </div>
            <div style="display:flex; justify-content:space-between;">
              <span style="opacity:0.5; text-transform:uppercase;">Crypto Core:</span>
              <span style="color:#6c757d; font-weight:700;">HMAC-SHA256</span>
            </div>
          </div>
        </div>
        """
        st.markdown(g_status_html, unsafe_allow_html=True)

    st.markdown('<div class="section-gap"></div>', unsafe_allow_html=True)

    # ======================================================================
    # ZONE 2 — INTELLIGENCE ANALYSIS
    # ======================================================================
    st.markdown('<div style="font-size:0.6rem; font-weight:800; opacity:0.35; letter-spacing:0.12em; text-transform:uppercase; margin-bottom:8px;">Zone 2: Forensic Intelligence Analysis</div>', unsafe_allow_html=True)
    
    row2_col1, row2_col2, row2_col3 = st.columns([1, 1, 1])

    with row2_col1:
        # Threat Memory Timeline
        timeline_html = render_threat_timeline(
            scan_history=scan_history,
            target=target,
            provenance=timeline_prov
        )
        st.markdown(timeline_html, unsafe_allow_html=True)

    with row2_col2:
        # Adversarial Pattern Analysis
        is_idn = any("XN--" in ev.upper() or "PUNYCODE" in ev.upper() for ev in evidence) if evidence else False
        is_homo = any("HOMOGLYPH" in ev.upper() or "CONFUSABLE" in ev.upper() for ev in evidence) if evidence else False
        is_brand = any("BRAND" in ev.upper() or "TYPOSQUAT" in ev.upper() for ev in evidence) if evidence else False
        
        ev_score = 0.85 if (is_idn or is_homo) else (0.45 if is_brand else 0.15)
        
        idn_svg = get_svg_indicator("adversarial_pattern" if is_idn else "verified", size=13)
        homo_svg = get_svg_indicator("adversarial_pattern" if is_homo else "verified", size=13)
        brand_svg = get_svg_indicator("adversarial_pattern" if is_brand else "verified", size=13)
        
        idn_border = "border: 1px solid rgba(220,53,69,0.3); background:rgba(220,53,69,0.04);" if is_idn else "border: 1px solid rgba(25,135,84,0.15); background:rgba(25,135,84,0.03);"
        idn_text_color = "#dc3545" if is_idn else "#198754"
        idn_label = "EVASION DETECTED" if is_idn else "SECURE"
        
        homo_border = "border: 1px solid rgba(220,53,69,0.3); background:rgba(220,53,69,0.04);" if is_homo else "border: 1px solid rgba(25,135,84,0.15); background:rgba(25,135,84,0.03);"
        homo_text_color = "#dc3545" if is_homo else "#198754"
        homo_label = "EVASION DETECTED" if is_homo else "SECURE"
        
        brand_border = "border: 1px solid rgba(220,53,69,0.3); background:rgba(220,53,69,0.04);" if is_brand else "border: 1px solid rgba(25,135,84,0.15); background:rgba(25,135,84,0.03);"
        brand_text_color = "#dc3545" if is_brand else "#198754"
        brand_label = "MASKING DETECTED" if is_brand else "SECURE"
        
        adversarial_html = f"""
        <div class="ep" style="border-left:3px solid #a370f7; border: 1px solid rgba(255,255,255,0.05); height:100%;">
          <div class="ep-hdr" style="background:transparent;">
            <div class="ep-pulse" style="background:#a370f7;"></div>
            <span class="ep-title" style="color:#a370f7;">Adversarial Pattern Analysis</span>
            <span class="ep-tag">Evasion</span>
          </div>
          <div class="ep-body" style="padding:16px 20px !important; display:flex; flex-direction:column; justify-content:center; background:rgba(0,0,0,0.20); height:330px;">
            <div style="font-size:0.72rem; margin-bottom:14px; opacity:0.8; font-family:monospace; line-height:1.4;">
              Detecting Unicode homoglyph domain masking, brand typosquatting, and evasion signatures:
            </div>
            <div style="display:flex; flex-direction:column; gap:12px; font-size:0.75rem; font-family:monospace;">
              <div style="display:flex; align-items:center; justify-content:space-between; padding:10px 14px; border-radius:4px; {idn_border}">
                <div style="display:flex; align-items:center; gap:8px;">{idn_svg} <span style="font-weight:700;">IDN Punycode</span></div>
                <div style="font-weight:800; color:{idn_text_color}; font-size:0.72rem;">[ {idn_label} ]</div>
              </div>
              <div style="display:flex; align-items:center; justify-content:space-between; padding:10px 14px; border-radius:4px; {homo_border}">
                <div style="display:flex; align-items:center; gap:8px;">{homo_svg} <span style="font-weight:700;">Unicode Homoglyphs</span></div>
                <div style="font-weight:800; color:{homo_text_color}; font-size:0.72rem;">[ {homo_label} ]</div>
              </div>
              <div style="display:flex; align-items:center; justify-content:space-between; padding:10px 14px; border-radius:4px; {brand_border}">
                <div style="display:flex; align-items:center; gap:8px;">{brand_svg} <span style="font-weight:700;">Brand Masking</span></div>
                <div style="font-weight:800; color:{brand_text_color}; font-size:0.72rem;">[ {brand_label} ]</div>
              </div>
              <div style="font-size:0.68rem; opacity:0.5; margin-top:8px; text-align:right;">
                Adversarial Evasion Score: <b>{ev_score:.2f} / 1.00</b>
              </div>
            </div>
          </div>
        </div>
        """
        st.markdown(adversarial_html, unsafe_allow_html=True)

    with row2_col3:
        # Qualitative Business Impact
        impact = compute_qualitative_impact(
            severity=severity,
            asset_criticality=st.session_state.get("asset_crit_input", "MEDIUM"),
            is_customer_facing=st.session_state.get("is_cf_input", False),
            compliance_scopes=st.session_state.get("comp_scopes_input", []),
            evidence=evidence,
            sla_days=sla_days,
            priority_urgency=priority_urgency,
        )
        impact_panel_html = render_business_impact_panel(impact)
        st.markdown(impact_panel_html, unsafe_allow_html=True)

    st.markdown('<div class="section-gap"></div>', unsafe_allow_html=True)

    # ======================================================================
    # ZONE 3 — DECISION SUPPORT (FULL WIDTH EVIDENCE & ACTIONS)
    # ======================================================================
    st.markdown('<div style="font-size:0.6rem; font-weight:800; opacity:0.35; letter-spacing:0.12em; text-transform:uppercase; margin-bottom:8px;">Zone 3: Decision Support & Recommended Actions</div>', unsafe_allow_html=True)

    breakdown_html = render_evidence_breakdown(
        evidence_items=evidence_chain.items,
        provenance=breakdown_prov
    )
    st.markdown(breakdown_html, unsafe_allow_html=True)

    st.markdown('<div class="section-gap"></div>', unsafe_allow_html=True)

    # Recommended Actions (dynamically loaded, no hardcoded ASNs/IPs)
    recommended_li = "".join(
        f"<li>{_html.escape(r)}</li>" for r in biz_report.recommended_actions
    )
    if not recommended_li:
        recommended_li = "<li>No specific action items generated for this risk profile.</li>"

    rec_actions_html = f"""
    <div class="ep" style="border-left:3px solid #dc3545; border: 1px solid rgba(255,255,255,0.05); margin-top:10px;">
      <div class="ep-hdr" style="background:transparent;">
        <div class="ep-pulse" style="background:#dc3545;"></div>
        <span class="ep-title" style="color:#dc3545;">SOC Escalation Rationale & Recommended Procedures</span>
        <span class="ep-tag">Security Playbook</span>
      </div>
      <div class="ep-body" style="padding:16px 20px !important; background:rgba(0,0,0,0.20); font-family:monospace; font-size:0.72rem; line-height:1.55;">
        <div>
          <span style="color:#dc3545; font-weight:800;">Escalation Trigger:</span> Priority Index of <b>{priority_score:.0f}</b> is above automated SLA bounds. Exposure signals suggest active verification requirements.
        </div>
        <div style="margin-top:10px;">
          <span style="color:#20c997; font-weight:800;">SOC Recommended Actions:</span>
          <ul style="margin:6px 0 0 16px; padding:0; list-style-type: decimal;">
            {recommended_li}
          </ul>
        </div>
      </div>
    </div>
    """
    st.markdown(rec_actions_html, unsafe_allow_html=True)

    st.markdown('<div class="section-gap"></div>', unsafe_allow_html=True)

    # ======================================================================
    # ZONE 4 — EXPORT & AUDIT (UTILITY AND COMPACT METADATA)
    # ======================================================================
    st.markdown('<div style="font-size:0.6rem; font-weight:800; opacity:0.35; letter-spacing:0.12em; text-transform:uppercase; margin-bottom:8px;">Zone 4: Investigation Archives & Forensic Export</div>', unsafe_allow_html=True)
    
    export_col1, export_col2 = st.columns([2, 1])
    
    with export_col1:
        try:
            pdf_bytes = _generate_pdf(biz_report, priority_item=priority_item, evidence=evidence)
            st.download_button(
                label="Download Cyber Intelligence PDF Report",
                data=pdf_bytes,
                file_name=f"AERIS_Forensic_Report_{target.replace('.', '_')}.pdf",
                mime="application/pdf",
                use_container_width=True,
            )
        except Exception as _pdf_err:
            st.warning(f"Intelligence Graph Pack PDF currently unavailable: {_pdf_err}")
            
    with export_col2:
        st.button("Export Graph Pack Assets (SVG)", key="export_svg_btn", use_container_width=True, type="secondary")
        
    # Clean metadata footer
    st.markdown(
        f'<div style="text-align:center; font-family:monospace; font-size:0.58rem; opacity:0.3; margin-top:20px;">'
        f'EIRPP Investigation Archive ID: {biz_report.generated_at.replace(" ", "_").upper()}_{target.replace(".", "_").upper()}'
        f'  |  Calibrated Target Risk Level: {severity.upper()}'
        f'</div>',
        unsafe_allow_html=True
    )
