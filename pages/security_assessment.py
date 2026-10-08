"""
AERIS Security Assessment Page
================================
Renders the scan input, options, runs assessment, and displays components.
"""
import streamlit as st
import html as _html
from services.assessment_service import run_assessment
from components.pipeline_tracker import render_pipeline_tracker
from components.score_display import render_score_display
from components.evidence_panel import render_evidence_panel
from components.report_panel import render_report_panel
from utils.svg_indicators import get_svg_indicator
from utils.helpers import get_sev_color
from reporting.business_translator import _generate_pdf

def render_security_assessment() -> None:
    st.title("Security Assessment")
    st.markdown(
        "Enter a website address below to receive a structured risk assessment "
        "in plain business language.",
        help="This tool performs passive external analysis only.",
    )

    st.markdown('<div style="height:12px;"></div>', unsafe_allow_html=True)
    col_inp, _gap, col_btn = st.columns([14, 0.3, 5])
    with col_inp:
        target_input = st.text_input(
            "Website address",
            placeholder="e.g. example.com or https://example.com",
            label_visibility="collapsed",
        )
    with _gap:
        pass
    with col_btn:
        run_btn = st.button("Run Assessment", use_container_width=True, type="primary")

    st.markdown('<div style="height:8px;"></div>', unsafe_allow_html=True)
    with st.expander("EIRPP Tier 4: Business & Compliance Context", expanded=False):
        col_crit, col_cf, col_comp = st.columns([2, 1, 3])
        with col_crit:
            asset_crit = st.selectbox(
                "Asset Criticality",
                options=["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
                index=0,
                key="asset_crit_input",
                help="Revenue-generating, customer-facing, or regulated status."
            )
        with col_cf:
            st.write('<div style="margin-top:20px;"></div>', unsafe_allow_html=True)
            is_cf = st.toggle("Customer Facing", value=False, key="is_cf_input", help="Is the asset directly exposed to external customers?")
        with col_comp:
            comp_scopes = st.multiselect(
                "Compliance Scopes",
                options=["PCI-DSS", "GDPR", "HIPAA", "SOC 2", "ISO 27001"],
                key="comp_scopes_input",
                help="Regulatory frameworks this asset is subject to."
            )
        col_bu, col_owner = st.columns(2)
        with col_bu:
            business_unit = st.text_input(
                "Business Unit",
                value="Corporate Infrastructure",
                key="business_unit_input",
                help="The corporate group or division owning this asset."
            )
        with col_owner:
            owner_team = st.text_input(
                "Owner Team",
                value="Security Operations",
                key="owner_team_input",
                help="The engineering or security operations team managing this asset."
            )

    if run_btn and target_input:
        st.session_state.current_target = target_input.strip()
        
    if st.session_state.get("current_target"):
        target = st.session_state.current_target
        if "." not in target:
            st.error("Please enter a valid domain or URL (e.g. example.com).")
        else:
            if run_btn or target != st.session_state.get("last_analyzed_target"):
                prog_placeholder = st.empty()
                with prog_placeholder.container():
                    st.subheader("Running Analysis")
                    status_box = st.empty()
                    
                    def show_tracker(done_up_to: int):
                        with status_box.container():
                            render_pipeline_tracker(done_up_to)
                        import time
                        if 0 < done_up_to <= 6:
                            time.sleep(0.3)
                            
                try:
                    result = run_assessment(
                        target=target,
                        asset_criticality=asset_crit,
                        is_customer_facing=is_cf,
                        compliance_scopes=comp_scopes,
                        business_unit=business_unit,
                        owner_team=owner_team,
                        progress_callback=show_tracker
                    )
                    st.session_state.assessment_result = result
                    st.session_state.last_analyzed_target = target
                except Exception as exc:
                    prog_placeholder.empty()
                    st.error(f"Analysis failed: {exc}")
                    st.stop()
                    
                prog_placeholder.empty()
                
            res = st.session_state.get("assessment_result")
            if not res:
                st.error("No result returned from the analysis engine.")
                st.stop()
                
            # Render page details
            st.divider()
            st.subheader(f"Assessment: {_html.escape(target)}")
            
            # Target page title if available
            raw_title = res.raw_result.get('page_title')
            if raw_title:
                st.markdown(f"**Target Website Identity:** `{_html.escape(raw_title)}`")
                
            st.caption(f"Completed in {res.elapsed_ms:.0f} ms  —  {res.biz_report.generated_at}")
            
            # 1. Pipeline execution status banner
            render_pipeline_tracker(6)
            
            # 2. Community Warning
            if res.community_reports > 0:
                st.markdown(
                    f'<div class="typosquat-banner" style="border-left:3px solid #ffc107;">'
                    f'<div style="padding:9px 14px;background:linear-gradient(90deg,rgba(255,193,7,0.12) 0%,transparent 100%);border-bottom:1px solid rgba(255,193,7,0.18);">'
                    f'<div class="typosquat-title" style="color:#c49a00;margin-bottom:0;">Community Observations</div>'
                    f'</div>'
                    f'<div style="padding:11px 14px;font-size:0.82rem;opacity:0.82;">Some users previously reported concerns about this website. '
                    f'Independent verification recommended.</div>'
                    f'</div>',
                    unsafe_allow_html=True,
                )
                st.markdown('<div class="section-gap"></div>', unsafe_allow_html=True)
                
            # 3. Risk change banner
            if res.biz_report.risk_change == "increased" and res.previous_score is not None:
                delta = res.score - res.previous_score
                st.markdown(
                    f'<div class="risk-up">'
                    f'<b>Risk level has increased since the previous assessment.</b> '
                    f'Previous score: {res.previous_score:.0f}/100 — Current: {res.score:.0f}/100 (+{delta:.0f}). '
                    f'Review recommended.'
                    f'</div>',
                    unsafe_allow_html=True,
                )
                st.markdown('<div class="section-gap"></div>', unsafe_allow_html=True)
            elif res.biz_report.risk_change == "decreased" and res.previous_score is not None:
                delta = res.previous_score - res.score
                st.markdown(
                    f'<div class="risk-down">'
                    f'<b>Exposure indicators have reduced compared to the previous assessment.</b> '
                    f'Previous score: {res.previous_score:.0f}/100 — Current: {res.score:.0f}/100 (-{delta:.0f}).'
                    f'</div>',
                    unsafe_allow_html=True,
                )
                st.markdown('<div class="section-gap"></div>', unsafe_allow_html=True)
                
            # 4. Display score display component
            render_score_display(
                score=res.score,
                severity=res.severity,
                priority_score=res.priority_score,
                priority_urgency=res.priority_urgency,
                confidence=res.confidence,
                business_unit=business_unit,
                asset_criticality=asset_crit,
                theme_color=res.theme_color
            )
            
            # Workspace redirect button
            st.markdown('<div style="height:14px;"></div>', unsafe_allow_html=True)
            if st.button("Open Intelligence Visualizations Workspace", key="open_workspace_btn", use_container_width=True, type="primary"):
                st.session_state.nav_page = "Intelligence Visualization Workspace"
                st.rerun()
                
            # Prioritization intelligence panel
            if res.priority_item:
                sla_lbl = "IMMEDIATE [24 hours]" if res.sla_days == 1 else (f"URGENT [{res.sla_days} days]" if res.sla_days == 7 else f"SCHEDULED [{res.sla_days} days]")
                sla_color = "#dc3545" if res.sla_days == 1 else ("#fd7e14" if res.sla_days == 7 else "#198754")
                epss_color = "#dc3545" if res.priority_item.epss_score >= 0.3 else ("#fd7e14" if res.priority_item.epss_score >= 0.05 else "#198754")
                tei_val = res.priority_item.threat_interest_score * 10
                tei_color = "#dc3545" if tei_val >= 7 else ("#fd7e14" if tei_val >= 4 else "#198754")
                
                is_adversarial = any(any(x in ev.upper() for x in ["TYPO", "HOMO", "UNICODE CONFUSABLE", "EVASION"]) for ev in res.evidence)
                adv_multiplier = "+25% Evasion Penalty" if is_adversarial else "1.00x (Baseline)"
                adv_svg = get_svg_indicator("adversarial_pattern", size=13)
                
                try:
                    from intelligence.threat_memory import ThreatMemory
                    tm = ThreatMemory()
                    hist_ctx = tm.recall(target)
                    recur_count = hist_ctx.scan_count if hist_ctx else 1
                    recur_val = f"{recur_count} Scans Logged"
                except Exception:
                    recur_val = "1 Scan Logged"
                    hist_ctx = None
                    
                recur_svg = get_svg_indicator("confidence_stable", size=13)
                biz_impact_desc = f"{asset_crit.upper()} Severity"
                biz_svg = get_svg_indicator("governance_locked", size=13)
                
                try:
                    related_targets = hist_ctx.related_targets if hist_ctx else []
                    correl_count = len(related_targets)
                    correl_val = f"{correl_count} Infrastructure Links" if correl_count > 0 else "No Shared Assets"
                except Exception:
                    correl_val = "No Shared Assets"
                correl_svg = get_svg_indicator("correlated", size=13)
                
                priority_badge_svg = get_svg_indicator("critical_priority" if res.priority_score >= 75 else "sla_breach", size=13)
                priority_badge_label = "CRITICAL PRIORITY" if res.priority_score >= 75 else "ESCALATED THREAT"
                
                st.markdown(
                    f'<div class="eirpp-di-banner" style="border-left:3px solid {res.theme_color}; margin-top:20px;">'
                    f'<div class="eirpp-di-header" style="background:linear-gradient(90deg,{res.theme_color}22 0%,{res.theme_color}08 60%,transparent 100%); border-bottom:1px solid {res.theme_color}30; display:flex; align-items:center; gap:8px;">'
                    f'<div class="eirpp-di-pulse" style="background:{res.theme_color};"></div>'
                    f'<span class="eirpp-di-badge" style="background:{res.theme_color}18; color:{res.theme_color}; border:1px solid {res.theme_color}40; display:inline-flex; align-items:center; gap:4px;">{priority_badge_svg} {priority_badge_label}</span>'
                    f'<span class="eirpp-di-title" style="color:{res.theme_color};">Prioritization Intelligence Panel</span>'
                    f'<span class="eirpp-di-tier" style="margin-left:auto;">Tier 4 Orchestration</span>'
                    f'</div>'
                    f'<div class="eirpp-di-body">'
                    f'<div class="eirpp-di-rationale" style="font-size:0.82rem; line-height:1.6; margin-bottom:12px;">'
                    f'<b>Operational Prioritization Statement &mdash;</b> {res.priority_item.priority_rationale}'
                    f'</div>'
                    f'<div style="background:rgba(0,0,0,0.15); border:1px solid rgba(255,255,255,0.04); padding:12px; border-radius:6px; margin-bottom:14px;">'
                    f'<div style="font-size:0.7rem; text-transform:uppercase; letter-spacing:0.08em; opacity:0.4; margin-bottom:6px;">Decision Logic Drivers</div>'
                    f'<div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap:12px; font-size:0.78rem;">'
                    f'<div style="display:flex; align-items:center; gap:8px;">{get_svg_indicator("critical_priority", size=13)} <b>Composite Priority Score:</b> <span style="color:{get_sev_color(res.priority_urgency)}; font-weight:700;">{res.priority_score:.0f}/100</span></div>'
                    f'<div style="display:flex; align-items:center; gap:8px;">{get_svg_indicator("sla_breach", size=13)} <b>Severity Tier:</b> <span class="sev-badge sev-{res.severity}" style="font-size:0.6rem; padding:1px 6px; font-weight:800;">{res.severity}</span></div>'
                    f'<div style="display:flex; align-items:center; gap:8px;">{adv_svg} <b>Adversarial Evasion Penalty:</b> <span style="font-weight:700; color:{"#dc3545" if is_adversarial else "inherit"};">{adv_multiplier}</span></div>'
                    f'<div style="display:flex; align-items:center; gap:8px;">{recur_svg} <b>Recurrence Score:</b> <span style="font-weight:700;">{recur_val}</span></div>'
                    f'<div style="display:flex; align-items:center; gap:8px;">{biz_svg} <b>Business Impact Score:</b> <span style="font-weight:700;">{biz_impact_desc}</span></div>'
                    f'<div style="display:flex; align-items:center; gap:8px;">{correl_svg} <b>Correlation Amplifier:</b> <span style="font-weight:700; color:{"#0dcaf0" if correl_count > 0 else "inherit"};">{correl_val}</span></div>'
                    f'</div>'
                    f'</div>'
                    f'<hr class="eirpp-di-divider"/>'
                    f'<div class="eirpp-di-stats" style="display:flex; flex-wrap:wrap; gap:10px; width:100%;">'
                    f'<div class="eirpp-di-stat" style="flex:1 1 0; min-width:0; border-right:1px solid rgba(255,255,255,0.06); padding:0 12px 0 0;">'
                    f'<div class="eirpp-di-stat-label">EPSS Probability</div>'
                    f'<div class="eirpp-di-stat-value" style="color:{epss_color}; font-size:1.15rem; font-weight:800;">{res.priority_item.epss_score*100:.2f}%</div>'
                    f'</div>'
                    f'<div class="eirpp-di-stat" style="flex:1 1 0; min-width:0; border-right:1px solid rgba(255,255,255,0.06); padding:0 12px;">'
                    f'<div class="eirpp-di-stat-label">Threat Exposure Index</div>'
                    f'<div class="eirpp-di-stat-value" style="color:{tei_color}; font-size:1.15rem; font-weight:800;">{tei_val:.1f} / 10</div>'
                    f'</div>'
                    f'<div class="eirpp-di-stat" style="flex:1 1 0; min-width:0; border-right:1px solid rgba(255,255,255,0.06); padding:0 12px;">'
                    f'<div class="eirpp-di-stat-label">Asset Criticality</div>'
                    f'<div class="eirpp-di-stat-value" style="font-size:1.15rem; font-weight:800;">{asset_crit}</div>'
                    f'</div>'
                    f'<div class="eirpp-di-stat" style="flex:1 1 0; min-width:0; padding:0 0 0 12px;">'
                    f'<div class="eirpp-di-stat-label">Remediation SLA</div>'
                    f'<div class="eirpp-di-stat-value" style="color:{sla_color}; font-size:1.15rem; font-weight:800;">{sla_lbl}</div>'
                    f'</div>'
                    f'</div>'
                    f'</div>'
                    f'</div>',
                    unsafe_allow_html=True,
                )
                
            # 5. Evidence Panel Component
            render_evidence_panel(
                score=res.score,
                severity=res.severity,
                evidence=res.evidence,
                evidence_chain=res.evidence_chain,
                tc=res.tc,
                threat_narrative=res.threat_narrative,
                priority_score=res.priority_score,
                priority_urgency=res.priority_urgency,
                sla_days=res.sla_days,
                hist_ctx=hist_ctx,
                theme_color=res.theme_color,
                theme_bg=f"rgba(25, 135, 84, 0.04)" if res.theme_color == "#198754" else (f"rgba(253, 126, 20, 0.04)" if res.theme_color == "#fd7e14" else f"rgba(220, 53, 69, 0.04)"),
                target=target,
                biz_report=res.biz_report
            )
            
            # Insufficient data warning
            conf_pct = int(res.confidence * 100)
            if conf_pct < 55 and res.severity == "LOW":
                st.markdown(
                    '<div class="limited-analysis">'
                    '<b>Limited Analysis</b><br>'
                    'We checked this website using basic structural analysis, but we could not '
                    'verify it through all our security databases. The "Low Risk" result may not '
                    'be complete.<br><br>'
                    'If you received this link unexpectedly, verify its legitimacy through another '
                    'channel before entering any personal information.'
                    '</div>',
                    unsafe_allow_html=True,
                )
                
            # DNS unreachable alert
            dns_failed = any("DOMAIN UNREACHABLE" in e for e in res.evidence)
            if dns_failed:
                st.markdown(
                    f'<div class="typosquat-banner" style="border-left:3px solid #fd7e14;">'
                    f'<div style="padding:9px 14px;background:linear-gradient(90deg,rgba(253,126,20,0.12) 0%,transparent 100%);border-bottom:1px solid rgba(253,126,20,0.18);">'
                    f'<div class="typosquat-title" style="color:#fd7e14;margin-bottom:0;">Domain Unreachable — Site Not Found</div>'
                    f'</div>'
                    f'<div style="padding:11px 14px;font-size:0.82rem;opacity:0.82;">This domain does not currently resolve to an active website. '
                    f'It may have been recently registered, or its DNS servers are unresponsive. Action SLA calibrated for pre-emptive block.</div>'
                    f'</div>',
                    unsafe_allow_html=True,
                )
                
            # 6. Report Panel Component
            render_report_panel(
                biz_report=res.biz_report,
                priority_item=res.priority_item,
                severity=res.severity,
                asset_criticality=asset_crit,
                is_customer_facing=is_cf,
                compliance_scopes=comp_scopes,
                theme_color=res.theme_color,
                theme_bg=f"rgba(25, 135, 84, 0.04)" if res.theme_color == "#198754" else (f"rgba(253, 126, 20, 0.04)" if res.theme_color == "#fd7e14" else f"rgba(220, 53, 69, 0.04)"),
                sla_days=res.sla_days
            )
            
            # Export & PDF download
            st.markdown('<div style="font-size:0.6rem; font-weight:800; opacity:0.35; letter-spacing:0.12em; text-transform:uppercase; margin-top:20px; margin-bottom:8px;">Zone 4: Investigation Archives & Forensic Export</div>', unsafe_allow_html=True)
            export_col1, export_col2 = st.columns([2, 1])
            with export_col1:
                try:
                    pdf_bytes = _generate_pdf(res.biz_report, priority_item=res.priority_item, evidence=res.evidence)
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
                
            # Footer
            st.markdown(
                f'<div style="text-align:center; font-family:monospace; font-size:0.58rem; opacity:0.3; margin-top:20px;">'
                f'EIRPP Investigation Archive ID: {res.biz_report.generated_at.replace(" ", "_").upper()}_{target.replace(".", "_").upper()}'
                f'  |  Calibrated Target Risk Level: {res.severity.upper()}'
                f'</div>',
                unsafe_allow_html=True
            )
            
            # Persist session state variables
            st.session_state.last_biz_report = res.biz_report
            st.session_state.last_evidence_chain = res.evidence_chain
            st.session_state.last_evidence = res.evidence
            st.session_state.last_tc = res.tc
            st.session_state.last_priority_item = res.priority_item
            st.session_state.last_priority_score = res.priority_score
            st.session_state.last_score = res.score
            st.session_state.last_severity = res.severity
            st.session_state.last_sla_days = res.sla_days
            st.session_state.last_elapsed_ms = res.elapsed_ms
            st.session_state.last_hist_ctx = hist_ctx
            st.session_state.last_threat_narrative = res.threat_narrative
