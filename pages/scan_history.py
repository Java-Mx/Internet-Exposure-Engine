"""
AERIS Scan History Page
=========================
Renders the historical scan list, detailed historical assessments, and target trend charts.
"""
import streamlit as st
import html as _html
import pandas as pd
import plotly.graph_objects as go
from services.history_service import get_history_service
from services.assessment_service import _build_business_report
from utils.helpers import get_sev_color
from reporting.business_translator import _generate_pdf, ADVISORY_NOTICE

def render_scan_history() -> None:
    st.title("Scan History")
    st.markdown(
        "Previous assessments are stored locally. "
        "Select a record to view the full report.",
    )

    try:
        history_service = get_history_service()
        history = history_service.get_recent_scans(limit=200)

        if not history:
            st.info("No scan records found. Run a Security Assessment to begin building history.")
            return

        # ── Summary table
        df = pd.DataFrame(history)
        df["scanned_at"] = pd.to_datetime(df["scanned_at"])
        df["date"] = df["scanned_at"].dt.strftime("%Y-%m-%d %H:%M")
        
        # Keep only the latest scan per domain for the summary table
        df_summary = df.drop_duplicates(subset=["domain"], keep="first").reset_index(drop=True)

        display_df = df_summary[["id", "date", "domain", "url", "score", "severity", "confidence"]].copy()
        display_df.columns = ["ID", "Date", "Domain", "URL", "Score", "Severity", "Confidence"]
        display_df["Score"] = display_df["Score"].apply(lambda x: f"{x:.0f}/100")
        display_df["Confidence"] = display_df["Confidence"].apply(lambda x: f"{x*100:.0f}%")

        st.dataframe(
            display_df,
            width='stretch',
            hide_index=True,
            column_config={
                "ID": st.column_config.NumberColumn("ID", width="small"),
                "Score": st.column_config.TextColumn("Score", width="small"),
                "Severity": st.column_config.TextColumn("Severity", width="medium"),
            },
        )

        # ── Record detail viewer
        st.markdown('<div class="section-gap"></div>', unsafe_allow_html=True)
        st.subheader("View Assessment Detail")

        if "id" in df.columns:
            scan_ids = df["id"].tolist()
            scan_labels = [
                f"[{row['date']}]  {row['domain']}  —  {row['severity']}  {row['score']:.0f}/100"
                for _, row in df.iterrows()
            ]
            selected_label = st.selectbox(
                "Select a scan record",
                options=scan_labels,
                index=0,
                label_visibility="collapsed",
            )
            selected_id = scan_ids[scan_labels.index(selected_label)]
            record = history_service.get_scan(selected_id)

            if record:
                r_url = record["url"]
                r_score = record["score"]
                r_sev = record["severity"]
                r_conf = record["confidence"]
                r_ts = record["scanned_at"]
                r_ev = record.get("findings", [])

                st.markdown(f"**Website:** `{_html.escape(r_url)}`")
                st.caption(f"Assessed: {r_ts}")

                hm1, hm2, hm3 = st.columns(3)
                sev_color = get_sev_color(r_sev)
                with hm1:
                    st.markdown(
                        f'<div class="card"><div class="score-circle" style="border-color:{sev_color};color:{sev_color};">'
                        f'<div class="score-circle-num">{r_score:.0f}</div><div class="score-circle-lbl">/ 100</div></div>'
                        f'<div class="card-label">Risk Score</div></div>',
                        unsafe_allow_html=True,
                    )
                with hm2:
                    st.markdown(
                        f'<div class="card"><div style="font-size:0.7rem;opacity:0.5;text-transform:uppercase;margin-bottom:6px;">Severity</div>'
                        f'<div class="sev-badge sev-{r_sev}">{r_sev}</div></div>',
                        unsafe_allow_html=True,
                    )
                with hm3:
                    st.markdown(
                        f'<div class="card"><div style="font-size:2rem;font-weight:800;">{r_conf*100:.0f}%</div>'
                        f'<div class="card-label">Confidence</div></div>',
                        unsafe_allow_html=True,
                    )

                # Business report for this historical record
                if r_ev:
                    st.markdown('<div class="section-gap"></div>', unsafe_allow_html=True)
                    hist_report = _build_business_report(r_url, r_score, r_sev, r_ev, r_conf)

                    st.markdown('<div class="result-section-header">Executive Summary</div>', unsafe_allow_html=True)
                    st.write(hist_report.executive_summary)

                    st.markdown('<div class="result-section-header">Recommended Actions</div>', unsafe_allow_html=True)
                    for i, action in enumerate(hist_report.recommended_actions[:5], 1):
                        st.markdown(f"**{i}.** {_html.escape(action)}")

                    # Re-download PDF
                    try:
                        pdf_bytes = _generate_pdf(hist_report)
                        safe_name = r_url.replace(".", "_").replace("/", "_").replace(":", "")[:40]
                        st.download_button(
                            "Download PDF Report for This Record",
                            data=pdf_bytes,
                            file_name=f"IERSS_Report_{safe_name}.pdf",
                            mime="application/pdf",
                            use_container_width=True,
                        )
                    except Exception:
                        pass

                # ── Domain trend chart
                try:
                    from urllib.parse import urlparse
                    host = urlparse(r_url if "://" in r_url else f"http://{r_url}").hostname or r_url
                    bare = host.lower().lstrip("www.")
                    
                    domain_history = history_service.get_domain_history(bare)

                    if len(domain_history) > 1:
                        st.markdown('<div class="section-gap"></div>', unsafe_allow_html=True)
                        st.markdown(f'<div class="result-section-header">Risk Score Trend — {_html.escape(bare)}</div>', unsafe_allow_html=True)
                        trend_df = pd.DataFrame(domain_history)
                        # Ensure sorted chronologically
                        trend_df = trend_df.sort_values(by="scanned_at").reset_index(drop=True)
                        
                        fig_trend = go.Figure()
                        fig_trend.add_trace(go.Scatter(
                            x=trend_df["scanned_at"], y=trend_df["score"],
                            mode="lines+markers",
                            line=dict(color=get_sev_color(r_sev), width=2),
                            marker=dict(size=7),
                            name="Risk Score",
                        ))
                        fig_trend.update_layout(
                            height=220, margin=dict(t=20, b=20, l=20, r=20),
                            yaxis=dict(range=[0, 100]),
                            paper_bgcolor="rgba(0,0,0,0)",
                            plot_bgcolor="rgba(0,0,0,0)",
                            font={"color": "inherit"},
                        )
                        st.plotly_chart(fig_trend, use_container_width=True)
                except Exception:
                    pass

        # ── Advisory notice
        st.markdown('<div class="section-gap"></div>', unsafe_allow_html=True)
        st.markdown(
            f'<div class="notice-box">'
            f'<div class="notice-title">Important Notice</div>'
            f'<div class="notice-body">{ADVISORY_NOTICE}</div>'
            f'</div>',
            unsafe_allow_html=True,
        )

    except Exception as hist_err:
        st.error(f"Could not load scan history: {hist_err}")
        st.caption("Run a Security Assessment to create the first record.")
