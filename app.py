"""
AERIS — Exposure Intelligence & Risk Prioritization Platform
=============================================================
Central dashboard router. Handles startup validation, authentication gate,
sidebar navigation based on role permissions, and dispatches page rendering.
"""
import os
import sys
import html as _html
import streamlit as st
import streamlit.components.v1 as st_components

# Add project root to path to ensure reliable imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# 1. Startup validation (Fail-fast environment validation)
try:
    from config.env_validator import fail_if_invalid
    fail_if_invalid()
except Exception as val_err:
    st.error(f"Environment validation execution failed: {val_err}")
    st.stop()

# st.set_page_config MUST be the very first Streamlit command in the main script
st.set_page_config(
    page_title="EIRPP Security Advisory",
    page_icon="shield",
    layout="wide",
    initial_sidebar_state="expanded",
)

# 2. Inject design system CSS resources
try:
    css_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "utils", "style.css")
    with open(css_path, "r", encoding="utf-8") as f:
        st.markdown(f.read(), unsafe_allow_html=True)
except Exception as e:
    st.warning(f"Failed to load CSS stylesheet: {e}")

# 3. Disable browser input autocomplete/suggestions via Mutex Observer component
st_components.html("""
<script>
(function() {
    function disableAutocomplete() {
        try {
            var doc = window.parent.document;
            doc.querySelectorAll('input').forEach(function(el) {
                el.setAttribute('autocomplete', 'new-password');
                el.setAttribute('autocomplete', 'off');
            });
        } catch(e) {}
    }
    disableAutocomplete();
    try {
        var observer = new MutationObserver(disableAutocomplete);
        observer.observe(window.parent.document.body, {
            childList: true,
            subtree: true
        });
    } catch(e) {}
})();
</script>
""", height=0)

# 4. Authentication Gate (Direct Access - Login screen disabled)
try:
    from auth.roles import Role, has_permission, get_allowed_pages
    _AUTH_AVAILABLE = True
except ImportError:
    _AUTH_AVAILABLE = False

# Auto-authenticate session with admin privileges for direct dashboard access
st.session_state['aeris_authenticated'] = True
st.session_state['aeris_username'] = 'admin'
st.session_state['aeris_role'] = 'admin'
_current_role = Role.ADMIN

# 5. Sidebar Branding Header
st.sidebar.markdown("""
<div style="padding: 10px 0 20px 0;">
  <div style="display:flex; align-items:center; gap:12px; margin-bottom:12px;">
    <div style="background:#dc3545; width:36px; height:36px; border-radius:8px; display:flex; align-items:center; justify-content:center;">
      <span style="font-family:monospace; font-weight:900; font-size:1.45rem; color:#000;">A</span>
    </div>
    <div style="font-weight:900; font-size:1.45rem; letter-spacing:-0.03em; color:#fff;">AERIS</div>
  </div>
  <div style="padding:10px 14px;background:rgba(0,0,0,0.20); border-radius:6px;">
    <div style="font-size:0.62rem;opacity:0.42;letter-spacing:0.06em;line-height:1.5;">Exposure Intelligence<br>&amp; Risk Prioritization Platform</div>
  </div>
</div>
""", unsafe_allow_html=True)

# 6. Sidebar Dynamic Navigation
st.sidebar.markdown("""<div style="font-size:0.55rem;font-weight:800;letter-spacing:0.14em;text-transform:uppercase;opacity:0.36;margin-bottom:8px;">Navigation</div>""", unsafe_allow_html=True)

allowed_pages = get_allowed_pages(_current_role)
if st.session_state.get("nav_page") not in allowed_pages:
    st.session_state.nav_page = allowed_pages[0] if allowed_pages else "Scan History"

_page_numbers = {
    "Security Assessment": "01",
    "Intelligence Visualization Workspace": "02",
    "Upgraded Platform": "03",
    "Batch Processing": "04",
    "Scan History": "05",
    "Adversarial Stress Test": "06",
    "Red-Team Testing": "07",
    "Admin: Readiness Tracker": "08",
    "Admin: Anti-Theater Scanner": "09",
}

for _pname in allowed_pages:
    _pnum = _page_numbers.get(_pname, "00")
    btn_type = "primary" if st.session_state.nav_page == _pname else "secondary"
    if st.sidebar.button(f"{_pnum}  {_pname}", key=f"nav_{_pname}", use_container_width=True, type=btn_type):
        st.session_state.nav_page = _pname
        st.rerun()

# 7. Sidebar System Status Panel
st.sidebar.markdown("""<div style="height:16px;"></div>""", unsafe_allow_html=True)
st.sidebar.markdown("""<div style="font-size:0.55rem;font-weight:800;letter-spacing:0.14em;text-transform:uppercase;opacity:0.36;margin-bottom:8px;">System Status</div>""", unsafe_allow_html=True)

try:
    from risk_scoring.google_safe_browsing import get_api_status as _gsb_s
    _gsb_ok = _gsb_s().get("configured", False)
except Exception:
    _gsb_ok = False

try:
    from risk_scoring.virustotal_client import get_api_status as _vt_s
    _vt_ok = _vt_s().get("configured", False)
except Exception:
    _vt_ok = False

try:
    from records.database import _get_connection
    _db_conn = _get_connection()
    _db_ok = bool(_db_conn and _db_conn.is_connected())
    if _db_ok: _db_conn.close()
    _db_label = "SQLite: Connected"
except Exception:
    _db_ok = False
    _db_label = "SQLite: Unavailable"

def _sbar_status(label, ok):
    c = "#198754" if ok else "#6c757d"
    dot_bg = "#198754" if ok else "rgba(108,117,125,0.5)"
    dot_glow = "rgba(25,135,84,0.3)" if ok else "rgba(108,117,125,0.15)"
    st.sidebar.markdown(
        f'<div style="display:flex; align-items:center; gap:8px; font-family:monospace; font-size:0.65rem; color:{c}; padding:2px 0;">'
        f'<div style="width:6px; height:6px; border-radius:50%; background:{dot_bg}; box-shadow:0 0 4px {dot_glow};"></div>'
        f'<span>{label}</span>'
        f'</div>',
        unsafe_allow_html=True
    )

_sbar_status("Google Safe Browsing", _gsb_ok)
_sbar_status("VirusTotal Reputations", _vt_ok)
_sbar_status(_db_label, _db_ok)

# 8. Environment Validation Warn block
_is_admin = st.session_state.get('aeris_role') == 'admin'

def _require_permission(permission: str) -> bool:
    """Helper to enforce permission gating on dispatcher."""
    if not has_permission(_current_role, permission):
        st.error(f"Access Denied: Insufficient permissions for {permission}")
        st.stop()
        return False
    return True

if _is_admin:
    try:
        from config.env_validator import get_validation_report
        _env_report = get_validation_report()
        if 'INVALID' in _env_report or 'MISSING' in _env_report:
            st.sidebar.warning(_env_report, icon="⚠️")
    except Exception:
        pass

# 9. Sidebar User Control Area
st.sidebar.markdown("""<div style="height:12px;"></div>""", unsafe_allow_html=True)
if _is_admin:
    st.sidebar.markdown("""<div style="font-size:0.55rem;font-weight:800;letter-spacing:0.14em;text-transform:uppercase;opacity:0.36;margin-bottom:8px;">Control Panel</div>""", unsafe_allow_html=True)
    st.session_state.debug_mode = st.sidebar.toggle("Debug Mode", value=st.session_state.get("debug_mode", False))
else:
    st.session_state.debug_mode = False

_aeris_user = st.session_state.get('aeris_username', '')
if _aeris_user:
    st.sidebar.markdown(
        f'<div style="font-size:0.62rem;opacity:0.42;margin-top:8px;margin-bottom:8px;font-family:monospace;">'
        f'Signed in as <b>{_html.escape(_aeris_user)}</b> [{_current_role.value.upper()}]'
        f'</div>',
        unsafe_allow_html=True
    )
    if st.sidebar.button('Sign Out', use_container_width=True, type='secondary'):
        for _k in ['aeris_authenticated', 'aeris_username', 'aeris_role', 'accepted_terms']:
            st.session_state.pop(_k, None)
        st.rerun()

# 10. Page Dispatcher
from pages import (
    render_security_assessment,
    render_visualization_workspace,
    render_upgraded_platform,
    render_scan_history,
    render_batch_processing,
    render_stress_test,
    render_red_team,
    render_readiness_tracker,
    render_anti_theater_scanner
)

page = st.session_state.nav_page

if page == "Security Assessment":
    _require_permission("can_run_assessment")
    render_security_assessment()
elif page == "Intelligence Visualization Workspace":
    _require_permission("can_view_visualization")
    render_visualization_workspace()
elif page == "Upgraded Platform":
    _require_permission("can_run_assessment")
    render_upgraded_platform()
elif page == "Scan History":
    _require_permission("can_view_history")
    render_scan_history()
elif page == "Batch Processing":
    _require_permission("can_run_batch")
    render_batch_processing()
elif page == "Adversarial Stress Test":
    _require_permission("can_access_stress_test")
    render_stress_test()
elif page == "Red-Team Testing":
    _require_permission("can_access_red_team")
    render_red_team()
elif page == "Admin: Readiness Tracker":
    _require_permission("can_view_readiness_tracker")
    render_readiness_tracker()
elif page == "Admin: Anti-Theater Scanner":
    _require_permission("can_run_anti_theater_scan")
    render_anti_theater_scanner()
