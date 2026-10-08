"""
AERIS SVG Status Indicators
============================
Provides stroke-based, lightweight glowing SVG icons matching the AERIS aesthetic.
"""
def get_svg_indicator(status_type: str, size: int = 14) -> str:
    """
    Returns enterprise-grade glowing SVG status indicators matching the AERIS aesthetic.
    All SVGs are stroke-based, lightweight, monochrome/minimal, with a subtle glow,
    calibrated for an Enterprise Operational Intelligence Console.
    """
    status_lower = status_type.lower().replace(" ", "_")
    
    # ── 1. Correlated (Interconnected network nodes)
    if status_lower in ("correlated", "correlation_active"):
        return (
            f'<svg viewBox="0 0 24 24" width="{size}" height="{size}" fill="none" stroke="#0dcaf0" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle; filter:drop-shadow(0 0 2px rgba(13,202,240,0.45));">'
            f'<circle cx="18" cy="5" r="3"></circle>'
            f'<circle cx="6" cy="12" r="3"></circle>'
            f'<circle cx="18" cy="19" r="3"></circle>'
            f'<line x1="8.59" y1="13.51" x2="15.42" y2="17.49"></line>'
            f'<line x1="15.41" y1="6.51" x2="8.59" y2="10.49"></line>'
            f'</svg>'
        )
        
    # ── 2. Verified (Double checkmark inside a shield)
    elif status_lower in ("verified", "layer_complete"):
        return (
            f'<svg viewBox="0 0 24 24" width="{size}" height="{size}" fill="none" stroke="#198754" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle; filter:drop-shadow(0 0 2px rgba(25,135,84,0.45));">'
            f'<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>'
            f'<path d="m9 11 2 2 4-4"></path>'
            f'</svg>'
        )
        
    # ── 3. Escalated (Upward trending chevron wave)
    elif status_lower in ("escalated", "in_progress"):
        return (
            f'<svg viewBox="0 0 24 24" width="{size}" height="{size}" fill="none" stroke="#ffc107" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle; filter:drop-shadow(0 0 2px rgba(255,193,7,0.45));">'
            f'<polyline points="18 15 12 9 6 15"></polyline>'
            f'<polyline points="18 20 12 14 6 20" style="opacity:0.5;"></polyline>'
            f'</svg>'
        )
        
    # ── 4. Governance Locked (Secure Vault Padlock)
    elif status_lower in ("governance_locked", "governance_verified"):
        return (
            f'<svg viewBox="0 0 24 24" width="{size}" height="{size}" fill="none" stroke="#198754" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle; filter:drop-shadow(0 0 2px rgba(25,135,84,0.5));">'
            f'<rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>'
            f'<path d="M7 11V7a5 5 0 0 1 10 0v4"></path>'
            f'<circle cx="12" cy="16" r="1.5" fill="#198754"></circle>'
            f'</svg>'
        )
        
    # ── 5. Analyst Reviewed (SOC Scope / Eyeball Target)
    elif status_lower in ("analyst_reviewed", "analyst_attention"):
        return (
            f'<svg viewBox="0 0 24 24" width="{size}" height="{size}" fill="none" stroke="#6c757d" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle; filter:drop-shadow(0 0 2px rgba(108,117,125,0.4));">'
            f'<path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7z"></path>'
            f'<circle cx="12" cy="12" r="3"></circle>'
            f'</svg>'
        )
        
    # ── 6. Adversarial Pattern (Crosshair target with warning diagonal)
    elif status_lower in ("adversarial_pattern", "adversarial"):
        return (
            f'<svg viewBox="0 0 24 24" width="{size}" height="{size}" fill="none" stroke="#dc3545" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle; filter:drop-shadow(0 0 3px rgba(220,53,69,0.6));">'
            f'<circle cx="12" cy="12" r="10"></circle>'
            f'<line x1="22" y1="12" x2="18" y2="12"></line>'
            f'<line x1="6" y1="12" x2="2" y2="12"></line>'
            f'<line x1="12" y1="6" x2="12" y2="2"></line>'
            f'<line x1="12" y1="22" x2="12" y2="18"></line>'
            f'<line x1="4.93" y1="4.93" x2="19.07" y2="19.07" style="stroke-dasharray: 2, 2;"></line>'
            f'</svg>'
        )
        
    # ── 7. Confidence Stable (Calibrated horizontal balancing index)
    elif status_lower in ("confidence_stable", "confidence_calibrated"):
        return (
            f'<svg viewBox="0 0 24 24" width="{size}" height="{size}" fill="none" stroke="#20c997" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle; filter:drop-shadow(0 0 2px rgba(32,201,151,0.45));">'
            f'<path d="M3 12h18M12 3v18"></path>'
            f'<circle cx="12" cy="12" r="5" fill="#20c997" style="fill-opacity:0.1;"></circle>'
            f'</svg>'
        )
        
    # ── 8. SLA Breach (Expired Alarm Clock / Timer alert)
    elif status_lower in ("sla_breach", "high_priority"):
        return (
            f'<svg viewBox="0 0 24 24" width="{size}" height="{size}" fill="none" stroke="#7b0d1e" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle; filter:drop-shadow(0 0 3px rgba(123,13,30,0.6));">'
            f'<circle cx="12" cy="13" r="8"></circle>'
            f'<polyline points="12 9 12 13 15 15"></polyline>'
            f'<path d="M5 3 2 6M19 3l3 3"></path>'
            f'</svg>'
        )
        
    # ── 9. Critical Priority (Alert Octagon)
    elif status_lower in ("critical_priority", "threat_detected"):
        return (
            f'<svg viewBox="0 0 24 24" width="{size}" height="{size}" fill="none" stroke="#dc3545" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle; filter:drop-shadow(0 0 3px rgba(220,53,69,0.65));">'
            f'<polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"></polygon>'
            f'<line x1="12" y1="8" x2="12" y2="12"></line>'
            f'<line x1="12" y1="16" x2="12.01" y2="16"></line>'
            f'</svg>'
        )
        
    # ── 10. Audit Locked (Slate lock)
    elif status_lower == "audit_locked":
        return (
            f'<svg viewBox="0 0 24 24" width="{size}" height="{size}" fill="none" stroke="#6c757d" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle; filter:drop-shadow(0 0 2px rgba(108,117,125,0.4));">'
            f'<rect x="5" y="11" width="14" height="10" rx="2" ry="2"></rect>'
            f'<path d="M12 11V7a3 3 0 0 0-6 0v4"></path>'
            f'</svg>'
        )
        
    # Default Fallback (Gray outline)
    else:
        return (
            f'<svg viewBox="0 0 24 24" width="{size}" height="{size}" fill="none" stroke="#6c757d" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle; opacity:0.5;">'
            f'<circle cx="12" cy="12" r="10"></circle>'
            f'</svg>'
        )
