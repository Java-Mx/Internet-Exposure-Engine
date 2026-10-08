"""
AERIS Radar Chart Visualization
================================
Renders the 5-dimensional calibrated confidence radar chart.
"""
from __future__ import annotations
import math
import html as _html
from typing import Any
from visualizations.provenance import DataProvenance, provenance_footer_html

def render_confidence_radar(
    tc: Any,
    provenance: DataProvenance
) -> str:
    """
    Renders the 5-dimensional calibrated confidence radar chart.
    """
    prov_footer = provenance_footer_html(provenance)

    rcx, rcy = 160, 160
    rrad = 110

    def get_radar_point(val, angle_deg):
        # Scale value: 0 to 1 mapped to radius 0 to rrad
        val_scaled = max(0.0, min(1.0, float(val))) * rrad
        # Convert to Cartesian relative to center
        # Angle offset by -90 to start at 12 o'clock (pointing up)
        rad = math.radians(angle_deg - 90)
        rx = rcx + val_scaled * math.cos(rad)
        ry = rcy + val_scaled * math.sin(rad)
        return rx, ry

    # Current target confidence points
    try:
        p0_x, p0_y = get_radar_point(tc.detection, 0)
        p1_x, p1_y = get_radar_point(tc.attribution, 72)
        p2_x, p2_y = get_radar_point(tc.behavioral, 144)
        p3_x, p3_y = get_radar_point(tc.environmental, 216)
        p4_x, p4_y = get_radar_point(tc.business_impact, 288)
    except Exception:
        p0_x, p0_y = get_radar_point(0.5, 0)
        p1_x, p1_y = get_radar_point(0.5, 72)
        p2_x, p2_y = get_radar_point(0.5, 144)
        p3_x, p3_y = get_radar_point(0.5, 216)
        p4_x, p4_y = get_radar_point(0.5, 288)

    # Grid polygon lines
    grid_polys = []
    for limit in [0.25, 0.50, 0.75, 1.0]:
        g0 = get_radar_point(limit, 0)
        g1 = get_radar_point(limit, 72)
        g2 = get_radar_point(limit, 144)
        g3 = get_radar_point(limit, 216)
        g4 = get_radar_point(limit, 288)
        grid_polys.append(
            f'<polygon points="{g0[0]:.1f},{g0[1]:.1f} {g1[0]:.1f},{g1[1]:.1f} '
            f'{g2[0]:.1f},{g2[1]:.1f} {g3[0]:.1f},{g3[1]:.1f} {g4[0]:.1f},{g4[1]:.1f}" '
            f'fill="none" stroke="rgba(255,255,255,0.035)" stroke-width="0.75"/>'
        )

    radar_svg = f"""
    <svg width="100%" height="280" viewBox="0 0 320 320" fill="none">
      {"".join(grid_polys)}
      <!-- Axis lines -->
      <line x1="{rcx}" y1="{rcy}" x2="{get_radar_point(1.0, 0)[0]:.1f}" y2="{get_radar_point(1.0, 0)[1]:.1f}" stroke="rgba(255,255,255,0.05)" stroke-width="0.75"/>
      <line x1="{rcx}" y1="{rcy}" x2="{get_radar_point(1.0, 72)[0]:.1f}" y2="{get_radar_point(1.0, 72)[1]:.1f}" stroke="rgba(255,255,255,0.05)" stroke-width="0.75"/>
      <line x1="{rcx}" y1="{rcy}" x2="{get_radar_point(1.0, 144)[0]:.1f}" y2="{get_radar_point(1.0, 144)[1]:.1f}" stroke="rgba(255,255,255,0.05)" stroke-width="0.75"/>
      <line x1="{rcx}" y1="{rcy}" x2="{get_radar_point(1.0, 216)[0]:.1f}" y2="{get_radar_point(1.0, 216)[1]:.1f}" stroke="rgba(255,255,255,0.05)" stroke-width="0.75"/>
      <line x1="{rcx}" y1="{rcy}" x2="{get_radar_point(1.0, 288)[0]:.1f}" y2="{get_radar_point(1.0, 288)[1]:.1f}" stroke="rgba(255,255,255,0.05)" stroke-width="0.75"/>
      
      <!-- Dimension labels -->
      <text x="{get_radar_point(1.22, 0)[0]:.1f}" y="{get_radar_point(1.22, 0)[1] + 3:.1f}" fill="#20c997" font-size="6.5" font-weight="800" font-family="monospace" text-anchor="middle">DET</text>
      <text x="{get_radar_point(1.22, 72)[0]:.1f}" y="{get_radar_point(1.22, 72)[1] + 3:.1f}" fill="#20c997" font-size="6.5" font-weight="800" font-family="monospace" text-anchor="start">ATT</text>
      <text x="{get_radar_point(1.22, 144)[0]:.1f}" y="{get_radar_point(1.22, 144)[1] + 5:.1f}" fill="#20c997" font-size="6.5" font-weight="800" font-family="monospace" text-anchor="start">BEH</text>
      <text x="{get_radar_point(1.22, 216)[0]:.1f}" y="{get_radar_point(1.22, 216)[1] + 5:.1f}" fill="#20c997" font-size="6.5" font-weight="800" font-family="monospace" text-anchor="end">ENV</text>
      <text x="{get_radar_point(1.22, 288)[0]:.1f}" y="{get_radar_point(1.22, 288)[1] + 3:.1f}" fill="#20c997" font-size="6.5" font-weight="800" font-family="monospace" text-anchor="end">IMP</text>
      
      <!-- Actual shape poly -->
      <polygon points="{p0_x:.1f},{p0_y:.1f} {p1_x:.1f},{p1_y:.1f} {p2_x:.1f},{p2_y:.1f} {p3_x:.1f},{p3_y:.1f} {p4_x:.1f},{p4_y:.1f}" 
               fill="rgba(32,201,151,0.065)" stroke="#20c997" stroke-width="2" style="filter:drop-shadow(0 0 3px rgba(32,201,151,0.4));"/>
      <circle cx="{rcx}" cy="{rcy}" r="2" fill="#20c997"/>
    </svg>
    """

    return (
        f'<div class="ep" style="border-left:3px solid #20c997;">'
        f'<div class="ep-hdr" style="background:linear-gradient(90deg,rgba(32,201,151,0.08) 0%,transparent 100%);">'
        f'<div class="ep-pulse" style="background:#20c997;"></div>'
        f'<span class="ep-title" style="color:#20c997;">Calibrated Confidence Radar</span>'
        f'<span class="ep-tag">5 Dimensions</span>'
        f'</div>'
        f'<div class="ep-body">'
        f'<div style="background:rgba(0,0,0,0.15);border:1px solid rgba(255,255,255,0.04);'
        f'border-radius:6px;padding:8px;display:flex;justify-content:center;">'
        f'{radar_svg}'
        f'</div>'
        f'{prov_footer}'
        f'</div>'
        f'</div>'
    )
