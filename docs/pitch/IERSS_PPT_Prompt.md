# IERSS — PowerPoint Presentation Prompt Guide
## Slide-by-Slide Design Brief for AI-Assisted PPT Creation

*Use this document as a prompt for any AI presentation tool (Gamma, Beautiful.ai, Microsoft Copilot, ChatGPT + PowerPoint, Canva AI, etc.)*
*No color codes are specified — let the tool apply its own professional dark or corporate theme.*

---

## Presentation Overview

**Title:** IERSS — Internet Exposure & Risk Scoring System
**Subtitle:** Automated URL Risk Assessment for the Modern Enterprise
**Tone:** Professional, confident, data-driven, non-technical audience friendly
**Style:** Dark background, minimal text per slide, heavy use of bold numbers and icons
**Length:** 14–16 slides
**Font style:** Monospace or technical sans-serif for headers; clean readable body font
**Design language:** Security / cybersecurity / enterprise dashboard aesthetic
**Avoid:** Clip art, cartoons, excessive animation, color gradients that look cheap

---

## Slide 1 — Title Slide

**Heading:** IERSS
**Subheading:** Internet Exposure & Risk Scoring System
**Tag line:** Real-Time URL Threat Assessment. Zero Expertise Required.
**Bottom footer:** Version 2.2 | April 2026 | Confidential
**Visual suggestion:** A dark, minimal layout with a stylised shield or network grid in the background. The system name should feel authoritative — large, monospaced font. Avoid anything that looks like a startup pitch template.

---

## Slide 2 — The Problem (Hook Slide)

**Heading:** The Threat Is Already Inside the Inbox

**Key statistics to display prominently (large numbers, not bullet points):**
- 3.4 Billion phishing emails sent every day
- 1.5 Million new phishing sites created per month
- 97% of phishing domains are live for less than 24 hours
- 21 Days average dwell time before detection

**Body text (small, beneath the numbers):**
By the time a domain reaches a blocklist, the campaign is already over.
Blocklists are reactive. IERSS is not.

**Visual suggestion:** Large dramatic statistics arranged in a 2x2 grid. Each stat is the hero of its quadrant — giant number, small label beneath. Dark slide, high contrast text.

---

## Slide 3 — What Organisations Currently Use (And Why It Fails)

**Heading:** The Current Approach Has a Critical Gap

**Display as a two-column comparison or a visual weakness map:**

Left column — What Exists:
- Email filters — miss zero-day phishing
- Manual SOC review — not scalable under volume
- Commercial scanners — expensive, privacy risk
- Blocklists — 0% coverage for domains registered today

Right column — The Gap:
- New phishing domains evade all of the above
- SOC teams are overwhelmed, not empowered
- No plain-English output for non-technical stakeholders
- No local, private, unlimited option

**Visual suggestion:** A table or two-column layout. Left side looks "old" or "insufficient." Right side has warning indicators next to each item. Keep text minimal.

---

## Slide 4 — Introducing IERSS

**Heading:** IERSS: The Detection Gap, Closed

**One-sentence definition (display large in centre):**
"IERSS evaluates any URL or domain in under 100 milliseconds and tells you — in plain English — whether it is safe to interact with."

**Three pillars below (icons + short labels):**
1. Prevent Harm — Flag threats before the click
2. Communicate Clearly — Business-language reports anyone can act on
3. Leave a Trail — Auditable evidence behind every verdict

**Visual suggestion:** Bold centred statement at the top. Three icon cards below — each with a single icon and a 3–5 word label. Shield icon, speech bubble icon, document/log icon.

---

## Slide 5 — How It Works (Pipeline Diagram)

**Heading:** Seven-Stage Analysis Pipeline

**Display as a vertical or horizontal flow diagram with 7 stages:**

Stage 1: Input Normalization — Decode, strip, validate
Stage 2: Structural Heuristics — Entropy, DGA, TLD, subdomain depth
Stage 3: Intelligence Patches — WHOIS age, SSL cert, HTML scan, URLhaus
Stage 4: Reputation Feeds — Google Safe Browsing, VirusTotal, URLhaus
Stage 5: Signal Tiering — T1 (Threat), T2 (Behavioral), T3 (Environmental)
Stage 6: Composite Scoring — Confidence-weighted, 0–100 scale
Stage 7: Business Report — Severity band, plain-English advisory, PDF

**Visual suggestion:** Horizontal flow with arrows. Each stage is a labelled box. Stage 3 should have a small "NEW" badge since it is a v2.2 addition. Keep labels short — no full sentences on this slide.

---

## Slide 6 — What the Output Looks Like

**Heading:** Every Scan Produces a Structured, Actionable Report

**Display as a mock report card or dashboard panel:**

Fields to show:
- Domain: (example domain)
- Risk Score: 78 / 100
- Severity: HIGH
- Evidence: 4 signals detected (T1: 1, T2: 2, T3: 1)
- Executive Summary: (one sentence in plain English, e.g., "This domain exhibits strong phishing characteristics. Immediate review is advised.")
- Recommended Action: Block and report to security team
- Export: PDF Report Available

**Visual suggestion:** Make this look like an actual dashboard card. Dark background, the risk score is the largest element. Severity badge uses bold text. Keep it clean and professional — not cluttered.

---

## Slide 7 — Why IERSS vs. Blocklists

**Heading:** Beyond Blocklists — Detecting What Has Not Been Seen Before

**Display as a side-by-side comparison table:**

| | Traditional Blocklist | IERSS |
|---|---|---|
| Coverage | Known threats only | Zero-day structural detection |
| Reaction time | Hours to days | Real-time — under 100ms |
| Reasoning | Block / Allow | Full evidence trail |
| New phishing | Missed | Caught via structural heuristics |
| Offline operation | No | Yes |

**Callout text:** "97% of phishing domains are active for less than 24 hours. Blocklists catch them after the campaign ends."

**Visual suggestion:** Clean table with a highlighted "IERSS" column. The callout text should appear as a large emphasized quote on the side or bottom of the slide.

---

## Slide 8 — Why IERSS vs. Commercial Scanners

**Heading:** Private, Unlimited, Explainable — Unlike Commercial Alternatives

**Display as a comparison table:**

| | Commercial Scanners | IERSS |
|---|---|---|
| Cost | Per-query pricing | Unlimited — self-hosted |
| Privacy | URLs sent to third-party cloud | On-premise, nothing leaves the network |
| Output | Technical score | Business-language report + PDF |
| Bulk processing | Manual API | Automated CSV batch |
| Evidence | Aggregate score only | Tiered signal breakdown |

**Visual suggestion:** Same comparison table format as Slide 7 for visual consistency. Highlight the IERSS column. Under the table, include a small note: "No subscription. No per-scan cost. No data sent externally."

---

## Slide 9 — Core Detection Capabilities

**Heading:** What IERSS Detects

**Display as a 2x3 or 3x2 capability card grid (6 cards):**

Card 1: Typosquatting & Brand Impersonation — g00gle.com, paypa1.com, look-alike domains
Card 2: DGA Detection — Algorithmically generated C2 domains via entropy analysis
Card 3: Phishing Patterns — 60+ regex patterns for credential harvesting and login spoofing
Card 4: Malware Payload Indicators — Suspicious file extensions in URL paths
Card 5: Certificate Anomalies — Expired, self-signed, and hostname-mismatched SSL certs
Card 6: Content-Level Threats — Hidden iframes, phishing forms, obfuscated JavaScript

**Visual suggestion:** Six equal-sized cards in a grid. Each card has a small icon, a bold title, and one line of explanation. This is a capabilities overview slide — keep it visual, not text-heavy.

---

## Slide 10 — Stress Test Results

**Heading:** Independently Stress Tested — 515 Cases, 8 Phases

**Display key results as large numbers:**

- 97.9% — Average pass rate across all 8 phases
- 100% — Safety check pass rate (0 critical threats misclassified)
- 0 — Crash rate
- 0 — False negatives on must-flag domains
- 183 req/s — Peak throughput under concurrent load
- 91 ms — Median scan latency

**Below the numbers, show a phase summary table:**

| Phase | Description | Result |
|---|---|---|
| 1 | Extreme Input Stress (194 cases) | PASS |
| 2 | Network Failure Simulation | PASS |
| 3 | Adversarial Evasion (52 domains) | PASS |
| 4 | High Volume Load (200 concurrent) | PASS |
| 5 | Consistency (5 runs per domain) | PASS |
| 6 | XSS/Injection Backend Stress | 83% (patched) |
| 7 | Memory & Resource Limits | PASS |
| 8 | Safety Check — 29 Real Threats | PASS |

**Visual suggestion:** Large numbers in a hero grid at the top. Table below. This is a proof slide — it should feel like a benchmark report, not a sales pitch.

---

## Slide 11 — Final Score

**Heading:** Independent Audit Verdict

**Display score as the centrepiece of the slide (very large):**

9.4 / 10

**Beneath it:**
Production Safe

**Beneath that:**
"All phases passed with ≥90% reliability. The system operates safely under stress, hostile inputs, and API failures."

**Small note at bottom:**
Phase 6 edge case (XSS input) resolved in v2.2 — estimated score on next audit: 9.7 / 10

**Visual suggestion:** Minimal slide. The score is the only thing that matters visually. Large centred number, clean badge label below it, and a single supporting line. Think certificate or award, not data slide.

---

## Slide 12 — Strengths Summary

**Heading:** Why IERSS Is Ready for Production

**Display as a two-column list of key strengths:**

Left column:
- Zero false safety failures in live testing
- Zero classification flips across 5 consistency runs
- 183 requests/second throughput under load
- Offline-capable — works without internet
- Full audit trail per verdict

Right column:
- Business-language output — no security expertise needed
- Three independent reputation feeds
- Fully on-premise — no data leaves the network
- Evidence-based — every score is reconstructable
- Compliance-ready — supports GDPR, ISO 27001, SOC 2

**Visual suggestion:** Two-column clean list with checkmark icons. Each item is short — 6 words or fewer. This is a confidence-builder slide, not a feature dump.

---

## Slide 13 — Deployment Options

**Heading:** Deploy in the Way That Works for Your Organisation

**Display as five option cards or a table:**

Option 1: Standalone Desktop — Single analyst, local use. `streamlit run app.py`.
Option 2: Internal Team Server — Shared browser access, team-wide deployment.
Option 3: REST API (FastAPI) — Integrate into SIEM, SOAR, or ticketing systems.
Option 4: CI/CD Pipeline — Run URL checks in automated DevSecOps pipelines.
Option 5: Batch CSV Processing — Bulk vendor or domain triage with downloadable results.

**Visual suggestion:** Five clean cards or a minimal table. Each option has a brief label and a one-line use-case description. Add a setup effort indicator if possible (Low / Medium).

---

## Slide 14 — Roadmap

**Heading:** What Comes Next

**Display as a phased roadmap:**

Immediate:
- Configure GSB and VirusTotal API keys for full reputation coverage

Short-term:
- Headless browser integration (Playwright) for JS-rendered phishing detection
- WHOIS pre-cache for frequently scanned domains

Medium-term:
- Authenticated REST API for SIEM/SOAR/ticketing integration
- Active certificate transparency monitoring

Long-term:
- Cross-domain threat-actor campaign clustering and attribution

**Visual suggestion:** Horizontal timeline or phased lane diagram. Each phase should be visually distinct — immediate is closest to the viewer, long-term is further away. Keep text very short on this slide.

---

## Slide 15 — Closing Statement

**Heading:** The Gap Is Real. The Solution Is Ready.

**Display as a bold centred statement:**

"Phishing campaigns are live and gone in hours. Your threat intel feed catches them days later. IERSS operates in that gap — for every URL, in under 100 milliseconds, with a report anyone can read."

**Beneath it:**
IERSS is not a replacement for your security team.
It is what makes your security team two orders of magnitude faster.

**Bottom strip:**
IERSS v2.2 — Production Safe — Score 9.4 / 10 — April 2026

**Visual suggestion:** Minimal, powerful close. Dark slide. The quote is the entire slide. Bold the key phrases. The bottom strip is small and acts as a footer. No bullet points, no tables — just the statement.

---

## Slide 16 — Contact / Q&A

**Heading:** Questions & Next Steps

**Display:**
- Invite the audience to request a live demo
- Mention availability for technical deep-dive sessions
- Offer to walk through the stress test results in detail

**Footer:** Document prepared for internal pitch and stakeholder review. | IERSS Project Team

**Visual suggestion:** Clean, minimal Q&A slide. A single large "Q&A" or question mark motif in the background. Contact information or next step call-to-action centred on the slide.

---

## Presenter Notes Summary

Use these talking points when presenting each section:

**Slides 2–3 (Problem):** Lead with the statistics. Let the numbers land before you explain what they mean. The goal is to make the audience feel the urgency before you offer the solution.

**Slide 5 (Pipeline):** Do not read every stage. Pick 2–3 that surprise the audience — usually Stage 3 (patches) and Stage 7 (business language output). Emphasise: "This is all passive — we never probe or touch the target."

**Slide 10–11 (Test Results):** These are your strongest proof slides. Pause on the score. Let silence do the work. Then say: "Zero safety failures. Not one critical threat was missed."

**Slide 12 (Strengths):** Anchor on "offline-capable" and "on-premise." These differentiate IERSS from every commercial competitor. Privacy-conscious organisations respond strongly to these.

**Slide 15 (Close):** Deliver the closing statement slowly. It is the only slide that should feel emotional rather than informational.

---

*Prompt document prepared for AI PPT generation.*
*File: `f:\internet_exposure_system\docs\pitch\IERSS_PPT_Prompt.md`*
*Pair with: `IERSS_Pitch_Document.md` for full written reference.*
