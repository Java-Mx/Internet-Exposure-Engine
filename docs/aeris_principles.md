# AERIS Permanent Design Principles

> These seven principles govern all development decisions in AERIS.
> They are non-negotiable. No feature, no deadline, and no visual goal overrides them.
> Future developers and AI agents must read and comply with these principles.

---

## Principle 1: No Hardcoded Intelligence

Every data point presented to users — IP addresses, ASN numbers, domain names,
campaign identifiers, hostnames — must originate from an actual data source
(database query, API response, or live computation).

**Banned:** Static values like `104.21.41.201`, `AS13335`, or `CAMP-002` embedded
directly in page templates or visualization code.

**Required:** All intelligence data flows from `services/` → `visualizations/` → `pages/`.
If no real data exists, render an empty-state message, not fabricated data.

---

## Principle 2: No Fake Metrics

All quantitative claims displayed in the UI must be derived from actual computation
or measured evaluation runs.

**Banned:** Hardcoded accuracy percentages (e.g., `98.0%`, `2.0% FNR`) as static
HTML strings. Financial estimates as Python dictionary lookups.

**Required:** Metrics come from `research/evaluation/results/latest.json` (Phase F)
or are clearly labelled as "unvalidated — run evaluation to compute."

---

## Principle 3: No Simulated Operational Data Presented as Real

Pipeline trackers, intelligence dashboards, and operational consoles must reflect
actual system state. Animation and visual polish are permitted; fabrication is not.

**Banned:** `time.sleep()` in rendering paths to simulate processing time.
Pipeline steps that show "LIVE" but execute in <100ms with no real work.

**Required:** Pipeline steps reflect actual execution (step fires, completes, updates).
If a step is fast, it appears fast. Honesty over impressiveness.

---

## Principle 4: Every Visualization Must Originate from Actual Evidence

No graph, chart, map, or timeline may render without a declared data source.
The `DataProvenance` contract is mandatory for all visualization functions.

**Banned:** SVG graphs with manually embedded node coordinates and labels.
Timelines with hardcoded event dates.

**Required:** All visualization functions accept a `DataProvenance` object and
render it. Empty state is shown when no evidence exists.

---

## Principle 5: Every Confidence Score Must Be Explainable

Confidence values are not decorative. Every confidence score displayed must have
a traceable explanation available to the user upon request.

**Banned:** Confidence scores derived from vague multipliers with no explanation.
"Composite confidence" that users cannot inspect.

**Required:** `ConfidenceScorer` output includes per-dimension rationale.
The UI exposes this rationale in an expandable section.

---

## Principle 6: Governance Claims Must Match Implementation

Labels like "Immutable Ledger", "Cryptographically Secured", and "Tamper-Proof"
are legal and reputational claims. They must be technically accurate.

**Banned:** HMAC signing with a hardcoded fallback key. MySQL INSERT-only tables
labelled as "immutable ledgers."

**Required:** HMAC key sourced from environment only (no default). Governance
status in the UI reflects actual implementation state (not aspirational state).

---

## Principle 7: Enterprise Trust Is More Important Than Visual Appeal

AERIS is a decision-support tool for security professionals. An analyst making
a wrong decision because of fabricated data is a security failure, not a UI
success. When in doubt between visual richness and data honesty: choose honesty.

**Banned:** Replacing empty data states with impressive-looking placeholder content.
Displaying confidence or scores that were not actually computed for this target.

**Required:** Empty states are shown when data is absent. Placeholder content is
clearly labelled as such. No confidence theater.

---

*Document version: 1.0 — Adopted following Phase-X Enterprise Foundation audit.*
*All future AERIS contributors must read and acknowledge these principles.*
