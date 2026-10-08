"""
AERIS Anti-Theater Scanner
============================
Scans the AERIS codebase for "intelligence theater" patterns — code that
presents fabricated, hardcoded, or simulated data as if it were real intelligence.

WHAT IS THEATER?
  Theater is any pattern that makes the system LOOK more capable than it IS.
  It misleads analysts and undermines enterprise trust.

HOW TO USE:
  CLI:  python governance/anti_theater_scanner.py
  API:  from governance.anti_theater_scanner import run_scan, TheaterFinding

The scanner returns a list of TheaterFinding objects, each with:
  - file, line_number, line_content
  - pattern_name (what type of theater)
  - severity (CRITICAL / HIGH / MEDIUM / LOW)
  - remediation_hint

Integrate into CI/CD to fail builds that introduce new theater patterns.
"""
from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple
from datetime import datetime

# ─── Base directory ─────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent.parent

# ─── Files/directories excluded from scanning ───────────────────────────────
EXCLUDE_DIRS = {
    "venv", ".git", "__pycache__", "htmlcov", ".pytest_cache",
    "node_modules", ".streamlit",
}
EXCLUDE_FILES = {
    "anti_theater_scanner.py",   # Don't flag the scanner itself
    "test_*.py",                  # Test files may contain these patterns as test data
}


# ─── Theater Pattern Definitions ────────────────────────────────────────────

@dataclass
class TheaterPattern:
    name: str
    pattern: str          # regex
    severity: str         # CRITICAL / HIGH / MEDIUM / LOW
    description: str
    remediation: str
    file_glob: str = "*.py"    # Which files to check


THEATER_PATTERNS: List[TheaterPattern] = [

    # ── Hardcoded IP Addresses ──────────────────────────────────────────────
    TheaterPattern(
        name="HARDCODED_IP_ADDRESS",
        pattern=r'["\'](\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})["\']',
        severity="CRITICAL",
        description="A hardcoded IP address found in source code. "
                    "IP addresses shown in visualizations must come from real DNS resolution, "
                    "not embedded literals.",
        remediation="Replace with data sourced from DNS lookup stored in DB. "
                    "Use visualizations/infrastructure_graph.py build_graph_nodes_from_evidence().",
    ),

    # ── Known Fake IPs (specific known offenders from audit) ───────────────
    TheaterPattern(
        name="KNOWN_FAKE_IP_104",
        pattern=r'104\.21\.41\.' + r'201',
        severity="CRITICAL",
        description="The specific hardcoded IP 104.21.41." + "201" + " (Cloudflare shared range) "
                    "was found embedded as a fake intelligence node in the original audit. "
                    "This must not appear in any production file.",
        remediation="Remove this IP entirely. Use real DNS resolution data from the scan.",
    ),

    # ── Hardcoded ASN Numbers ───────────────────────────────────────────────
    TheaterPattern(
        name="HARDCODED_ASN",
        pattern=r'AS\d{4,6}\s*\([A-Za-z]+\)|["\']AS13335["\']|["\']AS15169["\']',
        severity="CRITICAL",
        description="Hardcoded ASN (Autonomous System Number) found. "
                    "ASN nodes in graphs must come from real IP-to-ASN lookup, not embedded strings.",
        remediation="Source ASN from real lookup stored at scan time. "
                    "Store in DB via records/database.py extended save_scan().",
    ),

    # ── Financial Dollar Amounts from Lookup ─────────────────────────────────
    TheaterPattern(
        name="FAKE_FINANCIAL_FIGURES",
        pattern=r'\$[\d,]+[\s\u2013\-]+\$[\d,]+|breach_cost|\"financial_impact\".*\d{5,}',
        severity="HIGH",
        description="Possible fabricated financial dollar amounts or breach cost ranges "
                    "found in code. Financial figures must not be derived from dict lookups.",
        remediation="Replace with qualitative business impact categories. "
                    "Use visualizations/business_impact.py compute_qualitative_impact().",
    ),

    # ── time.sleep in rendering paths ───────────────────────────────────────
    TheaterPattern(
        name="SLEEP_IN_RENDER_PATH",
        pattern=r'time\.sleep\(',
        severity="HIGH",
        description="time.sleep() found. In rendering paths this simulates processing "
                    "time to make fast local heuristics appear as a live intelligence pipeline. "
                    "This is theatrical deception.",
        remediation="Remove time.sleep() from rendering paths. If step timing feedback is "
                    "needed, use real elapsed time from the actual computation.",
        file_glob="*.py",
    ),

    # ── Static Accuracy Claims ───────────────────────────────────────────────
    TheaterPattern(
        name="STATIC_ACCURACY_CLAIM",
        pattern=r'98\.0%|2\.0%\s*FNR|4\.0%\s*FPR|PASS\s*7/7|100%\s*accuracy',
        severity="HIGH",
        description="Hardcoded accuracy/performance metric claim found as a static string. "
                    "These claims are not linked to any reproducible evaluation run.",
        remediation="Remove static claims. Link to research/evaluation/results/latest.json "
                    "or show 'Not yet evaluated — run research/evaluation/run_evaluation.py'.",
    ),

    # ── Hardcoded Campaign IDs ───────────────────────────────────────────────
    TheaterPattern(
        name="HARDCODED_CAMPAIGN_ID",
        pattern=r'["\']CAMP-\d{3}["\'].*(?:in\s+target|if.*in\s+target|else\s+["\']CAMP)',
        severity="HIGH",
        description="Campaign ID is being hardcoded based on target name. "
                    "Campaign matching must come from the ThreatMemory campaign library, "
                    "not from if/else conditionals on the target string.",
        remediation="Use ThreatMemory.get_campaign_matches(target) which queries the "
                    "campaign seed library against actual evidence.",
    ),

    # ── IMMUTABLE LEDGER Theater ─────────────────────────────────────────────
    TheaterPattern(
        name="IMMUTABLE_LEDGER_CLAIM",
        pattern=r'IMMUTABLE.{0,20}LEDGER|CRYPTOGRAPHICALLY\s+SECURED\s+IN\s+LEDGER|tamper.?proof',
        severity="HIGH",
        description="False governance claim detected. 'Immutable Ledger' or 'Cryptographically "
                    "Secured Ledger' implies blockchain-grade immutability. The current "
                    "implementation is a MySQL INSERT — not an immutable ledger.",
        remediation="Replace with honest audit trail status: show whether the DB write "
                    "succeeded and whether AERIS_SIGNING_KEY is set from environment.",
    ),

    # ── Default HMAC Key ─────────────────────────────────────────────────────
    TheaterPattern(
        name="DEFAULT_HMAC_KEY",
        pattern=r'AERIS-SYSTEM-SECRET-DEFAULT-KEY',
        severity="CRITICAL",
        description="The default HMAC signing key is present in source code. "
                    "Any signature created without overriding this key can be forged by "
                    "anyone who reads the source code.",
        remediation="Remove the hardcoded default. Require AERIS_SIGNING_KEY env var. "
                    "Use config/env_validator.py to fail startup if not set.",
    ),

    # ── Bare except:pass (silent failure theater) ────────────────────────────
    TheaterPattern(
        name="SILENT_FAILURE_EXCEPT_PASS",
        pattern=r'except\s+Exception\s*:\s*\n\s*pass',
        severity="MEDIUM",
        description="Silent exception swallowing: 'except Exception: pass'. "
                    "This makes the system appear to work when components have failed. "
                    "It prevents operators from knowing the system is degraded.",
        remediation="Replace with explicit error handling: log the failure, return a "
                    "typed error result, or raise with context. Never silently pass.",
    ),

    # ── Import inside function body ──────────────────────────────────────────
    TheaterPattern(
        name="IMPORT_IN_FUNCTION_BODY",
        pattern=r'^\s{4,}import\s+(?:re|time|math|json|os|sys|hashlib)\b',
        severity="LOW",
        description="Import statement inside a function or method body. "
                    "This is an architectural smell indicating the code was not designed — "
                    "it grew. All imports belong at the file top.",
        remediation="Move import to the top of the file.",
    ),

    # ── Hardcoded brand names in visualization conditionals ──────────────────
    TheaterPattern(
        name="BRAND_CONDITIONAL_IN_VISUALIZATION",
        pattern=r'if\s+["\']facebook["\']\s+in\s+target|if\s+["\']apple["\']\s+in\s+target',
        severity="HIGH",
        description="Brand-conditional logic found in visualization code. "
                    "This means the visualization changes its displayed data based on "
                    "the target name, not based on real evidence.",
        remediation="Remove brand-conditional logic. All visualization data must come "
                    "from the evidence chain and DB records, not from target name matching.",
    ),

    # ── Hardcoded LIVE API keys ──────────────────────────────────────────────
    TheaterPattern(
        name="HARDCODED_API_KEY",
        pattern=r'AIzaSy[A-Za-z0-9_-]{33}|[0-9a-f]{64}',
        severity="CRITICAL",
        description="Possible hardcoded API key found in source. "
                    "API keys in source code are a critical security vulnerability.",
        remediation="Move all secrets to environment variables. "
                    "Use config/env_validator.py. Revoke the exposed key immediately.",
        file_glob="*.py",
    ),

    # ── st.markdown unsafe_allow_html with direct f-string user input ────────
    TheaterPattern(
        name="XSS_UNSAFE_HTML_FSTRING",
        pattern=r'st\.markdown\(f["\'].*\{(?:target|domain|url|user_input|page_title).*\}.*unsafe_allow_html\s*=\s*True',
        severity="CRITICAL",
        description="User-controlled variable interpolated directly into st.markdown "
                    "with unsafe_allow_html=True. This is an XSS vulnerability.",
        remediation="Use utils/html_sanitizer.py safe_html() on all user-controlled "
                    "values before inserting into HTML strings.",
    ),
]


# ─── Finding dataclass ───────────────────────────────────────────────────────

@dataclass
class TheaterFinding:
    file: str
    line_number: int
    line_content: str
    pattern_name: str
    severity: str
    description: str
    remediation: str

    @property
    def severity_icon(self) -> str:
        return {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(self.severity, "⚪")


# ─── Scanner core ─────────────────────────────────────────────────────────────

def _should_skip(path: Path) -> bool:
    """Return True if this path should be excluded from scanning."""
    for part in path.parts:
        if part in EXCLUDE_DIRS:
            return True
    for excl in EXCLUDE_FILES:
        if path.match(excl):
            return True
    return False


def scan_file(path: Path, patterns: List[TheaterPattern]) -> List[TheaterFinding]:
    """Scan a single file for all theater patterns.

    Lines annotated with ``# nosec`` are suppressed from reporting.
    This follows the standard security-scanner suppression convention
    (identical to Bandit / Semgrep). Each suppression must be documented
    in CRITICAL_finding_report.md with a justification before it is added.
    """
    findings: List[TheaterFinding] = []
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
        lines = content.splitlines()
    except Exception:
        return findings

    # Build a set of suppressed line numbers (1-indexed)
    suppressed_lines: set = {
        i + 1
        for i, line in enumerate(lines)
        if "# nosec" in line
    }

    for pattern in patterns:
        # Check file glob filter
        if not path.match(pattern.file_glob):
            continue
        compiled = re.compile(pattern.pattern, re.MULTILINE)
        for match in compiled.finditer(content):
            # Find line number
            line_num = content[:match.start()].count("\n") + 1
            # Skip suppressed lines
            if line_num in suppressed_lines:
                continue
            line_content = lines[line_num - 1] if line_num <= len(lines) else ""
            findings.append(TheaterFinding(
                file=str(path.relative_to(BASE_DIR)),
                line_number=line_num,
                line_content=line_content.strip()[:120],
                pattern_name=pattern.name,
                severity=pattern.severity,
                description=pattern.description,
                remediation=pattern.remediation,
            ))
    return findings


def run_scan(
    target_dir: Optional[Path] = None,
    patterns: Optional[List[TheaterPattern]] = None,
) -> List[TheaterFinding]:
    """
    Run the full anti-theater scan on the AERIS codebase.

    Args:
        target_dir:  Directory to scan (defaults to BASE_DIR)
        patterns:    Patterns to check (defaults to all THEATER_PATTERNS)

    Returns:
        List of TheaterFinding objects, sorted by severity then file.
    """
    scan_dir = target_dir or BASE_DIR
    active_patterns = patterns or THEATER_PATTERNS

    all_findings: List[TheaterFinding] = []

    for path in scan_dir.rglob("*.py"):
        if _should_skip(path):
            continue
        findings = scan_file(path, active_patterns)
        all_findings.extend(findings)

    # Sort: CRITICAL > HIGH > MEDIUM > LOW, then by file
    _sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    all_findings.sort(key=lambda f: (_sev_order.get(f.severity, 9), f.file, f.line_number))

    return all_findings


def generate_report(findings: List[TheaterFinding]) -> str:
    """Generate a text summary report of theater findings."""
    if not findings:
        return (
            "\n✅ AERIS Anti-Theater Scan: CLEAN\n"
            "No theater patterns detected in the codebase.\n"
        )

    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

    lines = [
        f"\n{'=' * 65}",
        f"  AERIS Anti-Theater Scan Report",
        f"  Scanned: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"  Total Findings: {len(findings)}",
        f"{'=' * 65}",
        f"",
        f"  🔴 CRITICAL: {sev_counts['CRITICAL']}",
        f"  🟠 HIGH:     {sev_counts['HIGH']}",
        f"  🟡 MEDIUM:   {sev_counts['MEDIUM']}",
        f"  🟢 LOW:      {sev_counts['LOW']}",
        f"",
        f"{'=' * 65}",
    ]

    for finding in findings:
        lines.extend([
            f"",
            f"{finding.severity_icon} [{finding.severity}] {finding.pattern_name}",
            f"  File:    {finding.file}:{finding.line_number}",
            f"  Code:    {finding.line_content}",
            f"  Issue:   {finding.description[:120]}...",
            f"  Fix:     {finding.remediation[:120]}...",
        ])

    lines.append(f"\n{'=' * 65}\n")
    return "\n".join(lines)


# ─── CLI entry point ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="AERIS Anti-Theater Scanner — detects fabricated intelligence patterns"
    )
    parser.add_argument(
        "--dir", type=Path, default=None,
        help="Directory to scan (default: AERIS project root)"
    )
    parser.add_argument(
        "--severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"], default=None,
        help="Filter findings to this severity and above"
    )
    parser.add_argument(
        "--fail-on", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "any"], default="CRITICAL",
        help="Exit code 1 if findings at this severity or above exist (default: CRITICAL)"
    )
    args = parser.parse_args()

    findings = run_scan(target_dir=args.dir)

    # Apply severity filter
    if args.severity:
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        threshold = sev_order.get(args.severity, 3)
        findings = [f for f in findings if sev_order.get(f.severity, 9) <= threshold]

    report = generate_report(findings)
    try:
        print(report)
    except UnicodeEncodeError:
        encoding = sys.stdout.encoding or 'utf-8'
        print(report.encode(encoding, errors='replace').decode(encoding))

    # Determine exit code
    if args.fail_on == "any":
        sys.exit(1 if findings else 0)
    else:
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        threshold = sev_order.get(args.fail_on, 0)
        blocking = [f for f in findings if sev_order.get(f.severity, 9) <= threshold]
        sys.exit(1 if blocking else 0)
