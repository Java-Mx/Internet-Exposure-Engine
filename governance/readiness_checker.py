"""
AERIS Enterprise Readiness Checker
=====================================
Automatically evaluates the AERIS codebase against the enterprise readiness
criteria defined in governance/enterprise_readiness.yaml.

Run: python governance/readiness_checker.py

Outputs:
- Updated enterprise_readiness.yaml with computed scores
- Console summary table
- Returns exit code 0 if overall score >= 80, else 1
"""
from __future__ import annotations

import os
import sys
import re
import yaml  # requires PyYAML
from pathlib import Path
from datetime import datetime
from typing import Dict, Tuple
from dotenv import load_dotenv

# Load environment configuration
load_dotenv()

# Handle yaml import gracefully
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

BASE_DIR = Path(__file__).parent.parent
YAML_PATH = Path(__file__).parent / 'enterprise_readiness.yaml'


def _file_exists(relative_path: str) -> bool:
    return (BASE_DIR / relative_path).exists()


def _grep_file(relative_path: str, pattern: str) -> bool:
    """Returns True if pattern found in file."""
    p = BASE_DIR / relative_path
    if not p.exists():
        return False
    try:
        content = p.read_text(encoding='utf-8', errors='ignore')
        return bool(re.search(pattern, content))
    except Exception:
        return False


def _grep_any_file(glob_pattern: str, search_pattern: str, exclude_dirs: list = None) -> bool:
    """Returns True if pattern found in any file matching glob."""
    defaults = ['venv', '.git', '__pycache__', 'htmlcov', '.pytest_cache', '.agents', '.streamlit']
    if exclude_dirs:
        defaults.extend(exclude_dirs)
    for p in BASE_DIR.rglob(glob_pattern):
        # Match against parts of path to be exact and fast
        if any(ex in p.parts for ex in defaults):
            continue
        try:
            content = p.read_text(encoding='utf-8', errors='ignore')
            if re.search(search_pattern, content):
                return True
        except Exception:
            continue
    return False


def _count_lines(relative_path: str) -> int:
    p = BASE_DIR / relative_path
    if not p.exists():
        return 9999
    try:
        return sum(1 for _ in p.open(encoding='utf-8', errors='ignore'))
    except Exception:
        return 9999


def run_checks() -> Dict[str, Dict]:
    """Run all checks. Returns {category: {check: passing}} dict."""
    results = {}

    # ── Authentication
    results['Authentication'] = {
        'auth_module_exists': _file_exists('auth/auth_manager.py'),
        'roles_defined': _file_exists('auth/roles.py'),
        'user_db_exists': _file_exists('auth/user_db.json'),
        'default_password_changed': _file_exists('auth/user_db.json') and not _grep_file('auth/user_db.json', 'CHANGE_ME_NOW'),
        'login_gate_active': _grep_file('app.py', 'aeris_authenticated'),
    }

    # ── Authorization
    results['Authorization'] = {
        'rbac_module_exists': _file_exists('auth/roles.py') and _grep_file('auth/roles.py', 'ROLE_PERMISSIONS'),
        'debug_gated_to_admin': _grep_file('app.py', 'aeris_role.*admin|admin.*aeris_role'),
        'red_team_gated': _grep_file('app.py', '_require_permission') or _grep_any_file('pages/*.py', '_require_permission'),
    }

    # ── Auditability
    results['Auditability'] = {
        'audit_trail_module_exists': _file_exists('ai_governance/audit_trail.py'),
        'signing_key_not_default': (
            os.getenv('AERIS_SIGNING_KEY', '') != '' and
            os.getenv('AERIS_SIGNING_KEY', '') != 'AERIS-SYSTEM-SECRET-DEFAULT-KEY-9821831'  # nosec: security guard — rejects default key, does not use it
        ),
        'no_hardcoded_intelligence': not _grep_any_file('*.py', r'104\.21\.41\.201', ['tests']),
        'constitution_exists': _file_exists('docs/AERIS_ENTERPRISE_CONSTITUTION.md'),
    }

    # ── Security
    env_content = ''
    env_path = BASE_DIR / '.env'
    if env_path.exists():
        env_content = env_path.read_text(encoding='utf-8', errors='ignore')

    _bad_keys = ['AIzaSy', '5d9c9c9ab3', 'javamx']
    secrets_clean = not any(bk in env_content for bk in _bad_keys)

    gitignore_content = ''
    gi_path = BASE_DIR / '.gitignore'
    if gi_path.exists():
        gitignore_content = gi_path.read_text()

    results['Security'] = {
        'env_validator_exists': _file_exists('config/env_validator.py'),
        'secrets_not_in_env': secrets_clean,
        'html_sanitizer_exists': _file_exists('utils/html_sanitizer.py'),
        'gitignore_covers_secrets': '.env' in gitignore_content and 'credentials.toml' in gitignore_content,
    }

    # ── Observability
    results['Observability'] = {
        'structured_logging_config': _file_exists('config/logging_config.py'),
        'error_handling_explicit': not _grep_any_file('services/*.py', r'except\s+Exception\s*:\s*\n\s*pass'),
        'env_validation_on_startup': _grep_file('app.py', 'env_validator|fail_if_invalid'),
    }

    # ── Architecture
    results['Architecture'] = {
        'pages_directory_exists': _file_exists('pages') and len(list((BASE_DIR / 'pages').glob('*.py'))) > 1,
        'services_directory_exists': _file_exists('services') and len(list((BASE_DIR / 'services').glob('*.py'))) > 1,
        'app_py_under_limit': _count_lines('app.py') < 300,
        'no_business_logic_in_pages': not _grep_any_file('pages/*.py', r'from records\.database|mysql\.connector|from risk_scoring'),
        'visualizations_directory_exists': _file_exists('visualizations/provenance.py'),
    }

    # ── Intelligence Integrity
    results['Intelligence_Integrity'] = {
        'no_hardcoded_asn': not _grep_any_file('pages/*.py', r'AS13335|AS15169', []),
        'data_provenance_module_exists': _file_exists('visualizations/provenance.py'),
        'no_fake_financial_figures': not _grep_any_file('pages/*.py', r'\$.*,.*USD|\$450,000|\$4,200,000'),
        'anti_theater_scanner_exists': _file_exists('governance/anti_theater_scanner.py'),
    }

    # ── Research Validation
    results['Research_Validation'] = {
        'no_static_accuracy_claims': not _grep_any_file('pages/*.py', r'98\.0%|2\.0%|4\.0%'),
        'research_directory_exists': _file_exists('research'),
        'evaluation_framework_exists': _file_exists('research/evaluation'),
    }

    return results


def compute_scores(check_results: Dict) -> Dict[str, int]:
    """Compute 0-100 score per category."""
    scores = {}
    for category, checks in check_results.items():
        if not checks:
            scores[category] = 0
            continue
        passed = sum(1 for v in checks.values() if v)
        scores[category] = int((passed / len(checks)) * 100)
    return scores


def update_yaml(check_results: Dict, scores: Dict) -> None:
    """Update the enterprise_readiness.yaml with computed results."""
    if not YAML_AVAILABLE:
        print("[Warning] PyYAML not available. Cannot update YAML file.")
        return
    try:
        content = YAML_PATH.read_text(encoding='utf-8')
        data = yaml.safe_load(content)

        root = data.get('aeris_enterprise_readiness', {})
        root['last_computed'] = datetime.now().isoformat()
        root['overall_score'] = int(sum(scores.values()) / max(len(scores), 1))

        for category, checks in check_results.items():
            if category in root.get('categories', {}):
                cat = root['categories'][category]
                cat['score'] = scores.get(category, 0)
                cat['status'] = 'passing' if cat['score'] == 100 else ('failing' if cat['score'] < 50 else 'partial')
                for check_name, passing in checks.items():
                    if check_name in cat.get('checks', {}):
                        cat['checks'][check_name]['passing'] = passing

        YAML_PATH.write_text(yaml.dump(data, default_flow_style=False, sort_keys=False), encoding='utf-8')
        print(f"[OK] Updated {YAML_PATH}")
    except Exception as e:
        print(f"[Warning] Could not update YAML: {e}")


def print_report(check_results: Dict, scores: Dict) -> None:
    overall = int(sum(scores.values()) / max(len(scores), 1))
    print("\n" + "=" * 60)
    print(f"  AERIS Enterprise Readiness Report")
    print(f"  Computed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    for category, checks in check_results.items():
        score = scores.get(category, 0)
        status = 'PASS' if score == 100 else ('WARN' if score >= 50 else 'FAIL')
        print(f"\n[{status}] {category}: {score}%")
        for check_name, passing in checks.items():
            icon = '  [PASS]' if passing else '  [FAIL]'
            print(f"{icon} {check_name}")
    print("\n" + "=" * 60)
    print(f"  OVERALL SCORE: {overall}%")
    grade = 'A' if overall >= 90 else ('B' if overall >= 75 else ('C' if overall >= 60 else ('D' if overall >= 40 else 'F')))
    print(f"  GRADE: {grade}")
    print("=" * 60 + "\n")


if __name__ == '__main__':
    print("Running AERIS Enterprise Readiness Checks...")
    results = run_checks()
    scores = compute_scores(results)
    print_report(results, scores)
    update_yaml(results, scores)
    overall = int(sum(scores.values()) / max(len(scores), 1))
    sys.exit(0 if overall >= 80 else 1)
