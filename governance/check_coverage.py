"""
AERIS Coverage Threshold Checker
================================
Enforces coverage targets per core module:
- Tier-1: threat_memory, correlation_engine, signal_integrator (80-90% target, min 80% enforced)
- Tier-2: feed_connector, virustotal_client, google_safe_browsing (70%+ target, min 70% enforced)
"""
import json
import os
import sys
import subprocess

TARGETS = {
    # Tier-1 (80-90% target)
    "intelligence/threat_memory.py": 80.0,
    "intelligence/correlation_engine.py": 80.0,
    "risk_scoring/signal_integrator.py": 80.0,
    # Tier-2 (70%+)
    "intelligence/feed_connector.py": 70.0,
    "risk_scoring/virustotal_client.py": 70.0,
    "risk_scoring/google_safe_browsing.py": 70.0,
}

TEST_FILES = [
    "tests/unit/test_threat_memory.py",
    "tests/unit/test_correlation_engine.py",
    "tests/unit/test_signal_integrator.py",
    "tests/unit/test_feed_connector.py",
    "tests/unit/test_virustotal_client.py",
    "tests/unit/test_google_safe_browsing.py"
]

def run_tests_and_get_coverage():
    print("Running pytest runs sequentially with coverage appending...")
    # Clean old report and database
    if os.path.exists("coverage.json"):
        try:
            os.remove("coverage.json")
        except Exception:
            pass

    subprocess.run([sys.executable, "-m", "coverage", "erase"])

    for tf in TEST_FILES:
        print(f"Running tests for {tf}...")
        res = subprocess.run(
            [sys.executable, "-m", "pytest", tf, "--cov=.", "--cov-append", "-q"],
            capture_output=True,
            text=True
        )
        print(res.stdout)
        if res.returncode != 0:
            print(f"Error running tests for {tf}:", file=sys.stderr)
            print(res.stderr, file=sys.stderr)

    # Generate JSON report
    print("Generating coverage.json report...")
    res = subprocess.run(
        [sys.executable, "-m", "coverage", "json"],
        capture_output=True,
        text=True
    )
    if res.returncode != 0:
        print("Error generating coverage.json:", file=sys.stderr)
        print(res.stderr, file=sys.stderr)

    if not os.path.exists("coverage.json"):
        print("Error: coverage.json was not generated.", file=sys.stderr)
        sys.exit(1)

def check_coverage():
    with open("coverage.json", "r") as f:
        data = json.load(f)

    files_data = data.get("files", {})
    failed = False

    print("\n" + "=" * 60)
    print("AERIS Core Modules Coverage Audit")
    print("=" * 60)

    # We normalize keys to match files_data keys which might use backslashes on Windows or forward slashes on Linux
    normalized_files_data = {}
    for filepath, file_info in files_data.items():
        normalized_files_data[os.path.normpath(filepath).replace("\\", "/")] = file_info

    for filepath, min_threshold in TARGETS.items():
        norm_path = os.path.normpath(filepath).replace("\\", "/")
        file_info = normalized_files_data.get(norm_path)
        
        if not file_info:
            print(f"[FAIL] {filepath}: NOT FOUND in coverage report! (Enforced min: {min_threshold}%)")
            failed = True
            continue
            
        covered_pct = file_info.get("summary", {}).get("percent_covered", 0.0)
        status = "[PASS]" if covered_pct >= min_threshold else "[FAIL]"
        print(f"{status} {filepath}: {covered_pct:.1f}% (Enforced min: {min_threshold}%)")
        if covered_pct < min_threshold:
            failed = True

    print("=" * 60)
    if failed:
        print("FAIL: One or more core modules did not meet the coverage targets.")
        sys.exit(1)
    else:
        print("PASS: All core modules met coverage targets.")
        sys.exit(0)

if __name__ == "__main__":
    run_tests_and_get_coverage()
    check_coverage()
