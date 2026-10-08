"""
AERIS Environment Validator
============================
Validates that all required secrets are present and not set to known-bad
placeholder or default values before the application starts.

This module should be imported early in app startup. Call fail_if_invalid()
to halt the process if the environment is not properly configured.

Usage:
    from config.env_validator import fail_if_invalid, get_validation_report
    fail_if_invalid()           # exits with code 1 if config is broken
    report = get_validation_report()  # human-readable status string for UI
"""

import os
import sys
import logging

logger = logging.getLogger(__name__)

# ── Required secrets ─────────────────────────────────────────────────────────
REQUIRED_SECRETS = [
    'GOOGLE_SAFE_BROWSING_API_KEY',
    'VIRUSTOTAL_API_KEY',
    'AERIS_SIGNING_KEY',
]

# ── Values that indicate the secret was never properly configured ─────────────
KNOWN_BAD_VALUES = [
    'your_gsb_api_key_here',
    'your_virustotal_api_key_here',
    'AERIS-SYSTEM-SECRET-DEFAULT-KEY-9821831',  # nosec: detection allowlist — intentional reference to default key string
    'javamx',
    'your_KEY_NAME_here',
    '',
]


def validate_environment() -> dict:
    """
    Check that all required secrets are set and do not contain known-bad values.

    Returns a dict with keys:
        ok       (bool)  — True only if all secrets pass validation
        missing  (list)  — Names of env vars that are not set at all
        insecure (list)  — Names of env vars set to a known-bad placeholder value
        warnings (list)  — Human-readable warning strings
    """
    missing = []
    insecure = []
    warnings = []

    for secret_name in REQUIRED_SECRETS:
        value = os.environ.get(secret_name)

        if value is None:
            missing.append(secret_name)
            warnings.append(f"MISSING: {secret_name} is not set in the environment.")
        elif value.strip() in KNOWN_BAD_VALUES or value.strip() == '':
            insecure.append(secret_name)
            warnings.append(
                f"INSECURE: {secret_name} is set to a placeholder or default value."
            )

    ok = (len(missing) == 0 and len(insecure) == 0)

    return {
        'ok': ok,
        'missing': missing,
        'insecure': insecure,
        'warnings': warnings,
    }


def fail_if_invalid() -> None:
    """
    Validate the environment and exit the process with code 1 if any required
    secret is missing or contains a known-bad value.

    Safe to call at startup. Produces a clear, formatted error message
    to stderr before exiting so operators know exactly what to fix.
    """
    result = validate_environment()
    if result['ok']:
        logger.info("[EnvValidator] All required secrets are configured correctly.")
        return

    print("", file=sys.stderr)
    print("=" * 72, file=sys.stderr)
    print("  AERIS STARTUP BLOCKED — ENVIRONMENT CONFIGURATION ERROR", file=sys.stderr)
    print("=" * 72, file=sys.stderr)

    if result['missing']:
        print("\n  MISSING SECRETS (not set in environment):", file=sys.stderr)
        for name in result['missing']:
            print(f"    ✗  {name}", file=sys.stderr)

    if result['insecure']:
        print("\n  INSECURE VALUES (placeholder / default detected):", file=sys.stderr)
        for name in result['insecure']:
            print(f"    ✗  {name}", file=sys.stderr)

    print("\n  Set these values in your .env file or environment and restart.", file=sys.stderr)
    print("=" * 72, file=sys.stderr)
    print("", file=sys.stderr)

    sys.exit(1)


def get_validation_report() -> str:
    """
    Return a human-readable multi-line string describing the current
    environment validation status. Suitable for display in the Streamlit UI.
    """
    result = validate_environment()

    if result['ok']:
        return "✓ All required secrets are configured."

    lines = ["⚠ Environment Validation Issues Detected:"]

    if result['missing']:
        lines.append(f"  MISSING ({len(result['missing'])}): " + ", ".join(result['missing']))

    if result['insecure']:
        lines.append(
            f"  INVALID VALUES ({len(result['insecure'])}): " + ", ".join(result['insecure'])
        )

    lines.append("Update your .env file and restart AERIS.")
    return "\n".join(lines)
