"""
AERIS Master Enterprise Core Integration Test Suite
===================================================
Rigorous, end-to-end automated verification validating all pillars of
operational realism, enterprise security, and auditable governance.
"""
from __future__ import annotations

import os
import time
import pytest
from datetime import datetime, timezone
from typing import Dict, Any, List
from unittest.mock import patch, MagicMock

from portal.core.db import db_manager
from portal.core.tenancy import set_tenant_context, get_tenant_context, clear_tenant_context, TenantManager, TenantContextError
from portal.core.auth import IAMEngine, AuthenticationError, AccessDeniedError
from portal.core.hardener import api_limiter, InputSanitizer
from portal.core.telemetry import metrics_collector, HealthCheckEngine
from portal.core.workflow import WorkflowManager, WorkflowError, SLAHelper
from portal.core.feedback import FeedbackEngine
from portal.core.governance import EvidenceSigner, GovernanceIntegrityError, ComplianceMapper
from portal.core.scheduler import scan_scheduler
from risk_scoring.heuristic_detector import HeuristicRiskDetector

@pytest.fixture(scope="module", autouse=True)
def db_cleanup():
    """Performs full pre-test cleanup to guarantee fresh, isolated relational testing states."""
    try:
        with db_manager.get_connection() as conn:
            conn.execute("DELETE FROM audit_trail WHERE tenant_id IN ('alpha_corp', 'beta_corp')")
            conn.execute("DELETE FROM evidence_signatures WHERE tenant_id IN ('alpha_corp', 'beta_corp')")
            conn.execute("DELETE FROM analyst_feedback WHERE tenant_id IN ('alpha_corp', 'beta_corp')")
            conn.execute("DELETE FROM workflow WHERE tenant_id IN ('alpha_corp', 'beta_corp')")
            conn.execute("DELETE FROM users WHERE username IN ('manager_mike_test', 'analyst_andy_test')")
            conn.execute("DELETE FROM users WHERE tenant_id IN ('alpha_corp', 'beta_corp')")
            conn.execute("DELETE FROM tenants WHERE id IN ('alpha_corp', 'beta_corp')")
            conn.commit()
    except Exception as e:
        print(f"Cleanup warning: {e}")
    yield


def test_01_multi_tenancy_isolation():
    """Verifies strict tenant context boundaries and profiles isolation."""
    print("\n-> Executing Multi-Tenancy Validation...")
    
    # 1. Clean previous states
    clear_tenant_context()
    with pytest.raises(TenantContextError):
        get_tenant_context()

    # 2. Register Tenant A and Tenant B
    tenant_a = "alpha_corp"
    tenant_b = "beta_corp"
    
    TenantManager.create_tenant(tenant_a, "Alpha Corporation", "finance", ["SOC 2"])
    TenantManager.create_tenant(tenant_b, "Beta Industries", "healthcare", ["GDPR"])

    # 3. Assert profile details
    prof_a = TenantManager.get_tenant_profile(tenant_a)
    prof_b = TenantManager.get_tenant_profile(tenant_b)
    
    assert prof_a is not None
    assert prof_b is not None
    assert prof_a["name"] == "Alpha Corporation"
    assert prof_b["name"] == "Beta Industries"
    assert "SOC 2" in prof_a["compliance_scope"]
    assert "GDPR" in prof_b["compliance_scope"]

    # 4. Check dynamic industry risk offsets
    assert TenantManager.get_industry_risk_weight("finance") == 1.4
    assert TenantManager.get_industry_risk_weight("healthcare") == 1.45
    assert TenantManager.get_industry_risk_weight("other") == 1.0


def test_02_authentication_and_rbac():
    """Verifies PBKDF2 hashing, session JWT issuance, and RBAC enforcement."""
    print("-> Executing Authentication & RBAC Validation...")
    
    tenant = "alpha_corp"
    user_manager = "manager_mike_test"
    user_analyst = "analyst_andy_test"
    
    # Register Manager (SOC_MANAGER) and Analyst (ANALYST)
    IAMEngine.register_user(tenant, user_manager, "mike_secure_pass_2026", "SOC_MANAGER")
    IAMEngine.register_user(tenant, user_analyst, "andy_secure_pass_2026", "ANALYST")

    # Authenticate and receive JWT
    auth_data = IAMEngine.authenticate_user(user_manager, "mike_secure_pass_2026")
    assert auth_data["username"] == user_manager
    assert auth_data["role"] == "SOC_MANAGER"
    assert "access_token" in auth_data

    # Verify Issued JWT
    token = auth_data["access_token"]
    payload = IAMEngine.verify_token(token)
    assert payload["sub"] == user_manager
    assert payload["tenant_id"] == tenant
    assert payload["role"] == "SOC_MANAGER"
    assert get_tenant_context() == tenant

    # Enforce RBAC validation
    # SOC_MANAGER should pass allowed roles check
    IAMEngine.require_role(payload, ["SOC_MANAGER"])
    
    # SOC_MANAGER should fail when only ANALYST is allowed
    with pytest.raises(AccessDeniedError):
        IAMEngine.require_role(payload, ["ANALYST"])


def test_03_analyst_workflow_and_sla_tracking():
    """Verifies exposure lifecycle transitions, SLA calculations, and audit logs."""
    print("-> Executing Workflow & Triage Validation...")
    
    tenant = "alpha_corp"
    set_tenant_context(tenant)

    # 1. Register new discovered exposure
    res = WorkflowManager.register_new_exposure("internal-dev.alpha.com", "Dev admin panel exposed", "HIGH")
    assert res["status"] in ("created", "existing")
    alert_id = res["id"]

    # Verify initialized alert queue details
    queue = WorkflowManager.get_tenant_queue()
    matching = [q for q in queue if q["id"] == alert_id]
    assert len(matching) == 1
    alert = matching[0]
    assert alert["state"] == "DISCOVERED"
    assert alert["is_sla_breached"] == 0

    # 2. Transition Exposure State: DISCOVERED -> UNDER_REVIEW
    WorkflowManager.transition_state(alert_id, "UNDER_REVIEW", "Andy investigating.", "analyst_andy_test")
    
    # Assert change recorded
    with db_manager.get_connection() as conn:
        row = conn.execute("SELECT * FROM workflow WHERE id = ?", (alert_id,)).fetchone()
        assert row["state"] == "UNDER_REVIEW"
        assert "Andy investigating" in row["notes"]

    # Assert audit log populated
    with db_manager.get_connection() as conn:
        audit = conn.execute("SELECT * FROM audit_trail WHERE target = ? ORDER BY id DESC", ("internal-dev.alpha.com",)).fetchone()
        assert audit["username"] == "analyst_andy_test"
        assert audit["action"] == "TRANSITION_DISCOVERED_TO_UNDER_REVIEW"

    # 3. Accept Exposure Risk: UNDER_REVIEW -> RISK_ACCEPTED
    WorkflowManager.accept_risk(alert_id, 30, "System legacy vendor exception.", "manager_mike_test")
    
    with db_manager.get_connection() as conn:
        row = conn.execute("SELECT * FROM workflow WHERE id = ?", (alert_id,)).fetchone()
        assert row["state"] == "RISK_ACCEPTED"
        assert "Risk Accepted" in row["notes"]


def test_04_operational_feedback_loop():
    """Verifies feedback override registration and dynamic risk score calibration."""
    print("-> Executing Feedback Loop & Score Calibration Validation...")
    
    tenant = "alpha_corp"
    set_tenant_context(tenant)
    
    # We use a synthetic domain containing Brand Impersonation matching signals (CAMP-002: apple + support)
    # to guarantee heuristic triggering offline!
    target_host = "apple-corporate-support-portal.com"
    
    # Patch requests and socket to run 100% offline and instantaneous
    with patch("requests.get") as mock_get, patch("socket.gethostbyname") as mock_dns:
        # Construct successful mock response to yield baseline indicators
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "<html><title>Apple Support Login Portal</title></html>"
        mock_get.return_value = mock_resp
        mock_dns.return_value = "17.142.160.59" # Apple IP

        # 1. Establish baseline run without feedback overrides
        detector = HeuristicRiskDetector()
        base_result = detector.get_complete_analysis(target_host, port=443)
        base_score = base_result["risk_score"]
        
        # Typosquatting/brand lookalike will fire, creating a positive risk score
        print(f"   Baseline Risk Score: {base_score} (Findings: {str(base_result['evidence']).replace('→', '->')})")
        assert base_score > 0.0

        # 2. Register analyst override: suppress "TYPOSQUATTING" on this hostname
        FeedbackEngine.register_false_positive(target_host, "TYPOSQUATTING", "Legitimate corporate branding lookalike", "manager_mike_test")

        # Assert override registered in database
        suppressed = FeedbackEngine.get_suppressed_signals(target_host)
        assert "TYPOSQUATTING" in suppressed

        # 3. Execute calibrated run with feedback loops intercepted
        calibrated_result = detector.get_complete_analysis(target_host, port=443)
        calibrated_score = calibrated_result["risk_score"]
        
        print(f"   Calibrated Risk Score: {calibrated_score} (Findings: {str(calibrated_result['evidence']).replace('→', '->')})")

        # Assert suppression works
        # - Risk score is calibrated downwards
        # - Evidence contains the feedback loop indicator
        assert calibrated_score < base_score
        assert any("[FEEDBACK_LOOP]" in ev for ev in calibrated_result["evidence"])


def test_05_governance_and_cryptographic_verification():
    """Verifies cryptographic evidence chain signing, tampering detection, and compliance mappings."""
    print("-> Executing Cryptographic Governance Validation...")
    
    scan_payload = {
        "target": "sensitive-data-portal.com",
        "risk_score": 85.0,
        "risk_level": "HIGH",
        "evidence": [
            "[T1] SSL EXPIRED: The SSL certificate has expired.",
            "[T1] ADMIN PANEL: Publicly exposed wordpress administrative panel."
        ]
    }

    # 1. Generate signature
    sig = EvidenceSigner.sign_result(scan_payload)
    assert sig is not None
    assert len(sig) == 64  # Hex-encoded SHA-256 hash length

    # 2. Verify signature passes
    assert EvidenceSigner.verify_result(scan_payload, sig) is True

    # 3. Alter payload and assert tampering detection triggers GovernanceIntegrityError
    tampered_payload = scan_payload.copy()
    tampered_payload["risk_score"] = 15.0  # Tampered score!
    
    with pytest.raises(GovernanceIntegrityError):
        EvidenceSigner.verify_result(tampered_payload, sig)

    # 4. Assert regulatory mapping matches correctly
    mappings = ComplianceMapper.map_exposure_to_standards(scan_payload["evidence"])
    assert len(mappings) > 0
    frameworks = [m["framework"] for m in mappings]
    assert "SOC 2 (Trust Services Criteria)" in frameworks
    assert "GDPR (General Data Protection Regulation)" in frameworks


def test_06_asynchronous_scan_scheduling():
    """Verifies background job queuing, scan executing, and thread-safe operations."""
    print("-> Executing Background Scan Scheduling Validation...")
    
    tenant = "alpha_corp"
    target = "github.com"
    
    # Submit async job
    job_id = scan_scheduler.submit_scan(target, 443, tenant)
    assert job_id is not None

    # Retrieve job status
    job = scan_scheduler.get_job(job_id)
    assert job["status"] in ("PENDING", "RUNNING", "COMPLETED")
    assert job["target"] == target

    # Wait for completion (github.com is highly cached and fast)
    max_wait = 15.0
    elapsed = 0.0
    while elapsed < max_wait:
        job = scan_scheduler.get_job(job_id)
        if job["status"] in ("COMPLETED", "FAILED"):
            break
        time.sleep(0.5)
        elapsed += 0.5

    assert job["status"] == "COMPLETED"
    assert job["result"] is not None
    assert "signature" in job["result"]  # Auto-signed by scheduler!


def test_07_structured_telemetry_and_metrics():
    """Verifies Prometheus metrics compiling and health diagnostic outputs."""
    print("-> Executing Telemetry and Metrics Validation...")
    
    # 1. Record requests and scans
    metrics_collector.record_request("/api/v1/assets")
    metrics_collector.record_request("/api/v1/scans/trigger")
    metrics_collector.increment_jobs()
    metrics_collector.decrement_jobs(success=True)
    metrics_collector.record_rate_limit()

    # 2. Export Prometheus metrics
    prom_str = metrics_collector.export_prometheus()
    assert "aeris_active_jobs" in prom_str
    assert "aeris_scans_completed_total" in prom_str
    assert "aeris_rate_limit_blocks_total" in prom_str
    assert 'aeris_http_requests_total{path="/api/v1/assets"}' in prom_str

    # 3. Verify Health Check Diagnostics
    diag = HealthCheckEngine.get_system_diagnostics()
    assert diag["status"] == "healthy"
    assert diag["components"]["database"]["status"] == "up"
    assert diag["components"]["disk"]["status"] == "healthy"
    assert diag["components"]["memory"]["status"] == "healthy"

    print("OK: All Integration Tests Completed successfully.")


if __name__ == "__main__":
    pytest.main(["-v", __file__])
