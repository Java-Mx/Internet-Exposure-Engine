"""
AERIS Production API Gateway & Enterprise Web Portal
=====================================================
FastAPI gateway orchestrating multi-tenancy, JWT validation, Token Bucket throttling,
structured SIEM telemetry, analyst triage queues, and forensic compliance auditing.
"""
from __future__ import annotations

import logging
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, Depends, HTTPException, Header, status, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from portal.core.db import db_manager
from portal.core.tenancy import get_tenant_context, set_tenant_context, clear_tenant_context, TenantManager
from portal.core.auth import IAMEngine, AuthenticationError, AccessDeniedError
from portal.core.hardener import api_limiter, InputSanitizer, RateLimitExceeded
from portal.core.telemetry import metrics_collector, HealthCheckEngine, configure_siem_logging
from portal.core.workflow import WorkflowManager, WorkflowError
from portal.core.feedback import FeedbackEngine
from portal.core.governance import EvidenceSigner, GovernanceIntegrityError, ComplianceMapper
from portal.core.scheduler import scan_scheduler

# Initialize SIEM logger formatting
configure_siem_logging("INFO")
logger = logging.getLogger("exposure_discovery.portal.api")

app = FastAPI(
    title="AERIS Cyber Decision Intelligence API Gateway",
    version="2.0.0",
    description="Enterprise-grade exposures, ML prioritizations, and compliance forensics gateway."
)

# CORS Policy configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Restrict to configured origins in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Dependency Injectors ──────────────────────────────────────────────────────

async def rate_limit_dependency(request: Request):
    """Enforces rate-limits per client IP address using the Token Bucket system."""
    client_ip = request.client.host if request.client else "unknown-client"
    try:
        api_limiter.check_limit(client_ip)
    except RateLimitExceeded as e:
        metrics_collector.record_rate_limit()
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=str(e)
        )


async def jwt_auth_dependency(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    """
    Validates the bearer token, establishes tenant isolation context,
    and returns the authenticated user payload.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization bearer token is missing or malformed."
        )
    
    token = authorization.split(" ")[1]
    try:
        # verify_token automatically sets set_tenant_context
        payload = IAMEngine.verify_token(token)
        return payload
    except AuthenticationError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )


# ── Pydantic Request Models ───────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    tenant_id: str = Field(..., example="acme_corp")
    tenant_name: str = Field(..., example="ACME Corporation")
    industry: str = Field("other", example="finance")
    compliance_scope: List[str] = Field(default_factory=list, example=["PCI-DSS", "GDPR"])
    username: str = Field(..., example="analyst_jane")
    password: str = Field(..., min_length=8, example="secure_pass_992")
    role: str = Field(..., example="ANALYST")


class LoginRequest(BaseModel):
    username: str = Field(..., example="analyst_jane")
    password: str = Field(..., example="secure_pass_992")


class ScanRequest(BaseModel):
    target: str = Field(..., example="paypal-secure-login.com")
    port: int = Field(443, ge=1, le=65535, example=443)


class TriageRequest(BaseModel):
    alert_id: int = Field(..., example=1)
    new_state: str = Field(..., example="UNDER_REVIEW")
    notes: str = Field(..., example="Assigned to Jane for typosquat review.")


class RiskAcceptanceRequest(BaseModel):
    alert_id: int = Field(..., example=1)
    duration_days: int = Field(90, ge=1, le=365)
    notes: str = Field(..., example="Business accepted risk due to legacy vendor requirement.")


class FeedbackRequest(BaseModel):
    hostname: str = Field(..., example="paypal-secure-login.com")
    signal_id: str = Field(..., example="STRUCT-001")
    comments: str = Field(..., example="False positive, internal staging hostname.")


class VerifyRequest(BaseModel):
    payload: Dict[str, Any]
    signature: str


# ── API Endpoint Implementations ──────────────────────────────────────────────

@app.post("/api/v1/auth/register", dependencies=[Depends(rate_limit_dependency)])
async def register_endpoint(req: RegisterRequest):
    """Registers a corporate tenant and pre-seeds the initial administrative user."""
    try:
        # Clean inputs
        clean_tenant = InputSanitizer.sanitize_string(req.tenant_id, 30).lower()
        clean_user = InputSanitizer.sanitize_string(req.username, 30).lower()
        
        # 1. Provision Tenant
        if not TenantManager.get_tenant_profile(clean_tenant):
            TenantManager.create_tenant(clean_tenant, req.tenant_name, req.industry, req.compliance_scope)
            
        # 2. Provision User
        user = IAMEngine.register_user(clean_tenant, clean_user, req.password, req.role)
        return {"status": "success", "message": f"Tenant {clean_tenant} and user {clean_user} registered successfully."}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@app.post("/api/v1/auth/login", dependencies=[Depends(rate_limit_dependency)])
async def login_endpoint(req: LoginRequest):
    """Validates user credentials and returns a secure JWT bearer session token."""
    try:
        clean_user = InputSanitizer.sanitize_string(req.username, 30).lower()
        auth_data = IAMEngine.authenticate_user(clean_user, req.password)
        return auth_data
    except AuthenticationError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))


@app.post("/api/v1/scans/trigger", status_code=status.HTTP_202_ACCEPTED)
async def trigger_scan_endpoint(req: ScanRequest, user: Dict[str, Any] = Depends(jwt_auth_dependency)):
    """Triggers an asynchronous scan job. Protected by JWT. Returns Job ID."""
    metrics_collector.record_request("/api/v1/scans/trigger")
    try:
        # Enforce RBAC (Auditors cannot trigger active scans)
        IAMEngine.require_role(user, ["CISO", "SOC_MANAGER", "ANALYST"])
        
        clean_target = InputSanitizer.validate_hostname(req.target)
        tenant_id = get_tenant_context()

        # Submit background task
        job_id = scan_scheduler.submit_scan(clean_target, req.port, tenant_id)
        return {"job_id": job_id, "status": "PENDING", "target": clean_target}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@app.get("/api/v1/scans/status/{job_id}")
async def scan_status_endpoint(job_id: str, user: Dict[str, Any] = Depends(jwt_auth_dependency)):
    """Checks the status and retrieves completed results for a scan. Protected by JWT."""
    metrics_collector.record_request("/api/v1/scans/status")
    job = scan_scheduler.get_job(job_id)
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan job not found.")
    
    # Enforce tenant isolation
    if job["tenant_id"] != get_tenant_context():
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied. Workspace mismatch.")

    # Expose results
    return {
        "job_id": job["id"],
        "status": job["status"],
        "created_at": job["created_at"],
        "completed_at": job["completed_at"],
        "error": job["error"],
        "result": job["result"]
    }


@app.get("/api/v1/workflow/queue")
async def workflow_queue_endpoint(user: Dict[str, Any] = Depends(jwt_auth_dependency)):
    """Retrieves all active alerts in the tenant queue. Protected by JWT."""
    metrics_collector.record_request("/api/v1/workflow/queue")
    return WorkflowManager.get_tenant_queue()


@app.post("/api/v1/workflow/triage")
async def triage_endpoint(req: TriageRequest, user: Dict[str, Any] = Depends(jwt_auth_dependency)):
    """Updates an exposure's lifecycle state. Protected by JWT (Analysts, SOC Managers)."""
    metrics_collector.record_request("/api/v1/workflow/triage")
    try:
        # Enforce RBAC (CISO/Auditors cannot triage exposures)
        IAMEngine.require_role(user, ["SOC_MANAGER", "ANALYST"])
        
        clean_notes = InputSanitizer.sanitize_string(req.notes, 1000)
        WorkflowManager.transition_state(req.alert_id, req.new_state.upper(), clean_notes, user["sub"])
        return {"status": "success", "message": f"Exposure triaged to {req.new_state} successfully."}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@app.post("/api/v1/workflow/accept-risk")
async def accept_risk_endpoint(req: RiskAcceptanceRequest, user: Dict[str, Any] = Depends(jwt_auth_dependency)):
    """Approves risk acceptance for an exposure. Protected by JWT (SOC Managers only)."""
    metrics_collector.record_request("/api/v1/workflow/accept-risk")
    try:
        # Enforce strict RBAC (Only managers can accept security risk)
        IAMEngine.require_role(user, ["SOC_MANAGER"])
        
        clean_notes = InputSanitizer.sanitize_string(req.notes, 1000)
        WorkflowManager.accept_risk(req.alert_id, req.duration_days, clean_notes, user["sub"])
        return {"status": "success", "message": f"Risk accepted for {req.duration_days} days."}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@app.post("/api/v1/feedback/override")
async def feedback_override_endpoint(req: FeedbackRequest, user: Dict[str, Any] = Depends(jwt_auth_dependency)):
    """Registers an analyst override marking a signal as False Positive. Protected by JWT (SOC Manager)."""
    metrics_collector.record_request("/api/v1/feedback/override")
    try:
        # Enforce RBAC (Only Managers can overwrite heuristics scoring models)
        IAMEngine.require_role(user, ["SOC_MANAGER"])
        
        clean_host = InputSanitizer.validate_hostname(req.hostname)
        clean_sig = InputSanitizer.sanitize_string(req.signal_id, 30).upper()
        clean_comments = InputSanitizer.sanitize_string(req.comments, 1000)
        
        FeedbackEngine.register_false_positive(clean_host, clean_sig, clean_comments, user["sub"])
        return {"status": "success", "message": f"Signal {clean_sig} suppressed on {clean_host} on-the-fly."}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@app.post("/api/v1/governance/verify")
async def verify_signature_endpoint(req: VerifyRequest):
    """Verifies the cryptographic integrity of signed scan results. No Auth required (Open audit)."""
    try:
        is_valid = EvidenceSigner.verify_result(req.payload, req.signature)
        compliance_map = ComplianceMapper.map_exposure_to_standards(req.payload.get("evidence", []))
        return {
            "status": "verified",
            "integrity_check": is_valid,
            "hash": EvidenceSigner.calculate_scan_hash(req.payload),
            "compliance_mapping": compliance_map
        }
    except GovernanceIntegrityError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Verification failed: {e}")


@app.get("/metrics")
async def metrics_endpoint():
    """Returns dynamic system performance telemetry formatted for Prometheus scraping."""
    from fastapi.responses import PlainTextResponse
    prometheus_data = metrics_collector.export_prometheus()
    return PlainTextResponse(content=prometheus_data)


@app.get("/healthz")
async def health_endpoint():
    """Liveness and readiness checks validating database, storage limits, and system memories."""
    diag = HealthCheckEngine.get_system_diagnostics()
    if diag["status"] != "healthy":
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=diag)
    return diag
