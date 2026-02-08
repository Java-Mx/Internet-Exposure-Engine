"""
REST API for Internet Exposure Risk Scoring System.
"""

from typing import Dict, List, Any, Optional
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel
from pathlib import Path
import uvicorn

from api.pipeline_orchestrator import PipelineOrchestrator
from config.logging_config import get_logger

logger = get_logger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Internet Exposure Risk Scoring API",
    description="ML-powered risk assessment for internet-exposed assets",
    version="1.0.0"
)

# Initialize orchestrator
orchestrator = PipelineOrchestrator()


# Pydantic models for request/response
class AssetInput(BaseModel):
    ip: Optional[str] = None
    domain: Optional[str] = None
    port: Optional[int] = None
    service: Optional[str] = None
    banner: Optional[str] = None
    country: Optional[str] = None
    asn: Optional[int] = None


class ScanRequest(BaseModel):
    assets: List[AssetInput]
    include_breaches: bool = False
    include_github: bool = False


class RiskResponse(BaseModel):
    risk_score: float
    severity: str
    confidence: Optional[float] = None


# API Endpoints

@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "message": "Internet Exposure Risk Scoring API",
        "version": "1.0.0",
        "status": "operational"
    }


@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "models_loaded": orchestrator.signal_integrator.models_loaded
    }


@app.post("/api/scan")
async def scan_assets(request: ScanRequest, background_tasks: BackgroundTasks):
    """
    Scan and assess risk for multiple assets.
    """
    try:
        logger.info(f"Received scan request for {len(request.assets)} assets")
        
        # Convert Pydantic models to dicts
        assets = [asset.dict() for asset in request.assets]
        
        # Run pipeline
        results = orchestrator.run_full_pipeline(assets)
        
        return JSONResponse(content=results)
        
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/assess")
async def assess_single_asset(asset: AssetInput):
    """
    Assess risk for a single asset.
    """
    try:
        asset_dict = asset.dict()
        result = orchestrator.process_single_asset(asset_dict)
        
        return JSONResponse(content=result)
        
    except Exception as e:
        logger.error(f"Assessment failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/reports")
async def list_reports():
    """
    List available reports.
    """
    try:
        reports_dir = Path("reports")
        if not reports_dir.exists():
            return {"reports": []}
        
        reports = []
        for file in reports_dir.glob("*.json"):
            reports.append({
                "filename": file.name,
                "path": str(file),
                "size": file.stat().st_size,
                "created": file.stat().st_ctime
            })
        
        return {"reports": reports}
        
    except Exception as e:
        logger.error(f"Failed to list reports: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/reports/{filename}")
async def get_report(filename: str):
    """
    Download a specific report.
    """
    try:
        file_path = Path("reports") / filename
        
        if not file_path.exists():
            raise HTTPException(status_code=404, detail="Report not found")
        
        return FileResponse(file_path)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to retrieve report: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/stats")
async def get_statistics():
    """
    Get system statistics.
    """
    try:
        # Get graph statistics if available
        graph_stats = orchestrator.graph_builder.get_graph_statistics()
        
        return {
            "graph_statistics": graph_stats,
            "models_loaded": orchestrator.signal_integrator.models_loaded
        }
        
    except Exception as e:
        logger.error(f"Failed to get statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


def start_api(host: str = "0.0.0.0", port: int = 8000):
    """
    Start the API server.
    
    Args:
        host: Host address
        port: Port number
    """
    logger.info(f"Starting API server on {host}:{port}")
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    start_api()
