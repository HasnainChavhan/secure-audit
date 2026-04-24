"""
SecureAudit — FastAPI Routes
"""
import logging
from fastapi import APIRouter, BackgroundTasks, HTTPException

from app.agent.audit_agent import AuditAgent
from app.agent.test_trajectory import TrajectoryEngine
from app.api.schemas import (
    AuditRequest,
    AuditResultResponse,
    AuditRunResponse,
    TestCaseRequest,
)

logger = logging.getLogger(__name__)
router = APIRouter()
agent = AuditAgent()
trajectory_engine = TrajectoryEngine()


@router.post("/audit/start", response_model=AuditRunResponse)
async def start_audit(request: AuditRequest, background_tasks: BackgroundTasks):
    """Start a new security audit run against the target URL."""
    try:
        plan = agent.generate_audit_plan(
            target_url=request.target_url,
            scope=[v.value for v in request.scope],
        )
        run_id = f"run-{hash(request.target_url) % 100000:05d}"
        logger.info(f"Audit started: {run_id} for {request.target_url}")
        return AuditRunResponse(
            run_id=run_id,
            status="running",
            target_url=request.target_url,
            scope=[v.value for v in request.scope],
            message=f"Audit queued — {len(request.scope)} vulnerability classes, {request.tests_per_class} tests each",
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/testcases/generate")
async def generate_test_cases(request: TestCaseRequest):
    """Generate targeted test cases for a specific vulnerability class."""
    test_cases = agent.generate_test_cases(
        vuln_class=request.vuln_class.value,
        endpoint=request.endpoint,
        method=request.method,
        auth_required=request.auth_required,
        count=request.count,
    )
    trajectories = trajectory_engine.build_from_test_cases(test_cases)
    return {
        "vuln_class": request.vuln_class.value,
        "endpoint": request.endpoint,
        "test_cases_generated": len(test_cases),
        "trajectories": [t.to_dict() for t in trajectories],
    }


@router.get("/audit/history")
async def get_audit_history():
    """Get recent audit run history."""
    return {"message": "Audit history requires Supabase connection", "runs": []}


@router.get("/health")
async def health():
    return {"status": "healthy", "service": "SecureAudit"}
