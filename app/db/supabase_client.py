"""
SecureAudit — Supabase Audit Trail Client
Real-time storage with full traceability for every test run.
"""
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from supabase import create_client, Client
from app.core.config import settings

logger = logging.getLogger(__name__)


def get_supabase_client() -> Client:
    """Initialise authenticated Supabase client."""
    return create_client(settings.supabase_url, settings.supabase_key)


class AuditTrailRepository:
    """
    Manages audit trail persistence in Supabase.

    Every audit run, test case, step execution, and finding is stored
    with full traceability — enabling reproducible, consistent audits.
    """

    def __init__(self):
        self.client: Client = get_supabase_client()

    # ─── Audit Runs ─────────────────────────────────────────────────────────

    def create_audit_run(self, target_url: str, scope: list[str], operator: str) -> str:
        """Create a new audit run record and return its ID."""
        run_id = str(uuid.uuid4())
        data = {
            "id": run_id,
            "target_url": target_url,
            "scope": scope,
            "operator": operator,
            "status": "running",
            "started_at": datetime.now(timezone.utc).isoformat(),
        }
        self.client.table("audit_runs").insert(data).execute()
        logger.info(f"Audit run created: {run_id} for {target_url}")
        return run_id

    def complete_audit_run(
        self,
        run_id: str,
        status: str,
        total_tests: int,
        vulnerabilities_found: int,
        report_path: Optional[str] = None,
    ):
        """Mark an audit run as completed with summary statistics."""
        self.client.table("audit_runs").update({
            "status": status,
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "total_tests": total_tests,
            "vulnerabilities_found": vulnerabilities_found,
            "report_path": report_path,
        }).eq("id", run_id).execute()

    # ─── Test Results ────────────────────────────────────────────────────────

    def log_test_result(
        self,
        run_id: str,
        trajectory_id: str,
        vulnerability_class: str,
        severity: str,
        goal: str,
        status: str,
        steps_passed: int,
        steps_failed: int,
        vulnerability_confirmed: bool,
        evidence: str,
        remediation: str,
    ) -> str:
        """Log a completed test trajectory result."""
        result_id = str(uuid.uuid4())
        self.client.table("test_results").insert({
            "id": result_id,
            "audit_run_id": run_id,
            "trajectory_id": trajectory_id,
            "vulnerability_class": vulnerability_class,
            "severity": severity,
            "goal": goal,
            "status": status,
            "steps_passed": steps_passed,
            "steps_failed": steps_failed,
            "vulnerability_confirmed": vulnerability_confirmed,
            "evidence": evidence,
            "remediation": remediation,
            "logged_at": datetime.now(timezone.utc).isoformat(),
        }).execute()
        return result_id

    def log_step_execution(
        self,
        result_id: str,
        step_number: int,
        action: str,
        input_data: str,
        expected: str,
        actual: str,
        status: str,
        execution_time_ms: float,
        error_message: Optional[str] = None,
    ):
        """Log individual step execution for full traceability."""
        self.client.table("step_executions").insert({
            "test_result_id": result_id,
            "step_number": step_number,
            "action": action,
            "input_data": input_data,
            "expected": expected,
            "actual": actual,
            "status": status,
            "execution_time_ms": execution_time_ms,
            "error_message": error_message,
            "executed_at": datetime.now(timezone.utc).isoformat(),
        }).execute()

    # ─── Queries ──────────────────────────────────────────────────────────────

    def get_audit_run(self, run_id: str) -> Optional[dict]:
        """Retrieve a specific audit run by ID."""
        response = self.client.table("audit_runs").select("*").eq("id", run_id).execute()
        return response.data[0] if response.data else None

    def get_audit_history(self, limit: int = 20) -> list[dict]:
        """Get recent audit runs ordered by start time."""
        response = (
            self.client.table("audit_runs")
            .select("*")
            .order("started_at", desc=True)
            .limit(limit)
            .execute()
        )
        return response.data

    def get_vulnerabilities_by_severity(self, run_id: str) -> dict:
        """Aggregate confirmed vulnerabilities by severity for a run."""
        response = (
            self.client.table("test_results")
            .select("severity, vulnerability_class")
            .eq("audit_run_id", run_id)
            .eq("vulnerability_confirmed", True)
            .execute()
        )

        breakdown = {"Critical": [], "High": [], "Medium": [], "Low": []}
        for row in response.data:
            severity = row.get("severity", "Low")
            if severity in breakdown:
                breakdown[severity].append(row["vulnerability_class"])

        return breakdown
