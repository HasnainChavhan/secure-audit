"""
SecureAudit — Test Suite: Audit Agent
"""
import pytest
from unittest.mock import MagicMock, patch
from app.agent.audit_agent import AuditAgent
from app.agent.test_trajectory import TrajectoryEngine, ActionType, StepStatus


class TestAuditAgent:

    @patch("app.agent.audit_agent.OpenAI")
    def test_generate_test_cases_success(self, mock_openai):
        """Test successful test case generation from LLM."""
        mock_response = MagicMock()
        mock_response.choices[0].message.content = '''[
            {
                "id": "TC-SQLI-001",
                "name": "Basic SQL Injection via login form",
                "vulnerability_class": "sqli",
                "severity": "Critical",
                "description": "Test SQL injection in username parameter",
                "preconditions": ["App is running"],
                "steps": [
                    {
                        "step_number": 1,
                        "action": "HTTP_REQUEST",
                        "input": "' OR 1=1 --",
                        "expected": "Login should fail or return 400",
                        "assertion": "Status code must not be 200 with auth token"
                    }
                ],
                "remediation": "Use parameterised queries",
                "references": ["https://owasp.org/www-community/attacks/SQL_Injection"]
            }
        ]'''
        mock_openai.return_value.chat.completions.create.return_value = mock_response

        agent = AuditAgent()
        test_cases = agent.generate_test_cases("sqli", "/api/login")

        assert len(test_cases) == 1
        assert test_cases[0]["vulnerability_class"] == "sqli"
        assert test_cases[0]["severity"] == "Critical"

    @patch("app.agent.audit_agent.OpenAI")
    def test_generate_test_cases_retries_on_json_error(self, mock_openai):
        """Test retry logic when LLM returns invalid JSON."""
        mock_response_bad = MagicMock()
        mock_response_bad.choices[0].message.content = "This is not JSON"

        mock_response_good = MagicMock()
        mock_response_good.choices[0].message.content = '[]'

        mock_openai.return_value.chat.completions.create.side_effect = [
            mock_response_bad,
            mock_response_good,
        ]

        agent = AuditAgent()
        result = agent.generate_test_cases("xss", "/api/comment")
        assert result == []

    def test_generate_audit_plan_structure(self):
        """Test audit plan has correct structure."""
        with patch("app.agent.audit_agent.OpenAI"):
            agent = AuditAgent()
            plan = agent.generate_audit_plan(
                "http://localhost:8080",
                ["sqli", "xss", "auth_bypass"]
            )

        assert plan["target_url"] == "http://localhost:8080"
        assert len(plan["trajectories"]) == 3
        assert plan["total_vulnerability_classes"] == 3
        assert all(t["status"] == "pending" for t in plan["trajectories"])


class TestTrajectoryEngine:

    def test_build_sqli_trajectory(self):
        engine = TrajectoryEngine()
        trajectory = engine.build_sqli_trajectory("/api/login", "username")

        assert trajectory.vulnerability_class == "sqli"
        assert trajectory.severity == "Critical"
        assert len(trajectory.steps) >= 3
        assert trajectory.steps[0].action == ActionType.SETUP
        assert trajectory.steps[1].action == ActionType.HTTP_REQUEST

    def test_build_xss_trajectory(self):
        engine = TrajectoryEngine()
        trajectory = engine.build_xss_trajectory("/api/comments", "content")

        assert trajectory.vulnerability_class == "xss"
        assert len(trajectory.steps) >= 3

    def test_step_result_tracking(self):
        engine = TrajectoryEngine()
        trajectory = engine.build_sqli_trajectory("/api/login", "username")

        trajectory.mark_step_result(1, StepStatus.PASSED, "Baseline OK", 45.0)
        trajectory.mark_step_result(2, StepStatus.FAILED, "SQL error found in response", 120.0)

        assert trajectory.passed_steps == 1
        assert trajectory.failed_steps == 1

    def test_build_from_test_cases(self):
        engine = TrajectoryEngine()
        test_cases = [
            {
                "name": "XSS in search",
                "vulnerability_class": "xss",
                "severity": "High",
                "preconditions": [],
                "remediation": "Sanitise input",
                "steps": [
                    {
                        "action": "HTTP_REQUEST",
                        "input": "<script>alert(1)</script>",
                        "expected": "Script rejected",
                        "assertion": "No script in response",
                    }
                ]
            }
        ]
        trajectories = engine.build_from_test_cases(test_cases)
        assert len(trajectories) == 1
        assert trajectories[0].vulnerability_class == "xss"
        assert len(trajectories[0].steps) == 1
