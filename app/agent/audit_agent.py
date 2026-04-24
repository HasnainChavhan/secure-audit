"""
SecureAudit — LLM-Based Audit Agent
Generates targeted test cases for OWASP Top 10 vulnerability classes
using structured prompting with OpenAI GPT-4o.
"""
import json
import time
import logging
from typing import Optional
from openai import OpenAI

from app.core.config import settings
from app.agent.prompts import (
    SYSTEM_PROMPT,
    OWASP_CLASS_DESCRIPTIONS,
    TEST_CASE_GENERATION_PROMPT,
    SEVERITY_CLASSIFICATION_PROMPT,
)

logger = logging.getLogger(__name__)


class AuditAgent:
    """
    AI-powered audit agent that generates and classifies security test cases.

    Uses structured LLM prompting with few-shot examples to produce:
    - Targeted test cases for OWASP Top 10 vulnerability classes
    - Atomic test steps with exact payloads
    - Severity classification of discovered vulnerabilities
    """

    def __init__(self):
        self.client = OpenAI(api_key=settings.openai_api_key)
        self.model = settings.openai_model
        self._few_shot_cache: dict = {}

    def generate_test_cases(
        self,
        vuln_class: str,
        endpoint: str,
        method: str = "POST",
        auth_required: bool = True,
        count: int = 5,
    ) -> list[dict]:
        """
        Generate targeted test cases for a specific vulnerability class.

        Args:
            vuln_class: OWASP vulnerability class (e.g., 'sqli', 'xss')
            endpoint: Target API endpoint path
            method: HTTP method (GET, POST, PUT, DELETE)
            auth_required: Whether endpoint requires authentication
            count: Number of test cases to generate

        Returns:
            List of test case dictionaries with steps and assertions
        """
        vuln_description = OWASP_CLASS_DESCRIPTIONS.get(
            vuln_class, f"Unknown vulnerability class: {vuln_class}"
        )

        prompt = TEST_CASE_GENERATION_PROMPT.format(
            count=count,
            vuln_class=vuln_class.upper(),
            vuln_description=vuln_description,
            endpoint=endpoint,
            method=method,
            auth_required=auth_required,
        )

        logger.info(f"Generating {count} test cases for {vuln_class} on {endpoint}")

        for attempt in range(settings.max_retries):
            try:
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": prompt},
                    ],
                    temperature=0.2,
                    response_format={"type": "json_object"},
                )

                content = response.choices[0].message.content
                parsed = json.loads(content)

                # Handle both array and wrapped object responses
                if isinstance(parsed, list):
                    test_cases = parsed
                elif "test_cases" in parsed:
                    test_cases = parsed["test_cases"]
                else:
                    test_cases = list(parsed.values())[0]

                logger.info(f"Generated {len(test_cases)} test cases successfully")
                return test_cases

            except json.JSONDecodeError as e:
                logger.warning(f"JSON parse error on attempt {attempt + 1}: {e}")
                if attempt < settings.max_retries - 1:
                    time.sleep(settings.retry_delay * (2**attempt))
            except Exception as e:
                logger.error(f"OpenAI API error on attempt {attempt + 1}: {e}")
                if attempt < settings.max_retries - 1:
                    time.sleep(settings.retry_delay * (2**attempt))

        logger.error(f"Failed to generate test cases after {settings.max_retries} attempts")
        return []

    def classify_severity(
        self,
        test_case_name: str,
        vuln_class: str,
        payload: str,
        response: str,
        status_code: int,
        response_time: float,
    ) -> dict:
        """
        Classify the severity of a discovered vulnerability using LLM analysis.

        Returns severity classification with CVSS score and remediation priority.
        """
        prompt = SEVERITY_CLASSIFICATION_PROMPT.format(
            test_case_name=test_case_name,
            vuln_class=vuln_class,
            payload=payload[:500],  # Truncate large payloads
            response=response[:1000],
            status_code=status_code,
            response_time=response_time,
        )

        try:
            response_obj = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.1,
                response_format={"type": "json_object"},
            )

            return json.loads(response_obj.choices[0].message.content)

        except Exception as e:
            logger.error(f"Severity classification failed: {e}")
            return {
                "severity": "Unknown",
                "cvss_score": 0.0,
                "confidence": "Low",
                "evidence": "Classification failed",
                "false_positive_likelihood": "High",
                "remediation_priority": "Low",
            }

    def generate_audit_plan(self, target_url: str, scope: list[str]) -> dict:
        """
        Generate a full audit plan decomposed into test trajectories.

        Args:
            target_url: Base URL of the application under audit
            scope: List of OWASP vulnerability classes to test

        Returns:
            Structured audit plan with test trajectories per vulnerability class
        """
        plan = {
            "target_url": target_url,
            "scope": scope,
            "total_vulnerability_classes": len(scope),
            "trajectories": [],
            "estimated_test_count": 0,
        }

        for vuln_class in scope:
            trajectory = {
                "vulnerability_class": vuln_class,
                "description": OWASP_CLASS_DESCRIPTIONS.get(vuln_class, vuln_class),
                "status": "pending",
                "test_cases": [],
            }
            plan["trajectories"].append(trajectory)

        logger.info(f"Audit plan created for {target_url} with {len(scope)} vulnerability classes")
        return plan
