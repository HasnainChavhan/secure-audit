"""
SecureAudit — Pydantic API Schemas
"""
from pydantic import BaseModel, HttpUrl
from typing import Optional
from enum import Enum


class VulnClass(str, Enum):
    SQLI = "sqli"
    XSS = "xss"
    CSRF = "csrf"
    IDOR = "idor"
    AUTH_BYPASS = "auth_bypass"
    PATH_TRAVERSAL = "path_traversal"
    SSRF = "ssrf"
    XXE = "xxe"
    RCE = "rce"
    SECURITY_MISCONFIGURATION = "security_misconfiguration"


class AuditRequest(BaseModel):
    target_url: str
    scope: list[VulnClass]
    operator: str = "anonymous"
    tests_per_class: int = 5

    model_config = {"json_schema_extra": {
        "example": {
            "target_url": "http://localhost:8080",
            "scope": ["sqli", "xss", "auth_bypass"],
            "operator": "security-team",
            "tests_per_class": 5
        }
    }}


class TestCaseRequest(BaseModel):
    vuln_class: VulnClass
    endpoint: str
    method: str = "POST"
    auth_required: bool = True
    count: int = 5


class AuditRunResponse(BaseModel):
    run_id: str
    status: str
    target_url: str
    scope: list[str]
    message: str


class AuditResultResponse(BaseModel):
    run_id: str
    status: str
    total_tests: int
    vulnerabilities_found: int
    breakdown: dict
    report_path: Optional[str] = None
