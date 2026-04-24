"""
SecureAudit — Structured LLM Prompts for OWASP Top 10 Vulnerability Classes
"""

SYSTEM_PROMPT = """You are an expert cybersecurity engineer specialising in web application penetration testing.
Your role is to generate precise, targeted test cases for OWASP Top 10 vulnerability classes.
Each test case must be atomic, executable, and include exact payloads.
Output ONLY valid JSON — no explanation, no markdown fences."""

OWASP_CLASS_DESCRIPTIONS = {
    "sqli": "SQL Injection — attacker injects malicious SQL via user input fields",
    "xss": "Cross-Site Scripting — injecting client-side scripts into web pages",
    "csrf": "Cross-Site Request Forgery — forging authenticated requests",
    "idor": "Insecure Direct Object Reference — accessing unauthorised resources by manipulating IDs",
    "auth_bypass": "Broken Authentication — bypassing login or session controls",
    "path_traversal": "Path Traversal — navigating directory structure to access forbidden files",
    "ssrf": "Server-Side Request Forgery — inducing server to make unintended requests",
    "xxe": "XML External Entity — exploiting XML parsers to disclose files or perform SSRF",
    "rce": "Remote Code Execution — achieving arbitrary code execution on the server",
    "security_misconfiguration": "Security Misconfiguration — exploiting default credentials, open debug endpoints",
}

TEST_CASE_GENERATION_PROMPT = """Generate {count} test cases for the vulnerability class: {vuln_class}.

Description: {vuln_description}

Target endpoint: {endpoint}
HTTP method: {method}
Authentication required: {auth_required}

Return a JSON array with this exact structure:
[
  {{
    "id": "TC-{vuln_class}-001",
    "name": "Descriptive test case name",
    "vulnerability_class": "{vuln_class}",
    "severity": "Critical|High|Medium|Low",
    "description": "What this test case checks",
    "preconditions": ["list of preconditions"],
    "steps": [
      {{
        "step_number": 1,
        "action": "HTTP_REQUEST|BROWSER_ACTION|ASSERTION",
        "input": "exact payload or input value",
        "expected": "expected server response or behaviour",
        "assertion": "how to verify the test passed or failed"
      }}
    ],
    "remediation": "Specific remediation recommendation",
    "references": ["OWASP link or CVE"]
  }}
]"""

SEVERITY_CLASSIFICATION_PROMPT = """Analyse the following security test result and classify its severity.

Test Case: {test_case_name}
Vulnerability Class: {vuln_class}
Payload Used: {payload}
Server Response: {response}
Status Code: {status_code}
Response Time: {response_time}ms

Classify severity as one of: Critical, High, Medium, Low, Informational.

Return JSON:
{{
  "severity": "Critical|High|Medium|Low|Informational",
  "cvss_score": 0.0,
  "confidence": "High|Medium|Low",
  "evidence": "What in the response confirms this vulnerability",
  "false_positive_likelihood": "High|Medium|Low",
  "remediation_priority": "Immediate|High|Medium|Low"
}}"""
