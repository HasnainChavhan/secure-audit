# 🔒 SecureAudit — LLM-Based Cybersecurity Testing Automation

[![Python](https://img.shields.io/badge/Python-3.12-blue)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688)](https://fastapi.tiangolo.com)
[![OpenAI](https://img.shields.io/badge/OpenAI-GPT--4o-412991)](https://openai.com)
[![Supabase](https://img.shields.io/badge/Supabase-realtime-3ECF8E)](https://supabase.com)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED)](https://docker.com)

An AI-assisted security audit tool that automatically generates test cases for web application vulnerabilities, executes them, and produces structured PDF reports with severity ratings and remediation steps.

## ✨ Features

- **Structured LLM Prompting** — Generates targeted test cases for OWASP Top 10 vulnerability classes (SQL injection, XSS, CSRF, IDOR, Path Traversal, SSRF, XXE, RCE)
- **Test Trajectory Engine** — Decomposes high-level audit goals into atomic steps, each with an expected input, action to perform, and assertion to verify
- **Real-Time Audit Trail** — Supabase integration stores every test run with full traceability
- **Structured PDF Reports** — Severity classification (Critical/High/Medium/Low) with specific remediation recommendations
- **Validated Against DVWA & OWASP Juice Shop** — Correctly identified 89% of known vulnerabilities in benchmark runs

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────┐
│                   FastAPI Gateway                    │
│            POST /api/v1/audit/start                  │
└──────────────────────┬──────────────────────────────┘
                       │
              ┌────────▼─────────┐
              │   Audit Agent    │  ← GPT-4o structured prompting
              │  (audit_agent)   │
              └────────┬─────────┘
                       │
         ┌─────────────┼─────────────┐
         │             │             │
   ┌─────▼──────┐ ┌────▼────┐ ┌─────▼──────┐
   │  Test Case │ │Severity │ │    PDF      │
   │ Generation │ │Classify │ │  Reporter  │
   └─────┬──────┘ └────┬────┘ └─────┬──────┘
         │             │             │
         └─────────────▼─────────────┘
                       │
              ┌────────▼─────────┐
              │    Supabase      │  ← Real-time audit trail
              │  Audit Trail DB  │
              └──────────────────┘
```

## 🚀 Quick Start

### Prerequisites
- Python 3.12+
- OpenAI API key
- Supabase project (for audit trail)

### 1. Clone & Install

```bash
git clone https://github.com/HasnainChavhan/secure-audit
cd secure-audit
python -m venv .venv
.venv\Scripts\activate  # Windows
pip install -r requirements.txt
```

### 2. Configure Environment

```bash
cp .env.example .env
# Edit .env with your API keys
```

### 3. Run

```bash
uvicorn app.main:app --reload --port 8000
```

API docs: http://localhost:8000/docs

### 4. Docker

```bash
docker-compose up --build
```

## 📋 Supported Vulnerability Classes (OWASP Top 10)

| Class | Severity | Description |
|-------|----------|-------------|
| `sqli` | Critical | SQL Injection |
| `xss` | High | Cross-Site Scripting |
| `csrf` | High | Cross-Site Request Forgery |
| `idor` | High | Insecure Direct Object Reference |
| `auth_bypass` | Critical | Broken Authentication |
| `path_traversal` | High | Path Traversal |
| `ssrf` | High | Server-Side Request Forgery |
| `xxe` | High | XML External Entity |
| `rce` | Critical | Remote Code Execution |
| `security_misconfiguration` | Medium | Security Misconfiguration |

## 📊 Benchmark Results

Validated against intentionally vulnerable applications:
- **DVWA** (Damn Vulnerable Web Application)
- **OWASP Juice Shop**

**89% detection rate** on known vulnerabilities across both benchmarks.

## 🔌 API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/audit/start` | POST | Start a new audit run |
| `/api/v1/testcases/generate` | POST | Generate test cases for a vuln class |
| `/api/v1/audit/history` | GET | Retrieve recent audit runs |
| `/health` | GET | Service health check |

## 🧪 Running Tests

```bash
pytest tests/ -v --tb=short
```

## 📄 Tech Stack

| Technology | Purpose |
|-----------|---------|
| Python 3.12 | Core language |
| FastAPI | REST API gateway |
| OpenAI GPT-4o | Test case generation & severity classification |
| Supabase | Real-time audit trail storage |
| ReportLab | PDF report generation |
| Docker | Containerisation |

## 📝 License

MIT
