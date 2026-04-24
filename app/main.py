"""
SecureAudit — FastAPI Application Entry Point
"""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router
from app.core.config import settings

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(f"🔒 {settings.app_name} v{settings.app_version} starting up")
    yield
    logger.info("SecureAudit shutting down")


app = FastAPI(
    title="SecureAudit",
    description=(
        "LLM-Based Cybersecurity Testing Automation. "
        "Automatically generates OWASP Top 10 test cases, executes them, "
        "and produces structured PDF reports with severity ratings."
    ),
    version=settings.app_version,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix="/api/v1")


@app.get("/")
async def root():
    return {
        "service": "SecureAudit",
        "version": settings.app_version,
        "docs": "/docs",
        "openapi": "/openapi.json",
    }
