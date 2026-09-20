"""Pydantic v2 schemas for Credit Risk Scoring API."""
from typing import List, Dict
from pydantic import BaseModel, Field


class LoanApplication(BaseModel):
    """Input features for a single loan application."""
    age: int = Field(..., ge=18, le=100, example=35)
    income: float = Field(..., gt=0, example=75000.0)
    employment_years: float = Field(..., ge=0, example=5.0)
    loan_amount: float = Field(..., gt=0, example=25000.0)
    loan_purpose: str = Field(..., example="debt_consolidation")
    credit_score: int = Field(..., ge=300, le=850, example=680)
    debt_to_income_ratio: float = Field(..., ge=0, example=0.35)
    num_credit_lines: int = Field(..., ge=0, example=8)
    num_late_payments: int = Field(..., ge=0, example=1)
    home_ownership: str = Field(..., example="RENT")
    loan_term: int = Field(..., example=36)

    model_config = {"json_schema_extra": {"example": {
        "age": 35, "income": 75000, "employment_years": 5.0,
        "loan_amount": 25000, "loan_purpose": "debt_consolidation",
        "credit_score": 680, "debt_to_income_ratio": 0.35,
        "num_credit_lines": 8, "num_late_payments": 1,
        "home_ownership": "RENT", "loan_term": 36,
    }}}


class PredictionResponse(BaseModel):
    application_id: str
    default_probability: float = Field(..., ge=0, le=1)
    risk_level: str = Field(..., description="LOW, MEDIUM, or HIGH")
    recommendation: str = Field(..., description="APPROVE or REJECT")
    processing_time_ms: float = 0.0


class BatchRequest(BaseModel):
    applications: List[LoanApplication] = Field(..., min_length=1, max_length=500)


class BatchResponse(BaseModel):
    predictions: List[PredictionResponse]
    total: int
    approved: int
    rejected: int
    processing_time_ms: float


class HealthResponse(BaseModel):
    status: str
    model_loaded: bool
    version: str


class MetricsResponse(BaseModel):
    model_name: str
    version: str
    metrics: Dict[str, float]
    training_samples: int
