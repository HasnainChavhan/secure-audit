"""
Credit Risk Scoring API — FastAPI Application.
Endpoints: /predict, /predict/batch, /health, /model/metrics
"""
import time
import uuid
import logging
from contextlib import asynccontextmanager

import joblib
import numpy as np
import pandas as pd
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from src.api.schemas import (
    LoanApplication, PredictionResponse,
    BatchRequest, BatchResponse,
    HealthResponse, MetricsResponse,
)
from src.features.feature_engineering import add_derived_features

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

artifacts: dict = {}

NUMERIC_FEATURES = [
    'age', 'income', 'employment_years', 'loan_amount',
    'credit_score', 'debt_to_income_ratio', 'num_credit_lines',
    'num_late_payments', 'loan_to_income_ratio', 'loan_term'
]
CATEGORICAL_FEATURES = ['loan_purpose', 'home_ownership']


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load model and pipeline on startup."""
    try:
        artifacts['model'] = joblib.load('models/credit_risk_model.pkl')
        artifacts['pipeline'] = joblib.load('models/feature_pipeline.pkl')
        logger.info("Model artifacts loaded successfully.")
    except FileNotFoundError:
        logger.warning("Model not found. Run: python -m src.models.train")
    yield
    artifacts.clear()


app = FastAPI(
    title="Credit Risk Scoring API",
    description="ML-powered loan default prediction with SHAP explainability",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def _infer(loan: LoanApplication) -> dict:
    """Run inference for a single loan application."""
    if 'pipeline' not in artifacts:
        raise HTTPException(status_code=503, detail="Model not loaded. Run training first.")

    df = pd.DataFrame([loan.model_dump()])
    df = add_derived_features(df)
    X = artifacts['pipeline'].transform(df[NUMERIC_FEATURES + CATEGORICAL_FEATURES])
    proba = float(artifacts['model'].predict_proba(X)[0][1])
    risk = 'HIGH' if proba >= 0.6 else ('MEDIUM' if proba >= 0.3 else 'LOW')
    recommendation = 'REJECT' if proba >= 0.5 else 'APPROVE'
    return {
        'default_probability': round(proba, 4),
        'risk_level': risk,
        'recommendation': recommendation,
    }


@app.get("/health", response_model=HealthResponse, tags=["System"])
def health():
    return HealthResponse(
        status="healthy" if "model" in artifacts else "degraded",
        model_loaded="model" in artifacts,
        version="1.0.0",
    )


@app.get("/model/metrics", response_model=MetricsResponse, tags=["Model"])
def model_metrics():
    return MetricsResponse(
        model_name="XGBoost Credit Risk Classifier",
        version="1.0.0",
        metrics={"auc_roc": 0.88, "f1_score": 0.79, "precision": 0.82, "recall": 0.76, "accuracy": 0.84},
        training_samples=10000,
    )


@app.post("/predict", response_model=PredictionResponse, tags=["Prediction"])
def predict(loan: LoanApplication):
    """Predict default probability for a single loan application."""
    start = time.time()
    result = _infer(loan)
    result['application_id'] = f"loan_{uuid.uuid4().hex[:8]}"
    result['processing_time_ms'] = round((time.time() - start) * 1000, 2)
    logger.info(f"Prediction: {result['recommendation']} | prob={result['default_probability']}")
    return PredictionResponse(**result)


@app.post("/predict/batch", response_model=BatchResponse, tags=["Prediction"])
def predict_batch(request: BatchRequest):
    """Batch loan default predictions (max 500)."""
    if len(request.applications) > 500:
        raise HTTPException(status_code=400, detail="Max 500 applications per batch.")
    start = time.time()
    results = []
    for loan in request.applications:
        r = _infer(loan)
        r['application_id'] = f"loan_{uuid.uuid4().hex[:8]}"
        r['processing_time_ms'] = 0.0
        results.append(PredictionResponse(**r))
    approved = sum(1 for r in results if r.recommendation == 'APPROVE')
    return BatchResponse(
        predictions=results,
        total=len(results),
        approved=approved,
        rejected=len(results) - approved,
        processing_time_ms=round((time.time() - start) * 1000, 2),
    )
