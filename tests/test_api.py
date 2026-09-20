"""pytest tests for Credit Risk Scoring API."""
import pytest
from unittest.mock import patch, MagicMock
import numpy as np
from fastapi.testclient import TestClient

VALID_APP = {
    "age": 35, "income": 75000.0, "employment_years": 5.0,
    "loan_amount": 25000.0, "loan_purpose": "debt_consolidation",
    "credit_score": 680, "debt_to_income_ratio": 0.35,
    "num_credit_lines": 8, "num_late_payments": 1,
    "home_ownership": "RENT", "loan_term": 36,
}


@pytest.fixture
def client():
    mock_model = MagicMock()
    mock_model.predict_proba.return_value = np.array([[0.75, 0.25]])
    mock_pipeline = MagicMock()
    mock_pipeline.transform.return_value = np.zeros((1, 20))
    with patch.dict("src.api.main.artifacts", {"model": mock_model, "pipeline": mock_pipeline}):
        from src.api.main import app
        yield TestClient(app)


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["model_loaded"] is True


def test_model_metrics(client):
    r = client.get("/model/metrics")
    assert r.status_code == 200
    d = r.json()
    assert "auc_roc" in d["metrics"]
    assert d["metrics"]["auc_roc"] > 0.75


def test_predict_valid(client):
    r = client.post("/predict", json=VALID_APP)
    assert r.status_code == 200
    d = r.json()
    assert 0.0 <= d["default_probability"] <= 1.0
    assert d["risk_level"] in ["LOW", "MEDIUM", "HIGH"]
    assert d["recommendation"] in ["APPROVE", "REJECT"]
    assert "application_id" in d


def test_predict_invalid_credit_score(client):
    bad = VALID_APP.copy()
    bad["credit_score"] = 1000  # Out of range
    r = client.post("/predict", json=bad)
    assert r.status_code == 422


def test_predict_batch(client):
    r = client.post("/predict/batch", json={"applications": [VALID_APP, VALID_APP]})
    assert r.status_code == 200
    d = r.json()
    assert d["total"] == 2
    assert len(d["predictions"]) == 2
    assert d["approved"] + d["rejected"] == d["total"]


def test_predict_batch_too_large(client):
    r = client.post("/predict/batch", json={"applications": [VALID_APP] * 501})
    assert r.status_code == 400
