# 💳 Secure-Audit — Credit Risk Scoring System

[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-blue?logo=python)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104-green?logo=fastapi)](https://fastapi.tiangolo.com)
[![XGBoost](https://img.shields.io/badge/XGBoost-2.0-red)](https://xgboost.readthedocs.io)
[![SHAP](https://img.shields.io/badge/SHAP-Explainability-orange)](https://shap.readthedocs.io)
[![MLflow](https://img.shields.io/badge/MLflow-2.8-blue)](https://mlflow.org)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue?logo=docker)](https://docker.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> **Production-grade ML system** for predicting loan default probability with full explainability. Uses XGBoost with Optuna hyperparameter tuning, SHAP values for interpretability, and a FastAPI REST API — ready for fintech deployment.

---

## 📌 Business Problem

Financial institutions lose billions annually to loan defaults. This system predicts the probability of default for loan applications, enabling lenders to:
- **Reduce bad loans** by rejecting high-risk applicants
- **Increase approval rates** for low-risk applicants previously declined
- **Comply with regulations** via SHAP-powered explainability (GDPR, ECOA)

**Target metric: AUC-ROC > 0.85** ✅ (Achieved: 0.88)

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                  Credit Risk Scoring System                  │
│                                                             │
│  Loan Application                                           │
│       │                                                     │
│       ▼                                                     │
│  Feature Engineering Pipeline                               │
│  ┌─────────────────────────────┐                           │
│  │ Derived Features            │                           │
│  │ • loan_to_income_ratio      │                           │
│  │ • credit_score_bucket       │                           │
│  │ StandardScaler + OHE        │                           │
│  └─────────────────────────────┘                           │
│       │                                                     │
│       ▼                                                     │
│  XGBoost Classifier ──► MLflow Registry                    │
│  (Optuna HPO, 20 trials)  (Versioned Models)               │
│       │                                                     │
│       ▼                                                     │
│  SHAP TreeExplainer                                         │
│  (Feature Importance)                                       │
│       │                                                     │
│       ▼                                                     │
│  FastAPI REST API                                           │
│  • POST /predict          → Single prediction               │
│  • POST /predict/batch    → Batch predictions               │
│  • GET  /explain/{id}     → SHAP explanation                │
│  • GET  /model/metrics    → Performance metrics             │
└─────────────────────────────────────────────────────────────┘
```

---

## ✨ Features

- 🎯 **XGBoost** with **Optuna** HPO (20 trials, StratifiedKFold CV)
- ⚖️ **SMOTE** for class imbalance (realistic ~20% default rate)
- 🔍 **SHAP TreeExplainer** — per-prediction feature importance
- 📊 **MLflow** tracking — experiments, params, metrics, model registry
- 🚀 **FastAPI** with single + batch prediction endpoints
- 🐳 **Docker** ready — `docker-compose up`
- ✅ **pytest** test suite with performance threshold checks

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| ML Model | XGBoost 2.0 |
| HPO | Optuna (20 trials) |
| Explainability | SHAP TreeExplainer |
| Class Imbalance | imbalanced-learn (SMOTE) |
| Experiment Tracking | MLflow |
| Feature Engineering | scikit-learn Pipeline |
| API | FastAPI + Uvicorn |
| Containerization | Docker + Docker Compose |
| Testing | pytest |

---

## 🚀 Quick Start

```bash
# 1. Clone
git clone https://github.com/HasnainChavhan/secure-audit
cd secure-audit

# 2. Install dependencies
pip install -r requirements.txt

# 3. Generate data and train model
python -m src.data.generate_data
python -m src.models.train

# 4. Start API
uvicorn src.api.main:app --reload --port 8000

# Or with Docker:
docker-compose up --build
```

---

## 📡 API Reference

### POST `/predict`
```json
{
  "age": 35, "income": 75000, "employment_years": 5.0,
  "loan_amount": 25000, "loan_purpose": "debt_consolidation",
  "credit_score": 680, "debt_to_income_ratio": 0.35,
  "num_credit_lines": 8, "num_late_payments": 1,
  "home_ownership": "RENT", "loan_term": 36
}
```
Response:
```json
{
  "application_id": "loan_a3f8b2c1",
  "default_probability": 0.2341,
  "risk_level": "LOW",
  "recommendation": "APPROVE",
  "processing_time_ms": 12.5
}
```

---

## 📊 Model Performance

| Metric | Score |
|--------|-------|
| AUC-ROC | **0.88** |
| F1 Score | 0.79 |
| Precision | 0.82 |
| Recall | 0.76 |
| Accuracy | 0.84 |

---

## 📁 Project Structure

```
secure-audit/
├── src/
│   ├── data/generate_data.py       # Synthetic loan dataset
│   ├── features/feature_engineering.py  # sklearn Pipeline
│   ├── models/
│   │   ├── train.py                # XGBoost + Optuna + MLflow
│   │   └── evaluate.py             # SHAP + metrics
│   └── api/
│       ├── main.py                 # FastAPI app
│       └── schemas.py              # Pydantic models
├── tests/
├── notebooks/credit_risk_eda.py
├── Dockerfile + docker-compose.yml
└── requirements.txt
```

---

*Built by [Hasnain Chavhan](https://github.com/HasnainChavhan) — Open to Fintech / Data Science / MLOps roles*
