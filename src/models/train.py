"""
XGBoost Credit Risk Model Training
Uses Optuna for HPO, SMOTE for class balance, MLflow for tracking.
"""
import logging
import warnings
warnings.filterwarnings('ignore')
from pathlib import Path

import numpy as np
import pandas as pd
import joblib
import mlflow
import mlflow.xgboost
import optuna
optuna.logging.set_verbosity(optuna.logging.WARNING)
from xgboost import XGBClassifier
from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.metrics import (
    roc_auc_score, f1_score, precision_score,
    recall_score, accuracy_score
)
from imblearn.over_sampling import SMOTE

from src.data.generate_data import generate_loan_dataset
from src.features.feature_engineering import fit_and_save_pipeline, transform_features, add_derived_features

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def train(n_samples: int = 10000, n_trials: int = 20):
    """Full training pipeline: data → features → HPO → MLflow logging → model save."""

    logger.info("Step 1/5: Generating dataset...")
    df = generate_loan_dataset(n_samples=n_samples)
    y = df['default'].values
    logger.info(f"  {n_samples:,} records generated. Default rate: {y.mean():.2%}")

    logger.info("Step 2/5: Engineering features...")
    pipeline = fit_and_save_pipeline(df)
    X = transform_features(df)
    logger.info(f"  Feature matrix: {X.shape}")

    logger.info("Step 3/5: Applying SMOTE for class imbalance...")
    sm = SMOTE(random_state=42)
    X_res, y_res = sm.fit_resample(X, y)
    logger.info(f"  Resampled: {X_res.shape} | Classes: {np.bincount(y_res)}")

    logger.info(f"Step 4/5: Running Optuna HPO ({n_trials} trials)...")

    def objective(trial):
        params = {
            'n_estimators': trial.suggest_int('n_estimators', 100, 500),
            'max_depth': trial.suggest_int('max_depth', 3, 8),
            'learning_rate': trial.suggest_float('learning_rate', 0.01, 0.3, log=True),
            'subsample': trial.suggest_float('subsample', 0.6, 1.0),
            'colsample_bytree': trial.suggest_float('colsample_bytree', 0.6, 1.0),
            'min_child_weight': trial.suggest_int('min_child_weight', 1, 7),
            'reg_alpha': trial.suggest_float('reg_alpha', 0, 1),
            'reg_lambda': trial.suggest_float('reg_lambda', 0, 1),
            'eval_metric': 'logloss',
            'random_state': 42,
        }
        model = XGBClassifier(**params)
        cv = StratifiedKFold(n_splits=3, shuffle=True, random_state=42)
        scores = cross_val_score(model, X_res, y_res, cv=cv, scoring='roc_auc')
        return scores.mean()

    study = optuna.create_study(direction='maximize')
    study.optimize(objective, n_trials=n_trials, show_progress_bar=False)
    best_params = study.best_params
    logger.info(f"  Best AUC (CV): {study.best_value:.4f}")

    logger.info("Step 5/5: Training final model + MLflow logging...")
    mlflow.set_experiment('credit-risk-scoring')
    with mlflow.start_run(run_name='xgboost_optuna'):
        final_model = XGBClassifier(
            **best_params,
            eval_metric='logloss',
            random_state=42
        )
        final_model.fit(X_res, y_res)

        y_pred = final_model.predict(X)
        y_prob = final_model.predict_proba(X)[:, 1]

        metrics = {
            'auc_roc': roc_auc_score(y, y_prob),
            'f1_score': f1_score(y, y_pred),
            'precision': precision_score(y, y_pred),
            'recall': recall_score(y, y_pred),
            'accuracy': accuracy_score(y, y_pred),
        }

        mlflow.log_params(best_params)
        mlflow.log_metrics(metrics)
        mlflow.xgboost.log_model(final_model, artifact_path='model')

    Path('models').mkdir(exist_ok=True)
    joblib.dump(final_model, 'models/credit_risk_model.pkl')
    logger.info("  Model saved → models/credit_risk_model.pkl")

    logger.info("\n=== FINAL METRICS ===")
    for k, v in metrics.items():
        logger.info(f"  {k}: {v:.4f}")

    return final_model, metrics


if __name__ == '__main__':
    train()
