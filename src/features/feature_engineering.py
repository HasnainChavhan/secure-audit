"""
Feature engineering pipeline for credit risk scoring.
Builds sklearn ColumnTransformer Pipeline with StandardScaler and OneHotEncoder.
"""
import numpy as np
import pandas as pd
import joblib
from pathlib import Path
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.impute import SimpleImputer

NUMERIC_FEATURES = [
    'age', 'income', 'employment_years', 'loan_amount',
    'credit_score', 'debt_to_income_ratio', 'num_credit_lines',
    'num_late_payments', 'loan_to_income_ratio', 'loan_term'
]
CATEGORICAL_FEATURES = ['loan_purpose', 'home_ownership']


def add_derived_features(df: pd.DataFrame) -> pd.DataFrame:
    """Add engineered features to the dataframe."""
    df = df.copy()
    df['loan_to_income_ratio'] = df['loan_amount'] / (df['income'] + 1)
    df['credit_score_bucket'] = pd.cut(
        df['credit_score'],
        bins=[0, 579, 669, 739, 799, 851],
        labels=['Poor', 'Fair', 'Good', 'Very Good', 'Exceptional']
    ).astype(str)
    return df


def build_pipeline() -> ColumnTransformer:
    """Build sklearn preprocessing pipeline."""
    numeric_transformer = Pipeline([
        ('imputer', SimpleImputer(strategy='median')),
        ('scaler', StandardScaler())
    ])
    categorical_transformer = Pipeline([
        ('imputer', SimpleImputer(strategy='most_frequent')),
        ('encoder', OneHotEncoder(handle_unknown='ignore', sparse_output=False))
    ])
    return ColumnTransformer([
        ('num', numeric_transformer, NUMERIC_FEATURES),
        ('cat', categorical_transformer, CATEGORICAL_FEATURES)
    ])


def fit_and_save_pipeline(df: pd.DataFrame, save_path: str = 'models/feature_pipeline.pkl') -> ColumnTransformer:
    """Fit pipeline on training data and save to disk."""
    df = add_derived_features(df)
    pipeline = build_pipeline()
    X = df[NUMERIC_FEATURES + CATEGORICAL_FEATURES]
    pipeline.fit(X)
    Path(save_path).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, save_path)
    print(f"Pipeline saved → {save_path}")
    return pipeline


def transform_features(df: pd.DataFrame, pipeline_path: str = 'models/feature_pipeline.pkl') -> np.ndarray:
    """Load saved pipeline and transform input features."""
    df = add_derived_features(df)
    pipeline = joblib.load(pipeline_path)
    return pipeline.transform(df[NUMERIC_FEATURES + CATEGORICAL_FEATURES])
