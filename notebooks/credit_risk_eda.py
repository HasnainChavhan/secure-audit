"""
Credit Risk Exploratory Data Analysis
Run: python notebooks/credit_risk_eda.py
"""
import pandas as pd
import numpy as np
from src.data.generate_data import generate_loan_dataset

df = generate_loan_dataset(n_samples=5000)
print('=== Dataset Overview ===')
print(df.describe().round(2))
print(f'\nDefault rate: {df["default"].mean():.2%}')
print(f'\nDefault by credit score bucket:')
df['credit_bucket'] = pd.cut(df['credit_score'], bins=[300,579,669,739,799,850], labels=['Poor','Fair','Good','Very Good','Exceptional'])
print(df.groupby('credit_bucket')['default'].mean().round(3))
print(f'\nDefault by loan purpose:')
print(df.groupby('loan_purpose')['default'].mean().round(3))
print(f'\nCorrelation with default:')
numeric_cols = ['age','income','employment_years','loan_amount','credit_score','debt_to_income_ratio','num_late_payments']
print(df[numeric_cols + ['default']].corr()['default'].sort_values().round(3))
