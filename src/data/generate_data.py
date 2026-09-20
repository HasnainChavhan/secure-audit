"""
Generate synthetic loan application dataset for credit risk modeling.
Creates 10,000 realistic records with proper statistical distributions
and realistic correlations between credit features and default probability.
"""
import numpy as np
import pandas as pd
from pathlib import Path


def generate_loan_dataset(n_samples: int = 10000, random_state: int = 42) -> pd.DataFrame:
    """
    Generate a realistic loan application dataset.

    Features engineered to reflect real credit risk factors:
    - Lower credit score → higher default probability
    - Higher debt-to-income → higher risk
    - More late payments → much higher risk
    - Longer employment → lower risk

    Returns:
        pd.DataFrame with n_samples rows and 12 feature columns + target
    """
    np.random.seed(random_state)

    # Demographics
    age = np.random.normal(40, 12, n_samples).clip(21, 75).astype(int)
    income = np.random.lognormal(10.8, 0.6, n_samples).clip(20000, 500000).round(2)
    employment_years = np.random.exponential(6, n_samples).clip(0, 40).round(1)

    # Loan details
    loan_amount = np.random.lognormal(10.5, 0.8, n_samples).clip(1000, 500000).round(2)
    purposes = ['home_improvement', 'debt_consolidation', 'business', 'education', 'medical', 'personal']
    loan_purpose = np.random.choice(purposes, n_samples, p=[0.25, 0.30, 0.15, 0.10, 0.10, 0.10])

    # Credit profile
    credit_score = np.random.normal(680, 80, n_samples).clip(300, 850).astype(int)
    debt_to_income = (loan_amount / income).clip(0, 5).round(3)
    num_credit_lines = np.random.poisson(8, n_samples).clip(1, 40)
    num_late_payments = np.random.choice([0, 1, 2, 3, 4, 5], n_samples, p=[0.60, 0.20, 0.10, 0.05, 0.03, 0.02])

    # Property
    ownership = ['RENT', 'OWN', 'MORTGAGE']
    home_ownership = np.random.choice(ownership, n_samples, p=[0.45, 0.20, 0.35])
    loan_term = np.random.choice([36, 60], n_samples, p=[0.6, 0.4])

    # Generate realistic default probability via logistic model
    log_odds = (
        -3.0
        + (700 - credit_score) * 0.012
        + debt_to_income * 1.2
        + num_late_payments * 0.5
        - employment_years * 0.04
        - np.log1p(income) * 0.1
        + (loan_amount / 100000) * 0.3
    )
    prob_default = 1 / (1 + np.exp(-log_odds))
    default = (np.random.uniform(0, 1, n_samples) < prob_default).astype(int)

    df = pd.DataFrame({
        'age': age,
        'income': income,
        'employment_years': employment_years,
        'loan_amount': loan_amount,
        'loan_purpose': loan_purpose,
        'credit_score': credit_score,
        'debt_to_income_ratio': debt_to_income,
        'num_credit_lines': num_credit_lines,
        'num_late_payments': num_late_payments,
        'home_ownership': home_ownership,
        'loan_term': loan_term,
        'default': default,
    })

    return df


if __name__ == '__main__':
    Path('data/raw').mkdir(parents=True, exist_ok=True)
    df = generate_loan_dataset()
    df.to_csv('data/raw/loan_data.csv', index=False)
    print(f"Generated {len(df):,} records.")
    print(f"Default rate: {df['default'].mean():.2%}")
    print(f"Columns: {list(df.columns)}")
    print(df.describe().round(2))
