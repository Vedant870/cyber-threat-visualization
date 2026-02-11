# Model Research

## Problem Statement
Predict cyber threat level (Low/Medium/High) using event telemetry metrics.

## Why this model?
- **Classification** problem with categorical output.
- **Random Forest** balances interpretability, non-linear relationships, and strong baseline accuracy.
- Handles mixed feature types and is robust to outliers.

## Features Considered
- Failed Logins
- Anomaly Score
- Severity Score
- Source Reputation (risk score)
- Data Exfiltration (MB)
- Geo Risk Score
- Alert Count

## Dataset
- **Type**: Synthetic, tabular
- **Size**: 30 records
- **Bias Handling**: Balanced class distribution for demo

## Metrics
- Accuracy, Precision, Recall, F1-score
- Confusion Matrix

## Future Enhancements
- Add time-series activity data
- Explore Gradient Boosting / XGBoost
- Add model explainability (SHAP)
