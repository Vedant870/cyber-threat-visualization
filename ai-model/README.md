# AI Model Training (Demo)

This folder contains a lightweight, reproducible AI training demo using a synthetic dataset.

## Files
- Dataset: [`data/synthetic_threat_events.csv`](data/synthetic_threat_events.csv)
- Training Script: [`train_model.py`](train_model.py)

## Setup
1. Create a virtual environment (optional)
2. Install dependencies:

```bash
pip install pandas scikit-learn joblib
```

## Run Training
```bash
python train_model.py
```

## Output
- Model file: `model.joblib`
- Metrics printed to console

## Notes
This demo is for internship submission and does not require real user data.
