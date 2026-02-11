# Learning Guide: How the Project Gets Ready

This guide explains how the project is structured, how each deliverable is produced, and how to prepare the final submission.

## 1) Understand the Deliverables
The submission requires structured documentation and links. Each item is already mapped in [`docs/Submission-Details.md`](Submission-Details.md).

## 2) AI Model (Training Demo)
The AI component is a **classification model** trained on a synthetic cyber threat dataset. Steps:
1. Review data schema in [`ai-model/data/synthetic_threat_events.csv`](../ai-model/data/synthetic_threat_events.csv).
2. Follow the training script in [`ai-model/train_model.py`](../ai-model/train_model.py).
3. Exported model and metrics are documented in [`ai-model/README.md`](../ai-model/README.md).

## 3) Python Task
The Python task demonstrates data cleaning, KPI calculation, and report generation for threat events.
See [`python-task/README.md`](../python-task/README.md).

## 4) SQL Task
The SQL task defines schema, inserts sample data, and provides analytical queries on threat events.
See [`sql-task/README.md`](../sql-task/README.md).

## 5) Architecture
Review the logical architecture and data flow in [`architecture/architecture.md`](../architecture/architecture.md).

## 6) Deployment
Deployment steps and placeholders are documented in [`deployment/deployment.md`](../deployment/deployment.md).

## 7) Agile, PPT, Leave
Each document has a professional template. Update with your name and dates.

---
**Tip:** Replace placeholders (Name, Email, Links) before submission.
