# Interactive Cyber Threat Visualization Dashboard

This dashboard implements a complete, module-based cybersecurity visualization workflow for the project:
**Development of Interactive Cyber Threat Visualization Dashboard**.

## Module Mapping

### Module 1: Data Acquisition and Structuring
- Input dataset: [`../data/threat_events.csv`](../data/threat_events.csv)
- Structuring and enrichment pipeline: [`data_pipeline.py`](data_pipeline.py)
- Output dataset: [`data/structured_threat_events.csv`](data/structured_threat_events.csv)

### Module 2: Core Visualization Development
- Daily attack trend with rolling anomaly detection
- Attack type distribution
- Weekday-hour heatmap for temporal pressure analysis

### Module 3: Geospatial and Hierarchical Visualization
- Geospatial threat route map (origin → target)
- MITRE ATT&CK treemap
- Business/system impact sunburst

### Module 4: Dashboard Integration and Finalization
- Single responsive Dash application: [`app.py`](app.py)
- Professional UI styling: [`assets/dashboard.css`](assets/dashboard.css)
- Interactive filtering and downloadable executive report

## Key Features
- KPI cards for incidents, risk, anomalies, critical volume, and top target
- Cross-filtering by date, severity, event type, source, and MITRE tactic
- Vulnerability prioritization table with calculated priority index
- Executive report download for management summary

## Installation
```bash
pip install -r requirements.txt
```

## Run
```bash
python app.py
```

Open `http://127.0.0.1:8050` in your browser.

## Regenerate Structured Data
```bash
python data_pipeline.py
```

The generated file is saved to [`data/structured_threat_events.csv`](data/structured_threat_events.csv).
