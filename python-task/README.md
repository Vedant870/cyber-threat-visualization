# Python Module: Interactive Cyber Threat Visualization Dashboard

This section now contains the implementation for the project title:
**Development of Interactive Cyber Threat Visualization Dashboard**

## Implemented Modules

### Module 1: Data Acquisition and Structuring
- Raw incident data source: [`data/threat_events.csv`](data/threat_events.csv)
- Structuring and enrichment script: [`dashboard/data_pipeline.py`](dashboard/data_pipeline.py)
- Structured output used by dashboard: [`dashboard/data/structured_threat_events.csv`](dashboard/data/structured_threat_events.csv)

### Module 2: Core Visualization Development
- Time-series attack trend chart
- Anomaly detection (rolling z-score)
- Event type distribution
- Severity heatmap (weekday vs hour)

### Module 3: Geospatial and Hierarchical Visualization
- Geospatial origin-target risk map
- MITRE ATT&CK hierarchy treemap
- System-focused sunburst chart
- Top threat-route prioritization table

### Module 4: Dashboard Integration and Finalization
- Unified Dash app integrating all visuals
- Interactive filters (date, severity, event type, source, MITRE tactic)
- KPI cards for analyst and executive views
- Downloadable executive risk report

## Dashboard Entry Point
- Main app: [`dashboard/app.py`](dashboard/app.py)
- Documentation: [`dashboard/README.md`](dashboard/README.md)
- Dependencies: [`dashboard/requirements.txt`](dashboard/requirements.txt)

## Quick Run
```bash
pip install -r python-task/dashboard/requirements.txt
python python-task/dashboard/app.py
```

Open: `http://127.0.0.1:8050`
