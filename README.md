# Development of Interactive Cyber Threat Visualization Dashboard

This repository contains a complete, professional cybersecurity analytics workspace with an interactive Plotly/Dash dashboard, AI model demo, SQL task files, and project documentation.

## Project Statement
The project builds an interactive, data-driven dashboard that gives cybersecurity analysts immediate visual understanding of the threat landscape. Simulated incident data is aggregated, normalized, and visualized to reveal attack patterns, temporal trends, geographical hotspots, and system vulnerabilities.

## Outcomes Delivered
- **Geospatial Risk Mapping**: Global view of origin-target threat routes and hotspot countries.
- **Trend and Anomaly Detection**: Time-series charts with rolling anomaly detection for unusual attack surges.
- **Vulnerability Prioritization**: Treemap/sunburst hierarchy by MITRE tactic, technique, and target systems.
- **Enhanced Reporting**: Downloadable executive-ready report generated from active dashboard filters.

## Module-Wise Implementation

### Module 1: Data Acquisition and Structuring
- Raw events source: [`python-task/data/threat_events.csv`](python-task/data/threat_events.csv)
- Data pipeline: [`python-task/dashboard/data_pipeline.py`](python-task/dashboard/data_pipeline.py)
- Structured dataset output: [`python-task/dashboard/data/structured_threat_events.csv`](python-task/dashboard/data/structured_threat_events.csv)

### Module 2: Core Visualization Development
- Time-series trend and anomaly analysis
- Event distribution and severity analytics
- Implemented in: [`python-task/dashboard/app.py`](python-task/dashboard/app.py)

### Module 3: Geospatial and Hierarchical Visualization
- Interactive global map (origins, targets, top threat routes)
- Treemap / sunburst for MITRE ATT&CK + target systems
- Implemented in: [`python-task/dashboard/app.py`](python-task/dashboard/app.py)

### Module 4: Dashboard Integration and Finalization
- Unified responsive Dash application
- Cross-filtering controls and KPI cards
- Executive report export
- Implemented in: [`python-task/dashboard/app.py`](python-task/dashboard/app.py)

## Run the Dashboard
1. Install dependencies:
   ```bash
   pip install -r python-task/dashboard/requirements.txt
   ```
2. Start the app:
   ```bash
   python python-task/dashboard/app.py
   ```
3. Open browser at `http://127.0.0.1:8050`.

## Key Project Documents
- Dashboard guide: [`python-task/dashboard/README.md`](python-task/dashboard/README.md)
- Python task overview: [`python-task/README.md`](python-task/README.md)
- AI model training demo: [`ai-model/README.md`](ai-model/README.md)
- System architecture: [`architecture/architecture.md`](architecture/architecture.md)
- Deployment notes: [`deployment/deployment.md`](deployment/deployment.md)
- Submission placeholders: [`docs/Submission-Details.md`](docs/Submission-Details.md)
