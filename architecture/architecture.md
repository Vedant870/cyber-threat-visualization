# Architecture

## Overview
The system is organized into three logical layers:
1. **Data Ingestion**: Collects threat events from sources (endpoint, network, email, auth).
2. **Analytics & AI**: Cleans data, computes KPIs, and predicts threat level using the model.
3. **Visualization & Reporting**: Dashboards and reports for analysts.

## Components
- **Event Collector**: API/agent to receive threat events.
- **Data Store**: Relational DB (e.g., PostgreSQL) for structured events.
- **Model Service**: Python service running the classifier.
- **Dashboard**: Frontend visualization.

## Data Flow
1. Events ingested into DB.
2. Batch/stream processing computes features.
3. Model predicts threat level.
4. Dashboard displays alerts and trends.

## Security Considerations
- Role-based access control
- Audit logging
- Data retention policies
