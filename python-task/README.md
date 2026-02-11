# Python Task: Threat Event Analytics

## Objective
Clean a threat events dataset, compute KPIs, and generate a concise report.

## Dataset
- File: [`data/threat_events.csv`](data/threat_events.csv)
- Fields: `event_id`, `event_type`, `severity`, `source`, `timestamp`, `detections`

## Tasks
1. Load the dataset and remove duplicates.
2. Convert timestamps to datetime.
3. Compute KPIs:
   - Total events
   - Average severity
   - Top 3 sources by event count
   - Event counts by type
4. Output a summary report as a dictionary or JSON.

## Example Code Snippet
```python
import pandas as pd

df = pd.read_csv("data/threat_events.csv")
df = df.drop_duplicates()
df["timestamp"] = pd.to_datetime(df["timestamp"])

report = {
    "total_events": len(df),
    "avg_severity": round(df["severity"].mean(), 2),
    "top_sources": df["source"].value_counts().head(3).to_dict(),
    "events_by_type": df["event_type"].value_counts().to_dict(),
}

print(report)
```

## Deliverable
Provide the final report output and a short explanation of the KPIs.
