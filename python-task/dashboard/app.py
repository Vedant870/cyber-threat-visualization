from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from dash import Dash, Input, Output, State, dash_table, dcc, html
from dash.exceptions import PreventUpdate
from plotly.subplots import make_subplots

from data_pipeline import build_structured_dataset

BASE_DIR = Path(__file__).resolve().parent
DATA_PATH = BASE_DIR / "data" / "structured_threat_events.csv"

WEEKDAY_ORDER = [
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
    "Sunday",
]

SEVERITY_ORDER = ["Low", "Medium", "High", "Critical"]

PALETTE = {
    "panel": "#111827",
    "bg": "#060b18",
    "text": "#e5e7eb",
    "muted": "#94a3b8",
    "cyan": "#22d3ee",
    "amber": "#f59e0b",
    "rose": "#fb7185",
    "lime": "#86efac",
    "indigo": "#818cf8",
}

GRAPH_CONFIG = {
    "displaylogo": False,
    "responsive": True,
    "modeBarButtonsToRemove": ["lasso2d", "select2d"],
}

GRAPH_STYLE = {"height": "360px"}

LIVE_INTERVAL_MS = 15000
LIVE_SLA_SECONDS = 120


def load_dataset() -> pd.DataFrame:
    if not DATA_PATH.exists():
        build_structured_dataset()

    df = pd.read_csv(DATA_PATH)
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    df = df.dropna(subset=["timestamp"]).copy()

    df["severity"] = pd.to_numeric(df["severity"], errors="coerce").fillna(5).round().astype(int)
    df["detections"] = pd.to_numeric(df["detections"], errors="coerce").fillna(1).round().astype(int)
    df["risk_score"] = pd.to_numeric(df["risk_score"], errors="coerce").fillna(0.0)
    df["hour_utc"] = pd.to_numeric(df["hour_utc"], errors="coerce").fillna(0).round().astype(int)
    df["anomaly_flag"] = df["anomaly_flag"].astype(str).str.lower().eq("true")

    if "severity_label" not in df.columns:
        bins = [0, 3, 6, 8, 10]
        labels = ["Low", "Medium", "High", "Critical"]
        df["severity_label"] = pd.cut(df["severity"], bins=bins, labels=labels)

    df["severity_label"] = pd.Categorical(
        df["severity_label"], categories=SEVERITY_ORDER, ordered=True
    )
    df["weekday"] = df["timestamp"].dt.day_name()
    df["event_date"] = df["timestamp"].dt.date
    return df.sort_values("timestamp").reset_index(drop=True)


DF = load_dataset()
MIN_DATE = DF["timestamp"].min().date()
MAX_DATE = DF["timestamp"].max().date()
DEFAULT_START = (pd.Timestamp(MAX_DATE) - pd.Timedelta(days=30)).date()
if DEFAULT_START < MIN_DATE:
    DEFAULT_START = MIN_DATE


def apply_filters(
    df: pd.DataFrame,
    start_date: str | None,
    end_date: str | None,
    severities: list[str] | None,
    event_types: list[str] | None,
    sources: list[str] | None,
    tactics: list[str] | None,
) -> pd.DataFrame:
    view = df.copy()

    if start_date:
        start_ts = pd.to_datetime(start_date, utc=True)
        view = view[view["timestamp"] >= start_ts]
    if end_date:
        end_ts = pd.to_datetime(end_date, utc=True) + pd.Timedelta(days=1) - pd.Timedelta(seconds=1)
        view = view[view["timestamp"] <= end_ts]

    if severities:
        view = view[view["severity_label"].isin(severities)]
    if event_types:
        view = view[view["event_type"].isin(event_types)]
    if sources:
        view = view[view["source"].isin(sources)]
    if tactics:
        view = view[view["mitre_tactic"].isin(tactics)]

    return view.copy()


def style_figure(fig: go.Figure, title: str) -> go.Figure:
    fig.update_layout(
        title=dict(text=title, x=0.02, xanchor="left", font=dict(size=17, color=PALETTE["text"])),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color=PALETTE["text"], family="Inter, Segoe UI, sans-serif"),
        margin=dict(l=30, r=20, t=58, b=34),
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.01,
            xanchor="right",
            x=1.0,
            bgcolor="rgba(0,0,0,0)",
            borderwidth=0,
            font=dict(size=11),
        ),
        hoverlabel=dict(
            bgcolor="#0f172a",
            bordercolor="#334155",
            font=dict(color=PALETTE["text"]),
        ),
        autosize=True,
        uirevision="threat-dashboard",
    )
    return fig


def empty_fig(title: str, text: str = "No data for selected filters") -> go.Figure:
    fig = go.Figure()
    fig.add_annotation(
        text=text,
        x=0.5,
        y=0.5,
        xref="paper",
        yref="paper",
        showarrow=False,
        font=dict(size=16, color=PALETTE["muted"]),
    )
    fig.update_xaxes(visible=False)
    fig.update_yaxes(visible=False)
    return style_figure(fig, title)


def trend_chart(df: pd.DataFrame) -> go.Figure:
    if df.empty:
        return empty_fig("Trend & Anomaly Detection")

    daily = (
        df.set_index("timestamp")
        .resample("D")
        .agg(events=("event_id", "count"), avg_risk=("risk_score", "mean"))
        .reset_index()
    )

    daily["rolling_mean"] = daily["events"].rolling(window=7, min_periods=2).mean()
    daily["rolling_std"] = daily["events"].rolling(window=7, min_periods=2).std().replace(0, np.nan)
    daily["z_score"] = (daily["events"] - daily["rolling_mean"]) / daily["rolling_std"]
    daily["is_anomaly"] = daily["z_score"].abs() >= 2.2

    fig = make_subplots(specs=[[{"secondary_y": True}]])
    fig.add_trace(
        go.Scatter(
            x=daily["timestamp"],
            y=daily["events"],
            mode="lines+markers",
            name="Daily Incidents",
            line=dict(color=PALETTE["cyan"], width=2.5),
            marker=dict(size=4),
        ),
        secondary_y=False,
    )
    fig.add_trace(
        go.Scatter(
            x=daily["timestamp"],
            y=daily["rolling_mean"],
            mode="lines",
            name="7-day Moving Avg",
            line=dict(color=PALETTE["amber"], dash="dash", width=2),
        ),
        secondary_y=False,
    )

    spikes = daily[daily["is_anomaly"]]
    if not spikes.empty:
        fig.add_trace(
            go.Scatter(
                x=spikes["timestamp"],
                y=spikes["events"],
                mode="markers",
                name="Anomaly Spike",
                marker=dict(color=PALETTE["rose"], size=10, symbol="x"),
            ),
            secondary_y=False,
        )

    fig.add_trace(
        go.Scatter(
            x=daily["timestamp"],
            y=daily["avg_risk"],
            mode="lines",
            name="Average Risk",
            line=dict(color=PALETTE["indigo"], width=2),
        ),
        secondary_y=True,
    )

    fig.update_xaxes(title="Date", gridcolor="#233047")
    fig.update_yaxes(title="Incident Count", secondary_y=False, gridcolor="#233047")
    fig.update_yaxes(title="Average Risk", secondary_y=True, gridcolor="#233047")
    return style_figure(fig, "Trend & Anomaly Detection")


def type_pie(df: pd.DataFrame) -> go.Figure:
    if df.empty:
        return empty_fig("Attack Type Distribution")

    grouped = (
        df.groupby("event_type", as_index=False)
        .agg(events=("event_id", "count"), avg_risk=("risk_score", "mean"))
        .sort_values("events", ascending=False)
    )

    fig = px.pie(
        grouped,
        names="event_type",
        values="events",
        hole=0.45,
        color_discrete_sequence=px.colors.qualitative.Set3,
        hover_data={"events": True, "avg_risk": ":.2f"},
    )
    fig = style_figure(fig, "Attack Type Distribution")
    fig.update_traces(
        textposition="inside",
        textinfo="percent",
        insidetextorientation="radial",
        hovertemplate="Type: %{label}<br>Incidents: %{value}<br>Share: %{percent}<extra></extra>",
    )
    fig.update_layout(
        legend=dict(
            orientation="v",
            yanchor="middle",
            y=0.5,
            xanchor="left",
            x=1.02,
            bgcolor="rgba(0,0,0,0)",
            borderwidth=0,
            font=dict(size=11),
        )
    )
    return fig


def severity_heatmap(df: pd.DataFrame) -> go.Figure:
    if df.empty:
        return empty_fig("Severity Heatmap (Weekday × Hour UTC)")

    matrix = (
        df.groupby(["weekday", "hour_utc"], as_index=False)
        .size()
        .rename(columns={"size": "events"})
        .pivot(index="weekday", columns="hour_utc", values="events")
        .reindex(WEEKDAY_ORDER)
        .fillna(0)
    )

    fig = px.imshow(
        matrix,
        labels={"x": "Hour (UTC)", "y": "Weekday", "color": "Incidents"},
        color_continuous_scale="Magma",
        aspect="auto",
    )
    return style_figure(fig, "Severity Heatmap (Weekday × Hour UTC)")


def geo_map(df: pd.DataFrame) -> go.Figure:
    if df.empty:
        return empty_fig("Geospatial Risk Mapping")

    routes = (
        df.groupby(
            [
                "origin_country",
                "target_country",
                "origin_lat",
                "origin_lon",
                "target_lat",
                "target_lon",
            ],
            as_index=False,
        )
        .agg(events=("event_id", "count"), avg_risk=("risk_score", "mean"))
        .sort_values(["events", "avg_risk"], ascending=False)
        .head(120)
    )

    fig = go.Figure()
    for row in routes.itertuples(index=False):
        width = max(1.0, min(6.0, row.events / 3.0))
        fig.add_trace(
            go.Scattergeo(
                lat=[row.origin_lat, row.target_lat],
                lon=[row.origin_lon, row.target_lon],
                mode="lines",
                line=dict(width=width, color="rgba(248,113,113,0.35)"),
                hovertemplate=(
                    f"Route: {row.origin_country} → {row.target_country}<br>"
                    f"Incidents: {row.events}<br>Avg Risk: {row.avg_risk:.2f}<extra></extra>"
                ),
                showlegend=False,
            )
        )

    origin = (
        df.groupby(["origin_country", "origin_lat", "origin_lon"], as_index=False)
        .agg(events=("event_id", "count"), avg_risk=("risk_score", "mean"))
        .sort_values("events", ascending=False)
    )
    target = (
        df.groupby(["target_country", "target_lat", "target_lon"], as_index=False)
        .agg(events=("event_id", "count"), avg_risk=("risk_score", "mean"))
        .sort_values("events", ascending=False)
    )

    fig.add_trace(
        go.Scattergeo(
            lat=origin["origin_lat"],
            lon=origin["origin_lon"],
            text=origin["origin_country"],
            mode="markers",
            name="Origin",
            customdata=np.column_stack([origin["events"], origin["avg_risk"]]),
            marker=dict(
                size=np.clip(origin["events"] / 9, 6, 24),
                color=origin["avg_risk"],
                colorscale="Reds",
                opacity=0.9,
                line=dict(color="#fecaca", width=0.8),
                colorbar=dict(title="Origin Risk", len=0.55, y=0.78),
            ),
            hovertemplate="Origin: %{text}<br>Incidents: %{customdata[0]}<br>Avg Risk: %{customdata[1]:.2f}<extra></extra>",
        )
    )
    fig.add_trace(
        go.Scattergeo(
            lat=target["target_lat"],
            lon=target["target_lon"],
            text=target["target_country"],
            mode="markers",
            name="Target",
            customdata=np.column_stack([target["events"], target["avg_risk"]]),
            marker=dict(
                size=np.clip(target["events"] / 9, 6, 24),
                color=target["avg_risk"],
                colorscale="Blues",
                symbol="diamond",
                opacity=0.85,
                line=dict(color="#bfdbfe", width=0.8),
            ),
            hovertemplate="Target: %{text}<br>Incidents: %{customdata[0]}<br>Avg Risk: %{customdata[1]:.2f}<extra></extra>",
        )
    )

    fig.update_layout(
        geo=dict(
            projection_type="natural earth",
            showland=True,
            landcolor="#0f172a",
            showocean=True,
            oceancolor="#020617",
            showcountries=True,
            countrycolor="#334155",
            coastlinecolor="#475569",
            bgcolor=PALETTE["panel"],
        )
    )
    return style_figure(fig, "Geospatial Risk Mapping")


def mitre_treemap(df: pd.DataFrame) -> go.Figure:
    if df.empty:
        return empty_fig("MITRE ATT&CK Treemap")

    grouped = (
        df.groupby(["mitre_tactic", "mitre_technique", "target_system"], as_index=False)
        .agg(events=("event_id", "count"), avg_risk=("risk_score", "mean"))
        .sort_values("events", ascending=False)
    )

    fig = px.treemap(
        grouped,
        path=["mitre_tactic", "mitre_technique", "target_system"],
        values="events",
        color="avg_risk",
        color_continuous_scale="Turbo",
        hover_data={"events": True, "avg_risk": ":.2f"},
    )
    return style_figure(fig, "MITRE ATT&CK Treemap")


def impact_sunburst(df: pd.DataFrame) -> go.Figure:
    if df.empty:
        return empty_fig("System Impact Sunburst")

    grouped = (
        df.groupby(["organization_unit", "target_system", "event_type"], as_index=False)
        .agg(events=("event_id", "count"), avg_risk=("risk_score", "mean"))
        .sort_values("events", ascending=False)
    )

    fig = px.sunburst(
        grouped,
        path=["organization_unit", "target_system", "event_type"],
        values="events",
        color="avg_risk",
        color_continuous_scale="RdYlBu_r",
        hover_data={"events": True, "avg_risk": ":.2f"},
    )
    return style_figure(fig, "System Impact Sunburst")


def hotspot_rows(df: pd.DataFrame) -> list[dict[str, object]]:
    if df.empty:
        return []

    ranked = (
        df.groupby(["target_country", "target_system", "mitre_technique"], as_index=False)
        .agg(
            incidents=("event_id", "count"),
            avg_risk=("risk_score", "mean"),
            critical=("severity_label", lambda s: int((s == "Critical").sum())),
            anomalies=("anomaly_flag", "sum"),
        )
        .sort_values("incidents", ascending=False)
    )

    ranked["priority"] = (
        ranked["incidents"] * 0.45
        + ranked["avg_risk"] * 0.35
        + ranked["critical"] * 2.0
        + ranked["anomalies"] * 2.3
    ).round(2)

    ranked["avg_risk"] = ranked["avg_risk"].round(2)
    return ranked.sort_values(["priority", "incidents"], ascending=False).head(12).to_dict("records")


def build_realtime_specs(
    live_df: pd.DataFrame,
    scoped_df: pd.DataFrame,
) -> tuple[str, str, str, str, str, str, str, str]:
    if live_df.empty:
        return (
            "Offline",
            "N/A",
            "0.00 ev/min",
            "0.0%",
            "N/A",
            "No coverage",
            "0.0%",
            "No sync",
        )

    now_ts = pd.Timestamp.now(tz="UTC")
    latest_ts = pd.to_datetime(live_df["timestamp"].max(), utc=True)
    lag_seconds = max(float((now_ts - latest_ts).total_seconds()), 0.0)

    if lag_seconds <= LIVE_SLA_SECONDS:
        status = "Live"
    elif lag_seconds <= LIVE_SLA_SECONDS * 3:
        status = "Warm"
    else:
        status = "Delayed"

    latency = f"{lag_seconds:.0f}s"

    active_df = scoped_df if not scoped_df.empty else live_df
    last_hour = active_df[active_df["timestamp"] >= now_ts - pd.Timedelta(hours=1)]
    velocity = len(last_hour) / 60.0
    anomaly_rate = (float(last_hour["anomaly_flag"].mean()) * 100.0) if not last_hour.empty else 0.0

    freshness = f"{lag_seconds:.0f}s lag • SLA {'met' if lag_seconds <= LIVE_SLA_SECONDS else 'breached'}"

    start_ts = pd.to_datetime(live_df["timestamp"].min(), utc=True)
    coverage_days = max(int((latest_ts - start_ts).total_seconds() // 86400) + 1, 1)
    coverage = f"{start_ts.strftime('%Y-%m-%d')} → {latest_ts.strftime('%Y-%m-%d')} ({coverage_days}d)"

    quality_cols = ["event_type", "source", "mitre_tactic", "risk_score", "target_system"]
    completeness = 1.0 - float(active_df[quality_cols].isna().mean().mean())
    timeliness_penalty = min(lag_seconds / 8.0, 25.0)
    signal_quality = max(0.0, min(100.0, completeness * 100.0 - timeliness_penalty))

    sync = now_ts.strftime("%Y-%m-%d %H:%M:%S UTC")

    return (
        status,
        latency,
        f"{velocity:.2f} ev/min",
        f"{anomaly_rate:.1f}%",
        freshness,
        coverage,
        f"{signal_quality:.1f}%",
        sync,
    )


def build_ai_insights(df: pd.DataFrame) -> tuple[str, str, str]:
    if df.empty:
        return (
            "No AI narrative available for the current filter selection.",
            "No AI forecast available because there are no incidents in range.",
            "No AI recommendation available without hotspot activity.",
        )

    end_ts = df["timestamp"].max()
    recent_start = end_ts - pd.Timedelta(days=7)
    previous_start = recent_start - pd.Timedelta(days=7)

    recent = df[df["timestamp"] >= recent_start]
    previous = df[(df["timestamp"] >= previous_start) & (df["timestamp"] < recent_start)]

    recent_count = len(recent)
    previous_count = len(previous)
    baseline = max(previous_count, 1)
    delta_pct = ((recent_count - previous_count) / baseline) * 100
    trend_word = "increased" if delta_pct >= 0 else "decreased"

    top_event_source = recent if not recent.empty else df
    top_event_mode = top_event_source["event_type"].mode()
    top_event = (
        str(top_event_mode.iloc[0]).replace("_", " ").title()
        if not top_event_mode.empty
        else "General Threat Activity"
    )
    narrative = (
        f"AI signal: {top_event} is the dominant threat pattern. Incident volume {trend_word} "
        f"{abs(delta_pct):.1f}% versus the previous 7-day window."
    )

    daily_counts = df.set_index("timestamp").resample("D").size().tail(14)
    if len(daily_counts) >= 3:
        x = np.arange(len(daily_counts))
        slope = float(np.polyfit(x, daily_counts.values, 1)[0])
        direction = "upward" if slope > 0.15 else "downward" if slope < -0.15 else "stable"
        forecast = (
            f"AI forecast: daily incident pressure looks {direction} over the next 72 hours "
            f"(trend slope {slope:+.2f} incidents/day)."
        )
    else:
        forecast = "AI forecast: insufficient daily data points for a reliable 72-hour projection."

    hotspots = hotspot_rows(df)
    if hotspots:
        top = hotspots[0]
        recommendation = (
            f"AI recommendation: prioritize {top['target_system']} in {top['target_country']} "
            f"against {top['mitre_technique']} (priority score {top['priority']})."
        )
    else:
        recommendation = "AI recommendation: no critical hotspot identified in the selected filters."

    return narrative, forecast, recommendation


def fmt_int(value: int) -> str:
    return f"{int(value):,}"


def build_executive_report(df: pd.DataFrame, start_date: str | None, end_date: str | None) -> str:
    if df.empty:
        return "Executive Cyber Risk Report\n\nNo data available for the selected filters."

    total = len(df)
    avg_risk = float(df["risk_score"].mean())
    anomalies = int(df["anomaly_flag"].sum())
    critical = int((df["severity_label"] == "Critical").sum())

    top_origin = df["origin_country"].value_counts().head(5)
    top_target = df["target_country"].value_counts().head(5)
    top_techniques = (
        df.groupby("mitre_technique", as_index=False)
        .agg(incidents=("event_id", "count"), avg_risk=("risk_score", "mean"))
        .sort_values(["incidents", "avg_risk"], ascending=False)
        .head(5)
    )

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    period = f"{start_date or MIN_DATE} to {end_date or MAX_DATE}"

    lines = [
        "Executive Cyber Risk Report",
        "=" * 28,
        f"Generated: {generated}",
        f"Analysis Window: {period}",
        "",
        "Key KPIs",
        "--------",
        f"Total Incidents: {total}",
        f"Average Risk Score: {avg_risk:.2f}",
        f"Anomaly Events: {anomalies}",
        f"Critical Severity Events: {critical}",
        "",
        "Top Origin Countries",
        "--------------------",
    ]

    for country, count in top_origin.items():
        lines.append(f"- {country}: {count}")

    lines.extend(["", "Top Target Countries", "--------------------"])
    for country, count in top_target.items():
        lines.append(f"- {country}: {count}")

    lines.extend(["", "Top MITRE Techniques", "--------------------"])
    for _, row in top_techniques.iterrows():
        lines.append(
            f"- {row['mitre_technique']}: {int(row['incidents'])} incidents | Avg Risk {row['avg_risk']:.2f}"
        )

    lines.extend(
        [
            "",
            "Recommended Actions",
            "--------------------",
            "1. Prioritize controls for highest-risk target countries and systems.",
            "2. Investigate anomaly spike dates with SOC rapid triage playbooks.",
            "3. Accelerate mitigation for top MITRE techniques listed above.",
        ]
    )

    return "\n".join(lines)


app = Dash(__name__, title="Interactive Cyber Threat Visualization Dashboard")
server = app.server

app.layout = html.Div(
    className="page",
    children=[
        dcc.Interval(id="live-interval", interval=LIVE_INTERVAL_MS, n_intervals=0),
        html.Div(
            className="hero",
            children=[
                html.Div(
                    className="hero-top",
                    children=[
                        html.Span("AI-Integrated SOC Console", className="hero-tag"),
                        html.Div(
                            className="hero-chips",
                            children=[
                                html.Span("Anomaly ML Signals", className="hero-chip"),
                                html.Span("MITRE Correlation", className="hero-chip"),
                                html.Span("Executive Risk Intelligence", className="hero-chip"),
                            ],
                        ),
                    ],
                ),
                html.H1("Interactive Cyber Threat Visualization Dashboard"),
                html.P(
                    "AI-enhanced security operations cockpit with geospatial risk mapping, temporal anomaly detection, "
                    "MITRE ATT&CK prioritization, and executive reporting."
                ),
                html.P(
                    f"Coverage: {MIN_DATE} to {MAX_DATE}  •  Structured Events: {len(DF):,}",
                    className="muted",
                ),
            ],
        ),
        html.Div(
            className="filters",
            children=[
                html.Div(
                    className="filter-item",
                    children=[
                        html.Label("Date Range"),
                        dcc.DatePickerRange(
                            id="date-range",
                            min_date_allowed=MIN_DATE,
                            max_date_allowed=MAX_DATE,
                            start_date=DEFAULT_START,
                            end_date=MAX_DATE,
                            display_format="YYYY-MM-DD",
                        ),
                    ],
                ),
                html.Div(
                    className="filter-item",
                    children=[
                        html.Label("Severity"),
                        dcc.Dropdown(
                            id="severity-filter",
                            options=[{"label": s, "value": s} for s in SEVERITY_ORDER],
                            value=["Medium", "High", "Critical"],
                            multi=True,
                            clearable=False,
                        ),
                    ],
                ),
                html.Div(
                    className="filter-item",
                    children=[
                        html.Label("Event Type"),
                        dcc.Dropdown(
                            id="event-filter",
                            options=[
                                {"label": e.title(), "value": e}
                                for e in sorted(DF["event_type"].dropna().unique())
                            ],
                            value=sorted(DF["event_type"].dropna().unique()),
                            multi=True,
                        ),
                    ],
                ),
                html.Div(
                    className="filter-item",
                    children=[
                        html.Label("Source"),
                        dcc.Dropdown(
                            id="source-filter",
                            options=[
                                {"label": s.title(), "value": s}
                                for s in sorted(DF["source"].dropna().unique())
                            ],
                            value=sorted(DF["source"].dropna().unique()),
                            multi=True,
                        ),
                    ],
                ),
                html.Div(
                    className="filter-item",
                    children=[
                        html.Label("MITRE Tactic"),
                        dcc.Dropdown(
                            id="tactic-filter",
                            options=[
                                {"label": t, "value": t}
                                for t in sorted(DF["mitre_tactic"].dropna().unique())
                            ],
                            value=sorted(DF["mitre_tactic"].dropna().unique()),
                            multi=True,
                        ),
                    ],
                ),
                html.Div(
                    className="filter-item action",
                    children=[
                        html.Button(
                            "Download AI Executive Report",
                            id="download-btn",
                            className="download-btn",
                            n_clicks=0,
                        ),
                        dcc.Download(id="download-report"),
                    ],
                ),
            ],
        ),
        html.Div(
            className="rt-spec-grid",
            children=[
                html.Div(
                    className="rt-spec",
                    children=[
                        html.Span("Stream Status"),
                        html.P(id="rt-status", className="text-highlight-black rt-value"),
                    ],
                ),
                html.Div(
                    className="rt-spec",
                    children=[
                        html.Span("Pipeline Latency"),
                        html.P(id="rt-latency", className="text-highlight-black rt-value"),
                    ],
                ),
                html.Div(
                    className="rt-spec",
                    children=[
                        html.Span("Incident Velocity"),
                        html.P(id="rt-velocity", className="text-highlight-black rt-value"),
                    ],
                ),
                html.Div(
                    className="rt-spec",
                    children=[
                        html.Span("Anomaly Rate (1h)"),
                        html.P(id="rt-anomaly-rate", className="text-highlight-black rt-value"),
                    ],
                ),
                html.Div(
                    className="rt-spec",
                    children=[
                        html.Span("Freshness"),
                        html.P(id="rt-freshness", className="text-highlight-black rt-value"),
                    ],
                ),
                html.Div(
                    className="rt-spec",
                    children=[
                        html.Span("Coverage Window"),
                        html.P(id="rt-coverage", className="text-highlight-black rt-value"),
                    ],
                ),
                html.Div(
                    className="rt-spec",
                    children=[
                        html.Span("Signal Quality"),
                        html.P(id="rt-signal-quality", className="text-highlight-black rt-value"),
                    ],
                ),
                html.Div(
                    className="rt-spec",
                    children=[
                        html.Span("Last Sync"),
                        html.P(id="rt-last-sync", className="text-highlight-black rt-value"),
                    ],
                ),
            ],
        ),
        html.Div(
            className="kpi-grid",
            children=[
                html.Div(className="kpi", children=[html.Span("Total Incidents"), html.H2(id="kpi-total")]),
                html.Div(className="kpi", children=[html.Span("Average Risk"), html.H2(id="kpi-risk")]),
                html.Div(className="kpi", children=[html.Span("Anomaly Events"), html.H2(id="kpi-anomaly")]),
                html.Div(className="kpi", children=[html.Span("Critical Events"), html.H2(id="kpi-critical")]),
                html.Div(className="kpi", children=[html.Span("Top Target"), html.H2(id="kpi-target")]),
            ],
        ),
        html.Div(
            className="ai-brief-grid",
            children=[
                html.Div(
                    className="ai-brief",
                    children=[
                        html.Span("AI Threat Narrative"),
                        html.P(id="ai-narrative"),
                    ],
                ),
                html.Div(
                    className="ai-brief",
                    children=[
                        html.Span("AI Forecast Signal"),
                        html.P(id="ai-forecast"),
                    ],
                ),
                html.Div(
                    className="ai-brief",
                    children=[
                        html.Span("AI Action Recommendation"),
                        html.P(id="ai-action"),
                    ],
                ),
            ],
        ),
        html.Div(
            className="grid two",
            children=[
                html.Div(
                    className="viz-card",
                    children=[
                        html.Div(
                            className="viz-head",
                            children=[
                                html.H4("Trend & Anomaly Detection"),
                                html.Span("Temporal risk behavior"),
                            ],
                        ),
                        dcc.Graph(
                            id="trend-graph",
                            className="viz-graph",
                            style=GRAPH_STYLE,
                            config=GRAPH_CONFIG,
                        ),
                    ],
                ),
                html.Div(
                    className="viz-card",
                    children=[
                        html.Div(
                            className="viz-head",
                            children=[
                                html.H4("Attack Type Distribution"),
                                html.Span("AI clustering view"),
                            ],
                        ),
                        dcc.Graph(
                            id="type-graph",
                            className="viz-graph",
                            style=GRAPH_STYLE,
                            config=GRAPH_CONFIG,
                        ),
                    ],
                ),
            ],
        ),
        html.Div(
            className="grid two",
            children=[
                html.Div(
                    className="viz-card",
                    children=[
                        html.Div(
                            className="viz-head",
                            children=[
                                html.H4("Severity Heatmap"),
                                html.Span("Weekday × hour intensity"),
                            ],
                        ),
                        dcc.Graph(
                            id="heatmap-graph",
                            className="viz-graph",
                            style=GRAPH_STYLE,
                            config=GRAPH_CONFIG,
                        ),
                    ],
                ),
                html.Div(
                    className="viz-card",
                    children=[
                        html.Div(
                            className="viz-head",
                            children=[
                                html.H4("Geospatial Risk Mapping"),
                                html.Span("Origin-to-target attack routes"),
                            ],
                        ),
                        dcc.Graph(
                            id="geo-graph",
                            className="viz-graph",
                            style=GRAPH_STYLE,
                            config=GRAPH_CONFIG,
                        ),
                    ],
                ),
            ],
        ),
        html.Div(
            className="grid two",
            children=[
                html.Div(
                    className="viz-card",
                    children=[
                        html.Div(
                            className="viz-head",
                            children=[
                                html.H4("MITRE ATT&CK Treemap"),
                                html.Span("Tactic and technique prioritization"),
                            ],
                        ),
                        dcc.Graph(
                            id="treemap-graph",
                            className="viz-graph",
                            style=GRAPH_STYLE,
                            config=GRAPH_CONFIG,
                        ),
                    ],
                ),
                html.Div(
                    className="viz-card",
                    children=[
                        html.Div(
                            className="viz-head",
                            children=[
                                html.H4("System Impact Sunburst"),
                                html.Span("Blast radius perspective"),
                            ],
                        ),
                        dcc.Graph(
                            id="sunburst-graph",
                            className="viz-graph",
                            style=GRAPH_STYLE,
                            config=GRAPH_CONFIG,
                        ),
                    ],
                ),
            ],
        ),
        html.Div(
            className="table-wrap",
            children=[
                html.H3("AI-Prioritized Vulnerability Table"),
                html.P(
                    "Target hotspots ranked by volume, risk, anomalies, and criticality.",
                    className="muted",
                ),
                dash_table.DataTable(
                    id="hotspot-table",
                    columns=[
                        {"name": "Target Country", "id": "target_country"},
                        {"name": "Target System", "id": "target_system"},
                        {"name": "MITRE Technique", "id": "mitre_technique"},
                        {"name": "Incidents", "id": "incidents", "type": "numeric"},
                        {"name": "Avg Risk", "id": "avg_risk", "type": "numeric"},
                        {"name": "Critical", "id": "critical", "type": "numeric"},
                        {"name": "Anomalies", "id": "anomalies", "type": "numeric"},
                        {"name": "Priority", "id": "priority", "type": "numeric"},
                    ],
                    data=[],
                    page_size=12,
                    style_as_list_view=True,
                    style_table={"overflowX": "auto"},
                    style_header={
                        "backgroundColor": "#1e293b",
                        "color": "#f8fafc",
                        "fontWeight": "700",
                        "border": "1px solid #334155",
                    },
                    style_cell={
                        "backgroundColor": "#0f172a",
                        "color": "#cbd5e1",
                        "padding": "10px",
                        "border": "1px solid #1e293b",
                        "fontSize": "13px",
                    },
                    style_data_conditional=[
                        {
                            "if": {"filter_query": "{priority} >= 75"},
                            "backgroundColor": "#3f1d2e",
                            "color": "#fecdd3",
                        }
                    ],
                ),
            ],
        ),
        html.Div(
            className="connect-wrap",
            children=[
                html.H3("Connect", className="text-highlight-black"),
                html.Div(
                    className="connect-grid",
                    children=[
                        html.Div(
                            className="connect-item",
                            children=[
                                html.Span("Name"),
                                html.P("Vedant Kasaudhan", className="text-highlight-black"),
                            ],
                        ),
                        html.Div(
                            className="connect-item",
                            children=[
                                html.Span("Email"),
                                html.A(
                                    "vedantkasaudhan0@gmail.com",
                                    href="mailto:vedantkasaudhan0@gmail.com",
                                    className="connect-link text-highlight-black",
                                ),
                            ],
                        ),
                        html.Div(
                            className="connect-item",
                            children=[
                                html.Span("LinkedIn"),
                                html.A(
                                    "linkedin.com/in/vedant-kasaudhan-9a444a291",
                                    href="https://www.linkedin.com/in/vedant-kasaudhan-9a444a291/",
                                    target="_blank",
                                    rel="noopener noreferrer",
                                    className="connect-link text-highlight-black",
                                ),
                            ],
                        ),
                    ],
                ),
            ],
        ),
        html.Div(
            className="footer",
            children="AI-enhanced dashboard built with Dash + Plotly for analyst and executive cybersecurity decision support",
        ),
    ],
)


@app.callback(
    Output("kpi-total", "children"),
    Output("kpi-risk", "children"),
    Output("kpi-anomaly", "children"),
    Output("kpi-critical", "children"),
    Output("kpi-target", "children"),
    Output("rt-status", "children"),
    Output("rt-latency", "children"),
    Output("rt-velocity", "children"),
    Output("rt-anomaly-rate", "children"),
    Output("rt-freshness", "children"),
    Output("rt-coverage", "children"),
    Output("rt-signal-quality", "children"),
    Output("rt-last-sync", "children"),
    Output("ai-narrative", "children"),
    Output("ai-forecast", "children"),
    Output("ai-action", "children"),
    Output("trend-graph", "figure"),
    Output("type-graph", "figure"),
    Output("heatmap-graph", "figure"),
    Output("geo-graph", "figure"),
    Output("treemap-graph", "figure"),
    Output("sunburst-graph", "figure"),
    Output("hotspot-table", "data"),
    Input("live-interval", "n_intervals"),
    Input("date-range", "start_date"),
    Input("date-range", "end_date"),
    Input("severity-filter", "value"),
    Input("event-filter", "value"),
    Input("source-filter", "value"),
    Input("tactic-filter", "value"),
)
def refresh(
    n_intervals: int,
    start_date: str | None,
    end_date: str | None,
    severities: list[str] | None,
    event_types: list[str] | None,
    sources: list[str] | None,
    tactics: list[str] | None,
):
    _ = n_intervals
    live_df = load_dataset()
    filtered = apply_filters(live_df, start_date, end_date, severities, event_types, sources, tactics)
    rt_status, rt_latency, rt_velocity, rt_anomaly_rate, rt_freshness, rt_coverage, rt_signal_quality, rt_last_sync = (
        build_realtime_specs(live_df, filtered)
    )

    if filtered.empty:
        return (
            "0",
            "0.00",
            "0",
            "0",
            "N/A",
            rt_status,
            rt_latency,
            rt_velocity,
            rt_anomaly_rate,
            rt_freshness,
            rt_coverage,
            rt_signal_quality,
            rt_last_sync,
            "No AI narrative available for the current filter selection.",
            "No AI forecast available because there are no incidents in range.",
            "No AI recommendation available without hotspot activity.",
            empty_fig("Trend & Anomaly Detection"),
            empty_fig("Attack Type Distribution"),
            empty_fig("Severity Heatmap (Weekday × Hour UTC)"),
            empty_fig("Geospatial Risk Mapping"),
            empty_fig("MITRE ATT&CK Treemap"),
            empty_fig("System Impact Sunburst"),
            [],
        )

    total = len(filtered)
    avg_risk = float(filtered["risk_score"].mean())
    anomalies = int(filtered["anomaly_flag"].sum())
    critical = int((filtered["severity_label"] == "Critical").sum())
    top_target = str(filtered["target_country"].value_counts().idxmax())
    ai_narrative, ai_forecast, ai_action = build_ai_insights(filtered)

    return (
        fmt_int(total),
        f"{avg_risk:.2f}",
        fmt_int(anomalies),
        fmt_int(critical),
        top_target,
        rt_status,
        rt_latency,
        rt_velocity,
        rt_anomaly_rate,
        rt_freshness,
        rt_coverage,
        rt_signal_quality,
        rt_last_sync,
        ai_narrative,
        ai_forecast,
        ai_action,
        trend_chart(filtered),
        type_pie(filtered),
        severity_heatmap(filtered),
        geo_map(filtered),
        mitre_treemap(filtered),
        impact_sunburst(filtered),
        hotspot_rows(filtered),
    )


@app.callback(
    Output("download-report", "data"),
    Input("download-btn", "n_clicks"),
    State("date-range", "start_date"),
    State("date-range", "end_date"),
    State("severity-filter", "value"),
    State("event-filter", "value"),
    State("source-filter", "value"),
    State("tactic-filter", "value"),
    prevent_initial_call=True,
)
def download_report(
    n_clicks: int,
    start_date: str | None,
    end_date: str | None,
    severities: list[str] | None,
    event_types: list[str] | None,
    sources: list[str] | None,
    tactics: list[str] | None,
):
    if not n_clicks:
        raise PreventUpdate

    live_df = load_dataset()
    filtered = apply_filters(live_df, start_date, end_date, severities, event_types, sources, tactics)
    report = build_executive_report(filtered, start_date, end_date)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    return {
        "content": report,
        "filename": f"executive_cyber_risk_report_{stamp}.txt",
    }


if __name__ == "__main__":
    app.run(debug=False)
