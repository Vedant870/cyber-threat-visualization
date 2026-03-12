from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Sequence, Tuple

import numpy as np
import pandas as pd

BASE_DIR = Path(__file__).resolve().parent
RAW_DATA_PATH = BASE_DIR.parent / "data" / "threat_events.csv"
OUTPUT_DATA_PATH = BASE_DIR / "data" / "structured_threat_events.csv"

EVENT_PROFILES: Dict[str, Dict[str, object]] = {
    "malware": {
        "mitre_tactic": "Execution",
        "mitre_technique": "T1059 - Command and Scripting Interpreter",
        "targets": ["Workstation", "Application Server", "Shared Endpoint"],
        "attack_stage": "Payload Execution",
        "weight": 1.18,
    },
    "phishing": {
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1566 - Phishing",
        "targets": ["Mail Gateway", "Employee Mailbox", "SSO Portal"],
        "attack_stage": "Credential Harvesting",
        "weight": 1.08,
    },
    "ddos": {
        "mitre_tactic": "Impact",
        "mitre_technique": "T1498 - Network Denial of Service",
        "targets": ["Perimeter Gateway", "Public API", "CDN Edge"],
        "attack_stage": "Service Disruption",
        "weight": 1.24,
    },
    "bruteforce": {
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1110 - Brute Force",
        "targets": ["Identity Provider", "VPN Gateway", "Privileged Console"],
        "attack_stage": "Account Takeover Attempt",
        "weight": 1.14,
    },
    "ransomware": {
        "mitre_tactic": "Impact",
        "mitre_technique": "T1486 - Data Encrypted for Impact",
        "targets": ["Database Cluster", "File Server", "Backup Repository"],
        "attack_stage": "Data Encryption",
        "weight": 1.32,
    },
}

SOURCE_RISK = {
    "endpoint": 1.10,
    "email": 1.00,
    "network": 1.22,
    "auth": 1.16,
}

COUNTRY_COORDS: Dict[str, Tuple[float, float]] = {
    "United States": (37.0902, -95.7129),
    "India": (20.5937, 78.9629),
    "Germany": (51.1657, 10.4515),
    "United Kingdom": (55.3781, -3.4360),
    "Brazil": (-14.2350, -51.9253),
    "Russia": (61.5240, 105.3188),
    "China": (35.8617, 104.1954),
    "Singapore": (1.3521, 103.8198),
    "Australia": (-25.2744, 133.7751),
    "United Arab Emirates": (23.4241, 53.8478),
    "South Africa": (-30.5595, 22.9375),
}

COUNTRY_RISK = {
    "United States": 1.05,
    "India": 1.10,
    "Germany": 1.03,
    "United Kingdom": 1.04,
    "Brazil": 1.16,
    "Russia": 1.28,
    "China": 1.20,
    "Singapore": 1.08,
    "Australia": 1.02,
    "United Arab Emirates": 1.12,
    "South Africa": 1.18,
}

DEFAULT_ORIGIN_DISTRIBUTION: List[Tuple[str, float]] = [
    ("Russia", 0.20),
    ("China", 0.16),
    ("Brazil", 0.12),
    ("India", 0.10),
    ("United States", 0.09),
    ("United Kingdom", 0.08),
    ("Germany", 0.08),
    ("Singapore", 0.07),
    ("United Arab Emirates", 0.05),
    ("South Africa", 0.05),
]

ORIGIN_BY_EVENT: Dict[str, List[Tuple[str, float]]] = {
    "malware": [
        ("Russia", 0.22),
        ("China", 0.20),
        ("Brazil", 0.13),
        ("India", 0.10),
        ("United States", 0.09),
        ("United Arab Emirates", 0.08),
        ("South Africa", 0.07),
        ("United Kingdom", 0.06),
        ("Germany", 0.05),
    ],
    "phishing": [
        ("United States", 0.17),
        ("India", 0.15),
        ("Russia", 0.13),
        ("China", 0.13),
        ("Brazil", 0.10),
        ("United Kingdom", 0.09),
        ("Germany", 0.08),
        ("Singapore", 0.08),
        ("United Arab Emirates", 0.07),
    ],
    "ddos": [
        ("Russia", 0.22),
        ("China", 0.20),
        ("Brazil", 0.14),
        ("United States", 0.11),
        ("India", 0.10),
        ("Germany", 0.08),
        ("United Kingdom", 0.07),
        ("Singapore", 0.05),
        ("South Africa", 0.03),
    ],
    "bruteforce": [
        ("Russia", 0.18),
        ("China", 0.16),
        ("India", 0.14),
        ("Brazil", 0.11),
        ("United States", 0.11),
        ("United Kingdom", 0.10),
        ("Germany", 0.10),
        ("United Arab Emirates", 0.06),
        ("Singapore", 0.04),
    ],
    "ransomware": [
        ("Russia", 0.24),
        ("China", 0.19),
        ("Brazil", 0.13),
        ("United States", 0.11),
        ("India", 0.10),
        ("Germany", 0.09),
        ("United Kingdom", 0.08),
        ("South Africa", 0.06),
    ],
}

TARGET_DISTRIBUTION: List[Tuple[str, float]] = [
    ("India", 0.29),
    ("United States", 0.23),
    ("Germany", 0.14),
    ("Singapore", 0.11),
    ("United Kingdom", 0.10),
    ("Australia", 0.08),
    ("United Arab Emirates", 0.05),
]

ORG_UNITS = [
    "Finance",
    "Operations",
    "Engineering",
    "Sales",
    "Support",
    "Executive",
]
ORG_UNIT_WEIGHTS = np.array([0.19, 0.16, 0.28, 0.12, 0.17, 0.08], dtype=float)
ORG_UNIT_WEIGHTS /= ORG_UNIT_WEIGHTS.sum()


def weighted_pick(rng: np.random.Generator, choices: Sequence[Tuple[str, float]]) -> str:
    labels, weights = zip(*choices)
    probabilities = np.array(weights, dtype=float)
    probabilities /= probabilities.sum()
    return str(rng.choice(labels, p=probabilities))


def severity_to_label(severity: int) -> str:
    if severity <= 3:
        return "Low"
    if severity <= 6:
        return "Medium"
    if severity <= 8:
        return "High"
    return "Critical"


def normalize_raw_events(df: pd.DataFrame) -> pd.DataFrame:
    cleaned = df.copy()
    cleaned = cleaned.drop_duplicates(subset=["event_id"]).reset_index(drop=True)
    cleaned["timestamp"] = pd.to_datetime(cleaned["timestamp"], errors="coerce", utc=True)
    cleaned = cleaned.dropna(subset=["timestamp"])

    cleaned["event_type"] = cleaned["event_type"].astype(str).str.lower().str.strip()
    cleaned["source"] = cleaned["source"].astype(str).str.lower().str.strip()
    cleaned["severity"] = (
        pd.to_numeric(cleaned["severity"], errors="coerce").fillna(5).round().clip(1, 10).astype(int)
    )
    cleaned["detections"] = (
        pd.to_numeric(cleaned["detections"], errors="coerce").fillna(1).round().clip(1, 99).astype(int)
    )
    cleaned = cleaned.sort_values("timestamp").reset_index(drop=True)
    return cleaned


def build_structured_dataset(
    raw_path: Path = RAW_DATA_PATH,
    output_path: Path = OUTPUT_DATA_PATH,
    days: int = 150,
    seed: int = 42,
) -> Path:
    raw_df = pd.read_csv(raw_path)
    raw_df = normalize_raw_events(raw_df)

    rng = np.random.default_rng(seed)
    event_keys = list(EVENT_PROFILES.keys())
    source_keys = list(SOURCE_RISK.keys())

    start_date = pd.Timestamp.utcnow().tz_localize(None).normalize() - pd.Timedelta(days=days)
    rows: List[Dict[str, object]] = []
    event_counter = 1

    for day_idx in range(days):
        day_anchor = start_date + pd.Timedelta(days=day_idx)
        daily_events = int(rng.integers(6, 15))
        sampled = raw_df.sample(n=daily_events, replace=True, random_state=seed + day_idx)

        for _, base_event in sampled.iterrows():
            event_type = str(base_event["event_type"])
            if event_type not in EVENT_PROFILES or rng.random() < 0.08:
                event_type = str(rng.choice(event_keys))

            source = str(base_event["source"])
            if source not in SOURCE_RISK or rng.random() < 0.08:
                source = str(rng.choice(source_keys))

            profile = EVENT_PROFILES[event_type]

            severity = int(np.clip(round(float(base_event["severity"]) + rng.normal(0, 1.5)), 1, 10))
            detections = int(max(1, round(float(base_event["detections"]) + rng.normal(0, 1.3))))

            timestamp = day_anchor + pd.Timedelta(minutes=int(rng.integers(0, 24 * 60)))
            origin_country = weighted_pick(
                rng, ORIGIN_BY_EVENT.get(event_type, DEFAULT_ORIGIN_DISTRIBUTION)
            )
            target_country = weighted_pick(rng, TARGET_DISTRIBUTION)
            origin_lat, origin_lon = COUNTRY_COORDS[origin_country]
            target_lat, target_lon = COUNTRY_COORDS[target_country]

            severity_label = severity_to_label(severity)
            source_factor = SOURCE_RISK[source]
            geo_factor = COUNTRY_RISK.get(origin_country, 1.0)
            threat_weight = float(profile["weight"])

            raw_risk = (
                (severity * 8)
                + (detections * 4)
                + (threat_weight * 14)
                + (source_factor * 10)
                + (geo_factor * 9)
            ) * rng.uniform(0.88, 1.15)
            risk_score = round(min(100.0, raw_risk / 1.9), 2)

            anomaly_flag = risk_score >= 75 or (severity >= 9 and detections >= 6)
            target_system = str(rng.choice(profile["targets"]))
            org_unit = str(rng.choice(ORG_UNITS, p=ORG_UNIT_WEIGHTS))

            rows.append(
                {
                    "event_id": f"CTE-{event_counter:06d}",
                    "event_type": event_type,
                    "severity": severity,
                    "severity_label": severity_label,
                    "source": source,
                    "detections": detections,
                    "timestamp": timestamp,
                    "event_date": timestamp.date().isoformat(),
                    "hour_utc": int(timestamp.hour),
                    "mitre_tactic": profile["mitre_tactic"],
                    "mitre_technique": profile["mitre_technique"],
                    "attack_stage": profile["attack_stage"],
                    "target_system": target_system,
                    "organization_unit": org_unit,
                    "origin_country": origin_country,
                    "origin_lat": origin_lat,
                    "origin_lon": origin_lon,
                    "target_country": target_country,
                    "target_lat": target_lat,
                    "target_lon": target_lon,
                    "geo_risk_factor": round(geo_factor, 2),
                    "risk_score": risk_score,
                    "anomaly_flag": anomaly_flag,
                }
            )
            event_counter += 1

    structured_df = pd.DataFrame(rows).sort_values("timestamp").reset_index(drop=True)
    structured_df["timestamp"] = structured_df["timestamp"].dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    structured_df.to_csv(output_path, index=False)
    return output_path


if __name__ == "__main__":
    output_file = build_structured_dataset()
    generated = pd.read_csv(output_file)
    print(f"Structured dataset generated at: {output_file}")
    print(f"Rows: {len(generated)} | Columns: {len(generated.columns)}")
    print(
        "Coverage:",
        generated["timestamp"].min(),
        "to",
        generated["timestamp"].max(),
    )

