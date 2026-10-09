"""Mock Trial Telemetry Loader.

Loads live mock election events from the application database or exported CSV/JSON
into the standardized telemetry schema:
    timestamp, session_id, event_type, ip_address, source, ground_truth_label
"""

import os
from typing import Optional
import pandas as pd
from sqlalchemy.orm import Session


def load_trial_data_from_db(
    db_session: Session,
    trial_source_name: str = "trial",
    filter_normal_only: bool = True
) -> pd.DataFrame:
    """Fetch mock trial events directly from the application database."""
    from ingestion.db import EventModel

    query = db_session.query(EventModel).filter(EventModel.source == trial_source_name)
    if filter_normal_only:
        # If ground_truth_label is populated, filter to normal only (or unlabelled trial traffic which is normal)
        query = query.filter((EventModel.ground_truth_label == "normal") | (EventModel.ground_truth_label.is_(None)))

    rows = query.order_by(EventModel.timestamp.asc()).all()

    events = []
    for r in rows:
        events.append({
            "timestamp": r.timestamp,
            "session_id": r.session_id,
            "event_type": r.event_type,
            "ip_address": r.ip_address,
            "source": r.source,
            "ground_truth_label": r.ground_truth_label or "normal"
        })

    df = pd.DataFrame(events, columns=[
        "timestamp", "session_id", "event_type", "ip_address", "source", "ground_truth_label"
    ])
    if not df.empty:
        df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
    return df


def load_trial_data_from_file(
    file_path: str,
    filter_normal_only: bool = True
) -> pd.DataFrame:
    """Load mock trial telemetry from an exported CSV or JSON file."""
    if not os.path.exists(file_path):
        return pd.DataFrame(columns=[
            "timestamp", "session_id", "event_type", "ip_address", "source", "ground_truth_label"
        ])

    if file_path.endswith(".json"):
        df = pd.read_json(file_path)
    else:
        df = pd.read_csv(file_path)

    if filter_normal_only and "ground_truth_label" in df.columns:
        df = df[(df["ground_truth_label"] == "normal") | (df["ground_truth_label"].isna())]

    # Ensure required columns
    for col in ["timestamp", "session_id", "event_type", "ip_address", "source", "ground_truth_label"]:
        if col not in df.columns:
            df[col] = "trial" if col == "source" else None

    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
    return df.sort_values("timestamp").reset_index(drop=True)
