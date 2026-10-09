"""HDFS Log Loader (LogHub format).

Parses structured HDFS log CSVs and associates them with anomaly labels.
Ensures strict segregation: normal rows for training, anomalous rows reserved
for cross-benchmark evaluation.

Standard schema:
    timestamp, session_id, event_type, ip_address, source, ground_truth_label
"""

import os
import re
from datetime import datetime, timezone
from typing import Optional, Dict
import pandas as pd


def load_hdfs_anomaly_labels(label_file_path: str) -> Dict[str, str]:
    """Load HDFS block anomaly labels mapping BlockId -> 'normal' | 'anomalous'."""
    labels = {}
    if not os.path.exists(label_file_path):
        return labels

    df = pd.read_csv(label_file_path)
    # Expected columns: BlockId, Label (Normal / Anomaly)
    for _, row in df.iterrows():
        b_id = str(row.get("BlockId") or row.get("block_id")).strip()
        raw_label = str(row.get("Label") or row.get("label")).strip().lower()
        labels[b_id] = "anomalous" if "anom" in raw_label else "normal"
    return labels


def load_hdfs_data(
    log_file_path: str,
    label_file_path: Optional[str] = None,
    filter_normal_only: bool = True,
    max_rows: Optional[int] = None
) -> pd.DataFrame:
    """Parse structured HDFS logs into the standard telemetry schema.
    
    Args:
        log_file_path: Path to structured HDFS CSV file.
        label_file_path: Path to anomaly_label.csv if available.
        filter_normal_only: If True, filters out anomalous rows (for training).
                            If False, retains all rows with ground_truth_label (for evaluation).
        max_rows: Optional row limit for fast processing.
    """
    if not os.path.exists(log_file_path):
        return pd.DataFrame(columns=[
            "timestamp", "session_id", "event_type", "ip_address", "source", "ground_truth_label"
        ])

    block_labels = load_hdfs_anomaly_labels(label_file_path) if label_file_path else {}

    df = pd.read_csv(log_file_path, nrows=max_rows)
    events = []

    block_regex = re.compile(r"(blk_[-0-9]+)")

    for idx, row in df.iterrows():
        # Handle date/time parsing
        date_str = str(row.get("Date") or "081109")
        time_str = str(row.get("Time") or "203515")
        try:
            # Format like '081109 203515' (YYMMDD HHMMSS)
            if len(date_str) == 6 and len(time_str) >= 6:
                dt = datetime.strptime(f"{date_str} {time_str[:6]}", "%y%m%d %H%M%S")
                dt = dt.replace(tzinfo=timezone.utc)
            else:
                dt = pd.to_datetime(f"{date_str} {time_str}", utc=True).to_pydatetime()
        except Exception:
            dt = datetime.now(timezone.utc)

        # Extract session / block identifier from content or component
        content = str(row.get("Content") or "")
        match = block_regex.search(content)
        session_id = match.group(1) if match else f"hdfs_session_{row.get('Pid', idx)}"

        # Ground truth label
        if session_id in block_labels:
            label = block_labels[session_id]
        else:
            # Check Level column
            level = str(row.get("Level") or "INFO").upper()
            label = "anomalous" if level in ("ERROR", "FATAL", "WARN") else "normal"

        if filter_normal_only and label != "normal":
            continue

        # Map log operation to event_type
        if "received block" in content.lower() or "addstoredblock" in content.lower():
            event_type = "vote"
        elif "verification" in content.lower() or "login" in content.lower():
            event_type = "login"
        elif label == "anomalous":
            event_type = "auth_fail"
        else:
            event_type = "nav"

        events.append({
            "timestamp": dt,
            "session_id": session_id,
            "event_type": event_type,
            "ip_address": None,
            "source": "hdfs",
            "ground_truth_label": label
        })

    result_df = pd.DataFrame(events, columns=[
        "timestamp", "session_id", "event_type", "ip_address", "source", "ground_truth_label"
    ])
    if not result_df.empty:
        result_df["timestamp"] = pd.to_datetime(result_df["timestamp"], utc=True)
        result_df = result_df.sort_values("timestamp").reset_index(drop=True)
    return result_df
