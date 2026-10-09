"""BGL Log Loader (LogHub format).

Parses BlueGene/L (BGL) supercomputer system logs.
The alert/non-alert tag in the first column ('-' = normal, otherwise anomalous)
is stored as ground_truth_label.

Normal rows feed training; anomalous rows are reserved for cross-benchmark testing.

Standard schema:
    timestamp, session_id, event_type, ip_address, source, ground_truth_label
"""

import os
from datetime import datetime, timezone
from typing import Optional
import pandas as pd


def load_bgl_data(
    log_file_path: str,
    filter_normal_only: bool = True,
    max_rows: Optional[int] = None
) -> pd.DataFrame:
    """Parse structured BGL logs into the standard telemetry schema.
    
    Args:
        log_file_path: Path to BGL structured CSV or raw log file.
        filter_normal_only: If True, filters out anomalous rows (for training).
                            If False, retains all rows with ground_truth_label (for evaluation).
        max_rows: Optional row limit for fast processing.
    """
    if not os.path.exists(log_file_path):
        return pd.DataFrame(columns=[
            "timestamp", "session_id", "event_type", "ip_address", "source", "ground_truth_label"
        ])

    events = []

    # Check if CSV or raw log line format
    is_csv = log_file_path.endswith(".csv")

    if is_csv:
        df = pd.read_csv(log_file_path, nrows=max_rows)
        for idx, row in df.iterrows():
            # First column or 'Label' / 'Alert'
            alert_tag = str(row.get("Label") or row.get("Alert") or row.iloc[0]).strip()
            label = "normal" if alert_tag in ("-", "None", "NORMAL", "0", "normal") else "anomalous"

            if filter_normal_only and label != "normal":
                continue

            # Timestamp parsing
            timestamp_val = row.get("Timestamp") or row.get("Time") or row.get("Date")
            try:
                dt = pd.to_datetime(timestamp_val, unit="s" if str(timestamp_val).isdigit() else None, utc=True).to_pydatetime()
            except Exception:
                dt = datetime.now(timezone.utc)

            node_id = str(row.get("Node") or row.get("Component") or f"bgl_node_{idx % 100}")

            # Map to event type
            content = str(row.get("Content") or "")
            if "login" in content.lower() or "auth" in content.lower():
                event_type = "login" if label == "normal" else "auth_fail"
            elif "job" in content.lower() or "vote" in content.lower() or "submit" in content.lower():
                event_type = "vote"
            elif label == "anomalous":
                event_type = "auth_fail"
            else:
                event_type = "nav"

            events.append({
                "timestamp": dt,
                "session_id": node_id,
                "event_type": event_type,
                "ip_address": None,
                "source": "bgl",
                "ground_truth_label": label
            })
    else:
        # Raw log format: first token is label ('-' = normal)
        count = 0
        with open(log_file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if max_rows and count >= max_rows:
                    break
                parts = line.strip().split()
                if not parts:
                    continue
                count += 1
                alert_tag = parts[0]
                label = "normal" if alert_tag == "-" else "anomalous"

                if filter_normal_only and label != "normal":
                    continue

                # Timestamp is typically the 3rd or 4th token in BGL
                dt = datetime.now(timezone.utc)
                if len(parts) > 4:
                    try:
                        ts_raw = parts[4]
                        if ts_raw.isdigit():
                            dt = datetime.fromtimestamp(int(ts_raw), tz=timezone.utc)
                    except Exception:
                        pass

                node_id = parts[3] if len(parts) > 3 else f"bgl_node_{count % 100}"
                events.append({
                    "timestamp": dt,
                    "session_id": node_id,
                    "event_type": "nav" if label == "normal" else "auth_fail",
                    "ip_address": None,
                    "source": "bgl",
                    "ground_truth_label": label
                })

    result_df = pd.DataFrame(events, columns=[
        "timestamp", "session_id", "event_type", "ip_address", "source", "ground_truth_label"
    ])
    if not result_df.empty:
        result_df["timestamp"] = pd.to_datetime(result_df["timestamp"], utc=True)
        result_df = result_df.sort_values("timestamp").reset_index(drop=True)
    return result_df
