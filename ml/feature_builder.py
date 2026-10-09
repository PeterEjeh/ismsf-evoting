"""Feature Builder for 5-minute telemetry windows.

Aggregates event streams into 5-minute windows and computes behavioral features:
- event_count: Total event frequency in the window
- vote_count: Volume of cast ballot events
- failed_login_ratio: Ratio of failed logins to total authentication attempts
- inter_arrival_variance: Variance of delta-t between consecutive events
- distinct_ip_count: Count of unique IP addresses (where available)
- ip_entropy: Shannon entropy over the IP distribution (where available)

Ensures that normal_windows.csv contains exclusively normal-labeled rows.
"""

import os
import sys
import math
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import pandas as pd
import numpy as np


FEATURE_COLUMNS_CORE = [
    "event_count",
    "vote_count",
    "failed_login_ratio",
    "inter_arrival_variance"
]

FEATURE_COLUMNS_FULL = FEATURE_COLUMNS_CORE + [
    "distinct_ip_count",
    "ip_entropy"
]


def calculate_ip_entropy(ip_series: pd.Series) -> float:
    """Calculate Shannon entropy for IP address distribution."""
    valid_ips = ip_series.dropna()
    if valid_ips.empty:
        return 0.0
    counts = valid_ips.value_counts()
    total = len(valid_ips)
    probabilities = counts / total
    entropy = -sum(p * math.log2(p) for p in probabilities if p > 0)
    return float(entropy)


def extract_features_from_events(
    events_df: pd.DataFrame,
    window_start: datetime,
    window_end: datetime,
    source: str = "trial"
) -> Dict[str, Any]:
    """Compute mathematical features for a given slice of events in a 5-minute window."""
    if events_df.empty:
        return {
            "window_start": window_start,
            "window_end": window_end,
            "source": source,
            "event_count": 0,
            "vote_count": 0,
            "failed_login_ratio": 0.0,
            "inter_arrival_variance": 0.0,
            "distinct_ip_count": 0,
            "ip_entropy": 0.0,
            "ground_truth_label": "normal"
        }

    # Sort events chronologically
    sorted_df = events_df.sort_values("timestamp")
    event_count = len(sorted_df)

    # Vote count
    vote_count = int((sorted_df["event_type"] == "vote").sum())

    # Authentication failure ratio
    auth_fail_count = int((sorted_df["event_type"] == "auth_fail").sum())
    login_count = int((sorted_df["event_type"] == "login").sum())
    total_login_attempts = auth_fail_count + login_count
    failed_login_ratio = float(auth_fail_count / total_login_attempts) if total_login_attempts > 0 else 0.0

    # Inter-arrival variance
    if event_count >= 2:
        ts_series = pd.to_datetime(sorted_df["timestamp"])
        deltas = ts_series.diff().dt.total_seconds().dropna()
        inter_arrival_variance = float(deltas.var(ddof=1)) if len(deltas) > 1 else 0.0
        if math.isnan(inter_arrival_variance):
            inter_arrival_variance = 0.0
    else:
        inter_arrival_variance = 0.0

    # IP metrics
    has_ips = sorted_df["ip_address"].dropna()
    if not has_ips.empty:
        distinct_ip_count = int(has_ips.nunique())
        ip_entropy = calculate_ip_entropy(sorted_df["ip_address"])
    else:
        distinct_ip_count = 1  # Default single entity
        ip_entropy = 0.0

    # Ground truth determination
    if "ground_truth_label" in sorted_df.columns:
        labels = sorted_df["ground_truth_label"].dropna().unique()
        ground_truth_label = "anomalous" if "anomalous" in labels else "normal"
    else:
        ground_truth_label = "normal"

    return {
        "window_start": window_start,
        "window_end": window_end,
        "source": source,
        "event_count": event_count,
        "vote_count": vote_count,
        "failed_login_ratio": failed_login_ratio,
        "inter_arrival_variance": inter_arrival_variance,
        "distinct_ip_count": distinct_ip_count,
        "ip_entropy": ip_entropy,
        "ground_truth_label": ground_truth_label
    }


def build_windows_from_events(
    events_df: pd.DataFrame,
    window_minutes: int = 5,
    slide_minutes: int = 5
) -> pd.DataFrame:
    """Group an event stream into 5-minute windows and extract feature vectors."""
    if events_df.empty:
        return pd.DataFrame()

    events_df = events_df.copy()
    events_df["timestamp"] = pd.to_datetime(events_df["timestamp"], utc=True)
    events_df = events_df.sort_values("timestamp")

    min_time = events_df["timestamp"].min().floor(f"{window_minutes}min")
    max_time = events_df["timestamp"].max().ceil(f"{window_minutes}min")

    windows = []
    current_start = min_time

    # Group by source or process together
    sources = events_df["source"].unique()

    for src in sources:
        src_df = events_df[events_df["source"] == src]
        curr = src_df["timestamp"].min().floor(f"{window_minutes}min")
        src_max = src_df["timestamp"].max()

        while curr <= src_max:
            curr_end = curr + timedelta(minutes=window_minutes)
            mask = (src_df["timestamp"] >= curr) & (src_df["timestamp"] < curr_end)
            win_events = src_df[mask]

            if not win_events.empty:
                feats = extract_features_from_events(win_events, curr, curr_end, source=src)
                windows.append(feats)

            curr += timedelta(minutes=slide_minutes)

    result_df = pd.DataFrame(windows)
    return result_df


def build_and_save_normal_windows(
    voteograph_dir: str = "data/raw/voteograph",
    cvr_path: str = "data/raw/cvr/cvr_sample.parquet",
    hdfs_log_path: str = "data/raw/hdfs/HDFS_sample.csv",
    hdfs_label_path: str = "data/raw/hdfs/anomaly_label.csv",
    bgl_log_path: str = "data/raw/bgl/BGL_sample.csv",
    output_path: str = "data/processed/normal_windows.csv"
) -> pd.DataFrame:
    """Load all raw datasets (filtering normal only) and build normal_windows.csv."""
    from ml.sourcing.voteograph_loader import load_voteograph_data
    from ml.sourcing.cvr_loader import load_cvr_data
    from ml.sourcing.hdfs_loader import load_hdfs_data
    from ml.sourcing.bgl_loader import load_bgl_data

    dfs = []

    # 1. Vote-o-graph
    vg_df = load_voteograph_data(voteograph_dir)
    if not vg_df.empty:
        dfs.append(vg_df)

    # 2. CVR
    cvr_df = load_cvr_data(cvr_path)
    if not cvr_df.empty:
        dfs.append(cvr_df)

    # 3. HDFS (Filter normal only!)
    hdfs_df = load_hdfs_data(hdfs_log_path, hdfs_label_path, filter_normal_only=True)
    if not hdfs_df.empty:
        dfs.append(hdfs_df)

    # 4. BGL (Filter normal only!)
    bgl_df = load_bgl_data(bgl_log_path, filter_normal_only=True)
    if not bgl_df.empty:
        dfs.append(bgl_df)

    all_normal_events = pd.concat(dfs, ignore_index=True)

    # Compute 5-minute feature windows
    windows_df = build_windows_from_events(all_normal_events, window_minutes=5)

    # Assert strict normal only guarantee
    assert (windows_df["ground_truth_label"] == "normal").all(), (
        "CRITICAL ERROR: Labeled anomaly leaked into normal training windows!"
    )

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    windows_df.to_csv(output_path, index=False)
    print(f"Successfully saved {len(windows_df)} verified normal windows to {output_path}")
    return windows_df


if __name__ == "__main__":
    build_and_save_normal_windows()
