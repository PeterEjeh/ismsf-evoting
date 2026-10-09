"""Cast Vote Records (CVR) Parquet Loader.

Reads Cast Vote Records (Harvard Dataverse format) from Parquet files.
Used for structural consistency checks and ballot profile validation.
"""

import os
from datetime import datetime, timezone
import pandas as pd


def load_cvr_data(file_or_dir_path: str, max_rows: int = 50000) -> pd.DataFrame:
    """Load Cast Vote Records from a Parquet file or directory.
    
    Transforms CVR rows into standard events or returns the raw dataframe
    for structural consistency verification.
    """
    if not os.path.exists(file_or_dir_path):
        return pd.DataFrame(columns=[
            "timestamp", "session_id", "event_type", "ip_address", "source", "ground_truth_label"
        ])

    files_to_read = []
    if os.path.isdir(file_or_dir_path):
        for root_dir, _, files in os.walk(file_or_dir_path):
            for file in files:
                if file.endswith((".parquet", ".pq")):
                    files_to_read.append(os.path.join(root_dir, file))
    else:
        files_to_read.append(file_or_dir_path)

    if not files_to_read:
        return pd.DataFrame(columns=[
            "timestamp", "session_id", "event_type", "ip_address", "source", "ground_truth_label"
        ])

    dfs = []
    for fp in files_to_read:
        try:
            cvr_df = pd.read_parquet(fp)
            if max_rows and len(cvr_df) > max_rows:
                cvr_df = cvr_df.head(max_rows)
            dfs.append(cvr_df)
        except Exception as e:
            print(f"Error reading CVR Parquet file {fp}: {e}")

    if not dfs:
        return pd.DataFrame(columns=[
            "timestamp", "session_id", "event_type", "ip_address", "source", "ground_truth_label"
        ])

    combined_cvr = pd.concat(dfs, ignore_index=True)

    # Standardize to common schema
    # CVR rows represent cast ballots (each ballot is a 'vote' event)
    events = []
    base_time = datetime.now(timezone.utc)
    for idx, row in combined_cvr.iterrows():
        session_id = str(row.get("cast_vote_record_id") or row.get("cvr_id") or f"cvr_ballot_{idx}")
        events.append({
            "timestamp": base_time,
            "session_id": session_id,
            "event_type": "vote",
            "ip_address": None,
            "source": "cvr",
            "ground_truth_label": "normal"
        })

    return pd.DataFrame(events)
