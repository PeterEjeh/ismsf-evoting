"""Seed sample dataset generator for development and local testing.

Generates realistic local raw samples for:
- Vote-o-graph XML event logs
- Cast Vote Records (CVR) Parquet files
- LogHub HDFS structured CSV logs + anomaly_label.csv
- LogHub BGL structured CSV logs
"""

import os
from datetime import datetime, timedelta, timezone
import pandas as pd
import numpy as np


def generate_seed_data(base_data_dir: str = "data/raw"):
    """Generate realistic test fixtures in data/raw for all sources."""
    os.makedirs(os.path.join(base_data_dir, "voteograph"), exist_ok=True)
    os.makedirs(os.path.join(base_data_dir, "cvr"), exist_ok=True)
    os.makedirs(os.path.join(base_data_dir, "hdfs"), exist_ok=True)
    os.makedirs(os.path.join(base_data_dir, "bgl"), exist_ok=True)

    now = datetime(2026, 10, 14, 9, 0, 0, tzinfo=timezone.utc)

    # 1. Vote-o-graph XML Samples (20 sessions)
    for session_idx in range(1, 21):
        session_time = now + timedelta(minutes=session_idx * 5)
        xml_content = ['<?xml version="1.0" encoding="UTF-8"?>', '<session log="voteograph">']
        
        # Human navigation and voting sequence
        xml_content.append(f'  <event time="{int(session_time.timestamp())}" type="touch" target="ballot_intro"/>')
        xml_content.append(f'  <event time="{int((session_time + timedelta(seconds=12)).timestamp())}" type="touch" target="candidate_card_1"/>')
        xml_content.append(f'  <event time="{int((session_time + timedelta(seconds=25)).timestamp())}" type="touch" target="review_ballot_nav"/>')
        xml_content.append(f'  <event time="{int((session_time + timedelta(seconds=40)).timestamp())}" type="touch" target="cast_vote_button"/>')
        xml_content.append('</session>')

        file_path = os.path.join(base_data_dir, "voteograph", f"session_{session_idx:02d}.xml")
        with open(file_path, "w", encoding="utf-8") as f:
            f.write("\n".join(xml_content))

    # 2. CVR Parquet Sample (100 cast vote records)
    cvr_records = []
    for idx in range(1, 101):
        cvr_records.append({
            "cast_vote_record_id": f"cvr_{idx:05d}",
            "precinct": f"Precinct_{idx % 5 + 1}",
            "ballot_style": "General_2026",
            "contest_1_choice": f"Candidate_{(idx % 3) + 1}",
            "contest_2_choice": f"Proposal_{(idx % 2) + 1}",
            "overvotes": 0,
            "undervotes": 0
        })
    cvr_df = pd.DataFrame(cvr_records)
    cvr_df.to_parquet(os.path.join(base_data_dir, "cvr", "cvr_sample.parquet"))

    # 3. LogHub HDFS Structured Logs + Anomaly Labels (200 log entries)
    hdfs_rows = []
    anomaly_labels = []
    for idx in range(1, 201):
        block_id = f"blk_{-idx}"
        # 10% anomalies reserved for evaluation
        is_anom = (idx % 10 == 0)
        label_str = "Anomaly" if is_anom else "Normal"
        anomaly_labels.append({"BlockId": block_id, "Label": label_str})

        t = now + timedelta(seconds=idx * 15)
        date_str = t.strftime("%y%m%d")
        time_str = t.strftime("%H%M%S")
        level = "ERROR" if is_anom else "INFO"
        content = f"Received block {block_id} src: /10.0.0.1 dest: /10.0.0.2" if not is_anom else f"Verification failed for {block_id}"

        hdfs_rows.append({
            "LineId": idx,
            "Date": date_str,
            "Time": time_str,
            "Pid": 1000 + (idx % 5),
            "Level": level,
            "Component": "DataNode",
            "Content": content,
            "EventId": "E1" if not is_anom else "E99",
            "EventTemplate": "template_content"
        })

    pd.DataFrame(hdfs_rows).to_csv(os.path.join(base_data_dir, "hdfs", "HDFS_sample.csv"), index=False)
    pd.DataFrame(anomaly_labels).to_csv(os.path.join(base_data_dir, "hdfs", "anomaly_label.csv"), index=False)

    # 4. LogHub BGL Structured Logs (200 log entries)
    bgl_rows = []
    for idx in range(1, 201):
        t = now + timedelta(seconds=idx * 12)
        is_anom = (idx % 12 == 0)
        alert_tag = "FATAL" if is_anom else "-"
        bgl_rows.append({
            "Label": alert_tag,
            "Timestamp": int(t.timestamp()),
            "Date": t.strftime("%Y-%m-%d"),
            "Node": f"R{idx % 16:02d}-M0-N0-C:J00-U01",
            "Time": t.strftime("%H:%M:%S"),
            "NodeRepeat": "normal",
            "Type": "NULL",
            "Component": "KERNEL",
            "Level": "FATAL" if is_anom else "INFO",
            "Content": "Authentication memory fault failure" if is_anom else "Job navigation step verification succeeded"
        })

    pd.DataFrame(bgl_rows).to_csv(os.path.join(base_data_dir, "bgl", "BGL_sample.csv"), index=False)
    print("Successfully generated raw dataset samples in", base_data_dir)


if __name__ == "__main__":
    generate_seed_data()
