"""Vote-o-graph XML Event Loader.

Parses Vote-o-graph touch and release event logs into the standardized
ingestion contract:
    {
        'timestamp': datetime,
        'session_id': str,
        'event_type': str,  # 'nav' | 'vote'
        'ip_address': None,
        'source': 'voteograph'
    }
"""

import os
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
import xml.etree.ElementTree as ET
import pandas as pd


def parse_voteograph_file(file_path: str) -> List[Dict[str, Any]]:
    """Parse a single Vote-o-graph XML session file."""
    events = []
    session_id = os.path.splitext(os.path.basename(file_path))[0]

    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
    except Exception as e:
        print(f"Error parsing Vote-o-graph XML file {file_path}: {e}")
        return events

    # Vote-o-graph XML files contain <event> tags with timestamp, action, type attributes/children
    # e.g., <event time="1234567890" type="touch" target="candidate_1"/>
    for elem in root.iter():
        if elem.tag in ("event", "action", "touch", "log"):
            time_val = elem.attrib.get("time") or elem.attrib.get("timestamp") or elem.attrib.get("t")
            event_kind = elem.attrib.get("type") or elem.attrib.get("action") or elem.tag
            target = elem.attrib.get("target") or elem.attrib.get("button") or elem.text or ""

            # Classify into 'vote' vs 'nav'
            if any(k in str(target).lower() for k in ("vote", "cast", "ballot", "candidate", "submit")):
                event_type = "vote"
            else:
                event_type = "nav"

            # Parse or synthesize timestamp
            dt: datetime
            if time_val:
                try:
                    ts_float = float(time_val)
                    # Detect if timestamp is milliseconds or seconds
                    if ts_float > 1e11:
                        ts_float /= 1000.0
                    dt = datetime.fromtimestamp(ts_float, tz=timezone.utc)
                except ValueError:
                    try:
                        dt = datetime.fromisoformat(time_val)
                        if dt.tzinfo is None:
                            dt = dt.replace(tzinfo=timezone.utc)
                    except ValueError:
                        dt = datetime.now(timezone.utc)
            else:
                dt = datetime.now(timezone.utc)

            events.append({
                "timestamp": dt,
                "session_id": session_id,
                "event_type": event_type,
                "ip_address": None,
                "source": "voteograph",
                "ground_truth_label": "normal"
            })

    return events


def load_voteograph_data(directory_path: str) -> pd.DataFrame:
    """Load and combine all Vote-o-graph XML logs from directory into a DataFrame."""
    all_events = []
    if os.path.exists(directory_path):
        for root_dir, _, files in os.walk(directory_path):
            for file in files:
                if file.endswith((".xml", ".log")):
                    file_path = os.path.join(root_dir, file)
                    all_events.extend(parse_voteograph_file(file_path))

    df = pd.DataFrame(all_events, columns=[
        "timestamp", "session_id", "event_type", "ip_address", "source", "ground_truth_label"
    ])
    if not df.empty:
        df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
        df = df.sort_values("timestamp").reset_index(drop=True)
    return df
