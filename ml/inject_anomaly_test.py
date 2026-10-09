"""Live Red-Team Anomaly Injection Test Harness.

Executes live simulated red-team attacks against the running ISMSF ingestion API:
1. Credential Stuffing: 25 rapid failed logins on a single account.
2. Bot-Driven Vote Stuffing: 30 automated ballot submissions with sub-second interval.
3. Off-Hours Surge: Burst of traffic with anomalous timing density.
4. Access-Endpoint Probing: High-frequency probing on administrative / invalid endpoints.

Records exact ground-truth injection windows and alert detections into
evidence/injection_test_log.json.
"""

import os
import sys
import time
import json
import uuid
from datetime import datetime, timezone
import httpx

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


def run_injection_harness(
    base_url: str = "http://127.0.0.1:8000",
    evidence_path: str = "evidence/injection_test_log.json"
):
    """Run all 4 red-team attack scenarios against the live API and log evidence."""
    client = httpx.Client(base_url=base_url, timeout=10.0)

    print(f"Connecting to live ISMSF ingestion service at {base_url}...")
    try:
        health = client.get("/api/current-window-score")
        if health.status_code != 200:
            print("Error: API returned status", health.status_code)
            return False
    except Exception as e:
        print(f"Could not connect to API at {base_url}: {e}")
        print("Please ensure the FastAPI service is running: uvicorn ingestion.main:app --port 8000")
        return False

    injection_results = []
    print("\n--- BEGIN RED-TEAM LIVE ANOMALY INJECTION HARNESS ---")

    # =========================================================================
    # Attack 1: Credential Stuffing (25 rapid auth_fail events)
    # =========================================================================
    print("\n[Attack 1/4] Triggering Credential Stuffing Attack...")
    session_id = f"attack_cred_{uuid.uuid4().hex[:8]}"
    start_time = datetime.now(timezone.utc)

    for i in range(25):
        client.post("/api/events", json={
            "session_id": session_id,
            "event_type": "auth_fail",
            "ip_address": "198.51.100.44",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "trial",
            "ground_truth_label": "anomalous"
        })
        time.sleep(0.05)

    end_time = datetime.now(timezone.utc)

    # Score current window
    res = client.get("/api/current-window-score").json()
    flagged = res.get("flagged", False)
    risk = res.get("risk_level", "Low")
    print(f"-> Result: Flagged={flagged}, Risk={risk}, ISO={res.get('iso_score')}, LOF={res.get('lof_score')}")

    injection_results.append({
        "attack_name": "Credential Stuffing",
        "description": "25 rapid failed authentications targeting a single account",
        "start_time": start_time.isoformat(),
        "end_time": end_time.isoformat(),
        "events_injected": 25,
        "flagged": flagged,
        "risk_level": risk,
        "iso_score": res.get("iso_score"),
        "lof_score": res.get("lof_score"),
        "failed_login_ratio": res.get("failed_login_ratio"),
        "target_ip": "198.51.100.44"
    })

    # =========================================================================
    # Attack 2: Bot-Driven Vote Stuffing (Sub-second automated ballot casts)
    # =========================================================================
    print("\n[Attack 2/4] Triggering Bot-Driven Vote Stuffing Attack...")
    bot_session = f"attack_bot_{uuid.uuid4().hex[:8]}"
    start_time = datetime.now(timezone.utc)

    for i in range(30):
        client.post("/api/events", json={
            "session_id": bot_session,
            "event_type": "vote",
            "ip_address": "203.0.113.88",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "trial",
            "ground_truth_label": "anomalous"
        })
        time.sleep(0.04)

    end_time = datetime.now(timezone.utc)

    res = client.get("/api/current-window-score").json()
    flagged = res.get("flagged", False)
    risk = res.get("risk_level", "Low")
    print(f"-> Result: Flagged={flagged}, Risk={risk}, ISO={res.get('iso_score')}, LOF={res.get('lof_score')}")

    injection_results.append({
        "attack_name": "Bot-Driven Vote Stuffing",
        "description": "30 rapid automated ballot casting events with collapsed delta-t variance",
        "start_time": start_time.isoformat(),
        "end_time": end_time.isoformat(),
        "events_injected": 30,
        "flagged": flagged,
        "risk_level": risk,
        "iso_score": res.get("iso_score"),
        "lof_score": res.get("lof_score"),
        "inter_arrival_variance": res.get("inter_arrival_variance"),
        "target_ip": "203.0.113.88"
    })

    # =========================================================================
    # Attack 3: Off-Hours Surge (High-density burst)
    # =========================================================================
    print("\n[Attack 3/4] Triggering Off-Hours Surge Attack...")
    burst_session = f"attack_offhours_{uuid.uuid4().hex[:8]}"
    start_time = datetime.now(timezone.utc)

    for i in range(40):
        client.post("/api/events", json={
            "session_id": burst_session,
            "event_type": "login" if i % 2 == 0 else "vote",
            "ip_address": "192.0.2.15",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "trial",
            "ground_truth_label": "anomalous"
        })
        time.sleep(0.03)

    end_time = datetime.now(timezone.utc)

    res = client.get("/api/current-window-score").json()
    flagged = res.get("flagged", False)
    risk = res.get("risk_level", "Low")
    print(f"-> Result: Flagged={flagged}, Risk={risk}, ISO={res.get('iso_score')}, LOF={res.get('lof_score')}")

    injection_results.append({
        "attack_name": "Off-Hours Surge",
        "description": "High-volume surge deviating from standard voting density",
        "start_time": start_time.isoformat(),
        "end_time": end_time.isoformat(),
        "events_injected": 40,
        "flagged": flagged,
        "risk_level": risk,
        "iso_score": res.get("iso_score"),
        "lof_score": res.get("lof_score"),
        "event_count": res.get("event_count"),
        "target_ip": "192.0.2.15"
    })

    # =========================================================================
    # Attack 4: Access-Endpoint Probing (Probing administrative endpoints)
    # =========================================================================
    print("\n[Attack 4/4] Triggering Access-Endpoint Probing Attack...")
    probe_session = f"attack_probe_{uuid.uuid4().hex[:8]}"
    start_time = datetime.now(timezone.utc)

    for i in range(20):
        client.post("/api/events", json={
            "session_id": probe_session,
            "event_type": "admin_access",
            "ip_address": "198.51.100.99",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "trial",
            "ground_truth_label": "anomalous"
        })
        time.sleep(0.05)

    end_time = datetime.now(timezone.utc)

    res = client.get("/api/current-window-score").json()
    flagged = res.get("flagged", False)
    risk = res.get("risk_level", "Low")
    print(f"-> Result: Flagged={flagged}, Risk={risk}, ISO={res.get('iso_score')}, LOF={res.get('lof_score')}")

    injection_results.append({
        "attack_name": "Access-Endpoint Probing",
        "description": "Repeated unauthorized probes on administrative functions",
        "start_time": start_time.isoformat(),
        "end_time": end_time.isoformat(),
        "events_injected": 20,
        "flagged": flagged,
        "risk_level": risk,
        "iso_score": res.get("iso_score"),
        "lof_score": res.get("lof_score"),
        "target_ip": "198.51.100.99"
    })

    # Save log
    os.makedirs(os.path.dirname(evidence_path), exist_ok=True)
    with open(evidence_path, "w", encoding="utf-8") as f:
        json.dump({
            "executed_at": datetime.now(timezone.utc).isoformat(),
            "total_attacks": len(injection_results),
            "attacks_flagged": sum(1 for a in injection_results if a["flagged"]),
            "results": injection_results
        }, f, indent=2)

    print(f"\nAll 4 injection tests completed! Evidence logged to {evidence_path}")
    return True


if __name__ == "__main__":
    run_injection_harness()
