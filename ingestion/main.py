"""FastAPI Ingestion and Real-Time Security Monitoring Service.

Configured for Abubakar Tafawa Balewa University (ATBU) SUG General Elections.
Students authenticate with their ATBU Registration Number (e.g., 21/48920U/1) and PIN.
Voting is constrained to a timed election period.
Real-time telemetry streams into unsupervised anomaly detection models (Isolation Forest & LOF).
"""

import os
import sys
import uuid
import json
import re
from datetime import datetime, timedelta, timezone
from typing import List, Optional

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import joblib
import pandas as pd
import numpy as np
from fastapi import FastAPI, Depends, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse, Response
from sqlalchemy.orm import Session

from ingestion.db import (
    init_db,
    get_db,
    SessionLocal,
    SessionModel,
    EventModel,
    WindowScoreModel,
    AlertModel,
    TrialModel,
    VoterModel,
    ElectionConfigModel,
    utc_now,
)
from ingestion.schemas import (
    EventCreate,
    EventResponse,
    SessionCreate,
    SessionUpdate,
    SessionResponse,
    WindowScoreResponse,
    AlertResponse,
    AlertUpdate,
    ActivityTrendResponse,
    ActivityTrendPoint,
    VoterRegister,
    VoterLogin,
    VoterResponse,
    ElectionConfigResponse,
)
from ml.feature_builder import extract_features_from_events, FEATURE_COLUMNS_CORE

app = FastAPI(
    title="ATBU SUG E-Voting Security Monitoring Service",
    description="Intelligent Security Monitoring System for ATBU E-Voting Telemetry",
    version="2.0.0"
)

# Enable CORS for local cross-origin development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def seed_default_atbu_data():
    """Seed initial ATBU election configuration (Friday 9th Oct 2026, 6:00 PM - 10:00 PM WAT) and voters."""
    db = SessionLocal()
    try:
        # 1. Scheduled 4-hour Election Window: Friday, 9th October 2026, 18:00 - 22:00 WAT (17:00 - 21:00 UTC)
        start_time_utc = datetime(2026, 10, 9, 17, 0, 0, tzinfo=timezone.utc)
        end_time_utc = datetime(2026, 10, 9, 21, 0, 0, tzinfo=timezone.utc)

        cfg = db.query(ElectionConfigModel).filter_by(id=1).first()
        if not cfg:
            cfg = ElectionConfigModel(
                id=1,
                title="Abubakar Tafawa Balewa University (ATBU) SUG General Elections 2026",
                start_time=start_time_utc,
                end_time=end_time_utc,
                is_active=True,
                test_mode=False
            )
            db.add(cfg)
            db.commit()
        else:
            cfg.start_time = start_time_utc
            cfg.end_time = end_time_utc
            cfg.title = "Abubakar Tafawa Balewa University (ATBU) SUG General Elections 2026"
            db.commit()

        # 2. Seed realistic ATBU student voters
        voter_count = db.query(VoterModel).count()
        if voter_count == 0:
            sample_voters = [
                VoterModel(
                    reg_no="21/48920U/1",
                    full_name="Ibrahim Musa",
                    faculty="Faculty of Engineering & Technology",
                    department="Computer & Communication Engineering",
                    pin="1234",
                    has_voted=False
                ),
                VoterModel(
                    reg_no="21/49105U/2",
                    full_name="Fatima Abubakar",
                    faculty="Faculty of Science",
                    department="Mathematical Sciences",
                    pin="2468",
                    has_voted=False
                ),
                VoterModel(
                    reg_no="22/55102U/1",
                    full_name="Emmanuel Okafor",
                    faculty="Faculty of Technology Education",
                    department="Electrical Technology",
                    pin="1357",
                    has_voted=False
                ),
                VoterModel(
                    reg_no="20/43891D/2",
                    full_name="Amina Danladi",
                    faculty="Faculty of Management Sciences",
                    department="Accounting",
                    pin="9876",
                    has_voted=False
                ),
                VoterModel(
                    reg_no="23/61204U/1",
                    full_name="Usman Bello",
                    faculty="Faculty of Agriculture",
                    department="Agricultural Economics",
                    pin="4321",
                    has_voted=False
                ),
            ]
            db.add_all(sample_voters)
            db.commit()
    finally:
        db.close()


@app.on_event("startup")
def on_startup():
    init_db()
    seed_default_atbu_data()
    load_ml_models()


# ML Model cache
MODELS = {
    "iso": None,
    "lof": None,
    "iso_threshold": 0.0,
    "lof_threshold": 0.0,
    "features": FEATURE_COLUMNS_CORE
}


def load_ml_models():
    """Load trained Isolation Forest and LOF models and threshold metadata."""
    models_dir = os.path.join(PROJECT_ROOT, "ml", "models")
    iso_path = os.path.join(models_dir, "isolation_forest.joblib")
    lof_path = os.path.join(models_dir, "lof.joblib")
    thresh_path = os.path.join(models_dir, "thresholds.json")

    if os.path.exists(iso_path) and os.path.exists(lof_path):
        MODELS["iso"] = joblib.load(iso_path)
        MODELS["lof"] = joblib.load(lof_path)

        if os.path.exists(thresh_path):
            with open(thresh_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
                MODELS["iso_threshold"] = meta.get("iso_threshold", 0.0)
                MODELS["lof_threshold"] = meta.get("lof_threshold", 0.0)
                MODELS["features"] = meta.get("features", FEATURE_COLUMNS_CORE)


# ==============================================================================
# ATBU Voter Registration & Authentication Endpoints
# ==============================================================================

@app.get("/api/election/config", response_model=ElectionConfigResponse)
def get_election_config(db: Session = Depends(get_db)):
    """Fetch ATBU SUG election parameters (Friday, 9th Oct 2026, 6-10pm WAT)."""
    cfg = db.query(ElectionConfigModel).filter_by(id=1).first()
    now = utc_now()

    start_t = cfg.start_time.replace(tzinfo=timezone.utc) if cfg.start_time.tzinfo is None else cfg.start_time
    end_t = cfg.end_time.replace(tzinfo=timezone.utc) if cfg.end_time.tzinfo is None else cfg.end_time

    # Open if within 6-10pm WAT window OR if test_mode override is enabled
    is_open = cfg.is_active and (cfg.test_mode or (start_t <= now <= end_t))

    if cfg.test_mode:
        status_label = "OPEN (PRE-ELECTION TEST MODE)"
        remaining = 14400  # 4 hours
    elif now < start_t:
        status_label = "OPENS AT 6:00 PM TODAY"
        remaining = int(max(0, (start_t - now).total_seconds()))
    elif start_t <= now <= end_t:
        status_label = "OPEN"
        remaining = int(max(0, (end_t - now).total_seconds()))
    else:
        status_label = "CLOSED (ELECTION CONCLUDED)"
        remaining = 0

    return ElectionConfigResponse(
        title=cfg.title,
        start_time=start_t,
        end_time=end_t,
        is_active=cfg.is_active,
        is_open=is_open,
        test_mode=cfg.test_mode,
        time_remaining_seconds=remaining,
        status_label=status_label
    )


@app.post("/api/election/toggle-test-mode")
def toggle_test_mode(db: Session = Depends(get_db)):
    """Toggle pre-election test mode to permit test voting before 6:00 PM."""
    cfg = db.query(ElectionConfigModel).filter_by(id=1).first()
    cfg.test_mode = not cfg.test_mode
    db.commit()
    status_str = "ENABLED (Voting window unlocked for early testing)" if cfg.test_mode else "DISABLED (Strict 6:00 PM - 10:00 PM schedule active)"
    return {"test_mode": cfg.test_mode, "status": status_str}


@app.post("/api/voters/register", response_model=VoterResponse)
def register_voter(voter_in: VoterRegister, db: Session = Depends(get_db)):
    """Register a new student voter with ATBU Reg Number and Voting PIN."""
    reg_clean = voter_in.reg_no.strip().upper()
    existing = db.query(VoterModel).filter_by(reg_no=reg_clean).first()
    if existing:
        # Update details/PIN
        existing.full_name = voter_in.full_name.strip()
        existing.faculty = voter_in.faculty
        existing.department = voter_in.department
        existing.pin = voter_in.pin.strip()
        db.commit()
        db.refresh(existing)
        return existing

    new_voter = VoterModel(
        reg_no=reg_clean,
        full_name=voter_in.full_name.strip(),
        faculty=voter_in.faculty,
        department=voter_in.department,
        pin=voter_in.pin.strip(),
        has_voted=False
    )
    db.add(new_voter)
    db.commit()
    db.refresh(new_voter)
    return new_voter


@app.post("/api/voters/login")
def voter_login(credentials: VoterLogin, request: Request, db: Session = Depends(get_db)):
    """Authenticate student with ATBU Reg No and PIN.
    
    Logs security telemetry on failure ('auth_fail') and success ('login').
    """
    reg_clean = credentials.reg_no.strip().upper()
    client_ip = request.client.host if request.client else "127.0.0.1"

    # Check election timing
    cfg = db.query(ElectionConfigModel).filter_by(id=1).first()
    now = utc_now()
    if cfg:
        start_t = cfg.start_time.replace(tzinfo=timezone.utc) if cfg.start_time.tzinfo is None else cfg.start_time
        end_t = cfg.end_time.replace(tzinfo=timezone.utc) if cfg.end_time.tzinfo is None else cfg.end_time
        is_open = cfg.is_active and (cfg.test_mode or (start_t <= now <= end_t))
        if not is_open:
            # Telemetry for off-hours login attempt
            ephemeral_id = str(uuid.uuid4())
            log_event_internal(db, ephemeral_id, "auth_fail", client_ip, "trial")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="ATBU SUG Election window is currently closed. Voting will officially open on Friday, 9th October 2026 from 6:00 PM to 10:00 PM (WAT)."
            )

    voter = db.query(VoterModel).filter_by(reg_no=reg_clean).first()

    # Invalid Reg No or Wrong PIN
    if not voter or voter.pin != credentials.pin.strip():
        ephemeral_id = str(uuid.uuid4())
        log_event_internal(db, ephemeral_id, "auth_fail", client_ip, "trial")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed. Invalid ATBU Registration Number or secret voting PIN."
        )

    # Check if voter already cast ballot
    if voter.has_voted:
        ephemeral_id = str(uuid.uuid4())
        log_event_internal(db, ephemeral_id, "auth_fail", client_ip, "trial")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Student {reg_clean} has already cast a vote in this election. Multiple voting is strictly prohibited."
        )

    # Authentication successful: create session
    session_id = str(uuid.uuid4())
    new_session = SessionModel(
        session_id=session_id,
        reg_no=reg_clean,
        source="trial",
        consent_given=True,
        consent_timestamp=now,
        started_at=now
    )
    db.add(new_session)
    db.commit()

    # Log telemetry event
    log_event_internal(db, session_id, "login", client_ip, "trial")

    return {
        "status": "authenticated",
        "session_id": session_id,
        "voter": {
            "reg_no": voter.reg_no,
            "full_name": voter.full_name,
            "faculty": voter.faculty,
            "department": voter.department
        }
    }


@app.post("/api/voters/cast-vote")
def cast_vote(payload: dict, request: Request, db: Session = Depends(get_db)):
    """Record official vote cast for a verified student session."""
    session_id = payload.get("session_id")
    reg_no = payload.get("reg_no")
    choices = payload.get("choices", {})
    client_ip = request.client.host if request.client else "127.0.0.1"

    if not session_id or not reg_no:
        raise HTTPException(status_code=400, detail="Missing session or voter ID")

    voter = db.query(VoterModel).filter_by(reg_no=reg_no.strip().upper()).first()
    if not voter:
        raise HTTPException(status_code=404, detail="Voter not found")

    if voter.has_voted:
        raise HTTPException(status_code=400, detail="Ballot already recorded for this student")

    # Mark voter as voted
    now = utc_now()
    voter.has_voted = True
    voter.voted_at = now

    # Close session
    sess = db.query(SessionModel).filter_by(session_id=session_id).first()
    if sess:
        sess.ended_at = now

    # Log vote telemetry event
    log_event_internal(db, session_id, "vote", client_ip, "trial")
    db.commit()

    receipt = f"ATBU-SUG-{uuid.uuid4().hex[:8].upper()}"
    return {
        "status": "success",
        "receipt_number": receipt,
        "timestamp": now.isoformat()
    }


# ==============================================================================
# Telemetry Ingestion & Scoring Endpoints
# ==============================================================================

def log_event_internal(db: Session, session_id: str, event_type: str, client_ip: str, source: str = "trial"):
    """Helper to persist telemetry events."""
    existing_session = db.query(SessionModel).filter_by(session_id=session_id).first()
    now = utc_now()
    if not existing_session:
        ephemeral = SessionModel(
            session_id=session_id,
            source=source,
            started_at=now
        )
        db.add(ephemeral)
        db.commit()

    db_event = EventModel(
        session_id=session_id,
        event_type=event_type,
        timestamp=now,
        ip_address=client_ip,
        source=source
    )
    db.add(db_event)
    db.commit()


@app.post("/api/events", response_model=EventResponse)
def ingest_event(event_in: EventCreate, request: Request, db: Session = Depends(get_db)):
    """Record one voting or authentication telemetry event."""
    client_ip = event_in.ip_address or (request.client.host if request.client else "127.0.0.1")
    event_time = event_in.timestamp or utc_now()

    existing_session = db.query(SessionModel).filter_by(session_id=event_in.session_id).first()
    if not existing_session:
        ephemeral = SessionModel(
            session_id=event_in.session_id,
            source=event_in.source or "trial",
            started_at=utc_now()
        )
        db.add(ephemeral)
        db.commit()

    db_event = EventModel(
        session_id=event_in.session_id,
        event_type=event_in.event_type,
        timestamp=event_time,
        ip_address=client_ip,
        ground_truth_label=event_in.ground_truth_label,
        source=event_in.source or "trial"
    )
    db.add(db_event)
    db.commit()
    db.refresh(db_event)

    return EventResponse(
        status="recorded",
        event_id=db_event.event_id,
        session_id=db_event.session_id,
        event_type=db_event.event_type,
        timestamp=db_event.timestamp
    )


@app.post("/api/sessions", response_model=SessionResponse)
def create_session(session_in: SessionCreate, db: Session = Depends(get_db)):
    """Start a new voter session."""
    new_session_id = str(uuid.uuid4())
    now = utc_now()
    db_session = SessionModel(
        session_id=new_session_id,
        reg_no=session_in.reg_no,
        source=session_in.source or "trial",
        consent_given=session_in.consent_given or False,
        consent_timestamp=now if session_in.consent_given else None,
        started_at=now
    )
    db.add(db_session)
    db.commit()
    db.refresh(db_session)
    return db_session


@app.patch("/api/sessions/{session_id}", response_model=SessionResponse)
def close_session(session_id: str, update_in: SessionUpdate, db: Session = Depends(get_db)):
    """Close an active session."""
    db_session = db.query(SessionModel).filter_by(session_id=session_id).first()
    if not db_session:
        raise HTTPException(status_code=404, detail="Session not found")
    db_session.ended_at = update_in.ended_at or utc_now()
    db.commit()
    db.refresh(db_session)
    return db_session


def evaluate_window_internal(db: Session, window_minutes: int = 5) -> WindowScoreModel:
    """Extract features for the most recent 5 minutes and evaluate ML anomaly scores."""
    if MODELS["iso"] is None or MODELS["lof"] is None:
        load_ml_models()

    now = utc_now()
    # Handle naive datetime comparisons in SQLite
    window_start = now - timedelta(minutes=window_minutes)
    window_start_naive = window_start.replace(tzinfo=None)

    events = db.query(EventModel).filter(
        EventModel.timestamp >= window_start_naive
    ).order_by(EventModel.timestamp.asc()).all()

    events_data = [{
        "timestamp": e.timestamp,
        "session_id": e.session_id,
        "event_type": e.event_type,
        "ip_address": e.ip_address,
        "source": e.source,
        "ground_truth_label": e.ground_truth_label
    } for e in events]

    events_df = pd.DataFrame(events_data)
    features = extract_features_from_events(events_df, window_start, now, source="trial")

    iso_score = None
    lof_score = None
    flagged = False
    risk_level = "Low"

    # Only score when there is actual activity in the window (prevent idle false alarms)
    if features["event_count"] > 0 and MODELS["iso"] and MODELS["lof"]:
        feature_vector = pd.DataFrame([{col: features.get(col, 0.0) for col in MODELS["features"]}])

        iso_val = float(MODELS["iso"].decision_function(feature_vector)[0])
        lof_val = float(MODELS["lof"].decision_function(feature_vector)[0])
        iso_score = iso_val
        lof_score = lof_val

        iso_flag = iso_val < MODELS["iso_threshold"]
        lof_flag = lof_val < MODELS["lof_threshold"]

        flagged = iso_flag or lof_flag
        if iso_flag and lof_flag:
            risk_level = "High"
        elif iso_flag or lof_flag:
            risk_level = "Medium"
        else:
            risk_level = "Low"

    window_record = WindowScoreModel(
        window_start=window_start,
        window_end=now,
        source="trial",
        event_count=features["event_count"],
        vote_count=features["vote_count"],
        failed_login_ratio=features["failed_login_ratio"],
        inter_arrival_variance=features["inter_arrival_variance"],
        distinct_ip_count=features["distinct_ip_count"],
        ip_entropy=features["ip_entropy"],
        iso_score=iso_score,
        lof_score=lof_score,
        flagged=flagged,
        risk_level=risk_level
    )
    db.add(window_record)
    db.commit()
    db.refresh(window_record)

    # Register alert only if flagged
    if flagged:
        alert = AlertModel(
            window_id=window_record.window_id,
            created_at=now,
            investigated=False
        )
        db.add(alert)
        db.commit()

    return window_record


@app.get("/api/current-window-score", response_model=WindowScoreResponse)
def get_current_window_score(db: Session = Depends(get_db)):
    """Evaluate and return anomaly scores for current 5-minute window."""
    window_record = evaluate_window_internal(db)
    return window_record


@app.get("/api/alerts", response_model=List[AlertResponse])
def get_alerts(
    since: Optional[datetime] = None,
    investigated: Optional[bool] = None,
    db: Session = Depends(get_db)
):
    """Retrieve security incident alerts with associated window telemetry."""
    query = db.query(AlertModel).join(WindowScoreModel)
    if since:
        query = query.filter(AlertModel.created_at >= since)
    if investigated is not None:
        query = query.filter(AlertModel.investigated == investigated)

    alerts = query.order_by(AlertModel.created_at.desc()).limit(100).all()

    response = []
    for a in alerts:
        w_resp = WindowScoreResponse.model_validate(a.window) if a.window else None
        response.append(AlertResponse(
            alert_id=a.alert_id,
            window_id=a.window_id,
            created_at=a.created_at,
            investigated=a.investigated,
            investigated_at=a.investigated_at,
            notes=a.notes,
            window=w_resp
        ))
    return response


@app.patch("/api/alerts/{alert_id}", response_model=AlertResponse)
def update_alert(alert_id: int, alert_in: AlertUpdate, db: Session = Depends(get_db)):
    """Mark an alert as investigated with free-text operator audit notes."""
    alert = db.query(AlertModel).filter(AlertModel.alert_id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.investigated = alert_in.investigated
    alert.investigated_at = utc_now() if alert_in.investigated else None
    if alert_in.notes is not None:
        alert.notes = alert_in.notes

    db.commit()
    db.refresh(alert)

    w_resp = WindowScoreResponse.model_validate(alert.window) if alert.window else None
    return AlertResponse(
        alert_id=alert.alert_id,
        window_id=alert.window_id,
        created_at=alert.created_at,
        investigated=alert.investigated,
        investigated_at=alert.investigated_at,
        notes=alert.notes,
        window=w_resp
    )


@app.get("/api/activity-trend", response_model=ActivityTrendResponse)
def get_activity_trend(range: str = Query("1h", regex="^(1h|6h|24h)$"), db: Session = Depends(get_db)):
    """Aggregate event counts over time buckets for the monitoring trend chart."""
    hours = 1 if range == "1h" else (6 if range == "6h" else 24)
    now = utc_now()
    start_time = now - timedelta(hours=hours)
    start_time_naive = start_time.replace(tzinfo=None)

    events = db.query(EventModel).filter(
        EventModel.timestamp >= start_time_naive
    ).order_by(EventModel.timestamp.asc()).all()

    bucket_seconds = 120
    buckets = {}

    current = start_time
    while current <= now:
        ts_key = current.replace(second=0, microsecond=0)
        buckets[ts_key] = {"event_count": 0, "vote_count": 0, "auth_fail_count": 0}
        current += timedelta(seconds=bucket_seconds)

    for e in events:
        e_time = e.timestamp.replace(second=0, microsecond=0)
        if e_time.tzinfo is None:
            e_time = e_time.replace(tzinfo=timezone.utc)
        closest_key = min(buckets.keys(), key=lambda b: abs((b - e_time).total_seconds())) if buckets else e_time
        if closest_key in buckets:
            buckets[closest_key]["event_count"] += 1
            if e.event_type == "vote":
                buckets[closest_key]["vote_count"] += 1
            elif e.event_type == "auth_fail":
                buckets[closest_key]["auth_fail_count"] += 1

    points = [
        ActivityTrendPoint(
            timestamp=k,
            event_count=v["event_count"],
            vote_count=v["vote_count"],
            auth_fail_count=v["auth_fail_count"]
        )
        for k, v in sorted(buckets.items())
    ]

    return ActivityTrendResponse(range=range, points=points)


# ==============================================================================
# Election Audit Log & Post-Election Report Endpoints
# ==============================================================================

@app.get("/api/admin/audit-log")
def get_audit_log(download: bool = False, db: Session = Depends(get_db)):
    """Retrieve or export complete end-to-end election audit logs, telemetry, and security incident records."""
    cfg = db.query(ElectionConfigModel).filter_by(id=1).first()
    voters = db.query(VoterModel).all()
    events = db.query(EventModel).order_by(EventModel.timestamp.asc()).all()
    windows = db.query(WindowScoreModel).order_by(WindowScoreModel.window_start.asc()).all()
    alerts = db.query(AlertModel).order_by(AlertModel.created_at.asc()).all()

    total_voters = len(voters)
    votes_cast = sum(1 for v in voters if v.has_voted)
    turnout = (votes_cast / total_voters * 100) if total_voters > 0 else 0.0

    log_data = {
        "election_title": cfg.title if cfg else "ATBU SUG General Elections 2026",
        "generated_at": utc_now().isoformat(),
        "summary": {
            "total_registered_voters": total_voters,
            "total_votes_cast": votes_cast,
            "turnout_percentage": round(turnout, 2),
            "total_telemetry_events": len(events),
            "total_anomaly_alerts": len(alerts),
            "resolved_alerts": sum(1 for a in alerts if a.investigated)
        },
        "voters_audit": [
            {
                "reg_no": v.reg_no,
                "full_name": v.full_name,
                "faculty": v.faculty,
                "department": v.department,
                "has_voted": v.has_voted,
                "voted_at": v.voted_at.isoformat() if v.voted_at else None
            }
            for v in voters
        ],
        "telemetry_events": [
            {
                "event_id": e.event_id,
                "timestamp": e.timestamp.isoformat(),
                "event_type": e.event_type,
                "session_id": e.session_id,
                "ip_address": e.ip_address,
                "ground_truth_label": e.ground_truth_label,
                "source": e.source
            }
            for e in events
        ],
        "window_scores": [
            {
                "window_id": w.window_id,
                "window_start": w.window_start.isoformat(),
                "window_end": w.window_end.isoformat(),
                "event_count": w.event_count,
                "vote_count": w.vote_count,
                "failed_login_ratio": w.failed_login_ratio,
                "inter_arrival_variance": w.inter_arrival_variance,
                "iso_score": w.iso_score,
                "lof_score": w.lof_score,
                "flagged": w.flagged,
                "risk_level": w.risk_level
            }
            for w in windows
        ],
        "alerts": [
            {
                "alert_id": a.alert_id,
                "created_at": a.created_at.isoformat(),
                "investigated": a.investigated,
                "investigated_at": a.investigated_at.isoformat() if a.investigated_at else None,
                "notes": a.notes
            }
            for a in alerts
        ]
    }

    if download:
        ts_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        content = json.dumps(log_data, indent=2)
        return Response(
            content=content,
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=atbu_election_audit_log_{ts_str}.json"}
        )

    return log_data


# ==============================================================================
# Admin Reset / Clean State Endpoint
# ==============================================================================

@app.post("/api/admin/reset-telemetry")
def reset_telemetry(db: Session = Depends(get_db)):
    """Clear out all alerts, window scores, and past telemetry events so dashboard is 100% clean."""
    db.query(AlertModel).delete()
    db.query(WindowScoreModel).delete()
    db.query(EventModel).delete()
    db.query(SessionModel).delete()
    # Reset voted flags for voters
    db.query(VoterModel).update({"has_voted": False, "voted_at": None})
    db.commit()
    return {"status": "success", "message": "Telemetry database and dashboard alerts cleared successfully. Ready for manual testing."}


@app.post("/api/test/inject-anomaly")
def inject_anomaly(payload: dict, request: Request, db: Session = Depends(get_db)):
    """Interactive Red-Team anomaly trigger for testing the monitoring system on demand."""
    attack_type = payload.get("type", "credential_stuffing")
    now = utc_now()
    session_id = f"attack_{attack_type}_{uuid.uuid4().hex[:6]}"

    # Ensure container session exists
    ephemeral = SessionModel(session_id=session_id, source="trial", started_at=now)
    db.add(ephemeral)

    injected_events = 0
    if attack_type == "credential_stuffing":
        for i in range(25):
            db_event = EventModel(
                session_id=session_id,
                event_type="auth_fail",
                timestamp=now - timedelta(seconds=(25 - i) * 0.1),
                ip_address="198.51.100.44",
                source="trial",
                ground_truth_label="anomalous"
            )
            db.add(db_event)
        injected_events = 25

    elif attack_type == "vote_stuffing":
        for i in range(30):
            db_event = EventModel(
                session_id=session_id,
                event_type="vote",
                timestamp=now - timedelta(seconds=(30 - i) * 0.05),
                ip_address="203.0.113.88",
                source="trial",
                ground_truth_label="anomalous"
            )
            db.add(db_event)
        injected_events = 30

    elif attack_type == "off_hours_surge":
        for i in range(40):
            db_event = EventModel(
                session_id=session_id,
                event_type="login" if i % 2 == 0 else "vote",
                timestamp=now - timedelta(seconds=(40 - i) * 0.08),
                ip_address="192.0.2.15",
                source="trial",
                ground_truth_label="anomalous"
            )
            db.add(db_event)
        injected_events = 40

    elif attack_type == "endpoint_probing":
        for i in range(20):
            db_event = EventModel(
                session_id=session_id,
                event_type="admin_access",
                timestamp=now - timedelta(seconds=(20 - i) * 0.1),
                ip_address="198.51.100.99",
                source="trial",
                ground_truth_label="anomalous"
            )
            db.add(db_event)
        injected_events = 20

    db.commit()

    # Re-score the current window immediately
    win_score = evaluate_window_internal(db)

    return {
        "status": "injected",
        "attack_type": attack_type,
        "events_injected": injected_events,
        "window_score": {
            "flagged": win_score.flagged,
            "risk_level": win_score.risk_level,
            "iso_score": win_score.iso_score,
            "lof_score": win_score.lof_score,
            "failed_login_ratio": win_score.failed_login_ratio,
            "inter_arrival_variance": win_score.inter_arrival_variance,
            "event_count": win_score.event_count
        }
    }


# ==============================================================================
# Frontends
# ==============================================================================

VOTER_PORTAL_DIR = os.path.join(PROJECT_ROOT, "evoting_site")
DASHBOARD_DIR = os.path.join(PROJECT_ROOT, "dashboard")

@app.get("/voter")
def serve_voter_portal():
    return FileResponse(os.path.join(VOTER_PORTAL_DIR, "index.html"))

@app.get("/dashboard")
def serve_dashboard():
    return FileResponse(os.path.join(DASHBOARD_DIR, "index.html"))

@app.get("/redteam")
def serve_redteam_console():
    return FileResponse(os.path.join(DASHBOARD_DIR, "redteam.html"))

@app.get("/")
def root_redirect():
    return RedirectResponse(url="/dashboard")
