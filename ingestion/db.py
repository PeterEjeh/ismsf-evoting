import os
from datetime import datetime, timezone
from typing import Generator
from sqlalchemy import (
    create_engine,
    Column,
    String,
    Integer,
    BigInteger,
    Float,
    Boolean,
    DateTime,
    ForeignKey,
    Text,
)
from sqlalchemy.orm import declarative_base, sessionmaker, Session, relationship

# Database URL from environment or default local SQLite
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./ismsf.db")

# SQLite requires check_same_thread=False for FastAPI concurrency
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, echo=False, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def utc_now() -> datetime:
    """Return current UTC datetime with timezone awareness."""
    return datetime.now(timezone.utc)


class SessionModel(Base):
    """Voter and Telemetry Sessions table."""
    __tablename__ = "sessions"

    session_id = Column(String(64), primary_key=True, index=True)
    reg_no = Column(String(64), nullable=True, index=True)
    source = Column(String(32), default="trial", nullable=False)
    consent_given = Column(Boolean, default=False, nullable=False)
    consent_timestamp = Column(DateTime, nullable=True)
    started_at = Column(DateTime, default=utc_now, nullable=False)
    ended_at = Column(DateTime, nullable=True)

    events = relationship("EventModel", back_populates="session", cascade="all, delete-orphan")


class EventModel(Base):
    """Append-only voting and authentication telemetry events."""
    __tablename__ = "events"

    event_id = Column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    session_id = Column(String(64), ForeignKey("sessions.session_id"), nullable=False, index=True)
    event_type = Column(String(32), nullable=False, index=True)  # login, auth_fail, vote, nav, admin_access
    timestamp = Column(DateTime, default=utc_now, nullable=False, index=True)
    ip_address = Column(String(45), nullable=True)  # IPv4/IPv6 nullable
    ground_truth_label = Column(String(32), nullable=True)  # 'normal' | 'anomalous'
    source = Column(String(32), default="trial", nullable=False)

    session = relationship("SessionModel", back_populates="events")


class WindowScoreModel(Base):
    """5-minute aggregated telemetry feature windows and ML evaluation scores."""
    __tablename__ = "window_scores"

    window_id = Column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    window_start = Column(DateTime, nullable=False, index=True)
    window_end = Column(DateTime, nullable=False, index=True)
    source = Column(String(32), default="trial", nullable=False)

    # Computed features
    event_count = Column(Integer, nullable=False, default=0)
    vote_count = Column(Integer, nullable=False, default=0)
    failed_login_ratio = Column(Float, nullable=False, default=0.0)
    inter_arrival_variance = Column(Float, nullable=True)
    distinct_ip_count = Column(Integer, nullable=True)
    ip_entropy = Column(Float, nullable=True)

    # Model scores
    iso_score = Column(Float, nullable=True)
    lof_score = Column(Float, nullable=True)
    flagged = Column(Boolean, default=False, nullable=False)
    risk_level = Column(String(16), default="Low", nullable=False)  # Low | Medium | High

    alerts = relationship("AlertModel", back_populates="window", cascade="all, delete-orphan")


class AlertModel(Base):
    """Actionable security alerts resulting from anomalous windows."""
    __tablename__ = "alerts"

    alert_id = Column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    window_id = Column(BigInteger().with_variant(Integer, "sqlite"), ForeignKey("window_scores.window_id"), nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    investigated = Column(Boolean, default=False, nullable=False)
    investigated_at = Column(DateTime, nullable=True)
    notes = Column(Text, nullable=True)

    window = relationship("WindowScoreModel", back_populates="alerts")


class TrialModel(Base):
    """Metadata tracking for controlled mock election trials."""
    __tablename__ = "trials"

    trial_id = Column(String(64), primary_key=True)
    start_time = Column(DateTime, default=utc_now, nullable=False)
    end_time = Column(DateTime, nullable=True)
    participant_count = Column(Integer, default=0, nullable=False)


class VoterModel(Base):
    """ATBU Student Voter Registry with Registration Number and Secret PIN."""
    __tablename__ = "voters"

    reg_no = Column(String(32), primary_key=True, index=True)  # e.g., '21/48920U/1'
    full_name = Column(String(128), nullable=False)
    faculty = Column(String(64), nullable=True)
    department = Column(String(64), nullable=True)
    pin = Column(String(16), nullable=False)  # 4-6 digit voting PIN
    has_voted = Column(Boolean, default=False, nullable=False)
    voted_at = Column(DateTime, nullable=True)


class ElectionConfigModel(Base):
    """Election window and timing configuration."""
    __tablename__ = "election_config"

    id = Column(Integer, primary_key=True, default=1)
    title = Column(String(128), default="ATBU Student Union Government (SUG) General Elections 2026")
    start_time = Column(DateTime, nullable=False)
    end_time = Column(DateTime, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    test_mode = Column(Boolean, default=False, nullable=False)  # Allows opening window for pre-election testing


def init_db():
    """Create all database tables if they do not exist."""
    Base.metadata.create_all(bind=engine)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency for yielding database sessions."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
