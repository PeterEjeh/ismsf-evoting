from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, ConfigDict, Field


class EventCreate(BaseModel):
    """Payload for POST /api/events"""
    session_id: str = Field(..., description="UUID or identifier of the active session")
    event_type: str = Field(..., description="'login' | 'auth_fail' | 'vote' | 'nav' | 'admin_access'")
    ip_address: Optional[str] = Field(None, description="Client IPv4 or IPv6 address")
    timestamp: Optional[datetime] = Field(None, description="UTC event timestamp (defaults to current server UTC if omitted)")
    source: Optional[str] = Field("trial", description="Data source identifier")
    ground_truth_label: Optional[str] = Field(None, description="Optional label for test/eval ('normal' | 'anomalous')")


class VoterRegister(BaseModel):
    """Payload for registering an ATBU student voter with Reg No and PIN."""
    reg_no: str = Field(..., description="ATBU Reg Number, e.g., '21/48920U/1' or '22/55102U/2'")
    full_name: str = Field(..., description="Full Name of the student")
    faculty: Optional[str] = Field("Engineering & Technology", description="Student Faculty")
    department: Optional[str] = Field("Computer & Communication Engineering", description="Department")
    pin: str = Field(..., min_length=4, max_length=8, description="Secret voting PIN (4-8 digits)")


class VoterLogin(BaseModel):
    """Payload for ATBU Student Authentication."""
    reg_no: str = Field(..., description="ATBU Registration Number (e.g. 21/48920U/1)")
    pin: str = Field(..., description="Secret voting PIN")


class VoterResponse(BaseModel):
    """Voter profile response."""
    reg_no: str
    full_name: str
    faculty: Optional[str] = None
    department: Optional[str] = None
    has_voted: bool
    model_config = ConfigDict(from_attributes=True)


class ElectionConfigResponse(BaseModel):
    """Election timing and status response."""
    title: str
    start_time: datetime
    end_time: datetime
    is_active: bool
    is_open: bool
    test_mode: bool = False
    time_remaining_seconds: int
    status_label: str = "OPEN"


class EventResponse(BaseModel):
    """Response returned upon event ingestion"""
    status: str = "recorded"
    event_id: int
    session_id: str
    event_type: str
    timestamp: datetime
    model_config = ConfigDict(from_attributes=True)


class SessionCreate(BaseModel):
    """Payload for POST /api/sessions"""
    reg_no: Optional[str] = Field(None, description="Voter registration number")
    consent_given: Optional[bool] = Field(False, description="Participant consent flag")
    source: Optional[str] = Field("trial", description="Data source identifier")


class SessionUpdate(BaseModel):
    """Payload for PATCH /api/sessions/{id}"""
    ended_at: Optional[datetime] = Field(None, description="Session termination timestamp")


class SessionResponse(BaseModel):
    """Session details response"""
    session_id: str
    reg_no: Optional[str] = None
    source: str
    consent_given: bool
    started_at: datetime
    ended_at: Optional[datetime] = None
    model_config = ConfigDict(from_attributes=True)


class WindowScoreResponse(BaseModel):
    """Response for GET /api/current-window-score and window evaluation history"""
    window_id: Optional[int] = None
    window_start: datetime
    window_end: datetime
    source: str = "trial"
    event_count: int = 0
    vote_count: int = 0
    failed_login_ratio: float = 0.0
    inter_arrival_variance: Optional[float] = None
    distinct_ip_count: Optional[int] = None
    ip_entropy: Optional[float] = None
    iso_score: Optional[float] = None
    lof_score: Optional[float] = None
    flagged: bool = False
    risk_level: str = "Low"  # 'Low' | 'Medium' | 'High'
    model_config = ConfigDict(from_attributes=True)


class AlertResponse(BaseModel):
    """Alert response for GET /api/alerts"""
    alert_id: int
    window_id: int
    created_at: datetime
    investigated: bool
    investigated_at: Optional[datetime] = None
    notes: Optional[str] = None
    window: Optional[WindowScoreResponse] = None
    model_config = ConfigDict(from_attributes=True)


class AlertUpdate(BaseModel):
    """Payload for PATCH /api/alerts/{id}"""
    investigated: bool = True
    notes: Optional[str] = None


class ActivityTrendPoint(BaseModel):
    """Single point in GET /api/activity-trend time series"""
    timestamp: datetime
    event_count: int
    vote_count: int
    auth_fail_count: int


class ActivityTrendResponse(BaseModel):
    """Response for GET /api/activity-trend"""
    range: str
    points: List[ActivityTrendPoint]
