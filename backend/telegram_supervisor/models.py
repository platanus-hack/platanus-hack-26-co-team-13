"""Data models for Telegram supervisor alerts and approvals."""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Optional, Any
from uuid import uuid4
import secrets


class AlertSeverity(str, Enum):
    """Severity levels for quarantined content."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ApprovalStatus(str, Enum):
    """Status of approval requests."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


@dataclass(frozen=True)
class QuarantineAlert:
    """Alert for content detected in quarantine."""

    alert_id: str = field(default_factory=lambda: str(uuid4())[:8])
    timestamp: datetime = field(default_factory=datetime.utcnow)
    severity: AlertSeverity = AlertSeverity.MEDIUM
    
    # Content information
    content_preview: str = ""  # First 200 chars
    full_content: Optional[str] = None
    source: str = ""  # email, user_input, web, etc.
    
    # Threat detection
    threats_detected: list[str] = field(default_factory=list)
    threat_score: float = 0.0  # 0-1
    
    # Analysis details
    authority_assigned: str = "untrusted"
    analysis_id: str = ""
    
    # Context
    analysis_metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ApprovalRequest:
    """Request to approve or reject quarantined content."""

    request_id: str = field(default_factory=lambda: str(uuid4())[:8])
    alert_id: str = ""
    created_at: datetime = field(default_factory=datetime.utcnow)
    expires_at: datetime = field(default_factory=lambda: datetime.utcnow() + timedelta(hours=24))
    
    # Decision
    status: ApprovalStatus = ApprovalStatus.PENDING
    approved_by: Optional[str] = None  # Telegram user ID
    decision_timestamp: Optional[datetime] = None
    reason: Optional[str] = None
    
    # One-time token for approval (cryptographically secure)
    approval_token: str = field(default_factory=lambda: secrets.token_urlsafe(32))


@dataclass
class SupervisorReport:
    """Daily/periodic report for administrators."""

    report_id: str = field(default_factory=lambda: str(uuid4())[:8])
    generated_at: datetime = field(default_factory=datetime.utcnow)
    period_start: datetime = field(default_factory=datetime.utcnow)
    period_end: datetime = field(default_factory=datetime.utcnow)
    
    # Statistics
    total_alerts: int = 0
    critical_alerts: int = 0
    high_alerts: int = 0
    medium_alerts: int = 0
    low_alerts: int = 0
    
    # Actions taken
    total_approved: int = 0
    total_rejected: int = 0
    pending_approvals: int = 0
    
    # Top threats
    top_threats: list[dict[str, Any]] = field(default_factory=list)
    
    # Recommendations
    recommendations: list[str] = field(default_factory=list)


@dataclass
class SupervisorConfig:
    """Configuration for Telegram supervisor."""

    telegram_token: str = ""
    admin_chat_id: str = ""
    
    # Features
    enable_quarantine_alerts: bool = True
    enable_approval_workflow: bool = True
    enable_daily_reports: bool = True
    
    # Thresholds
    alert_threshold: float = 0.5  # Threat score threshold
    critical_threshold: float = 0.9
    
    # Timing
    report_hour: int = 9  # Hour to send daily report (UTC)
    alert_batch_delay: int = 60  # Seconds to batch alerts
