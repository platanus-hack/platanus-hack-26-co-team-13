"""Telegram Supervisor Bot - Main bot logic."""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Optional, Callable, Any
from collections import defaultdict

from .models import (
    QuarantineAlert,
    ApprovalRequest,
    SupervisorReport,
    SupervisorConfig,
    ApprovalStatus,
    AlertSeverity,
)

logger = logging.getLogger(__name__)


class TelegramSupervisor:
    """Main Telegram supervisor bot for Memory Firewall management."""

    def __init__(self, config: SupervisorConfig):
        """Initialize the Telegram supervisor."""
        self.config = config
        self.alert_queue: list[QuarantineAlert] = []
        self.approval_requests: dict[str, ApprovalRequest] = {}
        self.last_batch_time: datetime = datetime.utcnow()
        self.alert_callbacks: list[Callable[[QuarantineAlert], Any]] = []
        self.approval_callbacks: list[Callable[[ApprovalRequest], Any]] = []

    async def start(self):
        """Start the bot and background tasks."""
        logger.info(f"Starting Telegram Supervisor Bot (Token: {self.config.telegram_token[:10]}...)")
        # Here we'll add actual Telegram connection
        # Using python-telegram-bot library

    async def on_quarantine_alert(self, alert: QuarantineAlert):
        """Handle a new quarantine alert from Memory Firewall."""
        logger.info(f"Received quarantine alert: {alert.alert_id}")
        
        self.alert_queue.append(alert)
        
        # Check if we should batch or send immediately
        time_since_last = (datetime.utcnow() - self.last_batch_time).total_seconds()
        
        if alert.severity == AlertSeverity.CRITICAL:
            # Send critical alerts immediately
            await self._send_alert_to_admin(alert)
        elif time_since_last > self.config.alert_batch_delay:
            # Send batched alerts
            await self._send_batched_alerts()
        
        # Execute callbacks
        for callback in self.alert_callbacks:
            try:
                await callback(alert) if asyncio.iscoroutinefunction(callback) else callback(alert)
            except Exception as e:
                logger.error(f"Error in alert callback: {e}")

    async def _send_alert_to_admin(self, alert: QuarantineAlert):
        """Send alert message to admin via Telegram."""
        severity_emoji = {
            AlertSeverity.LOW: "🟢",
            AlertSeverity.MEDIUM: "🟡",
            AlertSeverity.HIGH: "🔴",
            AlertSeverity.CRITICAL: "🚨",
        }
        
        emoji = severity_emoji.get(alert.severity, "❓")
        
        message = f"""{emoji} **QUARANTINE ALERT**

**ID:** `{alert.alert_id}`
**Severity:** {alert.severity.upper()}
**Time:** {alert.timestamp.isoformat()}
**Source:** {alert.source}

**Content Preview:**
```
{alert.content_preview[:200]}...
```

**Threats Detected:**
{chr(10).join(f"• {threat}" for threat in alert.threats_detected)}

**Threat Score:** {alert.threat_score:.1%}
**Authority Assigned:** {alert.authority_assigned.upper()}

**Actions:**
/approve_{alert.alert_id}
/reject_{alert.alert_id}
/details_{alert.alert_id}
"""
        
        # TODO: Send via Telegram API
        logger.info(f"Alert message ready for admin:\n{message}")

    async def _send_batched_alerts(self):
        """Send batched alerts as a summary."""
        if not self.alert_queue:
            return
        
        summary = self._create_alert_summary()
        # TODO: Send summary via Telegram
        logger.info(f"Batched alerts summary:\n{summary}")
        
        self.alert_queue.clear()
        self.last_batch_time = datetime.utcnow()

    def _create_alert_summary(self) -> str:
        """Create a summary of batched alerts."""
        by_severity = defaultdict(list)
        for alert in self.alert_queue:
            by_severity[alert.severity].append(alert)
        
        summary = "📊 **ALERT BATCH SUMMARY**\n\n"
        for severity in [AlertSeverity.CRITICAL, AlertSeverity.HIGH, AlertSeverity.MEDIUM, AlertSeverity.LOW]:
            alerts = by_severity.get(severity, [])
            if alerts:
                summary += f"**{severity.upper()}:** {len(alerts)} alerts\n"
                for alert in alerts[:3]:  # Show top 3
                    summary += f"  • `{alert.alert_id}` - {alert.threat_score:.0%}\n"
                if len(alerts) > 3:
                    summary += f"  • ... and {len(alerts) - 3} more\n"
        
        return summary

    async def create_approval_request(self, alert_id: str) -> ApprovalRequest:
        """Create an approval request for quarantined content."""
        expires_at = datetime.utcnow() + timedelta(hours=24)
        
        request = ApprovalRequest(
            alert_id=alert_id,
            expires_at=expires_at,
        )
        
        self.approval_requests[request.request_id] = request
        
        logger.info(f"Created approval request: {request.request_id}")
        
        # Execute callbacks
        for callback in self.approval_callbacks:
            try:
                await callback(request) if asyncio.iscoroutinefunction(callback) else callback(request)
            except Exception as e:
                logger.error(f"Error in approval callback: {e}")
        
        return request

    async def approve_alert(
        self,
        request_id: str,
        approved_by: str,
        reason: str = "",
    ) -> Optional[ApprovalRequest]:
        """Approve a quarantined alert."""
        request = self.approval_requests.get(request_id)
        
        if not request:
            logger.warning(f"Approval request not found: {request_id}")
            return None
        
        if request.status != ApprovalStatus.PENDING:
            logger.warning(f"Request already {request.status}: {request_id}")
            return None
        
        # Update request
        updated = ApprovalRequest(
            request_id=request.request_id,
            alert_id=request.alert_id,
            created_at=request.created_at,
            expires_at=request.expires_at,
            status=ApprovalStatus.APPROVED,
            approved_by=approved_by,
            decision_timestamp=datetime.utcnow(),
            reason=reason,
            approval_token=self._generate_approval_token(),
        )
        
        self.approval_requests[request_id] = updated
        
        logger.info(f"Approved alert {request.alert_id} by {approved_by}")
        
        return updated

    async def reject_alert(
        self,
        request_id: str,
        rejected_by: str,
        reason: str = "",
    ) -> Optional[ApprovalRequest]:
        """Reject a quarantined alert."""
        request = self.approval_requests.get(request_id)
        
        if not request:
            logger.warning(f"Approval request not found: {request_id}")
            return None
        
        if request.status != ApprovalStatus.PENDING:
            logger.warning(f"Request already {request.status}: {request_id}")
            return None
        
        updated = ApprovalRequest(
            request_id=request.request_id,
            alert_id=request.alert_id,
            created_at=request.created_at,
            expires_at=request.expires_at,
            status=ApprovalStatus.REJECTED,
            approved_by=rejected_by,
            decision_timestamp=datetime.utcnow(),
            reason=reason,
        )
        
        self.approval_requests[request_id] = updated
        
        logger.info(f"Rejected alert {request.alert_id} by {rejected_by}")
        
        return updated

    def _generate_approval_token(self) -> str:
        """Generate a one-time approval token."""
        import secrets
        return secrets.token_urlsafe(32)

    async def generate_daily_report(self) -> SupervisorReport:
        """Generate a daily report of alerts and actions."""
        yesterday = datetime.utcnow() - timedelta(days=1)
        
        # Count alerts by severity (in real implementation, query from database)
        report = SupervisorReport(
            period_start=yesterday,
            period_end=datetime.utcnow(),
        )
        
        logger.info(f"Generated daily report: {report.report_id}")
        
        return report

    def register_alert_callback(self, callback: Callable[[QuarantineAlert], Any]):
        """Register a callback for alerts."""
        self.alert_callbacks.append(callback)

    def register_approval_callback(self, callback: Callable[[ApprovalRequest], Any]):
        """Register a callback for approval requests."""
        self.approval_callbacks.append(callback)
