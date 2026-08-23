"""Handlers for Telegram commands and updates."""

import logging
from typing import Optional, Callable, Any, Dict
from datetime import datetime

from .models import (
    QuarantineAlert,
    ApprovalRequest,
    SupervisorReport,
    AlertSeverity,
    ApprovalStatus,
)

logger = logging.getLogger(__name__)


class QuarantineHandler:
    """Handle quarantine alerts and notifications."""

    def __init__(self):
        """Initialize quarantine handler."""
        self.alert_storage: Dict[str, QuarantineAlert] = {}
        self.alert_listeners: list[Callable] = []

    def register_listener(self, callback: Callable[[QuarantineAlert], Any]):
        """Register callback for new alerts."""
        self.alert_listeners.append(callback)

    async def handle_new_alert(self, alert: QuarantineAlert) -> bool:
        """Handle a new quarantine alert.

        Args:
            alert: The quarantine alert to handle

        Returns:
            True if handled successfully
        """
        logger.info(f"Handling alert: {alert.alert_id}")

        # Store alert
        self.alert_storage[alert.alert_id] = alert

        # Filter by threshold
        if alert.threat_score < 0.3:
            logger.debug(f"Alert below threshold: {alert.alert_id}")
            return False

        # Notify listeners
        for listener in self.alert_listeners:
            try:
                if asyncio.iscoroutinefunction(listener):
                    await listener(alert)
                else:
                    listener(alert)
            except Exception as e:
                logger.error(f"Error in alert listener: {e}")

        return True

    def get_alert(self, alert_id: str) -> Optional[QuarantineAlert]:
        """Get alert details by ID."""
        return self.alert_storage.get(alert_id)

    def get_recent_alerts(self, limit: int = 10) -> list[QuarantineAlert]:
        """Get recent alerts."""
        alerts = sorted(
            self.alert_storage.values(),
            key=lambda a: a.timestamp,
            reverse=True,
        )
        return alerts[:limit]

    def get_alerts_by_severity(self, severity: AlertSeverity) -> list[QuarantineAlert]:
        """Get alerts filtered by severity."""
        return [
            alert for alert in self.alert_storage.values()
            if alert.severity == severity
        ]


class ApprovalHandler:
    """Handle approval/rejection of quarantined content."""

    def __init__(self):
        """Initialize approval handler."""
        self.pending_approvals: Dict[str, ApprovalRequest] = {}
        self.approval_history: Dict[str, ApprovalRequest] = {}
        self.approval_listeners: list[Callable] = []

    def register_listener(self, callback: Callable[[ApprovalRequest], Any]):
        """Register callback for approval decisions."""
        self.approval_listeners.append(callback)

    async def create_approval(self, alert_id: str, expires_in_hours: int = 24) -> ApprovalRequest:
        """Create an approval request."""
        expires_at = datetime.utcnow() + timedelta(hours=expires_in_hours)

        approval = ApprovalRequest(
            alert_id=alert_id,
            expires_at=expires_at,
        )

        self.pending_approvals[approval.request_id] = approval

        logger.info(f"Created approval: {approval.request_id} for alert {alert_id}")

        return approval

    async def approve(
        self,
        request_id: str,
        approved_by: str,
        reason: str = "",
    ) -> Optional[ApprovalRequest]:
        """Approve a quarantined item."""
        approval = self.pending_approvals.get(request_id)

        if not approval:
            logger.warning(f"Approval not found: {request_id}")
            return None

        # Move to history
        del self.pending_approvals[request_id]

        approved = ApprovalRequest(
            request_id=approval.request_id,
            alert_id=approval.alert_id,
            created_at=approval.created_at,
            expires_at=approval.expires_at,
            status=ApprovalStatus.APPROVED,
            approved_by=approved_by,
            decision_timestamp=datetime.utcnow(),
            reason=reason,
            approval_token=self._generate_token(),
        )

        self.approval_history[request_id] = approved

        logger.info(f"Approved: {request_id}")

        # Notify listeners
        await self._notify_listeners(approved)

        return approved

    async def reject(
        self,
        request_id: str,
        rejected_by: str,
        reason: str = "",
    ) -> Optional[ApprovalRequest]:
        """Reject a quarantined item."""
        approval = self.pending_approvals.get(request_id)

        if not approval:
            logger.warning(f"Approval not found: {request_id}")
            return None

        del self.pending_approvals[request_id]

        rejected = ApprovalRequest(
            request_id=approval.request_id,
            alert_id=approval.alert_id,
            created_at=approval.created_at,
            expires_at=approval.expires_at,
            status=ApprovalStatus.REJECTED,
            approved_by=rejected_by,
            decision_timestamp=datetime.utcnow(),
            reason=reason,
        )

        self.approval_history[request_id] = rejected

        logger.info(f"Rejected: {request_id}")

        await self._notify_listeners(rejected)

        return rejected

    async def _notify_listeners(self, approval: ApprovalRequest):
        """Notify all listeners of approval decision."""
        for listener in self.approval_listeners:
            try:
                if asyncio.iscoroutinefunction(listener):
                    await listener(approval)
                else:
                    listener(approval)
            except Exception as e:
                logger.error(f"Error in approval listener: {e}")

    def get_pending_approvals(self) -> list[ApprovalRequest]:
        """Get all pending approvals."""
        return list(self.pending_approvals.values())

    def get_approval_history(self, limit: int = 50) -> list[ApprovalRequest]:
        """Get approval history."""
        return list(self.approval_history.values())[-limit:]

    @staticmethod
    def _generate_token() -> str:
        """Generate approval token."""
        import secrets
        return secrets.token_urlsafe(32)


class ReportHandler:
    """Handle report generation and distribution."""

    def __init__(self):
        """Initialize report handler."""
        self.report_history: Dict[str, SupervisorReport] = {}

    async def generate_report(
        self,
        total_alerts: int,
        critical_alerts: int,
        high_alerts: int,
        medium_alerts: int,
        low_alerts: int,
        total_approved: int,
        total_rejected: int,
        pending_approvals: int,
    ) -> SupervisorReport:
        """Generate a supervisor report."""
        report = SupervisorReport(
            total_alerts=total_alerts,
            critical_alerts=critical_alerts,
            high_alerts=high_alerts,
            medium_alerts=medium_alerts,
            low_alerts=low_alerts,
            total_approved=total_approved,
            total_rejected=total_rejected,
            pending_approvals=pending_approvals,
        )

        self.report_history[report.report_id] = report

        logger.info(f"Generated report: {report.report_id}")

        return report

    def get_report(self, report_id: str) -> Optional[SupervisorReport]:
        """Get report by ID."""
        return self.report_history.get(report_id)

    def get_recent_reports(self, limit: int = 10) -> list[SupervisorReport]:
        """Get recent reports."""
        reports = sorted(
            self.report_history.values(),
            key=lambda r: r.generated_at,
            reverse=True,
        )
        return reports[:limit]

    def format_report_message(self, report: SupervisorReport) -> str:
        """Format report as Telegram message."""
        message = f"""📊 **SUPERVISOR REPORT**

**Period:** {report.period_start.date()} → {report.period_end.date()}

**Alerts Summary:**
• 🚨 Critical: {report.critical_alerts}
• 🔴 High: {report.high_alerts}
• 🟡 Medium: {report.medium_alerts}
• 🟢 Low: {report.low_alerts}
• **Total:** {report.total_alerts}

**Actions Taken:**
• ✅ Approved: {report.total_approved}
• ❌ Rejected: {report.total_rejected}
• ⏳ Pending: {report.pending_approvals}

**Top Threats:**
"""
        for i, threat in enumerate(report.top_threats[:5], 1):
            message += f"{i}. {threat.get('name', 'Unknown')} ({threat.get('count', 0)} occurrences)\n"

        if report.recommendations:
            message += "\n**Recommendations:**\n"
            for rec in report.recommendations:
                message += f"• {rec}\n"

        return message


# Helper imports (will be added at the top when integrated)
import asyncio
from datetime import timedelta
