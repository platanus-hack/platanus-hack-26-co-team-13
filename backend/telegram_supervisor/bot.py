"""Telegram Supervisor Bot - Main bot logic."""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Optional, Callable, Any, Dict
from collections import defaultdict

from .models import (
    QuarantineAlert,
    ApprovalRequest,
    SupervisorReport,
    SupervisorConfig,
    ApprovalStatus,
    AlertSeverity,
)
from .telegram_client import TelegramClient
from .database import TelegramBotDatabase

logger = logging.getLogger(__name__)


class TelegramSupervisor:
    """Main Telegram supervisor bot for Memory Firewall management."""

    def __init__(self, config: SupervisorConfig, db_path: str = "telegram_bot.sqlite3"):
        """Initialize the Telegram supervisor."""
        self.config = config
        self.alert_queue: list[QuarantineAlert] = []
        self.approval_requests: dict[str, ApprovalRequest] = {}
        self.alert_history: list[QuarantineAlert] = []
        self.last_batch_time: datetime = datetime.utcnow()
        self.alert_callbacks: list[Callable[[QuarantineAlert], Any]] = []
        self.approval_callbacks: list[Callable[[ApprovalRequest], Any]] = []

        # Database for persistence
        self.db = TelegramBotDatabase(db_path)

        # Telegram client
        self.telegram_client = TelegramClient(
            token=config.telegram_token,
            admin_chat_id=config.admin_chat_id,
        )

        # Register Telegram callbacks
        self.telegram_client.set_approval_callback(self._handle_telegram_action)
        self.telegram_client.set_rejection_callback(self._handle_telegram_action)
        self.telegram_client.set_details_callback(self._handle_telegram_action)

        # Batch processing task
        self.batch_task: Optional[asyncio.Task] = None
        self.running = False

    async def start(self):
        """Start the bot and background tasks."""
        logger.info(f"Starting Telegram Supervisor Bot (Token: {self.config.telegram_token[:10]}...)")

        # Start Telegram client
        try:
            await self.telegram_client.start()
            self.running = True
            logger.info("Telegram client started")
        except Exception as e:
            logger.error(f"Failed to start Telegram client: {e}")
            raise

        # Start batch processing task
        self.batch_task = asyncio.create_task(self._batch_processing_loop())

        logger.info("Telegram Supervisor Bot started successfully")

    async def stop(self):
        """Stop the bot and background tasks."""
        self.running = False

        if self.batch_task:
            self.batch_task.cancel()
            try:
                await self.batch_task
            except asyncio.CancelledError:
                pass

        await self.telegram_client.stop()

        # Close database
        self.db.close()

        logger.info("Telegram Supervisor Bot stopped")

    async def on_quarantine_alert(self, alert: QuarantineAlert):
        """Handle a new quarantine alert from Memory Firewall."""
        logger.info(f"Received quarantine alert: {alert.alert_id} (severity: {alert.severity})")

        # Store in history (memory)
        self.alert_history.append(alert)

        # Store in database (persistent)
        self.db.save_alert({
            "alert_id": alert.alert_id,
            "timestamp": alert.timestamp.isoformat(),
            "severity": alert.severity.value,
            "content_preview": alert.content_preview,
            "full_content": alert.full_content,
            "source": alert.source,
            "threats_detected": alert.threats_detected,
            "threat_score": alert.threat_score,
            "authority_assigned": alert.authority_assigned,
            "analysis_id": alert.analysis_id,
            "analysis_metadata": alert.analysis_metadata,
        })

        # Check if we should send immediately or batch
        if alert.severity == AlertSeverity.CRITICAL:
            # Send critical alerts immediately
            await self._send_alert_to_admin(alert)
        else:
            # Queue for batching
            self.alert_queue.append(alert)

            # Check if enough time has passed for batching
            time_since_last = (datetime.utcnow() - self.last_batch_time).total_seconds()
            if time_since_last > self.config.alert_batch_delay:
                await self._send_batched_alerts()

    async def on_action_blocked(self, alert: QuarantineAlert):
        """Handle action blocked from Provenance Firewall."""
        logger.info(f"Received action blocked alert: {alert.alert_id}")
        # Same as quarantine alert
        await self.on_quarantine_alert(alert)

    async def create_approval_request(self, alert_id: str) -> ApprovalRequest:
        """Create an approval request for quarantined content."""
        request = ApprovalRequest(alert_id=alert_id)

        self.approval_requests[request.request_id] = request

        logger.info(f"Created approval request: {request.request_id} for alert {alert_id}")

        # Execute callbacks
        for callback in self.approval_callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(request)
                else:
                    callback(request)
            except Exception as e:
                logger.error(f"Error in approval callback: {e}")

        return request

    async def approve_alert(
        self,
        alert_id: str,
        approved_by: str,
        reason: str = "Approved via Telegram",
    ) -> Optional[ApprovalRequest]:
        """Admin approves a quarantined alert."""
        logger.info(f"Approving alert {alert_id} by {approved_by}")

        # Find or create approval request
        approval = None
        for req in self.approval_requests.values():
            if req.alert_id == alert_id and req.status == ApprovalStatus.PENDING:
                approval = req
                break

        if not approval:
            # Create new approval request
            approval = await self.create_approval_request(alert_id)

        # Create updated approval with decision
        updated = ApprovalRequest(
            request_id=approval.request_id,
            alert_id=approval.alert_id,
            created_at=approval.created_at,
            expires_at=approval.expires_at,
            status=ApprovalStatus.APPROVED,
            approved_by=approved_by,
            decision_timestamp=datetime.utcnow(),
            reason=reason,
            approval_token=approval.approval_token,
        )

        self.approval_requests[updated.request_id] = updated

        # Save to database
        self.db.save_approval({
            "request_id": updated.request_id,
            "alert_id": updated.alert_id,
            "created_at": updated.created_at.isoformat(),
            "expires_at": updated.expires_at.isoformat(),
            "status": updated.status.value,
            "approved_by": updated.approved_by,
            "decision_timestamp": updated.decision_timestamp.isoformat() if updated.decision_timestamp else None,
            "reason": updated.reason,
            "approval_token": updated.approval_token,
        })

        # Notify admin via Telegram
        await self.telegram_client.send_approval_confirmed(
            alert_id=alert_id,
            approval_token=updated.approval_token,
            expires_at=updated.expires_at.isoformat(),
        )

        logger.info(f"Alert {alert_id} approved with token: {updated.approval_token[:10]}...")

        return updated

    async def reject_alert(
        self,
        alert_id: str,
        rejected_by: str,
        reason: str = "Rejected via Telegram",
    ) -> Optional[ApprovalRequest]:
        """Admin rejects a quarantined alert."""
        logger.info(f"Rejecting alert {alert_id} by {rejected_by}")

        # Find or create approval request
        approval = None
        for req in self.approval_requests.values():
            if req.alert_id == alert_id and req.status == ApprovalStatus.PENDING:
                approval = req
                break

        if not approval:
            approval = await self.create_approval_request(alert_id)

        # Create updated approval with rejection
        updated = ApprovalRequest(
            request_id=approval.request_id,
            alert_id=approval.alert_id,
            created_at=approval.created_at,
            expires_at=approval.expires_at,
            status=ApprovalStatus.REJECTED,
            approved_by=rejected_by,
            decision_timestamp=datetime.utcnow(),
            reason=reason,
            approval_token=approval.approval_token,
        )

        self.approval_requests[updated.request_id] = updated

        # Save to database
        self.db.save_approval({
            "request_id": updated.request_id,
            "alert_id": updated.alert_id,
            "created_at": updated.created_at.isoformat(),
            "expires_at": updated.expires_at.isoformat(),
            "status": updated.status.value,
            "approved_by": updated.approved_by,
            "decision_timestamp": updated.decision_timestamp.isoformat() if updated.decision_timestamp else None,
            "reason": updated.reason,
            "approval_token": updated.approval_token,
        })

        # Notify admin
        await self.telegram_client.send_rejection_confirmed(alert_id)

        logger.info(f"Alert {alert_id} rejected")

        return updated

    async def _send_alert_to_admin(self, alert: QuarantineAlert):
        """Send alert message to admin via Telegram."""
        try:
            await self.telegram_client.send_alert(
                alert_id=alert.alert_id,
                severity=alert.severity.value.upper(),
                threat_score=alert.threat_score,
                content_preview=alert.content_preview,
                threats=alert.threats_detected,
                source=alert.source,
            )
        except Exception as e:
            logger.error(f"Failed to send alert to admin: {e}")

    async def _send_batched_alerts(self):
        """Send batched alerts as a summary."""
        if not self.alert_queue:
            return

        try:
            by_severity = defaultdict(list)
            for alert in self.alert_queue:
                by_severity[alert.severity].append(alert)

            # Create summary message
            summary = "📋 **Alert Batch Summary**\n\n"
            for severity in [AlertSeverity.CRITICAL, AlertSeverity.HIGH, AlertSeverity.MEDIUM, AlertSeverity.LOW]:
                alerts = by_severity.get(severity, [])
                if alerts:
                    emoji = {"CRITICAL": "🚨", "HIGH": "⚠️", "MEDIUM": "⚠", "LOW": "ℹ️"}.get(severity.value.upper(), "")
                    summary += f"{emoji} **{severity.value.upper()}:** {len(alerts)} alerts\n"

            await self.telegram_client.send_status(summary)

            self.alert_queue.clear()
            self.last_batch_time = datetime.utcnow()
            logger.info("Batched alerts sent")
        except Exception as e:
            logger.error(f"Failed to send batched alerts: {e}")

    async def get_daily_report(self) -> SupervisorReport:
        """Generate daily report from alert history."""
        today = datetime.utcnow().date()
        today_alerts = [
            a for a in self.alert_history
            if a.timestamp.date() == today
        ]

        critical = sum(1 for a in today_alerts if a.severity == AlertSeverity.CRITICAL)
        high = sum(1 for a in today_alerts if a.severity == AlertSeverity.HIGH)
        medium = sum(1 for a in today_alerts if a.severity == AlertSeverity.MEDIUM)
        low = sum(1 for a in today_alerts if a.severity == AlertSeverity.LOW)

        approved = sum(
            1 for r in self.approval_requests.values()
            if r.status == ApprovalStatus.APPROVED and r.alert_id in [a.alert_id for a in today_alerts]
        )
        rejected = sum(
            1 for r in self.approval_requests.values()
            if r.status == ApprovalStatus.REJECTED and r.alert_id in [a.alert_id for a in today_alerts]
        )
        pending = sum(
            1 for r in self.approval_requests.values()
            if r.status == ApprovalStatus.PENDING and r.alert_id in [a.alert_id for a in today_alerts]
        )

        # Get top threats
        threat_counts = defaultdict(int)
        for alert in today_alerts:
            for threat in alert.threats_detected:
                threat_counts[threat] += 1

        top_threats = sorted(threat_counts.items(), key=lambda x: x[1], reverse=True)[:5]

        report = SupervisorReport(
            period_start=datetime.combine(today, datetime.min.time()),
            period_end=datetime.combine(today, datetime.max.time()),
            total_alerts=len(today_alerts),
            critical_alerts=critical,
            high_alerts=high,
            medium_alerts=medium,
            low_alerts=low,
            total_approved=approved,
            total_rejected=rejected,
            pending_approvals=pending,
        )

        return report

    async def send_daily_report(self):
        """Send daily report to admin."""
        try:
            report = await self.get_daily_report()

            # Get top threats
            threat_counts = defaultdict(int)
            for alert in self.alert_history:
                if alert.timestamp.date() == datetime.utcnow().date():
                    for threat in alert.threats_detected:
                        threat_counts[threat] += 1

            top_threats = sorted(threat_counts.items(), key=lambda x: x[1], reverse=True)
            top_threats_names = [t[0] for t in top_threats[:5]]

            await self.telegram_client.send_daily_report(
                total_alerts=report.total_alerts,
                critical=report.critical_alerts,
                high=report.high_alerts,
                medium=report.medium_alerts,
                low=report.low_alerts,
                approved=report.total_approved,
                rejected=report.total_rejected,
                pending=report.pending_approvals,
                top_threats=top_threats_names,
            )
        except Exception as e:
            logger.error(f"Failed to send daily report: {e}")

    async def _batch_processing_loop(self):
        """Background loop for batch processing."""
        while self.running:
            try:
                # Every configured seconds, check if we should send batched alerts
                await asyncio.sleep(self.config.alert_batch_delay)

                if self.alert_queue and (
                    datetime.utcnow() - self.last_batch_time
                ).total_seconds() > self.config.alert_batch_delay:
                    await self._send_batched_alerts()

                # Check if it's time for daily report (e.g., 9 AM)
                now = datetime.utcnow()
                if now.hour == self.config.report_hour and now.minute == 0:
                    await self.send_daily_report()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in batch processing loop: {e}")

    async def _handle_telegram_action(self, action: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle actions from Telegram."""
        alert_id = data.get("alert_id")

        if action == "approve_alert":
            approval = await self.approve_alert(alert_id, "telegram_user")
            return {
                "success": True,
                "token": approval.approval_token if approval else None,
            }

        elif action == "reject_alert":
            await self.reject_alert(alert_id, "telegram_user")
            return {"success": True}

        elif action == "get_alert_details":
            for alert in self.alert_history:
                if alert.alert_id == alert_id:
                    return {
                        "full_content": alert.full_content,
                        "threats": alert.threats_detected,
                        "threat_score": alert.threat_score,
                    }
            return {"error": "Alert not found"}

        elif action == "get_status":
            return {
                "alerts": len(self.alert_history),
                "pending": len([r for r in self.approval_requests.values() if r.status == ApprovalStatus.PENDING]),
            }

        elif action == "get_recent_alerts":
            limit = data.get("limit", 5)
            recent = self.alert_history[-limit:]
            return [
                {
                    "alert_id": a.alert_id,
                    "severity": a.severity.value,
                    "source": a.source,
                    "threat_score": a.threat_score,
                }
                for a in recent
            ]

        elif action == "get_pending_approvals":
            pending = [
                r for r in self.approval_requests.values()
                if r.status == ApprovalStatus.PENDING
            ]
            return [
                {
                    "alert_id": r.alert_id,
                    "request_id": r.request_id,
                }
                for r in pending
            ]

        elif action == "get_daily_report":
            report = await self.get_daily_report()
            return {
                "total": report.total_alerts,
                "approved": report.total_approved,
                "rejected": report.total_rejected,
                "pending": report.pending_approvals,
            }

        return {"error": "Unknown action"}
