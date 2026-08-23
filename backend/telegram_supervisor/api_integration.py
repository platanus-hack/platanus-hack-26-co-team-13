"""Integration between Telegram Supervisor and Memory Firewall API."""

import logging
from typing import Optional
from datetime import datetime

from .bot import TelegramSupervisor
from .models import QuarantineAlert, AlertSeverity, SupervisorConfig

logger = logging.getLogger(__name__)


class TelegramFirewallBridge:
    """Bridge between Memory Firewall and Telegram Supervisor."""

    def __init__(self, supervisor: TelegramSupervisor):
        """Initialize the bridge."""
        self.supervisor = supervisor

    async def on_memory_quarantined(
        self,
        analysis_id: str,
        content: str,
        threats_detected: list[str],
        threat_score: float,
        authority: str,
        source: str,
    ) -> str:
        """Called when Memory Firewall quarantines content.

        Args:
            analysis_id: ID from memory firewall analysis
            content: The quarantined content
            threats_detected: List of detected threats
            threat_score: Threat score (0-1)
            authority: Authority level assigned
            source: Source of the content

        Returns:
            Alert ID
        """
        # Determine severity from threat score
        if threat_score >= 0.9:
            severity = AlertSeverity.CRITICAL
        elif threat_score >= 0.7:
            severity = AlertSeverity.HIGH
        elif threat_score >= 0.5:
            severity = AlertSeverity.MEDIUM
        else:
            severity = AlertSeverity.LOW

        # Create alert
        alert = QuarantineAlert(
            severity=severity,
            content_preview=content[:200],
            full_content=content,
            source=source,
            threats_detected=threats_detected,
            threat_score=threat_score,
            authority_assigned=authority,
            analysis_id=analysis_id,
        )

        # Send to supervisor
        await self.supervisor.on_quarantine_alert(alert)

        logger.info(f"Quarantine alert created: {alert.alert_id}")

        return alert.alert_id

    async def on_action_blocked(
        self,
        tool_name: str,
        args: dict,
        reason: str,
        taint_level: str,
        required_level: str,
    ) -> str:
        """Called when Provenance Firewall blocks an action.

        Args:
            tool_name: Name of blocked tool
            args: Tool arguments
            reason: Why it was blocked
            taint_level: Actual taint level
            required_level: Required level

        Returns:
            Alert ID
        """
        # Create alert for blocked action
        alert = QuarantineAlert(
            severity=AlertSeverity.HIGH,
            content_preview=f"Blocked action: {tool_name}",
            full_content=f"Tool: {tool_name}\nArgs: {args}\nReason: {reason}",
            source="provenance_firewall",
            threats_detected=[f"Privilege escalation attempt: {taint_level} < {required_level}"],
            threat_score=0.8,
            authority_assigned=taint_level,
            analysis_metadata={
                "tool_name": tool_name,
                "taint_level": taint_level,
                "required_level": required_level,
                "reason": reason,
            },
        )

        await self.supervisor.on_quarantine_alert(alert)

        logger.info(f"Action blocked alert created: {alert.alert_id}")

        return alert.alert_id

    async def get_approval_for_blocked_action(
        self,
        alert_id: str,
    ) -> Optional[str]:
        """Get approval token if admin approved the blocked action.

        Args:
            alert_id: The alert ID

        Returns:
            Approval token if approved, None otherwise
        """
        # Look up approval request for this alert
        for request in self.supervisor.approval_requests.values():
            if request.alert_id == alert_id:
                return request.approval_token

        return None


async def create_telegram_supervisor(
    telegram_token: str,
    admin_chat_id: str,
) -> tuple[TelegramSupervisor, TelegramFirewallBridge]:
    """Create and initialize Telegram Supervisor.

    Args:
        telegram_token: Telegram bot token
        admin_chat_id: Admin chat ID

    Returns:
        Tuple of (supervisor, bridge)
    """
    config = SupervisorConfig(
        telegram_token=telegram_token,
        admin_chat_id=admin_chat_id,
        enable_quarantine_alerts=True,
        enable_approval_workflow=True,
        enable_daily_reports=True,
        alert_threshold=0.3,
        critical_threshold=0.9,
    )

    supervisor = TelegramSupervisor(config)
    bridge = TelegramFirewallBridge(supervisor)

    await supervisor.start()

    return supervisor, bridge
