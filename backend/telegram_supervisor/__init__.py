"""Telegram Supervisor Bot - Monitor and manage memory firewall alerts."""

from .bot import TelegramSupervisor
from .handlers import QuarantineHandler, ReportHandler, ApprovalHandler
from .models import (
    QuarantineAlert,
    ApprovalRequest,
    SupervisorReport,
    SupervisorConfig,
    AlertSeverity,
    ApprovalStatus,
)
from .api_integration import TelegramFirewallBridge, create_telegram_supervisor
from .telegram_client import TelegramClient

__all__ = [
    "TelegramSupervisor",
    "QuarantineHandler",
    "ReportHandler",
    "ApprovalHandler",
    "QuarantineAlert",
    "ApprovalRequest",
    "SupervisorReport",
    "SupervisorConfig",
    "AlertSeverity",
    "ApprovalStatus",
    "TelegramFirewallBridge",
    "TelegramClient",
    "create_telegram_supervisor",
]
