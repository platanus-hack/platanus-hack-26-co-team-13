"""Telegram Bot API client for supervisor notifications."""

import logging
from typing import Optional, Callable, Any
from telegram import (
    Update,
    InlineKeyboardMarkup,
    InlineKeyboardButton,
    Bot,
)
from telegram.ext import (
    Application,
    CommandHandler,
    CallbackQueryHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

logger = logging.getLogger(__name__)


class TelegramClient:
    """Telegram Bot client for sending alerts and handling user interactions."""

    def __init__(self, token: str, admin_chat_id: str):
        """Initialize Telegram client.

        Args:
            token: Telegram bot token from @BotFather
            admin_chat_id: Chat ID of admin who receives alerts
        """
        self.token = token
        self.admin_chat_id = int(admin_chat_id)
        self.bot = Bot(token=token)
        self.application: Optional[Application] = None

        # Callbacks for handling actions
        self.approval_callback: Optional[Callable] = None
        self.rejection_callback: Optional[Callable] = None
        self.details_callback: Optional[Callable] = None

        logger.info(f"TelegramClient initialized for chat {admin_chat_id}")

    async def start(self):
        """Start the Telegram bot application."""
        self.application = Application.builder().token(self.token).build()

        # Register command handlers
        self.application.add_handler(CommandHandler("start", self._handle_start))
        self.application.add_handler(CommandHandler("status", self._handle_status))
        self.application.add_handler(CommandHandler("alerts", self._handle_alerts))
        self.application.add_handler(CommandHandler("pending", self._handle_pending))
        self.application.add_handler(CommandHandler("report", self._handle_report))

        # Register callback handlers for inline buttons
        self.application.add_handler(
            CallbackQueryHandler(self._handle_callback_query)
        )

        # Register message handlers
        self.application.add_handler(
            MessageHandler(filters.TEXT & ~filters.COMMAND, self._handle_message)
        )

        # Start webhook mode (if deployed) or polling mode
        await self.application.initialize()
        await self.application.start()

        logger.info("Telegram bot started successfully")

    async def stop(self):
        """Stop the Telegram bot application."""
        if self.application:
            await self.application.stop()
            await self.application.shutdown()
        logger.info("Telegram bot stopped")

    async def send_alert(
        self,
        alert_id: str,
        severity: str,
        threat_score: float,
        content_preview: str,
        threats: list[str],
        source: str,
    ) -> bool:
        """Send alert to admin with approval/rejection buttons.

        Args:
            alert_id: Unique alert ID
            severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW)
            threat_score: Threat confidence score (0-1)
            content_preview: Content preview (first 200 chars)
            threats: List of detected threats
            source: Source of the content

        Returns:
            True if message sent successfully
        """
        try:
            # Format message
            severity_emoji = {
                "CRITICAL": "🚨",
                "HIGH": "⚠️",
                "MEDIUM": "⚠",
                "LOW": "ℹ️",
            }.get(severity, "ℹ️")

            message = f"""{severity_emoji} **{severity} Alert** ({alert_id[:8]})

**Threat Score:** {threat_score:.1%}
**Source:** {source}
**Threats Detected:**
{chr(10).join(f'• {t}' for t in threats)}

**Preview:**
```
{content_preview[:150]}...
```

**Actions:**
- Tap approve to allow (generates one-time token)
- Tap reject to block
- Tap details for full content
"""

            # Create inline buttons
            keyboard = [
                [
                    InlineKeyboardButton(
                        "✅ Approve",
                        callback_data=f"approve:{alert_id}",
                    ),
                    InlineKeyboardButton(
                        "❌ Reject",
                        callback_data=f"reject:{alert_id}",
                    ),
                ],
                [
                    InlineKeyboardButton(
                        "📄 Details",
                        callback_data=f"details:{alert_id}",
                    ),
                    InlineKeyboardButton(
                        "🔍 Query",
                        callback_data=f"query:{alert_id}",
                    ),
                ],
            ]
            reply_markup = InlineKeyboardMarkup(keyboard)

            # Send message
            message = await self.bot.send_message(
                chat_id=self.admin_chat_id,
                text=message,
                reply_markup=reply_markup,
                parse_mode="Markdown",
            )

            logger.info(f"Alert sent: {alert_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to send alert: {e}")
            return False

    async def send_approval_confirmed(
        self,
        alert_id: str,
        approval_token: str,
        expires_at: str,
    ) -> bool:
        """Send confirmation that approval was recorded.

        Args:
            alert_id: Alert ID
            approval_token: One-time token for API
            expires_at: When token expires

        Returns:
            True if sent successfully
        """
        try:
            message = f"""✅ **Approval Confirmed**

Alert: `{alert_id}`

**Token (one-time use):**
```
{approval_token}
```

**Expires:** {expires_at}

Use this token in API calls:
```
POST /api/v1/firewall/escalations/approve
?token={approval_token}
```
"""

            await self.bot.send_message(
                chat_id=self.admin_chat_id,
                text=message,
                parse_mode="Markdown",
            )

            logger.info(f"Approval confirmed sent for {alert_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to send approval confirmation: {e}")
            return False

    async def send_rejection_confirmed(
        self,
        alert_id: str,
    ) -> bool:
        """Send confirmation that rejection was recorded.

        Args:
            alert_id: Alert ID

        Returns:
            True if sent successfully
        """
        try:
            message = f"""❌ **Rejection Confirmed**

Alert: `{alert_id}`

Content has been blocked and quarantined.
"""

            await self.bot.send_message(
                chat_id=self.admin_chat_id,
                text=message,
                parse_mode="Markdown",
            )

            logger.info(f"Rejection confirmed sent for {alert_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to send rejection confirmation: {e}")
            return False

    async def send_daily_report(
        self,
        total_alerts: int,
        critical: int,
        high: int,
        medium: int,
        low: int,
        approved: int,
        rejected: int,
        pending: int,
        top_threats: list[str],
    ) -> bool:
        """Send daily report to admin.

        Args:
            total_alerts: Total alerts in period
            critical: Critical count
            high: High count
            medium: Medium count
            low: Low count
            approved: Approved count
            rejected: Rejected count
            pending: Pending approvals
            top_threats: Top 5 detected threats

        Returns:
            True if sent successfully
        """
        try:
            threats_text = "\n".join(
                f"{i+1}. {t}" for i, t in enumerate(top_threats[:5])
            )

            message = f"""📊 **Daily Report**

**Alerts Summary:**
• 🚨 Critical: {critical}
• ⚠️ High: {high}
• ⚠ Medium: {medium}
• ℹ️ Low: {low}
**Total: {total_alerts}**

**Actions Taken:**
• ✅ Approved: {approved}
• ❌ Rejected: {rejected}
• ⏳ Pending: {pending}

**Top Threats:**
{threats_text}

Review pending approvals with /pending
"""

            await self.bot.send_message(
                chat_id=self.admin_chat_id,
                text=message,
                parse_mode="Markdown",
            )

            logger.info("Daily report sent")
            return True

        except Exception as e:
            logger.error(f"Failed to send daily report: {e}")
            return False

    async def send_status(self, status_text: str) -> bool:
        """Send status message.

        Args:
            status_text: Status message to send

        Returns:
            True if sent successfully
        """
        try:
            message = f"""🤖 **Bot Status**

{status_text}
"""

            await self.bot.send_message(
                chat_id=self.admin_chat_id,
                text=message,
                parse_mode="Markdown",
            )

            return True

        except Exception as e:
            logger.error(f"Failed to send status: {e}")
            return False

    async def edit_message(
        self,
        message_id: int,
        text: str,
        reply_markup: Optional[InlineKeyboardMarkup] = None,
    ) -> bool:
        """Edit existing message.

        Args:
            message_id: ID of message to edit
            text: New text
            reply_markup: New keyboard (optional)

        Returns:
            True if edited successfully
        """
        try:
            await self.bot.edit_message_text(
                chat_id=self.admin_chat_id,
                message_id=message_id,
                text=text,
                reply_markup=reply_markup,
                parse_mode="Markdown",
            )
            return True

        except Exception as e:
            logger.error(f"Failed to edit message: {e}")
            return False

    # --- Command Handlers ---

    async def _handle_start(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /start command."""
        await update.message.reply_text(
            """🔐 **Firewall Supervisor Bot**

Available commands:
• /status - Bot status
• /alerts - Last 5 alerts
• /pending - Pending approvals
• /report - Today's report
• /critical - Critical alerts only

Or use the buttons on alert messages to approve/reject.
"""
        )

    async def _handle_status(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /status command."""
        if self.approval_callback:
            status = await self.approval_callback("get_status", {})
            await update.message.reply_text(f"🤖 **Status:** {status}")

    async def _handle_alerts(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /alerts command."""
        if self.approval_callback:
            alerts = await self.approval_callback("get_recent_alerts", {"limit": 5})
            text = "📋 **Recent Alerts:**\n\n"
            for alert in alerts:
                text += f"• {alert['alert_id'][:8]} - {alert['severity']} - {alert['source']}\n"
            await update.message.reply_text(text)

    async def _handle_pending(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /pending command."""
        if self.approval_callback:
            pending = await self.approval_callback("get_pending_approvals", {})
            text = "⏳ **Pending Approvals:**\n\n"
            for req in pending:
                text += f"• {req['alert_id'][:8]} - Use buttons to approve/reject\n"
            await update.message.reply_text(text)

    async def _handle_report(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /report command."""
        if self.approval_callback:
            report = await self.approval_callback("get_daily_report", {})
            text = f"""📊 **Daily Report**

Total Alerts: {report.get('total', 0)}
Approved: {report.get('approved', 0)}
Rejected: {report.get('rejected', 0)}
Pending: {report.get('pending', 0)}
"""
            await update.message.reply_text(text)

    async def _handle_callback_query(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ):
        """Handle inline button callbacks."""
        query = update.callback_query
        await query.answer()

        data = query.data
        command, alert_id = data.split(":", 1)

        if command == "approve":
            if self.approval_callback:
                result = await self.approval_callback("approve_alert", {"alert_id": alert_id})
                await query.edit_message_text(
                    text=f"✅ Alert {alert_id[:8]} approved!\nToken: {result.get('token', 'N/A')}"
                )

        elif command == "reject":
            if self.rejection_callback:
                await self.rejection_callback("reject_alert", {"alert_id": alert_id})
                await query.edit_message_text(
                    text=f"❌ Alert {alert_id[:8]} rejected and blocked."
                )

        elif command == "details":
            if self.details_callback:
                details = await self.details_callback("get_alert_details", {"alert_id": alert_id})
                await query.edit_message_text(
                    text=f"""📄 **Full Details**

**Content:**
```
{details.get('full_content', 'N/A')[:500]}
```

**Threats:** {', '.join(details.get('threats', []))}
**Score:** {details.get('threat_score', 0):.1%}
"""
                )

    async def _handle_message(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle regular messages."""
        await update.message.reply_text(
            "I'm a bot that handles firewall alerts. Use commands like /status or buttons on alert messages."
        )

    def set_approval_callback(self, callback: Callable):
        """Set callback for approval actions."""
        self.approval_callback = callback

    def set_rejection_callback(self, callback: Callable):
        """Set callback for rejection actions."""
        self.rejection_callback = callback

    def set_details_callback(self, callback: Callable):
        """Set callback for details requests."""
        self.details_callback = callback
