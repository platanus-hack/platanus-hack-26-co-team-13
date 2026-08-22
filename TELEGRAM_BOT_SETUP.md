# Telegram Supervisor Bot - Setup Guide

Complete guide to set up the Telegram bot for real-time firewall alert notifications.

## Step 1: Create a Telegram Bot

### On your phone (or web.telegram.org):
1. Open Telegram
2. Search for "@BotFather" and start a conversation
3. Type: `/newbot`
4. Follow the prompts:
   - Name: `Firewall Supervisor` (or your preferred name)
   - Username: `your_project_firewall_bot` (must be unique, can use your project name)
5. BotFather will respond with a message containing your **Bot Token**

Example token: `123456789:ABCDefGHIjklMNOpqrsTUVwxyz1234567890`

**⚠️ Keep this token secret! Store it safely.**

## Step 2: Get Your Chat ID

1. Search for "@userinfobot" on Telegram
2. Start a conversation with it
3. It will reply with your Chat ID (a number like `987654321`)

**Note:** This is where the bot will send all alerts. You can be the admin, or add a dedicated admin user.

## Step 3: Configure Environment Variables

Create or edit your `.env` file in the backend root directory:

```bash
# backend/.env

# Telegram Bot Setup (from Steps 1-2 above)
TELEGRAM_BOT_TOKEN=123456789:ABCDefGHIjklMNOpqrsTUVwxyz1234567890
TELEGRAM_ADMIN_CHAT_ID=987654321

# Feature Flags (all enabled by default)
ENABLE_QUARANTINE_ALERTS=true
ENABLE_APPROVAL_WORKFLOW=true
ENABLE_DAILY_REPORTS=true

# Alert Thresholds (0-1 scale)
ALERT_THRESHOLD=0.3          # Show alerts above this threat score
CRITICAL_THRESHOLD=0.9       # Mark as CRITICAL above this

# Timing
REPORT_HOUR=9                # Hour to send daily report (UTC, 24h format)
ALERT_BATCH_DELAY=60         # Seconds to wait before batching non-critical alerts
```

## Step 4: Install Dependencies

```bash
cd backend

# Install python-telegram-bot and other dependencies
pip install -r requirements.txt

# Or install just the telegram dependencies if you already have the others:
pip install "python-telegram-bot>=20.0,<21.0" "aiohttp>=3.8.0,<4.0.0"
```

## Step 5: Start the Backend

```bash
cd backend

# Run the API server (bot will connect automatically)
python -m api.main

# Or use uvicorn directly:
uvicorn api.main:app --reload --host 127.0.0.1 --port 8000
```

You should see in the logs:
```
INFO:__main__:Telegram Supervisor configured and will start on app startup
INFO:__main__:Starting Telegram Supervisor...
INFO:telegram_supervisor.telegram_client:TelegramClient initialized for chat 987654321
INFO:telegram_supervisor.bot:Telegram Supervisor Bot started successfully
```

## Step 6: Test the Bot

### Test via Telegram:
1. Open Telegram
2. Find your bot (search for the username you created in Step 1)
3. Click `/start` to see available commands:
   - `/status` - Get bot status
   - `/alerts` - See recent alerts
   - `/pending` - Pending approvals
   - `/report` - Today's report
   - `/critical` - Critical alerts only

### Test via API:
```bash
# Get bot status
curl http://127.0.0.1:8000/api/v1/telegram/status

# Send a test alert
curl -X POST http://127.0.0.1:8000/api/v1/telegram/send-alert \
  -H "Content-Type: application/json" \
  -d '{
    "severity": "HIGH",
    "content_preview": "Suspicious code detected",
    "threats": ["prompt_injection"],
    "threat_score": 0.85,
    "source": "test"
  }'

# Send daily report
curl -X POST http://127.0.0.1:8000/api/v1/telegram/send-report
```

## Step 7: Hook Alerts from Memory Firewall

When Memory Firewall detects content, send it to Telegram:

```python
# In your code where Memory Firewall runs:
from api import telegram_routes

# From main.py, you have access to telegram_supervisor:
if telegram_supervisor:
    alert = QuarantineAlert(
        severity=AlertSeverity.HIGH,
        content_preview=content[:200],
        full_content=content,
        source="memory_firewall_analysis",
        threats_detected=threats,
        threat_score=threat_score,
        authority_assigned="untrusted",
    )
    await telegram_supervisor.on_quarantine_alert(alert)
```

Or use the bridge:

```python
# Using the telegram_bridge from main.py:
if telegram_bridge:
    alert_id = await telegram_bridge.on_memory_quarantined(
        analysis_id="ana_123",
        content=content,
        threats_detected=threats,
        threat_score=threat_score,
        authority="untrusted",
        source="email_attachment",
    )
```

## Step 8: Hook Alerts from Provenance Firewall

When Provenance Firewall blocks an action, send it to Telegram:

```python
# In provenance_firewall authorization code:
if telegram_bridge:
    alert_id = await telegram_bridge.on_action_blocked(
        tool_name="send_file_external",
        args={"file": "sensitive_data.csv", "recipient": "external@evil.com"},
        reason="Tool requires org_verified but source is untrusted",
        taint_level="untrusted",
        required_level="org_verified",
    )
```

## Alert Workflow in Telegram

### 1. Alert arrives:
```
🚨 HIGH Alert (5f2e1a3c)

Threat Score: 85.0%
Source: external_email
Threats Detected:
• prompt_injection
• data_exfiltration

Preview:
`Ignore previous instructions...`

Actions:
[✅ Approve] [❌ Reject] [📄 Details] [🔍 Query]
```

### 2. Click "✅ Approve":
The bot generates a one-time token:

```
✅ Approval Confirmed

Alert: `5f2e1a3c`

Token (one-time use):
`Au2SptnCqkKGpxWUlKWC...`

Expires: 2026-08-23 20:30:49

Use this token in API calls:
POST /api/v1/firewall/escalations/approve
?token=Au2SptnCqkKGpxWUlKWC...
```

### 3. Daily Report (9 AM UTC):
```
📊 Daily Report

Alerts Summary:
• 🚨 Critical: 2
• ⚠️ High: 5
• ⚠ Medium: 12
• ℹ️ Low: 3
Total: 22

Actions Taken:
• ✅ Approved: 4
• ❌ Rejected: 2
• ⏳ Pending: 3

Top Threats:
1. prompt_injection
2. secret_exfiltration
3. sql_injection
```

## Troubleshooting

### Bot doesn't respond
- Check that `TELEGRAM_BOT_TOKEN` is correct (no spaces or typos)
- Make sure the bot token is still valid (@BotFather can regenerate it)
- Check logs for errors: `grep "Telegram" <logs>`

### Can't approve alerts
- Verify `TELEGRAM_ADMIN_CHAT_ID` is correct
- Make sure bot has message permissions (should be automatic)
- Check that approval workflow is enabled: `ENABLE_APPROVAL_WORKFLOW=true`

### Alerts not appearing
- Confirm Memory Firewall is calling `telegram_supervisor.on_quarantine_alert()`
- Check that `ENABLE_QUARANTINE_ALERTS=true`
- Verify alert severity is above `ALERT_THRESHOLD` (default 0.3)
- CRITICAL alerts are sent immediately, others are batched after `ALERT_BATCH_DELAY`

### Can't get daily report
- Check `ENABLE_DAILY_REPORTS=true`
- Daily report is sent at `REPORT_HOUR` (default 9 UTC)
- Or manually trigger with: `curl -X POST http://127.0.0.1:8000/api/v1/telegram/send-report`

## Security Notes

⚠️ **Important:**
- Bot tokens should be treated as secrets (like passwords)
- Never commit tokens to git - use environment variables
- Approval tokens are one-time use and expire after 24 hours
- All approvals are logged with timestamp and user ID
- Content preview is 200 chars; full content in `/details` command only

## API Reference

Full REST API documentation available at: `/api/v1/telegram`

### Endpoints:
- `GET /api/v1/telegram/status` - Bot status
- `GET /api/v1/telegram/alerts/pending?limit=10` - Pending alerts
- `GET /api/v1/telegram/alerts/recent?limit=10` - Recent alerts
- `GET /api/v1/telegram/alerts/{alert_id}` - Alert details
- `GET /api/v1/telegram/approvals/pending?limit=10` - Pending approvals
- `GET /api/v1/telegram/approvals/{request_id}` - Approval details
- `POST /api/v1/telegram/approvals/{alert_id}/approve` - Approve alert
- `POST /api/v1/telegram/approvals/{alert_id}/reject` - Reject alert
- `GET /api/v1/telegram/report/daily` - Daily report
- `POST /api/v1/telegram/send-alert` - Send test alert
- `POST /api/v1/telegram/send-report` - Send report manually

See `backend/api/telegram_routes.py` for complete API documentation.

## Architecture Diagram

```
Memory Firewall        Provenance Firewall
     ↓                        ↓
  on_memory_quarantined   on_action_blocked
     ↓                        ↓
  TelegramFirewallBridge
     ├─ Create QuarantineAlert
     ├─ Assign severity
     └─ Call supervisor.on_quarantine_alert()
            ↓
      TelegramSupervisor
    ├─ alert_queue (non-critical)
    ├─ critical alerts (immediate send)
    ├─ approval_requests (track approvals)
    └─ alert_history (for reports)
            ↓
      TelegramClient
    ├─ send_alert() + buttons
    ├─ send_approval_confirmed()
    ├─ send_daily_report()
    └─ Handle commands & callbacks
            ↓
        Telegram API
            ↓
        Admin Chat
```

## Files Structure

```
backend/
├── telegram_supervisor/
│   ├── __init__.py              (Package exports)
│   ├── models.py                (Data classes)
│   ├── bot.py                   (TelegramSupervisor orchestrator)
│   ├── handlers.py              (Alert/approval/report handlers)
│   ├── api_integration.py       (Firewall bridge)
│   ├── telegram_client.py       (Telegram API client) ← NEW
│   ├── README.md                (Feature documentation)
│   ├── INTEGRATION_GUIDE.md     (Integration steps)
│   ├── config_example.env       (Configuration template)
│   └── requirements.txt         (Dependencies)
│
├── api/
│   ├── main.py                  (Modified: add Telegram init)
│   ├── telegram_routes.py       (REST endpoints) ← NEW
│   └── provenance_routes.py     (Existing)
│
├── requirements.txt             (Modified: add telegram deps)
└── .env                         (Create this: your config)
```

## Next Steps

1. **Test with real bot**: Set up bot, get token, configure `.env`, start backend
2. **Hook into firewalls**: Integrate `telegram_bridge` calls when alerts happen
3. **Database persistence** (Phase 3): Store alerts persistently
4. **Advanced features** (Phase 4): Message reactions, advanced scheduling

---

**Questions?** Check the logs, or review the code in `backend/telegram_supervisor/` for implementation details.
