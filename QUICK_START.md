# Telegram Supervisor Bot - Quick Start

Get the Telegram bot running in 5 minutes.

## Prerequisites
- Telegram account
- Python 3.9+
- Git

## Steps

### 1. Get Bot Token
```bash
Open Telegram
Search: @BotFather
Type: /newbot
Name: Firewall Supervisor (or your name)
Username: your_firewall_bot (must be unique)
Save the TOKEN
```

### 2. Get Your Chat ID
```bash
Search: @userinfobot
Save the CHAT_ID (numeric)
```

### 3. Create .env File
```bash
cd backend
cat > .env << 'DOTENV'
TELEGRAM_BOT_TOKEN=123456789:ABCDefGHIjklMNOpqrsTUVwxyz
TELEGRAM_ADMIN_CHAT_ID=987654321
ENABLE_QUARANTINE_ALERTS=true
ENABLE_APPROVAL_WORKFLOW=true
ENABLE_DAILY_REPORTS=true
DOTENV
```

### 4. Install Dependencies
```bash
pip install -r requirements.txt
```

### 5. Start Backend
```bash
python -m api.main
```

You should see:
```
INFO: Telegram Supervisor configured and will start on app startup
INFO: Starting Telegram Supervisor...
INFO: Telegram Supervisor Bot started successfully
```

### 6. Test Bot
Open Telegram, find your bot, type `/start`

You'll see:
```
🔐 Firewall Supervisor Bot

Available commands:
• /status - Bot status
• /alerts - Last 5 alerts
• /pending - Pending approvals
• /report - Today's report
• /critical - Critical alerts only
```

### 7. Send Test Alert
```bash
curl -X POST http://127.0.0.1:8000/api/v1/telegram/send-alert \
  -H "Content-Type: application/json" \
  -d '{
    "severity": "HIGH",
    "content_preview": "Suspicious code detected",
    "threats": ["prompt_injection"],
    "threat_score": 0.85,
    "source": "test"
  }'
```

Check Telegram - you should see the alert with buttons!

## How to Send Alerts from Code

### From Memory Firewall
```python
from api.main import telegram_bridge

if telegram_bridge:
    await telegram_bridge.on_memory_quarantined(
        analysis_id="ana_123",
        content="Malicious content",
        threats_detected=["prompt_injection"],
        threat_score=0.95,
        authority="untrusted",
        source="email",
    )
```

### From Provenance Firewall
```python
if telegram_bridge:
    await telegram_bridge.on_action_blocked(
        tool_name="send_file_external",
        args={"file": "data.csv"},
        reason="Untrusted source",
        taint_level="untrusted",
        required_level="org_verified",
    )
```

## Approving Alerts

1. Click "✅ Approve" on alert in Telegram
2. Bot generates one-time token
3. Use token in API: `POST /api/v1/firewall/escalations/approve?token=...`

## API Endpoints

```bash
# Get bot status
curl http://127.0.0.1:8000/api/v1/telegram/status

# Get recent alerts
curl http://127.0.0.1:8000/api/v1/telegram/alerts/recent?limit=10

# Get pending approvals
curl http://127.0.0.1:8000/api/v1/telegram/approvals/pending

# Get daily report
curl http://127.0.0.1:8000/api/v1/telegram/report/daily

# Approve alert manually
curl -X POST http://127.0.0.1:8000/api/v1/telegram/approvals/{alert_id}/approve

# Reject alert manually
curl -X POST http://127.0.0.1:8000/api/v1/telegram/approvals/{alert_id}/reject
```

## Configuration

See `TELEGRAM_BOT_SETUP.md` for full configuration options.

Key settings:
- `ALERT_THRESHOLD=0.3` - Show alerts above 30% threat score
- `CRITICAL_THRESHOLD=0.9` - Mark as CRITICAL above 90%
- `ALERT_BATCH_DELAY=60` - Batch non-critical alerts every 60 seconds
- `REPORT_HOUR=9` - Send daily report at 9 AM UTC

## Database

Data is persisted in `telegram_bot.sqlite3`:
- All alerts stored
- All approvals logged
- Reports archived
- No data loss on restart

## Troubleshooting

### Bot doesn't connect
- Check `TELEGRAM_BOT_TOKEN` is correct (no spaces, copy exactly)
- Verify token is still valid (@BotFather can regenerate)

### Can't send alerts
- Check `TELEGRAM_ADMIN_CHAT_ID` is correct
- Ensure alerts are enabled: `ENABLE_QUARANTINE_ALERTS=true`
- Check alert threat score > `ALERT_THRESHOLD`

### Approvals not working
- Enable: `ENABLE_APPROVAL_WORKFLOW=true`
- Check logs for errors: `grep Approval <logs>`

## Documentation

- `TELEGRAM_BOT_SETUP.md` - Complete setup guide
- `backend/telegram_supervisor/README.md` - Feature documentation
- `backend/telegram_supervisor/INTEGRATION_GUIDE.md` - Integration steps
- Code comments and docstrings

## Next Steps

Once working:
1. Hook Memory Firewall alerts to telegram_bridge
2. Hook Provenance Firewall blocks to telegram_bridge
3. Use approval tokens in firewall escalation endpoints
4. Monitor alerts in real-time via Telegram!

---

**Any issues?** Read `TELEGRAM_BOT_SETUP.md` for full troubleshooting.
