# Telegram Bot - Final Setup Steps

## Status

✅ **Bot Token Configured**
- Token saved in `backend/.env`
- Bot created via @BotFather

⏳ **Waiting For**
- Your Chat ID (from @userinfobot)

---

## Step-by-Step Setup

### 1️⃣ Get Your Chat ID (You do this)

1. Open Telegram
2. Search for: **@userinfobot**
3. Start a conversation (tap START)
4. The bot will respond with your information including **User ID**
5. Copy that number

Example response:
```
User ID: 987654321
First name: John
Username: @john_doe
```

Copy the number: `987654321`

---

### 2️⃣ Provide Chat ID (Tell me the number)

Once you have your Chat ID, just send me the number (example: `987654321`)

I will then:
- Update `backend/.env` with your Chat ID
- Test the bot connection
- Send you a test message
- Verify everything works

---

### 3️⃣ Start the Backend

Once verified, you'll run:

```bash
cd backend
python -m api.main
```

You should see:
```
INFO: Telegram Supervisor configured...
INFO: Starting Telegram Supervisor...
INFO: Telegram Supervisor Bot started successfully
```

---

### 4️⃣ Test in Telegram

1. Find your bot (search for the username you gave it to @BotFather)
2. Open the chat
3. Type: `/start`
4. You'll see the welcome message with available commands:
   - `/status` - Bot status
   - `/alerts` - Recent alerts
   - `/pending` - Pending approvals
   - `/report` - Daily report
   - `/critical` - Critical alerts only

---

### 5️⃣ Send Test Alert

```bash
curl -X POST http://127.0.0.1:8000/api/v1/telegram/send-alert \
  -H "Content-Type: application/json" \
  -d '{
    "severity": "HIGH",
    "content_preview": "Test alert from firewall",
    "threats": ["prompt_injection"],
    "threat_score": 0.85,
    "source": "test"
  }'
```

Check Telegram - you should see the alert with buttons!

---

## What's Happening Behind the Scenes

```
Your Code (Memory Firewall)
    ↓
telegram_bridge.on_memory_quarantined()
    ↓
TelegramSupervisor (receives alert)
    ├─ Stores in database
    ├─ Checks severity
    └─ Sends to Telegram
         ↓
    TelegramClient
         ↓
    Telegram API
         ↓
    Your Telegram Chat
         ↓
    You click "Approve"
         ↓
    One-time token generated
         ↓
    Token stored in database
         ↓
    You use token in API
```

---

## File Structure

```
backend/
├── .env                           ← Your config (TOKEN + CHAT_ID)
├── api/
│   ├── main.py                    ← FastAPI app
│   ├── telegram_routes.py         ← 11 REST endpoints
│   └── provenance_routes.py
├── telegram_supervisor/
│   ├── bot.py                     ← Main orchestrator
│   ├── telegram_client.py         ← Telegram API
│   ├── database.py                ← SQLite persistence
│   ├── models.py                  ← Data structures
│   ├── handlers.py                ← Alert handlers
│   └── api_integration.py         ← Firewall bridge
└── requirements.txt               ← Dependencies
```

---

## Once Everything is Running

### Send Alerts from Memory Firewall:

```python
from api.main import telegram_bridge

if telegram_bridge:
    alert_id = await telegram_bridge.on_memory_quarantined(
        analysis_id="ana_123",
        content="Malicious content detected",
        threats_detected=["prompt_injection", "data_exfiltration"],
        threat_score=0.95,
        authority="untrusted",
        source="external_email",
    )
```

### Send Alerts from Provenance Firewall:

```python
if telegram_bridge:
    alert_id = await telegram_bridge.on_action_blocked(
        tool_name="send_file_external",
        args={"file": "sensitive_data.csv", "recipient": "attacker@evil.com"},
        reason="Action requires org_verified but source is untrusted",
        taint_level="untrusted",
        required_level="org_verified",
    )
```

### API Endpoints Available:

```bash
# Get status
curl http://127.0.0.1:8000/api/v1/telegram/status

# Get recent alerts
curl http://127.0.0.1:8000/api/v1/telegram/alerts/recent?limit=10

# Get pending approvals
curl http://127.0.0.1:8000/api/v1/telegram/approvals/pending

# Manually approve
curl -X POST http://127.0.0.1:8000/api/v1/telegram/approvals/{alert_id}/approve

# Manually reject
curl -X POST http://127.0.0.1:8000/api/v1/telegram/approvals/{alert_id}/reject

# Get daily report
curl http://127.0.0.1:8000/api/v1/telegram/report/daily
```

---

## Approval Workflow in Telegram

When an alert arrives in Telegram:

```
🚨 HIGH Alert (5f2e1a3c)

Threat Score: 85.0%
Source: external_email
Threats Detected:
• prompt_injection

Preview:
`Ignore previous instructions...`

[✅ Approve] [❌ Reject] [📄 Details] [🔍 Query]
```

If you click **Approve**:

```
✅ Approval Confirmed

Alert: `5f2e1a3c`

Token (one-time use):
`Au2SptnCqkKGpxWUlKWC...`

Expires: 2026-08-23 20:30:49

Use in API:
POST /api/v1/firewall/escalations/approve?token=Au2Spt...
```

---

## Troubleshooting

### Bot doesn't connect
- Check `TELEGRAM_BOT_TOKEN` is correct
- Make sure token is from @BotFather (starts with number:ABC...)

### Can't find bot in Telegram
- Make sure you created it with @BotFather
- The username must be unique

### Alerts don't appear
- Check `TELEGRAM_ADMIN_CHAT_ID` is correct (numeric only)
- Make sure backend is running
- Check logs for errors

### Approvals not working
- Enable: `ENABLE_APPROVAL_WORKFLOW=true` in .env
- Make sure alert severity is visible (above threshold)

---

## Configuration Options

All in `backend/.env`:

```bash
# Required
TELEGRAM_BOT_TOKEN=your_token
TELEGRAM_ADMIN_CHAT_ID=your_chat_id

# Features
ENABLE_QUARANTINE_ALERTS=true
ENABLE_APPROVAL_WORKFLOW=true
ENABLE_DAILY_REPORTS=true

# Thresholds (0-1 scale)
ALERT_THRESHOLD=0.3              # Show alerts above 30%
CRITICAL_THRESHOLD=0.9           # CRITICAL above 90%

# Timing
REPORT_HOUR=9                    # Daily report at 9 AM UTC
ALERT_BATCH_DELAY=60             # Batch non-critical every 60 seconds
```

---

## Next Actions

1. **Get your Chat ID** from @userinfobot
2. **Send it to me** (just the number)
3. **I'll verify everything works**
4. **You run:** `python -m api.main`
5. **Alerts start flowing to Telegram!**

---

**Ready?** Send me your Chat ID and let's finish this! 🚀
