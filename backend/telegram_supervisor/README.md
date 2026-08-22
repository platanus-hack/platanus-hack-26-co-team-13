# Telegram Supervisor Bot

Real-time monitoring and management of Memory Firewall & Provenance Firewall events via Telegram.

## Features

### 1. **Quarantine Alerts** 🚨
- Real-time notifications when content is quarantined
- Severity levels: CRITICAL, HIGH, MEDIUM, LOW
- Content preview and threat detection details
- Smart batching for non-critical alerts

### 2. **Approval Workflow** ✅
- Admin can approve/reject quarantined content
- One-time approval tokens for secure authorization
- 24-hour expiry for security
- Audit trail of all decisions

### 3. **Daily Reports** 📊
- Summary of all alerts and actions taken
- Statistics by severity level
- Top detected threats
- Recommendations based on patterns

### 4. **Integration** 🔗
- Seamless integration with Memory Firewall (content analysis)
- Seamless integration with Provenance Firewall (action blocking)
- Real-time bridge between firewalls and Telegram

## Architecture

```
Memory Firewall          Provenance Firewall
      ↓                         ↓
   [Quarantine Alert]    [Action Blocked]
      ↓                         ↓
      └─────→ TelegramFirewallBridge ←─────┘
              ↓
        TelegramSupervisor
        ├─ QuarantineHandler (alerts)
        ├─ ApprovalHandler (approvals)
        └─ ReportHandler (reports)
              ↓
         Telegram Bot
              ↓
         Admin Chat
```

## Models

### QuarantineAlert
```python
QuarantineAlert(
    alert_id: str,              # Unique ID
    timestamp: datetime,         # When detected
    severity: AlertSeverity,     # CRITICAL | HIGH | MEDIUM | LOW
    content_preview: str,        # First 200 chars
    full_content: str,           # Complete content
    source: str,                 # email, user_input, web, etc.
    threats_detected: list,      # ["prompt_injection", "secret_exfiltration"]
    threat_score: float,         # 0-1 confidence
    authority_assigned: str,     # untrusted, observed, user_confirmed, etc.
)
```

### ApprovalRequest
```python
ApprovalRequest(
    request_id: str,             # Unique ID
    alert_id: str,               # Which alert this is for
    status: ApprovalStatus,      # PENDING | APPROVED | REJECTED
    approved_by: str,            # Telegram user ID who decided
    approval_token: str,         # One-time token for API
    expires_at: datetime,        # When token expires (24h)
)
```

### SupervisorReport
```python
SupervisorReport(
    report_id: str,              # Unique ID
    period_start: datetime,      # Period covered
    period_end: datetime,
    total_alerts: int,           # All alerts
    critical_alerts: int,        # By severity
    high_alerts: int,
    medium_alerts: int,
    low_alerts: int,
    total_approved: int,         # Admin actions
    total_rejected: int,
    pending_approvals: int,
)
```

## Usage

### Basic Setup

```python
from telegram_supervisor import TelegramSupervisor, SupervisorConfig

# Create config
config = SupervisorConfig(
    telegram_token="YOUR_BOT_TOKEN",
    admin_chat_id="YOUR_CHAT_ID",
)

# Create supervisor
supervisor = TelegramSupervisor(config)
await supervisor.start()
```

### Integration with Memory Firewall

```python
from telegram_supervisor import TelegramFirewallBridge

bridge = TelegramFirewallBridge(supervisor)

# When Memory Firewall detects quarantine:
alert_id = await bridge.on_memory_quarantined(
    analysis_id="ana_123",
    content="Ignore previous instructions...",
    threats_detected=["prompt_injection"],
    threat_score=0.95,
    authority="untrusted",
    source="external_email",
)
```

### Integration with Provenance Firewall

```python
# When Provenance Firewall blocks action:
alert_id = await bridge.on_action_blocked(
    tool_name="send_file_external",
    args={"file": "database.csv", "recipient": "attacker@evil.com"},
    reason="Action requires org_verified but source is untrusted",
    taint_level="untrusted",
    required_level="org_verified",
)
```

### Handling Approvals

```python
# Admin approves via Telegram command
approval = await supervisor.approve_alert(
    request_id="req_123",
    approved_by="user_456",
    reason="Verified via phone callback",
)

# Get approval token for API
token = approval.approval_token

# Use token in API:
# POST /api/v1/firewall/escalations/esc_123/approve?token=<token>
```

## Telegram Commands

### For Admins

```
/status              - Current system status
/alerts             - Last 5 alerts
/critical           - Critical alerts only
/pending            - Pending approvals
/report             - Today's report
/approve_<id>       - Approve alert
/reject_<id>        - Reject alert
/details_<id>       - Alert full details
```

### Examples

```
/approve_5f2e1a3c   - Approve alert with ID 5f2e1a3c
/reject_5f2e1a3c reason:False positive in regex
/details_5f2e1a3c   - View full details of alert
```

## File Structure

```
telegram_supervisor/
├── __init__.py              # Package init
├── models.py                # Data models
├── bot.py                   # Main supervisor bot
├── handlers.py              # Quarantine, Approval, Report handlers
├── api_integration.py       # Bridge with firewall APIs
├── telegram_client.py       # (TODO) Telegram API client
├── README.md                # This file
└── requirements.txt         # Dependencies
```

## Dependencies

```
python-telegram-bot>=20.0
aiohttp>=3.8.0
pydantic>=2.0.0
```

## Next Steps

1. **Implement Telegram Client** (`telegram_client.py`)
   - Handle message sending to admin
   - Command parsing
   - Message formatting

2. **Add API Endpoint** (`../api/telegram_routes.py`)
   - `POST /api/v1/telegram/webhook` - Receive Telegram updates
   - `GET /api/v1/telegram/status` - Bot status

3. **Database Integration**
   - Persist alerts to database
   - Persist approval history
   - Query for reports

4. **Advanced Features**
   - Message reactions (👍 approve, 👎 reject)
   - Inline keyboards for quick actions
   - Alert scheduling/throttling
   - Custom threat rules per admin

## Security Considerations

1. **Token Security**
   - Approval tokens are one-time use
   - 24-hour expiry prevents replay attacks
   - Tokens are cryptographically secure (secrets.token_urlsafe)

2. **Admin Authentication**
   - Only specified admin chat ID can approve
   - All approvals logged with user ID and timestamp

3. **Content Privacy**
   - Full content not sent to Telegram (preview only)
   - Full content available via `/details` command

4. **Rate Limiting**
   - Batching prevents spam
   - Alert thresholds filter noise
