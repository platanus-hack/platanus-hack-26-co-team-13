# Environment Variables - SAFE SETUP

⚠️ **IMPORTANT: NEVER commit tokens or secrets to GitHub**

This file explains how to set up environment variables safely without exposing credentials.

---

## Backend (.env) Variables

Create `backend/.env` file with these variables:

### Telegram Configuration

**TELEGRAM_BOT_TOKEN**
- What: Your Telegram Bot API token
- How to get: 
  1. Message @BotFather on Telegram
  2. Send `/newbot`
  3. Follow instructions to create a bot
  4. BotFather gives you a token like: `1234567890:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij`
  5. Copy the token (keep it secret!)
  6. Paste in `backend/.env` as `TELEGRAM_BOT_TOKEN=<your-token>`

**TELEGRAM_ADMIN_CHAT_ID**
- What: Your Telegram chat ID (numeric, like 123456789)
- How to get:
  1. Message your bot on Telegram
  2. Visit: `https://api.telegram.org/bot<YOUR_TOKEN>/getUpdates`
  3. Replace `<YOUR_TOKEN>` with your bot token
  4. Look for `"chat":{"id":` - copy that number
  5. Paste in `backend/.env` as `TELEGRAM_ADMIN_CHAT_ID=<your-chat-id>`

### Feature Flags (All true for full functionality)

```env
ENABLE_QUARANTINE_ALERTS=true
ENABLE_APPROVAL_WORKFLOW=true
ENABLE_DAILY_REPORTS=true
```

### Alert Thresholds

```env
ALERT_THRESHOLD=0.3
CRITICAL_THRESHOLD=0.9
```

### Timing

```env
REPORT_HOUR=9
ALERT_BATCH_DELAY=60
```

### CORS Configuration

```env
MEMORY_FIREWALL_ALLOWED_ORIGINS=http://localhost:3000,http://127.0.0.1:3000
```

For production, add your frontend domain:
```env
MEMORY_FIREWALL_ALLOWED_ORIGINS=http://localhost:3000,http://127.0.0.1:3000,https://your-frontend-domain.com
```

---

## Frontend (.env.local) Variables

Create `frontend/.env.local` file with:

**NEXT_PUBLIC_API_URL**
- Local development: `http://localhost:8000`
- Production (Render): `https://your-backend-url.onrender.com`

---

## GitHub Secrets Setup (For Deployments)

For Render/Vercel deployments, add secrets to your repository settings:

**URL:** `https://github.com/YOUR-USERNAME/YOUR-REPO/settings/secrets/actions`

Add these secrets (same values as .env):

| Secret Name | Value |
|-------------|-------|
| TELEGRAM_BOT_TOKEN | (your token from BotFather) |
| TELEGRAM_ADMIN_CHAT_ID | (your chat ID) |
| ENABLE_QUARANTINE_ALERTS | true |
| ENABLE_APPROVAL_WORKFLOW | true |
| ENABLE_DAILY_REPORTS | true |
| ALERT_THRESHOLD | 0.3 |
| CRITICAL_THRESHOLD | 0.9 |
| REPORT_HOUR | 9 |
| ALERT_BATCH_DELAY | 60 |
| MEMORY_FIREWALL_ALLOWED_ORIGINS | http://localhost:3000,http://127.0.0.1:3000 |
| NEXT_PUBLIC_API_URL | http://localhost:8000 |

---

## Security Best Practices

✅ **DO:**
- Store tokens in GitHub Secrets (encrypted)
- Use GitHub Secrets in CI/CD pipelines
- Keep .env files in .gitignore (never commit)
- Rotate tokens periodically
- Use strong, unique tokens

❌ **DON'T:**
- Commit .env files to Git
- Share tokens in chat or emails
- Hardcode tokens in source code
- Use the same token across environments
- Leave tokens in documentation

---

## Files to Never Commit

These files are protected by `.gitignore`:
- `.env` - local environment variables
- `.env.local` - frontend local variables
- `*.sqlite3` - local databases
- `*.key` - cryptographic keys
- `venv/` - Python virtual environment

---

## Testing Locally

1. Create `backend/.env` with your token
2. Run: `cd backend && python -m uvicorn api.main:app --reload`
3. Test endpoint: `curl http://localhost:8000/api/v1/telegram/status`
4. You should see: `{"status":"online","telegram_connected":true,...}`

---

## Deployment

When deploying to Render/Vercel:
1. Never manually copy tokens
2. Use GitHub Secrets instead
3. Services read secrets from GitHub automatically
4. Tokens stay encrypted and secure

---

## If Your Token Leaks

1. Immediately go to @BotFather on Telegram
2. Send `/mybots`
3. Select your bot
4. Select "Revoke current token"
5. This disables the old token instantly
6. Create a new token with `/newbot`
7. Update GitHub Secrets with new token

---

**Remember: A leaked token can compromise your bot. Always rotate immediately if exposed.**
