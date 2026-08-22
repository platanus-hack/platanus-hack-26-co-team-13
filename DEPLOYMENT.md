# Deployment

Single source of truth for deploying this project. Backend on Render, frontend
on Vercel. Both connect to a repository **you own** (personal/mirror), since
deploy platforms cannot connect to the organization repo directly.

## Prerequisites

- A GitHub repo you own (mirror of this project).
- Accounts on [Render](https://render.com) and [Vercel](https://vercel.com).
- A Telegram bot token from [@BotFather](https://t.me/BotFather) (only if you
  use the Telegram supervisor feature).

## Environment variables

Never commit real secrets. Set them in the platform dashboards.

### Backend (Render)

| Variable | Required | Example |
|----------|----------|---------|
| `TELEGRAM_BOT_TOKEN` | if bot enabled | `123456:ABC...` (from BotFather) |
| `TELEGRAM_ADMIN_CHAT_ID` | if bot enabled | your numeric chat id |
| `TELEGRAM_API_KEY` | yes (protects POST endpoints) | `openssl rand -hex 32` |
| `MEMORY_FIREWALL_ALLOWED_ORIGINS` | yes | `https://your-frontend.vercel.app` |
| `ENABLE_QUARANTINE_ALERTS` | no | `true` |
| `ENABLE_APPROVAL_WORKFLOW` | no | `true` |
| `ENABLE_DAILY_REPORTS` | no | `true` |

See `backend/.env.example` for the full list and local defaults.

### Frontend (Vercel)

| Variable | Required | Example |
|----------|----------|---------|
| `NEXT_PUBLIC_API_URL` | yes | `https://your-backend.onrender.com` |

## Deploy the backend (Render)

1. New → **Web Service** → connect your repo.
2. Render auto-detects `render.yaml` (root dir `backend`, uvicorn start command).
3. Fill in the `sync: false` secrets when prompted.
4. Deploy. Verify: `curl https://<your-backend>.onrender.com/api/v1/telegram/status`

## Deploy the frontend (Vercel)

1. New Project → import your repo.
2. Set **Root Directory** to `frontend`.
3. Add `NEXT_PUBLIC_API_URL` pointing at the Render backend URL.
4. Deploy.

## After deploy

- Update `MEMORY_FIREWALL_ALLOWED_ORIGINS` on the backend with the real Vercel
  URL, then redeploy the backend so CORS allows the frontend.
- Calls to state-changing endpoints require the `X-API-Key` header matching
  `TELEGRAM_API_KEY`.

## Local development

```bash
# backend
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn api.main:app --reload

# frontend
cd frontend
npm install
npm run dev
```
