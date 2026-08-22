# Quick Deployment (10 minutos)

## TL;DR - Instrucciones Rápidas

Este guía tiene instrucciones paso a paso de 10 minutos para desplegar en Vercel + Render.

**Para detalles completos, ver:** `DEPLOYMENT_GUIDE.md`

---

## 1️⃣ GitHub (Ya hecho ✅)

Tu código está en GitHub y listo para desplegar:
```bash
git log --oneline -1
# Deberías ver: d2538bc chore: Add Vercel + Render deployment configuration
```

---

## 2️⃣ Backend en Render (5 minutos)

### Crear cuenta

1. Ve a https://render.com
2. Haz click **"Sign up with GitHub"**
3. Autoriza a Render
4. Crea tu account

### Desplegar Backend

1. **Dashboard Render** → Click **"+ New"** → **"Web Service"**

2. **Conectar GitHub:**
   - Busca repo: `platanus-hack-26-co-team-13`
   - Haz click **"Connect"**

3. **Configurar:**
   - **Name**: `platanus-backend`
   - **Environment**: `Python 3.11`
   - **Region**: La más cercana a ti
   - **Branch**: `main`
   - **Root Directory**: `backend` ← IMPORTANTE

4. **Build/Start:**
   - Build: `pip install -r requirements.txt`
   - Start: `uvicorn api.main:app --host 0.0.0.0 --port 8000`

5. **Variables (copy-paste exacto):**
   ```
   TELEGRAM_BOT_TOKEN=[REDACTED_DO_NOT_COMMIT]
   TELEGRAM_ADMIN_CHAT_ID=[REDACTED_CHAT_ID]
   ENABLE_QUARANTINE_ALERTS=true
   ENABLE_APPROVAL_WORKFLOW=true
   ENABLE_DAILY_REPORTS=true
   ALERT_THRESHOLD=0.3
   CRITICAL_THRESHOLD=0.9
   REPORT_HOUR=9
   ALERT_BATCH_DELAY=60
   MEMORY_FIREWALL_ALLOWED_ORIGINS=http://localhost:3000,http://127.0.0.1:3000,https://platanus-frontend.vercel.app
   ```

6. **Deploy** → Espera 3-5 min

7. **Copia la URL**, ejemplo: `https://platanus-backend-abc123.onrender.com`

---

## 3️⃣ Frontend en Vercel (3 minutos)

### Crear cuenta

1. Ve a https://vercel.com
2. Haz click **"Sign up with GitHub"**
3. Autoriza a Vercel
4. Crea tu account

### Desplegar Frontend

1. **Dashboard Vercel** → Click **"Add New"** → **"Project"**

2. **Seleccionar repo:**
   - Busca: `platanus-hack-26-co-team-13`
   - Haz click **"Import"**

3. **Configurar:**
   - **Framework**: Next.js (auto-detectado)
   - **Root Directory**: `frontend/` ← IMPORTANTE

4. **Variables (reemplaza con tu URL de Render):**
   ```
   NEXT_PUBLIC_API_URL=https://platanus-backend-abc123.onrender.com
   ```

5. **Deploy** → Espera 1-2 min

6. **Copia la URL**, ejemplo: `https://platanus-frontend-xyz789.vercel.app`

---

## 4️⃣ Probar (1 minuto)

### Abre el frontend

```
https://platanus-frontend-xyz789.vercel.app
```

Deberías ver la landing page de Provenance Firewall.

### Envía un alert (desde terminal)

```bash
BACKEND="https://platanus-backend-abc123.onrender.com"

curl -X POST ${BACKEND}/api/v1/telegram/send-alert \
  -H "Content-Type: application/json" \
  -d '{
    "severity": "HIGH",
    "content_preview": "Production test",
    "threats": ["test"],
    "threat_score": 0.85,
    "source": "vercel_test"
  }'
```

### Revisa Telegram

En segundos deberías recibir el alert en `@provenancePlatanus_bot`

---

## 5️⃣ Futuro: Auto-Deployments

Ahora, cada push a `main` automáticamente:

```bash
git add .
git commit -m "tu cambio"
git push origin main
```

✅ Vercel redespliega (1-2 min)
✅ Render redespliega (3-5 min)

---

## URLs Finales

```
Frontend:  https://platanus-frontend-xyz789.vercel.app
Backend:   https://platanus-backend-abc123.onrender.com
Telegram:  @provenancePlatanus_bot
GitHub:    https://github.com/platanus-hack/platanus-hack-26-co-team-13
```

---

## ⚠️ IMPORTANTE

- **NEVER** commit tu `.env` file (it's in .gitignore)
- **Variables en Render/Vercel** son las "production" variables
- **CORS** ya está configurado (no tocar)
- **Build commands** son exactas (no cambiar)

---

## Problemas?

**Backend no arranca:**
- Revisa logs en Render Dashboard
- Verifica variables de entorno
- Asegúrate Root Directory = `backend`

**Frontend no ve el backend:**
- Verifica `NEXT_PUBLIC_API_URL` en Vercel
- La URL debe empezar con `https://`
- Sin trailing slash

**Telegram no recibe alerts:**
- Token: `[REDACTED_DO_NOT_COMMIT]`
- Chat ID: `[REDACTED_CHAT_ID]`
- Verifica en logs de Render

---

**¡Listo!** Tu app está en producción. 🚀
