# Deployment Guide: Vercel + Render

Este documento explica cómo desplegar la aplicación en producción:
- **Frontend**: Vercel
- **Backend**: Render

## Arquitectura

```
┌─────────────────────────────────────────────────────────────┐
│                      GitHub (main branch)                    │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌────────────────────────┐       ┌──────────────────────┐  │
│  │  /frontend (Next.js)   │       │  /backend (FastAPI)  │  │
│  └────────────────────────┘       └──────────────────────┘  │
│           │                                │                  │
│           ▼                                ▼                  │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │          Automatic Deployments via Webhooks             │ │
│  └─────────────────────────────────────────────────────────┘ │
│           │                                │                  │
│           ▼                                ▼                  │
│  ┌────────────────────┐       ┌─────────────────────────┐   │
│  │      VERCEL        │       │      RENDER             │   │
│  │ (CDN Global)       │       │ (Python App Container)  │   │
│  │ /app.vercel.app    │       │ /api.onrender.com       │   │
│  └────────────────────┘       └─────────────────────────┘   │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

## Requisitos

- GitHub account (ya tienes)
- Vercel account (https://vercel.com - Sign up with GitHub)
- Render account (https://render.com - Sign up with GitHub)

## Paso 1: Preparar GitHub

### Verificar que el código esté en GitHub

```bash
cd /Users/isaias/Documents/Platanus/team-13
git status
git log --oneline -3
```

Deberías ver:
- Rama actual: `main`
- Últimos commits con la configuración de Telegram

### Asegurar que .env NO está en Git

```bash
cat .gitignore | grep .env
```

Deberías ver: `.env` en .gitignore

## Paso 2: Desplegar Backend en Render

### 2.1: Crear cuenta en Render (si no tienes)

1. Ve a https://render.com
2. Haz click en "Sign up with GitHub"
3. Autoriza Render a acceder a tu GitHub

### 2.2: Crear nuevo servicio Web Service

1. En Render Dashboard, haz click en **"+ New"** → **"Web Service"**

2. **Conectar GitHub:**
   - Selecciona tu repositorio: `platanus-hack-26-co-team-13`
   - Haz click en "Connect"

3. **Configurar el servicio:**
   - **Name**: `platanus-backend` (o similar)
   - **Environment**: `Python 3.11`
   - **Region**: Elige la más cercana a ti (ej: `Frankfurt` para EU, `Oregon` para US-West)
   - **Branch**: `main`
   - **Root Directory**: `backend` ← IMPORTANTE: especifica esta carpeta

4. **Comandos de Build y Start:**
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `uvicorn api.main:app --host 0.0.0.0 --port 8000`

5. **Variables de Entorno** (Environment):
   Agrega estas variables (copiar exactamente los valores):

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

6. **Haz click en "Create Web Service"**

### 2.3: Esperar a que se despliegue

- Render mostrará los logs del build
- Espera 3-5 minutos para que termine
- Deberías ver: `Uvicorn running on http://0.0.0.0:8000`

### 2.4: Obtener la URL del backend

Cuando termine, Render te dará una URL como:
```
https://platanus-backend-XXXXX.onrender.com
```

**Copia esta URL** (la necesitarás para Vercel)

### 2.5: Verificar que funciona

```bash
# En tu terminal, reemplaza con tu URL real:
curl https://platanus-backend-XXXXX.onrender.com/api/v1/telegram/status

# Deberías ver:
{"status":"online","total_alerts":0,"pending_approvals":0,"telegram_connected":true}
```

## Paso 3: Desplegar Frontend en Vercel

### 3.1: Crear cuenta en Vercel (si no tienes)

1. Ve a https://vercel.com
2. Haz click en "Sign up with GitHub"
3. Autoriza Vercel a acceder a tu GitHub

### 3.2: Crear nuevo proyecto

1. En Vercel Dashboard, haz click en **"Add New..."** → **"Project"**

2. **Selecciona tu repositorio:**
   - Busca: `platanus-hack-26-co-team-13`
   - Haz click en "Import"

3. **Configurar el proyecto:**
   - **Framework Preset**: Next.js (Vercel lo detecta automáticamente)
   - **Root Directory**: `frontend/` ← IMPORTANTE
   - **Build Command**: `npm run build` (por defecto)
   - **Output Directory**: `.next` (por defecto)
   - **Install Command**: `npm install` (por defecto)

4. **Variables de Entorno:**
   Agrega esta variable (usa tu URL real de Render):

   ```
   NEXT_PUBLIC_API_URL=https://platanus-backend-XXXXX.onrender.com
   ```

   Ejemplo real:
   ```
   NEXT_PUBLIC_API_URL=https://platanus-backend-abc123.onrender.com
   ```

5. **Haz click en "Deploy"**

### 3.3: Esperar a que se despliegue

- Vercel mostrará los logs del build
- Espera 1-2 minutos (Vercel es rápido)
- Deberías ver: `✓ Deployed successfully`

### 3.4: Obtener la URL del frontend

Cuando termine, Vercel te dará una URL como:
```
https://platanus-frontend-XXXXX.vercel.app
```

**Esta es tu URL de producción del frontend**

## Paso 4: Verificar que todo funciona

### 4.1: Abre el frontend

```
https://platanus-frontend-XXXXX.vercel.app
```

Deberías ver:
- Landing page de Provenance Firewall
- "The agent is trusted. The instruction isn't."
- Diagrama de funcionamiento

### 4.2: Prueba un alert

En tu terminal:

```bash
# Reemplaza con tu URL real de Render
BACKEND_URL="https://platanus-backend-XXXXX.onrender.com"

curl -X POST ${BACKEND_URL}/api/v1/telegram/send-alert \
  -H "Content-Type: application/json" \
  -d '{
    "severity": "HIGH",
    "content_preview": "Production test from Vercel+Render",
    "threats": ["test"],
    "threat_score": 0.85,
    "source": "production_test"
  }'
```

Deberías ver:
```json
{"success": true, "message": "Alert sent to Telegram"}
```

### 4.3: Revisa tu Telegram

En segundos deberías recibir el alert en tu Telegram con:
- Alert ID
- Severity: HIGH (85%)
- Botones para aprobar/rechazar

## Paso 5: Configurar Auto-Deployments

### Para Render:

1. Ve a tu servicio en Render
2. Haz click en **"Settings"**
3. Ve a **"Deploy Hook"**
4. Copia el webhook
5. Ve a GitHub → Settings → Webhooks → Add webhook
6. Pega el URL y selecciona "push" events
7. Listo: cada push a `main` desplegará automáticamente

### Para Vercel:

- Vercel auto-detecta cambios en GitHub
- Cada push a `main` despliega automáticamente
- No requiere configuración adicional

## Paso 6: Updates futuros

Ahora que todo está configurado, para desplegar cambios es tan simple como:

```bash
cd /Users/isaias/Documents/Platanus/team-13
git add .
git commit -m "tu mensaje"
git push origin main
```

Y automáticamente:
1. Vercel redespliega el frontend (1-2 min)
2. Render redespliega el backend (3-5 min)

## Troubleshooting

### Backend no responde

```bash
# Revisa los logs en Render:
# 1. Ve a Render Dashboard
# 2. Selecciona tu servicio
# 3. Ve a "Logs"
# 4. Busca errores

# Verifica manualmente:
curl https://platanus-backend-XXXXX.onrender.com/api/v1/telegram/status
```

### Frontend muestra "Cannot reach backend"

1. Verifica que `NEXT_PUBLIC_API_URL` en Vercel es correcto
2. Verifica que CORS está configurado en el backend:
   - `MEMORY_FIREWALL_ALLOWED_ORIGINS` incluye tu URL de Vercel

### Telegram no recibe alerts

1. Verifica que bot token es correcto: `[REDACTED_DO_NOT_COMMIT]`
2. Verifica que chat ID es correcto: `[REDACTED_CHAT_ID]`
3. Revisa los logs del backend en Render

## URLs Finales

Una vez desplegado, tendrás:

```
Frontend:  https://platanus-frontend-XXXXX.vercel.app
Backend:   https://platanus-backend-XXXXX.onrender.com
Telegram:  @provenancePlatanus_bot
```

---

**¡Listo!** Tu aplicación está en producción. 🚀
