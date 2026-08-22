# Deployment Checklist

Usa este checklist mientras sigues QUICK_DEPLOYMENT.md

---

## ☐ Pre-Deployment (Verificaciones)

- [ ] Git push completado: `git log --oneline -1` muestra algo reciente
- [ ] Main branch: `git branch` muestra `* main`
- [ ] Repo pusheado: https://github.com/platanus-hack/platanus-hack-26-co-team-13 actualizado
- [ ] Backend código exists: `/backend` folder con `requirements.txt`
- [ ] Frontend código exists: `/frontend` folder con `package.json`

---

## ☐ RENDER Setup

### Crear Cuenta

- [ ] Ve a https://render.com
- [ ] Sign up with GitHub
- [ ] Autoriza Render a acceder a GitHub
- [ ] Email confirmado

### Crear Backend Web Service

- [ ] Dashboard Render abierto
- [ ] Click "**+ New**" → "**Web Service**"
- [ ] Selecciona repo: `platanus-hack-26-co-team-13`
- [ ] Click "**Connect**"

### Configurar Backend Service

- [ ] **Name**: `platanus-backend`
- [ ] **Environment**: `Python 3.11` (seleccionado)
- [ ] **Region**: Elegiste la más cercana
- [ ] **Branch**: `main`
- [ ] **Root Directory**: `backend` (SIN slash al inicio)

### Build & Start Commands

- [ ] **Build Command**: `pip install -r requirements.txt`
- [ ] **Start Command**: `uvicorn api.main:app --host 0.0.0.0 --port 8000`

### Environment Variables (Agregadas)

Copy-paste exacto. Cada una en su propia línea:

- [ ] `TELEGRAM_BOT_TOKEN=***REDACTED_COMPROMISED_TOKEN***`
- [ ] `TELEGRAM_ADMIN_CHAT_ID=[REDACTED_CHAT_ID]`
- [ ] `ENABLE_QUARANTINE_ALERTS=true`
- [ ] `ENABLE_APPROVAL_WORKFLOW=true`
- [ ] `ENABLE_DAILY_REPORTS=true`
- [ ] `ALERT_THRESHOLD=0.3`
- [ ] `CRITICAL_THRESHOLD=0.9`
- [ ] `REPORT_HOUR=9`
- [ ] `ALERT_BATCH_DELAY=60`
- [ ] `MEMORY_FIREWALL_ALLOWED_ORIGINS=http://localhost:3000,http://127.0.0.1:3000,https://platanus-frontend.vercel.app`

### Deploy Backend

- [ ] Click "**Create Web Service**"
- [ ] Mira los logs (busca "Build successful")
- [ ] Espera 3-5 minutos
- [ ] Mira el mensaje: `✓ Service is live` o similar

### Obtener Backend URL

- [ ] Abierto: https://platanus-backend-XXXXX.onrender.com
- [ ] Copiar la URL completa: `https://platanus-backend-XXXXX.onrender.com`
- [ ] Guardar en notepad (la necesitarás en 2 minutos)

### Verificar Backend

- [ ] Terminal: 
  ```bash
  BACKEND="https://platanus-backend-XXXXX.onrender.com"
  curl $BACKEND/api/v1/telegram/status
  ```
- [ ] Respuesta debe ser: `{"status":"online",...}`

---

## ☐ VERCEL Setup

### Crear Cuenta

- [ ] Ve a https://vercel.com
- [ ] Sign up with GitHub (puedes reutilizar la misma cuenta)
- [ ] Autoriza Vercel a acceder a GitHub
- [ ] Email confirmado

### Crear Frontend Project

- [ ] Dashboard Vercel abierto
- [ ] Click "**Add New**" → "**Project**"
- [ ] Busca repo: `platanus-hack-26-co-team-13`
- [ ] Click "**Import**"

### Configurar Frontend Project

- [ ] **Framework**: `Next.js` (auto-detectado, NO cambiar)
- [ ] **Root Directory**: `frontend/` (CON slash)
- [ ] **Build Command**: `npm run build` (default, OK)
- [ ] **Output Directory**: `.next` (default, OK)

### Environment Variables

- [ ] Click "**Add Environment Variable**"
- [ ] **Name**: `NEXT_PUBLIC_API_URL`
- [ ] **Value**: Pega tu URL de Render: `https://platanus-backend-XXXXX.onrender.com`
  (Sin trailing slash)
- [ ] Click "**Save**"

### Deploy Frontend

- [ ] Click "**Deploy**"
- [ ] Mira los logs (busca "Build successful")
- [ ] Espera 1-2 minutos
- [ ] Mira el mensaje: `✓ Deployment completed` o similar

### Obtener Frontend URL

- [ ] Abierto: https://platanus-frontend-XXXXX.vercel.app
- [ ] Copiar la URL completa: `https://platanus-frontend-XXXXX.vercel.app`
- [ ] Guardar en notepad

---

## ☐ Post-Deployment Testing

### Prueba 1: Frontend Abierto

- [ ] Navegador: https://platanus-frontend-XXXXX.vercel.app
- [ ] Página carga correctamente
- [ ] Ves: "The agent is trusted. The instruction isn't."
- [ ] Ves el diagrama de funcionamiento
- [ ] Ves "Control plane" section

### Prueba 2: Backend Responde

- [ ] Terminal:
  ```bash
  BACKEND="https://platanus-backend-XXXXX.onrender.com"
  curl $BACKEND/api/v1/telegram/status
  ```
- [ ] Respuesta: `{"status":"online","telegram_connected":true,...}`

### Prueba 3: Enviar Alert

- [ ] Terminal:
  ```bash
  BACKEND="https://platanus-backend-XXXXX.onrender.com"
  curl -X POST $BACKEND/api/v1/telegram/send-alert \
    -H "Content-Type: application/json" \
    -d '{
      "severity": "HIGH",
      "content_preview": "Production test",
      "threats": ["test"],
      "threat_score": 0.85,
      "source": "production"
    }'
  ```
- [ ] Respuesta: `{"success":true,"message":"Alert sent to Telegram"}`

### Prueba 4: Recibir en Telegram

- [ ] Abre Telegram
- [ ] Busca chat: `@provenancePlatanus_bot`
- [ ] Deberías ver el alert en 5-10 segundos
- [ ] Alert muestra:
  - [ ] Alert ID
  - [ ] Severity icon (🚨)
  - [ ] Score (85%)
  - [ ] Botones: [✅ Approve] [❌ Reject] [📄 Details] [🔍 Query]

### Prueba 5: Approval Workflow

- [ ] Haz click en "**✅ Approve**" en Telegram
- [ ] Recibes respuesta inmediata
- [ ] Deberías ver un token como: `Au2SptnCqkKGpxWUlKWC...`
- [ ] Token es válido 24 horas

---

## ☐ Final Verification

### URLs Documentadas

- [ ] Frontend URL: `https://platanus-frontend-XXXXX.vercel.app`
- [ ] Backend URL: `https://platanus-backend-XXXXX.onrender.com`
- [ ] Telegram Bot: `@provenancePlatanus_bot`
- [ ] GitHub: `https://github.com/platanus-hack/platanus-hack-26-co-team-13`

### Auto-Deployments Verificados

- [ ] Render: Está conectado a GitHub main
- [ ] Vercel: Está conectado a GitHub main
- [ ] (Los cambios futuros se deployarán automáticamente)

### Documentación Completa

- [ ] Leíste QUICK_DEPLOYMENT.md
- [ ] Leíste DEPLOYMENT_GUIDE.md (para futuros issues)
- [ ] Guardaste las URLs en un lugar seguro
- [ ] Sabes cómo hacer git push para nuevos cambios

---

## ✅ ¡DEPLOYMENT COMPLETADO!

### Próximos Pasos

Ahora puedes:

1. **Hacer cambios locales** y pushearlos:
   ```bash
   git add .
   git commit -m "tu cambio"
   git push origin main
   ```

2. **Vercel redespliega** automáticamente (1-2 min)

3. **Render redespliega** automáticamente (3-5 min)

### En Caso de Problemas

- [ ] Lee DEPLOYMENT_GUIDE.md sección "Troubleshooting"
- [ ] Revisa logs en Render Dashboard
- [ ] Revisa logs en Vercel Dashboard
- [ ] Verifica variables de entorno en ambas plataformas
- [ ] Asegúrate que CORS está configurado correctamente

---

## 📝 Notas

```
Fecha de Deploy: _______________
Frontend URL: _______________
Backend URL: _______________
Status: ✅ COMPLETADO / ⏳ EN PROGRESO / ❌ PROBLEMAS

Notas adicionales:
_________________________________
_________________________________
```

---

**¡Felicidades! Tu app está en producción!** 🚀

Para más help, revisa DEPLOYMENT_GUIDE.md.
