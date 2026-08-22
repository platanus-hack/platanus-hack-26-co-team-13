# Deployment Checklist - Todo lo que Necesitas Hacer

## Overview

Este documento es un **checklist completo** para desplegar toda la aplicación desde 0.

Tu compañero debe seguir estos pasos en orden.

---

## FASE 1: Preparación (GitHub)

### ✅ Paso 1: Agregar Secrets a GitHub

**Acceso:** https://github.com/platanus-hack/platanus-hack-26-co-team-13/settings/secrets/actions

**Documentación completa:** Ver `GITHUB_SECRETS_SETUP.md`

Necesitas agregar estos secrets (REQUERIDOS):

```
1. TELEGRAM_BOT_TOKEN = [REDACTED_DO_NOT_COMMIT]
2. TELEGRAM_ADMIN_CHAT_ID = [REDACTED_CHAT_ID]
3. ENABLE_QUARANTINE_ALERTS = true
4. ENABLE_APPROVAL_WORKFLOW = true
5. ENABLE_DAILY_REPORTS = true
6. ALERT_THRESHOLD = 0.3
7. CRITICAL_THRESHOLD = 0.9
8. REPORT_HOUR = 9
9. ALERT_BATCH_DELAY = 60
10. MEMORY_FIREWALL_ALLOWED_ORIGINS = http://localhost:3000,http://127.0.0.1:3000
11. NEXT_PUBLIC_API_URL = http://127.0.0.1:8000
```

**⏱️ Tiempo:** 10 minutos
**✅ Status:** [ ] Completado

---

### ✅ Paso 2: Verificar que los Secrets están en GitHub

```bash
# Simplemente verifica que aparezcan en:
# https://github.com/platanus-hack/platanus-hack-26-co-team-13/settings/secrets/actions

# Deberías ver algo como:
# ✓ TELEGRAM_BOT_TOKEN
# ✓ TELEGRAM_ADMIN_CHAT_ID
# ✓ ENABLE_QUARANTINE_ALERTS
# ... etc
```

**✅ Status:** [ ] Completado

---

## FASE 2: Setup del VPS

### ✅ Paso 3: Preparar el VPS

**Documentación completa:** Ver `DEPLOYMENT_VPS_SETUP.md` - Part 1 y 2

1. Conectarse al VPS
2. Instalar dependencias (Node.js, Python, PM2, Nginx)
3. Clonar el repositorio

```bash
# Resumen de comandos:
ssh root@your.vps.ip
sudo apt update && sudo apt upgrade -y
sudo apt install -y git curl wget build-essential python3 python3-pip python3-venv nodejs npm nginx

# Install PM2
sudo npm install -g pm2
pm2 startup
pm2 save

# Clone repo
cd /var/www/
git clone https://github.com/platanus-hack/platanus-hack-26-co-team-13.git app
cd app
```

**⏱️ Tiempo:** 15 minutos
**✅ Status:** [ ] Completado

---

### ✅ Paso 4: Configurar Variables de Entorno

**Documentación completa:** Ver `DEPLOYMENT_VPS_SETUP.md` - Part 3

Necesitas crear 2 archivos:

**Archivo 1: `/var/www/app/backend/.env`**

```env
# Telegram Bot Configuration
TELEGRAM_BOT_TOKEN=[REDACTED_DO_NOT_COMMIT]
TELEGRAM_ADMIN_CHAT_ID=[REDACTED_CHAT_ID]

# Feature Flags
ENABLE_QUARANTINE_ALERTS=true
ENABLE_APPROVAL_WORKFLOW=true
ENABLE_DAILY_REPORTS=true

# Alert Thresholds
ALERT_THRESHOLD=0.3
CRITICAL_THRESHOLD=0.9

# Timing
REPORT_HOUR=9
ALERT_BATCH_DELAY=60

# CORS Configuration
MEMORY_FIREWALL_ALLOWED_ORIGINS=http://localhost:3000,http://127.0.0.1:3000,https://your-domain.com
```

**Archivo 2: `/var/www/app/frontend/.env.local`**

```env
NEXT_PUBLIC_API_URL=http://localhost:8000
```

O para producción:
```env
NEXT_PUBLIC_API_URL=https://api.your-domain.com
```

**Cómo crear los archivos:**

```bash
# Backend .env
cd /var/www/app/backend
nano .env
# Pega el contenido de arriba
# Ctrl+O → Enter → Ctrl+X para guardar

# Frontend .env.local
cd /var/www/app/frontend
nano .env.local
# Pega el contenido
# Ctrl+O → Enter → Ctrl+X para guardar
```

**⏱️ Tiempo:** 5 minutos
**✅ Status:** [ ] Completado

---

### ✅ Paso 5: Instalar Dependencias

**Documentación completa:** Ver `DEPLOYMENT_VPS_SETUP.md` - Part 4

```bash
# Backend
cd /var/www/app/backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python -c "from api.main import app; print('✅ Backend imports OK')"
deactivate

# Frontend
cd /var/www/app/frontend
npm install
npm run build
```

**⏱️ Tiempo:** 10 minutos (mientras descarga)
**✅ Status:** [ ] Completado

---

### ✅ Paso 6: Configurar Nginx

**Documentación completa:** Ver `DEPLOYMENT_VPS_SETUP.md` - Part 5

Necesitas crear 2 archivos de configuración:

**Archivo 1: `/etc/nginx/sites-available/backend`**

```nginx
server {
    listen 80;
    server_name api.your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

**Archivo 2: `/etc/nginx/sites-available/frontend`**

```nginx
server {
    listen 80;
    server_name your-domain.com www.your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
```

**Cómo aplicar:**

```bash
# Backend
sudo nano /etc/nginx/sites-available/backend
# Pega el contenido
# Ctrl+O → Enter → Ctrl+X

sudo ln -s /etc/nginx/sites-available/backend /etc/nginx/sites-enabled/
sudo nginx -t  # Verifica que no hay errores
sudo systemctl reload nginx

# Frontend
sudo nano /etc/nginx/sites-available/frontend
# Pega el contenido
# Ctrl+O → Enter → Ctrl+X

sudo ln -s /etc/nginx/sites-available/frontend /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

**⏱️ Tiempo:** 5 minutos
**✅ Status:** [ ] Completado

---

### ✅ Paso 7: Configurar SSL (HTTPS)

**Documentación completa:** Ver `DEPLOYMENT_VPS_SETUP.md` - Part 5.4

```bash
# Instalar Certbot
sudo apt install -y certbot python3-certbot-nginx

# Generar certificado para backend
sudo certbot --nginx -d api.your-domain.com

# Generar certificado para frontend
sudo certbot --nginx -d your-domain.com

# Auto-renew
sudo systemctl enable certbot.timer
```

**⏱️ Tiempo:** 5 minutos
**✅ Status:** [ ] Completado

---

## FASE 3: Iniciar Servicios

### ✅ Paso 8: Iniciar Backend con PM2

**Documentación completa:** Ver `DEPLOYMENT_VPS_SETUP.md` - Part 6.1

```bash
cd /var/www/app/backend

# Crear script de inicio
cat > start.sh << 'EOF'
#!/bin/bash
source venv/bin/activate
uvicorn api.main:app --host 127.0.0.1 --port 8000
EOF

chmod +x start.sh

# Iniciar con PM2
pm2 start start.sh --name "backend"
pm2 save

# Verificar que arrancó
pm2 logs backend
```

**⏱️ Tiempo:** 2 minutos
**✅ Status:** [ ] Completado

---

### ✅ Paso 9: Iniciar Frontend con PM2

**Documentación completa:** Ver `DEPLOYMENT_VPS_SETUP.md` - Part 6.2

```bash
cd /var/www/app/frontend

# Iniciar con PM2
pm2 start "npm run start" --name "frontend" --cwd /var/www/app/frontend
pm2 save

# Verificar que arrancó
pm2 logs frontend
```

**⏱️ Tiempo:** 2 minutos
**✅ Status:** [ ] Completado

---

## FASE 4: Verificación

### ✅ Paso 10: Verificar Health Checks

**Documentación completa:** Ver `DEPLOYMENT_VPS_SETUP.md` - Part 7

#### Backend Health Check

```bash
# Desde el VPS
curl http://127.0.0.1:8000/api/v1/telegram/status

# Deberías ver algo como:
# {"status":"online","telegram_connected":true,...}
```

**✅ Status:** [ ] Completado

#### Frontend Health Check

```bash
# Desde el VPS
curl http://127.0.0.1:3000

# O abre en navegador:
# https://your-domain.com

# Deberías ver: Landing page con "The agent is trusted..."
```

**✅ Status:** [ ] Completado

---

### ✅ Paso 11: Verificar Telegram Bot

**Documentación completa:** Ver `DEPLOYMENT_VPS_SETUP.md` - Part 7.3

```bash
curl -X POST http://127.0.0.1:8000/api/v1/telegram/send-alert \
  -H "Content-Type: application/json" \
  -d '{
    "severity": "HIGH",
    "content_preview": "VPS Deployment Test",
    "threats": ["test"],
    "threat_score": 0.85,
    "source": "vps_test"
  }'
```

Deberías recibir un alert en Telegram en **@provenancePlatanus_bot**

**✅ Status:** [ ] Completado

---

## FASE 5: Actualizaciones Futuras

### ✅ Paso 12: Actualizar Código desde GitHub

**Documentación completa:** Ver `DEPLOYMENT_VPS_SETUP.md` - Part 10

Cada vez que hagas push a main, en el VPS:

```bash
cd /var/www/app
git pull origin main

# Si cambió backend
cd backend
source venv/bin/activate
pip install -r requirements.txt
deactivate

# Si cambió frontend
cd ../frontend
npm install
npm run build

# Restart services
pm2 restart backend frontend
```

**✅ Status:** [ ] Completado

---

## Resumen Final

| Fase | Tarea | Tiempo | Status |
|------|-------|--------|--------|
| 1 | Agregar Secrets a GitHub | 10 min | [ ] |
| 2 | Preparar VPS | 15 min | [ ] |
| 3 | Configurar variables .env | 5 min | [ ] |
| 4 | Instalar dependencias | 10 min | [ ] |
| 5 | Configurar Nginx | 5 min | [ ] |
| 6 | Configurar SSL | 5 min | [ ] |
| 7 | Iniciar Backend | 2 min | [ ] |
| 8 | Iniciar Frontend | 2 min | [ ] |
| 9 | Health checks | 5 min | [ ] |
| 10 | Test Telegram | 2 min | [ ] |
| | **TOTAL** | **~60 min** | [ ] |

---

## URLs Finales

```
Frontend:  https://your-domain.com
Backend:   https://api.your-domain.com
Bot:       @provenancePlatanus_bot
```

---

## Archivos de Referencia

- `DEPLOYMENT_VPS_SETUP.md` - Guía completa de setup
- `GITHUB_SECRETS_SETUP.md` - Guía de secrets en GitHub
- `.github/workflows/vercel-deploy.yml` - GitHub Actions (opcional)

---

## Ayuda

Si algo falla:

1. Revisa los logs: `pm2 logs backend` o `pm2 logs frontend`
2. Verifica puertos: `sudo lsof -i :8000` y `sudo lsof -i :3000`
3. Revisa Nginx: `sudo nginx -t` y `sudo systemctl status nginx`
4. Lee la sección "Troubleshooting" en `DEPLOYMENT_VPS_SETUP.md`
