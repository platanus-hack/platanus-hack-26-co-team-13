# Deployment VPS Setup - Complete Guide

## Overview

Este documento contiene **todas las instrucciones** para desplegar la aplicación completa (Backend + Frontend) en VPS desde 0.

**Requisitos previos:**
- Un VPS Linux (Ubuntu 22.04 LTS recomendado)
- Acceso SSH al VPS
- Git instalado en el VPS
- Node.js 18+ (para frontend build)
- Python 3.10+ (para backend)

---

## Part 1: Setup Inicial del VPS

### 1.1 Conectarse al VPS

```bash
ssh root@your.vps.ip.address
# O si tienes un user específico:
ssh username@your.vps.ip.address
```

### 1.2 Instalar Dependencias Básicas

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install essential tools
sudo apt install -y curl wget git nano build-essential

# Install Node.js (v20 LTS)
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs npm

# Install Python
sudo apt install -y python3 python3-pip python3-venv

# Verify installations
node --version    # v20.x.x
npm --version     # 10.x.x
python3 --version # 3.10+
```

### 1.3 Instalar PM2 (Process Manager)

```bash
sudo npm install -g pm2
pm2 startup
pm2 save
```

---

## Part 2: Clonar Repositorio

### 2.1 Clone del Repositorio

```bash
cd /var/www/
git clone https://github.com/platanus-hack/platanus-hack-26-co-team-13.git app
cd app
git checkout main
```

### 2.2 Verificar estructura

```bash
ls -la
# Deberías ver:
# - backend/
# - frontend/
# - .github/
# - .env.example (etc)
```

---

## Part 3: Configurar Variables de Entorno

### 3.1 Backend - .env

Crea `/var/www/app/backend/.env` con el siguiente contenido:

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

# CORS Configuration (cambia a tu dominio)
MEMORY_FIREWALL_ALLOWED_ORIGINS=http://localhost:3000,http://127.0.0.1:3000,https://your-domain.com
```

**Instrucciones de creación:**

```bash
cd /var/www/app/backend
nano .env
# Pega el contenido de arriba
# Presiona Ctrl+O → Enter → Ctrl+X para guardar
```

### 3.2 Frontend - .env.local

Crea `/var/www/app/frontend/.env.local` con:

```env
# Backend API URL
NEXT_PUBLIC_API_URL=http://localhost:8000
```

**O para producción:**

```env
NEXT_PUBLIC_API_URL=https://api.your-domain.com
```

**Instrucciones de creación:**

```bash
cd /var/www/app/frontend
nano .env.local
# Pega el contenido
# Presiona Ctrl+O → Enter → Ctrl+X para guardar
```

---

## Part 4: Instalar Dependencias

### 4.1 Backend Dependencies

```bash
cd /var/www/app/backend

# Crear virtual environment
python3 -m venv venv
source venv/bin/activate

# Instalar requirements
pip install -r requirements.txt

# Verificar que funciona
python -c "from api.main import app; print('✅ Backend imports OK')"

# Deactivate
deactivate
```

### 4.2 Frontend Dependencies

```bash
cd /var/www/app/frontend

# Instalar con npm
npm install

# Build frontend
npm run build

# Verificar build
ls -la .next
# Deberías ver carpeta .next/
```

---

## Part 5: Configurar Nginx (Reverse Proxy)

### 5.1 Instalar Nginx

```bash
sudo apt install -y nginx
sudo systemctl enable nginx
sudo systemctl start nginx
```

### 5.2 Crear configuración para backend

Crea `/etc/nginx/sites-available/backend`:

```nginx
server {
    listen 80;
    server_name api.your-domain.com;  # Cambia a tu dominio

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

**Aplicar:**

```bash
sudo ln -s /etc/nginx/sites-available/backend /etc/nginx/sites-enabled/
sudo nginx -t  # Test config
sudo systemctl reload nginx
```

### 5.3 Crear configuración para frontend

Crea `/etc/nginx/sites-available/frontend`:

```nginx
server {
    listen 80;
    server_name your-domain.com www.your-domain.com;  # Cambia a tu dominio

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

**Aplicar:**

```bash
sudo ln -s /etc/nginx/sites-available/frontend /etc/nginx/sites-enabled/
sudo nginx -t  # Test config
sudo systemctl reload nginx
```

### 5.4 SSL con Certbot (Recomendado)

```bash
sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d api.your-domain.com
sudo certbot --nginx -d your-domain.com

# Auto-renew
sudo systemctl enable certbot.timer
```

---

## Part 6: Iniciar Servicios con PM2

### 6.1 Backend Service

```bash
cd /var/www/app/backend

# Crear startup script
cat > start.sh << 'EOF'
#!/bin/bash
source venv/bin/activate
uvicorn api.main:app --host 127.0.0.1 --port 8000
EOF

chmod +x start.sh

# Iniciar con PM2
cd /var/www/app/backend
pm2 start start.sh --name "backend"
pm2 save
```

### 6.2 Frontend Service

```bash
cd /var/www/app/frontend

# Iniciar Next.js
pm2 start "npm run start" --name "frontend" --cwd /var/www/app/frontend
pm2 save
```

### 6.3 Verificar servicios

```bash
pm2 list
pm2 logs backend
pm2 logs frontend
```

---

## Part 7: Verificar Deployments

### 7.1 Backend Health Check

```bash
# Desde el VPS
curl http://127.0.0.1:8000/api/v1/telegram/status

# O desde otra máquina
curl http://api.your-domain.com/api/v1/telegram/status

# Deberías ver:
# {"status":"online","telegram_connected":true,...}
```

### 7.2 Frontend Health Check

```bash
# Desde el VPS
curl http://127.0.0.1:3000

# O desde navegador
https://your-domain.com

# Deberías ver: Landing page con "The agent is trusted..."
```

### 7.3 Telegram Bot Test

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

# Deberías recibir alert en Telegram en @provenancePlatanus_bot
```

---

## Part 8: GitHub Secrets para CI/CD (Opcional)

Si quieres que los futuros deploys sean automáticos desde GitHub Actions:

### 8.1 Crear Deploy Key en el VPS

```bash
ssh-keygen -t ed25519 -C "github-deploy" -f /root/.ssh/github_deploy
cat /root/.ssh/github_deploy.pub
```

### 8.2 Agregar Deploy Key a GitHub

1. Ve a: https://github.com/platanus-hack/platanus-hack-26-co-team-13/settings/keys
2. Click "Add deploy key"
3. Pega la clave pública
4. Enable "Allow write access"

### 8.3 Agregar Secrets a GitHub

Ve a: https://github.com/platanus-hack/platanus-hack-26-co-team-13/settings/secrets/actions

Agrega:
- `VPS_HOST`: tu-vps-ip.com
- `VPS_USER`: root (o username)
- `VPS_SSH_KEY`: contenido de `/root/.ssh/github_deploy`
- `VPS_DEPLOY_PATH`: /var/www/app

---

## Part 9: Troubleshooting

### Backend no arranca

```bash
pm2 logs backend

# Si ves errores de puerto:
sudo lsof -i :8000
sudo kill -9 <PID>

# Si ves errores de Python:
cd /var/www/app/backend
source venv/bin/activate
python -m uvicorn api.main:app --host 127.0.0.1 --port 8000
```

### Frontend no arranca

```bash
pm2 logs frontend

# Si ves errores de puerto:
sudo lsof -i :3000

# Manual test:
cd /var/www/app/frontend
npm run start
```

### Nginx no funciona

```bash
sudo nginx -t      # Test config
sudo systemctl restart nginx
sudo systemctl status nginx
```

---

## Part 10: Actualizar Código (Pull de GitHub)

```bash
cd /var/www/app
git pull origin main

# Backend: reinstalar si cambió requirements.txt
cd backend
source venv/bin/activate
pip install -r requirements.txt
deactivate

# Frontend: rebuild si cambió código
cd ../frontend
npm install
npm run build

# Restart services
pm2 restart backend
pm2 restart frontend
```

---

## Resumen de URLs

```
Frontend:  https://your-domain.com
Backend:   https://api.your-domain.com
Bot:       @provenancePlatanus_bot
```

---

## Support

Si algo falla:
1. Revisa los logs: `pm2 logs backend` o `pm2 logs frontend`
2. Verifica puertos: `sudo lsof -i :8000` y `sudo lsof -i :3000`
3. Revisa Nginx: `sudo nginx -t` y `sudo systemctl status nginx`
4. Revisa CORS: asegúrate que `MEMORY_FIREWALL_ALLOWED_ORIGINS` include tu dominio
