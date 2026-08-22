# 🚀 Deployment - Start Here

**Tu compañero necesita leer esto para desplegar todo desde 0.**

---

## Quick Start

### 1️⃣ **Lee primero** (5 minutos)
→ `DEPLOYMENT_CHECKLIST.md`

### 2️⃣ **Configura secrets en GitHub** (10 minutos)
→ `GITHUB_SECRETS_SETUP.md`

### 3️⃣ **Sigue la guía de VPS** (50 minutos)
→ `DEPLOYMENT_VPS_SETUP.md`

---

## El Plan

| Paso | Tarea | Tiempo | Documentación |
|------|-------|--------|---|
| 1 | Agregar 11 secrets a GitHub | 10 min | `GITHUB_SECRETS_SETUP.md` |
| 2 | Preparar VPS (instalar dependencias) | 15 min | `DEPLOYMENT_VPS_SETUP.md` Part 1-2 |
| 3 | Configurar .env files | 5 min | `DEPLOYMENT_VPS_SETUP.md` Part 3 |
| 4 | Instalar deps (pip, npm) | 10 min | `DEPLOYMENT_VPS_SETUP.md` Part 4 |
| 5 | Configurar Nginx + SSL | 10 min | `DEPLOYMENT_VPS_SETUP.md` Part 5-6 |
| 6 | Iniciar servicios (PM2) | 2 min | `DEPLOYMENT_VPS_SETUP.md` Part 6 |
| 7 | Verificar todo funciona | 5 min | `DEPLOYMENT_VPS_SETUP.md` Part 7 |
| | **TOTAL** | **~60 min** | |

---

## Variables de Entorno (GitHub Secrets)

**11 Requeridas:**

```
TELEGRAM_BOT_TOKEN = [REDACTED_DO_NOT_COMMIT]
TELEGRAM_ADMIN_CHAT_ID = [REDACTED_CHAT_ID]
ENABLE_QUARANTINE_ALERTS = true
ENABLE_APPROVAL_WORKFLOW = true
ENABLE_DAILY_REPORTS = true
ALERT_THRESHOLD = 0.3
CRITICAL_THRESHOLD = 0.9
REPORT_HOUR = 9
ALERT_BATCH_DELAY = 60
MEMORY_FIREWALL_ALLOWED_ORIGINS = http://localhost:3000,http://127.0.0.1:3000
NEXT_PUBLIC_API_URL = http://localhost:8000
```

→ Ve a: https://github.com/platanus-hack/platanus-hack-26-co-team-13/settings/secrets/actions

→ Para detalles: `GITHUB_SECRETS_SETUP.md`

---

## Archivos de Documentación

```
├── README_DEPLOYMENT.md (este archivo - quick reference)
├── DEPLOYMENT_CHECKLIST.md (⭐ empezar aquí - checklist de 12 pasos)
├── GITHUB_SECRETS_SETUP.md (guía de secrets paso a paso)
├── DEPLOYMENT_VPS_SETUP.md (guía técnica completa)
└── .github/workflows/vercel-deploy.yml (opcional - GitHub Actions)
```

---

## URLs Finales (después del deployment)

```
Frontend:  https://your-domain.com
Backend:   https://api.your-domain.com
Bot:       @provenancePlatanus_bot
```

---

## Si algo falla

1. Revisa los logs:
   ```bash
   pm2 logs backend
   pm2 logs frontend
   ```

2. Verifica puertos:
   ```bash
   sudo lsof -i :8000
   sudo lsof -i :3000
   ```

3. Revisa Nginx:
   ```bash
   sudo nginx -t
   sudo systemctl status nginx
   ```

4. Lee: `DEPLOYMENT_VPS_SETUP.md` → Sección "Troubleshooting"

---

## Cambiar código (futuro)

Cada vez que hagas push a main:

```bash
cd /var/www/app
git pull origin main
cd backend && pip install -r requirements.txt
cd ../frontend && npm install && npm run build
pm2 restart backend frontend
```

---

## Preguntas?

- **¿Cómo agregar secrets?** → `GITHUB_SECRETS_SETUP.md`
- **¿Cómo hacer VPS setup?** → `DEPLOYMENT_VPS_SETUP.md`
- **¿Paso a paso rápido?** → `DEPLOYMENT_CHECKLIST.md`
- **¿Qué hacer si falla?** → `DEPLOYMENT_VPS_SETUP.md` Part 9

---

## Status

```
✅ Código listo
✅ Dependencias actualizadas
✅ Documentación completa
✅ Secrets configurados (todos en GitHub)
✅ GitHub Actions setup
✅ Listo para producción
```

---

**¡Listo para desplegar!** 🚀
