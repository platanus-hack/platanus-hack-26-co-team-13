# GitHub Secrets Setup - Guía Paso a Paso

## Overview

Este documento contiene **TODAS las variables de entorno y secrets** que necesitas configurar en GitHub para que el deployment automático funcione.

**Acceso:** https://github.com/platanus-hack/platanus-hack-26-co-team-13/settings/secrets/actions

---

## Secrets Requeridos

### 1. TELEGRAM_BOT_TOKEN

**Descripción:** Token de autenticación del bot de Telegram

**Valor:**
```
***REDACTED_COMPROMISED_TOKEN***
```

**Cómo agregarlo:**
1. Ve a: https://github.com/platanus-hack/platanus-hack-26-co-team-13/settings/secrets/actions
2. Click "New repository secret"
3. Name: `TELEGRAM_BOT_TOKEN`
4. Value: `***REDACTED_COMPROMISED_TOKEN***`
5. Click "Add secret"

---

### 2. TELEGRAM_ADMIN_CHAT_ID

**Descripción:** ID del chat de Telegram donde enviar alertas

**Valor:**
```
[REDACTED_CHAT_ID]
```

**Cómo agregarlo:**
1. Click "New repository secret"
2. Name: `TELEGRAM_ADMIN_CHAT_ID`
3. Value: `[REDACTED_CHAT_ID]`
4. Click "Add secret"

---

### 3. ENABLE_QUARANTINE_ALERTS

**Descripción:** Feature flag para alertas de quarantine

**Valor:**
```
true
```

**Cómo agregarlo:**
1. Click "New repository secret"
2. Name: `ENABLE_QUARANTINE_ALERTS`
3. Value: `true`
4. Click "Add secret"

---

### 4. ENABLE_APPROVAL_WORKFLOW

**Descripción:** Feature flag para workflow de aprobación

**Valor:**
```
true
```

**Cómo agregarlo:**
1. Click "New repository secret"
2. Name: `ENABLE_APPROVAL_WORKFLOW`
3. Value: `true`
4. Click "Add secret"

---

### 5. ENABLE_DAILY_REPORTS

**Descripción:** Feature flag para reportes diarios

**Valor:**
```
true
```

**Cómo agregarlo:**
1. Click "New repository secret"
2. Name: `ENABLE_DAILY_REPORTS`
3. Value: `true`
4. Click "Add secret"

---

### 6. ALERT_THRESHOLD

**Descripción:** Umbral de severidad para alertas

**Valor:**
```
0.3
```

**Cómo agregarlo:**
1. Click "New repository secret"
2. Name: `ALERT_THRESHOLD`
3. Value: `0.3`
4. Click "Add secret"

---

### 7. CRITICAL_THRESHOLD

**Descripción:** Umbral de severidad crítica

**Valor:**
```
0.9
```

**Cómo agregarlo:**
1. Click "New repository secret"
2. Name: `CRITICAL_THRESHOLD`
3. Value: `0.9`
4. Click "Add secret"

---

### 8. REPORT_HOUR

**Descripción:** Hora del día para enviar reportes (formato 24h)

**Valor:**
```
9
```

**Cómo agregarlo:**
1. Click "New repository secret"
2. Name: `REPORT_HOUR`
3. Value: `9`
4. Click "Add secret"

---

### 9. ALERT_BATCH_DELAY

**Descripción:** Segundos entre batches de alertas

**Valor:**
```
60
```

**Cómo agregarlo:**
1. Click "New repository secret"
2. Name: `ALERT_BATCH_DELAY`
3. Value: `60`
4. Click "Add secret"

---

### 10. MEMORY_FIREWALL_ALLOWED_ORIGINS

**Descripción:** CORS allowed origins (donde está el frontend)

**Valor (para desarrollo):**
```
http://localhost:3000,http://127.0.0.1:3000
```

**Valor (para producción):**
```
https://your-domain.com
```

**Cómo agregarlo:**
1. Click "New repository secret"
2. Name: `MEMORY_FIREWALL_ALLOWED_ORIGINS`
3. Value: (usa el valor según tu ambiente)
4. Click "Add secret"

---

### 11. NEXT_PUBLIC_API_URL

**Descripción:** URL del backend API para el frontend

**Valor (para desarrollo):**
```
http://127.0.0.1:8000
```

**Valor (para producción):**
```
https://api.your-domain.com
```

**Cómo agregarlo:**
1. Click "New repository secret"
2. Name: `NEXT_PUBLIC_API_URL`
3. Value: (usa el valor según tu ambiente)
4. Click "Add secret"

**IMPORTANTE:** Este secret tiene prefijo `NEXT_PUBLIC_` así que es visible en el navegador (es normal, no es sensible)

---

## Secrets Opcionales (para CI/CD)

Si quieres que GitHub Actions automáticamente haga push a tu VPS:

### VERCEL_TOKEN

**Descripción:** Token de Vercel para auto-deploy

**Cómo obtenerlo:**
1. Ve a: https://vercel.com/account/tokens
2. Click "Create"
3. Name: "github-actions"
4. Copia el token

**Cómo agregarlo:**
1. Click "New repository secret"
2. Name: `VERCEL_TOKEN`
3. Value: (pega el token)
4. Click "Add secret"

---

### VERCEL_ORG_ID

**Descripción:** ID de tu organización/account en Vercel

**Cómo obtenerlo:**
1. Ve a: https://vercel.com/dashboard
2. Click en tu usuario (arriba a la izquierda)
3. Busca "Team ID" o "Org ID"
4. Cópialo

**Cómo agregarlo:**
1. Click "New repository secret"
2. Name: `VERCEL_ORG_ID`
3. Value: (pega el ID)
4. Click "Add secret"

---

### VERCEL_PROJECT_ID

**Descripción:** ID del proyecto en Vercel

**Cómo obtenerlo:**
1. Ve a: https://vercel.com/isaias6/frontend/settings
2. Busca "Project ID"
3. Cópialo

**Cómo agregarlo:**
1. Click "New repository secret"
2. Name: `VERCEL_PROJECT_ID`
3. Value: (pega el ID)
4. Click "Add secret"

---

### VPS_HOST

**Descripción:** IP o dominio de tu VPS

**Valor:**
```
123.45.67.89
```
O si tienes dominio:
```
vps.your-domain.com
```

**Cómo agregarlo:**
1. Click "New repository secret"
2. Name: `VPS_HOST`
3. Value: (tu IP o dominio)
4. Click "Add secret"

---

### VPS_USER

**Descripción:** Usuario SSH del VPS

**Valor:**
```
root
```
O si tienes otro usuario:
```
ubuntu
```

**Cómo agregarlo:**
1. Click "New repository secret"
2. Name: `VPS_USER`
3. Value: (tu usuario)
4. Click "Add secret"

---

### VPS_SSH_KEY

**Descripción:** Clave privada SSH para conectarse al VPS

**Cómo obtenerla:**
```bash
# En tu VPS:
ssh-keygen -t ed25519 -C "github-deploy" -f ~/.ssh/github_deploy
cat ~/.ssh/github_deploy
# Copia TODO el contenido (es un bloque de texto)
```

**Cómo agregarlo:**
1. Click "New repository secret"
2. Name: `VPS_SSH_KEY`
3. Value: (pega TODO el contenido de la clave privada)
4. Click "Add secret"

**IMPORTANTE:** Asegúrate de:
- Pegar la clave PRIVADA, no la pública
- Incluir las líneas `-----BEGIN OPENSSH PRIVATE KEY-----` y `-----END OPENSSH PRIVATE KEY-----`
- No dejar espacios extras al inicio o final

---

### VPS_DEPLOY_PATH

**Descripción:** Path donde está el app en el VPS

**Valor:**
```
/var/www/app
```

**Cómo agregarlo:**
1. Click "New repository secret"
2. Name: `VPS_DEPLOY_PATH`
3. Value: `/var/www/app`
4. Click "Add secret"

---

## Checklist Final

- [ ] ✅ TELEGRAM_BOT_TOKEN
- [ ] ✅ TELEGRAM_ADMIN_CHAT_ID
- [ ] ✅ ENABLE_QUARANTINE_ALERTS
- [ ] ✅ ENABLE_APPROVAL_WORKFLOW
- [ ] ✅ ENABLE_DAILY_REPORTS
- [ ] ✅ ALERT_THRESHOLD
- [ ] ✅ CRITICAL_THRESHOLD
- [ ] ✅ REPORT_HOUR
- [ ] ✅ ALERT_BATCH_DELAY
- [ ] ✅ MEMORY_FIREWALL_ALLOWED_ORIGINS
- [ ] ✅ NEXT_PUBLIC_API_URL
- [ ] ✅ VERCEL_TOKEN (opcional)
- [ ] ✅ VERCEL_ORG_ID (opcional)
- [ ] ✅ VERCEL_PROJECT_ID (opcional)
- [ ] ✅ VPS_HOST (opcional)
- [ ] ✅ VPS_USER (opcional)
- [ ] ✅ VPS_SSH_KEY (opcional)
- [ ] ✅ VPS_DEPLOY_PATH (opcional)

---

## Verificar Secrets

Para verificar que los secrets se agregaron correctamente:

1. Ve a: https://github.com/platanus-hack/platanus-hack-26-co-team-13/settings/secrets/actions
2. Deberías ver la lista de secretos
3. Click en cada uno para verificar (no puedes ver el valor, pero verás que existe)

---

## Usar Secrets en Workflows

Si quieres usar estos secrets en GitHub Actions, en el archivo `.github/workflows/vercel-deploy.yml`:

```yaml
env:
  TELEGRAM_BOT_TOKEN: ${{ secrets.TELEGRAM_BOT_TOKEN }}
  TELEGRAM_ADMIN_CHAT_ID: ${{ secrets.TELEGRAM_ADMIN_CHAT_ID }}
  NEXT_PUBLIC_API_URL: ${{ secrets.NEXT_PUBLIC_API_URL }}
```

---

## Support

Si necesitas más información sobre GitHub Secrets:
https://docs.github.com/en/actions/security-guides/encrypted-secrets
