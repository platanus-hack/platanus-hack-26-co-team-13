# 🚀 Telegram Supervisor Bot - Deployed to Production

Tu Telegram Supervisor Bot está ahora desplegado en **Render** en la rama `main`.

## 📊 Status

- **Deployment**: En progreso (2-5 minutos)
- **URL**: https://[REDACTED_BACKEND_URL]
- **Commit**: 67aca7c (merge from feature/telegram-supervisor)
- **GitHub**: https://github.com/platanus-hack/platanus-hack-26-co-team-13

---

## 🔐 Bot Credentials (Ya configurados)

```
Bot Token:     ***REDACTED_COMPROMISED_TOKEN***
Chat ID:       [REDACTED_CHAT_ID]
Bot Username:  @provenancePlatanus_bot
```

---

## ⏱️ Timeline

| Cuando | Qué pasa |
|--------|----------|
| **Ahora** | Push a main completado ✅ |
| **1-2 min** | Render detecta cambios y comienza build |
| **2-5 min** | Build finaliza, dependencias instaladas, servidor reiniciado |
| **5+ min** | APIs 100% operacionales |

---

## 🧪 Cómo Probar

### Paso 1: Verificar Status del Bot

Una vez que el deploy esté listo (espera 2-5 minutos):

```bash
curl https://[REDACTED_BACKEND_URL]/api/v1/telegram/status
```

Deberías ver:
```json
{
  "status": "online",
  "total_alerts": 0,
  "pending_approvals": 0,
  "telegram_connected": true
}
```

**O desde tu navegador:**
```
https://[REDACTED_BACKEND_URL]/api/v1/telegram/status
```

### Paso 2: Enviar Alert de Prueba

```bash
curl -X POST https://[REDACTED_BACKEND_URL]/api/v1/telegram/send-alert \
  -H "Content-Type: application/json" \
  -d '{
    "severity": "HIGH",
    "content_preview": "Test alert from production",
    "threats": ["prompt_injection"],
    "threat_score": 0.85,
    "source": "production_test"
  }'
```

Deberías ver:
```json
{
  "success": true,
  "message": "Alert sent to Telegram"
}
```

### Paso 3: Revisa tu Telegram

Deberías recibir un alert con:
- Icono de severidad (🚨, ⚠️, etc.)
- Score de amenaza: 85%
- Source: production_test
- Botones: [✅ Approve] [❌ Reject] [📄 Details]

### Paso 4: Aprueba/Rechaza desde Telegram

Haz click en **✅ Approve** en Telegram y obtendrás un token de una sola vez:
```
✅ Approval Confirmed

Token (one-time use):
Au2SptnCqkKGpxWUlKWC...
```

---

## 🌐 Todos los Endpoints Disponibles

| Método | Endpoint | Descripción |
|--------|----------|-------------|
| `GET` | `/api/v1/telegram/status` | Estado del bot |
| `POST` | `/api/v1/telegram/send-alert` | Enviar alert |
| `GET` | `/api/v1/telegram/alerts/recent?limit=10` | Ver alerts recientes |
| `GET` | `/api/v1/telegram/alerts/{alert_id}` | Ver detalles de alert |
| `GET` | `/api/v1/telegram/approvals/pending` | Ver aprobaciones pendientes |
| `GET` | `/api/v1/telegram/approvals/{request_id}` | Ver detalles de aprobación |
| `POST` | `/api/v1/telegram/approvals/{alert_id}/approve` | Aprobar alert manualmente |
| `POST` | `/api/v1/telegram/approvals/{alert_id}/reject` | Rechazar alert manualmente |
| `GET` | `/api/v1/telegram/report/daily` | Ver reporte diario |
| `POST` | `/api/v1/telegram/send-report` | Enviar reporte manualmente |

---

## 🎮 Ejemplos de Prueba

### Alert CRITICAL (enviado inmediatamente)
```bash
curl -X POST https://[REDACTED_BACKEND_URL]/api/v1/telegram/send-alert \
  -H "Content-Type: application/json" \
  -d '{
    "severity": "CRITICAL",
    "content_preview": "Unauthorized access attempt",
    "threats": ["privilege_escalation"],
    "threat_score": 0.95,
    "source": "security_test"
  }'
```

### Alert HIGH
```bash
curl -X POST https://[REDACTED_BACKEND_URL]/api/v1/telegram/send-alert \
  -H "Content-Type: application/json" \
  -d '{
    "severity": "HIGH",
    "content_preview": "Suspicious activity detected",
    "threats": ["data_exfiltration"],
    "threat_score": 0.82,
    "source": "waf"
  }'
```

### Ver Alerts Recientes
```bash
curl https://[REDACTED_BACKEND_URL]/api/v1/telegram/alerts/recent?limit=5
```

### Ver Reporte Diario
```bash
curl https://[REDACTED_BACKEND_URL]/api/v1/telegram/report/daily
```

---

## 📱 En tu Telegram Verás

Cuando envíes un alert:

```
🚨 HIGH Alert (5f2e1a3c)

Threat Score: 85.0%
Source: production_test
Threats Detected:
• prompt_injection

Preview:
`Test alert from production`

[✅ Approve] [❌ Reject] [📄 Details] [🔍 Query]
```

---

## ✅ Checklist de Deploy

- [ ] Deploy completado en Render (espera 2-5 min)
- [ ] Probar `/api/v1/telegram/status` devuelve JSON
- [ ] Enviar alert de prueba
- [ ] Recibir alert en Telegram
- [ ] Hacer click en Approve
- [ ] Recibir token en Telegram
- [ ] Ver reporte con `/api/v1/telegram/report/daily`

---

## 🔗 URLs Importantes

- **App URL**: https://[REDACTED_BACKEND_URL]
- **GitHub Repo**: https://github.com/platanus-hack/platanus-hack-26-co-team-13
- **Render Dashboard**: https://dashboard.render.com
- **Telegram Bot**: @provenancePlatanus_bot

---

## 🔧 Monitorear el Deploy

Ve a tu Render Dashboard para ver los logs:

```
https://dashboard.render.com
```

Busca tu servicio y mira los logs del deploy. Deberías ver:

```
INFO: Telegram Supervisor configured and will start on app startup
INFO: Starting Telegram Supervisor...
INFO: Telegram Supervisor Bot started successfully
```

---

## 📚 Documentación

Si necesitas más información:

- **TEST_TELEGRAM_BOT.md** - Guía completa de endpoints y pruebas
- **QUICK_START.md** - Setup rápido (5 minutos)
- **TELEGRAM_BOT_SETUP.md** - Guía detallada de configuración
- **FINAL_STEPS.md** - Pasos finales de setup
- **TELEGRAM_BOT_REVIEW.md** - Review técnico del código

---

## 🚀 Próximos Pasos (Opcional)

Una vez que el bot está funcionando:

### 1. Integrar con Memory Firewall

En tu código de análisis de memoria:

```python
from api.main import telegram_bridge

if telegram_bridge:
    await telegram_bridge.on_memory_quarantined(
        analysis_id="ana_123",
        content="Malicious content",
        threats_detected=["prompt_injection"],
        threat_score=0.95,
        authority="untrusted",
        source="external_email",
    )
```

### 2. Integrar con Provenance Firewall

En tu código de autorización:

```python
if telegram_bridge:
    await telegram_bridge.on_action_blocked(
        tool_name="send_file_external",
        args={"file": "data.csv"},
        reason="Untrusted source",
        taint_level="untrusted",
        required_level="org_verified",
    )
```

### 3. Usar Tokens en API

Cuando un admin aprueba en Telegram, obtiene un token:

```bash
TOKEN="<token_from_telegram>"

# Usar en escalations
curl -X POST https://[REDACTED_BACKEND_URL]/api/v1/firewall/escalations/approve \
  -H "Authorization: Bearer $TOKEN"
```

---

## 💡 Notas Importantes

1. **Tokens de Una Sola Vez**: Cada aprobación genera un token único que expira en 24 horas
2. **Sin Pérdida de Datos**: Todos los alerts se guardan en SQLite
3. **Real-time**: Los alerts CRITICAL se envían inmediatamente, los otros se agrupan cada 60 segundos
4. **Audit Trail**: Todas las aprobaciones se registran con timestamp y usuario

---

## 🆘 Troubleshooting

### "Connection refused"
- Espera a que el deploy termine (2-5 minutos)
- Verifica en Render Dashboard que el servicio está corriendo

### "404 Not Found"
- El endpoint no existe o Render aún está reiniciando
- Espera 2-5 minutos y vuelve a intentar

### "No messages in Telegram"
- Verifica que tu Chat ID es correcto ([REDACTED_CHAT_ID])
- Revisa los logs en Render Dashboard

### "Invalid request"
- Asegúrate de usar `Content-Type: application/json`
- `severity` debe ser: CRITICAL, HIGH, MEDIUM, o LOW
- `threat_score` debe estar entre 0 y 1

---

## 📞 Soporte

Si algo no funciona:

1. Revisa los logs en Render Dashboard
2. Intenta desde localhost primero (después de reiniciar backend local)
3. Verifica que el .env tiene el bot token y chat ID correcto
4. Lee la documentación en TEST_TELEGRAM_BOT.md

---

**¡Tu bot está listo en producción!** 🚀

Espera a que el deploy termine y comienza a recibir alertas en Telegram.
