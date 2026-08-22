# 🧪 Prueba tu Telegram Bot - Desde la Web

Tu backend está corriendo. Ahora puedes probar el bot directamente desde tu navegador o desde curl.

---

## 📋 Endpoints Disponibles

### 1️⃣ **Ver Estado del Bot**
```
GET http://127.0.0.1:8000/api/v1/telegram/status
```

Respuesta esperada:
```json
{
  "status": "online",
  "total_alerts": 0,
  "pending_approvals": 0,
  "approved_approvals": 0,
  "rejected_approvals": 0,
  "telegram_connected": true
}
```

**Pruébalo en tu navegador:**
```
http://127.0.0.1:8000/api/v1/telegram/status
```

---

### 2️⃣ **Enviar Alert de Prueba**
```
POST http://127.0.0.1:8000/api/v1/telegram/send-alert
```

Con datos:
```json
{
  "severity": "HIGH",
  "content_preview": "Malicious code detected in user input",
  "threats": ["prompt_injection", "code_execution"],
  "threat_score": 0.85,
  "source": "web_api_test"
}
```

**Con curl:**
```bash
curl -X POST http://127.0.0.1:8000/api/v1/telegram/send-alert \
  -H "Content-Type: application/json" \
  -d '{
    "severity": "HIGH",
    "content_preview": "Malicious code detected in user input",
    "threats": ["prompt_injection", "code_execution"],
    "threat_score": 0.85,
    "source": "web_api_test"
  }'
```

Respuesta:
```json
{
  "success": true,
  "message": "Alert sent to Telegram"
}
```

**¡Revisa tu Telegram! Deberías ver el alert con botones.**

---

### 3️⃣ **Ver Alerts Recientes**
```
GET http://127.0.0.1:8000/api/v1/telegram/alerts/recent?limit=10
```

**En tu navegador:**
```
http://127.0.0.1:8000/api/v1/telegram/alerts/recent?limit=5
```

Respuesta:
```json
[
  {
    "alert_id": "5f2e1a3c",
    "severity": "high",
    "threat_score": 0.85,
    "content_preview": "Malicious code detected...",
    "source": "web_api_test",
    "threats": ["prompt_injection", "code_execution"],
    "timestamp": "2026-08-22T15:47:12.123456"
  }
]
```

---

### 4️⃣ **Ver Aprobaciones Pendientes**
```
GET http://127.0.0.1:8000/api/v1/telegram/approvals/pending
```

**En tu navegador:**
```
http://127.0.0.1:8000/api/v1/telegram/approvals/pending
```

---

### 5️⃣ **Ver Reporte Diario**
```
GET http://127.0.0.1:8000/api/v1/telegram/report/daily
```

**En tu navegador:**
```
http://127.0.0.1:8000/api/v1/telegram/report/daily
```

Respuesta:
```json
{
  "report_id": "abc123",
  "period_start": "2026-08-22T00:00:00",
  "period_end": "2026-08-22T23:59:59",
  "total_alerts": 5,
  "critical_alerts": 1,
  "high_alerts": 2,
  "medium_alerts": 2,
  "low_alerts": 0,
  "total_approved": 1,
  "total_rejected": 0,
  "pending_approvals": 2
}
```

---

### 6️⃣ **Enviar Reporte Manualmente**
```
POST http://127.0.0.1:8000/api/v1/telegram/send-report
```

**Con curl:**
```bash
curl -X POST http://127.0.0.1:8000/api/v1/telegram/send-report
```

Respuesta:
```json
{
  "success": true,
  "message": "Report sent to Telegram"
}
```

**¡Revisa tu Telegram! Verás el reporte diario con estadísticas.**

---

## 🎮 Flujo Completo de Prueba

### Paso 1: Verificar que el bot está online
```bash
curl http://127.0.0.1:8000/api/v1/telegram/status
```

Deberías ver: `"status": "online"`

### Paso 2: Enviar un alert CRITICAL
```bash
curl -X POST http://127.0.0.1:8000/api/v1/telegram/send-alert \
  -H "Content-Type: application/json" \
  -d '{
    "severity": "CRITICAL",
    "content_preview": "⚠️ CRITICAL: Unauthorized access attempt detected!",
    "threats": ["privilege_escalation", "unauthorized_access"],
    "threat_score": 0.95,
    "source": "security_test"
  }'
```

**En Telegram verás:** Un alert CRÍTICO con botones para approve/reject

### Paso 3: Enviar un alert HIGH
```bash
curl -X POST http://127.0.0.1:8000/api/v1/telegram/send-alert \
  -H "Content-Type: application/json" \
  -d '{
    "severity": "HIGH",
    "content_preview": "⚠️ Suspicious file transfer detected",
    "threats": ["data_exfiltration"],
    "threat_score": 0.82,
    "source": "security_test"
  }'
```

### Paso 4: Ver alerts
```bash
curl http://127.0.0.1:8000/api/v1/telegram/alerts/recent?limit=10
```

### Paso 5: Aprobar un alert desde Telegram
1. En tu chat de Telegram, ve el alert
2. Haz click en ✅ **Approve**
3. El bot genera un token de una sola vez
4. Ver confirmación en Telegram

### Paso 6: Ver aprobaciones
```bash
curl http://127.0.0.1:8000/api/v1/telegram/approvals/pending
```

### Paso 7: Ver reporte
```bash
curl http://127.0.0.1:8000/api/v1/telegram/report/daily
```

---

## 🌐 Desde tu Navegador

Puedes abrir estos links directamente en tu navegador:

1. **Status:**
   ```
   http://127.0.0.1:8000/api/v1/telegram/status
   ```

2. **Alerts recientes:**
   ```
   http://127.0.0.1:8000/api/v1/telegram/alerts/recent?limit=10
   ```

3. **Aprobaciones pendientes:**
   ```
   http://127.0.0.1:8000/api/v1/telegram/approvals/pending
   ```

4. **Reporte diario:**
   ```
   http://127.0.0.1:8000/api/v1/telegram/report/daily
   ```

---

## 📊 Ejemplos de Diferentes Severidades

### CRITICAL Alert (enviado inmediatamente)
```bash
curl -X POST http://127.0.0.1:8000/api/v1/telegram/send-alert \
  -H "Content-Type: application/json" \
  -d '{
    "severity": "CRITICAL",
    "content_preview": "System compromise detected",
    "threats": ["malware", "ransomware"],
    "threat_score": 0.99,
    "source": "antivirus"
  }'
```

### HIGH Alert
```bash
curl -X POST http://127.0.0.1:8000/api/v1/telegram/send-alert \
  -H "Content-Type: application/json" \
  -d '{
    "severity": "HIGH",
    "content_preview": "Unauthorized admin access",
    "threats": ["privilege_escalation"],
    "threat_score": 0.88,
    "source": "access_log"
  }'
```

### MEDIUM Alert
```bash
curl -X POST http://127.0.0.1:8000/api/v1/telegram/send-alert \
  -H "Content-Type: application/json" \
  -d '{
    "severity": "MEDIUM",
    "content_preview": "Suspicious SQL pattern detected",
    "threats": ["sql_injection"],
    "threat_score": 0.65,
    "source": "waf"
  }'
```

### LOW Alert
```bash
curl -X POST http://127.0.0.1:8000/api/v1/telegram/send-alert \
  -H "Content-Type: application/json" \
  -d '{
    "severity": "LOW",
    "content_preview": "Unusual login time detected",
    "threats": ["anomalous_behavior"],
    "threat_score": 0.45,
    "source": "iam"
  }'
```

---

## ✅ Checklist de Prueba

- [ ] Status del bot online: `GET /status`
- [ ] Enviar alert CRITICAL: `POST /send-alert` (severity: CRITICAL)
- [ ] Ver alert en Telegram: ✅ Deberías recibirlo
- [ ] Hacer click en Approve: ✅ Deberías obtener token
- [ ] Ver aprobación: `GET /approvals/pending`
- [ ] Ver reporte diario: `GET /report/daily`
- [ ] Enviar múltiples alerts: `POST /send-alert` x 5
- [ ] Ver todos los alerts: `GET /alerts/recent?limit=10`
- [ ] Enviar reporte manual: `POST /send-report`
- [ ] Ver reporte en Telegram: ✅ Estadísticas completas

---

## 🔧 Troubleshooting

### "Connection refused"
- Verifica que el backend esté corriendo: `lsof -i :8000`
- Reinicia el backend si es necesario

### "No messages in Telegram"
- Verifica que tu Chat ID es correcto en `.env`
- Comprueba que el bot está online: `GET /status`
- Revisa los logs del backend

### "Invalid request"
- Asegúrate de usar `Content-Type: application/json`
- Verifica que `threat_score` esté entre 0 y 1
- `severity` debe ser: CRITICAL, HIGH, MEDIUM, o LOW

---

## 📝 Resumen

Tu bot está **100% operacional**. Puedes:

1. ✅ Enviar alertas vía API
2. ✅ Recibirlas en Telegram
3. ✅ Aprobar/rechazar desde Telegram
4. ✅ Obtener tokens seguros
5. ✅ Ver reportes con estadísticas
6. ✅ Consultar historial completo

**Todo funciona ahora mismo desde tu backend en ejecución.**

---

## 🚀 Próximo Paso

Integra estas llamadas en tu **Memory Firewall** y **Provenance Firewall**:

```python
from api.main import telegram_bridge

# En Memory Firewall
if telegram_bridge:
    await telegram_bridge.on_memory_quarantined(...)

# En Provenance Firewall  
if telegram_bridge:
    await telegram_bridge.on_action_blocked(...)
```

**¡Y listo! Tu sistema completo estará monitoreado via Telegram en tiempo real.**
