# HANDOFF - Memory Firewall Backend

## Estado Actual (commit 59c9669)

**Repositorio:** `/Users/isaias/Documents/Platanus/team-13/`
**Branch:** `main` (sincronizado con `origin/main`)
**Tests:** 60 pasando (39 originales + 20 nuevos de Memory Firewall + 1 adversarial)

---

## Qué está implementado y funcionando

### Backend completo (`backend/`)
```
backend/
├── api/main.py                    # FastAPI con 5 endpoints
├── analyzer/                      # Detector de código original (reutilizado)
├── memory_firewall/               # NUEVO - Core del Memory Firewall
│   ├── analyzer.py                # 8 reglas deterministas de memoria
│   ├── analyzer.py                # Patrones ReDoS-safe
│   ├── policy.py                  # Authority lattice + capabilities + action gate
│   ├── store.py                   # SQLite + HMAC-SHA256 integrity
│   ├── crypto.py                  # HMAC-SHA256 signing + verification
+   ├── schemas.py                 # Pydantic models (Decision, Authority, Capabilities, etc.)
│   ├── service.py                 # Orquestador: analyze/derive/evaluate_action
│   ├── store.py                   # SQLite + HMAC verification
│   ├── crypto.py                  # HMAC-SHA256 signing + integrity
│   └── schemas.py                 # Pydantic models completos
├── tests/
│   ├── test_analyze.py            # 23 tests originales (código)
│   ├── test_adversarial.py        # 6 tests adversariales
│   ├── test_security_fixes.py     # 10 tests de regresión
│   └── test_memory_firewall.py    # 20 tests funcionales + adversariales
├── requirements.txt
└── README.md
```

---

## Endpoints funcionando

| Endpoint | Método | Descripción |
|----------|--------|-------------|
| `/api/v1/analyze` | POST | Analizador de código original (PoC) |
| `/api/v1/memory/analyze` | POST | **NUEVO** - Analiza memoria/contexto |
| `/api/v1/memory/derive` | POST | **NUEVO** - Deriva memoria con provenance heredada |
| `/api/v1/actions/evaluate` | POST | **NUEVO** - Action gate (authority + capabilities + scope) |
| `/api/v1/analyses/{id}` | GET | Recupera análisis persistido |
| `/api/v1/health` | GET | Health check |
| `/health` | GET | Health check original |

---

## Modelo de decisión implementado

**Authority Lattice (5 niveles):**
```
SYSTEM_AUTHORITY > ORG_VERIFIED > USER_CONFIRMED > OBSERVED > UNTRUSTED
```

**Capacidades (intersección en derivación):**
- `allowed_actions`: READ, DERIVE, ISSUE_REFUND, CHANGE_ACCOUNT_DESTINATION, SEND_EXTERNAL_EMAIL
- `allowed_scopes`: customer_support_policy, customer_support_user, user_memory, etc.
- `requires_approval`: bool
- `usable_for_action`: bool

**Decisiones:** `ALLOW` | `REVIEW` | `BLOCK`
- `QUARANTINED` = estado operativo (no autoridad)

---

## Seguridad implementada

- ✅ Rate limiting: 10 req/min por IP real (ignora X-Forwarded-For)
- ✅ Input validation: max 50KB memoria, 100KB código, NUL/control chars rechazados
- ✅ ReDoS protection: regex lineales, prefilters, quantifiers bounded
- ✅ HMAC-SHA256 signing + verification (HMAC key via env `MEMORY_FIREWALL_SIGNING_KEY`)
- ✅ SQLite integrity verification on every read (tamper detection)
- ✅ Rate limit buckets bounded (10k IPs, LRU eviction)
- ✅ CPU-bound analysis offloaded from event loop
- ✅ No code execution ever (regex-only analysis)
- ✅ Rate limit buckets bounded (LRU, max 10k IPs)

---

## Tests pasando (60 total)

| Suite | Tests | Qué cubre |
|-------|-------|-----------|
| `test_analyze.py` | 23 | Code analyzer original |
| `test_security_fixes.py` | 10 | Regresiones de auditoría |
| `test_adversarial.py` | 6 | Bypass attempts + false positives |
| `test_memory_firewall.py` | 20 | Funcional + adversarial + integridad |
| **Total** | **60** | **100% passing** |

---

## Comandos para continuar

```bash
cd /Users/isaias/Documents/Platanus/team-13/backend
source .venv/bin/activate
python -m pytest tests/ -q          # 60 passing
uvicorn api.main:app --reload       # server en :8000
# docs: http://127.0.0.1:8000/docs
```

---

## Qué falta para el hackathon (próximos pasos)

1. **Demo end-to-end** script que ejecute el flujo completo
2. **Frontend integration** - conectar el dashboard Next.js a la API real
3. **README.md de proyecto** - llenar `platanus-hack-project.jsonc` y `project-description.md`
4. **Video de respaldo** de la demo (3 min)
5. **Pitch deck** - 30s / 1min / 3min versions

---

## Variables de entorno necesarias

```bash
# .env (crear en backend/)
MEMORY_FIREWALL_SIGNING_KEY=your-32-byte-secret-here
MEMORY_FIREWALL_SIGNING_KEY_ID=prod-key-1
MEMORY_FIREWALL_DB_PATH=memory_firewall.sqlite3
MEMORY_FIREWALL_ALLOWED_ORIGINS=http://localhost:3000,http://127.0.0.1:3000
```

---

## Decisiones técnicas clave (no cambiar sin razón)

1. **HMAC-SHA256** en lugar de Ed25519: evita dependencia `cryptography` en MVP; migración a Ed25519/KMS para producción
2. **Authority discreta** (no score numérico) - evita precisión falsa, explicable
3. **Rate limiting por IP real** - `request.client.host` (no X-Forwarded-For)
4. **Authority no escalable en derivación** - herencia por `min(authority)`
5. **Capabilities por intersección** - derivación usa intersección de parents
6. **HMAC-SHA256** con clave en env - migración a Ed25519/KMS en producción

---

## Archivos de documentación clave

- `docs/MEMORY_FIREWALL_REQUIREMENTS.md` - Requerimientos completos (3437 líneas)
- `docs/IMPLEMENTATION_PLAN.md` - Plan 36h para 3 devs
- `AGENTS.md` - Reglas de seguridad para agentes
- `backend/README.md` - Documentación API
- `backend/memory_firewall/` - Código del core

---

## Si algo falla al continuar

1. `git status` → verifica estado
2. `cd backend && source .venv/bin/activate && python -m pytest tests/ -q`
3. Si fallan tests: `git diff HEAD` para ver qué cambió
4. `git log --oneline -5` para ver últimos commits

---

**Último commit:** `59c9669` - "Add 3-dev implementation plan"
**Estado git:** Clean, sincronizado con `origin/main`

---

*Generado automáticamente para handoff de cuenta. El contexto de conversación no se transfiere; este archivo captura el estado técnico completo.*