# Memory Firewall — Plan de implementación (3 devs, 36 horas)

Plan operativo derivado de `MEMORY_FIREWALL_REQUIREMENTS.md`. Cada dev marca su progreso con checkboxes. Referencias cruzadas a secciones del documento de requerimientos (`[REQ §x]`).

## 0. Decisiones congeladas (no se negocian durante el build)

- Alcance: MVP B (provenance + integridad criptografica) + MVP C (vertical customer support) `[REQ §14.1]`.
- Prohibido lo listado en `[REQ §15.1]`: blockchain, HSM, K8s, multi-tenant real, Stripe real, SSO, billing, classifier entrenado, etc.
- Stack `[REQ §17.1]`: Python 3.12+, FastAPI, SQLite, `cryptography` (Ed25519), pytest, frontend Next.js existente en `frontend/`, React Flow para el grafo.
- Regla estructural: una memoria puede cambiar de forma, pero no de autoridad ni de capacidades sin un evento firmado de un principal autorizado `[REQ §25.5]`.
- El LLM no es TCB `[REQ §3.5]`. Agente determinista por defecto (`DEMO_DETERMINISTIC=1`): `EXTRACT_FACT` y `SUMMARIZE_MEMORY` usan fixtures; LLM opcional solo para texto decorativo tras H26, nunca como input del firewall.
- Cronograma: 36 horas.
- Frontend ya movido a `frontend/` (commit `2c6243f`).

## 1. Estructura de repo

```text
backend/
  memory_firewall/
    schemas.py          # MemoryEnvelope, Capabilities, Decision (contrato C1)
    canonical.py        # JSON canonico [REQ §8.12]
    crypto.py           # Ed25519, key_id, verificacion
    authority.py        # lattice discreto + meet [REQ §8.2-8.4]
    capabilities.py     # interseccion de capacidades [REQ §8.6]
    policy.py           # motor determinista (FR-032..034)
    action_gate.py      # FR-020, FR-021, FR-021A/B
    approval.py         # elevacion firmada [REQ §8.5, FR-024]
    firewall.py         # facade MemoryFirewall [REQ §17.5]
    store/
      base.py           # Protocol MemoryStore [REQ §17.4]
      sqlite.py         # schema Apendice B
      ledger.py         # hash chain + verify (FR-029..031)
  agent/
    loop.py             # maquina de estados [REQ §14.3]
    fixtures.py         # corpus sintetico [REQ §19.4]
  api/main.py           # FastAPI, endpoints A.1-A.7
  demo.py               # --firewall off/on [REQ §16]
  tests/                # T01-T18
frontend/               # front Next.js existente
```

## 2. Division por dev

### Dev A — Security Core (autoridad, cripto, policy, action gate)

- [ ] Ed25519: keypair, firma/verificacion de envelopes y eventos (FR-008, §8.11)
- [ ] Canonicalizacion determinista (§8.12): claves ordenadas, UTC, campos no firmables fuera
- [ ] Lattice de autoridad + `meet` (FR-013): `ORG_VERIFIED + UNTRUSTED -> UNTRUSTED`
- [ ] Capabilities: interseccion en derivaciones, nunca ampliacion (FR-021A, §8.6)
- [ ] Motor de policy determinista (FR-032/033/034) con las 5 reglas congeladas:
  - [ ] `external-cannot-create-org-policy` (fail-closed, §7.9)
  - [ ] high-risk requiere `USER_CONFIRMED`+ y capability explicita (FR-020)
  - [ ] derivacion no eleva autoridad ni capacidades
  - [ ] `cross_user_share requires org_verified`
  - [ ] memoria expirada excluida de acciones
- [ ] Action gate (FR-020/021/021B): authority + capability + scope + expiry + approval
- [ ] Elevacion explicita firmada (§8.5, FR-024): aprueba solo accion/scope/TTL; nueva version, no mutacion
- [ ] Tests propios: T02, T03, T05, T06, T07, T08, T13, T16, T18
- [ ] NFR a su cargo: NFR-001, NFR-006, NFR-007

### Dev B — Store, Ledger, Agente y Demo end-to-end

- [ ] Schema SQLite Apendice B: `memory_items` (con `allowed_actions/scopes`, `requires_approval`), `memory_parents`, `policy_decisions`, `ledger_events`, `keys`
- [ ] `MemoryStore` tras Protocol (NFR-002): put/get/search/versions/tombstone
- [ ] Ledger append-only con `previous_hash` + `verify_ledger()` (FR-029/030/031)
- [ ] Identidad: `actor_id/type`, tenant/scope en toda operacion (FR-001/002), API key local (FR-003)
- [ ] Origin/taint: origin classes, propagacion, separacion fuente/actor (FR-004/005/006)
- [ ] Retrieval verificado: firma, scope, exclusion/etiquetado de quarantined, provenance resumida (FR-015..018)
- [ ] Update/delete/share: versionado, tombstone, no elevacion al compartir (FR-025..028)
- [ ] Cuarentena como estado operativo (FR-022)
- [ ] Agent loop determinista (§14.3) + fixtures del corpus (§19.4): 5 tickets externos, 5 preferencias, 3 politicas, 3 summaries, 3 derivaciones, 3 shares, 3 tampering, 3 capability/approval
- [ ] `demo.py --firewall off/on` (§16.2-16.6) con refund simulado
- [ ] Tests propios: T01, T04, T09, T10, T11, T12, T14, T15
- [ ] Metricas de seguridad M1-M6 medidas sobre fixtures

### Dev C — API, Dashboard, QA y Pitch

- [ ] FastAPI con contrato exacto Apendice A: `evaluate-write`, `memories`, `derive`, `retrieve`, `actions/evaluate`, `approvals`, `ledger/verify` (incluye capabilities y `usable_for_action`)
- [ ] Config de acciones de alto riesgo: `ISSUE_REFUND`, `CHANGE_ACCOUNT_DESTINATION`, `SEND_EXTERNAL_EMAIL` (FR-019)
- [ ] Conectar front Next.js existente (hoy estatico) a la API:
  - [ ] timeline de eventos / "Recent events"
  - [ ] memory store con authority, capabilities y riesgo
  - [ ] provenance graph (React Flow): ticket externo -> memoria A -> memoria B -> accion bloqueada
  - [ ] panel de decision con reasons legibles (FR-021)
  - [ ] panel de cuarentena con boton de approval (FR-023/024) que dispara elevacion
  - [ ] estado de firma por memoria, switch Firewall ON/OFF para los 3 escenarios de la demo
  - [ ] metricas M1-M6 + `Signature verification: pass` en pantalla (§16.8)
- [ ] QA/NFR: NFR-005 (datos sinteticos), NFR-008 (arranque con un comando, README), NFR-009 (operation id + reason), NFR-010 (sin cuentas reales)
- [ ] Harness de latencia M7/M8/M9 (p50<25ms, p95<100ms), fixture M10 de firma invalida
- [ ] Material de pitch (§22), objeciones de jueces (§21), lista de limitaciones, video de respaldo

## 3. Fases (36h, 3 pistas paralelas)

### H0-4 — Alinear y congelar alcance

Dev A:
- [ ] Congelar JSON schemas `MemoryEnvelope`/`Capabilities`/`Decision` (contrato C1)
- [ ] Congelar las 5 policies exactas (contrato C2)

Dev B:
- [ ] Schema SQLite inicial + fixture sintetico del ticket veneno (§16.3)

Dev C:
- [ ] Wireframe de 3 pantallas
- [ ] Contrato de eventos del dashboard (C4)
- [ ] Skeleton FastAPI con stubs A.1-A.7

Regla de salida (§18.2): no se agrega ningun vector de ataque nuevo sin quitar otro feature.

### H4-10 — Core de memoria y firmas

Dev A:
- [ ] Crypto + canonical + lattice
- [ ] Firma/verificacion; T07 (tampering)

Dev B:
- [ ] `MemoryStore` SQLite + ledger + decision records
- [ ] FR-001..006 (identidad, origin/taint)

Dev C:
- [ ] API contra mocks segun Apendice A; tipos TS
- [ ] "Recent events" con datos del mock

Riesgo (§18.3): errores de serializacion → tests de canonicalizacion antes de integrar.

### H10-18 — Derivacion, cuarentena y policies (hito critico)

Dev A:
- [ ] Derive certificates, meet authority+capabilities
- [ ] Action gate, policy engine completo
- [ ] T02, T03, T05, T16

Dev B:
- [ ] Cuarentena, retrieval verificado
- [ ] Agent loop, modo off/on
- [ ] T01, T04

Dev C:
- [ ] Conectar API al store real
- [ ] Memory list + panels basicos
- [ ] Inicio harness latencia

Kill criterion (§24.3): si una derivacion no conserva autoridad para H18, fallbacks → congelar transforms a `SUMMARIZE`, eliminar sharing real, un solo parent.

### H18-26 — Agente y demo end-to-end

Dev A:
- [ ] Approvals/elevacion firmada
- [ ] T06, T08, T13, T18

Dev B:
- [ ] `demo.py` e2e off/on
- [ ] Shares, replay, expiry
- [ ] T09-T12, T14, T15; M1-M6

Dev C:
- [ ] Provenance graph, panel decision/cuarentena
- [ ] Boton approval, switch firewall, signature status

Riesgo (§18.5): LLM no determinista → fixture de decision + `DEMO_DETERMINISTIC=1`.

### H26-32 — Dashboard y provenance graph

Dev A:
- [ ] Hardening + tampering fixture + edge cases

Dev B:
- [ ] Corpus completo + `ledger verify` CLI + reset de DB

Dev C:
- [ ] Metricas en pantalla, README un-comando, pitch, limitaciones, video backup

Regla (§18.6): un grafico claro vale mas que animaciones.

### H32-36 — Hardening, ensayo y pitch

Dev A:
- [ ] Freeze: solo bugs que rompan demo (§18.7)

Dev B:
- [ ] Ensayo cronometrado < 3 min

Dev C:
- [ ] Ensayo + preguntas dificiles (§21) + fallback sin frontend

## 4. Contratos de integracion (puntos de sync)

- [ ] C1 (H4): JSON schemas firmables — sin esto no firma nadie
- [ ] C2 (H4): `MemoryStore` Protocol (§17.4)
- [ ] C3 (H8): OpenAPI del Apendice A
- [ ] C4 (H10): modelo de eventos del timeline (write/derive/read/share/approval/block + reasons)

## 5. Definition of Done (§14.7)

- [ ] `pytest` verde
- [ ] memoria externa escribe como `UNTRUSTED`
- [ ] derivacion conserva parent+autoridad
- [ ] derivacion conserva o reduce capacidades
- [ ] nuevo usuario recupera el item
- [ ] item no puede activar `ISSUE_REFUND`
- [ ] aprobacion firmada habilita solo accion+scope declarados
- [ ] dashboard muestra el camino original
- [ ] ledger verificable
- [ ] ataque funciona sin firewall
- [ ] mismo ataque bloqueado con firewall
- [ ] funciona sin red salvo LLM opcional

## 6. Riesgos y mitigaciones (§24 + §18)

| Riesgo | Mitigacion |
|---|---|
| Writes bypass del middleware (R1) | Store solo accesible via firewall; records sin firma = `UNTRUSTED` |
| Taint inicial incorrecto (R2) | origin_class desde canal autenticado, no del LLM; `UNKNOWN` conservador |
| Agente omite parents (R3) | `DERIVE` sin parents rechazado; wrapper obligatorio |
| Serializacion/divergencia de firma | Tests de canonicalizacion antes de integrar (H4-10) |
| LLM no determinista | Fixtures de decision + `DEMO_DETERMINISTIC=1` |
| Dashboard se traga el tiempo | Presupuesto de estilo limitado; un grafo claro > animaciones |
| Romper en la ultima hora | Sin refactors post H34 |

## 7. Trazabilidad completa (nada sin owner)

- FR-001..034 + FR-021A/B: A → 003,004,005,006,008,009,012,013,014,020,021,021A,021B,024,032,033,034 · B → 001,002,007,010,011,015,016,017,018,022,025,026,027,028,029,030,031 · C → 019,023,024(UI)
- NFR-001..010: A → 001,006,007 · B → 002,004 · C → 005,008,009,010
- Tests T01..T18: A → 02,03,05,06,07,08,13,16,18 · B → 01,04,09,10,11,12,14,15
- Metricas M1..M10: B → M1-M6 · C → M7-M10
- Demo §16.1-16.8: B (escenarios y fixtures) + C (visualizacion y metricas)
- Apendice A: C · Apendice B: B · Cripto/§8.x: A
