# Provenance Firewall

<img src="./project-logo.png" alt="Provenance Firewall" width="160" />

**Track:** AI Security · **Platanus Hack 26, Bogotá** · team-13

- Valeria Martínez ([@val0219](https://github.com/val0219))
- Isaías José Maciá Insignares ([@isaias-j](https://github.com/isaias-j))
- Cristian David Rugeles Díaz ([@rugelees](https://github.com/rugelees))

**Demo en vivo:** https://platanus.cristianrugeles.com

---

Un agente con memoria persistente no distingue entre lo que un operador le
autorizó y lo que un correo le dijo. Si algo quedó guardado, se lee igual.

Este middleware impone una sola garantía:

> Una memoria puede cambiar de forma, pero no puede ganar autoridad sin un
> evento de autorización explícito de un principal autorizado.

## Cómo funciona

Cada memoria nace atada al origen que la produjo, dentro de un lattice de cinco
niveles: `untrusted` → `observed` → `user_confirmed` → `org_verified` →
`system_authority`.

Resumir, traducir o combinar una memoria **no la promueve**: lo derivado hereda
la autoridad más baja de sus padres y la intersección de sus capacidades. Es el
camino por el que normalmente se lava la procedencia, y aquí está cerrado.

Antes de ejecutar una acción de riesgo, la puerta compara la autoridad exigida
con la que el dato realmente trae. Sin suficiente, la llamada no ocurre.

Sobre eso hay dos capas más:

- **Nueve reglas deterministas** (inyección de prompt, exfiltración, borrado
  destructivo, manipulación de memoria, jailbreak…). Sin modelo: la decisión de
  seguridad nunca depende de cómo un LLM interprete una frase.
- **Verificación semántica** con `nvidia/nemotron-3-nano-30b-a3b`, que solo
  corre sobre acciones de riesgo que las reglas ya aprobaron. Únicamente puede
  endurecer el veredicto (`ALLOW` → `REVIEW`/`BLOCK`); jamás desbloquear. Es
  opcional: sin clave configurada, el firewall decide igual.

Todo queda en un ledger append-only encadenado por hash, con sobres firmados en
Ed25519 y verificación de firma en cada lectura.

## Ejecutar en local

```bash
# Backend
cd backend && python -m pip install ".[test]"
uvicorn api.main:app --reload --port 8000

# Frontend
cd frontend && npm install && npm run dev
```

Panel en `http://localhost:3000`. API en `http://127.0.0.1:8000/docs`.

Con Docker: `docker compose up --build`.

## Pruebas

```bash
cd backend && MEMORY_FIREWALL_RATE_LIMIT=10 python -m pytest -q
```

255 tests. Cubren el lattice, el no-lavado por derivación, aislamiento entre
workspaces, resistencia a veredictos falsificados en el texto auditado e
integridad del ledger.

## Estructura

```
backend/
  memory_firewall/     lattice, políticas, análisis, ledger, capa semántica
  memory_firewall/adapters/   hermes · openclaw · pi
  api/                 FastAPI
frontend/              panel Next.js y demo guiada
```

Los agentes se autentican por workspace con la cabecera `X-Workspace-Key`; cada
cuenta queda aislada de las demás.

## Límites

Esto reduce la superficie del envenenamiento de memoria. **No demuestra que un
contenido sea verdadero** ni elimina toda inyección de prompt.

El alcance del MVP es deliberado: SQLite en vez de un almacén distribuido,
firma con clave en entorno en vez de HSM, y un vertical sintético de soporte al
cliente. Nada de la demo toca una red de pagos real.
