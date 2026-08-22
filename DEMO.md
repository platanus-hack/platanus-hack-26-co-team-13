# Memory Firewall Demo

All demo data is synthetic. The API authorizes evidence only; it never executes a refund.

## Start

Reset the isolated demo database before starting the API. Do not delete a SQLite
file while Uvicorn is running.

```bash
cd backend
export MEMORY_FIREWALL_DB_PATH="$(mktemp -d)/memory_firewall.sqlite3"
export MEMORY_FIREWALL_ED25519_PRIVATE_KEY="$(python -m memory_firewall.crypto)"
export MEMORY_FIREWALL_SIGNING_KEY_ID=demo-local
export MEMORY_FIREWALL_RATE_LIMIT=30
uvicorn api.main:app --host 127.0.0.1 --port 8000
```

In another terminal:

```bash
cd backend
python demo.py --scenario all --base-url http://127.0.0.1:8000 --tenant-id demo
```

## Scenarios

1. `off`: local, visibly simulated comparison where a poisoned ticket would trigger a refund. It does not call the firewall or execute anything.
2. `blocked`: real API flow. A poisoned ticket is blocked, its innocent summary remains quarantined, refund evidence is blocked, and approval of the blocked source returns 422.
3. `approved`: real API flow. A reviewable external ticket is quarantined, an authorized supervisor creates a signed successor with a TTL and refund capability, and only that successor authorizes the scoped refund.
4. `key-fixture`: corporate-sounding text produces no detector hit but is still blocked for refund because authority and capability are insufficient.

The command also prints M1-M6 from operations executed in the run and verifies the ledger after the security scenarios.

## Dashboard

```bash
cd frontend
NEXT_PUBLIC_API_URL=http://127.0.0.1:8000 pnpm dev
```

The dashboard uses tenant `demo`, displays tenant-scoped ledger events, shows ledger validity, sends actor context on requests, and offers scoped approval only for quarantined memories.

## Known Limits

- Actor and tenant are demo client claims; production requires authenticated identity binding.
- The browser shows key availability plus server-side ledger verification. It does not yet independently verify Ed25519 envelope signatures.
- Share/update/delete/tombstone operations are not part of this MVP.
