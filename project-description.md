# Memory Firewall for AI Agents

## Problem

AI agents that maintain persistent memory are vulnerable to **memory poisoning attacks**, where an attacker injects malicious content that gains undeserved authority. Once stored in memory, this content can influence future decisions, trigger unintended actions, or compromise sensitive operations like account changes or refunds—all without explicit human approval.

Current systems lack mechanisms to bind authority to information origin and prevent elevation of untrusted memory through derivation or composition.

## Solution

**Memory Firewall** is a security middleware that enforces origin-bound authority over persistent memory. It prevents untrusted information from gaining authority without explicit authorization events.

### Key Features

1. **Authority Lattice (5 Levels)**
   - SYSTEM_AUTHORITY (highest trust)
   - ORG_VERIFIED (verified by organization)
   - USER_CONFIRMED (confirmed by user)
   - OBSERVED (seen but not verified)
   - UNTRUSTED (lowest, no authority)

2. **Deterministic Analysis** (no LLM)
   - 8 threat detection rules (prompt injection, secret exfiltration, jailbreak attempts, etc.)
   - Regex-based analysis that never executes code
   - PII/payment card redaction (SSN, credit cards, API keys, emails)

3. **Provenance Tracking**
   - Every derived memory inherits lowest parent authority
   - Capabilities are intersected on derivation
   - Original source cannot be spoofed

4. **Action Gate**
   - High-risk actions (issue_refund, change_account_destination, send_external_email) require sufficient authority + capabilities
   - REVIEW decisions require explicit approval
   - BLOCK decisions are fail-closed

5. **Integrity Verification**
   - Ed25519 signing of all persisted results
   - Tamper detection on every read
   - SQLite-backed local storage with rate limiting

## Technical Highlights

- **Backend**: FastAPI with 7 REST endpoints (analyze, derive, evaluate_action, list, retrieve, health, keys)
- **Frontend**: Next.js dashboard with real API integration showing enforcement flow and provenance chain
- **Tests**: 67 passing tests (23 code analyzer + 10 security fixes + 6 adversarial + 28 Memory Firewall tests covering functional, adversarial, and integrity scenarios)
- **Security**: Rate limiting (10 req/min/IP), input validation (100KB memory/100KB code), ReDoS-safe regex, CORS protection, Ed25519 envelope signing with asymmetric key management

## Demo Flow

1. **Analyze**: External input (email, user message) is analyzed for threats → authority assigned (OBSERVED)
2. **Derive**: Memory is summarized → inherits lowest parent authority, capabilities intersected
3. **Action Gate**: High-risk action request → checked against authority + capabilities → ALLOW/REVIEW/BLOCK

Example: Untrusted customer email claiming "authorized refund" is analyzed → marked UNTRUSTED → cannot authorize ISSUE_REFUND without explicit USER_CONFIRMED or higher authority.

## Running Locally

```bash
# Backend
cd backend && source .venv/bin/activate && uvicorn api.main:app --reload --port 8000

# Frontend (in another terminal)
cd frontend && npm exec pnpm dev
```

Dashboard: http://localhost:3000
API Docs: http://127.0.0.1:8000/docs
Public Keys Endpoint: http://127.0.0.1:8000/api/v1/keys/current

## MVP Boundaries

- Local agent harness (no production deployment)
- SQLite backend (no blockchain/Kubernetes)
- Deterministic policy (no machine learning)
- Synthetic demo vertical (customer support with refund/account change actions)
- Ed25519 signing (KMS/HSM out of MVP scope, documented limitation)

## What's Next

- Approval/elevation workflow for REVIEW → ALLOW transitions with signed elevation events
- Multi-tenant isolation
- Structured logging + metrics
- Enterprise RBAC
- External verifier support (any component can verify envelopes with public key)
