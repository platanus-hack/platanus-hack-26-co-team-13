# ⚡ Provenance Firewall — Quick Start for Judges

**5-minute demo of the complete system.** No installation needed beyond Python + pip.

---

## Prerequisites (Already Done)

```bash
# If you need to set up the environment fresh:
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

## Demo (< 5 minutes)

### Run 1: Execute the Full Attack Scenario

```bash
cd backend
source .venv/bin/activate

python demo_provenance_attack.py --mode both
```

**What you'll see:**
- **VULNERABLE MODE**: Attack succeeds, 50,000 records exfiltrated ❌
- **PROTECTED MODE**: Attack blocked, 0 records, escalation created ✅
- **Comparison table**: Shows the impact side-by-side

### Run 2: Verify the Tests

```bash
python -m pytest tests/test_provenance_firewall.py -v
```

**Expected**: 16/16 passing (0.08 seconds)

### Run 3: Explore the API (Optional)

```bash
# Terminal 1: Start the server
uvicorn api.main:app --reload --port 8000
```

```bash
# Terminal 2: View API docs
# Visit: http://127.0.0.1:8000/docs
# Look for: /api/v1/firewall/* endpoints
```

---

## The Key Numbers

| Metric | Without Firewall | With Firewall |
|--------|------------------|---------------|
| Records exfiltrated | **50,000** ❌ | **0** ✅ |
| Attack success rate | **100%** ❌ | **0%** ✅ |
| Action blocked | No | **Yes** ✅ |
| Escalation created | No | **Yes** ✅ |
| Audit log signed | No | **Yes** ✅ |

---

## How It Works (30-second explanation)

1. **The Problem**
   - AI agents read untrusted emails/documents
   - Current security only checks "does agent have permission?"
   - Doesn't check "did this instruction come from a trusted source?"

2. **Our Solution**
   - Firewall intercepts every tool call
   - Checks: "Where did this instruction come from?"
   - If source is UNTRUSTED but action requires TRUSTED → BLOCK

3. **The Proof**
   - Same attack, same agent, same request
   - WITHOUT firewall: 50,000 records leak
   - WITH firewall: 0 records, action blocked, human notified

---

## File Guide (For Judges Looking at Code)

| File | What | Lines | Key Insight |
|------|------|-------|-------------|
| `backend/memory_firewall/provenance.py` | Taint engine | 300 | Computes trust level of data |
| `backend/memory_firewall/provenance_ledger.py` | Audit log | 250 | Ed25519-signed, tamper-proof |
| `backend/memory_firewall/escalation.py` | Human workflow | 350 | Approvals + one-time tokens |
| `backend/demo_provenance_attack.py` | Attack demo | 250 | Shows vulnerable vs protected |
| `backend/tests/test_provenance_firewall.py` | Test suite | 400 | 16 tests, 100% passing |

---

## What Makes This Win

1. ✅ **Solves Real Problem**: Indirect prompt injection is OWASP #1
2. ✅ **Demostrable**: "50k records → 0 records" (objective metric)
3. ✅ **Production Quality**: Tests, signatures, audit trail
4. ✅ **Deterministic**: No ML guessing, clear rules
5. ✅ **Differentiates**: Identity auth (Palo Alto) vs Provenance auth (us)
6. ✅ **Honest**: "CaMeL proved this works; we made it deployable"

---

## Questions?

### "Is this tested?"
Run: `pytest tests/test_provenance_firewall.py -v`  
Result: 16/16 passing ✅

### "Can I see it block an attack?"
Run: `python demo_provenance_attack.py --mode both`  
Result: 50,000 → 0 records ✅

### "How does it verify signatures?"
See: `backend/memory_firewall/provenance_ledger.py` line ~180  
Method: `ProvenanceLedger.verify_integrity()` ✅

### "What about false positives?"
Run escalation approval:  
```bash
curl -X POST http://127.0.0.1:8000/api/v1/firewall/escalations/{id}/approve
```
Result: One-time token generated, action allowed ✅

---

## Success Criteria (All Met)

- [x] Backend MVP complete
- [x] 16 tests passing
- [x] Demo runs in < 5 minutes
- [x] No external dependencies
- [x] Attack metric clear (50k → 0)
- [x] Code signed/verifiable
- [x] Documentation provided
- [x] Ready for live demo

---

## Estimated Time

- **Demo only**: 3 minutes
- **Demo + tests**: 4 minutes
- **Demo + tests + API explore**: 10 minutes

**Judges can run the full evaluation in < 5 minutes.**

---

*Team 13 | Platanus Hack 26 | AI Security Track*
