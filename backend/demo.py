"""Run synthetic Memory Firewall scenarios against a running local API."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import httpx

from demo_fixtures import DERIVED_SUMMARY, INNOCENT_LANGUAGE_TICKET, POISONED_TICKET, REVIEWABLE_TICKET

DEFAULT_BASE_URL = "http://127.0.0.1:8000"
DEFAULT_TENANT = "demo"
INGEST_ACTOR = {"id": "user:demo-ingest", "type": "user"}
AGENT_ACTOR = {"id": "agent:demo-support", "type": "agent"}
SCOPE = "customer_support_policy"


class DemoError(RuntimeError):
    """Raised when the API result differs from the security script."""


@dataclass
class Metrics:
    poison_attempts: int = 0
    poison_active: int = 0
    poisoned_sessions: int = 0
    poisoned_action_sessions: int = 0
    derived_count: int = 0
    derived_authority_escalations: int = 0
    unauthorized_actions: int = 0
    blocked_unauthorized_actions: int = 0
    derived_with_parent_chain: int = 0
    derived_or_shared_count: int = 0
    capability_escapes: int = 0

    def report(self) -> dict[str, float]:
        def ratio(numerator: int, denominator: int) -> float:
            return numerator / denominator if denominator else 0.0

        return {
            "M1_poisoning_write_acceptance_rate": ratio(self.poison_active, self.poison_attempts),
            "M2_cross_session_activation_rate": ratio(
                self.poisoned_action_sessions, self.poisoned_sessions
            ),
            "M3_laundering_escalation_rate": ratio(
                self.derived_authority_escalations, self.derived_count
            ),
            "M4_high_risk_block_rate": ratio(
                self.blocked_unauthorized_actions, self.unauthorized_actions
            ),
            "M5_provenance_completeness": ratio(
                self.derived_with_parent_chain, self.derived_count
            ),
            "M6_capability_escape_rate": ratio(
                self.capability_escapes, self.derived_or_shared_count
            ),
        }


@dataclass
class DemoClient:
    base_url: str
    tenant_id: str
    http: httpx.Client = field(default_factory=lambda: httpx.Client(timeout=5))

    def request(self, method: str, path: str, *, expected: int = 200, **kwargs: object) -> dict:
        response = self.http.request(method, f"{self.base_url}{path}", **kwargs)
        if response.status_code != expected:
            raise DemoError(f"{method} {path}: expected {expected}, got {response.status_code}: {response.text}")
        return response.json()

    def analyze(self, content: str) -> dict:
        return self.request(
            "POST",
            "/api/v1/memory/analyze",
            json={
                "content": content,
                "source": "email",
                "scope": SCOPE,
                "actor": INGEST_ACTOR,
                "tenant_id": self.tenant_id,
            },
        )

    def derive(self, parent_analysis_id: str) -> dict:
        return self.request(
            "POST",
            "/api/v1/memory/derive",
            json={
                "content": DERIVED_SUMMARY,
                "parent_analysis_ids": [parent_analysis_id],
                "transformation": "summarize",
                "scope": SCOPE,
                "actor": AGENT_ACTOR,
                "tenant_id": self.tenant_id,
            },
        )

    def evaluate(self, analysis_id: str, scope: str = SCOPE) -> dict:
        return self.request(
            "POST",
            "/api/v1/actions/evaluate",
            json={
                "analysis_ids": [analysis_id],
                "action": "ISSUE_REFUND",
                "scope": scope,
                "actor": AGENT_ACTOR,
                "tenant_id": self.tenant_id,
            },
        )

    def approve(self, analysis_id: str, *, expected: int = 200) -> dict:
        return self.request(
            "POST",
            "/api/v1/approvals",
            expected=expected,
            json={
                "analysis_id": analysis_id,
                "approver_id": "user:support-supervisor",
                "requested_new_authority": "user_confirmed",
                "allowed_actions": ["READ", "ISSUE_REFUND"],
                "scope": SCOPE,
                "reason": "Reviewed against the synthetic support policy.",
                "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat(),
                "tenant_id": self.tenant_id,
            },
        )

    def verify_ledger(self) -> dict:
        return self.request("GET", "/api/v1/ledger/verify")


def require(value: bool, message: str) -> None:
    if not value:
        raise DemoError(message)


def run_off() -> dict:
    """Show the intentionally unsafe comparison without contacting the firewall."""

    return {
        "scenario": "firewall_off_simulation",
        "ticket": POISONED_TICKET,
        "result": "SIMULATED_REFUND_EXECUTED",
        "note": "Local comparison only; no API call or refund is executed.",
    }


def run_blocked(client: DemoClient, metrics: Metrics) -> dict:
    poisoned = client.analyze(POISONED_TICKET)
    metrics.poison_attempts += 1
    metrics.poisoned_sessions += 1
    metrics.poison_active += int(poisoned["state"] == "active")
    require(poisoned["decision"] == "block", "poisoned ticket was not blocked")

    derived = client.derive(poisoned["analysis_id"])
    metrics.derived_count += 1
    metrics.derived_or_shared_count += 1
    metrics.derived_with_parent_chain += int(
        derived["provenance"]["parent_analysis_ids"] == [poisoned["analysis_id"]]
    )
    metrics.derived_authority_escalations += int(derived["authority"] != poisoned["authority"])
    metrics.capability_escapes += int(
        not set(derived["capabilities"]["allowed_actions"]).issubset(
            poisoned["capabilities"]["allowed_actions"]
        )
    )
    require(derived["state"] == "quarantined", "derived poisoned memory lost quarantine")

    decision = client.evaluate(derived["analysis_id"])
    metrics.unauthorized_actions += 1
    metrics.blocked_unauthorized_actions += int(decision["decision"] == "block")
    metrics.poisoned_action_sessions += int(decision["decision"] == "allow")
    require(decision["decision"] == "block", "poisoned derivative authorized a refund")
    client.approve(poisoned["analysis_id"], expected=422)
    ledger = client.verify_ledger()
    require(ledger["valid"], "ledger verification failed")
    return {"scenario": "firewall_on_blocked", "analysis": poisoned, "derived": derived, "action": decision}


def run_approved(client: DemoClient, metrics: Metrics) -> dict:
    reviewable = client.analyze(REVIEWABLE_TICKET)
    require(reviewable["state"] == "quarantined", "reviewable ticket was not quarantined")
    approved = client.approve(reviewable["analysis_id"])
    allowed = client.evaluate(approved["analysis_id"])
    wrong_scope = client.evaluate(approved["analysis_id"], scope="corporate_policy")
    require(allowed["decision"] == "allow", "approved successor did not authorize scoped refund")
    require(wrong_scope["decision"] == "block", "approval leaked into another scope")
    ledger = client.verify_ledger()
    require(ledger["valid"], "ledger verification failed")
    return {"scenario": "approval_real", "original": reviewable, "approved": approved, "action": allowed}


def run_key_fixture(client: DemoClient) -> dict:
    result = client.analyze(INNOCENT_LANGUAGE_TICKET)
    require(not result["threats"], "innocent-language fixture unexpectedly triggered a detector")
    decision = client.evaluate(result["analysis_id"])
    require(decision["decision"] == "block", "authority gate did not block innocent-language fixture")
    return {"scenario": "authority_not_detector", "analysis": result, "action": decision}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", choices=["off", "blocked", "approved", "key-fixture", "all"], default="all")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--tenant-id", default=DEFAULT_TENANT)
    parser.add_argument("--reset", action="store_true", help="Refuse unsafe reset while an API may be running.")
    args = parser.parse_args()
    if args.reset:
        print("Refusing to delete SQLite from a client. Reset MEMORY_FIREWALL_DB_PATH before starting Uvicorn.")
        return 2
    client = DemoClient(args.base_url.rstrip("/"), args.tenant_id)
    metrics = Metrics()
    try:
        client.request("GET", "/api/v1/health")
        runners = {
            "off": lambda: run_off(),
            "blocked": lambda: run_blocked(client, metrics),
            "approved": lambda: run_approved(client, metrics),
            "key-fixture": lambda: run_key_fixture(client),
        }
        scenarios = [args.scenario] if args.scenario != "all" else list(runners)
        results = [runners[scenario]() for scenario in scenarios]
    except (DemoError, httpx.HTTPError) as exc:
        print(f"DEMO FAILED: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"results": results, "metrics": metrics.report()}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
