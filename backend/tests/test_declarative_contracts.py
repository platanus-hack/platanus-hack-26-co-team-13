"""General action effects and independent signed claim authority tests."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from api.main import app
from memory_firewall import intent_judge
from memory_firewall.crypto import verify_result
from memory_firewall.policy import ACTION_CONTRACTS
from memory_firewall.schemas import (
    ActorContext,
    ActorType,
    ApprovalRequest,
    Authority,
    Decision,
    MemoryAnalyzeRequest,
    ToolCallAuthorizationRequest,
    ToolDescriptor,
    ToolRuntime,
    ToolSession,
)
from memory_firewall.service import MemoryFirewallService
from memory_firewall.store import AnalysisStore


TENANT = "ws_contracts"
SCOPE = "treasury"
PAYMENT_ARGUMENTS = {
    "invoice": "INV-900",
    "account": "operating-900",
    "amount": 900.0,
}


@pytest.fixture(autouse=True)
def no_semantic_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MEMORY_FIREWALL_LLM_API_KEY", raising=False)
    monkeypatch.setattr(
        intent_judge,
        "complete",
        lambda **_kwargs: (_ for _ in ()).throw(
            AssertionError("declarative authorization called the semantic provider")
        ),
    )


def _service(tmp_path: Path) -> MemoryFirewallService:
    return MemoryFirewallService(AnalysisStore(str(tmp_path / "firewall.sqlite3")))


def _store(firewall: MemoryFirewallService, claims: dict[str, Any]):
    return firewall.analyze(
        MemoryAnalyzeRequest(
            content="Synthetic independently sourced business evidence.",
            claims=claims,
            source="internal",
            scope=SCOPE,
            actor=ActorContext(id="user:treasury", type=ActorType.USER),
            tenant_id=TENANT,
        )
    )


def _payment_request(
    approved_id: str,
    request_id: str,
    *,
    account_lineage: list[str] | None = None,
) -> ToolCallAuthorizationRequest:
    lineage = {name: [approved_id] for name in PAYMENT_ARGUMENTS}
    if account_lineage is not None:
        lineage["account"] = account_lineage
    return ToolCallAuthorizationRequest(
        schema_version="memory-firewall.tool-call.v1",
        request_id=request_id,
        runtime=ToolRuntime(name="contract-test", adapter_version="1.0.0"),
        session=ToolSession(id="contract-session"),
        tool=ToolDescriptor(name="PAY_INVOICE", arguments=PAYMENT_ARGUMENTS),
        argument_lineage=lineage,
        scope=SCOPE,
        actor=ActorContext(id="agent:treasury", type=ActorType.AGENT),
        tenant_id=TENANT,
    )


def _independent_payment_approval(firewall: MemoryFirewallService):
    invoice = _store(firewall, {"invoice": PAYMENT_ARGUMENTS["invoice"]})
    account = _store(firewall, {"account": PAYMENT_ARGUMENTS["account"]})
    amount = _store(firewall, {"amount": PAYMENT_ARGUMENTS["amount"]})
    approved = firewall.approve(
        ApprovalRequest(
            analysis_id=invoice.analysis_id,
            evidence_analysis_ids=[account.analysis_id, amount.analysis_id],
            approver_id="user:support-supervisor",
            requested_new_authority=Authority.ORG_VERIFIED,
            allowed_actions=["PAY_INVOICE"],
            scope=SCOPE,
            reason="Invoice, destination, and amount checked independently.",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
            tenant_id=TENANT,
            approved_arguments=PAYMENT_ARGUMENTS,
            approved_argument_authorities={
                "invoice": Authority.USER_CONFIRMED,
                "account": Authority.ORG_VERIFIED,
                "amount": Authority.ORG_VERIFIED,
            },
        )
    )
    return approved, invoice, account, amount


def test_new_action_inherits_money_movement_policy_from_manifest(tmp_path: Path) -> None:
    contract = ACTION_CONTRACTS["TRANSFER_FUNDS"]

    assert contract.effects == {"MONEY_MOVEMENT"}
    assert contract.required_authority is Authority.ORG_VERIFIED
    assert contract.high_risk is True
    assert contract.semantic_review is True


def test_contract_registry_is_explainable_through_api() -> None:
    response = TestClient(app).get("/api/v1/policy/action-contracts")

    assert response.status_code == 200
    transfer = response.json()["actions"]["TRANSFER_FUNDS"]
    assert transfer["effects"] == ["MONEY_MOVEMENT"]
    assert transfer["arguments"]["to_account"]["required_authority"] == "org_verified"


def test_undeclared_argument_is_rejected_before_grant_issuance(tmp_path: Path) -> None:
    firewall = _service(tmp_path)
    arguments = {
        "from_account": "operating-100",
        "to_account": "reserve-200",
        "amount": 75.0,
        "skip_audit": True,
    }
    stored = _store(firewall, arguments)

    with pytest.raises(ValueError, match="not declared"):
        firewall.approve(
            ApprovalRequest(
                analysis_id=stored.analysis_id,
                approver_id="user:support-supervisor",
                requested_new_authority=Authority.ORG_VERIFIED,
                allowed_actions=["TRANSFER_FUNDS"],
                scope=SCOPE,
                reason="Synthetic approval.",
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
                tenant_id=TENANT,
                approved_arguments=arguments,
            )
        )


def test_independent_claim_sources_and_authorities_are_signed(tmp_path: Path) -> None:
    firewall = _service(tmp_path)
    approved, invoice, account, amount = _independent_payment_approval(firewall)

    assert approved.claim_authorities == {
        "invoice": Authority.USER_CONFIRMED,
        "account": Authority.ORG_VERIFIED,
        "amount": Authority.ORG_VERIFIED,
    }
    assert {
        name: [reference.analysis_id for reference in references]
        for name, references in (approved.claim_evidence or {}).items()
    } == {
        "invoice": [invoice.analysis_id],
        "account": [account.analysis_id],
        "amount": [amount.analysis_id],
    }
    assert verify_result(approved) is True

    result = firewall.authorize_tool_call(
        _payment_request(approved.analysis_id, "req-independent")
    )
    assert result.decision is Decision.ALLOW
    assert result.effects == ["MONEY_MOVEMENT"]
    assert result.argument_authorities == approved.claim_authorities


def test_weak_extra_lineage_blocks_without_consuming_exact_grant(tmp_path: Path) -> None:
    firewall = _service(tmp_path)
    approved, _invoice, account, _amount = _independent_payment_approval(firewall)

    denied = firewall.authorize_tool_call(
        _payment_request(
            approved.analysis_id,
            "req-weak-lineage",
            account_lineage=[approved.analysis_id, account.analysis_id],
        )
    )
    allowed = firewall.authorize_tool_call(
        _payment_request(approved.analysis_id, "req-after-weak-lineage")
    )

    assert denied.decision is Decision.BLOCK
    assert denied.argument_authorities["account"] is Authority.OBSERVED
    assert allowed.decision is Decision.ALLOW


def test_tampering_claim_authority_breaks_signature(tmp_path: Path) -> None:
    firewall = _service(tmp_path)
    approved, _invoice, _account, _amount = _independent_payment_approval(firewall)
    tampered = approved.model_copy(
        update={
            "claim_authorities": {
                **(approved.claim_authorities or {}),
                "invoice": Authority.SYSTEM_AUTHORITY,
            }
        }
    )

    assert verify_result(tampered) is False
