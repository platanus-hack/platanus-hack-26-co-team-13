"""Cross-session integration tests for signed memory tool authorization."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from memory_firewall.schemas import (
    ActorContext,
    ActorType,
    ApprovalRequest,
    Authority,
    Decision,
    MemoryAnalyzeRequest,
    MemoryDeriveRequest,
    MemoryRetrieveRequest,
    ToolCallAuthorizationRequest,
    ToolDescriptor,
    ToolRuntime,
    ToolSession,
)
from memory_firewall.service import MemoryFirewallService
from memory_firewall.store import AnalysisStore
from memory_firewall.tool_gateway import MemoryToolExecutionGateway


def _service(tmp_path: Path) -> MemoryFirewallService:
    return MemoryFirewallService(AnalysisStore(str(tmp_path / "firewall.sqlite3")))


def _lineage(service: MemoryFirewallService):
    source = service.analyze(
        MemoryAnalyzeRequest(
            content="Andina Logistics changed its account to 8842 for invoice INV-3812.",
            claims={
                "vendor": "Andina Logistics",
                "account": "8842",
                "amount": 48_000_000,
            },
            source="email",
            scope="accounts_payable",
            actor=ActorContext(id="external:vendor-email", type=ActorType.EXTERNAL_SOURCE),
            tenant_id="demo",
        )
    )
    summary = service.derive(
        MemoryDeriveRequest(
            content="Andina Logistics account 8842, invoice INV-3812, amount 48000000.",
            parent_analysis_ids=[source.analysis_id],
            transformation="summarize",
            scope="accounts_payable",
            actor=ActorContext(id="agent:finance-session-a", type=ActorType.AGENT),
            tenant_id="demo",
        )
    )
    return source, summary


def _tool_request(analysis_id: str, request_id: str = "req-3812") -> ToolCallAuthorizationRequest:
    arguments = {
        "vendor": "Andina Logistics",
        "account": "8842",
        "amount": 48_000_000,
    }
    return ToolCallAuthorizationRequest(
        schema_version="memory-firewall.tool-call.v1",
        request_id=request_id,
        runtime=ToolRuntime(name="pi", adapter_version="0.1.0"),
        session=ToolSession(id="session-b", tool_call_id="call-3812"),
        tool=ToolDescriptor(name="pay_invoice", arguments=arguments),
        argument_lineage={key: [analysis_id] for key in arguments},
        scope="accounts_payable",
        actor=ActorContext(id="agent:finance-session-b", type=ActorType.AGENT),
        tenant_id="demo",
    )


def test_cross_session_lineage_blocks_before_tool_execution(tmp_path: Path) -> None:
    service = _service(tmp_path)
    source, summary = _lineage(service)
    retrieval = service.retrieve(
        MemoryRetrieveRequest(
            analysis_id=summary.analysis_id,
            session_id="session-b",
            actor=ActorContext(id="agent:finance-session-b", type=ActorType.AGENT),
            tenant_id="demo",
        )
    )
    invocations = []
    gateway = MemoryToolExecutionGateway(
        service,
        {"pay_invoice": lambda **arguments: invocations.append(arguments)},
    )

    result = gateway.execute(_tool_request(retrieval.memory.analysis_id))

    assert result.executed is False
    assert result.decision.decision == Decision.BLOCK
    assert result.decision.provided_authority == Authority.UNTRUSTED
    assert result.decision.required_authority == Authority.ORG_VERIFIED
    assert result.decision.ancestor_analysis_ids == [source.analysis_id]
    assert invocations == []
    event_types = [event.event_type for event in reversed(service.store.list_events("demo"))]
    assert event_types == ["WRITE", "DERIVE", "RETRIEVE", "TOOL_DECISION"]
    assert service.store.verify_chain()[0] is True


def test_scoped_approved_successor_can_execute_once(tmp_path: Path) -> None:
    service = _service(tmp_path)
    _, summary = _lineage(service)
    approved = service.approve(
        ApprovalRequest(
            analysis_id=summary.analysis_id,
            approver_id="user:support-supervisor",
            requested_new_authority=Authority.ORG_VERIFIED,
            allowed_actions=["PAY_INVOICE"],
            scope="accounts_payable",
            reason="Vendor change independently verified.",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
            tenant_id="demo",
        )
    )
    invocations = []
    gateway = MemoryToolExecutionGateway(
        service,
        {"PAY_INVOICE": lambda **arguments: invocations.append(arguments) or "created"},
    )

    result = gateway.execute(_tool_request(approved.analysis_id, "req-approved"))

    assert result.executed is True
    assert result.value == "created"
    assert len(invocations) == 1


def test_every_tool_argument_requires_signed_lineage(tmp_path: Path) -> None:
    service = _service(tmp_path)
    _, summary = _lineage(service)
    request = _tool_request(summary.analysis_id)
    request.argument_lineage.pop("amount")

    try:
        service.authorize_tool_call(request)
    except ValueError as exc:
        assert str(exc) == "every_tool_argument_requires_lineage"
    else:
        raise AssertionError("missing argument lineage must fail closed")


def test_signed_lineage_cannot_be_reused_for_different_argument_value(tmp_path: Path) -> None:
    service = _service(tmp_path)
    _, summary = _lineage(service)
    request = _tool_request(summary.analysis_id)
    request.tool.arguments["account"] = "attacker-account"

    try:
        service.authorize_tool_call(request)
    except ValueError as exc:
        assert str(exc) == "argument_value_not_bound:account"
    else:
        raise AssertionError("evidence for one value must not authorize another value")
