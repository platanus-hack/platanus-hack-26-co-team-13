"""End-to-end high-risk authorization with no semantic provider installed."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from memory_firewall import intent_judge
from memory_firewall.policy import ACTION_CONTRACTS, HIGH_RISK_ACTIONS
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
from memory_firewall.tool_gateway import MemoryToolExecutionGateway


ACTION_ARGUMENTS: dict[str, dict[str, Any]] = {
    "ISSUE_REFUND": {"refund_id": "refund-100", "amount": 125.0},
    "CHANGE_ACCOUNT_DESTINATION": {
        "account_id": "account-100",
        "new_destination": "destination-200",
    },
    "SEND_EXTERNAL_EMAIL": {
        "recipient": "recipient@example.test",
        "subject": "Approved update",
        "body": "Synthetic approved message.",
    },
    "PAY_INVOICE": {
        "invoice": "INV-100",
        "account": "operating-100",
        "amount": 320.0,
    },
    "TRANSFER_FUNDS": {
        "from_account": "operating-100",
        "to_account": "reserve-200",
        "amount": 75.0,
    },
    "SEND_FILE_EXTERNAL": {
        "recipient": "recipient@example.test",
        "file_id": "file-100",
    },
    "DELETE_USER": {"user_id": "user-100", "reason": "synthetic cleanup"},
    "EXPORT_USER_DATA": {
        "export_id": "export-100",
        "destination": "vault-100",
    },
}


@pytest.fixture(autouse=True)
def disable_semantic_layer(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MEMORY_FIREWALL_LLM_API_KEY", raising=False)

    def unexpected_model_call(**_kwargs: Any) -> str:
        raise AssertionError("deterministic authorization called the semantic provider")

    monkeypatch.setattr(intent_judge, "complete", unexpected_model_call)


def _service(tmp_path: Path) -> MemoryFirewallService:
    return MemoryFirewallService(AnalysisStore(str(tmp_path / "firewall.sqlite3")))


def _store(
    firewall: MemoryFirewallService,
    action: str,
    arguments: dict[str, Any],
):
    return firewall.analyze(
        MemoryAnalyzeRequest(
            content=f"Synthetic business record for {action}.",
            claims=arguments,
            source="internal",
            scope="deterministic_test",
            actor=ActorContext(id="user:operator", type=ActorType.USER),
            tenant_id="ws_deterministic",
        )
    )


def _approve(
    firewall: MemoryFirewallService,
    analysis_id: str,
    action: str,
    arguments: dict[str, Any],
):
    return firewall.approve(
        ApprovalRequest(
            analysis_id=analysis_id,
            approver_id="user:support-supervisor",
            requested_new_authority=Authority.ORG_VERIFIED,
            allowed_actions=[action],
            scope="deterministic_test",
            reason="Exact synthetic action independently approved.",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
            tenant_id="ws_deterministic",
            approved_arguments=arguments,
        )
    )


def _request(
    analysis_id: str,
    action: str,
    arguments: dict[str, Any],
    request_id: str,
) -> ToolCallAuthorizationRequest:
    return ToolCallAuthorizationRequest(
        schema_version="memory-firewall.tool-call.v1",
        request_id=request_id,
        runtime=ToolRuntime(name="deterministic-test", adapter_version="1.0.0"),
        session=ToolSession(id="deterministic-session"),
        tool=ToolDescriptor(name=action, arguments=arguments),
        argument_lineage={name: [analysis_id] for name in arguments},
        scope="deterministic_test",
        actor=ActorContext(id="agent:test", type=ActorType.AGENT),
        tenant_id="ws_deterministic",
    )


def test_matrix_covers_every_registered_high_risk_action() -> None:
    assert set(ACTION_ARGUMENTS) == HIGH_RISK_ACTIONS
    for action, arguments in ACTION_ARGUMENTS.items():
        assert set(arguments) >= ACTION_CONTRACTS[action].required_arguments


@pytest.mark.parametrize("action", sorted(ACTION_ARGUMENTS))
def test_high_risk_action_without_grant_fails_closed(
    tmp_path: Path,
    action: str,
) -> None:
    firewall = _service(tmp_path)
    arguments = ACTION_ARGUMENTS[action]
    stored = _store(firewall, action, arguments)

    result = firewall.authorize_tool_call(
        _request(stored.analysis_id, action, arguments, f"req-no-grant-{action.lower()}")
    )

    assert result.decision is Decision.BLOCK
    assert result.semantic_judgement is None


@pytest.mark.parametrize("action", sorted(ACTION_ARGUMENTS))
def test_exact_grant_executes_once_without_ai(
    tmp_path: Path,
    action: str,
) -> None:
    firewall = _service(tmp_path)
    arguments = ACTION_ARGUMENTS[action]
    stored = _store(firewall, action, arguments)
    approved = _approve(firewall, stored.analysis_id, action, arguments)
    invocations: list[dict[str, Any]] = []
    gateway = MemoryToolExecutionGateway(
        firewall,
        {action: lambda **values: invocations.append(values) or "executed"},
    )

    first = gateway.execute(
        _request(approved.analysis_id, action, arguments, f"req-first-{action.lower()}")
    )
    replay = gateway.execute(
        _request(approved.analysis_id, action, arguments, f"req-replay-{action.lower()}")
    )

    assert first.executed is True
    assert first.decision.decision is Decision.ALLOW
    assert first.decision.semantic_judgement is None
    assert replay.executed is False
    assert replay.decision.decision is Decision.BLOCK
    assert invocations == [arguments]


@pytest.mark.parametrize("action", sorted(ACTION_ARGUMENTS))
def test_incomplete_attempt_does_not_consume_exact_grant(
    tmp_path: Path,
    action: str,
) -> None:
    firewall = _service(tmp_path)
    arguments = ACTION_ARGUMENTS[action]
    stored = _store(firewall, action, arguments)
    approved = _approve(firewall, stored.analysis_id, action, arguments)
    missing_name = next(iter(ACTION_CONTRACTS[action].required_arguments))
    incomplete = {name: value for name, value in arguments.items() if name != missing_name}

    denied = firewall.authorize_tool_call(
        _request(
            approved.analysis_id,
            action,
            incomplete,
            f"req-incomplete-{action.lower()}",
        )
    )
    allowed = firewall.authorize_tool_call(
        _request(approved.analysis_id, action, arguments, f"req-valid-{action.lower()}")
    )

    assert denied.decision is Decision.BLOCK
    assert any("missing" in reason.lower() for reason in denied.reasons)
    assert allowed.decision is Decision.ALLOW
    assert allowed.semantic_judgement is None


def test_concurrent_replay_executes_exactly_once(tmp_path: Path) -> None:
    firewall = _service(tmp_path)
    action = "PAY_INVOICE"
    arguments = ACTION_ARGUMENTS[action]
    stored = _store(firewall, action, arguments)
    approved = _approve(firewall, stored.analysis_id, action, arguments)
    invocations: list[dict[str, Any]] = []
    gateway = MemoryToolExecutionGateway(
        firewall,
        {action: lambda **values: invocations.append(values) or "executed"},
    )

    def execute(index: int):
        return gateway.execute(
            _request(
                approved.analysis_id,
                action,
                arguments,
                f"req-concurrent-{index}",
            )
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(execute, range(2)))

    assert sum(outcome.executed for outcome in outcomes) == 1
    assert {outcome.decision.decision for outcome in outcomes} == {
        Decision.ALLOW,
        Decision.BLOCK,
    }
    assert invocations == [arguments]
