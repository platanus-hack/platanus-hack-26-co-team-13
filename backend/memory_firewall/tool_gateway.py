"""Fail-closed execution boundary for agent tools."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Optional

from .escalation import EscalationManager
from .provenance import (
    ActionAuthorizationDecision,
    ActionAuthorizationRequest,
    AuthorizationPolicyEngine,
    TaggedMessage,
)
from .provenance_ledger import ProvenanceLedger
from .schemas import (
    ActorContext,
    Authority,
    Decision,
    ToolCallAuthorizationRequest,
    ToolCallAuthorizationResponse,
)
from .service import MemoryFirewallService


Tool = Callable[..., Any]


class UnknownToolError(LookupError):
    """Raised before execution when a tool is not registered with the gateway."""


@dataclass(frozen=True)
class ToolExecutionResult:
    """Authorization and execution outcome returned to an agent adapter."""

    executed: bool
    decision: ActionAuthorizationDecision
    value: Any = None
    escalation_id: Optional[str] = None


class ToolExecutionGateway:
    """The only execution path exposed to an agent harness.

    Tools are selected from a local registry after authorization, so callers
    cannot authorize one name and supply a different callable for execution.
    """

    def __init__(
        self,
        action_requirements: dict[str, Authority],
        tools: dict[str, Tool],
        ledger: ProvenanceLedger,
        escalation_manager: EscalationManager,
        agent_actor: ActorContext,
    ) -> None:
        self.engine = AuthorizationPolicyEngine(action_requirements)
        self.tools = dict(tools)
        self.ledger = ledger
        self.escalation_manager = escalation_manager
        self.agent_actor = agent_actor

    def execute(
        self,
        tool_name: str,
        tool_args: dict[str, Any],
        context_messages: list[TaggedMessage],
    ) -> ToolExecutionResult:
        """Authorize and, only when allowed, invoke a registered tool."""
        if tool_name not in self.tools:
            raise UnknownToolError(f"Tool is not registered: {tool_name}")

        request = ActionAuthorizationRequest(
            tool_name=tool_name,
            tool_args=tool_args,
            context_messages=context_messages,
            agent_actor=self.agent_actor,
        )
        decision = self.engine.authorize(request)
        self.ledger.append(
            decision,
            agent_id=self.agent_actor.id,
            action_name=tool_name,
        )

        if decision.verdict != Decision.ALLOW:
            ticket = self.escalation_manager.create_escalation(
                decision=decision,
                blocked_action=tool_name,
                agent_id=self.agent_actor.id,
                created_by="firewall:tool_execution_gateway",
            )
            return ToolExecutionResult(
                executed=False,
                decision=decision,
                escalation_id=ticket.ticket_id,
            )

        value = self.tools[tool_name](**tool_args)
        return ToolExecutionResult(
            executed=True,
            decision=decision,
            value=value,
        )


@dataclass(frozen=True)
class MemoryToolExecutionResult:
    """Execution result backed by persisted, signed memory lineage."""

    executed: bool
    decision: ToolCallAuthorizationResponse
    value: Any = None


class MemoryToolExecutionGateway:
    """Execute registered tools only after signed memory authorization."""

    def __init__(
        self,
        service: MemoryFirewallService,
        tools: dict[str, Tool],
    ) -> None:
        self.service = service
        self.tools = {name.strip().upper(): tool for name, tool in tools.items()}

    def execute(
        self, request: ToolCallAuthorizationRequest
    ) -> MemoryToolExecutionResult:
        tool_name = request.tool.name
        if tool_name not in self.tools:
            raise UnknownToolError(f"Tool is not registered: {tool_name}")

        decision = self.service.authorize_tool_call(request)
        if decision.decision != Decision.ALLOW:
            return MemoryToolExecutionResult(executed=False, decision=decision)

        value = self.tools[tool_name](**request.tool.arguments)
        return MemoryToolExecutionResult(
            executed=True,
            decision=decision,
            value=value,
        )
