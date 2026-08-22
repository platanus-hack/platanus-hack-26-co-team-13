"""LangGraph middleware integration for Provenance Firewall.

This module provides a drop-in middleware for LangGraph agents that enforces
provenance-based authorization on every tool call.

Usage:
  from memory_firewall.langgraph_middleware import ProvenanceFirewallMiddleware
  
  middleware = ProvenanceFirewallMiddleware(
      action_requirements={...},
      escalation_manager=escalation_mgr,
      ledger=ledger
  )
  
  agent = create_agent(
      model=...,
      tools=[...],
      middleware=[middleware]
  )
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Optional

from .provenance import (
    ActionAuthorizationRequest,
    AuthorizationPolicyEngine,
    ProvenanceTracer,
    SourceMetadata,
    SourceType,
    TaggedMessage,
)
from .provenance_ledger import ProvenanceLedger
from .escalation import EscalationManager
from .schemas import Authority, ActorContext, ActorType


@dataclass
class ToolCallDecision:
    """Result of authorizing a tool call."""

    allowed: bool
    blocked_reason: Optional[str] = None
    escalation_id: Optional[str] = None
    taint_level: Optional[Authority] = None


class ProvenanceFirewallMiddleware:
    """
    Middleware that enforces provenance-based authorization for LangGraph agents.

    For every tool call:
    1. Extract the tool name and arguments
    2. Look up the conversation history (context) with metadata
    3. Compute taint of the arguments
    4. Check if the action is allowed given the taint
    5. ALLOW: let the tool execute
    6. BLOCK: intercept, create escalation, return denial message
    """

    def __init__(
        self,
        action_requirements: dict[str, Authority],
        escalation_manager: EscalationManager,
        ledger: ProvenanceLedger,
        agent_id: str = "agent:default",
    ):
        """
        Initialize the middleware.

        Args:
            action_requirements: mapping of tool_name -> required Authority
            escalation_manager: EscalationManager instance
            ledger: ProvenanceLedger instance for audit logging
            agent_id: identifier for this agent
        """
        self.engine = AuthorizationPolicyEngine(action_requirements)
        self.escalation_manager = escalation_manager
        self.ledger = ledger
        self.agent_id = agent_id

    def should_intercept_tool_call(
        self,
        tool_name: str,
        tool_args: dict[str, Any],
        context_messages: list[dict[str, Any]],
    ) -> ToolCallDecision:
        """
        Decide whether to allow or block a tool call.

        Args:
            tool_name: name of the tool being called
            tool_args: arguments passed to the tool
            context_messages: conversation history (each should have 'content' and metadata)

        Returns:
            ToolCallDecision indicating ALLOW/BLOCK and details
        """
        # Convert raw context messages to TaggedMessages with provenance
        tagged_messages = self._tag_messages(context_messages)

        # Create authorization request
        request = ActionAuthorizationRequest(
            tool_name=tool_name,
            tool_args=tool_args,
            context_messages=tagged_messages,
            agent_actor=ActorContext(id=self.agent_id, type=ActorType.AGENT),
        )

        # Get authorization decision
        decision = self.engine.authorize(request)

        # Log the decision
        self.ledger.append(decision, agent_id=self.agent_id, action_name=tool_name)

        # If blocked, create escalation
        if decision.verdict.value == "block":
            escalation = self.escalation_manager.create_escalation(
                decision=decision,
                blocked_action=tool_name,
                agent_id=self.agent_id,
                created_by="firewall:tool_call_gate",
            )

            return ToolCallDecision(
                allowed=False,
                blocked_reason=decision.reason,
                escalation_id=escalation.ticket_id,
                taint_level=decision.taint_level,
            )

        # If allowed, permit execution
        return ToolCallDecision(
            allowed=True,
            taint_level=decision.taint_level,
        )

    def get_denial_message(self, decision: ToolCallDecision) -> dict[str, Any]:
        """Generate a tool message indicating the action was denied."""
        return {
            "type": "tool",
            "name": "provenance_firewall",
            "content": (
                f"**Action Blocked by Provenance Firewall**\n\n"
                f"Reason: {decision.blocked_reason}\n\n"
                f"This action was blocked because the information that triggered it "
                f"does not have sufficient trust level to authorize this action.\n\n"
                f"Escalation ticket: {decision.escalation_id}\n\n"
                f"An administrator will review this request."
            ),
            "escalation_id": decision.escalation_id,
        }

    def _tag_messages(self, raw_messages: list[dict[str, Any]]) -> list[TaggedMessage]:
        """
        Convert raw message dicts to TaggedMessages with provenance metadata.

        Heuristics:
        - If message has role="user", mark as USER_INPUT
        - If message has role="assistant" or "agent", mark as AGENT_REASONING
        - If message has role="tool", mark as SYSTEM_CONFIG
        - If message contains metadata ["source_type"], use that
        - If message comes from an email-like source or contains "external", mark as UNTRUSTED_EXTERNAL
        - Default: LOW_TRUST (OBSERVED)
        """
        tagged = []

        for msg in raw_messages:
            content = msg.get("content", "")
            role = msg.get("role", "").lower()
            metadata = msg.get("metadata", {})

            # Determine source type
            if "source_type" in metadata:
                source_type = SourceType[metadata["source_type"].upper()]
            elif role == "user":
                source_type = SourceType.USER_INPUT
            elif role in ("assistant", "agent"):
                source_type = SourceType.AGENT_REASONING
            elif role == "tool":
                source_type = SourceType.SYSTEM_CONFIG
            elif "email" in str(content).lower() or "external" in str(content).lower():
                source_type = SourceType.UNTRUSTED_EXTERNAL
            else:
                source_type = SourceType.INTERNAL_DOCUMENT

            # Determine actor
            actor_id = metadata.get("actor_id", f"{role}:unknown")
            actor_type = ActorType[metadata.get("actor_type", role.upper())]

            # Create source metadata
            source_metadata = SourceMetadata.from_type(
                source_type=source_type,
                actor=ActorContext(id=actor_id, type=actor_type),
            )

            # Create tagged message
            tagged_msg = TaggedMessage(
                content=content,
                source_metadata=source_metadata,
            )
            tagged.append(tagged_msg)

        return tagged


# LangGraph integration helper
def create_firewall_middleware(
    action_requirements: dict[str, Authority],
    escalation_manager: EscalationManager,
    ledger: ProvenanceLedger,
    agent_id: str = "agent:default",
) -> ProvenanceFirewallMiddleware:
    """Factory function to create Provenance Firewall middleware for LangGraph."""
    return ProvenanceFirewallMiddleware(
        action_requirements=action_requirements,
        escalation_manager=escalation_manager,
        ledger=ledger,
        agent_id=agent_id,
    )
