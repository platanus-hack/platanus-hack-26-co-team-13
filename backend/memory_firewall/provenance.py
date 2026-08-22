"""Provenance Firewall: taint-based authorization for AI agent actions.

This module implements the core provenance-based authorization engine that
gates agent tool calls by data lineage, not just identity.

Key concepts:
- Source: where information originated (user, email, document, tool, system)
- Trust Level: authority rank of that source
- Taint: the minimum trust level of the data that influenced an action
- Action Requirement: the minimum trust level an action demands
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Optional

from .schemas import Authority, Decision, ActorContext, ActorType


class SourceType(str, Enum):
    """Classification of where information originated."""

    UNTRUSTED_EXTERNAL = "untrusted_external"  # email, web, external API
    INTERNAL_DOCUMENT = "internal_document"     # internal doc, not verified
    USER_INPUT = "user_input"                   # authenticated user
    AGENT_REASONING = "agent_reasoning"         # agent's own reasoning
    SYSTEM_CONFIG = "system_config"             # system configuration
    ADMIN_INPUT = "admin_input"                 # admin / privileged user


# Map SourceType to Authority for consistency
SOURCE_TO_AUTHORITY: dict[SourceType, Authority] = {
    SourceType.UNTRUSTED_EXTERNAL: Authority.UNTRUSTED,
    SourceType.INTERNAL_DOCUMENT: Authority.OBSERVED,
    SourceType.USER_INPUT: Authority.USER_CONFIRMED,
    SourceType.AGENT_REASONING: Authority.USER_CONFIRMED,
    SourceType.SYSTEM_CONFIG: Authority.ORG_VERIFIED,
    SourceType.ADMIN_INPUT: Authority.SYSTEM_AUTHORITY,
}


@dataclass(frozen=True)
class SourceMetadata:
    """Metadata about the origin of a piece of information."""

    source_type: SourceType
    authority_level: Authority
    timestamp: datetime
    actor: ActorContext
    context_id: Optional[str] = None  # conversation/session context

    @classmethod
    def from_type(
        cls,
        source_type: SourceType,
        actor: ActorContext,
        timestamp: Optional[datetime] = None,
        context_id: Optional[str] = None,
    ) -> SourceMetadata:
        """Construct metadata from source type (authority derived automatically)."""
        return cls(
            source_type=source_type,
            authority_level=SOURCE_TO_AUTHORITY[source_type],
            timestamp=timestamp or datetime.utcnow(),
            actor=actor,
            context_id=context_id,
        )


@dataclass(frozen=True)
class TaintLineage:
    """Provenance of a piece of data: which sources influenced it."""

    primary_source: SourceMetadata
    secondary_sources: list[SourceMetadata]  # if data was derived
    min_trust_level: Authority  # weakest link in the chain

    @classmethod
    def from_sources(
        cls, sources: list[SourceMetadata]
    ) -> TaintLineage:
        """Compute taint from a list of sources (weakest link principle)."""
        if not sources:
            raise ValueError("Cannot create taint from empty sources")

        from .policy import AUTHORITY_RANK

        primary = sources[0]
        secondary = sources[1:] if len(sources) > 1 else []

        # Min trust = weakest link
        min_rank = min(AUTHORITY_RANK[s.authority_level] for s in sources)
        min_trust = min(
            (s.authority_level for s in sources),
            key=lambda a: AUTHORITY_RANK[a],
        )

        return cls(
            primary_source=primary,
            secondary_sources=secondary,
            min_trust_level=min_trust,
        )


@dataclass(frozen=True)
class TaggedMessage:
    """A message/input with provenance metadata."""

    content: Any  # the actual message/input
    source_metadata: SourceMetadata
    timestamp: datetime = None

    def __post_init__(self):
        if self.timestamp is None:
            object.__setattr__(self, "timestamp", datetime.utcnow())


@dataclass(frozen=True)
class ActionAuthorizationRequest:
    """Request to authorize an agent tool call."""

    tool_name: str
    tool_args: dict[str, Any]
    context_messages: list[TaggedMessage]  # conversation history with metadata
    agent_actor: ActorContext
    request_timestamp: datetime = None

    def __post_init__(self):
        if self.request_timestamp is None:
            object.__setattr__(self, "request_timestamp", datetime.utcnow())


@dataclass(frozen=True)
class ActionAuthorizationDecision:
    """Result of an authorization check."""

    verdict: Decision
    reason: str
    taint_level: Authority  # actual taint of the arguments
    required_level: Authority  # what the action requires
    lineage: TaintLineage  # provenance chain
    escalation_required: bool = False
    escalation_id: Optional[str] = None
    timestamp: datetime = None

    def __post_init__(self):
        if self.timestamp is None:
            object.__setattr__(self, "timestamp", datetime.utcnow())


class ProvenanceTracer:
    """Traces provenance of tool arguments through message history."""

    @staticmethod
    def compute_taint(
        tool_args: dict[str, Any],
        context_messages: list[TaggedMessage],
    ) -> TaintLineage:
        """
        Compute the minimum trust level (taint) of tool arguments.

        Algorithm: for each argument, find which message it originated from,
        extract that message's trust level. The taint is the weakest link.

        For the MVP (deterministic, not ML-based), we use simple string matching:
        if an arg value appears in a message, that message is a potential source.
        """
        from .policy import AUTHORITY_RANK

        # Collect all source metadata for all arguments
        argument_sources: list[SourceMetadata] = []

        for arg_name, arg_value in tool_args.items():
            # Convert argument to string for matching
            if arg_value is None:
                continue
            arg_str = str(arg_value).lower()

            # Find which message(s) contain this argument
            source_found = False
            for msg in context_messages:
                msg_content_str = str(msg.content).lower()
                if arg_str in msg_content_str:
                    argument_sources.append(msg.source_metadata)
                    source_found = True
                    break  # First match wins

            # If no message mentions this argument, assume agent reasoning
            if not source_found:
                argument_sources.append(
                    SourceMetadata.from_type(
                        SourceType.AGENT_REASONING,
                        ActorContext(id="agent:internal", type=ActorType.AGENT),
                    )
                )

        # If no sources at all, default to agent reasoning (safe)
        if not argument_sources:
            argument_sources.append(
                SourceMetadata.from_type(
                    SourceType.AGENT_REASONING,
                    ActorContext(id="agent:internal", type=ActorType.AGENT),
                )
            )

        return TaintLineage.from_sources(argument_sources)


class AuthorizationPolicyEngine:
    """Policy engine that decides whether to allow/block/escalate actions."""

    def __init__(self, action_requirements: dict[str, Authority]):
        """
        Initialize with action requirements.

        Args:
            action_requirements: mapping of action name -> required authority
                E.g., {"send_file": Authority.PRIVILEGED}
        """
        self.action_requirements = action_requirements

    def get_required_authority(self, action: str) -> Authority:
        """Get the required authority for an action, default to ORG_VERIFIED."""
        return self.action_requirements.get(
            action, Authority.ORG_VERIFIED
        )

    def authorize(
        self, request: ActionAuthorizationRequest
    ) -> ActionAuthorizationDecision:
        """
        Authorize an agent action based on provenance.

        Returns ActionAuthorizationDecision with:
        - ALLOW if taint >= required
        - BLOCK if taint < required (privilege escalation attempt)
        - REVIEW for edge cases
        """
        from .policy import AUTHORITY_RANK

        # Compute taint of the arguments
        taint = ProvenanceTracer.compute_taint(
            request.tool_args,
            request.context_messages,
        )

        required = self.get_required_authority(request.tool_name)

        # Decision logic: deterministic, no ML
        required_rank = AUTHORITY_RANK[required]
        taint_rank = AUTHORITY_RANK[taint.min_trust_level]

        if taint_rank < required_rank:
            # Taint < required = unauthorized
            return ActionAuthorizationDecision(
                verdict=Decision.BLOCK,
                reason=(
                    f"Action '{request.tool_name}' requires {required.value} authority, "
                    f"but arguments derived from {taint.min_trust_level.value} source"
                ),
                taint_level=taint.min_trust_level,
                required_level=required,
                lineage=taint,
                escalation_required=True,
                timestamp=request.request_timestamp,
            )
        elif taint_rank == required_rank:
            # Borderline: allow but log
            return ActionAuthorizationDecision(
                verdict=Decision.ALLOW,
                reason=(
                    f"Action '{request.tool_name}' permitted: "
                    f"arguments at required {required.value} level"
                ),
                taint_level=taint.min_trust_level,
                required_level=required,
                lineage=taint,
                escalation_required=False,
                timestamp=request.request_timestamp,
            )
        else:
            # Taint > required = clear allow
            return ActionAuthorizationDecision(
                verdict=Decision.ALLOW,
                reason=(
                    f"Action '{request.tool_name}' permitted: "
                    f"arguments from {taint.min_trust_level.value} source "
                    f"(requires {required.value})"
                ),
                taint_level=taint.min_trust_level,
                required_level=required,
                lineage=taint,
                escalation_required=False,
                timestamp=request.request_timestamp,
            )
