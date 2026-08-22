"""FastAPI routes for Provenance Firewall.

Provides REST endpoints for:
- Authorization decisions
- Audit ledger queries
- Escalation management
- Policy configuration
"""

import hmac
import os
from typing import Any, Optional
from fastapi import APIRouter, HTTPException, Header, Depends
from pydantic import BaseModel, Field

from memory_firewall.provenance import (
    ActionAuthorizationRequest,
    TaggedMessage,
    SourceMetadata,
    SourceType,
)
from memory_firewall.provenance_ledger import ProvenanceLedger
from memory_firewall.escalation import EscalationManager
from memory_firewall.langgraph_middleware import ProvenanceFirewallMiddleware
from memory_firewall.schemas import Authority, ActorContext, ActorType

router = APIRouter(prefix="/api/v1/firewall", tags=["firewall"])


def require_api_key(x_api_key: Optional[str] = Header(default=None)) -> None:
    """Fail-closed API key check for sensitive (state-changing) endpoints.

    Set TELEGRAM_API_KEY in the environment to enable. If unset, the
    endpoint returns 503 rather than allowing unauthenticated access.
    """
    expected = os.getenv("TELEGRAM_API_KEY", "")
    if not expected:
        raise HTTPException(
            status_code=503,
            detail="Endpoint disabled: TELEGRAM_API_KEY not configured",
        )
    if not x_api_key or not hmac.compare_digest(x_api_key, expected):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


# Request/Response Models
class AuthorizeToolCallRequest(BaseModel):
    """Request to authorize a tool call."""

    tool_name: str = Field(..., description="Name of the tool being called")
    tool_args: dict[str, Any] = Field(..., description="Arguments to the tool")
    context_messages: list[dict[str, Any]] = Field(
        ..., description="Conversation history with provenance metadata"
    )
    agent_id: Optional[str] = Field(default="agent:default", description="Agent ID")


class AuthorizeToolCallResponse(BaseModel):
    """Response with authorization decision."""

    allowed: bool
    reason: str
    taint_level: str
    required_level: str
    escalation_id: Optional[str] = None
    timestamp: str


class AuditEntryView(BaseModel):
    """View of an audit ledger entry."""

    entry_id: str
    timestamp: str
    action: str
    agent_id: str
    taint_level: str
    required_level: str
    decision: str
    reason: str
    lineage_summary: str
    signature_valid: bool


class EscalationTicketView(BaseModel):
    """View of an escalation ticket."""

    ticket_id: str
    status: str
    created_at: str
    blocked_action: str
    blocked_reason: str
    agent_id: str
    escalation_id: Optional[str] = None
    approval_token: Optional[str] = None


class ApproveEscalationRequest(BaseModel):
    """Request to approve an escalation."""

    approved_by: str = Field(..., description="ID of approver")
    approval_reason: str = Field(..., description="Why action is being approved")


# Global instances (should be injected in production)
_ledger: Optional[ProvenanceLedger] = None
_escalation_manager: Optional[EscalationManager] = None
_middleware: Optional[ProvenanceFirewallMiddleware] = None


def set_firewall_instances(
    ledger: ProvenanceLedger,
    escalation_manager: EscalationManager,
    middleware: ProvenanceFirewallMiddleware,
) -> None:
    """Configure the firewall instances for the routes."""
    global _ledger, _escalation_manager, _middleware
    _ledger = ledger
    _escalation_manager = escalation_manager
    _middleware = middleware


@router.post("/authorize", response_model=AuthorizeToolCallResponse)
async def authorize_tool_call(
    request: AuthorizeToolCallRequest,
) -> AuthorizeToolCallResponse:
    """
    Authorize a tool call based on provenance.

    Returns:
    - allowed=True if the tool call is permitted
    - allowed=False if blocked (with escalation_id for human review)
    """
    if not _middleware:
        raise HTTPException(status_code=500, detail="Firewall not initialized")

    # Run authorization
    decision = _middleware.should_intercept_tool_call(
        tool_name=request.tool_name,
        tool_args=request.tool_args,
        context_messages=request.context_messages,
    )

    return AuthorizeToolCallResponse(
        allowed=decision.allowed,
        reason=decision.blocked_reason or "Action permitted",
        taint_level=decision.taint_level.value,
        required_level=request.tool_args.get("_required_level", "org_verified"),
        escalation_id=decision.escalation_id,
        timestamp=str(_ledger.entries[-1].timestamp) if _ledger.entries else "unknown",
    )


@router.get("/ledger", response_model=list[AuditEntryView])
async def get_ledger() -> list[AuditEntryView]:
    """Get all audit ledger entries."""
    if not _ledger:
        raise HTTPException(status_code=500, detail="Ledger not initialized")

    entries = []
    for entry in _ledger.entries:
        entries.append(
            AuditEntryView(
                entry_id=entry.entry_id,
                timestamp=entry.timestamp.isoformat(),
                action=entry.action,
                agent_id=entry.agent_id,
                taint_level=entry.taint_level,
                required_level=entry.required_level,
                decision=entry.decision,
                reason=entry.reason,
                lineage_summary=entry.lineage_summary,
                signature_valid=_ledger.verify_entry(entry),
            )
        )

    return entries


@router.get("/ledger/{action}", response_model=list[AuditEntryView])
async def get_ledger_for_action(action: str) -> list[AuditEntryView]:
    """Get audit entries for a specific action."""
    if not _ledger:
        raise HTTPException(status_code=500, detail="Ledger not initialized")

    entries = []
    for entry in _ledger.get_entries_for_action(action):
        entries.append(
            AuditEntryView(
                entry_id=entry.entry_id,
                timestamp=entry.timestamp.isoformat(),
                action=entry.action,
                agent_id=entry.agent_id,
                taint_level=entry.taint_level,
                required_level=entry.required_level,
                decision=entry.decision,
                reason=entry.reason,
                lineage_summary=entry.lineage_summary,
                signature_valid=_ledger.verify_entry(entry),
            )
        )

    return entries


@router.get("/escalations/pending", response_model=list[EscalationTicketView])
async def get_pending_escalations() -> list[EscalationTicketView]:
    """Get all pending escalation tickets."""
    if not _escalation_manager:
        raise HTTPException(status_code=500, detail="Escalation manager not initialized")

    tickets = []
    for ticket in _escalation_manager.get_pending_escalations():
        tickets.append(
            EscalationTicketView(
                ticket_id=ticket.ticket_id,
                status=ticket.status.value,
                created_at=ticket.created_at.isoformat(),
                blocked_action=ticket.blocked_action,
                blocked_reason=ticket.blocked_reason,
                agent_id=ticket.agent_id,
                escalation_id=ticket.ticket_id,
            )
        )

    return tickets


@router.get("/escalations/{ticket_id}", response_model=EscalationTicketView)
async def get_escalation(ticket_id: str) -> EscalationTicketView:
    """Get details of a specific escalation ticket."""
    if not _escalation_manager:
        raise HTTPException(status_code=500, detail="Escalation manager not initialized")

    ticket = _escalation_manager.get_ticket(ticket_id)
    if not ticket:
        raise HTTPException(status_code=404, detail="Escalation ticket not found")

    return EscalationTicketView(
        ticket_id=ticket.ticket_id,
        status=ticket.status.value,
        created_at=ticket.created_at.isoformat(),
        blocked_action=ticket.blocked_action,
        blocked_reason=ticket.blocked_reason,
        agent_id=ticket.agent_id,
        escalation_id=ticket.ticket_id,
        approval_token=ticket.approval_token,
    )


@router.post(
    "/escalations/{ticket_id}/approve",
    response_model=dict,
    dependencies=[Depends(require_api_key)],
)
async def approve_escalation(
    ticket_id: str,
    request: ApproveEscalationRequest,
) -> dict:
    """Approve a blocked action. Requires X-API-Key header."""
    if not _escalation_manager:
        raise HTTPException(status_code=500, detail="Escalation manager not initialized")

    success, token, error = _escalation_manager.approve_escalation(
        ticket_id=ticket_id,
        approved_by=request.approved_by,
        approval_reason=request.approval_reason,
    )

    if not success:
        raise HTTPException(status_code=400, detail=error)

    return {
        "ticket_id": ticket_id,
        "status": "approved",
        "approval_token": token,
        "token_expires_in_minutes": _escalation_manager.approval_token_lifetime_minutes,
    }


@router.get("/ledger/verify")
async def verify_ledger_integrity() -> dict:
    """Verify the integrity of the entire ledger."""
    if not _ledger:
        raise HTTPException(status_code=500, detail="Ledger not initialized")

    is_valid = _ledger.verify_integrity()
    blocked_count = len(_ledger.get_blocked_actions())

    return {
        "integrity_valid": is_valid,
        "total_entries": len(_ledger.entries),
        "blocked_actions": blocked_count,
        "timestamp": str(_ledger.entries[-1].timestamp) if _ledger.entries else None,
    }


@router.get("/policy")
async def get_policy() -> dict:
    """Get the current authorization policy."""
    if not _middleware:
        raise HTTPException(status_code=500, detail="Firewall not initialized")

    return {
        "action_requirements": {
            action: authority.value
            for action, authority in _middleware.engine.action_requirements.items()
        },
        "trust_levels": [level.value for level in Authority],
    }
