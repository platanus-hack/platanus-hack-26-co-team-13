"""Escalation workflow for blocked actions requiring human approval.

When an action is blocked due to insufficient source trust, an escalation
ticket is created for human review. An authorized approver can then approve
the action, which generates a one-time token that "breaks" the taint and
allows the action.
"""

from __future__ import annotations

import json
import secrets
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Optional

from .provenance import ActionAuthorizationDecision
from .schemas import ActorContext


class EscalationStatus(str, Enum):
    """Status of an escalation ticket."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


@dataclass(frozen=True)
class EscalationTicket:
    """A request for human approval of a blocked action."""

    ticket_id: str
    created_at: datetime
    created_by: str  # agent or actor that triggered the escalation
    blocked_action: str  # tool name
    blocked_reason: str  # why it was blocked
    taint_level: str  # actual trust level
    required_level: str  # required trust level
    agent_id: str  # agent requesting the action
    status: EscalationStatus = EscalationStatus.PENDING

    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    approval_reason: Optional[str] = None
    approval_signature: Optional[str] = None

    expires_at: Optional[datetime] = None

    # One-time approval token (only set after approval)
    approval_token: Optional[str] = None
    approval_token_expires_at: Optional[datetime] = None

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        """Check if the ticket has expired."""
        if now is None:
            now = datetime.utcnow()
        if self.expires_at and now > self.expires_at:
            return True
        return False

    def is_token_valid(self, now: Optional[datetime] = None) -> bool:
        """Check if the approval token is still valid."""
        if not self.approval_token:
            return False
        if now is None:
            now = datetime.utcnow()
        if self.approval_token_expires_at and now > self.approval_token_expires_at:
            return False
        return True


@dataclass
class EscalationManager:
    """Manages escalation tickets and approval workflow."""

    tickets: dict[str, EscalationTicket] = field(default_factory=dict)
    approved_tokens: dict[str, EscalationTicket] = field(default_factory=dict)
    max_ticket_lifetime_hours: int = 24
    approval_token_lifetime_minutes: int = 15

    def create_escalation(
        self,
        decision: ActionAuthorizationDecision,
        blocked_action: str,
        agent_id: str,
        created_by: str = "system",
    ) -> EscalationTicket:
        """
        Create an escalation ticket for a blocked action.

        Args:
            decision: The BLOCK decision that triggered escalation
            blocked_action: name of the action that was blocked
            agent_id: agent attempting the action
            created_by: who created the escalation

        Returns:
            EscalationTicket
        """
        ticket_id = f"esc_{uuid.uuid4().hex[:12]}"
        now = datetime.utcnow()
        expires_at = now + timedelta(hours=self.max_ticket_lifetime_hours)

        ticket = EscalationTicket(
            ticket_id=ticket_id,
            created_at=now,
            created_by=created_by,
            blocked_action=blocked_action,
            blocked_reason=decision.reason,
            taint_level=decision.taint_level.value,
            required_level=decision.required_level.value,
            agent_id=agent_id,
            expires_at=expires_at,
        )

        self.tickets[ticket_id] = ticket
        return ticket

    def approve_escalation(
        self,
        ticket_id: str,
        approved_by: str,
        approval_reason: str,
        approval_signature: Optional[str] = None,
    ) -> tuple[bool, Optional[str], Optional[str]]:
        """
        Approve a blocked action.

        Args:
            ticket_id: the escalation ticket ID
            approved_by: approver ID (e.g., "user:admin123")
            approval_reason: why the action is being approved
            approval_signature: optional Ed25519 signature for audit

        Returns:
            tuple of (success: bool, approval_token: str | None, error_msg: str | None)
        """
        if ticket_id not in self.tickets:
            return False, None, "Ticket not found"

        ticket = self.tickets[ticket_id]

        # Check if ticket is still pending
        if ticket.status != EscalationStatus.PENDING:
            return False, None, f"Ticket already {ticket.status.value}"

        # Check if ticket has expired
        if ticket.is_expired():
            self.tickets[ticket_id] = self._update_ticket_status(
                ticket, EscalationStatus.EXPIRED
            )
            return False, None, "Ticket has expired"

        # Generate one-time approval token
        approval_token = secrets.token_urlsafe(32)
        approval_token_expires_at = datetime.utcnow() + timedelta(
            minutes=self.approval_token_lifetime_minutes
        )

        # Update ticket with approval
        updated_ticket = EscalationTicket(
            ticket_id=ticket.ticket_id,
            created_at=ticket.created_at,
            created_by=ticket.created_by,
            blocked_action=ticket.blocked_action,
            blocked_reason=ticket.blocked_reason,
            taint_level=ticket.taint_level,
            required_level=ticket.required_level,
            agent_id=ticket.agent_id,
            status=EscalationStatus.APPROVED,
            approved_by=approved_by,
            approved_at=datetime.utcnow(),
            approval_reason=approval_reason,
            approval_signature=approval_signature,
            expires_at=ticket.expires_at,
            approval_token=approval_token,
            approval_token_expires_at=approval_token_expires_at,
        )

        self.tickets[ticket_id] = updated_ticket
        self.approved_tokens[approval_token] = updated_ticket

        return True, approval_token, None

    def reject_escalation(
        self,
        ticket_id: str,
        rejected_by: str,
        rejection_reason: str,
    ) -> tuple[bool, str]:
        """
        Reject a blocked action request.

        Args:
            ticket_id: the escalation ticket ID
            rejected_by: approver ID
            rejection_reason: why it was rejected

        Returns:
            tuple of (success: bool, error_msg: str)
        """
        if ticket_id not in self.tickets:
            return False, "Ticket not found"

        ticket = self.tickets[ticket_id]

        if ticket.status != EscalationStatus.PENDING:
            return False, f"Ticket already {ticket.status.value}"

        # Mark as rejected
        updated_ticket = EscalationTicket(
            ticket_id=ticket.ticket_id,
            created_at=ticket.created_at,
            created_by=ticket.created_by,
            blocked_action=ticket.blocked_action,
            blocked_reason=ticket.blocked_reason,
            taint_level=ticket.taint_level,
            required_level=ticket.required_level,
            agent_id=ticket.agent_id,
            status=EscalationStatus.REJECTED,
            approved_by=rejected_by,
            approved_at=datetime.utcnow(),
            approval_reason=rejection_reason,
            expires_at=ticket.expires_at,
        )

        self.tickets[ticket_id] = updated_ticket
        return True, ""

    def verify_approval_token(self, token: str) -> Optional[EscalationTicket]:
        """
        Verify an approval token and return the associated ticket.

        Args:
            token: the one-time approval token

        Returns:
            EscalationTicket if valid, None otherwise
        """
        if token not in self.approved_tokens:
            return None

        ticket = self.approved_tokens[token]

        if not ticket.is_token_valid():
            return None

        return ticket

    def get_ticket(self, ticket_id: str) -> Optional[EscalationTicket]:
        """Get a ticket by ID."""
        return self.tickets.get(ticket_id)

    def get_pending_escalations(self) -> list[EscalationTicket]:
        """Get all pending escalation tickets."""
        return [
            t
            for t in self.tickets.values()
            if t.status == EscalationStatus.PENDING and not t.is_expired()
        ]

    def get_escalations_for_agent(self, agent_id: str) -> list[EscalationTicket]:
        """Get all escalations for a specific agent."""
        return [t for t in self.tickets.values() if t.agent_id == agent_id]

    def cleanup_expired(self) -> int:
        """Mark expired tickets as expired and return count."""
        count = 0
        now = datetime.utcnow()
        for ticket_id, ticket in self.tickets.items():
            if (
                ticket.status == EscalationStatus.PENDING
                and ticket.is_expired(now)
            ):
                self.tickets[ticket_id] = self._update_ticket_status(
                    ticket, EscalationStatus.EXPIRED
                )
                count += 1
        return count

    def to_json(self) -> str:
        """Serialize all tickets to JSON."""
        return json.dumps(
            {
                "tickets": {
                    k: asdict(v) for k, v in self.tickets.items()
                },
            },
            default=str,
        )

    @staticmethod
    def _update_ticket_status(
        ticket: EscalationTicket, new_status: EscalationStatus
    ) -> EscalationTicket:
        """Create a new ticket with updated status."""
        return EscalationTicket(
            ticket_id=ticket.ticket_id,
            created_at=ticket.created_at,
            created_by=ticket.created_by,
            blocked_action=ticket.blocked_action,
            blocked_reason=ticket.blocked_reason,
            taint_level=ticket.taint_level,
            required_level=ticket.required_level,
            agent_id=ticket.agent_id,
            status=new_status,
            approved_by=ticket.approved_by,
            approved_at=ticket.approved_at,
            approval_reason=ticket.approval_reason,
            approval_signature=ticket.approval_signature,
            expires_at=ticket.expires_at,
            approval_token=ticket.approval_token,
            approval_token_expires_at=ticket.approval_token_expires_at,
        )
