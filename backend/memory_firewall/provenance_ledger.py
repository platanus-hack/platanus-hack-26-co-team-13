"""Append-only audit ledger for provenance-based authorization decisions.

Every authorization decision is logged, signed with Ed25519, and stored in
an immutable chain. This provides evidence for compliance, debugging, and
escalation workflows.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Optional

from . import crypto as crypto_module
from .provenance import ActionAuthorizationDecision, SourceMetadata
from .schemas import Decision


class Ed25519Handler:
    """Wrapper around crypto module functions for ledger signing."""

    def sign(self, data: bytes) -> str:
        """Sign data and return base64-encoded signature."""
        payload = {"data": data.hex()}
        return crypto_module.sign_ledger_event(payload)

    def verify(self, data: bytes, signature_b64: str) -> bool:
        """Verify a signature."""
        payload = {"data": data.hex()}
        return crypto_module.verify_ledger_event(payload, signature_b64)


@dataclass(frozen=True)
class ProvenanceAuditEntry:
    """A single entry in the provenance audit ledger."""

    entry_id: str  # unique identifier (UUID or sequence number)
    timestamp: datetime
    action: str  # tool name
    agent_id: str  # agent that made the request
    taint_level: str  # authority level of data
    required_level: str  # authority level required
    decision: str  # ALLOW/BLOCK/REVIEW
    reason: str
    lineage_summary: str  # human-readable source chain
    signature: Optional[str] = None  # Ed25519 signature
    previous_entry_hash: Optional[str] = None  # for chain integrity


@dataclass
class ProvenanceLedger:
    """Append-only ledger for authorization decisions."""

    entries: list[ProvenanceAuditEntry]
    crypto_handler: Ed25519Handler
    entry_counter: int = 0

    def append(
        self,
        decision: ActionAuthorizationDecision,
        agent_id: str,
        action_name: str,
    ) -> ProvenanceAuditEntry:
        """
        Append a new authorization decision to the ledger.

        Args:
            decision: ActionAuthorizationDecision to log
            agent_id: identifier of the agent
            action_name: name of the tool/action

        Returns:
            ProvenanceAuditEntry with signature
        """
        import hashlib
        import uuid

        self.entry_counter += 1

        # Generate entry ID
        entry_id = f"prov_{uuid.uuid4().hex[:16]}"

        # Compute previous entry hash (for chain integrity)
        previous_hash = None
        if self.entries:
            last_entry = self.entries[-1]
            # Hash the last entry's essential fields
            last_data = f"{last_entry.entry_id}:{last_entry.timestamp}:{last_entry.decision}"
            previous_hash = hashlib.sha256(last_data.encode()).hexdigest()[:16]

        # Create lineage summary
        lineage_summary = self._summarize_lineage(decision.lineage)

        # Create the entry (unsigned)
        entry = ProvenanceAuditEntry(
            entry_id=entry_id,
            timestamp=decision.timestamp or datetime.utcnow(),
            action=action_name,
            agent_id=agent_id,
            taint_level=decision.taint_level.value,
            required_level=decision.required_level.value,
            decision=decision.verdict.value,
            reason=decision.reason,
            lineage_summary=lineage_summary,
            previous_entry_hash=previous_hash,
        )

        # Sign the entry
        entry_data = self._entry_to_bytes(entry)
        signature = self.crypto_handler.sign(entry_data)

        # Create signed entry
        signed_entry = ProvenanceAuditEntry(
            entry_id=entry.entry_id,
            timestamp=entry.timestamp,
            action=entry.action,
            agent_id=entry.agent_id,
            taint_level=entry.taint_level,
            required_level=entry.required_level,
            decision=entry.decision,
            reason=entry.reason,
            lineage_summary=entry.lineage_summary,
            signature=signature,
            previous_entry_hash=entry.previous_entry_hash,
        )

        self.entries.append(signed_entry)
        return signed_entry

    def verify_entry(self, entry: ProvenanceAuditEntry) -> bool:
        """
        Verify an entry's signature.

        Args:
            entry: ProvenanceAuditEntry to verify

        Returns:
            True if signature is valid, False otherwise
        """
        if not entry.signature:
            return False

        # Recreate the entry without signature
        unsigned_entry = ProvenanceAuditEntry(
            entry_id=entry.entry_id,
            timestamp=entry.timestamp,
            action=entry.action,
            agent_id=entry.agent_id,
            taint_level=entry.taint_level,
            required_level=entry.required_level,
            decision=entry.decision,
            reason=entry.reason,
            lineage_summary=entry.lineage_summary,
            signature=None,
            previous_entry_hash=entry.previous_entry_hash,
        )

        entry_data = self._entry_to_bytes(unsigned_entry)
        return self.crypto_handler.verify(entry_data, entry.signature)

    def verify_integrity(self) -> bool:
        """
        Verify the ledger's chain integrity (all entries signed + chain hashes).

        Returns:
            True if all entries are valid and chain is intact
        """
        import hashlib

        for i, entry in enumerate(self.entries):
            # Verify signature
            if not self.verify_entry(entry):
                return False

            # Verify chain hash (if not first entry)
            if i > 0:
                prev_entry = self.entries[i - 1]
                expected_prev_hash = hashlib.sha256(
                    f"{prev_entry.entry_id}:{prev_entry.timestamp}:{prev_entry.decision}".encode()
                ).hexdigest()[:16]

                if entry.previous_entry_hash != expected_prev_hash:
                    return False

        return True

    def get_entries_for_action(self, action: str) -> list[ProvenanceAuditEntry]:
        """Get all ledger entries for a specific action."""
        return [e for e in self.entries if e.action == action]

    def get_entries_for_agent(self, agent_id: str) -> list[ProvenanceAuditEntry]:
        """Get all ledger entries for a specific agent."""
        return [e for e in self.entries if e.agent_id == agent_id]

    def get_blocked_actions(self) -> list[ProvenanceAuditEntry]:
        """Get all BLOCK decisions."""
        return [e for e in self.entries if e.decision == Decision.BLOCK.value]

    def to_json(self) -> str:
        """Serialize ledger to JSON."""
        return json.dumps(
            [asdict(e) for e in self.entries],
            default=str,  # handle datetime serialization
        )

    @staticmethod
    def _summarize_lineage(lineage) -> str:
        """Create a human-readable summary of the taint lineage."""
        sources = [lineage.primary_source.source_type.value]
        for secondary in lineage.secondary_sources:
            sources.append(secondary.source_type.value)

        return " -> ".join(sources)

    @staticmethod
    def _entry_to_bytes(entry: ProvenanceAuditEntry) -> bytes:
        """Convert entry to bytes for signing/verification."""
        data = (
            f"{entry.entry_id}:"
            f"{entry.timestamp.isoformat()}:"
            f"{entry.action}:"
            f"{entry.agent_id}:"
            f"{entry.taint_level}:"
            f"{entry.required_level}:"
            f"{entry.decision}:"
            f"{entry.reason}:"
            f"{entry.previous_entry_hash or 'null'}"
        )
        return data.encode("utf-8")
