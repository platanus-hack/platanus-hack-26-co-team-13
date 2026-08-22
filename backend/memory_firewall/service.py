"""Application service that composes analysis, provenance and policy."""

from __future__ import annotations

from datetime import datetime, timezone
from secrets import token_urlsafe

from .analyzer import analyze_memory
from .crypto import sign_result
from .policy import (
    AUTHORITY_RANK,
    authority_for_source,
    evaluate_policy,
    required_authority_for_action,
)
from .schemas import (
    MemoryAnalysisResponse,
    MemoryAnalyzeRequest,
    ActionEvaluationRequest,
    ActionEvaluationResponse,
    Authority,
    Decision,
    MemoryCapabilities,
    MemoryDeriveRequest,
    MemoryProvenance,
    MemoryState,
    MemoryThreat,
)
from .store import AnalysisStore


class MemoryFirewallService:
    """Orchestrates the deterministic Memory Firewall MVP."""

    def __init__(self, store: AnalysisStore) -> None:
        self.store = store

    def analyze(self, request: MemoryAnalyzeRequest) -> MemoryAnalysisResponse:
        """Analyze content and create a sanitized, retrievable result."""

        raw_threats, risk_score, sanitized_content = analyze_memory(request.content)
        authority = authority_for_source(request.source)
        policy = evaluate_policy(
            threats=raw_threats,
            authority=authority,
            source=request.source,
            scope=request.scope,
            requested_action=request.requested_action,
        )
        analysis_id = f"analysis_{token_urlsafe(12)}"
        created_at = datetime.now(timezone.utc)
        state = {
            Decision.ALLOW: MemoryState.ACTIVE,
            Decision.REVIEW: MemoryState.QUARANTINED,
            Decision.BLOCK: MemoryState.BLOCKED,
        }[policy.decision]

        result = MemoryAnalysisResponse(
            analysis_id=analysis_id,
            decision=policy.decision,
            risk_score=risk_score,
            threats=[MemoryThreat.model_validate(threat) for threat in raw_threats],
            sanitized_content=sanitized_content,
            reason=policy.reason,
            source=request.source,
            authority=authority,
            capabilities=policy.capabilities,
            provenance=MemoryProvenance(
                origin=request.source,
                authority=authority,
                verified=False,
            ),
            state=state,
            requested_action=request.requested_action,
            created_at=created_at,
        )
        signed_result = sign_result(result)
        self.store.save(signed_result)
        return signed_result

    def get_analysis(self, analysis_id: str) -> MemoryAnalysisResponse | None:
        """Retrieve a previously persisted result."""

        return self.store.get(analysis_id)

    def derive(self, request: MemoryDeriveRequest) -> MemoryAnalysisResponse:
        """Create a derived result without allowing authority escalation."""

        parents: list[MemoryAnalysisResponse] = []
        for parent_id in request.parent_analysis_ids:
            parent = self.store.get(parent_id)
            if parent is None:
                raise LookupError("parent_analysis_not_found")
            parents.append(parent)

        child = self.analyze(
            MemoryAnalyzeRequest(
                content=request.content,
                source="derived",
                scope=request.scope,
            )
        )

        derived_authority = min(
            (parent.authority for parent in parents),
            key=lambda authority: AUTHORITY_RANK[authority],
        )
        common_actions = set(parents[0].capabilities.allowed_actions)
        common_scopes = set(parents[0].capabilities.allowed_scopes)
        for parent in parents[1:]:
            common_actions.intersection_update(parent.capabilities.allowed_actions)
            common_scopes.intersection_update(parent.capabilities.allowed_scopes)

        parent_is_untrusted = any(
            parent.state != MemoryState.ACTIVE or parent.decision != Decision.ALLOW
            for parent in parents
        )
        decision = child.decision
        reason = child.reason
        if parent_is_untrusted and decision == Decision.ALLOW:
            decision = Decision.REVIEW
            reason = "Derived memory inherits quarantine from at least one parent."

        derived_state = {
            Decision.ALLOW: MemoryState.ACTIVE,
            Decision.REVIEW: MemoryState.QUARANTINED,
            Decision.BLOCK: MemoryState.BLOCKED,
        }[decision]
        derived_capabilities = MemoryCapabilities(
            allowed_actions=sorted(common_actions),
            allowed_scopes=sorted(common_scopes),
            requires_approval=(child.capabilities.requires_approval or parent_is_untrusted),
            usable_for_action=False,
        )
        derived = child.model_copy(
            update={
                "decision": decision,
                "reason": reason,
                "authority": derived_authority,
                "capabilities": derived_capabilities,
                "state": derived_state,
                "provenance": child.provenance.model_copy(
                    update={
                        "origin": "derived",
                        "authority": derived_authority,
                        "parent_analysis_ids": request.parent_analysis_ids,
                        "transformation": request.transformation,
                    }
                ),
            }
        )
        signed_derived = sign_result(derived)
        self.store.save(signed_derived)
        return signed_derived

    def evaluate_action(self, request: ActionEvaluationRequest) -> ActionEvaluationResponse:
        """Check whether the supplied memories may influence an action."""

        memories: list[MemoryAnalysisResponse] = []
        for analysis_id in request.analysis_ids:
            memory = self.store.get(analysis_id)
            if memory is None:
                raise LookupError("analysis_not_found")
            memories.append(memory)

        required_authority = required_authority_for_action(request.action)
        provided_authority = min(
            (memory.authority for memory in memories),
            key=lambda authority: AUTHORITY_RANK[authority],
        )
        provided_capabilities = set(memories[0].capabilities.allowed_actions)
        for memory in memories[1:]:
            provided_capabilities.intersection_update(memory.capabilities.allowed_actions)

        usable_memory_ids: list[str] = []
        blocked_memory_ids: list[str] = []
        reasons: list[str] = []
        scope_valid = True
        for memory in memories:
            memory_scope_valid = request.scope in memory.capabilities.allowed_scopes
            scope_valid = scope_valid and memory_scope_valid
            usable = (
                memory.state == MemoryState.ACTIVE
                and memory.decision == Decision.ALLOW
                and AUTHORITY_RANK[memory.authority] >= AUTHORITY_RANK[required_authority]
                and request.action in memory.capabilities.allowed_actions
                and memory_scope_valid
                and not memory.capabilities.requires_approval
            )
            if usable:
                usable_memory_ids.append(memory.analysis_id)
            else:
                blocked_memory_ids.append(memory.analysis_id)

        if blocked_memory_ids:
            if not scope_valid:
                reasons.append("Requested scope is not allowed by every memory.")
            if request.action not in provided_capabilities:
                reasons.append(f"Required capability {request.action} is missing.")
            if AUTHORITY_RANK[provided_authority] < AUTHORITY_RANK[required_authority]:
                reasons.append(
                    f"Required authority is {required_authority.value}; "
                    f"received {provided_authority.value}."
                )
            if any(memory.state != MemoryState.ACTIVE for memory in memories):
                reasons.append("At least one memory is not active.")
            if not reasons:
                reasons.append("At least one memory requires approval before this action.")
            decision = Decision.BLOCK
        else:
            reasons.append("All memories satisfy authority, capability, scope, and state checks.")
            decision = Decision.ALLOW

        return ActionEvaluationResponse(
            decision=decision,
            action=request.action,
            scope=request.scope,
            required_authority=required_authority,
            provided_authority=provided_authority,
            required_capability=request.action,
            provided_capabilities=sorted(provided_capabilities),
            usable_memory_ids=usable_memory_ids,
            blocked_memory_ids=blocked_memory_ids,
            scope_valid=scope_valid,
            reasons=reasons,
        )
