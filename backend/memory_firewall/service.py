"""Application service that composes analysis, provenance, policy and audit."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from secrets import token_urlsafe

from .analyzer import analyze_memory
from .crypto import canonical_arguments_bytes, canonical_bytes, sign_result
from .intent_judge import (
    Judgement,
    apply_verdict,
    judge_intent,
    semantic_layer_installed,
)
from .policy import (
    ACTION_CONTRACTS,
    AUTHORITY_RANK,
    HIGH_RISK_ACTIONS,
    actions_with_insufficient_authority,
    approver_grant_ceiling,
    authority_for_source,
    evaluate_policy,
    effects_for_action,
    required_authority_for_action,
    required_authority_for_argument,
    validate_action_arguments,
)
from .schemas import (
    ActionEvaluationRequest,
    ActionEvaluationResponse,
    ActorContext,
    ActorType,
    ApprovalInfo,
    ApprovalRequest,
    Authority,
    ClaimEvidenceRef,
    Decision,
    MemoryAnalysisResponse,
    MemoryAnalyzeRequest,
    MemoryCapabilities,
    MemoryDeriveRequest,
    MemoryProvenance,
    MemoryRetrieveRequest,
    MemoryRetrieveResponse,
    MemoryState,
    MemoryThreat,
    ToolCallAuthorizationRequest,
    ToolCallAuthorizationResponse,
)
from .store import AnalysisStore

# Per-memory slice handed to the semantic verifier. Bounded so a long document
# cannot push the real instruction out of the model's attention window.
_JUDGE_CONTENT_CHARS = 2_000
_GRANT_ID = "_mfw_grant_id"
_GRANT_ACTION = "_mfw_grant_action"
_GRANT_SCOPE = "_mfw_grant_scope"
_GRANT_ARGS_HASH = "_mfw_grant_args_hash"


class MemoryFirewallService:
    """Orchestrates deterministic Memory Firewall decisions."""

    def __init__(self, store: AnalysisStore) -> None:
        self.store = store

    @staticmethod
    def _state_for(decision: Decision) -> MemoryState:
        return {
            Decision.ALLOW: MemoryState.ACTIVE,
            Decision.REVIEW: MemoryState.QUARANTINED,
            Decision.BLOCK: MemoryState.BLOCKED,
        }[decision]

    @staticmethod
    def _is_expired(memory: MemoryAnalysisResponse, now: datetime | None = None) -> bool:
        if memory.expires_at is None:
            return False
        now = now or datetime.now(timezone.utc)
        expires_at = memory.expires_at
        if expires_at.tzinfo is None:
            return True
        return expires_at <= now

    @staticmethod
    def _require_tenant(memory: MemoryAnalysisResponse, tenant_id: str) -> None:
        if memory.tenant_id != tenant_id:
            raise LookupError("analysis_not_found")

    @staticmethod
    def _business_claims(memory: MemoryAnalysisResponse) -> dict[str, object]:
        return {
            name: value
            for name, value in memory.claims.items()
            if not name.startswith("_mfw_")
        }

    @staticmethod
    def _claim_authority(memory: MemoryAnalysisResponse, name: str) -> Authority:
        if memory.claim_authorities is not None:
            return memory.claim_authorities.get(name, Authority.UNTRUSTED)
        # Legacy envelopes had one signed authority for every claim.
        return memory.authority

    def analyze(self, request: MemoryAnalyzeRequest) -> MemoryAnalysisResponse:
        """Analyze content and create a sanitized, signed memory envelope."""

        signed_result = self._analyze_result(request)
        self.store.save(signed_result, event_type="WRITE", actor_id=request.actor.id)
        return signed_result

    def analyze_preview(self, request: MemoryAnalyzeRequest) -> MemoryAnalysisResponse:
        """Analyze content without persisting an envelope or ledger event."""

        return self._analyze_result(request)

    def _analyze_result(self, request: MemoryAnalyzeRequest) -> MemoryAnalysisResponse:
        raw_threats, risk_score, sanitized_content = analyze_memory(request.content)
        authority = authority_for_source(request.source)
        policy = evaluate_policy(
            threats=raw_threats,
            authority=authority,
            source=request.source,
            scope=request.scope,
            requested_action=request.requested_action,
        )
        result = MemoryAnalysisResponse(
            analysis_id=f"analysis_{token_urlsafe(12)}",
            decision=policy.decision,
            risk_score=risk_score,
            threats=[MemoryThreat.model_validate(threat) for threat in raw_threats],
            sanitized_content=sanitized_content,
            claims=request.claims,
            claim_authorities={name: authority for name in request.claims},
            claim_evidence={name: [] for name in request.claims},
            reason=policy.reason,
            source=request.source,
            authority=authority,
            capabilities=policy.capabilities,
            provenance=MemoryProvenance(
                origin=request.source,
                authority=authority,
                verified=False,
            ),
            state=self._state_for(policy.decision),
            requested_action=request.requested_action,
            actor=request.actor,
            tenant_id=request.tenant_id,
            created_at=datetime.now(timezone.utc),
        )
        return sign_result(result)

    def get_analysis(
        self, analysis_id: str, tenant_id: str | None = None
    ) -> MemoryAnalysisResponse | None:
        """Retrieve a persisted result, optionally enforcing tenant isolation."""

        result = self.store.get(analysis_id)
        if result is not None and tenant_id is not None:
            self._require_tenant(result, tenant_id)
        return result

    def retrieve(self, request: MemoryRetrieveRequest) -> MemoryRetrieveResponse:
        """Verify and retrieve a signed envelope while auditing the session hop."""

        memory = self.store.get(request.analysis_id)
        if memory is None:
            raise LookupError("analysis_not_found")
        self._require_tenant(memory, request.tenant_id)
        payload = {
            "analysis_id": memory.analysis_id,
            "content_hash": memory.content_hash,
            "session_id": request.session_id,
            "actor": request.actor.model_dump(mode="json"),
        }
        event = self.store.append_event(
            event_type="RETRIEVE",
            object_id=memory.analysis_id,
            actor_id=request.actor.id,
            tenant_id=request.tenant_id,
            payload_hash=hashlib.sha256(canonical_bytes(payload)).hexdigest(),
        )
        return MemoryRetrieveResponse(
            memory=memory,
            retrieval_event=event,
            integrity_verified=True,
            session_id=request.session_id,
        )

    def derive(self, request: MemoryDeriveRequest) -> MemoryAnalysisResponse:
        """Create a signed derivative whose authority/capabilities cannot increase."""

        parents: list[MemoryAnalysisResponse] = []
        for parent_id in request.parent_analysis_ids:
            parent = self.store.get(parent_id)
            if parent is None:
                raise LookupError("parent_analysis_not_found")
            self._require_tenant(parent, request.tenant_id)
            parents.append(parent)

        raw_threats, risk_score, sanitized_content = analyze_memory(request.content)
        child_policy = evaluate_policy(
            threats=raw_threats,
            authority=Authority.UNTRUSTED,
            source="derived",
            scope=request.scope,
            requested_action=None,
        )
        derived_authority = min(
            (parent.authority for parent in parents), key=lambda value: AUTHORITY_RANK[value]
        )
        common_actions = set(parents[0].capabilities.allowed_actions)
        common_scopes = set(parents[0].capabilities.allowed_scopes)
        for parent in parents[1:]:
            common_actions.intersection_update(parent.capabilities.allowed_actions)
            common_scopes.intersection_update(parent.capabilities.allowed_scopes)

        parent_not_usable = any(
            parent.state != MemoryState.ACTIVE
            or parent.decision != Decision.ALLOW
            or self._is_expired(parent)
            for parent in parents
        )
        decision = child_policy.decision
        reason = child_policy.reason
        if parent_not_usable and decision == Decision.ALLOW:
            decision = Decision.REVIEW
            reason = "Derived memory inherits quarantine from an inactive, unapproved, or expired parent."
        capabilities = MemoryCapabilities(
            allowed_actions=sorted(common_actions),
            allowed_scopes=sorted(common_scopes),
            requires_approval=(child_policy.capabilities.requires_approval or parent_not_usable),
            usable_for_action=False,
        )
        derived_claims: dict[str, object] = {}
        derived_claim_authorities: dict[str, Authority] = {}
        derived_claim_evidence: dict[str, list[ClaimEvidenceRef]] = {}
        claim_names = {
            name
            for parent in parents
            for name in self._business_claims(parent)
        }
        for name in claim_names:
            sources = [parent for parent in parents if name in self._business_claims(parent)]
            values = [parent.claims[name] for parent in sources]
            if not all(
                canonical_bytes({"value": value})
                == canonical_bytes({"value": values[0]})
                for value in values[1:]
            ):
                continue
            derived_claims[name] = values[0]
            derived_claim_authorities[name] = min(
                (self._claim_authority(parent, name) for parent in sources),
                key=lambda authority: AUTHORITY_RANK[authority],
            )
            derived_claim_evidence[name] = [
                ClaimEvidenceRef(analysis_id=parent.analysis_id, claim_name=name)
                for parent in sources
            ]

        result = MemoryAnalysisResponse(
            analysis_id=f"analysis_{token_urlsafe(12)}",
            decision=decision,
            risk_score=risk_score,
            threats=[MemoryThreat.model_validate(threat) for threat in raw_threats],
            sanitized_content=sanitized_content,
            claims=derived_claims,
            claim_authorities=derived_claim_authorities,
            claim_evidence=derived_claim_evidence,
            reason=reason,
            source="derived",
            authority=derived_authority,
            capabilities=capabilities,
            provenance=MemoryProvenance(
                origin="derived",
                authority=derived_authority,
                verified=False,
                parent_analysis_ids=request.parent_analysis_ids,
                transformation=request.transformation,
            ),
            state=self._state_for(decision),
            actor=request.actor,
            tenant_id=request.tenant_id,
            created_at=datetime.now(timezone.utc),
        )
        signed_result = sign_result(result)
        self.store.save(signed_result, event_type="DERIVE", actor_id=request.actor.id)
        return signed_result

    def approve(self, request: ApprovalRequest) -> MemoryAnalysisResponse:
        """Create an immutable, explicitly authorized successor envelope."""

        ceiling = approver_grant_ceiling(request.approver_id)
        if ceiling is None:
            raise PermissionError("approver_not_authorized")
        if AUTHORITY_RANK[request.requested_new_authority] > AUTHORITY_RANK[ceiling]:
            raise ValueError("requested authority exceeds approver ceiling")
        if request.expires_at.tzinfo is None or request.expires_at <= datetime.now(timezone.utc):
            raise ValueError("expires_at must be a future timezone-aware timestamp")
        insufficient_actions = actions_with_insufficient_authority(
            request.allowed_actions, request.requested_new_authority
        )
        if insufficient_actions:
            raise ValueError(
                "approved authority is insufficient for actions: " + ", ".join(insufficient_actions)
            )
        original = self.store.get(request.analysis_id)
        if original is None:
            raise LookupError("analysis_not_found")
        self._require_tenant(original, request.tenant_id)
        if original.state == MemoryState.BLOCKED:
            raise ValueError("blocked memories cannot be elevated")
        if self._is_expired(original):
            raise ValueError("expired memories cannot be elevated")
        if AUTHORITY_RANK[request.requested_new_authority] <= AUTHORITY_RANK[original.authority]:
            raise ValueError("requested authority must exceed existing authority")
        approval_sources = [original]
        for analysis_id in request.evidence_analysis_ids:
            if analysis_id == original.analysis_id:
                continue
            evidence = self.store.get(analysis_id)
            if evidence is None:
                raise LookupError("analysis_not_found")
            self._require_tenant(evidence, request.tenant_id)
            if evidence.state == MemoryState.BLOCKED or self._is_expired(evidence):
                raise ValueError("approval evidence must be live and non-blocked")
            approval_sources.append(evidence)

        high_risk_actions = [
            action for action in request.allowed_actions if action in HIGH_RISK_ACTIONS
        ]
        if len(high_risk_actions) > 1:
            raise ValueError("one high-risk action must be approved at a time")

        approved_claims = dict(original.claims)
        approved_claim_authorities = (
            dict(original.claim_authorities)
            if original.claim_authorities is not None
            else {
                name: original.authority
                for name in self._business_claims(original)
            }
        )
        approved_claim_evidence = (
            dict(original.claim_evidence)
            if original.claim_evidence is not None
            else {name: [] for name in self._business_claims(original)}
        )
        grant: tuple[str, str, str] | None = None
        arguments = request.approved_arguments
        argument_actions = [
            action
            for action in request.allowed_actions
            if (contract := ACTION_CONTRACTS.get(action)) is not None
            and contract.arguments
        ]
        if high_risk_actions and arguments is None:
            raise ValueError("high-risk approval requires exact approved_arguments")
        if arguments is not None:
            if len(argument_actions) != 1:
                raise ValueError(
                    "approved_arguments require exactly one argument-bearing action"
                )
            action = argument_actions[0]
            violations = validate_action_arguments(action, arguments)
            if violations:
                raise ValueError(" ".join(violations))
            evidence_by_claim: dict[str, list[MemoryAnalysisResponse]] = {}
            for name, value in arguments.items():
                matching_sources = [
                    source
                    for source in approval_sources
                    if name in source.claims
                    and canonical_bytes({"value": source.claims[name]})
                    == canonical_bytes({"value": value})
                ]
                if not matching_sources:
                    raise ValueError(f"approved argument is not bound to signed claim: {name}")
                evidence_by_claim[name] = matching_sources
            selected_authorities = request.approved_argument_authorities or {
                name: request.requested_new_authority for name in arguments
            }
            for name, authority in selected_authorities.items():
                required = required_authority_for_argument(action, name)
                if AUTHORITY_RANK[authority] < AUTHORITY_RANK[required]:
                    raise ValueError(
                        f"approved authority for {name} is below {required.value}"
                    )
                if AUTHORITY_RANK[authority] > AUTHORITY_RANK[ceiling]:
                    raise ValueError(
                        f"approved authority for {name} exceeds approver ceiling"
                    )
            approved_claims = dict(arguments)
            approved_claim_authorities = {
                name: selected_authorities[name] for name in arguments
            }
            approved_claim_evidence = {
                name: [
                    ClaimEvidenceRef(
                        analysis_id=source.analysis_id,
                        claim_name=name,
                    )
                    for source in evidence_by_claim[name]
                ]
                for name in arguments
            }
            if action in HIGH_RISK_ACTIONS:
                args_hash = hashlib.sha256(canonical_arguments_bytes(arguments)).hexdigest()
                grant_id = f"grant_{token_urlsafe(12)}"
                approved_claims.update(
                    {
                        _GRANT_ID: grant_id,
                        _GRANT_ACTION: action,
                        _GRANT_SCOPE: request.scope,
                        _GRANT_ARGS_HASH: args_hash,
                    }
                )
                grant = (grant_id, action, args_hash)
        else:
            business_claims = self._business_claims(original)
            approved_claim_authorities = {
                name: request.requested_new_authority for name in business_claims
            }
            approved_claim_evidence = {
                name: [
                    ClaimEvidenceRef(
                        analysis_id=original.analysis_id,
                        claim_name=name,
                    )
                ]
                for name in business_claims
            }

        actor_type = request.approver_id.split(":", 1)[0]
        try:
            approval_actor = ActorContext(id=request.approver_id, type=ActorType(actor_type))
        except ValueError:
            approval_actor = ActorContext(id=request.approver_id, type=ActorType.USER)
        approved_at = datetime.now(timezone.utc)
        elevated = original.model_copy(
            update={
                "analysis_id": f"analysis_{token_urlsafe(12)}",
                "decision": Decision.ALLOW,
                "reason": "Explicitly elevated by an authorized approver within a scoped TTL.",
                "authority": request.requested_new_authority,
                "claims": approved_claims,
                "claim_authorities": approved_claim_authorities,
                "claim_evidence": approved_claim_evidence,
                "capabilities": MemoryCapabilities(
                    allowed_actions=request.allowed_actions,
                    allowed_scopes=[request.scope],
                    requires_approval=False,
                    usable_for_action=True,
                ),
                "provenance": original.provenance.model_copy(
                    update={
                        "authority": request.requested_new_authority,
                        "parent_analysis_ids": [
                            source.analysis_id for source in approval_sources
                        ],
                        "transformation": "authority_elevation",
                    }
                ),
                "state": MemoryState.ACTIVE,
                "actor": approval_actor,
                "version": original.version + 1,
                "supersedes_analysis_id": original.analysis_id,
                "expires_at": request.expires_at,
                "approval": ApprovalInfo(
                    approved_by=request.approver_id,
                    reason=request.reason,
                    approved_at=approved_at,
                ),
                "created_at": approved_at,
                "content_hash": "",
                "signature": "",
            }
        )
        signed_elevated = sign_result(elevated)
        if grant is not None:
            grant_id, action, args_hash = grant
            self.store.register_high_risk_grant(
                grant_id=grant_id,
                analysis_id=signed_elevated.analysis_id,
                tenant_id=request.tenant_id,
                action=action,
                scope=request.scope,
                args_hash=args_hash,
                expires_at=int(request.expires_at.timestamp()),
            )
        # Register first: an orphan grant cannot authorize anything, whereas a
        # persisted envelope without its grant could expose low-risk capabilities
        # after an API operation that reported failure.
        self.store.save(
            signed_elevated,
            event_type="AUTHORITY_ELEVATION",
            actor_id=request.approver_id,
        )
        return signed_elevated

    def _has_exact_high_risk_grant(
        self,
        memory: MemoryAnalysisResponse,
        request: ActionEvaluationRequest,
        args_hash: str,
    ) -> bool:
        grant_id = memory.claims.get(_GRANT_ID)
        if not isinstance(grant_id, str):
            return False
        if (
            memory.claims.get(_GRANT_ACTION) != request.action
            or memory.claims.get(_GRANT_SCOPE) != request.scope
            or memory.claims.get(_GRANT_ARGS_HASH) != args_hash
        ):
            return False
        return self.store.high_risk_grant_available(
            grant_id=grant_id,
            analysis_id=memory.analysis_id,
            tenant_id=request.tenant_id,
            action=request.action,
            scope=request.scope,
            args_hash=args_hash,
        )

    def _evaluate_action(
        self,
        request: ActionEvaluationRequest,
        argument_authorities: dict[str, Authority] | None = None,
    ) -> ActionEvaluationResponse:
        memories: list[MemoryAnalysisResponse] = []
        for analysis_id in request.analysis_ids:
            memory = self.store.get(analysis_id)
            if memory is None:
                raise LookupError("analysis_not_found")
            self._require_tenant(memory, request.tenant_id)
            memories.append(memory)

        required_authority = required_authority_for_action(request.action)
        effects = effects_for_action(request.action)
        action_known = request.action in ACTION_CONTRACTS
        high_risk = request.action in HIGH_RISK_ACTIONS
        argument_reasons: list[str] = []
        args_hash: str | None = None
        if not action_known:
            argument_reasons.append(f"Unknown action {request.action} is not registered.")
        else:
            contract_arguments = request.arguments or {}
            if request.arguments is None and ACTION_CONTRACTS[request.action].required_arguments:
                argument_reasons.append(
                    "Action requires exact structured arguments."
                )
            else:
                argument_reasons.extend(
                    validate_action_arguments(request.action, contract_arguments)
                )
                if high_risk and not argument_reasons:
                    args_hash = hashlib.sha256(
                        canonical_arguments_bytes(contract_arguments)
                    ).hexdigest()
        envelope_authority = min(
            (memory.authority for memory in memories), key=lambda value: AUTHORITY_RANK[value]
        )
        if argument_authorities is None and request.arguments is not None:
            argument_authorities = {}
            for name, value in request.arguments.items():
                matching = [
                    self._claim_authority(memory, name)
                    for memory in memories
                    if name in memory.claims
                    and canonical_bytes({"value": memory.claims[name]})
                    == canonical_bytes({"value": value})
                ]
                argument_authorities[name] = (
                    min(matching, key=lambda authority: AUTHORITY_RANK[authority])
                    if matching
                    else Authority.UNTRUSTED
                )
        argument_authorities = argument_authorities or {}
        if action_known:
            for name, authority in argument_authorities.items():
                required = required_authority_for_argument(request.action, name)
                if AUTHORITY_RANK[authority] < AUTHORITY_RANK[required]:
                    argument_reasons.append(
                        f"Argument {name} requires {required.value} authority; received {authority.value}."
                    )
        provided_authority = (
            min(
                argument_authorities.values(),
                key=lambda authority: AUTHORITY_RANK[authority],
            )
            if argument_authorities
            else envelope_authority
        )
        provided_capabilities = set(memories[0].capabilities.allowed_actions)
        for memory in memories[1:]:
            provided_capabilities.intersection_update(memory.capabilities.allowed_actions)

        usable_memory_ids: list[str] = []
        blocked_memory_ids: list[str] = []
        reasons: list[str] = []
        scope_valid = True
        expired_memory_ids: list[str] = []
        for memory in memories:
            memory_scope_valid = request.scope in memory.capabilities.allowed_scopes
            expired = self._is_expired(memory)
            if expired:
                expired_memory_ids.append(memory.analysis_id)
            scope_valid = scope_valid and memory_scope_valid
            usable = (
                action_known
                and not argument_reasons
                and memory.state == MemoryState.ACTIVE
                and memory.decision == Decision.ALLOW
                and not expired
                and AUTHORITY_RANK[memory.authority] >= AUTHORITY_RANK[required_authority]
                and request.action in memory.capabilities.allowed_actions
                and memory_scope_valid
                and not memory.capabilities.requires_approval
                and memory.capabilities.usable_for_action
                and (
                    not high_risk
                    or (
                        args_hash is not None
                        and self._has_exact_high_risk_grant(memory, request, args_hash)
                    )
                )
            )
            (usable_memory_ids if usable else blocked_memory_ids).append(memory.analysis_id)

        if blocked_memory_ids:
            reasons.extend(argument_reasons)
            if high_risk and not argument_reasons:
                reasons.append(
                    "Every referenced memory requires a live, exact, unconsumed high-risk grant."
                )
            if expired_memory_ids:
                reasons.append("Memory approval expired: " + ", ".join(expired_memory_ids) + ".")
            if not scope_valid:
                reasons.append("Requested scope is not allowed by every memory.")
            if request.action not in provided_capabilities:
                reasons.append(f"Required capability {request.action} is missing.")
            if AUTHORITY_RANK[provided_authority] < AUTHORITY_RANK[required_authority]:
                reasons.append(
                    f"Required authority is {required_authority.value}; received {provided_authority.value}."
                )
            if any(memory.state != MemoryState.ACTIVE for memory in memories):
                reasons.append("At least one memory is not active.")
            if not reasons:
                reasons.append("At least one memory requires approval before this action.")
            decision = Decision.BLOCK
        else:
            reasons.append("All memories satisfy authority, capability, scope, TTL, and state checks.")
            decision = Decision.ALLOW

        semantic_judgement: str | None = None
        semantic_reason: str | None = None
        semantic_model: str | None = None

        # Deterministic authority, exact arguments, scope, TTL, and grant state
        # have already allowed the call. The optional semantic layer runs only
        # here and may tighten that outcome; it can never create authority.
        if (
            decision == Decision.ALLOW
            and ACTION_CONTRACTS[request.action].semantic_review
            and semantic_layer_installed()
        ):
            verdict = judge_intent(
                content="\n\n".join(
                    memory.sanitized_content[:_JUDGE_CONTENT_CHARS] for memory in memories
                ),
                action=request.action,
                scope=request.scope,
                authority=provided_authority,
                question=request.justification,
            )
            semantic_judgement = verdict.judgement.value
            semantic_reason = verdict.reason
            semantic_model = verdict.model

            if verdict.judgement is Judgement.UNAVAILABLE:
                # The signed exact grant is authoritative. The optional model
                # can tighten a decision when present, but availability is not
                # part of the deterministic security boundary.
                reasons.append(
                    "Semantic verification was unavailable; deterministic authorization remains authoritative."
                )
            elif verdict.escalates:
                decision = apply_verdict(decision, verdict)
                reasons.append(f"Semantic verification: {verdict.reason}")
            else:
                reasons.append("Semantic verification found no conflicting intent.")

        response = ActionEvaluationResponse(
            decision=decision,
            action=request.action,
            effects=effects,
            scope=request.scope,
            required_authority=required_authority,
            provided_authority=provided_authority,
            argument_authorities=argument_authorities,
            required_capability=request.action,
            provided_capabilities=sorted(provided_capabilities),
            usable_memory_ids=usable_memory_ids,
            blocked_memory_ids=blocked_memory_ids,
            scope_valid=scope_valid,
            reasons=reasons,
            semantic_judgement=semantic_judgement,
            semantic_reason=semantic_reason,
            semantic_model=semantic_model,
        )
        return response

    def evaluate_action(self, request: ActionEvaluationRequest) -> ActionEvaluationResponse:
        """Evaluate evidence without issuing an execution-grade authorization."""

        response = self._evaluate_action(request)
        if request.action in HIGH_RISK_ACTIONS and response.decision == Decision.ALLOW:
            response = response.model_copy(
                update={
                    "decision": Decision.REVIEW,
                    "reasons": [
                        *response.reasons,
                        "High-risk execution requires the one-shot tool-call authorization endpoint.",
                    ],
                }
            )
        self.store.append_event(
            event_type="ACTION_DECISION",
            object_id=f"action_{token_urlsafe(12)}",
            actor_id=request.actor.id,
            tenant_id=request.tenant_id,
            payload_hash=hashlib.sha256(canonical_bytes(response.model_dump(mode="json"))).hexdigest(),
            decision=response.decision.value,
        )
        return response

    def _verify_ancestry(
        self,
        analysis_ids: list[str],
        tenant_id: str,
    ) -> list[str]:
        """Recursively verify every ancestor without allowing cycles or runaway depth."""

        ancestors: list[str] = []
        expanded: set[str] = set()
        active: set[str] = set()
        referenced = set(analysis_ids)

        def visit(analysis_id: str, depth: int) -> None:
            if depth > 32:
                raise ValueError("provenance_lineage_too_deep")
            if analysis_id in active:
                raise ValueError("provenance_cycle_detected")
            if analysis_id in expanded:
                return
            memory = self.store.get(analysis_id)
            if memory is None:
                raise LookupError("analysis_not_found")
            self._require_tenant(memory, tenant_id)
            active.add(analysis_id)
            for parent_id in memory.provenance.parent_analysis_ids:
                if parent_id not in referenced and parent_id not in ancestors:
                    ancestors.append(parent_id)
                visit(parent_id, depth + 1)
            for claim_name, references in (memory.claim_evidence or {}).items():
                for reference in references:
                    if reference.analysis_id not in memory.provenance.parent_analysis_ids:
                        raise ValueError("claim_evidence_not_in_parent_lineage")
                    parent = self.store.get(reference.analysis_id)
                    if parent is None:
                        raise LookupError("analysis_not_found")
                    self._require_tenant(parent, tenant_id)
                    if (
                        reference.claim_name not in parent.claims
                        or claim_name not in memory.claims
                        or canonical_bytes({"value": parent.claims[reference.claim_name]})
                        != canonical_bytes({"value": memory.claims[claim_name]})
                    ):
                        raise ValueError("claim_evidence_value_mismatch")
            active.remove(analysis_id)
            expanded.add(analysis_id)

        for analysis_id in analysis_ids:
            visit(analysis_id, 0)
        return ancestors

    def authorize_tool_call(
        self, request: ToolCallAuthorizationRequest
    ) -> ToolCallAuthorizationResponse:
        """Authorize a native agent tool event using signed memory evidence only."""

        argument_names = set(request.tool.arguments)
        lineage_names = set(request.argument_lineage)
        if argument_names != lineage_names:
            raise ValueError("every_tool_argument_requires_lineage")

        argument_authorities: dict[str, Authority] = {}
        for argument, value in request.tool.arguments.items():
            evidence = []
            for analysis_id in request.argument_lineage[argument]:
                memory = self.store.get(analysis_id)
                if memory is None or memory.tenant_id != request.tenant_id:
                    raise ValueError(f"argument_evidence_invalid:{argument}")
                if (
                    argument not in memory.claims
                    or canonical_bytes({"value": memory.claims[argument]})
                    != canonical_bytes({"value": value})
                ):
                    raise ValueError(f"argument_value_not_bound:{argument}")
                evidence.append(memory)
            argument_authorities[argument] = min(
                (self._claim_authority(memory, argument) for memory in evidence),
                key=lambda authority: AUTHORITY_RANK[authority],
            )

        referenced_ids = list(
            dict.fromkeys(
                analysis_id
                for analysis_ids in request.argument_lineage.values()
                for analysis_id in analysis_ids
            )
        )
        ancestors = self._verify_ancestry(referenced_ids, request.tenant_id)
        action_request = ActionEvaluationRequest(
            analysis_ids=referenced_ids,
            action=request.tool.name,
            scope=request.scope,
            actor=request.actor,
            tenant_id=request.tenant_id,
            justification=request.justification,
            arguments=request.tool.arguments,
        )
        evaluation = self._evaluate_action(action_request, argument_authorities)
        if evaluation.decision == Decision.ALLOW and request.tool.name in HIGH_RISK_ACTIONS:
            grant_ids = [
                memory.claims[_GRANT_ID]
                for analysis_id in referenced_ids
                if (memory := self.store.get(analysis_id)) is not None
                and isinstance(memory.claims.get(_GRANT_ID), str)
            ]
            if not self.store.consume_high_risk_grants(
                grant_ids=grant_ids,
                tenant_id=request.tenant_id,
                request_id=request.request_id,
            ):
                evaluation = evaluation.model_copy(
                    update={
                        "decision": Decision.BLOCK,
                        "reasons": [
                            *evaluation.reasons,
                            "High-risk authorization grant is missing, expired, or already consumed.",
                        ],
                    }
                )
        action_id = f"action_{token_urlsafe(12)}"
        args_hash = hashlib.sha256(
            canonical_arguments_bytes(request.tool.arguments)
        ).hexdigest()
        decision_payload = {
            "schema_version": request.schema_version,
            "request_id": request.request_id,
            "action_id": action_id,
            "runtime": request.runtime.model_dump(mode="json"),
            "session": request.session.model_dump(mode="json"),
            "tool_name": request.tool.name,
            "args_hash": args_hash,
            "argument_lineage": request.argument_lineage,
            "referenced_analysis_ids": referenced_ids,
            "ancestor_analysis_ids": ancestors,
            "evaluation": evaluation.model_dump(mode="json"),
        }
        event = self.store.append_event(
            event_type="TOOL_DECISION",
            object_id=action_id,
            actor_id=request.actor.id,
            tenant_id=request.tenant_id,
            payload_hash=hashlib.sha256(canonical_bytes(decision_payload)).hexdigest(),
            decision=evaluation.decision.value,
        )
        return ToolCallAuthorizationResponse(
            request_id=request.request_id,
            action_id=action_id,
            decision=evaluation.decision,
            tool_name=request.tool.name,
            effects=evaluation.effects,
            session_id=request.session.id,
            args_hash=args_hash,
            argument_lineage=request.argument_lineage,
            referenced_analysis_ids=referenced_ids,
            ancestor_analysis_ids=ancestors,
            required_authority=evaluation.required_authority,
            provided_authority=evaluation.provided_authority,
            argument_authorities=evaluation.argument_authorities,
            required_capability=evaluation.required_capability,
            provided_capabilities=evaluation.provided_capabilities,
            reason=" ".join(evaluation.reasons),
            reasons=evaluation.reasons,
            audit_event_id=event.event_id,
            semantic_judgement=evaluation.semantic_judgement,
            semantic_reason=evaluation.semantic_reason,
            semantic_model=evaluation.semantic_model,
        )
