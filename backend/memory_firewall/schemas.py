"""Public domain schemas for memory analysis and policy decisions."""

from __future__ import annotations

import json
import re
import unicodedata
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class Decision(str, Enum):
    """Decision returned by the memory policy engine."""

    ALLOW = "allow"
    REVIEW = "review"
    BLOCK = "block"


class Severity(str, Enum):
    """Severity assigned to a detected memory threat."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class MemoryState(str, Enum):
    """Operational state of an analyzed memory record."""

    ACTIVE = "active"
    QUARANTINED = "quarantined"
    BLOCKED = "blocked"
    EXPIRED = "expired"


class Authority(str, Enum):
    """Discrete authority levels; quarantine is an operational state, not one."""

    UNTRUSTED = "untrusted"
    OBSERVED = "observed"
    USER_CONFIRMED = "user_confirmed"
    ORG_VERIFIED = "org_verified"
    SYSTEM_AUTHORITY = "system_authority"


class ClaimEvidenceRef(BaseModel):
    """Signed reference to the exact parent claim supporting a claim value."""

    model_config = ConfigDict(extra="forbid")

    analysis_id: str = Field(min_length=1, max_length=64)
    claim_name: str = Field(min_length=1, max_length=64)

    @field_validator("analysis_id")
    @classmethod
    def validate_analysis_id(cls, value: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", value):
            raise ValueError("claim evidence contains an invalid analysis id")
        return value

    @field_validator("claim_name")
    @classmethod
    def validate_claim_name(cls, value: str) -> str:
        if (
            not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.:-]{0,63}", value)
            or value.startswith("_mfw_")
        ):
            raise ValueError("claim evidence contains an invalid claim name")
        return value


class ActorType(str, Enum):
    """Actor classes registered on every operation (FR-001)."""

    USER = "user"
    AGENT = "agent"
    TOOL = "tool"
    SYSTEM = "system"
    EXTERNAL_SOURCE = "external_source"


class ActorContext(BaseModel):
    """Identity of the actor performing an operation."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=64)
    type: ActorType

    @field_validator("id")
    @classmethod
    def validate_actor_id(cls, value: str) -> str:
        normalized = unicodedata.normalize("NFKC", value).strip().lower()
        if not re.fullmatch(r"[a-z0-9_.:-]+", normalized):
            raise ValueError("actor id must contain only lowercase letters, numbers, _, ., :, or -")
        return normalized


class ApprovalInfo(BaseModel):
    """Signed evidence of the explicit elevation that produced an envelope."""

    model_config = ConfigDict(extra="forbid")

    approved_by: str = Field(min_length=1, max_length=64)
    reason: str = Field(min_length=1, max_length=500)
    approved_at: datetime


class MemoryCapabilities(BaseModel):
    """Actions and scopes a memory is allowed to influence."""

    model_config = ConfigDict(extra="forbid")

    allowed_actions: list[str] = Field(default_factory=lambda: ["READ"], max_length=16)
    allowed_scopes: list[str] = Field(default_factory=lambda: ["user_memory"], max_length=16)
    requires_approval: bool = False
    usable_for_action: bool = False

    @field_validator("allowed_actions")
    @classmethod
    def validate_actions(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        for value in values:
            token = value.strip().upper()
            if not token or len(token) > 64 or not re.fullmatch(r"[A-Za-z0-9_.:-]+", token):
                raise ValueError("capability tokens must contain only letters, numbers, _, ., :, or -")
            if token not in normalized:
                normalized.append(token)
        return normalized

    @field_validator("allowed_scopes")
    @classmethod
    def validate_scopes(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        for value in values:
            token = value.strip().lower()
            if not token or len(token) > 64 or not re.fullmatch(r"[A-Za-z0-9_.:-]+", token):
                raise ValueError("capability tokens must contain only letters, numbers, _, ., :, or -")
            if token not in normalized:
                normalized.append(token)
        return normalized


class MemoryThreat(BaseModel):
    """A threat found in memory content without echoing the original payload."""

    model_config = ConfigDict(extra="forbid")

    type: str = Field(min_length=1, max_length=64)
    severity: Severity
    line: int = Field(ge=1)
    description: str = Field(min_length=1, max_length=500)
    confidence: float = Field(ge=0.0, le=1.0)
    indicator: str = Field(min_length=1, max_length=160)


class MemoryProvenance(BaseModel):
    """Source metadata returned with an analysis result."""

    model_config = ConfigDict(extra="forbid")

    origin: str = Field(min_length=1, max_length=64)
    authority: Authority
    verified: bool = False
    parent_analysis_ids: list[str] = Field(default_factory=list, max_length=16)
    transformation: str | None = Field(default=None, max_length=64)


class MemoryAnalyzeRequest(BaseModel):
    """Input accepted by the memory firewall analysis endpoint."""

    model_config = ConfigDict(extra="forbid")

    content: str = Field(min_length=1, max_length=50_000)
    source: str = Field(default="unknown", min_length=1, max_length=64)
    metadata: dict[str, Any] = Field(default_factory=dict)
    claims: dict[str, Any] = Field(default_factory=dict, max_length=32)
    scope: str = Field(default="user_memory", min_length=1, max_length=64)
    requested_action: str | None = Field(default=None, max_length=64)
    actor: ActorContext
    tenant_id: str = Field(default="default", min_length=1, max_length=64)

    @field_validator("content")
    @classmethod
    def normalize_and_validate_content(cls, value: str) -> str:
        normalized = unicodedata.normalize("NFKC", value)
        for character in normalized:
            codepoint = ord(character)
            if codepoint == 0 or (codepoint < 32 and character not in "\n\r\t"):
                raise ValueError("content contains unsupported control characters")
        return normalized

    @field_validator("source", "scope", "tenant_id")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        normalized = unicodedata.normalize("NFKC", value).strip().lower()
        if not re.fullmatch(r"[a-z0-9_.:-]+", normalized):
            raise ValueError("must contain only lowercase letters, numbers, _, ., :, or -")
        return normalized

    @field_validator("requested_action")
    @classmethod
    def validate_action(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip().upper()
        if not re.fullmatch(r"[A-Z0-9_.:-]+", normalized):
            raise ValueError("requested_action contains unsupported characters")
        return normalized

    @field_validator("metadata")
    @classmethod
    def bound_metadata(cls, value: dict[str, Any]) -> dict[str, Any]:
        if len(value) > 20:
            raise ValueError("metadata cannot contain more than 20 keys")
        try:
            serialized = json.dumps(value, ensure_ascii=False, default=str)
        except (TypeError, ValueError) as exc:
            raise ValueError("metadata must be JSON serializable") from exc
        if len(serialized.encode("utf-8")) > 8_192:
            raise ValueError("metadata is too large")
        return value

    @field_validator("claims")
    @classmethod
    def bound_claims(cls, value: dict[str, Any]) -> dict[str, Any]:
        for name in value:
            if (
                not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.:-]{0,63}", name)
                or name.startswith("_mfw_")
            ):
                raise ValueError("claims contains an invalid argument name")
        try:
            serialized = json.dumps(value, ensure_ascii=False, sort_keys=True)
        except (TypeError, ValueError) as exc:
            raise ValueError("claims must be JSON serializable") from exc
        if len(serialized.encode("utf-8")) > 32_768:
            raise ValueError("claims are too large")
        return value


class MemoryDeriveRequest(BaseModel):
    """Request to create a memory derived from previously analyzed memories."""

    model_config = ConfigDict(extra="forbid")

    content: str = Field(min_length=1, max_length=50_000)
    parent_analysis_ids: list[str] = Field(min_length=1, max_length=16)
    transformation: str = Field(default="summarize", min_length=1, max_length=64)
    scope: str = Field(default="user_memory", min_length=1, max_length=64)
    actor: ActorContext
    tenant_id: str = Field(default="default", min_length=1, max_length=64)

    @field_validator("content")
    @classmethod
    def normalize_and_validate_content(cls, value: str) -> str:
        normalized = unicodedata.normalize("NFKC", value)
        for character in normalized:
            codepoint = ord(character)
            if codepoint == 0 or (codepoint < 32 and character not in "\n\r\t"):
                raise ValueError("content contains unsupported control characters")
        return normalized

    @field_validator("parent_analysis_ids")
    @classmethod
    def validate_parent_ids(cls, values: list[str]) -> list[str]:
        for value in values:
            if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", value):
                raise ValueError("parent_analysis_ids contain an invalid identifier")
        return list(dict.fromkeys(values))

    @field_validator("transformation")
    @classmethod
    def validate_transformation(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not re.fullmatch(r"[a-z0-9_.:-]+", normalized):
            raise ValueError("transformation contains unsupported characters")
        return normalized

    @field_validator("scope", "tenant_id")
    @classmethod
    def validate_scope(cls, value: str) -> str:
        normalized = unicodedata.normalize("NFKC", value).strip().lower()
        if not re.fullmatch(r"[a-z0-9_.:-]+", normalized):
            raise ValueError("scope must contain only lowercase letters, numbers, _, ., :, or -")
        return normalized


class ActionEvaluationRequest(BaseModel):
    """Request to evaluate whether memories may influence an action."""

    model_config = ConfigDict(extra="forbid")

    analysis_ids: list[str] = Field(min_length=1, max_length=16)
    action: str = Field(min_length=1, max_length=64)
    scope: str = Field(default="user_memory", min_length=1, max_length=64)
    actor: ActorContext
    tenant_id: str = Field(default="default", min_length=1, max_length=64)
    # Operator-supplied purpose. Context for the semantic layer only; it carries
    # no authority and can never by itself unlock an action.
    justification: str | None = Field(default=None, max_length=500)
    arguments: dict[str, Any] | None = Field(default=None, max_length=32)

    @field_validator("analysis_ids")
    @classmethod
    def validate_analysis_ids(cls, values: list[str]) -> list[str]:
        for value in values:
            if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", value):
                raise ValueError("analysis_ids contain an invalid identifier")
        return list(dict.fromkeys(values))

    @field_validator("action")
    @classmethod
    def normalize_action(cls, value: str) -> str:
        normalized = value.strip().upper()
        if not re.fullmatch(r"[A-Z0-9_.:-]+", normalized):
            raise ValueError("action contains unsupported characters")
        return normalized

    @field_validator("scope", "tenant_id")
    @classmethod
    def normalize_scope(cls, value: str) -> str:
        normalized = unicodedata.normalize("NFKC", value).strip().lower()
        if not re.fullmatch(r"[a-z0-9_.:-]+", normalized):
            raise ValueError("scope must contain only lowercase letters, numbers, _, ., :, or -")
        return normalized

    @field_validator("arguments")
    @classmethod
    def bound_arguments(cls, value: dict[str, Any] | None) -> dict[str, Any] | None:
        if value is None:
            return None
        for name in value:
            if (
                not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.:-]{0,63}", name)
                or name.startswith("_mfw_")
            ):
                raise ValueError("arguments contains an invalid argument name")
        serialized = json.dumps(value, ensure_ascii=False, sort_keys=True)
        if len(serialized.encode("utf-8")) > 32_768:
            raise ValueError("action arguments are too large")
        return value


class MemoryRetrieveRequest(BaseModel):
    """Audited retrieval of a signed memory in a new agent session."""

    model_config = ConfigDict(extra="forbid")

    analysis_id: str = Field(min_length=1, max_length=64)
    session_id: str = Field(min_length=1, max_length=128)
    actor: ActorContext
    tenant_id: str = Field(default="default", min_length=1, max_length=64)

    @field_validator("analysis_id")
    @classmethod
    def validate_analysis_id(cls, value: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", value):
            raise ValueError("analysis_id contains an invalid identifier")
        return value

    @field_validator("session_id", "tenant_id")
    @classmethod
    def validate_context_id(cls, value: str) -> str:
        normalized = unicodedata.normalize("NFKC", value).strip().lower()
        if not re.fullmatch(r"[a-z0-9_.:-]+", normalized):
            raise ValueError("context identifiers contain unsupported characters")
        return normalized


class ToolRuntime(BaseModel):
    """Agent runtime that produced a native pre-tool event."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=32)
    adapter_version: str = Field(min_length=1, max_length=32)

    @field_validator("name", "adapter_version")
    @classmethod
    def validate_token(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not re.fullmatch(r"[a-z0-9_.:-]+", normalized):
            raise ValueError("runtime fields contain unsupported characters")
        return normalized


class ToolSession(BaseModel):
    """Opaque correlation identifiers supplied by an agent host."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=128)
    turn_id: str | None = Field(default=None, max_length=128)
    tool_call_id: str | None = Field(default=None, max_length=128)

    @field_validator("id", "turn_id", "tool_call_id")
    @classmethod
    def validate_identifier(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = unicodedata.normalize("NFKC", value).strip().lower()
        if not re.fullmatch(r"[a-z0-9_.:-]+", normalized):
            raise ValueError("session identifiers contain unsupported characters")
        return normalized


class ToolDescriptor(BaseModel):
    """Tool name and the exact arguments pending execution."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=64)
    arguments: dict[str, Any] = Field(max_length=32)

    @field_validator("name")
    @classmethod
    def normalize_name(cls, value: str) -> str:
        normalized = value.strip().upper()
        if not re.fullmatch(r"[A-Z0-9_.:-]+", normalized):
            raise ValueError("tool name contains unsupported characters")
        return normalized

    @field_validator("arguments")
    @classmethod
    def bound_arguments(cls, value: dict[str, Any]) -> dict[str, Any]:
        for name in value:
            if (
                not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.:-]{0,63}", name)
                or name.startswith("_mfw_")
            ):
                raise ValueError("tool arguments contain an invalid argument name")
        serialized = json.dumps(value, ensure_ascii=False, sort_keys=True)
        if len(serialized.encode("utf-8")) > 32_768:
            raise ValueError("tool arguments are too large")
        return value


class ToolCallAuthorizationRequest(BaseModel):
    """Common protocol used by every native agent adapter."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = Field(pattern=r"^memory-firewall\.tool-call\.v1$")
    request_id: str = Field(min_length=1, max_length=128)
    runtime: ToolRuntime
    session: ToolSession
    tool: ToolDescriptor
    argument_lineage: dict[str, list[str]] = Field(min_length=1, max_length=32)
    scope: str = Field(min_length=1, max_length=64)
    actor: ActorContext
    tenant_id: str = Field(default="default", min_length=1, max_length=64)
    # Why the agent believes this call is warranted. Context for the semantic
    # layer only; it carries no authority.
    justification: str | None = Field(default=None, max_length=500)

    @field_validator("request_id", "scope", "tenant_id")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        normalized = unicodedata.normalize("NFKC", value).strip().lower()
        if not re.fullmatch(r"[a-z0-9_.:-]+", normalized):
            raise ValueError("request identifiers contain unsupported characters")
        return normalized

    @field_validator("argument_lineage")
    @classmethod
    def validate_argument_lineage(
        cls, value: dict[str, list[str]]
    ) -> dict[str, list[str]]:
        normalized: dict[str, list[str]] = {}
        for argument, analysis_ids in value.items():
            if (
                not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.:-]{0,63}", argument)
                or argument.startswith("_mfw_")
            ):
                raise ValueError("argument_lineage contains an invalid argument name")
            if not analysis_ids or len(analysis_ids) > 16:
                raise ValueError("every argument requires one to sixteen evidence ids")
            for analysis_id in analysis_ids:
                if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", analysis_id):
                    raise ValueError("argument_lineage contains an invalid analysis id")
            normalized[argument] = list(dict.fromkeys(analysis_ids))
        return normalized


class ApprovalRequest(BaseModel):
    """Explicit authority elevation signed by an authorized principal (FR-024)."""

    model_config = ConfigDict(extra="forbid")

    analysis_id: str = Field(min_length=1, max_length=64)
    evidence_analysis_ids: list[str] = Field(default_factory=list, max_length=15)
    approver_id: str = Field(min_length=1, max_length=64)
    requested_new_authority: Authority
    allowed_actions: list[str] = Field(min_length=1, max_length=16)
    scope: str = Field(min_length=1, max_length=64)
    reason: str = Field(min_length=1, max_length=500)
    expires_at: datetime
    tenant_id: str = Field(default="default", min_length=1, max_length=64)
    # Four signed grant metadata claims are added to the resulting envelope.
    approved_arguments: dict[str, Any] | None = Field(default=None, max_length=28)
    approved_argument_authorities: dict[str, Authority] | None = Field(
        default=None, max_length=28
    )

    @field_validator("analysis_id")
    @classmethod
    def validate_analysis_id(cls, value: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", value):
            raise ValueError("analysis_id contains an invalid identifier")
        return value

    @field_validator("evidence_analysis_ids")
    @classmethod
    def validate_evidence_analysis_ids(cls, values: list[str]) -> list[str]:
        for value in values:
            if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", value):
                raise ValueError("evidence_analysis_ids contain an invalid identifier")
        return list(dict.fromkeys(values))

    @field_validator("approver_id")
    @classmethod
    def validate_approver_id(cls, value: str) -> str:
        normalized = unicodedata.normalize("NFKC", value).strip().lower()
        if not re.fullmatch(r"[a-z0-9_.:-]+", normalized):
            raise ValueError("approver_id must contain only lowercase letters, numbers, _, ., :, or -")
        return normalized

    @field_validator("allowed_actions")
    @classmethod
    def validate_allowed_actions(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        for value in values:
            token = value.strip().upper()
            if not token or len(token) > 64 or not re.fullmatch(r"[A-Za-z0-9_.:-]+", token):
                raise ValueError("capability tokens must contain only letters, numbers, _, ., :, or -")
            if token not in normalized:
                normalized.append(token)
        return normalized

    @field_validator("scope", "tenant_id")
    @classmethod
    def validate_scope(cls, value: str) -> str:
        normalized = unicodedata.normalize("NFKC", value).strip().lower()
        if not re.fullmatch(r"[a-z0-9_.:-]+", normalized):
            raise ValueError("scope must contain only lowercase letters, numbers, _, ., :, or -")
        return normalized

    @field_validator("approved_arguments")
    @classmethod
    def bound_approved_arguments(
        cls, value: dict[str, Any] | None
    ) -> dict[str, Any] | None:
        if value is None:
            return None
        for name in value:
            if (
                not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.:-]{0,63}", name)
                or name.startswith("_mfw_")
            ):
                raise ValueError("approved_arguments contains an invalid argument name")
        serialized = json.dumps(value, ensure_ascii=False, sort_keys=True)
        if len(serialized.encode("utf-8")) > 32_768:
            raise ValueError("approved_arguments are too large")
        return value

    @model_validator(mode="after")
    def validate_argument_authority_keys(self) -> "ApprovalRequest":
        if self.approved_argument_authorities is not None:
            if self.approved_arguments is None:
                raise ValueError(
                    "approved_argument_authorities require approved_arguments"
                )
            if set(self.approved_argument_authorities) != set(self.approved_arguments):
                raise ValueError(
                    "approved_argument_authorities must cover every approved argument"
                )
        return self


class MemoryAnalysisResponse(BaseModel):
    """Stable API response persisted by the analysis store."""

    model_config = ConfigDict(extra="forbid")

    analysis_id: str = Field(min_length=1, max_length=64)
    decision: Decision
    risk_score: float = Field(ge=0.0, le=1.0)
    threats: list[MemoryThreat] = Field(default_factory=list, max_length=100)
    sanitized_content: str = Field(max_length=50_000)
    claims: dict[str, Any] = Field(default_factory=dict, max_length=32)
    # ``None`` identifies legacy envelopes. New envelopes carry server-issued,
    # signed authority and evidence for each business claim.
    claim_authorities: dict[str, Authority] | None = Field(default=None, max_length=32)
    claim_evidence: dict[str, list[ClaimEvidenceRef]] | None = Field(
        default=None, max_length=32
    )
    reason: str = Field(min_length=1, max_length=500)
    source: str = Field(min_length=1, max_length=64)
    authority: Authority
    capabilities: MemoryCapabilities
    provenance: MemoryProvenance
    state: MemoryState = MemoryState.ACTIVE
    content_hash: str = Field(default="", max_length=128)
    key_id: str = Field(default="", max_length=128)
    signature: str = Field(default="", max_length=256)
    requested_action: str | None = Field(default=None, max_length=64)
    actor: ActorContext | None = None
    tenant_id: str | None = None
    version: int = Field(default=1, ge=1)
    supersedes_analysis_id: str | None = Field(default=None, max_length=64)
    expires_at: datetime | None = None
    approval: ApprovalInfo | None = None
    created_at: datetime

    @model_validator(mode="after")
    def validate_claim_security_metadata(self) -> "MemoryAnalysisResponse":
        business_claims = {
            name for name in self.claims if not name.startswith("_mfw_")
        }
        if self.claim_authorities is not None:
            if set(self.claim_authorities) != business_claims:
                raise ValueError("claim_authorities must cover every business claim")
        if self.claim_evidence is not None:
            if set(self.claim_evidence) != business_claims:
                raise ValueError("claim_evidence must cover every business claim")
            if any(len(refs) > 16 for refs in self.claim_evidence.values()):
                raise ValueError("a claim cannot reference more than sixteen evidence claims")
        return self


class ActionEvaluationResponse(BaseModel):
    """Explainable result of the memory-to-action authorization check."""

    model_config = ConfigDict(extra="forbid")

    decision: Decision
    action: str
    effects: list[str] = Field(default_factory=list, max_length=16)
    scope: str
    required_authority: Authority
    provided_authority: Authority | None = None
    argument_authorities: dict[str, Authority] = Field(default_factory=dict, max_length=32)
    required_capability: str
    provided_capabilities: list[str] = Field(default_factory=list)
    usable_memory_ids: list[str] = Field(default_factory=list)
    blocked_memory_ids: list[str] = Field(default_factory=list)
    scope_valid: bool
    reasons: list[str] = Field(default_factory=list, max_length=16)
    # Semantic backstop. ``None`` means the layer never ran, which is the case
    # whenever the deterministic rules already settled the outcome.
    semantic_judgement: str | None = Field(default=None, max_length=32)
    semantic_reason: str | None = Field(default=None, max_length=300)
    semantic_model: str | None = Field(default=None, max_length=64)


class MemoryRetrieveResponse(BaseModel):
    """Verified memory and the signed event proving its retrieval."""

    model_config = ConfigDict(extra="forbid")

    memory: MemoryAnalysisResponse
    retrieval_event: "LedgerEventView"
    integrity_verified: bool
    session_id: str


class ToolCallAuthorizationResponse(BaseModel):
    """Deterministic decision returned to native agent hooks."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = "memory-firewall.tool-call.v1"
    request_id: str
    action_id: str
    decision: Decision
    tool_name: str
    effects: list[str] = Field(default_factory=list, max_length=16)
    session_id: str
    args_hash: str
    argument_lineage: dict[str, list[str]]
    referenced_analysis_ids: list[str]
    ancestor_analysis_ids: list[str]
    required_authority: Authority
    provided_authority: Authority | None = None
    argument_authorities: dict[str, Authority] = Field(default_factory=dict, max_length=32)
    required_capability: str
    provided_capabilities: list[str] = Field(default_factory=list)
    reason: str
    reasons: list[str] = Field(default_factory=list, max_length=16)
    audit_event_id: str
    # Mirrors ActionEvaluationResponse; ``None`` means the semantic layer never
    # ran because the deterministic rules already settled the outcome.
    semantic_judgement: str | None = Field(default=None, max_length=32)
    semantic_reason: str | None = Field(default=None, max_length=300)
    semantic_model: str | None = Field(default=None, max_length=64)


class DemoToolExecutionResponse(BaseModel):
    """Evidence that the synthetic demo callable was gated, not merely evaluated."""

    model_config = ConfigDict(extra="forbid")

    authorization: ToolCallAuthorizationResponse
    executed: bool
    function_invocations: int = Field(ge=0, le=1)


class RuntimeAdapterStatus(BaseModel):
    """Source-distribution status for one supported native adapter."""

    model_config = ConfigDict(extra="forbid")

    name: str
    hook: str
    language: str
    status: str
    install_command: str


class RuntimeStatusResponse(BaseModel):
    """Truthful runtime capabilities displayed by the control plane."""

    model_config = ConfigDict(extra="forbid")

    service: str
    core_status: str
    memory_store: str
    execution_boundary: str
    cli_install_command: str
    adapters: list[RuntimeAdapterStatus]
    live_connections: list[str] = Field(default_factory=list)


class RuntimeHeartbeatRequest(BaseModel):
    """Short-lived proof that a native runtime loaded its adapter."""

    model_config = ConfigDict(extra="forbid")

    runtime: ToolRuntime
    session: ToolSession


class RuntimeBlockEventRequest(BaseModel):
    """Fail-closed decision made by an adapter before core authorization."""

    model_config = ConfigDict(extra="forbid")

    runtime: ToolRuntime
    session: ToolSession
    tool_name: str = Field(min_length=1, max_length=128)
    reason: str = Field(min_length=1, max_length=256)
    actor: ActorContext
    tenant_id: str = Field(default="default", min_length=1, max_length=128)


class ViewerLoginRequest(BaseModel):
    """Credentials for the local protected-activity viewer."""

    model_config = ConfigDict(extra="forbid")

    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=256)


class ViewerRegistrationRequest(BaseModel):
    """Credentials selected by a new control-plane user."""

    model_config = ConfigDict(extra="forbid")

    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=12, max_length=256)


class ViewerSessionResponse(BaseModel):
    """Authenticated control-plane identity and the workspace it owns.

    ``workspace_key`` is the plaintext agent credential. It is populated only
    by registration -- the server keeps just its sha256 digest, so login and
    session lookups return ``None`` and the key can never be re-read.
    """

    model_config = ConfigDict(extra="forbid")

    authenticated: bool
    email: str
    workspace_id: str = Field(min_length=1, max_length=64)
    expires_in_seconds: int = Field(ge=0)
    workspace_key: str | None = None


class WorkspaceKeyResponse(BaseModel):
    """A freshly minted agent workspace key, shown exactly once."""

    model_config = ConfigDict(extra="forbid")

    workspace_key: str = Field(min_length=1, max_length=256)
    workspace_id: str = Field(min_length=1, max_length=64)


class WorkspaceStatsResponse(BaseModel):
    """Aggregated ledger activity for the caller's own workspace only."""

    model_config = ConfigDict(extra="forbid")

    workspace_id: str = Field(min_length=1, max_length=64)
    total_events: int = Field(ge=0)
    blocked_actions: int = Field(ge=0)
    allowed_actions: int = Field(ge=0)
    memories_written: int = Field(ge=0)
    last_event_at: str | None = None


def _reject_control_characters(value: str) -> str:
    """Normalize to NFKC and reject control characters except \\n, \\r, \\t."""

    normalized = unicodedata.normalize("NFKC", value)
    for character in normalized:
        codepoint = ord(character)
        if codepoint == 0 or (codepoint < 32 and character not in "\n\r\t"):
            raise ValueError("field contains unsupported control characters")
    return normalized


class DemoEmailRequest(BaseModel):
    """Synthetic inbound email injected into the caller's own workspace."""

    model_config = ConfigDict(extra="forbid")

    sender: str = Field(min_length=1, max_length=120)
    subject: str = Field(min_length=1, max_length=200)
    body: str = Field(min_length=1, max_length=5_000)
    # Simulates a compromised internal account: the message arrives already
    # carrying the authority a high-risk action requires, so the authority gate
    # cannot be what stops it. Demo-only, and scoped to the caller's workspace.
    from_verified_account: bool = False

    @field_validator("sender", "subject", "body")
    @classmethod
    def normalize_text(cls, value: str) -> str:
        normalized = _reject_control_characters(value)
        if not normalized.strip():
            raise ValueError("field cannot be blank")
        return normalized


class DemoEmailResponse(BaseModel):
    """Firewall verdict for an ingested synthetic email."""

    model_config = ConfigDict(extra="forbid")

    message_id: str = Field(min_length=1, max_length=64)
    decision: Decision
    risk_score: float = Field(ge=0.0, le=1.0)
    authority: Authority
    state: MemoryState
    threats: list[MemoryThreat] = Field(default_factory=list, max_length=100)
    reason: str = Field(min_length=1, max_length=500)
    sanitized_preview: str = Field(max_length=400)
    created_at: datetime


class DemoAgentAskRequest(BaseModel):
    """Question posed to the demo agent about a stored workspace message."""

    model_config = ConfigDict(extra="forbid")

    message_id: str = Field(min_length=1, max_length=64)
    question: str = Field(min_length=1, max_length=500)

    @field_validator("message_id")
    @classmethod
    def validate_message_id(cls, value: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", value):
            raise ValueError("message_id contains an invalid identifier")
        return value

    @field_validator("question")
    @classmethod
    def normalize_question(cls, value: str) -> str:
        normalized = _reject_control_characters(value)
        if not normalized.strip():
            raise ValueError("question cannot be blank")
        return normalized


class DemoAgentStep(BaseModel):
    """One auditable hop of the write -> derive -> retrieve -> tool trace."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=32)
    label: str = Field(min_length=1, max_length=200)
    status: str = Field(pattern=r"^(ok|quarantined|blocked)$")
    detail: str = Field(min_length=1, max_length=500)
    event_type: str = Field(min_length=1, max_length=32)
    analysis_id: str = Field(min_length=1, max_length=64)
    authority: Authority


class DemoAgentAskResponse(BaseModel):
    """Deterministic end-to-end trace proving the action was gated."""

    model_config = ConfigDict(extra="forbid")

    question: str
    inferred_action: str = Field(min_length=1, max_length=64)
    agent_answer: str = Field(min_length=1, max_length=1_000)
    decision: Decision
    executed: bool
    function_invocations: int = Field(ge=0)
    steps: list[DemoAgentStep] = Field(default_factory=list, max_length=8)
    # Populated only when the semantic layer actually ran, which happens after
    # the deterministic rules found nothing to object to.
    semantic_judgement: str | None = Field(default=None, max_length=32)
    semantic_reason: str | None = Field(default=None, max_length=300)
    semantic_model: str | None = Field(default=None, max_length=64)
    answer_source: str = Field(default="deterministic", max_length=32)


class LedgerEventView(BaseModel):
    """Read model of a hash-chained, signed ledger event."""

    model_config = ConfigDict(extra="forbid")

    seq: int = Field(ge=1)
    event_id: str = Field(min_length=1, max_length=64)
    event_type: str = Field(min_length=1, max_length=32)
    object_id: str = Field(min_length=1, max_length=64)
    actor_id: str = Field(min_length=1, max_length=64)
    tenant_id: str = Field(min_length=1, max_length=64)
    payload_hash: str = Field(min_length=64, max_length=64)
    previous_hash: str = Field(min_length=64, max_length=64)
    event_hash: str = Field(min_length=64, max_length=64)
    signature: str = Field(min_length=1, max_length=256)
    created_at: datetime


class PublicLedgerEventView(BaseModel):
    """Signed public projection that does not reveal reusable internal IDs."""

    model_config = ConfigDict(extra="forbid")

    seq: int = Field(ge=1)
    event_id: str = Field(min_length=1, max_length=64)
    event_type: str = Field(min_length=1, max_length=32)
    object_ref: str = Field(min_length=1, max_length=64)
    actor_ref: str = Field(min_length=1, max_length=64)
    tenant_id: str = Field(min_length=1, max_length=64)
    source_event_hash: str = Field(min_length=64, max_length=64)
    projection_signature: str = Field(min_length=1, max_length=256)
    created_at: datetime


class LedgerVerifyResponse(BaseModel):
    """Result of recomputing the append-only hash chain (Appendix A.7)."""

    model_config = ConfigDict(extra="forbid")

    valid: bool
    events_checked: int = Field(ge=0)
    first_invalid_event: int | None = None
