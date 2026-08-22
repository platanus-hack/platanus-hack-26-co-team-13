"""Public domain schemas for memory analysis and policy decisions."""

from __future__ import annotations

import json
import re
import unicodedata
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


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


class ApprovalRequest(BaseModel):
    """Explicit authority elevation signed by an authorized principal (FR-024)."""

    model_config = ConfigDict(extra="forbid")

    analysis_id: str = Field(min_length=1, max_length=64)
    approver_id: str = Field(min_length=1, max_length=64)
    requested_new_authority: Authority
    allowed_actions: list[str] = Field(min_length=1, max_length=16)
    scope: str = Field(min_length=1, max_length=64)
    reason: str = Field(min_length=1, max_length=500)
    expires_at: datetime
    tenant_id: str = Field(default="default", min_length=1, max_length=64)

    @field_validator("analysis_id")
    @classmethod
    def validate_analysis_id(cls, value: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", value):
            raise ValueError("analysis_id contains an invalid identifier")
        return value

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


class MemoryAnalysisResponse(BaseModel):
    """Stable API response persisted by the analysis store."""

    model_config = ConfigDict(extra="forbid")

    analysis_id: str = Field(min_length=1, max_length=64)
    decision: Decision
    risk_score: float = Field(ge=0.0, le=1.0)
    threats: list[MemoryThreat] = Field(default_factory=list, max_length=100)
    sanitized_content: str = Field(max_length=50_000)
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


class ActionEvaluationResponse(BaseModel):
    """Explainable result of the memory-to-action authorization check."""

    model_config = ConfigDict(extra="forbid")

    decision: Decision
    action: str
    scope: str
    required_authority: Authority
    provided_authority: Authority | None = None
    required_capability: str
    provided_capabilities: list[str] = Field(default_factory=list)
    usable_memory_ids: list[str] = Field(default_factory=list)
    blocked_memory_ids: list[str] = Field(default_factory=list)
    scope_valid: bool
    reasons: list[str] = Field(default_factory=list, max_length=16)


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


class LedgerVerifyResponse(BaseModel):
    """Result of recomputing the append-only hash chain (Appendix A.7)."""

    model_config = ConfigDict(extra="forbid")

    valid: bool
    events_checked: int = Field(ge=0)
    first_invalid_event: int | None = None
