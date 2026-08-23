"""Deterministic policy decisions for memory analysis."""

from __future__ import annotations

import math
import json
import os
from dataclasses import dataclass
from pathlib import Path

from .schemas import Authority, Decision, MemoryCapabilities, Severity


AUTHORITY_RANK: dict[Authority, int] = {
    Authority.UNTRUSTED: 0,
    Authority.OBSERVED: 1,
    Authority.USER_CONFIRMED: 2,
    Authority.ORG_VERIFIED: 3,
    Authority.SYSTEM_AUTHORITY: 4,
}

@dataclass(frozen=True)
class EffectPolicy:
    """Security invariants inherited by every action with this effect."""

    required_authority: Authority
    one_shot: bool
    semantic_review: bool


@dataclass(frozen=True)
class ArgumentContract:
    """Deterministic type and authority requirements for one argument."""

    kind: str
    required: bool
    required_authority: Authority


@dataclass(frozen=True)
class ActionContract:
    """Declarative closed-world contract for one executable action."""

    name: str
    effects: frozenset[str]
    arguments: dict[str, ArgumentContract]
    required_authority: Authority
    high_risk: bool
    semantic_review: bool

    @property
    def required_arguments(self) -> frozenset[str]:
        return frozenset(
            name for name, contract in self.arguments.items() if contract.required
        )


def _load_action_contracts() -> tuple[
    dict[str, EffectPolicy], dict[str, ActionContract]
]:
    """Load and strictly validate the packaged action manifest at startup."""

    path = Path(__file__).with_name("action_contracts.json")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("action contract manifest cannot be loaded") from exc
    if document.get("schema_version") != "memory-firewall.action-contracts.v1":
        raise RuntimeError("unsupported action contract manifest")

    effects: dict[str, EffectPolicy] = {}
    for name, raw in document.get("effects", {}).items():
        if not isinstance(name, str) or not isinstance(raw, dict):
            raise RuntimeError("invalid effect contract")
        if (
            set(raw) != {"required_authority", "one_shot", "semantic_review"}
            or type(raw.get("one_shot")) is not bool
            or type(raw.get("semantic_review")) is not bool
        ):
            raise RuntimeError(f"invalid effect contract: {name}")
        try:
            effects[name] = EffectPolicy(
                required_authority=Authority(raw["required_authority"]),
                one_shot=raw["one_shot"],
                semantic_review=raw["semantic_review"],
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise RuntimeError(f"invalid effect contract: {name}") from exc

    actions: dict[str, ActionContract] = {}
    for raw_action in document.get("actions", []):
        if not isinstance(raw_action, dict):
            raise RuntimeError("invalid action contract")
        name = str(raw_action.get("name", "")).strip().upper()
        if not name or name in actions:
            raise RuntimeError(f"invalid or duplicate action contract: {name}")
        effect_names = frozenset(raw_action.get("effects", []))
        if not effect_names or not effect_names <= effects.keys():
            raise RuntimeError(f"action has unknown effects: {name}")
        required_authority = max(
            (effects[effect].required_authority for effect in effect_names),
            key=lambda authority: AUTHORITY_RANK[authority],
        )
        arguments: dict[str, ArgumentContract] = {}
        raw_arguments = raw_action.get("arguments", {})
        if not isinstance(raw_arguments, dict):
            raise RuntimeError(f"action arguments must be an object: {name}")
        for argument, raw_rule in raw_arguments.items():
            if (
                not isinstance(argument, str)
                or not isinstance(raw_rule, dict)
                or raw_rule.get("type") not in {"string", "positive_number", "email"}
            ):
                raise RuntimeError(f"invalid argument contract: {name}.{argument}")
            try:
                argument_authority = Authority(
                    raw_rule.get("authority", required_authority.value)
                )
            except ValueError as exc:
                raise RuntimeError(
                    f"invalid argument authority: {name}.{argument}"
                ) from exc
            arguments[argument] = ArgumentContract(
                kind=raw_rule["type"],
                required=raw_rule.get("required", True) is not False,
                required_authority=argument_authority,
            )
        actions[name] = ActionContract(
            name=name,
            effects=effect_names,
            arguments=arguments,
            required_authority=required_authority,
            high_risk=any(effects[effect].one_shot for effect in effect_names),
            semantic_review=any(
                effects[effect].semantic_review for effect in effect_names
            ),
        )
    if not actions:
        raise RuntimeError("action contract manifest contains no actions")
    return effects, actions


EFFECT_POLICIES, ACTION_CONTRACTS = _load_action_contracts()

HIGH_RISK_ACTIONS = {
    action for action, contract in ACTION_CONTRACTS.items() if contract.high_risk
}

ACTION_REQUIRED_AUTHORITY: dict[str, Authority] = {
    action: contract.required_authority
    for action, contract in ACTION_CONTRACTS.items()
}
ACTION_REQUIRED_AUTHORITY.update(
    {
        "READ": Authority.UNTRUSTED,
        "DERIVE": Authority.USER_CONFIRMED,
    }
)

BLOCKING_THREATS = {
    "prompt_injection",
    "system_instruction_override",
    "persistent_prompt_injection",
    "secret_exfiltration",
    "memory_manipulation",
    "future_behavior_modification",
}

REVIEW_THREATS = {
    "jailbreak_instruction",
    "sensitive_information",
}

_APPROVERS_ENV = "MEMORY_FIREWALL_ORG_APPROVERS"
DEFAULT_APPROVERS = frozenset({"user:support-supervisor"})


@dataclass(frozen=True)
class PolicyDecision:
    decision: Decision
    reason: str
    capabilities: MemoryCapabilities


def required_authority_for_action(action: str) -> Authority:
    """Return the conservative minimum authority for an action."""

    return ACTION_REQUIRED_AUTHORITY.get(action, Authority.ORG_VERIFIED)


def required_authority_for_argument(action: str, argument: str) -> Authority:
    """Return the claim authority required by one declared argument."""

    contract = ACTION_CONTRACTS.get(action)
    if contract is None:
        return Authority.ORG_VERIFIED
    rule = contract.arguments.get(argument)
    return rule.required_authority if rule is not None else Authority.ORG_VERIFIED


def effects_for_action(action: str) -> list[str]:
    """Return stable effect labels used in decision explanations."""

    contract = ACTION_CONTRACTS.get(action)
    return sorted(contract.effects) if contract is not None else []


def validate_action_arguments(action: str, arguments: dict[str, object]) -> list[str]:
    """Return deterministic contract violations for an executable call."""

    contract = ACTION_CONTRACTS.get(action)
    if contract is None:
        return [f"Unknown action {action} is not registered."]
    missing = sorted(contract.required_arguments - set(arguments))
    reasons = [f"Required argument {name} is missing." for name in missing]
    extra = sorted(set(arguments) - set(contract.arguments))
    reasons.extend(f"Argument {name} is not declared by the action contract." for name in extra)
    for name in set(contract.arguments) & set(arguments):
        value = arguments[name]
        rule = contract.arguments[name]
        if value is None or isinstance(value, bool):
            reasons.append(f"Required argument {name} has an invalid value.")
        elif rule.kind == "positive_number" and (
            not isinstance(value, (int, float))
            or not math.isfinite(value)
            or value <= 0
        ):
            reasons.append(f"Argument {name} must be a positive number.")
        elif rule.kind in {"string", "email"} and (
            not isinstance(value, str) or not value.strip()
        ):
            reasons.append(f"Required argument {name} must be a non-empty string.")
        elif rule.kind == "email" and (
            value.count("@") != 1
            or value.startswith("@")
            or value.endswith("@")
            or "." not in value.rsplit("@", 1)[1]
        ):
            reasons.append(f"Argument {name} must be a valid email address.")
    return reasons


def authorized_approvers() -> set[str]:
    """Return explicitly configured principals allowed to elevate memories."""

    configured = os.getenv(_APPROVERS_ENV)
    if configured is None:
        return set(DEFAULT_APPROVERS)
    return {value.strip().lower() for value in configured.split(",") if value.strip()}


def approver_grant_ceiling(approver_id: str) -> Authority | None:
    """Authorized API approvers may grant at most org-verified authority."""

    if approver_id in authorized_approvers():
        return Authority.ORG_VERIFIED
    return None


def actions_with_insufficient_authority(
    actions: list[str], authority: Authority
) -> list[str]:
    """Return requested capabilities that exceed the approved authority."""

    return [
        action
        for action in actions
        if (required := ACTION_REQUIRED_AUTHORITY.get(action)) is None
        or AUTHORITY_RANK[authority] < AUTHORITY_RANK[required]
    ]


def authority_for_source(source: str) -> Authority:
    """Map an asserted source conservatively.

    The public MVP endpoint has no authenticated source connector. Therefore a
    caller cannot obtain verified authority merely by sending ``source=system``
    or ``source=internal``. A future authenticated connector can explicitly
    elevate authority through a separate approval flow.
    """

    if source in {"email", "web", "tool", "external", "ticket", "support_ticket"}:
        return Authority.UNTRUSTED
    if source in {"system", "internal", "org_verified"}:
        return Authority.OBSERVED
    if source in {"user", "customer", "user_confirmed"}:
        return Authority.OBSERVED
    return Authority.UNTRUSTED


def _base_capabilities(scope: str, authority: Authority) -> MemoryCapabilities:
    allowed_scopes = [scope]
    actions = ["READ"]
    if AUTHORITY_RANK[authority] >= AUTHORITY_RANK[Authority.USER_CONFIRMED]:
        actions.append("DERIVE")
    return MemoryCapabilities(
        allowed_actions=actions,
        allowed_scopes=allowed_scopes,
        requires_approval=False,
        usable_for_action=False,
    )


def evaluate_policy(
    *,
    threats: list[dict[str, object]],
    authority: Authority,
    source: str,
    scope: str,
    requested_action: str | None,
) -> PolicyDecision:
    """Evaluate memory use without asking a model to make the security decision."""

    threat_types = {str(threat["type"]) for threat in threats}
    threat_severities = {threat["severity"] for threat in threats}
    capabilities = _base_capabilities(scope, authority)

    if requested_action in HIGH_RISK_ACTIONS and AUTHORITY_RANK[authority] < AUTHORITY_RANK[Authority.USER_CONFIRMED]:
        return PolicyDecision(
            decision=Decision.BLOCK,
            reason=(
                f"High-risk action {requested_action} requires user-confirmed "
                f"or stronger authority; received {authority.value}."
            ),
            capabilities=capabilities.model_copy(update={"requires_approval": True}),
        )

    if threat_types & BLOCKING_THREATS or Severity.CRITICAL in threat_severities:
        return PolicyDecision(
            decision=Decision.BLOCK,
            reason="Persistent instructions, overrides, manipulation, or exfiltration require blocking.",
            capabilities=capabilities.model_copy(update={"requires_approval": True}),
        )

    if threat_types & REVIEW_THREATS or Severity.HIGH in threat_severities:
        return PolicyDecision(
            decision=Decision.REVIEW,
            reason="The content may be useful, but it requires human review before becoming trusted memory.",
            capabilities=capabilities.model_copy(update={"requires_approval": True}),
        )

    if source in {"email", "web", "tool", "external", "ticket", "support_ticket"} and scope in {
        "corporate_policy",
        "customer_support_policy",
    }:
        return PolicyDecision(
            decision=Decision.REVIEW,
            reason="External content cannot create organization-wide policy automatically.",
            capabilities=capabilities.model_copy(update={"requires_approval": True}),
        )

    return PolicyDecision(
        decision=Decision.ALLOW,
        reason="No blocking memory threat was detected; content remains bound to its source authority.",
        capabilities=capabilities,
    )
