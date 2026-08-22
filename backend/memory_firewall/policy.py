"""Deterministic policy decisions for memory analysis."""

from __future__ import annotations

import os
from dataclasses import dataclass

from .schemas import Authority, Decision, MemoryCapabilities, Severity


AUTHORITY_RANK: dict[Authority, int] = {
    Authority.UNTRUSTED: 0,
    Authority.OBSERVED: 1,
    Authority.USER_CONFIRMED: 2,
    Authority.ORG_VERIFIED: 3,
    Authority.SYSTEM_AUTHORITY: 4,
}

HIGH_RISK_ACTIONS = {
    "ISSUE_REFUND",
    "CHANGE_ACCOUNT_DESTINATION",
    "SEND_EXTERNAL_EMAIL",
}

ACTION_REQUIRED_AUTHORITY: dict[str, Authority] = {
    "ISSUE_REFUND": Authority.USER_CONFIRMED,
    "CHANGE_ACCOUNT_DESTINATION": Authority.ORG_VERIFIED,
    "SEND_EXTERNAL_EMAIL": Authority.USER_CONFIRMED,
}

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
        if (required := ACTION_REQUIRED_AUTHORITY.get(action)) is not None
        and AUTHORITY_RANK[authority] < AUTHORITY_RANK[required]
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
