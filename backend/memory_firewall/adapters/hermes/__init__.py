"""Hermes pre-tool-call adapter for Memory Firewall."""

from __future__ import annotations

import json
import os
import uuid
from collections.abc import Callable
from typing import Any
from urllib.request import Request, urlopen

ADAPTER_VERSION = "0.1.0"
DEFAULT_URL = "http://127.0.0.1:8000/api/v1/firewall/tool-calls/authorize"


def _unprotected_tools() -> set[str]:
    return {
        name.strip().lower()
        for name in os.getenv("MEMORY_FIREWALL_UNPROTECTED_TOOLS", "").split(",")
        if name.strip()
    }


def _timeout_seconds() -> float:
    try:
        value = int(os.getenv("MEMORY_FIREWALL_TIMEOUT_MS", "2000"))
        return value / 1000 if value > 0 else 2.0
    except ValueError:
        return 2.0


def _metadata(value: Any) -> tuple[dict[str, list[str]], str, str] | None:
    if not isinstance(value, dict) or not isinstance(value.get("argument_lineage"), dict):
        return None
    lineage = value["argument_lineage"]
    if any(
        not isinstance(key, str)
        or not isinstance(sources, list)
        or any(not isinstance(source, str) for source in sources)
        for key, sources in lineage.items()
    ):
        return None
    scope = value.get("scope", os.getenv("MEMORY_FIREWALL_SCOPE", "default"))
    tenant_id = value.get("tenant_id", os.getenv("MEMORY_FIREWALL_TENANT_ID", "default"))
    if not isinstance(scope, str) or not scope or not isinstance(tenant_id, str) or not tenant_id:
        return None
    return lineage, scope, tenant_id


def authorize_tool_call(payload: dict[str, Any]) -> dict[str, str]:
    """Call the firewall and normalize all failures to a block decision."""
    try:
        request = Request(
            os.getenv("MEMORY_FIREWALL_URL", DEFAULT_URL),
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(request, timeout=_timeout_seconds()) as response:  # noqa: S310 - configured endpoint
            if response.status < 200 or response.status >= 300:
                raise ValueError(f"HTTP {response.status}")
            body = json.loads(response.read().decode("utf-8"))
        if (
            not isinstance(body, dict)
            or body.get("request_id") != payload["request_id"]
            or body.get("decision") not in {"allow", "block", "review"}
            or ("reason" in body and not isinstance(body["reason"], str))
        ):
            raise ValueError("malformed or unbound response")
        return {"decision": body["decision"], "reason": body.get("reason", "")}
    except Exception as exc:  # Network, timeout, HTTP, and decoding errors all fail closed.
        return {"decision": "block", "reason": f"Memory Firewall unavailable: {exc}"}


def pre_tool_call(
    tool_name: str,
    args: dict[str, Any],
    task_id: str = "",
    *,
    client: Callable[[dict[str, Any]], dict[str, str]] = authorize_tool_call,
    **kwargs: Any,
) -> dict[str, Any]:
    """Strip adapter metadata and return a native Hermes tool directive."""
    metadata_value = args.pop("_memory_firewall", None)
    clean_args = dict(args)
    if tool_name.strip().lower() in _unprotected_tools():
        return {"action": "modify", "args": clean_args}

    parsed = _metadata(metadata_value)
    if parsed is None:
        return {"action": "block", "message": "Memory Firewall metadata is required"}
    lineage, scope, tenant_id = parsed
    request_id = str(uuid.uuid4())
    session_id = str(kwargs.get("session_id") or task_id or "hermes-session")
    session: dict[str, str] = {"id": session_id}
    for source, target in (("turn_id", "turn_id"), ("tool_call_id", "tool_call_id")):
        if kwargs.get(source):
            session[target] = str(kwargs[source])
    result = client(
        {
            "schema_version": "memory-firewall.tool-call.v1",
            "request_id": request_id,
            "runtime": {"name": "hermes", "adapter_version": ADAPTER_VERSION},
            "session": session,
            "tool": {"name": tool_name, "arguments": clean_args},
            "argument_lineage": lineage,
            "scope": scope,
            "actor": {
                "id": os.getenv("MEMORY_FIREWALL_ACTOR_ID", "hermes-agent"),
                "type": "agent",
            },
            "tenant_id": tenant_id,
        }
    )
    decision = result.get("decision")
    reason = result.get("reason") or f"Memory Firewall decision: {decision}"
    if decision == "allow":
        return {"action": "modify", "args": clean_args}
    if decision == "review":
        return {"action": "approve", "message": reason, "rule_key": request_id}
    return {"action": "block", "message": reason}


def register(ctx: Any) -> None:
    ctx.register_hook("pre_tool_call", pre_tool_call)
