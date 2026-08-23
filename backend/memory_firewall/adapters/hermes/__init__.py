"""Hermes pre-tool-call adapter for Memory Firewall."""

from __future__ import annotations

import hashlib
import json
import math
import os
import uuid
from collections.abc import Callable
from decimal import Decimal
from typing import Any
from urllib.request import Request, urlopen

ADAPTER_VERSION = "0.1.0"
DEFAULT_URL = "http://127.0.0.1:8000/api/v1/firewall/tool-calls/authorize"


def _canonical_number(value: int | float) -> str:
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("non-finite action argument")
    text = format(Decimal(str(value)), "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return "0" if text in {"", "-0"} else text


def _normalize_arguments(value: Any) -> Any:
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return value
    if isinstance(value, (int, float)):
        return {"$number": _canonical_number(value)}
    if isinstance(value, list):
        return [_normalize_arguments(item) for item in value]
    if isinstance(value, dict):
        return {key: _normalize_arguments(item) for key, item in value.items()}
    raise ValueError("action arguments must contain JSON values")


# A high-risk call may be routed through the server's semantic verifier, which
# costs a few seconds. The old 2s budget expired during that check and, because
# this adapter fails closed, every such call was denied on a timeout rather than
# on its merits. The ceiling must exceed the server's own verifier timeout.
DEFAULT_TIMEOUT_MS = 15_000


def _timeout_seconds() -> float:
    try:
        value = int(os.getenv("MEMORY_FIREWALL_TIMEOUT_MS", str(DEFAULT_TIMEOUT_MS)))
        return value / 1000 if value > 0 else DEFAULT_TIMEOUT_MS / 1000
    except ValueError:
        return DEFAULT_TIMEOUT_MS / 1000


def _workspace_key() -> str:
    """Return the workspace credential, or raise.

    The workspace is proven by this key alone. There is deliberately no default
    and no fallback to a "tenant id" env var: an unauthenticated agent must
    fail loudly rather than silently write into somebody else's workspace.
    """

    key = os.getenv("MEMORY_FIREWALL_WORKSPACE_KEY", "").strip()
    if not key:
        raise RuntimeError(
            "MEMORY_FIREWALL_WORKSPACE_KEY is not set. Obtain the key from "
            "POST /api/v1/auth/register or /api/v1/workspace/key/rotate."
        )
    return key


def _metadata(value: Any) -> tuple[dict[str, list[str]], str, str | None] | None:
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
    if not isinstance(scope, str) or not scope:
        return None

    # Why the agent believes the call is warranted. The server weighs it as
    # context for its semantic check; it confers no authority, so a persuasive
    # justification cannot unlock anything on its own.
    justification = value.get("justification")
    if justification is not None:
        if not isinstance(justification, str):
            return None
        justification = justification.strip()[:500] or None

    # No tenant_id: the server derives the workspace from the workspace key and
    # ignores anything the caller puts in the body.
    return lineage, scope, justification


def authorize_tool_call(payload: dict[str, Any]) -> dict[str, str]:
    """Call the firewall and normalize all failures to a block decision."""
    try:
        request = Request(
            os.getenv("MEMORY_FIREWALL_URL", DEFAULT_URL),
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "X-Workspace-Key": _workspace_key(),
            },
            method="POST",
        )
        with urlopen(request, timeout=_timeout_seconds()) as response:  # noqa: S310 - configured endpoint
            if response.status < 200 or response.status >= 300:
                raise ValueError(f"HTTP {response.status}")
            body = json.loads(response.read().decode("utf-8"))
        if (
            not isinstance(body, dict)
            or body.get("request_id") != payload["request_id"]
            or body.get("tool_name") != str(payload["tool"]["name"]).strip().upper()
            or body.get("session_id") != str(payload["session"]["id"]).strip().lower()
            or body.get("args_hash")
            != hashlib.sha256(
                json.dumps(
                    _normalize_arguments(payload["tool"]["arguments"]),
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()
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
    parsed = _metadata(metadata_value)
    if parsed is None:
        return {"action": "block", "message": "Memory Firewall metadata is required"}
    lineage, scope, justification = parsed
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
            "justification": justification,
            "actor": {
                "id": os.getenv("MEMORY_FIREWALL_ACTOR_ID", "hermes-agent"),
                "type": "agent",
            },
        }
    )
    decision = result.get("decision")
    reason = result.get("reason") or f"Memory Firewall decision: {decision}"
    if decision == "allow":
        return {"action": "modify", "args": clean_args}
    if decision == "review":
        # Native approval cannot mint the signed, scoped grant required by the
        # core. Every review therefore remains fail-closed at the adapter.
        return {"action": "block", "message": reason}
    return {"action": "block", "message": reason}


def register(ctx: Any) -> None:
    ctx.register_hook("pre_tool_call", pre_tool_call)
