"""Integration contracts shared by the demo harness and frontend."""

from __future__ import annotations

from fastapi.testclient import TestClient

from api.main import (
    _auth_rate_buckets,
    _rate_buckets,
    _runtime_heartbeats,
    analysis_store,
    app,
)
from memory_firewall.crypto import verify_ledger_event


client = TestClient(app)
ACTOR = {"id": "agent:integration", "type": "agent"}

# Every write endpoint derives its tenant from the caller's credential (session
# cookie or X-Workspace-Key), never from the request body, so tests must
# authenticate as the workspace they intend to write into.
OPERATOR_WORKSPACE = ""


def setup_function() -> None:
    global OPERATOR_WORKSPACE
    _rate_buckets.clear()
    _auth_rate_buckets.clear()
    _runtime_heartbeats.clear()
    analysis_store.clear()
    response = client.post(
        "/api/v1/auth/register",
        json={"email": "operator@example.com", "password": "test-viewer-password"},
    )
    assert response.status_code == 201
    OPERATOR_WORKSPACE = response.json()["workspace_id"]


def teardown_function() -> None:
    _rate_buckets.clear()
    _auth_rate_buckets.clear()
    _runtime_heartbeats.clear()
    analysis_store.clear()
    client.cookies.clear()


def _analyze(
    content: str = "A support note.",
    claims: dict | None = None,
    headers: dict[str, str] | None = None,
) -> dict:
    """Write into the operator's workspace unless another credential is given.

    A ``tenant_id`` is deliberately not sent: the server would discard it.
    """

    response = client.post(
        "/api/v1/memory/analyze",
        json={
            "content": content,
            "claims": claims or {},
            "source": "email",
            "scope": "customer_support_policy",
            "actor": ACTOR,
        },
        headers=headers,
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_search_and_ledger_events_are_tenant_scoped(monkeypatch) -> None:
    neighbour = TestClient(app).post(
        "/api/v1/auth/register",
        json={"email": "neighbour@example.com", "password": "test-viewer-password"},
    )
    assert neighbour.status_code == 201
    neighbour_workspace = neighbour.json()["workspace_id"]
    monkeypatch.setenv("MEMORY_FIREWALL_ADMIN_TENANT_ID", neighbour_workspace)

    # Written with the neighbour's agent key on the operator's own connection:
    # the key, not the cookie and not the body, decides the workspace.
    foreign = _analyze(
        headers={"X-Workspace-Key": neighbour.json()["workspace_key"]}
    )
    owned = _analyze(content="An operator-owned note.")

    search_foreign = client.get(
        f"/api/v1/memory/search?tenant_id={neighbour_workspace}",
        headers={"Authorization": "Bearer test-admin-token"},
    )
    # A query parameter can no longer select the workspace: the session does.
    events = client.get(f"/api/v1/ledger/events?tenant_id={neighbour_workspace}")

    assert [item["analysis_id"] for item in search_foreign.json()] == [
        foreign["analysis_id"]
    ]
    assert len(events.json()) == 1
    assert events.json()[0]["tenant_id"] == OPERATOR_WORKSPACE
    assert events.json()[0]["object_ref"].startswith("object_")
    assert events.json()[0]["object_ref"] != owned["analysis_id"]
    assert events.json()[0]["projection_signature"]
    projection = events.json()[0]
    signature = projection.pop("projection_signature")
    assert verify_ledger_event(projection, signature) is True
    assert owned["analysis_id"] not in search_foreign.text
    assert foreign["analysis_id"] not in events.text


def test_evaluate_write_is_signed_but_does_not_persist_or_write_a_ledger_event() -> None:
    response = client.post(
        "/api/v1/memory/evaluate-write",
        json={
            "content": "Preview only.",
            "source": "email",
            "scope": "customer_support_policy",
            "actor": ACTOR,
        },
    )

    assert response.status_code == 200
    preview = response.json()
    assert preview["content_hash"]
    assert preview["signature"]
    # Not persisted, so not readable even by the workspace that previewed it.
    assert client.get(
        f"/api/v1/analyses/{preview['analysis_id']}"
    ).status_code == 404
    assert client.get("/api/v1/ledger/events").json() == []


def test_ledger_verification_includes_tenant_in_signed_event_payload() -> None:
    _analyze()
    assert client.get("/api/v1/ledger/verify").json()["valid"] is True


def test_runtime_status_reports_verified_adapters_without_fake_connections() -> None:
    response = client.get("/api/v1/runtime/status")

    assert response.status_code == 200
    payload = response.json()
    assert [adapter["name"] for adapter in payload["adapters"]] == [
        "Pi",
        "Hermes",
        "OpenClaw",
    ]
    assert all(adapter["status"] == "adapter_verified" for adapter in payload["adapters"])
    assert payload["cli_install_command"].startswith(
        'PYTHON_BIN="$(command -v python3.14'
    )
    assert "Python 3.11+ is required" in payload["cli_install_command"]
    commands = {adapter["name"]: adapter["install_command"] for adapter in payload["adapters"]}
    assert commands["Pi"].startswith("pi --version")
    assert "memory-firewall install pi" in commands["Pi"]
    assert commands["Hermes"].startswith("hermes --version")
    assert "hermes plugins enable memory-firewall" in commands["Hermes"]
    assert commands["OpenClaw"].startswith("openclaw --version")
    assert "openclaw gateway install --force" in commands["OpenClaw"]
    assert "openclaw gateway restart" in commands["OpenClaw"]
    assert payload["live_connections"] == []

    heartbeat = client.post(
        "/api/v1/runtime/connections/heartbeat",
        json={
            "runtime": {"name": "pi", "adapter_version": "0.1.0"},
            "session": {"id": "pi-live-session"},
        },
    )
    connected = client.get("/api/v1/runtime/status")

    assert heartbeat.status_code == 204
    assert connected.json()["live_connections"] == ["pi"]


def test_runtime_local_block_is_visible_in_protected_ledger() -> None:
    blocked = client.post(
        "/api/v1/runtime/tool-blocks",
        json={
            "runtime": {"name": "pi", "adapter_version": "0.1.0"},
            "session": {"id": "pi-session", "tool_call_id": "call-1"},
            "tool_name": "bash",
            "reason": "Memory Firewall metadata is required",
            "actor": {"id": "pi-agent", "type": "agent"},
        },
    )
    login = client.post(
        "/api/v1/auth/login",
        json={"email": "operator@example.com", "password": "test-viewer-password"},
    )
    events = client.get("/api/v1/ledger/events")

    assert blocked.status_code == 204
    assert login.status_code == 200
    assert events.status_code == 200
    assert events.json()[0]["event_type"] == "TOOL_BLOCKED_LOCAL"


def test_legacy_escalation_tokens_require_admin_authentication() -> None:
    pending = client.get("/api/v1/firewall/escalations/pending")
    read = client.get("/api/v1/firewall/escalations/ticket-missing")
    approve = client.post(
        "/api/v1/firewall/escalations/ticket-missing/approve",
        json={
            "approved_by": "user:support-supervisor",
            "approval_reason": "Reviewed.",
        },
    )

    assert pending.status_code == 401
    assert read.status_code == 401
    assert approve.status_code == 401


def test_protected_activity_requires_viewer_login() -> None:
    anonymous = TestClient(app)

    denied = anonymous.get("/api/v1/ledger/events")
    registered = anonymous.post(
        "/api/v1/auth/register",
        json={"email": "new-user@example.com", "password": "a-secure-password"},
    )
    duplicate = TestClient(app).post(
        "/api/v1/auth/register",
        json={"email": "NEW-USER@example.com", "password": "another-secure-password"},
    )
    anonymous.post("/api/v1/auth/logout")
    invalid = anonymous.post(
        "/api/v1/auth/login",
        json={"email": "new-user@example.com", "password": "wrong-password"},
    )
    authenticated = anonymous.post(
        "/api/v1/auth/login",
        json={"email": "new-user@example.com", "password": "a-secure-password"},
    )
    allowed = anonymous.get("/api/v1/ledger/events")
    session_cookie = authenticated.cookies.get("memory_firewall_session")
    logout = anonymous.post("/api/v1/auth/logout")
    anonymous.cookies.set("memory_firewall_session", session_cookie)
    revoked = anonymous.get("/api/v1/ledger/events")

    assert denied.status_code == 401
    assert registered.status_code == 201
    assert duplicate.status_code == 409
    assert invalid.status_code == 401
    assert authenticated.status_code == 200
    assert session_cookie
    assert "HttpOnly" in authenticated.headers["set-cookie"]
    assert "SameSite=lax" in authenticated.headers["set-cookie"]
    assert allowed.status_code == 200
    assert logout.status_code == 204
    assert revoked.status_code == 401


def test_retrieve_and_native_tool_authorization_are_cross_session() -> None:
    stored = _analyze(
        "Andina Logistics account 8842, invoice INV-3812, amount 48000000.",
        {"vendor": "Andina Logistics", "account": "8842", "amount": 48000000},
    )
    retrieved = client.post(
        "/api/v1/memory/retrieve",
        json={
            "analysis_id": stored["analysis_id"],
            "session_id": "session-b",
            "actor": {"id": "agent:finance-session-b", "type": "agent"},
        },
    )
    assert retrieved.status_code == 200
    assert retrieved.json()["memory"]["analysis_id"] == stored["analysis_id"]

    arguments = {"vendor": "Andina Logistics", "account": "8842", "amount": 48000000}
    authorized = client.post(
        "/api/v1/firewall/tool-calls/authorize",
        json={
            "schema_version": "memory-firewall.tool-call.v1",
            "request_id": "req-api-3812",
            "runtime": {"name": "pi", "adapter_version": "0.1.0"},
            "session": {"id": "session-b", "tool_call_id": "call-3812"},
            "tool": {"name": "pay_invoice", "arguments": arguments},
            "argument_lineage": {
                key: [stored["analysis_id"]] for key in arguments
            },
            "scope": "customer_support_policy",
            "actor": {"id": "agent:finance-session-b", "type": "agent"},
        },
    )
    assert authorized.status_code == 200
    payload = authorized.json()
    assert payload["request_id"] == "req-api-3812"
    assert payload["decision"] == "block"
    assert payload["required_authority"] == "org_verified"
    assert payload["provided_authority"] == "untrusted"
