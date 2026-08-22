"""Integration contracts shared by the demo harness and frontend."""

from __future__ import annotations

from fastapi.testclient import TestClient

from api.main import _rate_buckets, analysis_store, app


client = TestClient(app)
ACTOR = {"id": "agent:integration", "type": "agent"}


def setup_function() -> None:
    _rate_buckets.clear()
    analysis_store.clear()


def teardown_function() -> None:
    _rate_buckets.clear()
    analysis_store.clear()


def _analyze(tenant_id: str, content: str = "A support note.") -> dict:
    response = client.post(
        "/api/v1/memory/analyze",
        json={
            "content": content,
            "source": "email",
            "scope": "customer_support_policy",
            "actor": ACTOR,
            "tenant_id": tenant_id,
        },
    )
    assert response.status_code == 200
    return response.json()


def test_search_and_ledger_events_are_tenant_scoped() -> None:
    tenant_a = _analyze("tenant-a")
    tenant_b = _analyze("tenant-b")

    search_a = client.get("/api/v1/memory/search?tenant_id=tenant-a")
    events_a = client.get("/api/v1/ledger/events?tenant_id=tenant-a")

    assert [item["analysis_id"] for item in search_a.json()] == [tenant_a["analysis_id"]]
    assert [event["object_id"] for event in events_a.json()] == [tenant_a["analysis_id"]]
    assert tenant_b["analysis_id"] not in search_a.text
    assert tenant_b["analysis_id"] not in events_a.text


def test_evaluate_write_is_signed_but_does_not_persist_or_write_a_ledger_event() -> None:
    response = client.post(
        "/api/v1/memory/evaluate-write",
        json={
            "content": "Preview only.",
            "source": "email",
            "scope": "customer_support_policy",
            "actor": ACTOR,
            "tenant_id": "tenant-a",
        },
    )

    assert response.status_code == 200
    preview = response.json()
    assert preview["content_hash"]
    assert preview["signature"]
    assert client.get(
        f"/api/v1/analyses/{preview['analysis_id']}?tenant_id=tenant-a"
    ).status_code == 404
    assert client.get("/api/v1/ledger/events?tenant_id=tenant-a").json() == []


def test_ledger_verification_includes_tenant_in_signed_event_payload() -> None:
    _analyze("tenant-a")
    assert client.get("/api/v1/ledger/verify").json()["valid"] is True
