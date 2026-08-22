"""Ed25519 envelope signing and independent verification tests."""

from __future__ import annotations

import base64
import json
import os
import sqlite3

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from api.main import _rate_buckets, analysis_store, app
from memory_firewall.crypto import (
    PUBLIC_KEY_B64,
    verify_result,
    verify_result_with_key,
)
from memory_firewall.schemas import MemoryAnalysisResponse


client = TestClient(app)


def setup_function() -> None:
    _rate_buckets.clear()
    analysis_store.clear()


def teardown_function() -> None:
    _rate_buckets.clear()
    analysis_store.clear()


def _analyze(content: str, source: str) -> MemoryAnalysisResponse:
    response = client.post(
        "/api/v1/memory/analyze",
        json={
            "content": content,
            "source": source,
            "actor": {"id": "user:test", "type": "user"},
        },
    )
    assert response.status_code == 200
    return MemoryAnalysisResponse.model_validate(response.json())


def test_result_signature_verifies_with_exposed_public_key() -> None:
    result = _analyze("Customer prefers email notifications.", "user")

    assert verify_result(result) is True
    # Independent verification uses only the public key, like an external party.
    assert verify_result_with_key(result, PUBLIC_KEY_B64) is True


def test_verification_with_wrong_public_key_fails() -> None:
    result = _analyze("Customer prefers email notifications.", "user")
    other_public = Ed25519PrivateKey.generate().public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    assert verify_result_with_key(result, base64.b64encode(other_public).decode("ascii")) is False


def test_forged_signature_does_not_verify() -> None:
    result = _analyze("Customer prefers email notifications.", "user")
    forged = result.model_copy(
        update={"signature": base64.b64encode(os.urandom(64)).decode("ascii")}
    )

    assert verify_result(forged) is False
    assert verify_result_with_key(forged, PUBLIC_KEY_B64) is False


def test_tampered_content_fails_independent_verification() -> None:
    result = _analyze("Customer prefers email notifications.", "user")
    tampered = result.model_copy(
        update={"sanitized_content": "Customer prefers wire transfers to attacker."}
    )

    assert verify_result(tampered) is False
    assert verify_result_with_key(tampered, PUBLIC_KEY_B64) is False


def test_public_key_endpoint_exposes_verification_key() -> None:
    response = client.get("/api/v1/keys/current")

    assert response.status_code == 200
    body = response.json()
    assert body["algorithm"] == "Ed25519"
    assert body["key_id"]
    # The exposed key verifies real signatures but is not a signing key.
    result = _analyze("Customer prefers email notifications.", "user")
    assert verify_result_with_key(result, body["public_key_base64"]) is True


def test_unsigned_result_does_not_verify() -> None:
    result = _analyze("Customer prefers email notifications.", "user")
    unsigned = result.model_copy(update={"signature": "", "content_hash": ""})

    assert verify_result(unsigned) is False


def test_tamper_detected_on_read_with_ed25519() -> None:
    created = client.post(
        "/api/v1/memory/analyze",
        json={
            "content": "Customer prefers Spanish.",
            "source": "user",
            "actor": {"id": "user:test", "type": "user"},
        },
    )
    analysis_id = created.json()["analysis_id"]

    with sqlite3.connect(analysis_store.database_path) as connection:
        row = connection.execute(
            "SELECT result_json FROM analyses WHERE analysis_id = ?",
            (analysis_id,),
        ).fetchone()
        tampered = json.loads(row[0])
        tampered["sanitized_content"] = "tampered content"
        connection.execute(
            "UPDATE analyses SET result_json = ? WHERE analysis_id = ?",
            (json.dumps(tampered), analysis_id),
        )

    response = client.get(f"/api/v1/analyses/{analysis_id}")
    assert response.status_code == 500
    assert response.json() == {"error": "analysis_failed"}
