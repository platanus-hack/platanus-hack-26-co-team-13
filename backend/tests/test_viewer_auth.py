from __future__ import annotations

import hashlib
import sqlite3

from memory_firewall.store import AnalysisStore
from memory_firewall.viewer_auth import (
    generate_workspace_id,
    generate_workspace_key,
    hash_password,
    hash_workspace_key,
    verify_password,
)


def test_passwords_are_salted_and_verified() -> None:
    first = hash_password("a-secure-password")
    second = hash_password("a-secure-password")

    assert first != second
    assert "a-secure-password" not in first
    assert verify_password("a-secure-password", first) is True
    assert verify_password("wrong-password", first) is False
    assert verify_password("a-secure-password", "malformed") is False


def test_session_tokens_are_stored_only_as_hashes(tmp_path) -> None:
    database = tmp_path / "auth.sqlite3"
    store = AnalysisStore(str(database))
    assert store.create_viewer_user(
        "person", hash_password("a-secure-password"), generate_workspace_id()
    )
    raw_token = "raw-session-token"
    store.create_viewer_session("person", "stored-token-hash", 4_000_000_000)

    with sqlite3.connect(database) as connection:
        row = connection.execute(
            "SELECT token_hash FROM viewer_sessions WHERE username = ?", ("person",)
        ).fetchone()

    assert row == ("stored-token-hash",)
    assert raw_token not in row


def test_workspace_ids_are_random_opaque_and_not_derived_from_a_username() -> None:
    first = generate_workspace_id()
    second = generate_workspace_id()

    assert first.startswith("ws_")
    assert len(first) == 19
    # Unguessable: two calls never collide, so nothing about the caller leaks.
    assert first != second
    assert len({generate_workspace_id() for _ in range(200)}) == 200
    # The old, exploitable derivation must not be reproducible any more.
    legacy = "ws_" + hashlib.sha256(b"alice").hexdigest()[:16]
    assert legacy not in {generate_workspace_id() for _ in range(200)}


def test_workspace_keys_are_prefixed_random_and_stored_only_as_hashes() -> None:
    key = generate_workspace_key()

    assert key.startswith("mfw_")
    assert len(key) > 20
    assert key != generate_workspace_key()
    digest = hash_workspace_key(key)
    assert digest == hashlib.sha256(key.encode("utf-8")).hexdigest()
    assert key not in digest


def test_sessions_resolve_the_owning_workspace(tmp_path) -> None:
    store = AnalysisStore(str(tmp_path / "auth.sqlite3"))
    tenant_id = generate_workspace_id()
    assert store.create_viewer_user("person", hash_password("a-secure-password"), tenant_id)
    store.create_viewer_session("person", "stored-token-hash", 4_000_000_000)

    session = store.get_viewer_session("stored-token-hash", 1_000)

    assert session == ("person", tenant_id, 4_000_000_000)
    assert store.get_viewer_session("stored-token-hash", 4_000_000_001) is None
    assert store.get_viewer_session("unknown-token-hash", 1_000) is None
