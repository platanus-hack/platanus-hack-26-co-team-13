from __future__ import annotations

import sqlite3

from memory_firewall.store import AnalysisStore
from memory_firewall.viewer_auth import hash_password, verify_password


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
    assert store.create_viewer_user("person", hash_password("a-secure-password"))
    raw_token = "raw-session-token"
    store.create_viewer_session("person", "stored-token-hash", 4_000_000_000)

    with sqlite3.connect(database) as connection:
        row = connection.execute(
            "SELECT token_hash FROM viewer_sessions WHERE username = ?", ("person",)
        ).fetchone()

    assert row == ("stored-token-hash",)
    assert raw_token not in row
