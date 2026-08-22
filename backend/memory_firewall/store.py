"""SQLite persistence for signed memory envelopes and audit evidence."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from secrets import token_urlsafe
from threading import RLock

from .crypto import canonical_bytes, ensure_integrity, sign_ledger_event, verify_ledger_event
from .schemas import LedgerEventView, MemoryAnalysisResponse

_GENESIS_HASH = "0" * 64


class AnalysisStore:
    """Thread-safe SQLite store with an append-only, signed hash-chain ledger."""

    def __init__(self, database_path: str = "memory_firewall.sqlite3") -> None:
        self.database_path = database_path
        self._lock = RLock()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=5)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        if self.database_path != ":memory:":
            Path(self.database_path).expanduser().parent.mkdir(parents=True, exist_ok=True)
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS analyses (
                    analysis_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    source TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    risk_score REAL NOT NULL,
                    result_json TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS ledger_events (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT UNIQUE NOT NULL,
                    event_type TEXT NOT NULL,
                    object_id TEXT NOT NULL,
                    actor_id TEXT NOT NULL,
                    payload_hash TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL,
                    signature TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            connection.commit()

    def _append_event(
        self,
        connection: sqlite3.Connection,
        *,
        event_type: str,
        object_id: str,
        actor_id: str,
        payload_hash: str,
    ) -> LedgerEventView:
        row = connection.execute(
            "SELECT event_hash FROM ledger_events ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        previous_hash = row["event_hash"] if row is not None else _GENESIS_HASH
        event_id = f"evt_{token_urlsafe(12)}"
        created_at = datetime.now(timezone.utc)
        event_payload = {
            "event_id": event_id,
            "event_type": event_type,
            "object_id": object_id,
            "actor_id": actor_id,
            "payload_hash": payload_hash,
            "previous_hash": previous_hash,
            "created_at": created_at.isoformat(),
        }
        event_hash = hashlib.sha256(canonical_bytes(event_payload)).hexdigest()
        signature = sign_ledger_event({**event_payload, "event_hash": event_hash})
        cursor = connection.execute(
            """
            INSERT INTO ledger_events
                (event_id, event_type, object_id, actor_id, payload_hash,
                 previous_hash, event_hash, signature, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                event_type,
                object_id,
                actor_id,
                payload_hash,
                previous_hash,
                event_hash,
                signature,
                created_at.isoformat(),
            ),
        )
        return LedgerEventView(
            seq=cursor.lastrowid,
            event_hash=event_hash,
            signature=signature,
            **event_payload,
        )

    def save(
        self,
        result: MemoryAnalysisResponse,
        *,
        event_type: str | None = None,
        actor_id: str | None = None,
    ) -> None:
        """Persist a result and its write event in one SQLite transaction."""

        serialized = json.dumps(result.model_dump(mode="json"), ensure_ascii=False)
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                INSERT INTO analyses
                    (analysis_id, created_at, source, decision, risk_score, result_json)
                VALUES (?, ?, ?, ?, ?, ?)
                """
                """
                ON CONFLICT(analysis_id) DO UPDATE SET
                    created_at = excluded.created_at,
                    source = excluded.source,
                    decision = excluded.decision,
                    risk_score = excluded.risk_score,
                    result_json = excluded.result_json
                """,
                (
                    result.analysis_id,
                    result.created_at.isoformat(),
                    result.source,
                    result.decision.value,
                    result.risk_score,
                    serialized,
                ),
            )
            if event_type is not None:
                self._append_event(
                    connection,
                    event_type=event_type,
                    object_id=result.analysis_id,
                    actor_id=actor_id or "system:firewall",
                    payload_hash=result.content_hash,
                )
            connection.commit()

    def append_event(
        self, *, event_type: str, object_id: str, actor_id: str, payload_hash: str
    ) -> LedgerEventView:
        """Append a non-envelope event, such as an action decision."""

        with self._lock, self._connect() as connection:
            event = self._append_event(
                connection,
                event_type=event_type,
                object_id=object_id,
                actor_id=actor_id,
                payload_hash=payload_hash,
            )
            connection.commit()
            return event

    def get(self, analysis_id: str) -> MemoryAnalysisResponse | None:
        """Return a verified response or ``None`` when it does not exist."""

        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT result_json FROM analyses WHERE analysis_id = ?", (analysis_id,)
            ).fetchone()
        if row is None:
            return None
        return ensure_integrity(MemoryAnalysisResponse.model_validate(json.loads(row["result_json"])))

    def list_events(self, limit: int = 50) -> list[LedgerEventView]:
        """Return newest ledger events for the dashboard timeline."""

        with self._lock, self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM ledger_events ORDER BY seq DESC LIMIT ?", (limit,)
            ).fetchall()
        return [LedgerEventView.model_validate(dict(row)) for row in rows]

    def verify_chain(self) -> tuple[bool, int, int | None]:
        """Recompute hashes, links and signatures; return first bad sequence."""

        with self._lock, self._connect() as connection:
            rows = connection.execute("SELECT * FROM ledger_events ORDER BY seq ASC").fetchall()
        previous_hash = _GENESIS_HASH
        checked = 0
        for row in rows:
            event_payload = {
                "event_id": row["event_id"],
                "event_type": row["event_type"],
                "object_id": row["object_id"],
                "actor_id": row["actor_id"],
                "payload_hash": row["payload_hash"],
                "previous_hash": row["previous_hash"],
                "created_at": row["created_at"],
            }
            expected_hash = hashlib.sha256(canonical_bytes(event_payload)).hexdigest()
            signed_payload = {**event_payload, "event_hash": row["event_hash"]}
            checked += 1
            if (
                row["previous_hash"] != previous_hash
                or row["event_hash"] != expected_hash
                or not verify_ledger_event(signed_payload, row["signature"])
            ):
                return False, checked, row["seq"]
            previous_hash = row["event_hash"]
        return True, checked, None

    def clear(self) -> None:
        """Delete all records; intended for tests and local demo resets."""

        with self._lock, self._connect() as connection:
            connection.execute("DELETE FROM analyses")
            connection.execute("DELETE FROM ledger_events")
            connection.commit()
