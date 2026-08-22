"""Small SQLite persistence layer for analysis results.

Only sanitized response data is persisted. The original submitted content and
request metadata are deliberately not stored by this MVP.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from threading import RLock

from .crypto import ensure_integrity
from .schemas import MemoryAnalysisResponse


class AnalysisStore:
    """Thread-safe SQLite store for retrieving analysis results by id."""

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
            connection.commit()

    def save(self, result: MemoryAnalysisResponse) -> None:
        """Persist only the sanitized, schema-validated result."""

        serialized = json.dumps(result.model_dump(mode="json"), ensure_ascii=False)
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO analyses
                    (analysis_id, created_at, source, decision, risk_score, result_json)
                VALUES (?, ?, ?, ?, ?, ?)
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
            connection.commit()

    def get(self, analysis_id: str) -> MemoryAnalysisResponse | None:
        """Return a validated response or ``None`` when it does not exist."""

        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT result_json FROM analyses WHERE analysis_id = ?",
                (analysis_id,),
            ).fetchone()
        if row is None:
            return None
        return ensure_integrity(
            MemoryAnalysisResponse.model_validate(json.loads(row["result_json"]))
        )

    def list_analyses(
        self,
        scope: str | None = None,
        source: str | None = None,
        limit: int = 100,
    ) -> list[MemoryAnalysisResponse]:
        """Return analyses ordered by created_at descending.

        Filters by scope (checks allowed_scopes inside capabilities JSON) and
        source when provided.  Results that fail integrity checks are silently
        skipped so a single tampered row does not break the whole listing.
        """
        from .crypto import ensure_integrity, IntegrityError  # local import avoids circular

        query = "SELECT result_json FROM analyses"
        params: list[object] = []
        conditions: list[str] = []

        if source is not None:
            conditions.append("source = ?")
            params.append(source)

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(min(max(1, limit), 500))

        with self._lock, self._connect() as connection:
            rows = connection.execute(query, params).fetchall()

        results: list[MemoryAnalysisResponse] = []
        for row in rows:
            try:
                import json as _json
                record = MemoryAnalysisResponse.model_validate(_json.loads(row["result_json"]))
                verified = ensure_integrity(record)
                # Scope filter applied in-process (capabilities stored inside JSON blob)
                if scope is not None and scope not in verified.capabilities.allowed_scopes:
                    continue
                results.append(verified)
            except Exception:
                # Skip tampered or malformed rows
                continue

        return results

    def clear(self) -> None:
        """Delete all records; intended for tests and local demo resets."""

        with self._lock, self._connect() as connection:
            connection.execute("DELETE FROM analyses")
            connection.commit()
