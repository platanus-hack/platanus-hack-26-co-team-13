"""SQLite persistence for signed memory envelopes and audit evidence."""

from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from secrets import token_hex, token_urlsafe
from threading import RLock

from .crypto import canonical_bytes, ensure_integrity, sign_ledger_event, verify_ledger_event
from .schemas import LedgerEventView, MemoryAnalysisResponse

_GENESIS_HASH = "0" * 64

#: Columns of ``ledger_events`` that belong to the signed, canonical event view.
#: ``decision`` is deliberately excluded: it is dashboard indexing metadata and
#: must never influence the hash chain or the Ed25519 signature.
_LEDGER_VIEW_COLUMNS = (
    "seq",
    "event_id",
    "event_type",
    "object_id",
    "actor_id",
    "tenant_id",
    "payload_hash",
    "previous_hash",
    "event_hash",
    "signature",
    "created_at",
)


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
                    tenant_id TEXT NOT NULL,
                    payload_hash TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL,
                    signature TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    decision TEXT
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS viewer_users (
                    username TEXT PRIMARY KEY,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    tenant_id TEXT NOT NULL DEFAULT 'default',
                    workspace_key_hash TEXT NOT NULL DEFAULT ''
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS viewer_sessions (
                    token_hash TEXT PRIMARY KEY,
                    username TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (username) REFERENCES viewer_users(username) ON DELETE CASCADE
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS high_risk_grants (
                    grant_id TEXT PRIMARY KEY,
                    analysis_id TEXT UNIQUE NOT NULL,
                    tenant_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    scope TEXT NOT NULL,
                    args_hash TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    consumed_at INTEGER,
                    consumed_request_id TEXT
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS viewer_sessions_expires_at ON viewer_sessions(expires_at)"
            )
            # Accounts are identified by email. Legacy rows whose username is
            # not an email address can never log in again, so they are purged
            # together with their sessions. The FK cascade cannot be relied on
            # (the ``foreign_keys`` pragma is not enabled), hence the explicit
            # session cleanup. Idempotent: runs on every open.
            legacy_ids = [
                row["username"]
                for row in connection.execute(
                    "SELECT username FROM viewer_users WHERE username NOT LIKE '%_@_%._%'"
                ).fetchall()
            ]
            for legacy_id in legacy_ids:
                connection.execute(
                    "DELETE FROM viewer_sessions WHERE username = ?", (legacy_id,)
                )
                connection.execute(
                    "DELETE FROM viewer_users WHERE username = ?", (legacy_id,)
                )
            columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(ledger_events)").fetchall()
            }
            if "tenant_id" not in columns:
                connection.execute(
                    "ALTER TABLE ledger_events ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default'"
                )
            if "decision" not in columns:
                # Nullable, unsigned indexing metadata for the workspace dashboard.
                connection.execute("ALTER TABLE ledger_events ADD COLUMN decision TEXT")
            viewer_columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(viewer_users)").fetchall()
            }
            if "tenant_id" not in viewer_columns:
                # SQLite forces a constant default, so every legacy row would
                # land on the same tenant and its owners would see each other's
                # evidence. Add the column with an empty sentinel, then give
                # each existing account its own unpredictable workspace.
                connection.execute(
                    "ALTER TABLE viewer_users ADD COLUMN tenant_id TEXT NOT NULL DEFAULT ''"
                )
                legacy_usernames = [
                    row["username"]
                    for row in connection.execute(
                        "SELECT username FROM viewer_users WHERE tenant_id = ''"
                    ).fetchall()
                ]
                for username in legacy_usernames:
                    connection.execute(
                        "UPDATE viewer_users SET tenant_id = ? WHERE username = ?",
                        (f"ws_{token_hex(8)}", username),
                    )
            if "workspace_key_hash" not in viewer_columns:
                # SQLite requires a non-null default when adding a NOT NULL column.
                # Legacy rows migrate to the empty sentinel, which can never equal
                # a sha256 digest, so they hold no usable agent credential until
                # the owner rotates one in.
                connection.execute(
                    "ALTER TABLE viewer_users "
                    "ADD COLUMN workspace_key_hash TEXT NOT NULL DEFAULT ''"
                )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS ledger_events_tenant_id ON ledger_events(tenant_id)"
            )
            # Partial unique index: real key hashes must be unique, while the
            # empty migration sentinel may repeat across legacy rows.
            connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS viewer_users_workspace_key_hash "
                "ON viewer_users(workspace_key_hash) WHERE workspace_key_hash != ''"
            )
            connection.commit()

    def _append_event(
        self,
        connection: sqlite3.Connection,
        *,
        event_type: str,
        object_id: str,
        actor_id: str,
        tenant_id: str,
        payload_hash: str,
        decision: str | None = None,
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
            "tenant_id": tenant_id,
            "payload_hash": payload_hash,
            "previous_hash": previous_hash,
            "created_at": created_at.isoformat(),
        }
        event_hash = hashlib.sha256(canonical_bytes(event_payload)).hexdigest()
        signature = sign_ledger_event({**event_payload, "event_hash": event_hash})
        # ``decision`` is appended as an extra, unsigned column only: it is not
        # part of ``event_payload`` and therefore not part of ``event_hash``.
        cursor = connection.execute(
            """
            INSERT INTO ledger_events
                (event_id, event_type, object_id, actor_id, tenant_id, payload_hash,
                 previous_hash, event_hash, signature, created_at, decision)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                event_type,
                object_id,
                actor_id,
                tenant_id,
                payload_hash,
                previous_hash,
                event_hash,
                signature,
                created_at.isoformat(),
                decision,
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
                    tenant_id=result.tenant_id or "default",
                    payload_hash=result.content_hash,
                )
            connection.commit()

    def append_event(
        self,
        *,
        event_type: str,
        object_id: str,
        actor_id: str,
        tenant_id: str,
        payload_hash: str,
        decision: str | None = None,
    ) -> LedgerEventView:
        """Append a non-envelope event, such as an action decision.

        ``decision`` is optional, unsigned indexing metadata used by the
        workspace dashboard. It never enters the canonical signed payload.
        """

        with self._lock, self._connect() as connection:
            event = self._append_event(
                connection,
                event_type=event_type,
                object_id=object_id,
                actor_id=actor_id,
                tenant_id=tenant_id,
                payload_hash=payload_hash,
                decision=decision,
            )
            connection.commit()
            return event

    def register_high_risk_grant(
        self,
        *,
        grant_id: str,
        analysis_id: str,
        tenant_id: str,
        action: str,
        scope: str,
        args_hash: str,
        expires_at: int,
    ) -> None:
        """Persist the one-shot state for a grant already signed in an envelope."""

        with self._lock, self._connect() as connection:
            connection.execute(
                """
                INSERT INTO high_risk_grants
                    (grant_id, analysis_id, tenant_id, action, scope, args_hash, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (grant_id, analysis_id, tenant_id, action, scope, args_hash, expires_at),
            )
            connection.commit()

    def high_risk_grant_available(
        self,
        *,
        grant_id: str,
        analysis_id: str,
        tenant_id: str,
        action: str,
        scope: str,
        args_hash: str,
    ) -> bool:
        """Return whether an exact signed grant remains live and unconsumed."""

        now = int(datetime.now(timezone.utc).timestamp())
        with self._lock, self._connect() as connection:
            row = connection.execute(
                """
                SELECT 1 FROM high_risk_grants
                WHERE grant_id = ? AND analysis_id = ? AND tenant_id = ?
                  AND action = ? AND scope = ? AND args_hash = ?
                  AND expires_at > ? AND consumed_at IS NULL
                """,
                (grant_id, analysis_id, tenant_id, action, scope, args_hash, now),
            ).fetchone()
        return row is not None

    def consume_high_risk_grants(
        self,
        *,
        grant_ids: list[str],
        tenant_id: str,
        request_id: str,
    ) -> bool:
        """Atomically consume every grant needed for one high-risk execution."""

        unique_ids = list(dict.fromkeys(grant_ids))
        if not unique_ids:
            return False
        now = int(datetime.now(timezone.utc).timestamp())
        placeholders = ",".join("?" for _ in unique_ids)
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                f"SELECT grant_id FROM high_risk_grants WHERE grant_id IN ({placeholders}) "
                "AND tenant_id = ? AND expires_at > ? AND consumed_at IS NULL",
                (*unique_ids, tenant_id, now),
            ).fetchall()
            if {row["grant_id"] for row in rows} != set(unique_ids):
                connection.rollback()
                return False
            connection.execute(
                f"UPDATE high_risk_grants SET consumed_at = ?, consumed_request_id = ? "
                f"WHERE grant_id IN ({placeholders})",
                (now, request_id, *unique_ids),
            )
            connection.commit()
        return True

    def get(self, analysis_id: str) -> MemoryAnalysisResponse | None:
        """Return a verified response or ``None`` when it does not exist."""

        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT result_json FROM analyses WHERE analysis_id = ?", (analysis_id,)
            ).fetchone()
        if row is None:
            return None
        return ensure_integrity(MemoryAnalysisResponse.model_validate(json.loads(row["result_json"])))

    def list_events(self, tenant_id: str, limit: int = 50) -> list[LedgerEventView]:
        """Return newest ledger events owned by one tenant/workspace."""

        columns = ", ".join(_LEDGER_VIEW_COLUMNS)
        with self._lock, self._connect() as connection:
            rows = connection.execute(
                f"SELECT {columns} FROM ledger_events "
                "WHERE tenant_id = ? ORDER BY seq DESC LIMIT ?",
                (tenant_id, limit),
            ).fetchall()
        return [LedgerEventView.model_validate(dict(row)) for row in rows]

    def workspace_stats(self, tenant_id: str) -> dict[str, object]:
        """Aggregate one workspace's ledger activity for the dashboard.

        Counts are computed with SQL aggregates over ``ledger_events`` filtered
        by ``tenant_id``, so one workspace can never observe another's volume.
        """

        with self._lock, self._connect() as connection:
            row = connection.execute(
                """
                SELECT
                    COUNT(*) AS total_events,
                    COALESCE(SUM(CASE WHEN decision = 'block' THEN 1 ELSE 0 END), 0)
                        AS blocked_actions,
                    COALESCE(SUM(CASE WHEN decision = 'allow' THEN 1 ELSE 0 END), 0)
                        AS allowed_actions,
                    COALESCE(SUM(CASE WHEN event_type = 'WRITE' THEN 1 ELSE 0 END), 0)
                        AS memories_written,
                    MAX(created_at) AS last_event_at
                FROM ledger_events
                WHERE tenant_id = ?
                """,
                (tenant_id,),
            ).fetchone()
        return {
            "total_events": int(row["total_events"] or 0),
            "blocked_actions": int(row["blocked_actions"] or 0),
            "allowed_actions": int(row["allowed_actions"] or 0),
            "memories_written": int(row["memories_written"] or 0),
            "last_event_at": row["last_event_at"],
        }

    def list_analyses(
        self,
        *,
        tenant_id: str,
        scope: str | None = None,
        source: str | None = None,
        limit: int = 50,
    ) -> list[MemoryAnalysisResponse]:
        """Return verified envelopes owned by one tenant and matching filters."""

        with self._lock, self._connect() as connection:
            rows = connection.execute("SELECT result_json FROM analyses ORDER BY created_at DESC").fetchall()
        results: list[MemoryAnalysisResponse] = []
        for row in rows:
            result = ensure_integrity(MemoryAnalysisResponse.model_validate(json.loads(row["result_json"])))
            if result.tenant_id != tenant_id:
                continue
            if scope is not None and scope not in result.capabilities.allowed_scopes:
                continue
            if source is not None and result.source != source:
                continue
            results.append(result)
            if len(results) == limit:
                break
        return results

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
                "tenant_id": row["tenant_id"],
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

    def create_viewer_user(
        self,
        username: str,
        password_hash: str,
        tenant_id: str = "default",
        workspace_key_hash: str = "",
    ) -> bool:
        """Create a unique control-plane user bound to its own workspace.

        ``workspace_key_hash`` is the sha256 digest of the agent workspace key.
        The plaintext key is never accepted or stored here.
        """

        try:
            with self._lock, self._connect() as connection:
                connection.execute(
                    """
                    INSERT INTO viewer_users
                        (username, password_hash, created_at, tenant_id, workspace_key_hash)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        username,
                        password_hash,
                        datetime.now(timezone.utc).isoformat(),
                        tenant_id,
                        workspace_key_hash,
                    ),
                )
                connection.commit()
        except sqlite3.IntegrityError:
            return False
        return True

    def set_workspace_key_hash(self, username: str, key_hash: str) -> bool:
        """Replace the stored agent key digest, invalidating the previous key.

        Returns ``False`` when the user does not exist or the digest collides
        with another workspace, so rotation can never silently no-op.
        """

        if not key_hash:
            return False
        try:
            with self._lock, self._connect() as connection:
                cursor = connection.execute(
                    "UPDATE viewer_users SET workspace_key_hash = ? WHERE username = ?",
                    (key_hash, username),
                )
                connection.commit()
        except sqlite3.IntegrityError:
            return False
        return cursor.rowcount == 1

    def get_tenant_by_workspace_key_hash(self, key_hash: str) -> str | None:
        """Resolve the workspace owning an agent key digest, or ``None``.

        The lookup uses the unique index on ``workspace_key_hash`` and confirms
        the match with ``hmac.compare_digest`` so a partial-index or collation
        surprise can never widen the match. The empty sentinel used by migrated
        rows is rejected up front (fail closed).
        """

        if not key_hash:
            return None
        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT tenant_id, workspace_key_hash FROM viewer_users "
                "WHERE workspace_key_hash = ?",
                (key_hash,),
            ).fetchone()
        if row is None:
            return None
        if not hmac.compare_digest(str(row["workspace_key_hash"]), key_hash):
            return None
        tenant_id = row["tenant_id"]
        return tenant_id if tenant_id else None

    def get_viewer_tenant_id(self, username: str) -> str | None:
        """Return the workspace owned by a control-plane user."""

        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT tenant_id FROM viewer_users WHERE username = ?", (username,)
            ).fetchone()
        return row["tenant_id"] if row is not None else None

    def get_viewer_password_hash(self, username: str) -> str | None:
        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT password_hash FROM viewer_users WHERE username = ?", (username,)
            ).fetchone()
        return row["password_hash"] if row is not None else None

    def create_viewer_session(
        self, username: str, token_hash: str, expires_at: int
    ) -> None:
        now = int(datetime.now(timezone.utc).timestamp())
        with self._lock, self._connect() as connection:
            connection.execute("DELETE FROM viewer_sessions WHERE expires_at <= ?", (now,))
            connection.execute(
                """
                INSERT INTO viewer_sessions (token_hash, username, expires_at, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (token_hash, username, expires_at, datetime.now(timezone.utc).isoformat()),
            )
            connection.commit()

    def get_viewer_session(
        self, token_hash: str, now: int
    ) -> tuple[str, str, int] | None:
        """Return ``(username, tenant_id, expires_at)`` for a live session.

        Expired sessions are deleted and reported as missing (fail closed).
        Sessions whose user row disappeared are also treated as invalid because
        the inner join yields no row.
        """

        with self._lock, self._connect() as connection:
            row = connection.execute(
                """
                SELECT s.username AS username,
                       u.tenant_id AS tenant_id,
                       s.expires_at AS expires_at
                FROM viewer_sessions AS s
                JOIN viewer_users AS u ON u.username = s.username
                WHERE s.token_hash = ?
                """,
                (token_hash,),
            ).fetchone()
            if row is not None and row["expires_at"] <= now:
                connection.execute(
                    "DELETE FROM viewer_sessions WHERE token_hash = ?", (token_hash,)
                )
                connection.commit()
                return None
        if row is None:
            return None
        return row["username"], row["tenant_id"], row["expires_at"]

    def delete_viewer_session(self, token_hash: str) -> None:
        with self._lock, self._connect() as connection:
            connection.execute(
                "DELETE FROM viewer_sessions WHERE token_hash = ?", (token_hash,)
            )
            connection.commit()

    def clear(self) -> None:
        """Delete all records; intended for tests and local demo resets."""

        with self._lock, self._connect() as connection:
            connection.execute("DELETE FROM viewer_sessions")
            connection.execute("DELETE FROM viewer_users")
            connection.execute("DELETE FROM high_risk_grants")
            connection.execute("DELETE FROM analyses")
            connection.execute("DELETE FROM ledger_events")
            connection.commit()
