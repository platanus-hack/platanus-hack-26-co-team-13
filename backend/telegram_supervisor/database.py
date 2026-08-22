"""Database persistence layer for Telegram Supervisor Bot."""

import sqlite3
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any

logger = logging.getLogger(__name__)


class TelegramBotDatabase:
    """SQLite database for Telegram bot alerts and approvals."""

    def __init__(self, db_path: str = "telegram_bot.sqlite3"):
        """Initialize database connection.
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = Path(db_path)
        self.connection = None
        self._init_db()

    def _init_db(self):
        """Initialize database schema."""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            # Alerts table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    content_preview TEXT,
                    full_content TEXT,
                    source TEXT,
                    threats_detected TEXT,  -- JSON array
                    threat_score REAL,
                    authority_assigned TEXT,
                    analysis_id TEXT,
                    analysis_metadata TEXT,  -- JSON
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Approvals table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS approvals (
                    request_id TEXT PRIMARY KEY,
                    alert_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    approved_by TEXT,
                    decision_timestamp TEXT,
                    reason TEXT,
                    approval_token TEXT NOT NULL,
                    FOREIGN KEY (alert_id) REFERENCES alerts (alert_id)
                )
            """)
            
            # Reports table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS reports (
                    report_id TEXT PRIMARY KEY,
                    generated_at TEXT NOT NULL,
                    period_start TEXT NOT NULL,
                    period_end TEXT NOT NULL,
                    total_alerts INTEGER,
                    critical_alerts INTEGER,
                    high_alerts INTEGER,
                    medium_alerts INTEGER,
                    low_alerts INTEGER,
                    total_approved INTEGER,
                    total_rejected INTEGER,
                    pending_approvals INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            conn.commit()
            conn.close()
            logger.info(f"Database initialized: {self.db_path}")
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
            raise

    def _get_connection(self) -> sqlite3.Connection:
        """Get database connection."""
        if self.connection is None:
            self.connection = sqlite3.connect(str(self.db_path))
            self.connection.row_factory = sqlite3.Row
        return self.connection

    def close(self):
        """Close database connection."""
        if self.connection:
            self.connection.close()
            self.connection = None

    # --- Alerts ---

    def save_alert(self, alert: Dict[str, Any]) -> bool:
        """Save alert to database."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT OR REPLACE INTO alerts
                (alert_id, timestamp, severity, content_preview, full_content, source,
                 threats_detected, threat_score, authority_assigned, analysis_id, analysis_metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert.get("alert_id"),
                alert.get("timestamp"),
                alert.get("severity"),
                alert.get("content_preview"),
                alert.get("full_content"),
                alert.get("source"),
                json.dumps(alert.get("threats_detected", [])),
                alert.get("threat_score"),
                alert.get("authority_assigned"),
                alert.get("analysis_id"),
                json.dumps(alert.get("analysis_metadata", {})),
            ))
            
            conn.commit()
            logger.debug(f"Alert saved: {alert.get('alert_id')}")
            return True
        except Exception as e:
            logger.error(f"Failed to save alert: {e}")
            return False

    def get_alert(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """Get alert by ID."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,))
            row = cursor.fetchone()
            
            if row:
                return dict(row)
            return None
        except Exception as e:
            logger.error(f"Failed to get alert: {e}")
            return None

    def get_recent_alerts(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent alerts."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT * FROM alerts
                ORDER BY created_at DESC
                LIMIT ?
            """, (limit,))
            
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
        except Exception as e:
            logger.error(f"Failed to get recent alerts: {e}")
            return []

    def get_alerts_by_date(self, date: str) -> List[Dict[str, Any]]:
        """Get alerts from a specific date."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT * FROM alerts
                WHERE DATE(timestamp) = ?
                ORDER BY timestamp DESC
            """, (date,))
            
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
        except Exception as e:
            logger.error(f"Failed to get alerts by date: {e}")
            return []

    # --- Approvals ---

    def save_approval(self, approval: Dict[str, Any]) -> bool:
        """Save approval request to database."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT OR REPLACE INTO approvals
                (request_id, alert_id, created_at, expires_at, status,
                 approved_by, decision_timestamp, reason, approval_token)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                approval.get("request_id"),
                approval.get("alert_id"),
                approval.get("created_at"),
                approval.get("expires_at"),
                approval.get("status"),
                approval.get("approved_by"),
                approval.get("decision_timestamp"),
                approval.get("reason"),
                approval.get("approval_token"),
            ))
            
            conn.commit()
            logger.debug(f"Approval saved: {approval.get('request_id')}")
            return True
        except Exception as e:
            logger.error(f"Failed to save approval: {e}")
            return False

    def get_approval(self, request_id: str) -> Optional[Dict[str, Any]]:
        """Get approval by request ID."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("SELECT * FROM approvals WHERE request_id = ?", (request_id,))
            row = cursor.fetchone()
            
            if row:
                return dict(row)
            return None
        except Exception as e:
            logger.error(f"Failed to get approval: {e}")
            return None

    def get_approval_by_alert(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """Get approval request for an alert."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute(
                "SELECT * FROM approvals WHERE alert_id = ? ORDER BY created_at DESC LIMIT 1",
                (alert_id,)
            )
            row = cursor.fetchone()
            
            if row:
                return dict(row)
            return None
        except Exception as e:
            logger.error(f"Failed to get approval by alert: {e}")
            return None

    def get_pending_approvals(self) -> List[Dict[str, Any]]:
        """Get all pending approval requests."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT * FROM approvals
                WHERE status = 'pending'
                ORDER BY created_at DESC
            """)
            
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
        except Exception as e:
            logger.error(f"Failed to get pending approvals: {e}")
            return []

    def get_approval_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Get approval by token."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute(
                "SELECT * FROM approvals WHERE approval_token = ?",
                (token,)
            )
            row = cursor.fetchone()
            
            if row:
                return dict(row)
            return None
        except Exception as e:
            logger.error(f"Failed to get approval by token: {e}")
            return None

    # --- Reports ---

    def save_report(self, report: Dict[str, Any]) -> bool:
        """Save report to database."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO reports
                (report_id, generated_at, period_start, period_end,
                 total_alerts, critical_alerts, high_alerts, medium_alerts, low_alerts,
                 total_approved, total_rejected, pending_approvals)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                report.get("report_id"),
                report.get("generated_at"),
                report.get("period_start"),
                report.get("period_end"),
                report.get("total_alerts"),
                report.get("critical_alerts"),
                report.get("high_alerts"),
                report.get("medium_alerts"),
                report.get("low_alerts"),
                report.get("total_approved"),
                report.get("total_rejected"),
                report.get("pending_approvals"),
            ))
            
            conn.commit()
            logger.debug(f"Report saved: {report.get('report_id')}")
            return True
        except Exception as e:
            logger.error(f"Failed to save report: {e}")
            return False

    def get_recent_reports(self, limit: int = 7) -> List[Dict[str, Any]]:
        """Get recent reports (default: last 7 days)."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT * FROM reports
                ORDER BY generated_at DESC
                LIMIT ?
            """, (limit,))
            
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
        except Exception as e:
            logger.error(f"Failed to get recent reports: {e}")
            return []

    # --- Statistics ---

    def get_statistics(self, days: int = 7) -> Dict[str, Any]:
        """Get statistics for the last N days."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Total alerts
            cursor.execute("""
                SELECT COUNT(*) as total, 
                       SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical,
                       SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) as high,
                       SUM(CASE WHEN severity = 'MEDIUM' THEN 1 ELSE 0 END) as medium,
                       SUM(CASE WHEN severity = 'LOW' THEN 1 ELSE 0 END) as low
                FROM alerts
                WHERE DATE(timestamp) >= DATE('now', ? || ' days')
            """, (f"-{days}",))
            
            alert_stats = dict(cursor.fetchone() or {})
            
            # Approval stats
            cursor.execute("""
                SELECT COUNT(*) as total,
                       SUM(CASE WHEN status = 'APPROVED' THEN 1 ELSE 0 END) as approved,
                       SUM(CASE WHEN status = 'REJECTED' THEN 1 ELSE 0 END) as rejected,
                       SUM(CASE WHEN status = 'PENDING' THEN 1 ELSE 0 END) as pending
                FROM approvals
                WHERE DATE(created_at) >= DATE('now', ? || ' days')
            """, (f"-{days}",))
            
            approval_stats = dict(cursor.fetchone() or {})
            
            return {
                "period_days": days,
                "alerts": alert_stats,
                "approvals": approval_stats,
            }
        except Exception as e:
            logger.error(f"Failed to get statistics: {e}")
            return {}

    def get_top_threats(self, days: int = 7) -> List[tuple]:
        """Get top threats from the last N days."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT * FROM alerts
                WHERE DATE(timestamp) >= DATE('now', ? || ' days')
                ORDER BY timestamp DESC
            """, (f"-{days}",))
            
            rows = cursor.fetchall()
            
            threat_counts = {}
            for row in rows:
                threats = json.loads(row["threats_detected"] or "[]")
                for threat in threats:
                    threat_counts[threat] = threat_counts.get(threat, 0) + 1
            
            # Return as sorted list of (threat, count) tuples
            return sorted(threat_counts.items(), key=lambda x: x[1], reverse=True)
        except Exception as e:
            logger.error(f"Failed to get top threats: {e}")
            return []
