"""Telegram Supervisor Bot API routes."""

import hmac
import logging
import os
from fastapi import APIRouter, HTTPException, Query, Header, Depends
from pydantic import BaseModel
from typing import Optional

logger = logging.getLogger(__name__)


# --- API key authentication for state-changing endpoints ---
# Set TELEGRAM_API_KEY in the environment to protect POST endpoints.
# If unset, protected endpoints fail closed (return 503) to avoid
# accidentally exposing an open, unauthenticated control surface.
def require_api_key(x_api_key: Optional[str] = Header(default=None)) -> None:
    """Fail-closed API key check for sensitive (state-changing) endpoints."""
    expected = os.getenv("TELEGRAM_API_KEY", "")
    if not expected:
        # No key configured: refuse to serve the endpoint rather than
        # leaving it open to the public internet.
        raise HTTPException(
            status_code=503,
            detail="Endpoint disabled: TELEGRAM_API_KEY not configured",
        )
    if not x_api_key or not hmac.compare_digest(x_api_key, expected):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


# Request models
class SendAlertRequest(BaseModel):
    severity: str
    content_preview: str
    threats: list[str]
    threat_score: float
    source: str = "test"

router = APIRouter(prefix="/api/v1/telegram", tags=["telegram"])

# These will be set by main.py
supervisor = None
bridge = None


def set_supervisor(sup):
    """Set the supervisor instance."""
    global supervisor
    supervisor = sup


def set_bridge(b):
    """Set the bridge instance."""
    global bridge
    bridge = b


@router.get("/status")
async def get_status():
    """Get Telegram supervisor bot status."""
    if not supervisor:
        raise HTTPException(status_code=503, detail="Supervisor not initialized")

    try:
        # Get stats
        alerts = len(supervisor.alert_history)
        pending = len([r for r in supervisor.approval_requests.values() if r.status.value == "pending"])
        approved = len([r for r in supervisor.approval_requests.values() if r.status.value == "approved"])
        rejected = len([r for r in supervisor.approval_requests.values() if r.status.value == "rejected"])

        return {
            "status": "online" if supervisor.running else "offline",
            "total_alerts": alerts,
            "pending_approvals": pending,
            "approved_approvals": approved,
            "rejected_approvals": rejected,
            "telegram_connected": supervisor.running,
        }
    except Exception as e:
        logger.error(f"Error getting status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/alerts/pending")
async def get_pending_alerts(limit: int = Query(10, ge=1, le=100)):
    """Get pending quarantine alerts."""
    if not supervisor:
        raise HTTPException(status_code=503, detail="Supervisor not initialized")

    try:
        pending = supervisor.alert_queue[-limit:]
        return [
            {
                "alert_id": a.alert_id,
                "severity": a.severity.value,
                "threat_score": a.threat_score,
                "content_preview": a.content_preview,
                "source": a.source,
                "threats": a.threats_detected,
                "timestamp": a.timestamp.isoformat(),
            }
            for a in pending
        ]
    except Exception as e:
        logger.error(f"Error getting pending alerts: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/alerts/recent")
async def get_recent_alerts(limit: int = Query(10, ge=1, le=100)):
    """Get recent alerts from history."""
    if not supervisor:
        raise HTTPException(status_code=503, detail="Supervisor not initialized")

    try:
        recent = supervisor.alert_history[-limit:]
        return [
            {
                "alert_id": a.alert_id,
                "severity": a.severity.value,
                "threat_score": a.threat_score,
                "content_preview": a.content_preview,
                "source": a.source,
                "threats": a.threats_detected,
                "timestamp": a.timestamp.isoformat(),
            }
            for a in reversed(recent)
        ]
    except Exception as e:
        logger.error(f"Error getting recent alerts: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/alerts/{alert_id}")
async def get_alert_details(alert_id: str):
    """Get full details of a specific alert."""
    if not supervisor:
        raise HTTPException(status_code=503, detail="Supervisor not initialized")

    try:
        for alert in supervisor.alert_history:
            if alert.alert_id == alert_id:
                return {
                    "alert_id": alert.alert_id,
                    "severity": alert.severity.value,
                    "threat_score": alert.threat_score,
                    "content_preview": alert.content_preview,
                    "full_content": alert.full_content,
                    "source": alert.source,
                    "threats": alert.threats_detected,
                    "authority_assigned": alert.authority_assigned,
                    "timestamp": alert.timestamp.isoformat(),
                    "analysis_id": alert.analysis_id,
                }

        raise HTTPException(status_code=404, detail="Alert not found")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting alert details: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/approvals/pending")
async def get_pending_approvals(limit: int = Query(10, ge=1, le=100)):
    """Get pending approval requests."""
    if not supervisor:
        raise HTTPException(status_code=503, detail="Supervisor not initialized")

    try:
        pending = [
            r for r in supervisor.approval_requests.values()
            if r.status.value == "pending"
        ][-limit:]

        return [
            {
                "request_id": r.request_id,
                "alert_id": r.alert_id,
                "created_at": r.created_at.isoformat(),
                "expires_at": r.expires_at.isoformat(),
                "approval_token": r.approval_token[:10] + "..." if r.approval_token else None,
            }
            for r in pending
        ]
    except Exception as e:
        logger.error(f"Error getting pending approvals: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/approvals/{request_id}")
async def get_approval_request(request_id: str):
    """Get details of a specific approval request."""
    if not supervisor:
        raise HTTPException(status_code=503, detail="Supervisor not initialized")

    try:
        request = supervisor.approval_requests.get(request_id)
        if not request:
            raise HTTPException(status_code=404, detail="Approval request not found")

        return {
            "request_id": request.request_id,
            "alert_id": request.alert_id,
            "created_at": request.created_at.isoformat(),
            "expires_at": request.expires_at.isoformat(),
            "status": request.status.value,
            "approved_by": request.approved_by,
            "decision_timestamp": request.decision_timestamp.isoformat() if request.decision_timestamp else None,
            "reason": request.reason,
            "approval_token": request.approval_token[:10] + "..." if request.approval_token else None,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting approval request: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/approvals/{alert_id}/approve", dependencies=[Depends(require_api_key)])
async def approve_alert(alert_id: str, reason: Optional[str] = None):
    """Manually approve an alert via API. Requires X-API-Key header."""
    if not supervisor:
        raise HTTPException(status_code=503, detail="Supervisor not initialized")

    try:
        result = await supervisor.approve_alert(
            alert_id=alert_id,
            approved_by="api_user",
            reason=reason or "Approved via API",
        )

        if not result:
            raise HTTPException(status_code=404, detail="Alert not found")

        return {
            "success": True,
            "request_id": result.request_id,
            "approval_token": result.approval_token,
            "expires_at": result.expires_at.isoformat(),
        }
    except Exception as e:
        logger.error(f"Error approving alert: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/approvals/{alert_id}/reject", dependencies=[Depends(require_api_key)])
async def reject_alert(alert_id: str, reason: Optional[str] = None):
    """Manually reject an alert via API. Requires X-API-Key header."""
    if not supervisor:
        raise HTTPException(status_code=503, detail="Supervisor not initialized")

    try:
        result = await supervisor.reject_alert(
            alert_id=alert_id,
            rejected_by="api_user",
            reason=reason or "Rejected via API",
        )

        if not result:
            raise HTTPException(status_code=404, detail="Alert not found")

        return {
            "success": True,
            "request_id": result.request_id,
        }
    except Exception as e:
        logger.error(f"Error rejecting alert: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/report/daily")
async def get_daily_report():
    """Get today's report."""
    if not supervisor:
        raise HTTPException(status_code=503, detail="Supervisor not initialized")

    try:
        report = await supervisor.get_daily_report()

        return {
            "report_id": report.report_id,
            "period_start": report.period_start.isoformat(),
            "period_end": report.period_end.isoformat(),
            "total_alerts": report.total_alerts,
            "critical_alerts": report.critical_alerts,
            "high_alerts": report.high_alerts,
            "medium_alerts": report.medium_alerts,
            "low_alerts": report.low_alerts,
            "total_approved": report.total_approved,
            "total_rejected": report.total_rejected,
            "pending_approvals": report.pending_approvals,
        }
    except Exception as e:
        logger.error(f"Error getting daily report: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/send-alert", dependencies=[Depends(require_api_key)])
async def send_alert_manual(request: SendAlertRequest):
    """Manual alert sending for testing purposes. Requires X-API-Key header."""
    if not supervisor:
        raise HTTPException(status_code=503, detail="Supervisor not initialized")

    try:
        # Create and send alert
        await supervisor.telegram_client.send_alert(
            alert_id="test_" + str(len(supervisor.alert_history)),
            severity=request.severity.upper(),
            threat_score=request.threat_score,
            content_preview=request.content_preview,
            threats=request.threats,
            source=request.source,
        )

        return {"success": True, "message": "Alert sent to Telegram"}
    except Exception as e:
        logger.error(f"Error sending alert: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/send-report", dependencies=[Depends(require_api_key)])
async def send_report_manual():
    """Manually send today's report. Requires X-API-Key header."""
    if not supervisor:
        raise HTTPException(status_code=503, detail="Supervisor not initialized")

    try:
        await supervisor.send_daily_report()
        return {"success": True, "message": "Report sent to Telegram"}
    except Exception as e:
        logger.error(f"Error sending report: {e}")
        raise HTTPException(status_code=500, detail=str(e))
