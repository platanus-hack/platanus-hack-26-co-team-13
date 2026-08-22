"""FastAPI app for deterministic security code analysis.

Threat model measures:
- Never executes analyzed code (regex/line analysis only).
- Input validated with Pydantic (length 1..100_000) + 413 for oversized bodies.
- Rejects NUL/control characters.
- In-memory per-IP rate limiting (10 req/min).
- Global error handler returns generic {"error": "analysis_failed"}.
- Max 100 findings per request.
"""

from __future__ import annotations

import os
import hashlib
import time
from collections import OrderedDict
from threading import RLock
from typing import Any

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator
from starlette.exceptions import HTTPException as StarletteHTTPException

from analyzer.detector import analyze_code
from memory_firewall.crypto import (
    canonical_bytes,
    IntegrityError,
    EPHEMERAL_SIGNING_KEY,
    PUBLIC_KEY_B64,
    SIGNING_KEY_ID,
    public_key_base64,
    sign_ledger_event,
)
from memory_firewall.admin_auth import require_admin
from memory_firewall.schemas import (
    ActionEvaluationRequest,
    ActionEvaluationResponse,
    ApprovalRequest,
    LedgerVerifyResponse,
    MemoryAnalysisResponse,
    MemoryAnalyzeRequest,
    MemoryDeriveRequest,
    MemoryRetrieveRequest,
    MemoryRetrieveResponse,
    Decision,
    DemoToolExecutionResponse,
    MemoryState,
    PublicLedgerEventView,
    RuntimeAdapterStatus,
    RuntimeBlockEventRequest,
    RuntimeHeartbeatRequest,
    RuntimeStatusResponse,
    ToolCallAuthorizationRequest,
    ToolCallAuthorizationResponse,
    ViewerLoginRequest,
    ViewerRegistrationRequest,
    ViewerSessionResponse,
)
from memory_firewall.service import MemoryFirewallService
from memory_firewall.store import AnalysisStore
from memory_firewall.tool_gateway import MemoryToolExecutionGateway
from memory_firewall.viewer_auth import (
    COOKIE_NAME,
    SESSION_TTL_SECONDS,
    authenticate_viewer,
    register_viewer,
    require_viewer,
    revoke_viewer_session,
)
from memory_firewall.provenance_ledger import ProvenanceLedger, Ed25519Handler
from memory_firewall.escalation import EscalationManager
from memory_firewall.langgraph_middleware import ProvenanceFirewallMiddleware
from memory_firewall.schemas import Authority
from api import provenance_routes

MAX_BODY_BYTES = 256 * 1024  # 256KB
RATE_LIMIT = int(os.getenv("MEMORY_FIREWALL_RATE_LIMIT", "0"))  # 0 = no limit (dev mode)
RATE_WINDOW_SECONDS = 60
MAX_TRACKED_IPS = 10_000

app = FastAPI(
    title="Security Code Analyzer",
    description="Deterministic (non-LLM) vulnerability detection for code snippets.",
    version="1.0.0",
)

_allowed_origins = [
    origin.strip()
    for origin in os.getenv(
        "MEMORY_FIREWALL_ALLOWED_ORIGINS",
        "http://localhost:3000,http://127.0.0.1:3000",
    ).split(",")
    if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)

# --- Middleware: reject oversized bodies with 413 ---


@app.middleware("http")
async def limit_body_size(request: Request, call_next: Any) -> Any:
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            if int(content_length) > MAX_BODY_BYTES:
                return JSONResponse(
                    status_code=413,
                    content={"error": "analysis_failed"},
                )
        except ValueError:
            return JSONResponse(status_code=400, content={"error": "analysis_failed"})
    return await call_next(request)


# --- In-memory rate limiting (per IP, sliding window, LRU-bounded) ---

_rate_buckets: OrderedDict[str, list[float]] = OrderedDict()
_rate_lock = RLock()
_auth_rate_buckets: OrderedDict[str, list[float]] = OrderedDict()
_auth_rate_lock = RLock()
AUTH_RATE_LIMIT = 10
_runtime_heartbeats: dict[str, float] = {}
_runtime_heartbeat_lock = RLock()
RUNTIME_HEARTBEAT_TTL_SECONDS = 30

_database_path = os.getenv("MEMORY_FIREWALL_DB_PATH", "memory_firewall.sqlite3")
if _database_path != ":memory:" and EPHEMERAL_SIGNING_KEY:
    raise RuntimeError(
        "Persistent SQLite requires MEMORY_FIREWALL_ED25519_PRIVATE_KEY; "
        "start the packaged server with `memory-firewall serve`."
    )
analysis_store = AnalysisStore(_database_path)
memory_firewall = MemoryFirewallService(analysis_store)


def _set_viewer_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        max_age=SESSION_TTL_SECONDS,
        httponly=True,
        secure=os.getenv("MEMORY_FIREWALL_COOKIE_SECURE", "0") == "1",
        samesite="lax",
        path="/",
    )


@app.post(
    "/api/v1/auth/register",
    response_model=ViewerSessionResponse,
    status_code=201,
)
def viewer_register(
    request: Request,
    response: Response,
    payload: ViewerRegistrationRequest,
) -> ViewerSessionResponse:
    if _is_auth_rate_limited(_client_ip(request)):
        raise HTTPException(status_code=429, detail="rate_limit_exceeded")
    username, token = register_viewer(
        analysis_store, payload.username, payload.password
    )
    _set_viewer_cookie(response, token)
    return ViewerSessionResponse(
        authenticated=True,
        username=username,
        expires_in_seconds=SESSION_TTL_SECONDS,
    )


@app.post("/api/v1/auth/login", response_model=ViewerSessionResponse)
def viewer_login(
    request: Request,
    response: Response,
    payload: ViewerLoginRequest,
) -> ViewerSessionResponse:
    if _is_auth_rate_limited(_client_ip(request)):
        raise HTTPException(status_code=429, detail="rate_limit_exceeded")
    username, token = authenticate_viewer(
        analysis_store, payload.username, payload.password
    )
    _set_viewer_cookie(response, token)
    return ViewerSessionResponse(
        authenticated=True,
        username=username,
        expires_in_seconds=SESSION_TTL_SECONDS,
    )


@app.get("/api/v1/auth/session", response_model=ViewerSessionResponse)
def viewer_session(request: Request) -> ViewerSessionResponse:
    username = require_viewer(request, analysis_store)
    return ViewerSessionResponse(
        authenticated=True,
        username=username,
        expires_in_seconds=SESSION_TTL_SECONDS,
    )


@app.post("/api/v1/auth/logout", status_code=204)
def viewer_logout(request: Request, response: Response) -> Response:
    revoke_viewer_session(request, analysis_store)
    response.delete_cookie(COOKIE_NAME, path="/", samesite="lax")
    response.status_code = 204
    return response


# --- Initialize Provenance Firewall ---
crypto_handler = Ed25519Handler()
provenance_ledger = ProvenanceLedger(entries=[], crypto_handler=crypto_handler)
escalation_manager = EscalationManager()
provenance_firewall = ProvenanceFirewallMiddleware(
    action_requirements={
        "read_ticket": Authority.UNTRUSTED,
        "search_kb": Authority.UNTRUSTED,
        "send_email_internal": Authority.USER_CONFIRMED,
        "send_file_external": Authority.ORG_VERIFIED,
        "delete_user": Authority.ORG_VERIFIED,
        "export_database": Authority.SYSTEM_AUTHORITY,
    },
    escalation_manager=escalation_manager,
    ledger=provenance_ledger,
    agent_id="agent:supportbot",
)

# Wire firewall to API routes
provenance_routes.set_firewall_instances(
    ledger=provenance_ledger,
    escalation_manager=escalation_manager,
    middleware=provenance_firewall,
)
app.include_router(provenance_routes.router)


def _client_ip(request: Request) -> str:
    # Trust ONLY the connection IP. X-Forwarded-For is client-controlled and
    # would let attackers rotate fake IPs to evade the rate limit (there is
    # no reverse proxy in front of this service).
    return request.client.host if request.client else "unknown"


def _is_auth_rate_limited(client_ip: str) -> bool:
    now = time.monotonic()
    cutoff = now - RATE_WINDOW_SECONDS
    with _auth_rate_lock:
        timestamps = [
            timestamp
            for timestamp in _auth_rate_buckets.get(client_ip, [])
            if timestamp > cutoff
        ]
        if len(timestamps) >= AUTH_RATE_LIMIT:
            _auth_rate_buckets[client_ip] = timestamps
            return True
        timestamps.append(now)
        _auth_rate_buckets[client_ip] = timestamps
        _auth_rate_buckets.move_to_end(client_ip)
        while len(_auth_rate_buckets) > MAX_TRACKED_IPS:
            _auth_rate_buckets.popitem(last=False)
    return False


def _evict_stale_ips() -> None:
    """Bound memory: drop least-recently-used IPs beyond MAX_TRACKED_IPS."""
    while len(_rate_buckets) > MAX_TRACKED_IPS:
        _rate_buckets.popitem(last=False)


def _is_rate_limited(ip: str) -> bool:
     if RATE_LIMIT == 0:
         return False  # Rate limiting disabled for development
     with _rate_lock:
         now = time.monotonic()
         bucket = [ts for ts in _rate_buckets.get(ip, []) if now - ts < RATE_WINDOW_SECONDS]
         if len(bucket) >= RATE_LIMIT:
             _rate_buckets[ip] = bucket
             _rate_buckets.move_to_end(ip)
             _evict_stale_ips()
             return True
         bucket.append(now)
         _rate_buckets[ip] = bucket
         _rate_buckets.move_to_end(ip)
         _evict_stale_ips()
         return False


# --- Schemas ---


class AnalyzeRequest(BaseModel):
    code: str = Field(..., min_length=1, max_length=100_000, description="Code snippet to analyze")

    @field_validator("code")
    @classmethod
    def reject_control_chars(cls, v: str) -> str:
        if "\x00" in v:
            raise ValueError("NUL characters not allowed")
        # Reject control chars except \n, \r, \t
        for ch in v:
            if ord(ch) < 32 and ch not in "\n\r\t":
                raise ValueError("Control characters not allowed")
        return v


# --- Endpoints ---


@app.post("/api/v1/analyze")
def analyze(request: Request, payload: AnalyzeRequest) -> dict:
    ip = _client_ip(request)
    if _is_rate_limited(ip):
        return JSONResponse(
            status_code=429,
            content={"error": "rate_limit_exceeded"},
        )
    return analyze_code(payload.code)


@app.post("/api/v1/memory/analyze", response_model=MemoryAnalysisResponse)
def analyze_memory(
    request: Request, payload: MemoryAnalyzeRequest
) -> MemoryAnalysisResponse | JSONResponse:
    """Analyze memory/context before it can be used by an agent."""

    if _is_rate_limited(_client_ip(request)):
        return JSONResponse(
            status_code=429,
            content={"error": "rate_limit_exceeded"},
        )
    return memory_firewall.analyze(payload)


@app.post("/api/v1/memory/evaluate-write", response_model=MemoryAnalysisResponse)
def evaluate_memory_write(
    request: Request, payload: MemoryAnalyzeRequest
) -> MemoryAnalysisResponse | JSONResponse:
    """Preview a signed memory decision without storing it or adding a ledger event."""

    if _is_rate_limited(_client_ip(request)):
        return JSONResponse(status_code=429, content={"error": "rate_limit_exceeded"})
    return memory_firewall.analyze_preview(payload)


@app.post("/api/v1/memory/derive", response_model=MemoryAnalysisResponse)
def derive_memory(
    request: Request, payload: MemoryDeriveRequest
) -> MemoryAnalysisResponse | JSONResponse:
    """Create a derived memory while preserving parent authority."""

    if _is_rate_limited(_client_ip(request)):
        return JSONResponse(
            status_code=429,
            content={"error": "rate_limit_exceeded"},
        )
    try:
        return memory_firewall.derive(payload)
    except LookupError:
        raise HTTPException(status_code=404, detail="parent_analysis_not_found") from None


@app.post("/api/v1/memory/retrieve", response_model=MemoryRetrieveResponse)
def retrieve_memory(
    request: Request, payload: MemoryRetrieveRequest
) -> MemoryRetrieveResponse | JSONResponse:
    """Retrieve signed memory and append a session-correlated custody event."""

    if _is_rate_limited(_client_ip(request)):
        return JSONResponse(status_code=429, content={"error": "rate_limit_exceeded"})
    try:
        return memory_firewall.retrieve(payload)
    except LookupError:
        raise HTTPException(status_code=404, detail="analysis_not_found") from None


@app.post("/api/v1/actions/evaluate", response_model=ActionEvaluationResponse)
def evaluate_action(
    request: Request, payload: ActionEvaluationRequest
) -> ActionEvaluationResponse | JSONResponse:
    """Evaluate whether memory evidence can authorize a high-risk action."""

    if _is_rate_limited(_client_ip(request)):
        return JSONResponse(
            status_code=429,
            content={"error": "rate_limit_exceeded"},
        )
    try:
        return memory_firewall.evaluate_action(payload)
    except LookupError:
        raise HTTPException(status_code=404, detail="analysis_not_found") from None


@app.post(
    "/api/v1/firewall/tool-calls/authorize",
    response_model=ToolCallAuthorizationResponse,
)
def authorize_native_tool_call(
    request: Request, payload: ToolCallAuthorizationRequest
) -> ToolCallAuthorizationResponse | JSONResponse:
    """Authorize a native pre-tool hook from signed cross-session evidence."""

    if _is_rate_limited(_client_ip(request)):
        return JSONResponse(status_code=429, content={"error": "rate_limit_exceeded"})
    try:
        return memory_firewall.authorize_tool_call(payload)
    except LookupError:
        raise HTTPException(status_code=404, detail="analysis_not_found") from None
    except ValueError:
        raise HTTPException(status_code=422, detail="invalid_lineage") from None


@app.post(
    "/api/v1/demo/tool-calls/execute",
    response_model=DemoToolExecutionResponse,
)
def execute_synthetic_demo_tool(
    request: Request, payload: ToolCallAuthorizationRequest
) -> DemoToolExecutionResponse | JSONResponse:
    """Run the synthetic callable through the same signed-memory gateway used by tests."""

    if _is_rate_limited(_client_ip(request)):
        return JSONResponse(status_code=429, content={"error": "rate_limit_exceeded"})
    invocations = 0

    def synthetic_pay_invoice(**_arguments: Any) -> None:
        nonlocal invocations
        invocations += 1

    gateway = MemoryToolExecutionGateway(
        memory_firewall,
        {"PAY_INVOICE": synthetic_pay_invoice},
    )
    try:
        outcome = gateway.execute(payload)
    except LookupError:
        raise HTTPException(status_code=404, detail="analysis_not_found") from None
    except ValueError:
        raise HTTPException(status_code=422, detail="invalid_lineage") from None
    return DemoToolExecutionResponse(
        authorization=outcome.decision,
        executed=outcome.executed,
        function_invocations=invocations,
    )


@app.post("/api/v1/approvals", response_model=MemoryAnalysisResponse)
def approve_memory(
    request: Request, payload: ApprovalRequest
) -> MemoryAnalysisResponse | JSONResponse:
    """Create an immutable, signed authority elevation from explicit approval."""

    if _is_rate_limited(_client_ip(request)):
        return JSONResponse(status_code=429, content={"error": "rate_limit_exceeded"})
    authenticated_approver = require_admin(request, payload.tenant_id)
    if payload.approver_id != authenticated_approver:
        raise HTTPException(status_code=403, detail="approver_identity_mismatch")
    try:
        return memory_firewall.approve(payload)
    except PermissionError:
        raise HTTPException(status_code=403, detail="approver_not_authorized") from None
    except LookupError:
        raise HTTPException(status_code=404, detail="analysis_not_found") from None
    except ValueError:
        raise HTTPException(status_code=422, detail="invalid_approval") from None


@app.get("/api/v1/analyses/{analysis_id}", response_model=MemoryAnalysisResponse)
def get_analysis(
    analysis_id: str, request: Request, tenant_id: str = "default"
) -> MemoryAnalysisResponse:
    """Retrieve a sanitized analysis result by id."""

    if _is_rate_limited(_client_ip(request)):
        raise HTTPException(status_code=429, detail="rate_limit_exceeded")
    if len(analysis_id) > 64:
        raise HTTPException(status_code=404, detail="analysis_not_found")
    try:
        result = memory_firewall.get_analysis(analysis_id, tenant_id=tenant_id)
    except IntegrityError:
        raise HTTPException(status_code=500, detail="analysis_failed") from None
    except LookupError:
        raise HTTPException(status_code=404, detail="analysis_not_found") from None
    if result is None:
        raise HTTPException(status_code=404, detail="analysis_not_found")
    return result


@app.get("/api/v1/memory/search", response_model=list[MemoryAnalysisResponse])
def search_memories(
    request: Request,
    tenant_id: str = "default",
    scope: str | None = None,
    source: str | None = None,
    limit: int = 50,
) -> list[MemoryAnalysisResponse]:
    """Search verified memory envelopes without crossing tenant boundaries."""

    if _is_rate_limited(_client_ip(request)):
        raise HTTPException(status_code=429, detail="rate_limit_exceeded")
    require_admin(request, tenant_id)
    if limit < 1 or limit > 100:
        raise HTTPException(status_code=422, detail="invalid_limit")
    try:
        return analysis_store.list_analyses(
            tenant_id=tenant_id, scope=scope, source=source, limit=limit
        )
    except IntegrityError:
        raise HTTPException(status_code=500, detail="analysis_failed") from None


@app.get("/api/v1/ledger/verify", response_model=LedgerVerifyResponse)
def verify_ledger(request: Request) -> LedgerVerifyResponse:
    """Verify all hash-chain links and Ed25519 signatures (Appendix A.7)."""

    if _is_rate_limited(_client_ip(request)):
        raise HTTPException(status_code=429, detail="rate_limit_exceeded")
    valid, events_checked, first_invalid_event = analysis_store.verify_chain()
    return LedgerVerifyResponse(
        valid=valid,
        events_checked=events_checked,
        first_invalid_event=first_invalid_event,
    )


@app.get("/api/v1/ledger/events", response_model=list[PublicLedgerEventView])
def list_ledger_events(
    request: Request, tenant_id: str = "default", limit: int = 50
) -> list[PublicLedgerEventView]:
    """Return recent evidence for the dashboard timeline."""

    if _is_rate_limited(_client_ip(request)):
        raise HTTPException(status_code=429, detail="rate_limit_exceeded")
    require_viewer(request, analysis_store)
    if limit < 1 or limit > 100:
        raise HTTPException(status_code=422, detail="invalid_limit")
    projections: list[PublicLedgerEventView] = []
    for event in analysis_store.list_events(tenant_id, limit):
        projection = PublicLedgerEventView(
            seq=event.seq,
            event_id=event.event_id,
            event_type=event.event_type,
            object_ref="object_"
            + hashlib.sha256(event.object_id.encode("utf-8")).hexdigest()[:16],
            actor_ref="actor_"
            + hashlib.sha256(event.actor_id.encode("utf-8")).hexdigest()[:16],
            tenant_id=event.tenant_id,
            source_event_hash=event.event_hash,
            projection_signature="unsigned",
            created_at=event.created_at,
        )
        payload = projection.model_dump(mode="json", exclude={"projection_signature"})
        projections.append(
            projection.model_copy(
                update={"projection_signature": sign_ledger_event(payload)}
            )
        )
    return projections


@app.get("/api/v1/keys/current")
async def current_signing_key() -> dict:
    """Expose the public verification key.

    Any verifier (dashboard, adapter, judge) can validate envelope signatures
    with this key alone; it grants no signing capability.
    """

    return {
        "key_id": SIGNING_KEY_ID,
        "algorithm": "Ed25519",
        "public_key_base64": public_key_base64(),
    }


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@app.get("/api/v1/health")
async def api_health() -> dict:
    return {"status": "ok", "service": "memory-firewall"}


@app.get("/api/v1/runtime/status", response_model=RuntimeStatusResponse)
async def runtime_status() -> RuntimeStatusResponse:
    """Report shipped adapters and only recently observed live runtimes."""

    now = time.monotonic()
    with _runtime_heartbeat_lock:
        expired = [
            name
            for name, last_seen in _runtime_heartbeats.items()
            if now - last_seen > RUNTIME_HEARTBEAT_TTL_SECONDS
        ]
        for name in expired:
            _runtime_heartbeats.pop(name, None)
        live_connections = sorted(_runtime_heartbeats)

    return RuntimeStatusResponse(
        service="memory-firewall",
        core_status="live",
        memory_store="sqlite",
        execution_boundary="native pre-tool hook",
        adapters=[
            RuntimeAdapterStatus(
                name="Pi",
                hook="tool_call",
                language="TypeScript",
                status="adapter_verified",
                install_command="memory-firewall install pi",
            ),
            RuntimeAdapterStatus(
                name="Hermes",
                hook="pre_tool_call",
                language="Python",
                status="adapter_verified",
                install_command="memory-firewall install hermes",
            ),
            RuntimeAdapterStatus(
                name="OpenClaw",
                hook="before_tool_call",
                language="TypeScript",
                status="adapter_verified",
                install_command="memory-firewall install openclaw",
            ),
        ],
        live_connections=live_connections,
    )


@app.post("/api/v1/runtime/connections/heartbeat", status_code=204)
async def runtime_heartbeat(payload: RuntimeHeartbeatRequest) -> Response:
    """Record an adapter heartbeat with a bounded in-memory TTL."""

    with _runtime_heartbeat_lock:
        _runtime_heartbeats[payload.runtime.name] = time.monotonic()
    return Response(status_code=204)


@app.post("/api/v1/runtime/tool-blocks", status_code=204)
async def record_runtime_tool_block(
    request: Request, payload: RuntimeBlockEventRequest
) -> Response:
    """Persist a sanitized audit event for a fail-closed adapter decision."""

    if _is_rate_limited(_client_ip(request)):
        raise HTTPException(status_code=429, detail="rate_limit_exceeded")
    event_payload = payload.model_dump(mode="json")
    analysis_store.append_event(
        event_type="TOOL_BLOCKED_LOCAL",
        object_id=payload.session.tool_call_id or payload.session.id,
        actor_id=payload.actor.id,
        tenant_id=payload.tenant_id,
        payload_hash=hashlib.sha256(canonical_bytes(event_payload)).hexdigest(),
    )
    return Response(status_code=204)


# --- Error handling: never leak internals ---


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    return JSONResponse(status_code=500, content={"error": "analysis_failed"})


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    if exc.status_code == 404:
        return JSONResponse(status_code=404, content={"error": "analysis_not_found"})
    if exc.status_code == 429:
        return JSONResponse(status_code=429, content={"error": "rate_limit_exceeded"})
    return JSONResponse(status_code=exc.status_code, content={"error": "analysis_failed"})


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    # Do not echo submitted content or internal model details in the API error.
    return JSONResponse(status_code=422, content={"error": "invalid_request"})


if __name__ == "__main__":  # pragma: no cover
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
