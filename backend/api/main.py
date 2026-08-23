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
import re
import secrets
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
from memory_firewall.intent_judge import explain_decision
from memory_firewall.policy import ACTION_CONTRACTS, EFFECT_POLICIES
from memory_firewall.schemas import (
    ActionEvaluationRequest,
    ActionEvaluationResponse,
    ActorContext,
    ActorType,
    ApprovalRequest,
    DemoAgentAskRequest,
    DemoAgentAskResponse,
    DemoAgentStep,
    DemoEmailRequest,
    DemoEmailResponse,
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
    ToolDescriptor,
    ToolRuntime,
    ToolSession,
    ViewerLoginRequest,
    ViewerRegistrationRequest,
    ViewerSessionResponse,
    WorkspaceKeyResponse,
    WorkspaceStatsResponse,
)
from memory_firewall.cli import ADAPTER_INSTALL_COMMANDS, CLI_INSTALL_COMMAND
from memory_firewall.service import MemoryFirewallService
from memory_firewall.store import AnalysisStore
from memory_firewall.tool_gateway import MemoryToolExecutionGateway
from memory_firewall.viewer_auth import (
    COOKIE_NAME,
    SESSION_TTL_SECONDS,
    authenticate_viewer,
    register_viewer,
    require_viewer,
    require_workspace,
    revoke_viewer_session,
    rotate_workspace_key,
)
from memory_firewall.provenance_ledger import ProvenanceLedger, Ed25519Handler
from memory_firewall.escalation import EscalationManager
from memory_firewall.langgraph_middleware import ProvenanceFirewallMiddleware
from memory_firewall.schemas import Authority
from api import provenance_routes, telegram_routes
from telegram_supervisor import (
    create_telegram_supervisor,
    TelegramSupervisor,
    TelegramFirewallBridge,
)

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


# --- Telegram Supervisor Bot Integration ---

_telegram_supervisor: TelegramSupervisor | None = None
_telegram_bridge: TelegramFirewallBridge | None = None


@app.on_event("startup")
async def startup_telegram() -> None:
    """Initialize Telegram supervisor bot if configured."""
    global _telegram_supervisor, _telegram_bridge
    
    token = os.getenv("TELEGRAM_BOT_TOKEN")
    chat_id = os.getenv("TELEGRAM_ADMIN_CHAT_ID")
    
    if token and chat_id:
        try:
            import logging
            logger = logging.getLogger(__name__)
            logger.info("Initializing Telegram Supervisor Bot...")
            
            _telegram_supervisor, _telegram_bridge = await create_telegram_supervisor(
                telegram_token=token,
                admin_chat_id=chat_id,
            )
            
            # Register telegram routes with supervisor and bridge
            telegram_routes.set_supervisor(_telegram_supervisor)
            telegram_routes.set_bridge(_telegram_bridge)
            
            logger.info("Telegram Supervisor Bot initialized successfully")
        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Failed to initialize Telegram Supervisor: {e}", exc_info=True)
            # Don't raise; allow server to run without Telegram if config is invalid


@app.on_event("shutdown")
async def shutdown_telegram() -> None:
    """Gracefully shutdown Telegram supervisor bot."""
    global _telegram_supervisor
    
    if _telegram_supervisor:
        try:
            import logging
            logger = logging.getLogger(__name__)
            logger.info("Shutting down Telegram Supervisor Bot...")
            await _telegram_supervisor.stop()
            logger.info("Telegram Supervisor Bot shut down successfully")
        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Error during Telegram shutdown: {e}", exc_info=True)


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
    identity, token, workspace_key = register_viewer(
        analysis_store, payload.email, payload.password
    )
    _set_viewer_cookie(response, token)
    # The only response that ever carries the plaintext agent key. Rotation is
    # the sole way to obtain another one.
    return ViewerSessionResponse(
        authenticated=True,
        email=identity.email,
        workspace_id=identity.tenant_id,
        expires_in_seconds=SESSION_TTL_SECONDS,
        workspace_key=workspace_key,
    )


@app.post("/api/v1/auth/login", response_model=ViewerSessionResponse)
def viewer_login(
    request: Request,
    response: Response,
    payload: ViewerLoginRequest,
) -> ViewerSessionResponse:
    if _is_auth_rate_limited(_client_ip(request)):
        raise HTTPException(status_code=429, detail="rate_limit_exceeded")
    identity, token = authenticate_viewer(
        analysis_store, payload.email, payload.password
    )
    _set_viewer_cookie(response, token)
    return ViewerSessionResponse(
        authenticated=True,
        email=identity.email,
        workspace_id=identity.tenant_id,
        expires_in_seconds=SESSION_TTL_SECONDS,
    )


@app.get("/api/v1/auth/session", response_model=ViewerSessionResponse)
def viewer_session(request: Request) -> ViewerSessionResponse:
    identity = require_viewer(request, analysis_store)
    return ViewerSessionResponse(
        authenticated=True,
        email=identity.email,
        workspace_id=identity.tenant_id,
        expires_in_seconds=SESSION_TTL_SECONDS,
    )


@app.post("/api/v1/auth/logout", status_code=204)
def viewer_logout(request: Request, response: Response) -> Response:
    revoke_viewer_session(request, analysis_store)
    response.delete_cookie(COOKIE_NAME, path="/", samesite="lax")
    response.status_code = 204
    return response


@app.post("/api/v1/workspace/key/rotate", response_model=WorkspaceKeyResponse)
def rotate_workspace_agent_key(request: Request) -> WorkspaceKeyResponse:
    """Mint a new agent key for the caller's workspace and revoke the old one.

    Requires a browser session: an agent key cannot rotate itself, so a leaked
    key cannot lock the owner out of their own workspace.
    """

    if _is_rate_limited(_client_ip(request)):
        raise HTTPException(status_code=429, detail="rate_limit_exceeded")
    identity = require_viewer(request, analysis_store)
    workspace_key = rotate_workspace_key(analysis_store, identity.email)
    return WorkspaceKeyResponse(
        workspace_key=workspace_key, workspace_id=identity.tenant_id
    )


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
app.include_router(telegram_routes.router)


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


# --- Authenticated write plane -----------------------------------------------
#
# Every endpoint below mutates or reads workspace-owned state, so each one
# resolves its tenant with ``require_workspace`` (viewer cookie OR agent key)
# and then OVERWRITES ``payload.tenant_id`` with the authenticated value. The
# ``tenant_id`` a client puts in the body is accepted by the schema for
# backwards compatibility but is discarded here: it can never select, widen, or
# cross a workspace boundary.


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
    tenant_id = require_workspace(request, analysis_store)
    return memory_firewall.analyze(payload.model_copy(update={"tenant_id": tenant_id}))


@app.post("/api/v1/memory/evaluate-write", response_model=MemoryAnalysisResponse)
def evaluate_memory_write(
    request: Request, payload: MemoryAnalyzeRequest
) -> MemoryAnalysisResponse | JSONResponse:
    """Preview a signed memory decision without storing it or adding a ledger event."""

    if _is_rate_limited(_client_ip(request)):
        return JSONResponse(status_code=429, content={"error": "rate_limit_exceeded"})
    tenant_id = require_workspace(request, analysis_store)
    return memory_firewall.analyze_preview(
        payload.model_copy(update={"tenant_id": tenant_id})
    )


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
    tenant_id = require_workspace(request, analysis_store)
    try:
        return memory_firewall.derive(payload.model_copy(update={"tenant_id": tenant_id}))
    except LookupError:
        raise HTTPException(status_code=404, detail="parent_analysis_not_found") from None


@app.post("/api/v1/memory/retrieve", response_model=MemoryRetrieveResponse)
def retrieve_memory(
    request: Request, payload: MemoryRetrieveRequest
) -> MemoryRetrieveResponse | JSONResponse:
    """Retrieve signed memory and append a session-correlated custody event."""

    if _is_rate_limited(_client_ip(request)):
        return JSONResponse(status_code=429, content={"error": "rate_limit_exceeded"})
    tenant_id = require_workspace(request, analysis_store)
    try:
        return memory_firewall.retrieve(
            payload.model_copy(update={"tenant_id": tenant_id})
        )
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
    tenant_id = require_workspace(request, analysis_store)
    try:
        return memory_firewall.evaluate_action(
            payload.model_copy(update={"tenant_id": tenant_id})
        )
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
    tenant_id = require_workspace(request, analysis_store)
    try:
        return memory_firewall.authorize_tool_call(
            payload.model_copy(update={"tenant_id": tenant_id})
        )
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
    tenant_id = require_workspace(request, analysis_store)
    payload = payload.model_copy(update={"tenant_id": tenant_id})
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
def get_analysis(analysis_id: str, request: Request) -> MemoryAnalysisResponse:
    """Retrieve a sanitized analysis result owned by the authenticated workspace.

    There is no ``tenant_id`` query parameter: an id belonging to another
    workspace is reported as 404, never disclosed.
    """

    if _is_rate_limited(_client_ip(request)):
        raise HTTPException(status_code=429, detail="rate_limit_exceeded")
    tenant_id = require_workspace(request, analysis_store)
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
    request: Request, limit: int = 50
) -> list[PublicLedgerEventView]:
    """Return recent evidence for the authenticated caller's workspace only.

    The workspace is taken from the session, never from client input, so one
    account cannot enumerate another account's ledger.
    """

    if _is_rate_limited(_client_ip(request)):
        raise HTTPException(status_code=429, detail="rate_limit_exceeded")
    identity = require_viewer(request, analysis_store)
    if limit < 1 or limit > 100:
        raise HTTPException(status_code=422, detail="invalid_limit")
    projections: list[PublicLedgerEventView] = []
    for event in analysis_store.list_events(identity.tenant_id, limit):
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


@app.get("/api/v1/workspace/stats", response_model=WorkspaceStatsResponse)
def workspace_stats(request: Request) -> WorkspaceStatsResponse:
    """Summarize ledger activity for the caller's own workspace."""

    if _is_rate_limited(_client_ip(request)):
        raise HTTPException(status_code=429, detail="rate_limit_exceeded")
    identity = require_viewer(request, analysis_store)
    stats = analysis_store.workspace_stats(identity.tenant_id)
    return WorkspaceStatsResponse(workspace_id=identity.tenant_id, **stats)


# --- Session-scoped demo console ---------------------------------------------
#
# Every endpoint below derives its tenant from the authenticated session. No
# request body may name a workspace, so a demo action can only ever touch the
# caller's own isolated data.

_DEMO_SCOPE = "accounts_payable"
_DEMO_AGENT_ACTOR = ActorContext(id="agent:assistant", type=ActorType.AGENT)
_DEMO_SESSION_ID = "assistant-session"
_MAX_PREVIEW_CHARS = 400
_MAX_SUMMARY_CHARS = 300

_PAY_KEYWORDS = ("pag", "transfer", "invoice", "factura", "cuenta")
_SEND_KEYWORDS = ("envia", "send", "export", "archivo", "file", "adjunt")
_EMAIL_KEYWORDS = (
    "correo",
    "email",
    "mail",
    "mensaje",
    "message",
    "responde",
    "reply",
    "contesta",
)
_DELETE_KEYWORDS = ("borra", "elimina", "delete")
# Bulk reads of personal data. Kept separate from _SEND_KEYWORDS because asking
# for the records and shipping them out are different actions, and the request
# alone is enough to warrant scrutiny.
_DATA_KEYWORDS = (
    "usuario",
    "user",
    "cliente",
    "customer",
    "base de datos",
    "database",
    " db",
    "registro",
    "record",
    "listado",
    "lista de",
    "dame todo",
    "give all",
    "dump",
)


def _sender_slug(sender: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", sender.lower())[:40].strip("-")
    return slug or "unknown"


def _external_actor_id(sender: str) -> str:
    """Build a valid, deterministic external actor id from a sender string."""

    return "external:" + _sender_slug(sender)


def _internal_actor_id(sender: str) -> str:
    """Same sender, but presented as an already-verified internal principal."""

    return "user:" + _sender_slug(sender)


def _infer_action(question: str) -> str | None:
    """Map an actionable question to a high-risk action with a fixed keyword table.

    Deterministic by design: the security decision must never depend on a
    language model's interpretation of the user's phrasing.
    """

    normalized = question.casefold()
    if any(keyword in normalized for keyword in _DELETE_KEYWORDS):
        return "DELETE_USER"
    if any(keyword in normalized for keyword in _PAY_KEYWORDS):
        return "PAY_INVOICE"
    # Checked before the generic send table: "envia la lista de usuarios" is a
    # data disclosure first and a transport detail second.
    if any(keyword in normalized for keyword in _DATA_KEYWORDS):
        return "EXPORT_USER_DATA"
    if any(keyword in normalized for keyword in _EMAIL_KEYWORDS):
        return "SEND_EMAIL_INTERNAL"
    if any(keyword in normalized for keyword in _SEND_KEYWORDS):
        return "SEND_FILE_EXTERNAL"
    return None


def _email_claims(sender: str, subject: str, body: str) -> dict[str, Any]:
    """Extract deterministic, bounded claims so tool arguments have lineage."""

    claims: dict[str, Any] = {
        "sender": sender[:120],
        "subject": subject[:200],
    }
    account = re.search(r"(?:account|cuenta)\D{0,10}(\d{3,20})", body, re.IGNORECASE)
    if account is not None:
        claims["account"] = account.group(1)
    amount = re.search(r"(\d[\d.,]{3,19})", body)
    if amount is not None:
        claims["amount"] = amount.group(1)
    return claims


def _status_for(decision: Decision, state: MemoryState) -> str:
    if decision == Decision.BLOCK or state == MemoryState.BLOCKED:
        return "blocked"
    if state == MemoryState.QUARANTINED:
        return "quarantined"
    return "ok"


@app.post("/api/v1/demo/inbox/email", response_model=DemoEmailResponse)
def demo_inbox_email(
    request: Request, payload: DemoEmailRequest
) -> DemoEmailResponse | JSONResponse:
    """Ingest a synthetic email into the caller's workspace as untrusted memory."""

    if _is_rate_limited(_client_ip(request)):
        return JSONResponse(status_code=429, content={"error": "rate_limit_exceeded"})
    identity = require_viewer(request, analysis_store)
    internal = payload.from_verified_account

    analyze_request = MemoryAnalyzeRequest(
        content=f"From: {payload.sender}\nSubject: {payload.subject}\n\n{payload.body}",
        source="internal" if internal else "email",
        scope=_DEMO_SCOPE,
        claims=_email_claims(payload.sender, payload.subject, payload.body),
        actor=ActorContext(
            id=_internal_actor_id(payload.sender)
            if internal
            else _external_actor_id(payload.sender),
            type=ActorType.USER if internal else ActorType.EXTERNAL_SOURCE,
        ),
        tenant_id=identity.tenant_id,
    )
    result = memory_firewall.analyze(analyze_request)

    return DemoEmailResponse(
        message_id=result.analysis_id,
        decision=result.decision,
        risk_score=result.risk_score,
        authority=result.authority,
        state=result.state,
        threats=result.threats,
        reason=result.reason,
        sanitized_preview=result.sanitized_content[:_MAX_PREVIEW_CHARS],
        created_at=result.created_at,
    )


@app.post("/api/v1/demo/agent/ask", response_model=DemoAgentAskResponse)
def demo_agent_ask(
    request: Request, payload: DemoAgentAskRequest
) -> DemoAgentAskResponse | JSONResponse:
    """Replay write -> derive -> retrieve -> tool for one workspace message."""

    if _is_rate_limited(_client_ip(request)):
        return JSONResponse(status_code=429, content={"error": "rate_limit_exceeded"})
    identity = require_viewer(request, analysis_store)

    # Cross-workspace reads fail closed as "not found".
    try:
        parent = memory_firewall.get_analysis(
            payload.message_id, tenant_id=identity.tenant_id
        )
    except LookupError:
        raise HTTPException(status_code=404, detail="analysis_not_found") from None
    if parent is None:
        raise HTTPException(status_code=404, detail="analysis_not_found")

    action = _infer_action(payload.question)
    if action is None:
        raise HTTPException(status_code=422, detail="no_action_inferred")

    derived = memory_firewall.derive(
        MemoryDeriveRequest(
            content="Summary of stored message: "
            + parent.sanitized_content[:_MAX_SUMMARY_CHARS],
            parent_analysis_ids=[parent.analysis_id],
            transformation="summarize",
            scope=_DEMO_SCOPE,
            actor=_DEMO_AGENT_ACTOR,
            tenant_id=identity.tenant_id,
        )
    )
    retrieved = memory_firewall.retrieve(
        MemoryRetrieveRequest(
            analysis_id=derived.analysis_id,
            session_id=_DEMO_SESSION_ID,
            actor=_DEMO_AGENT_ACTOR,
            tenant_id=identity.tenant_id,
        )
    )

    # Which memory backs the call. A derived summary is born without capability
    # to act, so in the compromised-internal-account scenario the agent cites
    # the approved message itself -- exactly as a real agent would when the
    # operator's own account vouched for it. That removes the capability and
    # authority gates from the path, leaving only the content to be judged.
    evidence = parent if parent.capabilities.usable_for_action else derived

    arguments: dict[str, Any] = dict(evidence.claims) or {
        "target": "external",
        "evidence": evidence.analysis_id,
    }
    invocations = 0

    def synthetic_high_risk_tool(**_arguments: Any) -> None:
        nonlocal invocations
        invocations += 1

    gateway = MemoryToolExecutionGateway(
        memory_firewall, {action: synthetic_high_risk_tool}
    )
    authorization_request = ToolCallAuthorizationRequest(
        schema_version="memory-firewall.tool-call.v1",
        request_id=f"req-demo-{secrets.token_hex(8)}",
        runtime=ToolRuntime(name="demo-console", adapter_version="1.0.0"),
        session=ToolSession(id=_DEMO_SESSION_ID),
        tool=ToolDescriptor(name=action, arguments=arguments),
        argument_lineage={name: [evidence.analysis_id] for name in arguments},
        scope=_DEMO_SCOPE,
        actor=_DEMO_AGENT_ACTOR,
        tenant_id=identity.tenant_id,
        justification=payload.question,
    )
    try:
        outcome = gateway.execute(authorization_request)
    except LookupError:
        raise HTTPException(status_code=404, detail="analysis_not_found") from None
    except ValueError:
        raise HTTPException(status_code=422, detail="invalid_lineage") from None

    decision = outcome.decision.decision
    required = outcome.decision.required_authority.value
    provided = (outcome.decision.provided_authority or derived.authority).value

    # Deterministic fallback: the demo must still explain itself when no model
    # is configured or the gateway is down.
    if decision == Decision.ALLOW:
        agent_answer = (
            f"Ejecute {action}: la evidencia alcanza la autoridad requerida "
            f"({required}) y conserva su linaje firmado."
        )
    elif decision == Decision.REVIEW:
        agent_answer = (
            f"Retuve {action} para revision humana: {outcome.decision.reason}"
        )
    else:
        agent_answer = (
            f"No puedo ejecutar {action}: la evidencia proviene de un correo "
            f"externo no verificado (autoridad {provided}). "
            f"La accion requiere {required}."
        )

    # The model only narrates the decision above; it never revisits it.
    spoken = explain_decision(
        question=payload.question,
        action=action,
        decision=decision,
        reason=outcome.decision.reason,
        required_authority=required,
        provided_authority=provided,
        content=parent.sanitized_content,
    )
    if spoken:
        agent_answer = spoken

    steps = [
        DemoAgentStep(
            id="write",
            label="Correo recibido y analizado",
            status=_status_for(parent.decision, parent.state),
            detail=parent.reason[:500],
            event_type="WRITE",
            analysis_id=parent.analysis_id,
            authority=parent.authority,
        ),
        DemoAgentStep(
            id="derive",
            label="Resumen derivado por el agente",
            status=_status_for(derived.decision, derived.state),
            detail=derived.reason[:500],
            event_type="DERIVE",
            analysis_id=derived.analysis_id,
            authority=derived.authority,
        ),
        DemoAgentStep(
            id="retrieve",
            label="Memoria recuperada en la sesion del agente",
            status=_status_for(derived.decision, derived.state),
            detail=(
                "Firma verificada al recuperar; la autoridad heredada sigue "
                f"siendo {derived.authority.value}."
            ),
            event_type="RETRIEVE",
            analysis_id=retrieved.memory.analysis_id,
            authority=retrieved.memory.authority,
        ),
        DemoAgentStep(
            id="tool",
            label=f"Autorizacion de la herramienta {action}",
            status="blocked" if decision != Decision.ALLOW else "ok",
            detail=outcome.decision.reason[:500],
            event_type="TOOL_DECISION",
            analysis_id=derived.analysis_id,
            authority=outcome.decision.provided_authority or derived.authority,
        ),
    ]

    return DemoAgentAskResponse(
        question=payload.question,
        inferred_action=action,
        agent_answer=agent_answer,
        decision=decision,
        executed=outcome.executed,
        function_invocations=invocations,
        steps=steps,
        semantic_judgement=outcome.decision.semantic_judgement,
        semantic_reason=outcome.decision.semantic_reason,
        semantic_model=outcome.decision.semantic_model,
        answer_source="model" if spoken else "deterministic",
    )


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


@app.get("/api/v1/policy/action-contracts")
async def action_contracts() -> dict[str, Any]:
    """Expose the deterministic contract registry for operators and auditors."""

    return {
        "schema_version": "memory-firewall.action-contracts.v1",
        "effects": {
            name: {
                "required_authority": policy.required_authority.value,
                "one_shot": policy.one_shot,
                "semantic_review": policy.semantic_review,
            }
            for name, policy in sorted(EFFECT_POLICIES.items())
        },
        "actions": {
            name: {
                "effects": sorted(contract.effects),
                "required_authority": contract.required_authority.value,
                "one_shot": contract.high_risk,
                "semantic_review": contract.semantic_review,
                "arguments": {
                    argument: {
                        "type": rule.kind,
                        "required": rule.required,
                        "required_authority": rule.required_authority.value,
                    }
                    for argument, rule in sorted(contract.arguments.items())
                },
            }
            for name, contract in sorted(ACTION_CONTRACTS.items())
        },
    }


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
        cli_install_command=CLI_INSTALL_COMMAND,
        adapters=[
            RuntimeAdapterStatus(
                name="Pi",
                hook="tool_call",
                language="TypeScript",
                status="adapter_verified",
                install_command=ADAPTER_INSTALL_COMMANDS["pi"],
            ),
            RuntimeAdapterStatus(
                name="Hermes",
                hook="pre_tool_call",
                language="Python",
                status="adapter_verified",
                install_command=ADAPTER_INSTALL_COMMANDS["hermes"],
            ),
            RuntimeAdapterStatus(
                name="OpenClaw",
                hook="before_tool_call",
                language="JavaScript",
                status="adapter_verified",
                install_command=ADAPTER_INSTALL_COMMANDS["openclaw"],
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
    tenant_id = require_workspace(request, analysis_store)
    payload = payload.model_copy(update={"tenant_id": tenant_id})
    event_payload = payload.model_dump(mode="json")
    analysis_store.append_event(
        event_type="TOOL_BLOCKED_LOCAL",
        object_id=payload.session.tool_call_id or payload.session.id,
        actor_id=payload.actor.id,
        tenant_id=tenant_id,
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
    if exc.status_code == 422 and exc.detail == "no_action_inferred":
        return JSONResponse(status_code=422, content={"error": "no_action_inferred"})
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
