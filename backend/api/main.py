"""FastAPI app for deterministic security code analysis.

Threat model measures:
- Never executes analyzed code (regex/line analysis only).
- Input validated with Pydantic (length 1..100_000) + 413 for oversized bodies.
- Rejects NUL/control characters.
- In-memory per-IP rate limiting (10 req/min).
- Global error handler returns generic {"error": "analysis_failed"}.
- Max 100 findings per request.
"""

import os
import time
from collections import OrderedDict
from threading import RLock
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator
from starlette.exceptions import HTTPException as StarletteHTTPException

from analyzer.detector import analyze_code
from memory_firewall.crypto import (
    IntegrityError,
    PUBLIC_KEY_B64,
    SIGNING_KEY_ID,
    public_key_base64,
)
from memory_firewall.schemas import (
    ActionEvaluationRequest,
    ActionEvaluationResponse,
    MemoryAnalysisResponse,
    MemoryAnalyzeRequest,
    MemoryDeriveRequest,
)
from memory_firewall.service import MemoryFirewallService
from memory_firewall.store import AnalysisStore

MAX_BODY_BYTES = 256 * 1024  # 256KB
RATE_LIMIT = 10
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
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type"],
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

analysis_store = AnalysisStore(
    os.getenv("MEMORY_FIREWALL_DB_PATH", "memory_firewall.sqlite3")
)
memory_firewall = MemoryFirewallService(analysis_store)


def _client_ip(request: Request) -> str:
    # Trust ONLY the connection IP. X-Forwarded-For is client-controlled and
    # would let attackers rotate fake IPs to evade the rate limit (there is
    # no reverse proxy in front of this service).
    return request.client.host if request.client else "unknown"


def _evict_stale_ips() -> None:
    """Bound memory: drop least-recently-used IPs beyond MAX_TRACKED_IPS."""
    while len(_rate_buckets) > MAX_TRACKED_IPS:
        _rate_buckets.popitem(last=False)


def _is_rate_limited(ip: str) -> bool:
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


@app.get("/api/v1/analyses/{analysis_id}", response_model=MemoryAnalysisResponse)
def get_analysis(analysis_id: str, request: Request) -> MemoryAnalysisResponse:
    """Retrieve a sanitized analysis result by id."""

    if _is_rate_limited(_client_ip(request)):
        raise HTTPException(status_code=429, detail="rate_limit_exceeded")
    if len(analysis_id) > 64:
        raise HTTPException(status_code=404, detail="analysis_not_found")
    try:
        result = memory_firewall.get_analysis(analysis_id)
    except IntegrityError:
        raise HTTPException(status_code=500, detail="analysis_failed") from None
    if result is None:
        raise HTTPException(status_code=404, detail="analysis_not_found")
    return result


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
