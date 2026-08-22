"""Tamper-evident signing for sanitized memory analysis envelopes.

The MVP uses an HMAC key supplied through the environment. This is appropriate
for one trusted process; production deployments with independent verifiers
should replace it with Ed25519 backed by KMS/HSM.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from secrets import token_bytes
from typing import Any

from .schemas import MemoryAnalysisResponse


_ENV_KEY = os.getenv("MEMORY_FIREWALL_SIGNING_KEY")
_SIGNING_KEY = _ENV_KEY.encode("utf-8") if _ENV_KEY else token_bytes(32)
SIGNING_KEY_ID = os.getenv("MEMORY_FIREWALL_SIGNING_KEY_ID", "local-ephemeral")


class IntegrityError(ValueError):
    """Raised when persisted analysis data fails envelope verification."""


def _canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _unsigned_payload(result: MemoryAnalysisResponse) -> dict[str, Any]:
    payload = result.model_dump(mode="json")
    payload.pop("signature", None)
    payload.pop("content_hash", None)
    payload["key_id"] = SIGNING_KEY_ID
    return payload


def sign_result(result: MemoryAnalysisResponse) -> MemoryAnalysisResponse:
    """Return a copy with a deterministic hash and keyed signature."""

    payload = _unsigned_payload(result)
    content_hash = hashlib.sha256(_canonical(payload)).hexdigest()
    signature_payload = _canonical(
        {"content_hash": content_hash, "key_id": SIGNING_KEY_ID}
    )
    signature = hmac.new(
        _SIGNING_KEY,
        signature_payload,
        hashlib.sha256,
    ).hexdigest()
    return result.model_copy(
        update={
            "content_hash": content_hash,
            "key_id": SIGNING_KEY_ID,
            "signature": signature,
        }
    )


def verify_result(result: MemoryAnalysisResponse) -> bool:
    """Verify the hash and signature of a result loaded from storage."""

    if not result.content_hash or not result.signature:
        return False
    payload = _unsigned_payload(result)
    expected_hash = hashlib.sha256(_canonical(payload)).hexdigest()
    if not hmac.compare_digest(expected_hash, result.content_hash):
        return False
    signature_payload = _canonical(
        {"content_hash": result.content_hash, "key_id": result.key_id}
    )
    expected_signature = hmac.new(
        _SIGNING_KEY,
        signature_payload,
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected_signature, result.signature)


def ensure_integrity(result: MemoryAnalysisResponse) -> MemoryAnalysisResponse:
    """Raise an integrity error instead of returning tampered data."""

    if not verify_result(result):
        raise IntegrityError("analysis envelope integrity verification failed")
    return result
