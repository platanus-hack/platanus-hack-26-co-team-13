"""Tamper-evident Ed25519 signing for sanitized memory analysis envelopes.

Asymmetric signatures allow any component to verify envelopes with the public
key alone: holders of the verification key hold no signing capability. This
matches the trust boundary where the firewall is the signing component and the
backend is not part of the TCB (requirements sections 3.4/3.5/8.11).

Key management (MVP): the private key is either supplied through the
environment as a base64 32-byte seed or generated ephemerally at startup.
Production deployments should back it with KMS/HSM; that is out of MVP scope.

Generate a stable key for demos with:

    python -m memory_firewall.crypto
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .schemas import MemoryAnalysisResponse


_PRIVATE_KEY_ENV = "MEMORY_FIREWALL_ED25519_PRIVATE_KEY"
SIGNING_KEY_ID = os.getenv("MEMORY_FIREWALL_SIGNING_KEY_ID", "local-ephemeral")


class IntegrityError(ValueError):
    """Raised when persisted analysis data fails envelope verification."""


def _load_private_key() -> Ed25519PrivateKey:
    encoded = os.getenv(_PRIVATE_KEY_ENV, "").strip()
    if not encoded:
        return Ed25519PrivateKey.generate()
    try:
        seed = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise RuntimeError(f"{_PRIVATE_KEY_ENV} must be valid base64") from exc
    if len(seed) != 32:
        raise RuntimeError(f"{_PRIVATE_KEY_ENV} must decode to exactly 32 bytes")
    return Ed25519PrivateKey.from_private_bytes(seed)


_SIGNING_KEY = _load_private_key()
_VERIFY_KEY: Ed25519PublicKey = _SIGNING_KEY.public_key()
PUBLIC_KEY_B64 = base64.b64encode(
    _VERIFY_KEY.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
).decode("ascii")


def public_key_base64() -> str:
    """Return the current verification key; safe to share with verifiers."""

    return PUBLIC_KEY_B64


def canonical_bytes(payload: dict[str, Any]) -> bytes:
    """Serialize security-relevant payloads deterministically."""

    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


# Kept private compatibility for existing envelope helpers in this module.
_canonical = canonical_bytes


def _unsigned_payload(result: MemoryAnalysisResponse) -> dict[str, Any]:
    payload = result.model_dump(mode="json")
    payload.pop("signature", None)
    payload.pop("content_hash", None)
    payload["key_id"] = SIGNING_KEY_ID
    return payload


def sign_result(result: MemoryAnalysisResponse) -> MemoryAnalysisResponse:
    """Return a copy with a deterministic hash and an Ed25519 signature."""

    payload = _unsigned_payload(result)
    content_hash = hashlib.sha256(_canonical(payload)).hexdigest()
    signature_payload = _canonical(
        {"content_hash": content_hash, "key_id": SIGNING_KEY_ID}
    )
    signature = base64.b64encode(_SIGNING_KEY.sign(signature_payload)).decode("ascii")
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
    try:
        signature = base64.b64decode(result.signature, validate=True)
    except (ValueError, binascii.Error):
        return False
    try:
        _VERIFY_KEY.verify(signature, signature_payload)
    except InvalidSignature:
        return False
    return True


def verify_result_with_key(
    result: MemoryAnalysisResponse, public_key_base64: str
) -> bool:
    """Verify a result using only a public key, as an external verifier would.

    This mirrors what a dashboard, adapter, or judge could do independently
    with just the exposed verification key.
    """

    try:
        raw_key = base64.b64decode(public_key_base64, validate=True)
        verify_key = Ed25519PublicKey.from_public_bytes(raw_key)
    except (ValueError, binascii.Error):
        return False
    if not result.content_hash or not result.signature:
        return False
    payload = _unsigned_payload(result)
    expected_hash = hashlib.sha256(_canonical(payload)).hexdigest()
    if not hmac.compare_digest(expected_hash, result.content_hash):
        return False
    signature_payload = _canonical(
        {"content_hash": result.content_hash, "key_id": result.key_id}
    )
    try:
        signature = base64.b64decode(result.signature, validate=True)
    except (ValueError, binascii.Error):
        return False
    try:
        verify_key.verify(signature, signature_payload)
    except InvalidSignature:
        return False
    return True


def ensure_integrity(result: MemoryAnalysisResponse) -> MemoryAnalysisResponse:
    """Raise an integrity error instead of returning tampered data."""

    if not verify_result(result):
        raise IntegrityError("analysis envelope integrity verification failed")
    return result


def sign_ledger_event(payload: dict[str, Any]) -> str:
    """Sign canonical ledger event content with the firewall's private key."""

    return base64.b64encode(_SIGNING_KEY.sign(canonical_bytes(payload))).decode("ascii")


def verify_ledger_event(payload: dict[str, Any], signature_b64: str) -> bool:
    """Verify a ledger event signature using only the current public key."""

    try:
        signature = base64.b64decode(signature_b64, validate=True)
        _VERIFY_KEY.verify(signature, canonical_bytes(payload))
    except (ValueError, binascii.Error, InvalidSignature):
        return False
    return True


if __name__ == "__main__":  # pragma: no cover
    # Generate and print a base64 seed for MEMORY_FIREWALL_ED25519_PRIVATE_KEY.
    print(base64.b64encode(os.urandom(32)).decode("ascii"))
