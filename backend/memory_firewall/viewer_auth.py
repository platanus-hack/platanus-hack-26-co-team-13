"""Persistent users and revocable sessions for the local control plane."""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import time
import unicodedata

from fastapi import HTTPException, Request

from .store import AnalysisStore

COOKIE_NAME = "memory_firewall_session"
SESSION_TTL_SECONDS = 8 * 60 * 60
PASSWORD_MIN_LENGTH = 12
_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_MAXMEM = 64 * 1024 * 1024
_USERNAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")


def normalize_username(username: str) -> str:
    normalized = unicodedata.normalize("NFKC", username).strip().casefold()
    if not _USERNAME_PATTERN.fullmatch(normalized):
        raise HTTPException(status_code=422, detail="invalid_username")
    return normalized


def hash_password(password: str) -> str:
    if len(password) < PASSWORD_MIN_LENGTH or len(password) > 256:
        raise HTTPException(status_code=422, detail="invalid_password")
    salt = secrets.token_bytes(16)
    derived = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        dklen=32,
        maxmem=_SCRYPT_MAXMEM,
    )
    return "scrypt${}${}${}${}${}".format(
        _SCRYPT_N,
        _SCRYPT_R,
        _SCRYPT_P,
        base64.urlsafe_b64encode(salt).decode("ascii"),
        base64.urlsafe_b64encode(derived).decode("ascii"),
    )


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, n_raw, r_raw, p_raw, salt_raw, expected_raw = encoded.split("$")
        n, r, p = int(n_raw), int(r_raw), int(p_raw)
        if algorithm != "scrypt" or (n, r, p) != (_SCRYPT_N, _SCRYPT_R, _SCRYPT_P):
            return False
        salt = base64.urlsafe_b64decode(salt_raw.encode("ascii"))
        expected = base64.urlsafe_b64decode(expected_raw.encode("ascii"))
        if len(salt) != 16 or len(expected) != 32:
            return False
        actual = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=n,
            r=r,
            p=p,
            dklen=32,
            maxmem=_SCRYPT_MAXMEM,
        )
    except (ValueError, UnicodeError):
        return False
    return hmac.compare_digest(actual, expected)


_DUMMY_PASSWORD_HASH = hash_password("memory-firewall-dummy-password")


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("ascii", errors="ignore")).hexdigest()


def issue_viewer_session(store: AnalysisStore, username: str) -> str:
    token = secrets.token_urlsafe(32)
    store.create_viewer_session(
        username,
        _token_hash(token),
        int(time.time()) + SESSION_TTL_SECONDS,
    )
    return token


def register_viewer(
    store: AnalysisStore, username: str, password: str
) -> tuple[str, str]:
    normalized = normalize_username(username)
    password_hash = hash_password(password)
    if not store.create_viewer_user(normalized, password_hash):
        raise HTTPException(status_code=409, detail="username_unavailable")
    return normalized, issue_viewer_session(store, normalized)


def authenticate_viewer(
    store: AnalysisStore, username: str, password: str
) -> tuple[str, str]:
    try:
        normalized = normalize_username(username)
    except HTTPException:
        normalized = "invalid-user"
    stored_hash = store.get_viewer_password_hash(normalized)
    valid = verify_password(password, stored_hash or _DUMMY_PASSWORD_HASH)
    if stored_hash is None or not valid:
        raise HTTPException(status_code=401, detail="invalid_credentials")
    return normalized, issue_viewer_session(store, normalized)


def require_viewer(request: Request, store: AnalysisStore) -> str:
    token = request.cookies.get(COOKIE_NAME, "")
    if not token:
        raise HTTPException(status_code=401, detail="viewer_login_required")
    session = store.get_viewer_session(_token_hash(token), int(time.time()))
    if session is None:
        raise HTTPException(status_code=401, detail="invalid_viewer_session")
    return session[0]


def revoke_viewer_session(request: Request, store: AnalysisStore) -> None:
    token = request.cookies.get(COOKIE_NAME, "")
    if token:
        store.delete_viewer_session(_token_hash(token))
