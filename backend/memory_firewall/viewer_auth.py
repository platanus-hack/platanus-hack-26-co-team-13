"""Persistent users and revocable sessions for the local control plane."""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import time
import unicodedata
from typing import NamedTuple

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

#: Header carrying the plaintext agent workspace key. Agents (adapters, CLI
#: harnesses) have no browser cookie, so this is their only credential.
WORKSPACE_KEY_HEADER = "X-Workspace-Key"
WORKSPACE_KEY_PREFIX = "mfw_"
_WORKSPACE_KEY_ENTROPY_BYTES = 32
_MAX_WORKSPACE_KEY_LENGTH = 256


class ViewerIdentity(NamedTuple):
    """Authenticated control-plane principal and the workspace it owns."""

    username: str
    tenant_id: str


def generate_workspace_id() -> str:
    """Mint an unguessable workspace id.

    Deliberately NOT derived from the username: a workspace id that is a
    function of a public identifier lets anyone who knows the username address
    another account's workspace. 64 bits of entropy from ``secrets``.
    """

    return "ws_" + secrets.token_hex(8)


def generate_workspace_key() -> str:
    """Mint a plaintext agent workspace key; only its sha256 is ever stored."""

    return WORKSPACE_KEY_PREFIX + secrets.token_urlsafe(_WORKSPACE_KEY_ENTROPY_BYTES)


def hash_workspace_key(key: str) -> str:
    """Return the sha256 digest used as the at-rest form of a workspace key."""

    return hashlib.sha256(key.encode("utf-8")).hexdigest()


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
) -> tuple[ViewerIdentity, str, str]:
    """Create an account bound to its own isolated workspace.

    Returns ``(identity, session_token, workspace_key)``. The workspace key is
    plaintext and is the only time it exists outside the caller: the store only
    ever holds its sha256 digest.
    """

    normalized = normalize_username(username)
    password_hash = hash_password(password)
    tenant_id = generate_workspace_id()
    workspace_key = generate_workspace_key()
    created = store.create_viewer_user(
        normalized,
        password_hash,
        tenant_id,
        hash_workspace_key(workspace_key),
    )
    if not created:
        raise HTTPException(status_code=409, detail="username_unavailable")
    return (
        ViewerIdentity(username=normalized, tenant_id=tenant_id),
        issue_viewer_session(store, normalized),
        workspace_key,
    )


def rotate_workspace_key(store: AnalysisStore, username: str) -> str:
    """Issue a new agent key and invalidate the previous one atomically."""

    workspace_key = generate_workspace_key()
    if not store.set_workspace_key_hash(username, hash_workspace_key(workspace_key)):
        raise HTTPException(status_code=401, detail="invalid_viewer_session")
    return workspace_key


def authenticate_viewer(
    store: AnalysisStore, username: str, password: str
) -> tuple[ViewerIdentity, str]:
    """Verify credentials in constant-ish time and load the stored workspace."""

    try:
        normalized = normalize_username(username)
    except HTTPException:
        normalized = "invalid-user"
    stored_hash = store.get_viewer_password_hash(normalized)
    valid = verify_password(password, stored_hash or _DUMMY_PASSWORD_HASH)
    if stored_hash is None or not valid:
        raise HTTPException(status_code=401, detail="invalid_credentials")
    tenant_id = store.get_viewer_tenant_id(normalized)
    if tenant_id is None:
        raise HTTPException(status_code=401, detail="invalid_credentials")
    return (
        ViewerIdentity(username=normalized, tenant_id=tenant_id),
        issue_viewer_session(store, normalized),
    )


def require_viewer(request: Request, store: AnalysisStore) -> ViewerIdentity:
    """Resolve the authenticated identity or fail closed with 401."""

    token = request.cookies.get(COOKIE_NAME, "")
    if not token:
        raise HTTPException(status_code=401, detail="viewer_login_required")
    session = store.get_viewer_session(_token_hash(token), int(time.time()))
    if session is None:
        raise HTTPException(status_code=401, detail="invalid_viewer_session")
    username, tenant_id, _expires_at = session
    return ViewerIdentity(username=username, tenant_id=tenant_id)


#: Digest of a key that is never issued. Comparing against it on the miss path
#: keeps the "unknown key" branch doing the same work as the "known key" branch,
#: mirroring the ``_DUMMY_PASSWORD_HASH`` trick used for login.
_DUMMY_WORKSPACE_KEY_HASH = hash_workspace_key(
    "mfw_memory-firewall-dummy-workspace-key"
)


def require_workspace(request: Request, store: AnalysisStore) -> str:
    """Return the authenticated tenant id. Accepts a viewer cookie OR agent key.

    Resolution order, fail closed at every step:

    1. ``X-Workspace-Key`` header, when present, is hashed with sha256 and
       resolved against the stored digests. An unknown or malformed key is a
       401 ``invalid_workspace_key`` -- it never falls through to the cookie,
       so a stolen browser session cannot rescue a bad agent key.
    2. Otherwise the viewer session cookie, when present, yields its workspace.
    3. Otherwise 401 ``workspace_auth_required``.

    The caller-supplied ``tenant_id`` in a request body is never consulted.
    There is no default workspace.
    """

    presented = request.headers.get(WORKSPACE_KEY_HEADER, "").strip()
    if presented:
        if len(presented) > _MAX_WORKSPACE_KEY_LENGTH:
            raise HTTPException(status_code=401, detail="invalid_workspace_key")
        key_hash = hash_workspace_key(presented)
        tenant_id = store.get_tenant_by_workspace_key_hash(key_hash)
        if tenant_id is None:
            hmac.compare_digest(key_hash, _DUMMY_WORKSPACE_KEY_HASH)
            raise HTTPException(status_code=401, detail="invalid_workspace_key")
        return tenant_id
    if not request.cookies.get(COOKIE_NAME, ""):
        raise HTTPException(status_code=401, detail="workspace_auth_required")
    return require_viewer(request, store).tenant_id


def revoke_viewer_session(request: Request, store: AnalysisStore) -> None:
    token = request.cookies.get(COOKIE_NAME, "")
    if token:
        store.delete_viewer_session(_token_hash(token))
