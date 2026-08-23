"""Stable, isolated process configuration for backend tests."""

from __future__ import annotations

import base64
import os
import tempfile
from pathlib import Path
from typing import NamedTuple


os.environ.setdefault(
    "MEMORY_FIREWALL_DB_PATH",
    str(Path(tempfile.gettempdir()) / "memory-firewall-tests.sqlite3"),
)
os.environ.setdefault(
    "MEMORY_FIREWALL_ED25519_PRIVATE_KEY",
    base64.b64encode(bytes(range(32))).decode("ascii"),
)
os.environ.setdefault("MEMORY_FIREWALL_ADMIN_TOKEN", "test-admin-token")
os.environ.setdefault("MEMORY_FIREWALL_ADMIN_ACTOR_ID", "user:support-supervisor")
os.environ.setdefault("MEMORY_FIREWALL_ADMIN_TENANT_ID", "default")

# Imported after the environment is fixed: api.main opens SQLite at import time.
import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from api.main import app  # noqa: E402
from memory_firewall.viewer_auth import WORKSPACE_KEY_HEADER  # noqa: E402


TEST_PASSWORD = "a-secure-password"


class Workspace(NamedTuple):
    """An isolated workspace plus both credentials that can reach it.

    ``client`` carries the browser session cookie. ``workspace_key`` is the
    plaintext agent credential, returned exactly once by registration.
    """

    client: TestClient
    workspace_key: str
    tenant_id: str
    username: str

    @property
    def key_header(self) -> dict[str, str]:
        """Headers an agent (adapter/CLI) would send instead of a cookie."""

        return {WORKSPACE_KEY_HEADER: self.workspace_key}


def register_workspace(username: str, password: str = TEST_PASSWORD) -> Workspace:
    """Register an account on a fresh client and capture its one-time key."""

    client = TestClient(app)
    response = client.post(
        "/api/v1/auth/register",
        json={"username": username, "password": password},
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["workspace_key"], "registration must return the agent key once"
    return Workspace(
        client=client,
        workspace_key=body["workspace_key"],
        tenant_id=body["workspace_id"],
        username=username,
    )


@pytest.fixture
def workspace() -> Workspace:
    """A registered account: cookie client, agent key, and workspace id."""

    return register_workspace("workspace-owner")


@pytest.fixture
def other_workspace() -> Workspace:
    """A second, unrelated account used to prove cross-workspace isolation."""

    return register_workspace("workspace-neighbor")
